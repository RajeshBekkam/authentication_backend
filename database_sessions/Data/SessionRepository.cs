using Microsoft.EntityFrameworkCore;

namespace DatabaseSessions.Data;

public sealed class SessionRepository(IDbContextFactory<AuthDbContext> dbFactory)
{
    /// <summary>
    /// Inserts a session while enforcing the per-user concurrent session cap. The user row is locked
    /// so parallel logins for the same account cannot exceed the cap. Returns the ids of evicted sessions,
    /// or null if the account was disabled before the session could be created.
    /// </summary>
    public async Task<IReadOnlyList<Guid>?> CreateAsync(UserSession session, int maxConcurrentSessions, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var isDisabled = await db.Users
            .FromSql($"SELECT * FROM auth.Users WITH (UPDLOCK, HOLDLOCK) WHERE Id = {session.UserId}")
            .Select(u => (bool?)u.IsDisabled)
            .SingleOrDefaultAsync(ct);
        if (isDisabled is null or true) return null;

        var now = session.CreatedUtc;
        var evicted = await db.Sessions
            .Where(s => s.UserId == session.UserId && s.RevokedUtc == null && s.IdleExpiresUtc > now && s.AbsoluteExpiresUtc > now)
            .OrderByDescending(s => s.CreatedUtc).ThenByDescending(s => s.Id)
            .Skip(maxConcurrentSessions - 1)
            .Select(s => s.Id)
            .ToListAsync(ct);

        if (evicted.Count > 0)
        {
            await db.Sessions.Where(s => evicted.Contains(s.Id)).ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedUtc, now)
                .SetProperty(x => x.RevokedReason, "session_limit"), ct);
        }

        db.Sessions.Add(session);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return evicted;
    }

    /// <summary>
    /// Validates a token hash in a single query: the session must exist, not be revoked or expired,
    /// and belong to an enabled account. Roles and permissions are loaded fresh on every request.
    /// </summary>
    public async Task<ValidatedSession?> ValidateAsync(byte[] tokenHash, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var row = await db.Sessions.AsNoTracking()
            .Where(s => s.TokenHash == tokenHash
                        && s.RevokedUtc == null
                        && s.IdleExpiresUtc > now
                        && s.AbsoluteExpiresUtc > now
                        && !s.User.IsDisabled)
            .Select(s => new
            {
                s.Id,
                s.UserId,
                s.User.Email,
                s.Transport,
                s.CsrfToken,
                s.LastSeenUtc,
                s.AbsoluteExpiresUtc,
                Roles = s.User.UserRoles.Select(ur => ur.Role.Name).ToList(),
                Permissions = s.User.UserRoles.SelectMany(ur => ur.Role.RolePermissions).Select(rp => rp.Permission.Name).ToList(),
            })
            .SingleOrDefaultAsync(ct);

        if (row is null) return null;

        return new ValidatedSession
        {
            SessionId = row.Id,
            UserId = row.UserId,
            Email = row.Email,
            Transport = row.Transport,
            CsrfToken = row.CsrfToken,
            LastSeenUtc = row.LastSeenUtc,
            AbsoluteExpiresUtc = row.AbsoluteExpiresUtc,
            Roles = row.Roles,
            Permissions = row.Permissions.Distinct(StringComparer.Ordinal).ToList(),
        };
    }

    /// <summary>Slides the idle expiry forward (never past the absolute expiry).</summary>
    public async Task TouchAsync(Guid sessionId, DateTimeOffset now, DateTimeOffset idleExpires, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.Sessions
            .Where(s => s.Id == sessionId && s.RevokedUtc == null && s.LastSeenUtc < now)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.LastSeenUtc, now)
                .SetProperty(x => x.IdleExpiresUtc, x => idleExpires < x.AbsoluteExpiresUtc ? idleExpires : x.AbsoluteExpiresUtc), ct);
    }

    public async Task<UserSession?> FindByIdAsync(Guid sessionId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Sessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == sessionId, ct);
    }

    public async Task<IReadOnlyList<UserSession>> ListActiveForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedUtc == null && s.IdleExpiresUtc > now && s.AbsoluteExpiresUtc > now)
            .OrderByDescending(s => s.LastSeenUtc)
            .ToListAsync(ct);
    }

    /// <summary>Revokes one session. When <paramref name="userId"/> is given, the session must belong to that user.</summary>
    public async Task<bool> RevokeAsync(Guid sessionId, string reason, DateTimeOffset now, Guid? userId = null, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var query = db.Sessions.Where(s => s.Id == sessionId && s.RevokedUtc == null);
        if (userId is { } owner) query = query.Where(s => s.UserId == owner);
        return await query.ExecuteUpdateAsync(s => s
            .SetProperty(x => x.RevokedUtc, now)
            .SetProperty(x => x.RevokedReason, reason), ct) == 1;
    }

    public async Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset now, Guid? exceptSessionId = null,
        CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var query = db.Sessions.Where(s => s.UserId == userId && s.RevokedUtc == null);
        if (exceptSessionId is { } except) query = query.Where(s => s.Id != except);
        return await query.ExecuteUpdateAsync(s => s
            .SetProperty(x => x.RevokedUtc, now)
            .SetProperty(x => x.RevokedReason, reason), ct);
    }

    /// <summary>Deletes sessions that were revoked or expired before the cutoff.</summary>
    public async Task<int> PurgeAsync(DateTimeOffset cutoff, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Sessions
            .Where(s => s.RevokedUtc < cutoff || s.AbsoluteExpiresUtc < cutoff || s.IdleExpiresUtc < cutoff)
            .ExecuteDeleteAsync(ct);
    }
}
