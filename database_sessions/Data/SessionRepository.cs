using Dapper;
using Microsoft.Data.SqlClient;

namespace DatabaseSessions.Data;

public sealed class SessionRepository(SqlConnectionFactory db)
{
    private const string SessionColumns = """
        Id, UserId, Transport, CreatedUtc, LastSeenUtc, IdleExpiresUtc, AbsoluteExpiresUtc,
        RevokedUtc, RevokedReason, IpAddress, UserAgent
        """;

    /// <summary>
    /// Inserts a session while enforcing the per-user concurrent session cap. The user row is locked
    /// so parallel logins for the same account cannot exceed the cap. Returns the ids of evicted sessions,
    /// or null if the account was disabled before the session could be created.
    /// </summary>
    public async Task<IReadOnlyList<Guid>?> CreateAsync(NewSession session, int maxConcurrentSessions, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await using var tx = (SqlTransaction)await conn.BeginTransactionAsync(ct);

        var isDisabled = await conn.QuerySingleOrDefaultAsync<bool?>(new CommandDefinition(
            "SELECT IsDisabled FROM auth.Users WITH (UPDLOCK, HOLDLOCK) WHERE Id = @UserId",
            new { session.UserId }, tx, cancellationToken: ct));
        if (isDisabled is null or true)
        {
            await tx.RollbackAsync(ct);
            return null;
        }

        var evicted = (await conn.QueryAsync<Guid>(new CommandDefinition("""
            WITH active AS
            (
                SELECT Id, ROW_NUMBER() OVER (ORDER BY CreatedUtc DESC, Id DESC) AS rn
                FROM auth.Sessions
                WHERE UserId = @UserId AND RevokedUtc IS NULL
                  AND IdleExpiresUtc > @CreatedUtc AND AbsoluteExpiresUtc > @CreatedUtc
            )
            UPDATE s SET RevokedUtc = @CreatedUtc, RevokedReason = 'session_limit'
            OUTPUT inserted.Id
            FROM auth.Sessions s JOIN active a ON a.Id = s.Id
            WHERE a.rn >= @maxConcurrentSessions;
            """, new { session.UserId, session.CreatedUtc, maxConcurrentSessions }, tx, cancellationToken: ct))).AsList();

        await conn.ExecuteAsync(new CommandDefinition("""
            INSERT INTO auth.Sessions
                (Id, TokenHash, UserId, Transport, CsrfToken, CreatedUtc, LastSeenUtc, IdleExpiresUtc, AbsoluteExpiresUtc, IpAddress, UserAgent)
            VALUES
                (@Id, @TokenHash, @UserId, @Transport, @CsrfToken, @CreatedUtc, @CreatedUtc, @IdleExpiresUtc, @AbsoluteExpiresUtc, @IpAddress, @UserAgent);
            """, session, tx, cancellationToken: ct));

        await tx.CommitAsync(ct);
        return evicted;
    }

    /// <summary>
    /// Validates a token hash in a single round trip: the session must exist, not be revoked or expired,
    /// and belong to an enabled account. Roles and permissions are loaded fresh on every request.
    /// </summary>
    public async Task<ValidatedSession?> ValidateAsync(byte[] tokenHash, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        using var multi = await conn.QueryMultipleAsync(new CommandDefinition("""
            DECLARE @sessionId uniqueidentifier, @userId uniqueidentifier;

            SELECT @sessionId = s.Id, @userId = s.UserId
            FROM auth.Sessions s
            JOIN auth.Users u ON u.Id = s.UserId
            WHERE s.TokenHash = @tokenHash
              AND s.RevokedUtc IS NULL
              AND s.IdleExpiresUtc > @now
              AND s.AbsoluteExpiresUtc > @now
              AND u.IsDisabled = 0;

            SELECT s.Id AS SessionId, s.UserId, u.Email, s.Transport, s.CsrfToken, s.LastSeenUtc, s.AbsoluteExpiresUtc
            FROM auth.Sessions s JOIN auth.Users u ON u.Id = s.UserId
            WHERE s.Id = @sessionId;

            SELECT r.Name FROM auth.UserRoles ur JOIN auth.Roles r ON r.Id = ur.RoleId
            WHERE ur.UserId = @userId;

            SELECT DISTINCT p.Name
            FROM auth.UserRoles ur
            JOIN auth.RolePermissions rp ON rp.RoleId = ur.RoleId
            JOIN auth.Permissions p ON p.Id = rp.PermissionId
            WHERE ur.UserId = @userId;
            """, new { tokenHash, now }, cancellationToken: ct));

        var row = await multi.ReadSingleOrDefaultAsync<SessionRow>();
        if (row is null) return null;

        var roles = (await multi.ReadAsync<string>()).AsList();
        var permissions = (await multi.ReadAsync<string>()).AsList();

        return new ValidatedSession
        {
            SessionId = row.SessionId,
            UserId = row.UserId,
            Email = row.Email,
            Transport = row.Transport,
            CsrfToken = row.CsrfToken,
            LastSeenUtc = row.LastSeenUtc,
            AbsoluteExpiresUtc = row.AbsoluteExpiresUtc,
            Roles = roles,
            Permissions = permissions,
        };
    }

    /// <summary>Slides the idle expiry forward (never past the absolute expiry).</summary>
    public async Task TouchAsync(Guid sessionId, DateTimeOffset now, DateTimeOffset idleExpires, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Sessions
            SET LastSeenUtc = @now,
                IdleExpiresUtc = CASE WHEN @idleExpires < AbsoluteExpiresUtc THEN @idleExpires ELSE AbsoluteExpiresUtc END
            WHERE Id = @sessionId AND RevokedUtc IS NULL AND LastSeenUtc < @now;
            """, new { sessionId, now, idleExpires }, cancellationToken: ct));
    }

    public async Task<SessionRecord?> FindByIdAsync(Guid sessionId, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<SessionRecord>(new CommandDefinition(
            $"SELECT {SessionColumns} FROM auth.Sessions WHERE Id = @sessionId", new { sessionId }, cancellationToken: ct));
    }

    public async Task<IReadOnlyList<SessionRecord>> ListActiveForUserAsync(Guid userId, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return (await conn.QueryAsync<SessionRecord>(new CommandDefinition($"""
            SELECT {SessionColumns} FROM auth.Sessions
            WHERE UserId = @userId AND RevokedUtc IS NULL AND IdleExpiresUtc > @now AND AbsoluteExpiresUtc > @now
            ORDER BY LastSeenUtc DESC;
            """, new { userId, now }, cancellationToken: ct))).AsList();
    }

    /// <summary>Revokes one session. When <paramref name="userId"/> is given, the session must belong to that user.</summary>
    public async Task<bool> RevokeAsync(Guid sessionId, string reason, DateTimeOffset now, Guid? userId = null, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Sessions SET RevokedUtc = @now, RevokedReason = @reason
            WHERE Id = @sessionId AND RevokedUtc IS NULL AND (@userId IS NULL OR UserId = @userId);
            """, new { sessionId, reason, now, userId }, cancellationToken: ct)) == 1;
    }

    public async Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset now, Guid? exceptSessionId = null,
        CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Sessions SET RevokedUtc = @now, RevokedReason = @reason
            WHERE UserId = @userId AND RevokedUtc IS NULL AND (@exceptSessionId IS NULL OR Id <> @exceptSessionId);
            """, new { userId, reason, now, exceptSessionId }, cancellationToken: ct));
    }

    /// <summary>Deletes sessions that were revoked or expired before the cutoff, in batches.</summary>
    public async Task<int> PurgeAsync(DateTimeOffset cutoff, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        var total = 0;
        int deleted;
        do
        {
            deleted = await conn.ExecuteAsync(new CommandDefinition("""
                DELETE TOP (5000) FROM auth.Sessions
                WHERE RevokedUtc < @cutoff OR AbsoluteExpiresUtc < @cutoff OR IdleExpiresUtc < @cutoff;
                """, new { cutoff }, cancellationToken: ct));
            total += deleted;
        } while (deleted == 5000 && !ct.IsCancellationRequested);
        return total;
    }

    private sealed class SessionRow
    {
        public Guid SessionId { get; init; }
        public Guid UserId { get; init; }
        public string Email { get; init; } = "";
        public string Transport { get; init; } = "";
        public string? CsrfToken { get; init; }
        public DateTimeOffset LastSeenUtc { get; init; }
        public DateTimeOffset AbsoluteExpiresUtc { get; init; }
    }
}
