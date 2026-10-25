using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace DatabaseSessions.Data;

public sealed class UserRepository(IDbContextFactory<AuthDbContext> dbFactory)
{
    public async Task<UserAccount?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, ct);
    }

    public async Task<UserAccount?> FindByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id, ct);
    }

    /// <summary>Creates a user with the given role. Returns false if the email is already taken.</summary>
    public async Task<bool> CreateAsync(Guid id, string email, string normalizedEmail, string passwordHash, string roleName,
        DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);

        var roleId = await db.Roles.Where(r => r.Name == roleName).Select(r => (int?)r.Id).SingleOrDefaultAsync(ct)
            ?? throw new InvalidOperationException($"Role '{roleName}' does not exist.");

        db.Users.Add(new UserAccount
        {
            Id = id,
            Email = email,
            NormalizedEmail = normalizedEmail,
            PasswordHash = passwordHash,
            PasswordChangedUtc = now,
            CreatedUtc = now,
            UpdatedUtc = now,
            UserRoles = [new UserRole { UserId = id, RoleId = roleId }],
        });

        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateException ex) when (ex.InnerException is SqlException { Number: 2627 or 2601 })
        {
            return false;
        }
    }

    /// <summary>
    /// Atomically increments the failed-login counter and, when the threshold is reached,
    /// sets a lockout and resets the counter. Returns true if this attempt triggered a lockout.
    /// </summary>
    public async Task<bool> RegisterFailedLoginAsync(Guid id, int maxAttempts, DateTimeOffset lockoutEnd, DateTimeOffset now,
        CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        // A single UPDATE evaluates every SET against the pre-update row, so this is race-free.
        var updated = await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.LockoutEndUtc, u => u.FailedLoginCount + 1 >= maxAttempts ? lockoutEnd : u.LockoutEndUtc)
            .SetProperty(u => u.FailedLoginCount, u => u.FailedLoginCount + 1 >= maxAttempts ? 0 : u.FailedLoginCount + 1)
            .SetProperty(u => u.UpdatedUtc, now), ct);
        if (updated == 0) return false;

        // The row is still locked by our UPDATE, so this reads exactly what we wrote.
        var currentLockoutEnd = await db.Users.Where(u => u.Id == id).Select(u => u.LockoutEndUtc).SingleAsync(ct);
        await tx.CommitAsync(ct);
        return currentLockoutEnd == lockoutEnd;
    }

    public async Task RecordSuccessfulLoginAsync(Guid id, string? newPasswordHash, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.FailedLoginCount, 0)
            .SetProperty(u => u.LockoutEndUtc, (DateTimeOffset?)null)
            .SetProperty(u => u.PasswordHash, u => newPasswordHash ?? u.PasswordHash)
            .SetProperty(u => u.UpdatedUtc, now), ct);
    }

    public async Task ChangePasswordAsync(Guid id, string passwordHash, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.PasswordHash, passwordHash)
            .SetProperty(u => u.PasswordChangedUtc, now)
            .SetProperty(u => u.UpdatedUtc, now), ct);
    }

    /// <summary>Disables the account and revokes all its sessions in one transaction.</summary>
    public async Task<bool> DisableAsync(Guid id, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var updated = await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.IsDisabled, true)
            .SetProperty(u => u.DisabledAtUtc, now)
            .SetProperty(u => u.UpdatedUtc, now), ct);
        await db.Sessions.Where(x => x.UserId == id && x.RevokedUtc == null).ExecuteUpdateAsync(s => s
            .SetProperty(x => x.RevokedUtc, now)
            .SetProperty(x => x.RevokedReason, "account_disabled"), ct);

        await tx.CommitAsync(ct);
        return updated == 1;
    }

    public async Task<bool> EnableAsync(Guid id, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.IsDisabled, false)
            .SetProperty(u => u.DisabledAtUtc, (DateTimeOffset?)null)
            .SetProperty(u => u.UpdatedUtc, now), ct) == 1;
    }

    public async Task<bool> UnlockAsync(Guid id, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.FailedLoginCount, 0)
            .SetProperty(u => u.LockoutEndUtc, (DateTimeOffset?)null)
            .SetProperty(u => u.UpdatedUtc, now), ct) == 1;
    }

    public async Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.UserRoles.Where(ur => ur.UserId == userId)
            .Select(ur => ur.Role.Name).OrderBy(n => n).ToListAsync(ct);
    }

    public async Task<IReadOnlyList<string>> GetPermissionsAsync(Guid userId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.UserRoles.Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role.RolePermissions.Select(rp => rp.Permission.Name))
            .Distinct().OrderBy(n => n).ToListAsync(ct);
    }

    /// <summary>Replaces the user's roles. Returns false if any role name does not exist.</summary>
    public async Task<bool> SetRolesAsync(Guid userId, IReadOnlyCollection<string> roleNames, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var names = roleNames.ToArray();
        var roleIds = await db.Roles.Where(r => names.Contains(r.Name)).Select(r => r.Id).ToListAsync(ct);
        if (roleIds.Count != names.Length) return false;

        await db.UserRoles.Where(ur => ur.UserId == userId).ExecuteDeleteAsync(ct);
        db.UserRoles.AddRange(roleIds.Select(roleId => new UserRole { UserId = userId, RoleId = roleId }));
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return true;
    }

    public async Task<int> CountUsersInRoleAsync(string roleName, bool activeOnly, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.UserRoles.CountAsync(ur => ur.Role.Name == roleName && (!activeOnly || !ur.User.IsDisabled), ct);
    }

    public async Task<(IReadOnlyList<UserAccount> Items, int Total)> ListAsync(string? search, int page, int pageSize,
        CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var query = db.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var normalized = search.Trim().ToUpperInvariant();
            query = query.Where(u => u.NormalizedEmail.Contains(normalized));
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(u => u.CreatedUtc).ThenBy(u => u.Id)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(ct);
        return (items, total);
    }
}
