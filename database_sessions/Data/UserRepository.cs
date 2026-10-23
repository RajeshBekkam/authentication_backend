using Dapper;
using Microsoft.Data.SqlClient;

namespace DatabaseSessions.Data;

public sealed class UserRepository(SqlConnectionFactory db)
{
    private const string UserColumns = """
        Id, Email, NormalizedEmail, PasswordHash, IsDisabled, DisabledAtUtc, FailedLoginCount,
        LockoutEndUtc, PasswordChangedUtc, CreatedUtc, UpdatedUtc
        """;

    public async Task<UserRecord?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<UserRecord>(new CommandDefinition(
            $"SELECT {UserColumns} FROM auth.Users WHERE NormalizedEmail = @normalizedEmail",
            new { normalizedEmail }, cancellationToken: ct));
    }

    public async Task<UserRecord?> FindByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<UserRecord>(new CommandDefinition(
            $"SELECT {UserColumns} FROM auth.Users WHERE Id = @id", new { id }, cancellationToken: ct));
    }

    /// <summary>Creates a user with the given role. Returns false if the email is already taken.</summary>
    public async Task<bool> CreateAsync(Guid id, string email, string normalizedEmail, string passwordHash, string roleName,
        DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await using var tx = (SqlTransaction)await conn.BeginTransactionAsync(ct);
        try
        {
            await conn.ExecuteAsync(new CommandDefinition("""
                INSERT INTO auth.Users (Id, Email, NormalizedEmail, PasswordHash, PasswordChangedUtc, CreatedUtc, UpdatedUtc)
                VALUES (@id, @email, @normalizedEmail, @passwordHash, @now, @now, @now);

                INSERT INTO auth.UserRoles (UserId, RoleId)
                SELECT @id, Id FROM auth.Roles WHERE Name = @roleName;

                IF @@ROWCOUNT = 0 THROW 50001, 'Role does not exist.', 1;
                """,
                new { id, email, normalizedEmail, passwordHash, roleName, now }, tx, cancellationToken: ct));
            await tx.CommitAsync(ct);
            return true;
        }
        catch (SqlException ex) when (ex.Number is 2627 or 2601)
        {
            await tx.RollbackAsync(ct);
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
        await using var conn = await db.OpenAsync(ct);
        var lockedOut = await conn.QuerySingleOrDefaultAsync<bool?>(new CommandDefinition("""
            UPDATE auth.Users
            SET FailedLoginCount = CASE WHEN FailedLoginCount + 1 >= @maxAttempts THEN 0 ELSE FailedLoginCount + 1 END,
                LockoutEndUtc    = CASE WHEN FailedLoginCount + 1 >= @maxAttempts THEN @lockoutEnd ELSE LockoutEndUtc END,
                UpdatedUtc       = @now
            OUTPUT CAST(CASE WHEN deleted.FailedLoginCount + 1 >= @maxAttempts THEN 1 ELSE 0 END AS bit)
            WHERE Id = @id;
            """, new { id, maxAttempts, lockoutEnd, now }, cancellationToken: ct));
        return lockedOut ?? false;
    }

    public async Task RecordSuccessfulLoginAsync(Guid id, string? newPasswordHash, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Users
            SET FailedLoginCount = 0,
                LockoutEndUtc    = NULL,
                PasswordHash     = COALESCE(@newPasswordHash, PasswordHash),
                UpdatedUtc       = @now
            WHERE Id = @id;
            """, new { id, newPasswordHash, now }, cancellationToken: ct));
    }

    public async Task ChangePasswordAsync(Guid id, string passwordHash, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Users
            SET PasswordHash = @passwordHash, PasswordChangedUtc = @now, UpdatedUtc = @now
            WHERE Id = @id;
            """, new { id, passwordHash, now }, cancellationToken: ct));
    }

    /// <summary>Disables the account and revokes all its sessions in one transaction.</summary>
    public async Task<bool> DisableAsync(Guid id, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await using var tx = (SqlTransaction)await conn.BeginTransactionAsync(ct);
        var updated = await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Users SET IsDisabled = 1, DisabledAtUtc = @now, UpdatedUtc = @now WHERE Id = @id;
            """, new { id, now }, tx, cancellationToken: ct));
        await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Sessions SET RevokedUtc = @now, RevokedReason = 'account_disabled'
            WHERE UserId = @id AND RevokedUtc IS NULL;
            """, new { id, now }, tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
        return updated == 1;
    }

    public async Task<bool> EnableAsync(Guid id, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Users SET IsDisabled = 0, DisabledAtUtc = NULL, UpdatedUtc = @now WHERE Id = @id;
            """, new { id, now }, cancellationToken: ct)) == 1;
    }

    public async Task<bool> UnlockAsync(Guid id, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE auth.Users SET FailedLoginCount = 0, LockoutEndUtc = NULL, UpdatedUtc = @now WHERE Id = @id;
            """, new { id, now }, cancellationToken: ct)) == 1;
    }

    public async Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return (await conn.QueryAsync<string>(new CommandDefinition("""
            SELECT r.Name FROM auth.UserRoles ur JOIN auth.Roles r ON r.Id = ur.RoleId
            WHERE ur.UserId = @userId ORDER BY r.Name;
            """, new { userId }, cancellationToken: ct))).AsList();
    }

    public async Task<IReadOnlyList<string>> GetPermissionsAsync(Guid userId, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return (await conn.QueryAsync<string>(new CommandDefinition("""
            SELECT DISTINCT p.Name
            FROM auth.UserRoles ur
            JOIN auth.RolePermissions rp ON rp.RoleId = ur.RoleId
            JOIN auth.Permissions p ON p.Id = rp.PermissionId
            WHERE ur.UserId = @userId ORDER BY p.Name;
            """, new { userId }, cancellationToken: ct))).AsList();
    }

    /// <summary>Replaces the user's roles. Returns false if any role name does not exist.</summary>
    public async Task<bool> SetRolesAsync(Guid userId, IReadOnlyCollection<string> roleNames, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await using var tx = (SqlTransaction)await conn.BeginTransactionAsync(ct);

        var roleIds = (await conn.QueryAsync<int>(new CommandDefinition(
            "SELECT Id FROM auth.Roles WHERE Name IN @roleNames", new { roleNames }, tx, cancellationToken: ct))).AsList();
        if (roleIds.Count != roleNames.Count)
        {
            await tx.RollbackAsync(ct);
            return false;
        }

        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM auth.UserRoles WHERE UserId = @userId", new { userId }, tx, cancellationToken: ct));
        await conn.ExecuteAsync(new CommandDefinition(
            "INSERT INTO auth.UserRoles (UserId, RoleId) VALUES (@userId, @roleId)",
            roleIds.Select(roleId => new { userId, roleId }), tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
        return true;
    }

    public async Task<int> CountUsersInRoleAsync(string roleName, bool activeOnly, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(new CommandDefinition("""
            SELECT COUNT(*) FROM auth.UserRoles ur JOIN auth.Roles r ON r.Id = ur.RoleId
            JOIN auth.Users u ON u.Id = ur.UserId
            WHERE r.Name = @roleName AND (@activeOnly = 0 OR u.IsDisabled = 0);
            """, new { roleName, activeOnly }, cancellationToken: ct));
    }

    public async Task<(IReadOnlyList<UserRecord> Items, int Total)> ListAsync(string? search, int page, int pageSize,
        CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        var pattern = string.IsNullOrWhiteSpace(search) ? null : "%" + EscapeLike(search.Trim().ToUpperInvariant()) + "%";
        using var multi = await conn.QueryMultipleAsync(new CommandDefinition($"""
            SELECT COUNT(*) FROM auth.Users WHERE @pattern IS NULL OR NormalizedEmail LIKE @pattern ESCAPE '\';

            SELECT {UserColumns} FROM auth.Users
            WHERE @pattern IS NULL OR NormalizedEmail LIKE @pattern ESCAPE '\'
            ORDER BY CreatedUtc DESC, Id
            OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY;
            """, new { pattern, offset = (page - 1) * pageSize, pageSize }, cancellationToken: ct));
        var total = await multi.ReadSingleAsync<int>();
        var items = (await multi.ReadAsync<UserRecord>()).AsList();
        return (items, total);
    }

    private static string EscapeLike(string value) =>
        value.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_").Replace("[", @"\[");
}
