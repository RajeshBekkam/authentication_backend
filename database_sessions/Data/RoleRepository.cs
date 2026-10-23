using Dapper;
using Microsoft.Data.SqlClient;

namespace DatabaseSessions.Data;

public sealed class RoleRepository(SqlConnectionFactory db)
{
    public async Task<IReadOnlyList<(RoleRecord Role, IReadOnlyList<string> Permissions)>> ListWithPermissionsAsync(
        CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        using var multi = await conn.QueryMultipleAsync(new CommandDefinition("""
            SELECT Id, Name, Description, IsSystem FROM auth.Roles ORDER BY Name;
            SELECT rp.RoleId, p.Name FROM auth.RolePermissions rp JOIN auth.Permissions p ON p.Id = rp.PermissionId;
            """, cancellationToken: ct));
        var roles = (await multi.ReadAsync<RoleRecord>()).AsList();
        var perms = (await multi.ReadAsync<(int RoleId, string Name)>()).ToLookup(x => x.RoleId, x => x.Name);
        return roles
            .Select(r => (r, (IReadOnlyList<string>)perms[r.Id].Order(StringComparer.Ordinal).ToList()))
            .ToList();
    }

    public async Task<IReadOnlyList<PermissionRecord>> ListPermissionsAsync(CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return (await conn.QueryAsync<PermissionRecord>(new CommandDefinition(
            "SELECT Id, Name, Description FROM auth.Permissions ORDER BY Name", cancellationToken: ct))).AsList();
    }

    public async Task<RoleRecord?> FindByNameAsync(string name, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<RoleRecord>(new CommandDefinition(
            "SELECT Id, Name, Description, IsSystem FROM auth.Roles WHERE Name = @name", new { name }, cancellationToken: ct));
    }

    /// <summary>Returns false if a role with that name already exists.</summary>
    public async Task<bool> CreateAsync(string name, string? description, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        try
        {
            await conn.ExecuteAsync(new CommandDefinition(
                "INSERT INTO auth.Roles (Name, Description, IsSystem) VALUES (@name, @description, 0)",
                new { name, description }, cancellationToken: ct));
            return true;
        }
        catch (SqlException ex) when (ex.Number is 2627 or 2601)
        {
            return false;
        }
    }

    /// <summary>Replaces a role's permissions. Returns false if any permission name does not exist.</summary>
    public async Task<bool> SetPermissionsAsync(int roleId, IReadOnlyCollection<string> permissionNames, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await using var tx = (SqlTransaction)await conn.BeginTransactionAsync(ct);

        var permissionIds = (await conn.QueryAsync<int>(new CommandDefinition(
            "SELECT Id FROM auth.Permissions WHERE Name IN @permissionNames",
            new { permissionNames }, tx, cancellationToken: ct))).AsList();
        if (permissionIds.Count != permissionNames.Count)
        {
            await tx.RollbackAsync(ct);
            return false;
        }

        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM auth.RolePermissions WHERE RoleId = @roleId", new { roleId }, tx, cancellationToken: ct));
        await conn.ExecuteAsync(new CommandDefinition(
            "INSERT INTO auth.RolePermissions (RoleId, PermissionId) VALUES (@roleId, @permissionId)",
            permissionIds.Select(permissionId => new { roleId, permissionId }), tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
        return true;
    }
}
