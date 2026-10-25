using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace DatabaseSessions.Data;

public sealed class RoleRepository(IDbContextFactory<AuthDbContext> dbFactory)
{
    public async Task<IReadOnlyList<RoleWithPermissions>> ListWithPermissionsAsync(CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var roles = await db.Roles.AsNoTracking()
            .OrderBy(r => r.Name)
            .Select(r => new
            {
                r.Name,
                r.Description,
                r.IsSystem,
                Permissions = r.RolePermissions.Select(rp => rp.Permission.Name).ToList(),
            })
            .ToListAsync(ct);
        return roles
            .Select(r => new RoleWithPermissions(r.Name, r.Description, r.IsSystem, r.Permissions.Order(StringComparer.Ordinal).ToList()))
            .ToList();
    }

    public async Task<IReadOnlyList<Permission>> ListPermissionsAsync(CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Permissions.AsNoTracking().OrderBy(p => p.Name).ToListAsync(ct);
    }

    public async Task<Role?> FindByNameAsync(string name, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Roles.AsNoTracking().SingleOrDefaultAsync(r => r.Name == name, ct);
    }

    /// <summary>Returns false if a role with that name already exists.</summary>
    public async Task<bool> CreateAsync(string name, string? description, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        db.Roles.Add(new Role { Name = name, Description = description, IsSystem = false });
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

    /// <summary>Replaces a role's permissions. Returns false if any permission name does not exist.</summary>
    public async Task<bool> SetPermissionsAsync(int roleId, IReadOnlyCollection<string> permissionNames, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var names = permissionNames.ToArray();
        var permissionIds = await db.Permissions.Where(p => names.Contains(p.Name)).Select(p => p.Id).ToListAsync(ct);
        if (permissionIds.Count != names.Length) return false;

        await db.RolePermissions.Where(rp => rp.RoleId == roleId).ExecuteDeleteAsync(ct);
        db.RolePermissions.AddRange(permissionIds.Select(permissionId => new RolePermission { RoleId = roleId, PermissionId = permissionId }));
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return true;
    }
}
