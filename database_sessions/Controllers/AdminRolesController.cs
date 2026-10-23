using DatabaseSessions.Contracts;
using DatabaseSessions.Data;
using DatabaseSessions.Security;
using DatabaseSessions.Services;
using Microsoft.AspNetCore.Mvc;

namespace DatabaseSessions.Controllers;

[ApiController]
[Route("api/admin")]
public sealed class AdminRolesController(RoleRepository roles, AuditLogger audit) : ControllerBase
{
    [HttpGet("roles")]
    [HasPermission(Permissions.RolesRead)]
    public async Task<IEnumerable<RoleResponse>> ListRoles(CancellationToken ct) =>
        (await roles.ListWithPermissionsAsync(ct))
            .Select(x => new RoleResponse(x.Role.Name, x.Role.Description, x.Role.IsSystem, x.Permissions));

    [HttpGet("permissions")]
    [HasPermission(Permissions.RolesRead)]
    public Task<IReadOnlyList<PermissionRecord>> ListPermissions(CancellationToken ct) => roles.ListPermissionsAsync(ct);

    [HttpPost("roles")]
    [HasPermission(Permissions.RolesManage)]
    public async Task<IActionResult> CreateRole(CreateRoleRequest request, CancellationToken ct)
    {
        if (!await roles.CreateAsync(request.Name, request.Description, ct))
        {
            return Problem(statusCode: StatusCodes.Status409Conflict, title: "Role already exists");
        }

        await audit.WriteAsync(AuditEvents.RoleCreated, details: new { role = request.Name }, actorUserId: User.GetUserId());
        return StatusCode(StatusCodes.Status201Created, new RoleResponse(request.Name, request.Description, false, []));
    }

    /// <summary>Replaces a role's permissions. The Admin role is immutable so it can never lose access.</summary>
    [HttpPut("roles/{name}/permissions")]
    [HasPermission(Permissions.RolesManage)]
    public async Task<IActionResult> SetPermissions(string name, SetPermissionsRequest request, CancellationToken ct)
    {
        var role = await roles.FindByNameAsync(name, ct);
        if (role is null) return NotFound();
        if (string.Equals(role.Name, Roles.Admin, StringComparison.OrdinalIgnoreCase))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "The Admin role's permissions cannot be changed");
        }

        var permissions = request.Permissions.Select(p => p.Trim()).Where(p => p.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (!await roles.SetPermissionsAsync(role.Id, permissions, ct))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "One or more permissions do not exist");
        }

        await audit.WriteAsync(AuditEvents.RolePermissionsChanged, details: new { role = role.Name, permissions },
            actorUserId: User.GetUserId());
        return NoContent();
    }
}
