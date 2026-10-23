using DatabaseSessions.Contracts;
using DatabaseSessions.Data;
using DatabaseSessions.Security;
using DatabaseSessions.Services;
using Microsoft.AspNetCore.Mvc;

namespace DatabaseSessions.Controllers;

[ApiController]
[Route("api/admin")]
public sealed class AdminUsersController(
    UserRepository users,
    SessionRepository sessions,
    AuditLogger audit,
    TimeProvider clock) : ControllerBase
{
    [HttpGet("users")]
    [HasPermission(Permissions.UsersRead)]
    public async Task<PagedResponse<UserSummaryResponse>> ListUsers(string? search, int page = 1, int pageSize = 25,
        CancellationToken ct = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var (items, total) = await users.ListAsync(search, page, pageSize, ct);
        var now = clock.GetUtcNow();
        return new PagedResponse<UserSummaryResponse>(items.Select(u => UserSummaryResponse.From(u, now)).ToList(), page, pageSize, total);
    }

    [HttpGet("users/{userId:guid}")]
    [HasPermission(Permissions.UsersRead)]
    public async Task<IActionResult> GetUser(Guid userId, CancellationToken ct)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return NotFound();

        return Ok(new UserDetailResponse(
            UserSummaryResponse.From(user, clock.GetUtcNow()),
            await users.GetRolesAsync(userId, ct),
            await users.GetPermissionsAsync(userId, ct),
            user.FailedLoginCount,
            user.PasswordChangedUtc));
    }

    /// <summary>Disables the account and immediately revokes all of its sessions.</summary>
    [HttpPost("users/{userId:guid}/disable")]
    [HasPermission(Permissions.UsersManage)]
    public async Task<IActionResult> Disable(Guid userId, CancellationToken ct)
    {
        if (userId == User.GetUserId())
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "You cannot disable your own account");
        }

        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return NotFound();
        if (user.IsDisabled) return NoContent();

        if (await IsLastActiveAdminAsync(userId, ct))
        {
            return Problem(statusCode: StatusCodes.Status409Conflict, title: "Cannot disable the last active admin");
        }

        await users.DisableAsync(userId, clock.GetUtcNow(), ct);
        await audit.WriteAsync(AuditEvents.AccountDisabled, userId, actorUserId: User.GetUserId());
        return NoContent();
    }

    [HttpPost("users/{userId:guid}/enable")]
    [HasPermission(Permissions.UsersManage)]
    public async Task<IActionResult> Enable(Guid userId, CancellationToken ct)
    {
        if (!await users.EnableAsync(userId, clock.GetUtcNow(), ct)) return NotFound();
        await audit.WriteAsync(AuditEvents.AccountEnabled, userId, actorUserId: User.GetUserId());
        return NoContent();
    }

    [HttpPost("users/{userId:guid}/unlock")]
    [HasPermission(Permissions.UsersManage)]
    public async Task<IActionResult> Unlock(Guid userId, CancellationToken ct)
    {
        if (!await users.UnlockAsync(userId, clock.GetUtcNow(), ct)) return NotFound();
        await audit.WriteAsync(AuditEvents.AccountUnlocked, userId, actorUserId: User.GetUserId());
        return NoContent();
    }

    /// <summary>Replaces the user's roles. Takes effect on the user's very next request (no re-login needed).</summary>
    [HttpPut("users/{userId:guid}/roles")]
    [HasPermission(Permissions.RolesAssign)]
    public async Task<IActionResult> SetRoles(Guid userId, SetRolesRequest request, CancellationToken ct)
    {
        if (userId == User.GetUserId())
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "You cannot change your own roles");
        }

        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return NotFound();

        var roles = request.Roles.Select(r => r.Trim()).Where(r => r.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var previous = await users.GetRolesAsync(userId, ct);

        var losesAdmin = previous.Contains(Roles.Admin, StringComparer.OrdinalIgnoreCase) &&
                         !roles.Contains(Roles.Admin, StringComparer.OrdinalIgnoreCase);
        if (losesAdmin && await IsLastActiveAdminAsync(userId, ct))
        {
            return Problem(statusCode: StatusCodes.Status409Conflict, title: "Cannot remove the last active admin");
        }

        if (!await users.SetRolesAsync(userId, roles, ct))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "One or more roles do not exist");
        }

        await audit.WriteAsync(AuditEvents.RolesChanged, userId, details: new { from = previous, to = roles },
            actorUserId: User.GetUserId());
        return NoContent();
    }

    [HttpGet("users/{userId:guid}/sessions")]
    [HasPermission(Permissions.SessionsRead)]
    public async Task<IEnumerable<SessionResponse>> ListUserSessions(Guid userId, CancellationToken ct)
    {
        var current = User.GetSessionId();
        var list = await sessions.ListActiveForUserAsync(userId, clock.GetUtcNow(), ct);
        return list.Select(s => SessionResponse.From(s, current));
    }

    [HttpPost("users/{userId:guid}/sessions/revoke-all")]
    [HasPermission(Permissions.SessionsRevoke)]
    public async Task<IActionResult> RevokeAllUserSessions(Guid userId, CancellationToken ct)
    {
        var count = await sessions.RevokeAllForUserAsync(userId, "revoked_by_admin", clock.GetUtcNow(), ct: ct);
        await audit.WriteAsync(AuditEvents.SessionsRevokedAll, userId, details: new { count, reason = "admin" },
            actorUserId: User.GetUserId());
        return Ok(new { revoked = count });
    }

    [HttpDelete("sessions/{sessionId:guid}")]
    [HasPermission(Permissions.SessionsRevoke)]
    public async Task<IActionResult> RevokeSession(Guid sessionId, CancellationToken ct)
    {
        var session = await sessions.FindByIdAsync(sessionId, ct);
        if (session is null) return NotFound();
        if (session.RevokedUtc is not null) return NoContent();

        await sessions.RevokeAsync(sessionId, "revoked_by_admin", clock.GetUtcNow(), ct: ct);
        await audit.WriteAsync(AuditEvents.SessionRevoked, session.UserId, sessionId, new { by = "admin" },
            actorUserId: User.GetUserId());
        return NoContent();
    }

    [HttpGet("audit")]
    [HasPermission(Permissions.AuditRead)]
    public Task<IReadOnlyList<AuditRecord>> Audit([FromServices] AuditRepository auditLog, Guid? userId, string? eventType,
        int page = 1, int pageSize = 50, CancellationToken ct = default) =>
        auditLog.QueryAsync(userId, eventType, Math.Max(page, 1), Math.Clamp(pageSize, 1, 200), ct);

    private async Task<bool> IsLastActiveAdminAsync(Guid userId, CancellationToken ct)
    {
        var roles = await users.GetRolesAsync(userId, ct);
        return roles.Contains(Roles.Admin, StringComparer.OrdinalIgnoreCase) &&
               await users.CountUsersInRoleAsync(Roles.Admin, activeOnly: true, ct) <= 1;
    }
}
