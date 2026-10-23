using DatabaseSessions.Contracts;
using DatabaseSessions.Data;
using DatabaseSessions.Security;
using DatabaseSessions.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace DatabaseSessions.Controllers;

[ApiController]
[Route("api/account")]
public sealed class AccountController(
    AuthService auth,
    SessionRepository sessions,
    AuditLogger audit,
    TimeProvider clock) : ControllerBase
{
    [HttpPost("change-password")]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest request, CancellationToken ct)
    {
        var result = await auth.ChangePasswordAsync(User.GetUserId(), User.GetSessionId(), request.CurrentPassword, request.NewPassword, ct);
        return result.Status switch
        {
            ChangePasswordStatus.Success => NoContent(),
            ChangePasswordStatus.WrongCurrentPassword => Problem(statusCode: StatusCodes.Status400BadRequest,
                title: "Current password is incorrect"),
            _ => ValidationProblem(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                [nameof(request.NewPassword)] = result.Errors!.ToArray(),
            })),
        };
    }

    [HttpGet("sessions")]
    public async Task<IEnumerable<SessionResponse>> ListSessions(CancellationToken ct)
    {
        var current = User.GetSessionId();
        var list = await sessions.ListActiveForUserAsync(User.GetUserId(), clock.GetUtcNow(), ct);
        return list.Select(s => SessionResponse.From(s, current));
    }

    [HttpDelete("sessions/{sessionId:guid}")]
    public async Task<IActionResult> RevokeSession(Guid sessionId, CancellationToken ct)
    {
        var userId = User.GetUserId();
        // Scoped to the caller's own sessions; someone else's session id simply yields 404.
        if (!await sessions.RevokeAsync(sessionId, "revoked_by_user", clock.GetUtcNow(), userId, ct))
        {
            return NotFound();
        }

        await audit.WriteAsync(AuditEvents.SessionRevoked, userId, sessionId, new { by = "self" }, actorUserId: userId);
        return NoContent();
    }

    [HttpPost("sessions/revoke-others")]
    public async Task<IActionResult> RevokeOtherSessions(CancellationToken ct)
    {
        var userId = User.GetUserId();
        var current = User.GetSessionId();
        var count = await sessions.RevokeAllForUserAsync(userId, "revoked_by_user", clock.GetUtcNow(), current, ct);
        await audit.WriteAsync(AuditEvents.SessionsRevokedAll, userId, current, new { count, reason = "revoke_others" }, userId);
        return Ok(new { revoked = count });
    }
}
