using System.Text.Json;
using DatabaseSessions.Data;
using DatabaseSessions.Security;

namespace DatabaseSessions.Services;

public static class AuditEvents
{
    public const string UserRegistered = "user.registered";
    public const string LoginSucceeded = "login.succeeded";
    public const string LoginFailed = "login.failed";
    public const string LoginBlockedLockedOut = "login.blocked_locked_out";
    public const string LoginBlockedDisabled = "login.blocked_disabled";
    public const string AccountLockedOut = "account.locked_out";
    public const string AccountDisabled = "account.disabled";
    public const string AccountEnabled = "account.enabled";
    public const string AccountUnlocked = "account.unlocked";
    public const string PasswordChanged = "password.changed";
    public const string PasswordChangeFailed = "password.change_failed";
    public const string Logout = "session.logout";
    public const string SessionRevoked = "session.revoked";
    public const string SessionsRevokedAll = "session.revoked_all";
    public const string SessionEvicted = "session.evicted";
    public const string RolesChanged = "user.roles_changed";
    public const string RoleCreated = "role.created";
    public const string RolePermissionsChanged = "role.permissions_changed";
}

/// <summary>Writes security events to auth.AuditLog. Failures are logged and never break the request.</summary>
public sealed class AuditLogger(
    AuditRepository repository,
    IHttpContextAccessor httpContextAccessor,
    TimeProvider clock,
    ILogger<AuditLogger> logger)
{
    public async Task WriteAsync(string eventType, Guid? userId = null, Guid? sessionId = null, object? details = null,
        Guid? actorUserId = null)
    {
        var http = httpContextAccessor.HttpContext;
        var record = new AuditLogEntry
        {
            OccurredUtc = clock.GetUtcNow(),
            EventType = eventType,
            UserId = userId,
            ActorUserId = actorUserId,
            SessionId = sessionId,
            IpAddress = http?.ClientIp(),
            UserAgent = http?.ClientUserAgent(),
            Details = details is null ? null : Truncate(JsonSerializer.Serialize(details), 2000),
        };

        try
        {
            await repository.InsertAsync(record);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to write audit event {EventType} for user {UserId}", eventType, userId);
        }
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}
