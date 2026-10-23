using System.ComponentModel.DataAnnotations;
using DatabaseSessions.Data;

namespace DatabaseSessions.Contracts;

public sealed record RegisterRequest(
    [Required, EmailAddress, MaxLength(256)] string Email,
    [Required] string Password);

public sealed record LoginRequest(
    [Required, MaxLength(256)] string Email,
    [Required] string Password,
    [RegularExpression("^(cookie|bearer)$", ErrorMessage = "Transport must be 'cookie' or 'bearer'.")] string? Transport);

/// <summary>For cookie logins Token is null (it is in the HttpOnly cookie) and CsrfToken is set; for bearer logins the reverse.</summary>
public sealed record LoginResponse(
    Guid UserId,
    Guid SessionId,
    string Transport,
    string? Token,
    string? CsrfToken,
    DateTimeOffset IdleExpiresUtc,
    DateTimeOffset AbsoluteExpiresUtc);

public sealed record ChangePasswordRequest([Required] string CurrentPassword, [Required] string NewPassword);

public sealed record MeResponse(
    Guid UserId,
    string Email,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    Guid SessionId,
    string Transport,
    string? CsrfToken,
    DateTimeOffset AbsoluteExpiresUtc);

public sealed record SessionResponse(
    Guid Id,
    string Transport,
    DateTimeOffset CreatedUtc,
    DateTimeOffset LastSeenUtc,
    DateTimeOffset IdleExpiresUtc,
    DateTimeOffset AbsoluteExpiresUtc,
    DateTimeOffset? RevokedUtc,
    string? RevokedReason,
    string? IpAddress,
    string? UserAgent,
    bool IsCurrent)
{
    public static SessionResponse From(SessionRecord s, Guid? currentSessionId) => new(
        s.Id, s.Transport, s.CreatedUtc, s.LastSeenUtc, s.IdleExpiresUtc, s.AbsoluteExpiresUtc,
        s.RevokedUtc, s.RevokedReason, s.IpAddress, s.UserAgent, s.Id == currentSessionId);
}

public sealed record UserSummaryResponse(
    Guid Id,
    string Email,
    bool IsDisabled,
    DateTimeOffset? DisabledAtUtc,
    bool IsLockedOut,
    DateTimeOffset? LockoutEndUtc,
    DateTimeOffset CreatedUtc)
{
    public static UserSummaryResponse From(UserRecord u, DateTimeOffset now) => new(
        u.Id, u.Email, u.IsDisabled, u.DisabledAtUtc, u.IsLockedOut(now), u.LockoutEndUtc, u.CreatedUtc);
}

public sealed record UserDetailResponse(
    UserSummaryResponse User,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    int FailedLoginCount,
    DateTimeOffset PasswordChangedUtc);

public sealed record PagedResponse<T>(IReadOnlyList<T> Items, int Page, int PageSize, int Total);

public sealed record SetRolesRequest([Required, MaxLength(32)] IReadOnlyList<string> Roles);

public sealed record CreateRoleRequest(
    [Required, RegularExpression("^[A-Za-z][A-Za-z0-9_.-]{1,63}$")] string Name,
    [MaxLength(256)] string? Description);

public sealed record SetPermissionsRequest([Required, MaxLength(256)] IReadOnlyList<string> Permissions);

public sealed record RoleResponse(string Name, string? Description, bool IsSystem, IReadOnlyList<string> Permissions);
