namespace DatabaseSessions.Data;

public sealed class UserRecord
{
    public Guid Id { get; init; }
    public string Email { get; init; } = "";
    public string NormalizedEmail { get; init; } = "";
    public string PasswordHash { get; init; } = "";
    public bool IsDisabled { get; init; }
    public DateTimeOffset? DisabledAtUtc { get; init; }
    public int FailedLoginCount { get; init; }
    public DateTimeOffset? LockoutEndUtc { get; init; }
    public DateTimeOffset PasswordChangedUtc { get; init; }
    public DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset UpdatedUtc { get; init; }

    public bool IsLockedOut(DateTimeOffset now) => LockoutEndUtc is { } end && end > now;
}

public sealed class SessionRecord
{
    public Guid Id { get; init; }
    public Guid UserId { get; init; }
    public string Transport { get; init; } = "";
    public DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset LastSeenUtc { get; init; }
    public DateTimeOffset IdleExpiresUtc { get; init; }
    public DateTimeOffset AbsoluteExpiresUtc { get; init; }
    public DateTimeOffset? RevokedUtc { get; init; }
    public string? RevokedReason { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
}

public sealed class NewSession
{
    public required Guid Id { get; init; }
    public required byte[] TokenHash { get; init; }
    public required Guid UserId { get; init; }
    public required string Transport { get; init; }
    public string? CsrfToken { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required DateTimeOffset IdleExpiresUtc { get; init; }
    public required DateTimeOffset AbsoluteExpiresUtc { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
}

/// <summary>Result of validating a presented session token: session, account and authorization data.</summary>
public sealed class ValidatedSession
{
    public required Guid SessionId { get; init; }
    public required Guid UserId { get; init; }
    public required string Email { get; init; }
    public required string Transport { get; init; }
    public string? CsrfToken { get; init; }
    public required DateTimeOffset LastSeenUtc { get; init; }
    public required DateTimeOffset AbsoluteExpiresUtc { get; init; }
    public required IReadOnlyList<string> Roles { get; init; }
    public required IReadOnlyList<string> Permissions { get; init; }
}

public sealed class RoleRecord
{
    public int Id { get; init; }
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    public bool IsSystem { get; init; }
}

public sealed class PermissionRecord
{
    public int Id { get; init; }
    public string Name { get; init; } = "";
    public string? Description { get; init; }
}

public sealed class AuditRecord
{
    public long Id { get; init; }
    public DateTimeOffset OccurredUtc { get; init; }
    public string EventType { get; init; } = "";
    public Guid? UserId { get; init; }
    public Guid? ActorUserId { get; init; }
    public Guid? SessionId { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? Details { get; init; }
}
