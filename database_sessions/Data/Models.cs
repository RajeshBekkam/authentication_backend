namespace DatabaseSessions.Data;

public sealed class UserAccount
{
    public Guid Id { get; set; }
    public string Email { get; set; } = "";
    public string NormalizedEmail { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool IsDisabled { get; set; }
    public DateTimeOffset? DisabledAtUtc { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTimeOffset? LockoutEndUtc { get; set; }
    public DateTimeOffset PasswordChangedUtc { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }

    public List<UserRole> UserRoles { get; set; } = [];
    public List<UserSession> Sessions { get; set; } = [];

    public bool IsLockedOut(DateTimeOffset now) => LockoutEndUtc is { } end && end > now;
}

public sealed class Role
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public bool IsSystem { get; set; }

    public List<UserRole> UserRoles { get; set; } = [];
    public List<RolePermission> RolePermissions { get; set; } = [];
}

public sealed class Permission
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string? Description { get; set; }

    public List<RolePermission> RolePermissions { get; set; } = [];
}

public sealed class UserRole
{
    public Guid UserId { get; set; }
    public UserAccount User { get; set; } = null!;
    public int RoleId { get; set; }
    public Role Role { get; set; } = null!;
}

public sealed class RolePermission
{
    public int RoleId { get; set; }
    public Role Role { get; set; } = null!;
    public int PermissionId { get; set; }
    public Permission Permission { get; set; } = null!;
}

/// <summary>A database-backed session. The raw token is never stored; only its SHA-256 hash.</summary>
public sealed class UserSession
{
    public Guid Id { get; set; }
    public byte[] TokenHash { get; set; } = [];
    public Guid UserId { get; set; }
    public UserAccount User { get; set; } = null!;
    public string Transport { get; set; } = "";
    public string? CsrfToken { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public DateTimeOffset IdleExpiresUtc { get; set; }
    public DateTimeOffset AbsoluteExpiresUtc { get; set; }
    public DateTimeOffset? RevokedUtc { get; set; }
    public string? RevokedReason { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

public sealed class AuditLogEntry
{
    public long Id { get; set; }
    public DateTimeOffset OccurredUtc { get; set; }
    public string EventType { get; set; } = "";
    public Guid? UserId { get; set; }
    public Guid? ActorUserId { get; set; }
    public Guid? SessionId { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Details { get; set; }
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

public sealed record RoleWithPermissions(string Name, string? Description, bool IsSystem, IReadOnlyList<string> Permissions);
