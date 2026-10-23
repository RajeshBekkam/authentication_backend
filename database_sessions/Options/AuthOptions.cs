using System.ComponentModel.DataAnnotations;

namespace DatabaseSessions.Options;

public sealed class SessionOptions
{
    public const string Section = "Auth:Session";

    [Range(1, 1440)] public int IdleTimeoutMinutes { get; set; } = 30;
    [Range(1, 720)] public int AbsoluteLifetimeHours { get; set; } = 12;
    [Range(1, 100)] public int MaxConcurrentSessions { get; set; } = 5;

    /// <summary>LastSeen/idle expiry is only written when at least this much time has passed, to limit DB writes.</summary>
    [Range(0, 600)] public int TouchIntervalSeconds { get; set; } = 60;

    /// <summary>Revoked/expired sessions are purged after this many days.</summary>
    [Range(1, 3650)] public int RetentionDays { get; set; } = 30;

    [Required] public string CookieName { get; set; } = "__Host-sid";

    public TimeSpan IdleTimeout => TimeSpan.FromMinutes(IdleTimeoutMinutes);
    public TimeSpan AbsoluteLifetime => TimeSpan.FromHours(AbsoluteLifetimeHours);
}

public sealed class LockoutOptions
{
    public const string Section = "Auth:Lockout";

    [Range(1, 100)] public int MaxFailedAttempts { get; set; } = 5;
    [Range(1, 1440)] public int LockoutMinutes { get; set; } = 15;
}

public sealed class PasswordHashingOptions
{
    public const string Section = "Auth:PasswordHashing";

    // OWASP minimum recommendation for Argon2id: m=19 MiB, t=2, p=1.
    [Range(8192, 1048576)] public int MemorySizeKiB { get; set; } = 19456;
    [Range(1, 20)] public int Iterations { get; set; } = 2;
    [Range(1, 16)] public int Parallelism { get; set; } = 1;
}

public sealed class BootstrapAdminOptions
{
    public const string Section = "Auth:BootstrapAdmin";

    public string? Email { get; set; }
    public string? Password { get; set; }
}
