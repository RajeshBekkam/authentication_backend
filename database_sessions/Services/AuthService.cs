using DatabaseSessions.Data;
using DatabaseSessions.Options;
using DatabaseSessions.Security;
using Microsoft.Extensions.Options;
using SessionOptions = DatabaseSessions.Options.SessionOptions;

namespace DatabaseSessions.Services;

public enum LoginStatus
{
    Success,
    InvalidCredentials,
    AccountDisabled,
}

public sealed record LoginResult(
    LoginStatus Status,
    Guid? UserId = null,
    Guid? SessionId = null,
    string? Token = null,
    string? CsrfToken = null,
    DateTimeOffset? IdleExpiresUtc = null,
    DateTimeOffset? AbsoluteExpiresUtc = null);

public enum RegisterStatus
{
    Success,
    EmailTaken,
    InvalidPassword,
}

public sealed record RegisterResult(RegisterStatus Status, Guid? UserId = null, IReadOnlyList<string>? Errors = null);

public enum ChangePasswordStatus
{
    Success,
    WrongCurrentPassword,
    InvalidNewPassword,
}

public sealed record ChangePasswordResult(ChangePasswordStatus Status, IReadOnlyList<string>? Errors = null);

public sealed class AuthService(
    UserRepository users,
    SessionRepository sessions,
    Argon2PasswordHasher hasher,
    AuditLogger audit,
    IOptions<SessionOptions> sessionOptions,
    IOptions<LockoutOptions> lockoutOptions,
    TimeProvider clock)
{
    private readonly SessionOptions _session = sessionOptions.Value;
    private readonly LockoutOptions _lockout = lockoutOptions.Value;

    public async Task<RegisterResult> RegisterAsync(string email, string password, string roleName = Roles.User,
        CancellationToken ct = default)
    {
        email = email.Trim();
        var errors = CredentialRules.ValidatePassword(password, email);
        if (errors.Count > 0) return new RegisterResult(RegisterStatus.InvalidPassword, Errors: errors);

        var id = Guid.CreateVersion7();
        var hash = await hasher.HashAsync(password);
        var created = await users.CreateAsync(id, email, CredentialRules.NormalizeEmail(email), hash, roleName, clock.GetUtcNow(), ct);
        if (!created) return new RegisterResult(RegisterStatus.EmailTaken);

        await audit.WriteAsync(AuditEvents.UserRegistered, id, details: new { role = roleName });
        return new RegisterResult(RegisterStatus.Success, id);
    }

    public async Task<LoginResult> LoginAsync(string email, string password, string transport, string? ipAddress,
        string? userAgent, CancellationToken ct = default)
    {
        // Oversized passwords are rejected without hashing (they could never have been set).
        if (password.Length > CredentialRules.MaxPasswordLength)
        {
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        var now = clock.GetUtcNow();
        var user = await users.FindByNormalizedEmailAsync(CredentialRules.NormalizeEmail(email), ct);

        if (user is null)
        {
            await hasher.SimulateVerifyAsync(password);
            await audit.WriteAsync(AuditEvents.LoginFailed, details: new { reason = "unknown_user" });
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        // While locked out the password is not checked at all, so a correct guess during
        // lockout is indistinguishable from a wrong one.
        if (user.IsLockedOut(now))
        {
            await hasher.SimulateVerifyAsync(password);
            await audit.WriteAsync(AuditEvents.LoginBlockedLockedOut, user.Id);
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        var verification = await hasher.VerifyAsync(user.PasswordHash, password);
        if (verification == PasswordVerification.Failed)
        {
            var lockedOut = await users.RegisterFailedLoginAsync(
                user.Id, _lockout.MaxFailedAttempts, now.AddMinutes(_lockout.LockoutMinutes), now, ct);
            await audit.WriteAsync(AuditEvents.LoginFailed, user.Id, details: new { reason = "bad_password" });
            if (lockedOut)
            {
                await audit.WriteAsync(AuditEvents.AccountLockedOut, user.Id, details: new { minutes = _lockout.LockoutMinutes });
            }
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        if (user.IsDisabled)
        {
            await audit.WriteAsync(AuditEvents.LoginBlockedDisabled, user.Id);
            return new LoginResult(LoginStatus.AccountDisabled);
        }

        var rehash = verification == PasswordVerification.SuccessRehashNeeded ? await hasher.HashAsync(password) : null;
        await users.RecordSuccessfulLoginAsync(user.Id, rehash, now, ct);

        var token = SessionTokens.Generate();
        var csrf = transport == SessionTransport.Cookie ? SessionTokens.GenerateCsrfToken() : null;
        var absolute = now + _session.AbsoluteLifetime;
        var idle = Min(now + _session.IdleTimeout, absolute);
        var sessionId = Guid.CreateVersion7();

        var evicted = await sessions.CreateAsync(new UserSession
        {
            Id = sessionId,
            TokenHash = SessionTokens.Hash(token),
            UserId = user.Id,
            Transport = transport,
            CsrfToken = csrf,
            CreatedUtc = now,
            LastSeenUtc = now,
            IdleExpiresUtc = idle,
            AbsoluteExpiresUtc = absolute,
            IpAddress = ipAddress,
            UserAgent = userAgent,
        }, _session.MaxConcurrentSessions, ct);

        if (evicted is null)
        {
            // Account was disabled between the password check and session creation.
            await audit.WriteAsync(AuditEvents.LoginBlockedDisabled, user.Id);
            return new LoginResult(LoginStatus.AccountDisabled);
        }

        foreach (var evictedId in evicted)
        {
            await audit.WriteAsync(AuditEvents.SessionEvicted, user.Id, evictedId, new { reason = "session_limit" });
        }
        await audit.WriteAsync(AuditEvents.LoginSucceeded, user.Id, sessionId, new { transport });

        return new LoginResult(LoginStatus.Success, user.Id, sessionId, token, csrf, idle, absolute);
    }

    public async Task LogoutAsync(Guid userId, Guid sessionId, CancellationToken ct = default)
    {
        if (await sessions.RevokeAsync(sessionId, "logout", clock.GetUtcNow(), userId, ct))
        {
            await audit.WriteAsync(AuditEvents.Logout, userId, sessionId);
        }
    }

    public async Task<int> LogoutEverywhereAsync(Guid userId, Guid currentSessionId, CancellationToken ct = default)
    {
        var count = await sessions.RevokeAllForUserAsync(userId, "logout_all", clock.GetUtcNow(), ct: ct);
        await audit.WriteAsync(AuditEvents.SessionsRevokedAll, userId, currentSessionId, new { count, reason = "logout_all" });
        return count;
    }

    /// <summary>Changes the password and revokes every other session of the user.</summary>
    public async Task<ChangePasswordResult> ChangePasswordAsync(Guid userId, Guid currentSessionId, string currentPassword,
        string newPassword, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct) ?? throw new InvalidOperationException("Authenticated user not found.");

        if (currentPassword.Length > CredentialRules.MaxPasswordLength ||
            await hasher.VerifyAsync(user.PasswordHash, currentPassword) == PasswordVerification.Failed)
        {
            await audit.WriteAsync(AuditEvents.PasswordChangeFailed, userId, currentSessionId);
            return new ChangePasswordResult(ChangePasswordStatus.WrongCurrentPassword);
        }

        var errors = CredentialRules.ValidatePassword(newPassword, user.Email);
        if (errors.Count > 0) return new ChangePasswordResult(ChangePasswordStatus.InvalidNewPassword, errors);

        var now = clock.GetUtcNow();
        await users.ChangePasswordAsync(userId, await hasher.HashAsync(newPassword), now, ct);
        var revoked = await sessions.RevokeAllForUserAsync(userId, "password_changed", now, currentSessionId, ct);
        await audit.WriteAsync(AuditEvents.PasswordChanged, userId, currentSessionId, new { otherSessionsRevoked = revoked });
        return new ChangePasswordResult(ChangePasswordStatus.Success);
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;
}
