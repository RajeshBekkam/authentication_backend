using DatabaseSessions.Data;
using DatabaseSessions.Options;
using DatabaseSessions.Security;
using Microsoft.Extensions.Options;

namespace DatabaseSessions.Services;

/// <summary>
/// Creates the first Admin from configuration (user-secrets / environment) when no Admin exists yet.
/// It never promotes an existing account, so a pre-registered email cannot be hijacked into Admin.
/// </summary>
public sealed class AdminBootstrapper(
    IOptions<BootstrapAdminOptions> options,
    UserRepository users,
    AuthService auth,
    ILogger<AdminBootstrapper> logger)
{
    public async Task RunAsync(CancellationToken ct = default)
    {
        var (email, password) = (options.Value.Email, options.Value.Password);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrEmpty(password))
        {
            logger.LogInformation("Auth:BootstrapAdmin not configured; skipping admin bootstrap.");
            return;
        }

        if (await users.CountUsersInRoleAsync(Roles.Admin, activeOnly: false, ct) > 0) return;

        if (await users.FindByNormalizedEmailAsync(CredentialRules.NormalizeEmail(email), ct) is not null)
        {
            logger.LogWarning("Bootstrap admin email {Email} already belongs to a non-admin account; not promoting it.", email);
            return;
        }

        var result = await auth.RegisterAsync(email, password, Roles.Admin, ct);
        if (result.Status == RegisterStatus.Success)
            logger.LogInformation("Bootstrap admin {Email} created.", email);
        else
            logger.LogError("Bootstrap admin could not be created: {Status} {Errors}", result.Status,
                string.Join(" ", result.Errors ?? []));
    }
}
