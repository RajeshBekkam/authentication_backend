using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace DatabaseSessions.Security;

/// <summary>Requires the current session's user to hold the given permission (resolved from the DB per request).</summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class HasPermissionAttribute(string permission) : AuthorizeAttribute(PolicyPrefix + permission)
{
    public const string PolicyPrefix = "perm:";
}

/// <summary>Builds "perm:&lt;name&gt;" policies on demand so permissions need no up-front registration.</summary>
public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options) : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallback = new(options);

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(HasPermissionAttribute.PolicyPrefix, StringComparison.Ordinal))
        {
            var permission = policyName[HasPermissionAttribute.PolicyPrefix.Length..];
            return Task.FromResult<AuthorizationPolicy?>(new AuthorizationPolicyBuilder(AuthSchemes.Session)
                .RequireAuthenticatedUser()
                .RequireClaim(AuthClaimTypes.Permission, permission)
                .Build());
        }

        return _fallback.GetPolicyAsync(policyName);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();
}
