using System.Security.Claims;

namespace DatabaseSessions.Security;

public static class HttpContextExtensions
{
    private const int MaxUserAgentLength = 512;

    /// <summary>
    /// Remote IP as seen by Kestrel. If you deploy behind a reverse proxy, configure
    /// ForwardedHeadersOptions with KnownProxies/KnownNetworks; never trust X-Forwarded-For blindly.
    /// </summary>
    public static string? ClientIp(this HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString();

    public static string? ClientUserAgent(this HttpContext context)
    {
        var ua = context.Request.Headers.UserAgent.ToString();
        if (string.IsNullOrEmpty(ua)) return null;
        return ua.Length > MaxUserAgentLength ? ua[..MaxUserAgentLength] : ua;
    }
}

public static class ClaimsPrincipalExtensions
{
    public static Guid GetUserId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("Principal has no user id."));

    public static Guid GetSessionId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(AuthClaimTypes.SessionId)
            ?? throw new InvalidOperationException("Principal has no session id."));

    public static string? GetTransport(this ClaimsPrincipal user) => user.FindFirstValue(AuthClaimTypes.Transport);
}
