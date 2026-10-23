using System.Security.Claims;
using System.Text.Encodings.Web;
using DatabaseSessions.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SessionOptions = DatabaseSessions.Options.SessionOptions;

namespace DatabaseSessions.Security;

/// <summary>
/// Authenticates every request against the Sessions table. The token may arrive as a
/// "Authorization: Bearer" header (bearer sessions) or as the session cookie (cookie sessions);
/// a token is only accepted over the transport it was issued for.
/// </summary>
public sealed class SessionAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    SessionRepository sessions,
    IOptions<SessionOptions> sessionOptions,
    TimeProvider clock)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string ValidatedSessionItemKey = "auth.validated-session";
    private const string FailureReasonItemKey = "auth.failure";

    private readonly SessionOptions _sessionOptions = sessionOptions.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? token;
        string transport;

        var authorization = Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authorization))
        {
            if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.NoResult();
            }
            token = authorization["Bearer ".Length..].Trim();
            transport = SessionTransport.Bearer;
        }
        else if (Request.Cookies.TryGetValue(_sessionOptions.CookieName, out var cookie))
        {
            token = cookie;
            transport = SessionTransport.Cookie;
        }
        else
        {
            return AuthenticateResult.NoResult();
        }

        if (!SessionTokens.IsWellFormed(token))
        {
            return Fail("invalid_token");
        }

        var now = clock.GetUtcNow();
        var session = await sessions.ValidateAsync(SessionTokens.Hash(token!), now, Context.RequestAborted);
        if (session is null)
        {
            return Fail("invalid_session");
        }

        if (session.Transport != transport)
        {
            return Fail("transport_mismatch");
        }

        if (now - session.LastSeenUtc >= TimeSpan.FromSeconds(_sessionOptions.TouchIntervalSeconds))
        {
            await sessions.TouchAsync(session.SessionId, now, now + _sessionOptions.IdleTimeout, Context.RequestAborted);
        }

        Context.Items[ValidatedSessionItemKey] = session;

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, session.UserId.ToString()),
            new(ClaimTypes.Name, session.Email),
            new(ClaimTypes.Email, session.Email),
            new(AuthClaimTypes.SessionId, session.SessionId.ToString()),
            new(AuthClaimTypes.Transport, session.Transport),
        };
        claims.AddRange(session.Roles.Select(r => new Claim(ClaimTypes.Role, r)));
        claims.AddRange(session.Permissions.Select(p => new Claim(AuthClaimTypes.Permission, p)));

        var identity = new ClaimsIdentity(claims, Scheme.Name, ClaimTypes.Name, ClaimTypes.Role);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    private AuthenticateResult Fail(string reason)
    {
        Context.Items[FailureReasonItemKey] = reason;
        return AuthenticateResult.Fail(reason);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // A cookie that failed validation is useless to the client; clear it.
        if (Context.Items.ContainsKey(FailureReasonItemKey) && string.IsNullOrEmpty(Request.Headers.Authorization) &&
            Request.Cookies.ContainsKey(_sessionOptions.CookieName))
        {
            SessionCookie.Delete(Response, _sessionOptions);
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "Bearer";
        await Response.WriteAsJsonAsync(new ProblemDetails
        {
            Status = StatusCodes.Status401Unauthorized,
            Title = "Unauthorized",
            Detail = "A valid session is required.",
        }, options: null, contentType: "application/problem+json");
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        await Response.WriteAsJsonAsync(new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = "Forbidden",
            Detail = "You do not have permission to perform this action.",
        }, options: null, contentType: "application/problem+json");
    }
}
