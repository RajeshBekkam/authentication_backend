using DatabaseSessions.Contracts;
using DatabaseSessions.Data;
using DatabaseSessions.Security;
using DatabaseSessions.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using SessionOptions = DatabaseSessions.Options.SessionOptions;

namespace DatabaseSessions.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(AuthService auth, IOptions<SessionOptions> sessionOptions) : ControllerBase
{
    [HttpPost("register")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct)
    {
        var result = await auth.RegisterAsync(request.Email, request.Password, ct: ct);
        return result.Status switch
        {
            RegisterStatus.Success => StatusCode(StatusCodes.Status201Created, new { id = result.UserId, email = request.Email.Trim() }),
            RegisterStatus.EmailTaken => Problem(statusCode: StatusCodes.Status409Conflict, title: "Email already registered"),
            _ => ValidationProblem(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                [nameof(request.Password)] = result.Errors!.ToArray(),
            })),
        };
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var transport = request.Transport ?? SessionTransport.Cookie;
        var result = await auth.LoginAsync(request.Email, request.Password, transport,
            HttpContext.ClientIp(), HttpContext.ClientUserAgent(), ct);

        switch (result.Status)
        {
            case LoginStatus.InvalidCredentials:
                return Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Login failed",
                    detail: "Invalid email or password, or the account is temporarily locked.");
            case LoginStatus.AccountDisabled:
                return Problem(statusCode: StatusCodes.Status403Forbidden, title: "Account disabled",
                    detail: "This account has been disabled.");
        }

        // A browser that logs in while holding an old session cookie gets that session revoked
        // (prevents a fixated/planted cookie from surviving the login).
        if (User.Identity?.IsAuthenticated == true && User.GetTransport() == SessionTransport.Cookie)
        {
            await auth.LogoutAsync(User.GetUserId(), User.GetSessionId(), ct);
        }

        if (transport == SessionTransport.Cookie)
        {
            SessionCookie.Append(Response, sessionOptions.Value, result.Token!, result.AbsoluteExpiresUtc!.Value);
        }

        return Ok(new LoginResponse(
            result.UserId!.Value,
            result.SessionId!.Value,
            transport,
            transport == SessionTransport.Bearer ? result.Token : null,
            result.CsrfToken,
            result.IdleExpiresUtc!.Value,
            result.AbsoluteExpiresUtc!.Value));
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        await auth.LogoutAsync(User.GetUserId(), User.GetSessionId(), ct);
        if (User.GetTransport() == SessionTransport.Cookie) SessionCookie.Delete(Response, sessionOptions.Value);
        return NoContent();
    }

    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutAll(CancellationToken ct)
    {
        var count = await auth.LogoutEverywhereAsync(User.GetUserId(), User.GetSessionId(), ct);
        if (User.GetTransport() == SessionTransport.Cookie) SessionCookie.Delete(Response, sessionOptions.Value);
        return Ok(new { revoked = count });
    }

    /// <summary>Current user, roles, permissions and session. Cookie clients use this to (re)obtain their CSRF token.</summary>
    [HttpGet("me")]
    public IActionResult Me()
    {
        var session = (ValidatedSession)HttpContext.Items[SessionAuthenticationHandler.ValidatedSessionItemKey]!;
        return Ok(new MeResponse(
            session.UserId,
            session.Email,
            session.Roles,
            session.Permissions,
            session.SessionId,
            session.Transport,
            session.CsrfToken,
            session.AbsoluteExpiresUtc));
    }
}
