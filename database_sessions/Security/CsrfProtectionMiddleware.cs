using DatabaseSessions.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DatabaseSessions.Security;

/// <summary>
/// Synchronizer-token CSRF defence for cookie sessions. Any state-changing request authenticated by
/// the session cookie must echo the session's CSRF token in the X-CSRF-Token header. Bearer sessions are
/// exempt because browsers never attach the Authorization header automatically.
/// </summary>
public sealed class CsrfProtectionMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-CSRF-Token";

    public async Task InvokeAsync(HttpContext context)
    {
        if (RequiresCheck(context) &&
            context.Items[SessionAuthenticationHandler.ValidatedSessionItemKey] is ValidatedSession session)
        {
            var presented = context.Request.Headers[HeaderName].ToString();
            if (session.CsrfToken is null || string.IsNullOrEmpty(presented) ||
                !SessionTokens.FixedTimeEquals(presented, session.CsrfToken))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new ProblemDetails
                {
                    Status = StatusCodes.Status403Forbidden,
                    Title = "CSRF validation failed",
                    Detail = $"Cookie-authenticated requests that change state must include the {HeaderName} header.",
                }, options: null, contentType: "application/problem+json");
                return;
            }
        }

        await next(context);
    }

    private static bool RequiresCheck(HttpContext context)
    {
        if (HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method) ||
            HttpMethods.IsOptions(context.Request.Method) || HttpMethods.IsTrace(context.Request.Method))
        {
            return false;
        }

        if (context.User.Identity?.IsAuthenticated != true || context.User.GetTransport() != SessionTransport.Cookie)
        {
            return false;
        }

        // Anonymous endpoints (login/register) don't act on the session, so they are exempt.
        return context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is null;
    }
}
