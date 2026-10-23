using SessionOptions = DatabaseSessions.Options.SessionOptions;

namespace DatabaseSessions.Security;

public static class SessionCookie
{
    public static void Append(HttpResponse response, SessionOptions options, string token, DateTimeOffset absoluteExpiry) =>
        response.Cookies.Append(options.CookieName, token, Build(absoluteExpiry));

    public static void Delete(HttpResponse response, SessionOptions options) =>
        response.Cookies.Delete(options.CookieName, Build(null));

    // "__Host-" cookies must be Secure, Path=/ and have no Domain. Browsers accept Secure cookies on http://localhost.
    private static CookieOptions Build(DateTimeOffset? expires) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        IsEssential = true,
        Expires = expires,
    };
}
