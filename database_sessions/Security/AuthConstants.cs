namespace DatabaseSessions.Security;

public static class AuthSchemes
{
    public const string Session = "Session";
}

public static class AuthClaimTypes
{
    public const string SessionId = "sid";
    public const string Permission = "perm";
    public const string Transport = "transport";
}

public static class SessionTransport
{
    public const string Cookie = "cookie";
    public const string Bearer = "bearer";
}

public static class Roles
{
    public const string Admin = "Admin";
    public const string User = "User";
}

public static class Permissions
{
    public const string UsersRead = "users.read";
    public const string UsersManage = "users.manage";
    public const string RolesRead = "roles.read";
    public const string RolesManage = "roles.manage";
    public const string RolesAssign = "roles.assign";
    public const string SessionsRead = "sessions.read";
    public const string SessionsRevoke = "sessions.revoke";
    public const string AuditRead = "audit.read";
}

public static class RateLimitPolicies
{
    public const string Auth = "auth";
}
