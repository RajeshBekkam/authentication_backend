# Database-Session Authentication Backend

ASP.NET Core (.NET 9) Web API + SQL Server + Dapper. The database is the single source of truth for
authentication, session validity, account state and authorization — every request is validated against it.

## Run

1. SQL Server must be reachable on `localhost,1433`.
2. Set your SA password (the dev connection string in `appsettings.Development.json` uses the `YOUR_SA_PASSWORD` placeholder).
   Prefer user-secrets over editing the file:
   ```powershell
   dotnet user-secrets set "ConnectionStrings:AuthDb" "Server=localhost,1433;Database=AuthDb;User Id=sa;Password=<your-sa-password>;TrustServerCertificate=True;Encrypt=True"
   dotnet user-secrets set "Auth:BootstrapAdmin:Email" "admin@example.com"
   dotnet user-secrets set "Auth:BootstrapAdmin:Password" "<a long admin passphrase>"
   ```
3. `dotnet run` — in Development the `AuthDb` database is created and `Data/Scripts/*.sql` are applied
   automatically (tracked in `dbo.SchemaVersions`). The bootstrap admin is created only if no Admin exists.
4. OpenAPI document (Development): `GET /openapi/v1.json`. Sample calls: `database_sessions.http`.

## Design

| Concern | Implementation |
|---|---|
| Passwords | Argon2id (m=19 MiB, t=2, p=1, configurable), PHC string format, transparent rehash on login when params change. 12–128 chars. |
| Session token | 256-bit random, base64url. Only its **SHA-256 hash** is stored (`auth.Sessions.TokenHash`). |
| Transports | `cookie` → `__Host-sid` cookie (HttpOnly, Secure, SameSite=Strict) + CSRF token; `bearer` → `Authorization: Bearer`. A token is only accepted on the transport it was issued for. |
| Lifetime | 30 min sliding idle timeout, 12 h absolute cap. `LastSeen` writes throttled to once per 60 s. |
| Validation | Every request: session exists, not revoked, not idle/absolute-expired, user not disabled. Roles & permissions loaded fresh — changes apply on the next request. |
| CSRF | Cookie-authenticated non-GET requests must send `X-CSRF-Token` (returned by login and `GET /api/auth/me`). |
| Concurrency cap | Max 5 active sessions/user; oldest evicted (row lock on the user serializes concurrent logins). |
| Lockout | 5 failed attempts → 15 min lockout. During lockout the password is not checked, and the response is identical to a wrong password. |
| Enumeration | Unknown users get a dummy Argon2 verify; login errors are generic. (Registration returns 409 for a taken email — inherent to open signup without email verification.) |
| Disable | Disabling an account revokes all its sessions in the same transaction. |
| AuthZ | Roles → permissions. `[HasPermission("users.read")]`; fallback policy requires auth on every endpoint. |
| Rate limit | 10 req/min per IP on register/login/change-password. |
| Audit | `auth.AuditLog` records logins, failures, lockouts, revocations, role/permission changes. |
| Cleanup | Hourly purge of sessions revoked/expired > 30 days ago. |

## Endpoints

| Method | Path | Auth |
|---|---|---|
| POST | `/api/auth/register` | anonymous |
| POST | `/api/auth/login` (`transport`: `cookie`\|`bearer`) | anonymous |
| POST | `/api/auth/logout`, `/api/auth/logout-all` | session |
| GET | `/api/auth/me` | session |
| POST | `/api/account/change-password` | session |
| GET | `/api/account/sessions` | session |
| DELETE | `/api/account/sessions/{id}` | session |
| POST | `/api/account/sessions/revoke-others` | session |
| GET | `/api/admin/users`, `/api/admin/users/{id}` | `users.read` |
| POST | `/api/admin/users/{id}/disable` \| `enable` \| `unlock` | `users.manage` |
| PUT | `/api/admin/users/{id}/roles` | `roles.assign` |
| GET | `/api/admin/users/{id}/sessions` | `sessions.read` |
| POST | `/api/admin/users/{id}/sessions/revoke-all` | `sessions.revoke` |
| DELETE | `/api/admin/sessions/{id}` | `sessions.revoke` |
| GET | `/api/admin/roles`, `/api/admin/permissions` | `roles.read` |
| POST | `/api/admin/roles`; PUT `/api/admin/roles/{name}/permissions` | `roles.manage` |
| GET | `/api/admin/audit` | `audit.read` |

Safeguards: admins cannot disable themselves or change their own roles; the last active Admin cannot be
disabled or demoted; the Admin role's permissions are immutable.

## Production notes

- Don't run as `sa`; create a least-privilege SQL login (`db_datareader`/`db_datawriter` + EXECUTE) and run
  migrations separately with an elevated login (`Database:MigrateOnStartup=false` is the default outside Development).
- Use a trusted certificate on SQL Server and drop `TrustServerCertificate=True`.
- Behind a reverse proxy, configure `ForwardedHeaders` with explicit `KnownProxies` so client IPs (rate limiting, audit) are correct.
- The `__Host-` cookie with `SameSite=Strict` assumes the browser client is same-site with the API.
  For a cross-site SPA, use bearer transport or change the SameSite mode and set `Cors:AllowedOrigins`.
