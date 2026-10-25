# PRD — React Frontend for the Database-Session Auth Backend

| | |
|---|---|
| **Status** | Draft |
| **Owner** | Rajesh Bekkam |
| **Date** | 2026-10-23 |
| **Backend** | `database_sessions` (ASP.NET Core 9 Web API, SQL Server, DB-backed sessions) |

---

## 1. Summary

Build a React single-page app for the existing authentication backend. End users can register, sign in, manage their password and sessions. Administrators can manage users, roles, permissions and sessions, and review the security audit log.

**The backend is the source of truth.** The frontend never decides whether a user is authenticated or authorized. It reflects what the API says and gets out of the way when the API says no. UI permission checks exist only to hide controls that would fail; they are not security.

## 2. Goals and non-goals

### Goals
1. Ship a secure browser client that uses the **cookie transport** (HttpOnly `__Host-sid` cookie + CSRF token).
2. Cover every backend endpoint that is relevant to a human user (Section 7).
3. Handle session expiry, revocation, account disable, lockout, rate limiting and permission changes cleanly, with no stale "logged-in" UI.
4. Permission-driven navigation: admins see admin screens; users without a permission never see the matching controls.

### Non-goals
- Email verification, forgot/reset password, MFA. The backend doesn't support them.
- Bearer-token transport in the browser. The app must **never** request `"transport": "bearer"` or store a session token.
- Mobile or native apps, SSR, i18n (v1), theming beyond light/dark.
- Any backend changes, except the optional items in Section 12.

## 3. Users and roles

| Persona | Backend role | Needs |
|---|---|---|
| **End user** | `User` | Register, log in or out, see their account, change their password, see and revoke their sessions. |
| **Administrator** | `Admin` (all permissions) | Everything above, plus user, role, session and audit management. |
| **Delegated operator** | Custom role with a subset of permissions | Only the admin screens their permissions allow. |

Permissions defined by the backend:

| Permission | Unlocks |
|---|---|
| `users.read` | User list, user detail |
| `users.manage` | Disable / enable / unlock a user |
| `roles.assign` | Change a user's roles |
| `roles.read` | Roles and permissions screens |
| `roles.manage` | Create a role, edit a role's permissions |
| `sessions.read` | View any user's sessions |
| `sessions.revoke` | Revoke any session, or all of a user's sessions |
| `audit.read` | Audit log |

## 4. Technical approach

### 4.1 Stack (recommended)
- **React 18+ with TypeScript (strict)** and **Vite**
- **React Router** for routing and route guards
- **TanStack Query** for all server state. Do not mirror auth state in Redux/Zustand.
- **React Hook Form + Zod** for forms and client-side validation
- A component library of the team's choice (e.g. MUI, Mantine or shadcn/ui), used consistently
- **Vitest + React Testing Library + MSW** for unit and integration tests, **Playwright** for end-to-end tests against the real backend

### 4.2 Hosting topology: same origin
The session cookie is `__Host-sid; Secure; HttpOnly; SameSite=Strict; Path=/`. To keep the cookie and CSRF model simple, the SPA and the API must be served from the **same origin**:

- **Development:** the Vite dev server proxies `/api` to `http://localhost:5154`, so the browser only sees `http://localhost:5173`.
  ```ts
  // vite.config.ts
  server: { proxy: { '/api': { target: 'http://localhost:5154', changeOrigin: false } } }
  ```
- **Production:** a reverse proxy serves the static build and `/api/*` on one HTTPS origin.
- Use Chrome or Firefox for local development; they accept `Secure` cookies on `http://localhost`. Safari may not; use HTTPS (`https://localhost:7164` behind the proxy) if needed.
- Do **not** configure the backend's `Cors:AllowedOrigins` unless the deployment truly needs to be cross-origin.

### 4.3 HTTP client contract
A single `apiFetch` wrapper is the only place that talks to the API. It must:

1. Use relative URLs (`/api/...`) and `credentials: 'same-origin'`.
2. Send `Content-Type: application/json` for request bodies.
3. Attach `X-CSRF-Token: <csrfToken>` on every **POST, PUT and DELETE** when a CSRF token is held.
4. Parse error bodies as RFC 7807 ProblemDetails (`{ status, title, detail, errors? }`).
5. Apply the global error handling in Section 6.

### 4.4 Auth state model
- **Source of truth:** `GET /api/auth/me`, cached by TanStack Query under the key `['me']`.
- On app boot, call `/me`.
  - `200`: authenticated. Store `csrfToken` from the response **in memory only**.
  - `401`: anonymous.
- **The CSRF token is never written to `localStorage`, `sessionStorage` or a JS-readable cookie.** After a page reload it is re-fetched from `/me`.
- **The session token is never visible to JS.** It lives only in the HttpOnly cookie.
- After login, logout, password change or any role-affecting action, invalidate or refetch `['me']`.
- Because the backend reloads roles and permissions on every request, refetch `['me']` on window focus so the UI notices permission changes promptly.

## 5. Functional requirements

### 5.1 Public screens

**FR-1: Register (`/register`)**
- Fields: email, password, confirm password.
- Client validation mirrors the backend:
  - valid email, at most 256 characters
  - password 12–128 characters
  - password not equal to the email
  - password has at least 4 distinct characters
- Show a password-strength hint; do not invent composition rules.
- `POST /api/auth/register`, with these outcomes:
  - `201`: go to `/login?registered=1` with a success banner.
  - `409`: "An account with this email already exists."
  - `400`: map `errors.Password[]` (and any other `errors` keys) onto fields.
  - `429`: rate-limit message (Section 6).

**FR-2: Login (`/login`)**
- Fields: email, password. The body always includes `"transport": "cookie"`.
- `POST /api/auth/login`, with these outcomes:
  - `200`: store `csrfToken` in memory, set `['me']`, then redirect to the `returnTo` query param (same-app paths only; reject absolute or external URLs) or `/`.
  - `401`: show exactly: *"Invalid email or password, or the account is temporarily locked."* Do not try to tell the two cases apart.
  - `403` (title "Account disabled"): "This account has been disabled. Contact an administrator."
  - `429`: rate-limit message with a countdown from `Retry-After`.
- Disable the submit button while the request is pending; never auto-retry a login.
- Clear the password field after any failure.

### 5.2 Authenticated user screens
All routes below require an authenticated `['me']`; otherwise redirect to `/login?returnTo=…`.

**FR-3: App shell**
- Top bar: user email and a menu with Account, Sessions and Sign out.
- Side navigation: admin entries appear only if the user holds the matching permission (Section 3).

**FR-4: Home (`/`)**
- Welcome view showing the email, roles, and the current session's absolute expiry ("Session ends at …").

**FR-5: Account (`/account`)**
- Read-only: email, roles, permissions (collapsible).
- **Change password** form with current password, new password and confirm:
  - `POST /api/account/change-password`
  - `204`: success toast "Password changed. All other sessions were signed out." Then refetch the sessions list.
  - `400` with title "Current password is incorrect": show an error on the current-password field.
  - `400` with `errors.NewPassword[]`: show the messages on the new-password field.
  - `429`: rate-limit message.

**FR-6: My sessions (`/account/sessions`)**
- `GET /api/account/sessions` returns a table with: device (parsed from `userAgent`), IP, created, last seen, idle expiry, absolute expiry.
- The current session is labeled "This device" (`isCurrent: true`).
- **Revoke** per row: `DELETE /api/account/sessions/{id}`, after a confirm dialog.
  - Revoking the current session behaves like Sign out.
  - `404`: refresh the list, since the session was already gone.
- **Sign out all other sessions**: `POST /api/account/sessions/revoke-others`. Show "N sessions signed out."
- **Sign out everywhere**: `POST /api/auth/logout-all`, then go to `/login`.
- Note under the table: *"You can be signed in on up to 5 devices. Signing in on a 6th signs out the oldest."*

**FR-7: Sign out**
- `POST /api/auth/logout` (with the CSRF header). Then, regardless of the result:
  - clear the in-memory CSRF token
  - `queryClient.clear()`
  - navigate to `/login`

### 5.3 Admin screens
Each route is guarded by its permission. Without the permission, the route renders a 403 page; it does not redirect to login.

**FR-8: Users list (`/admin/users`, `users.read`)**
- `GET /api/admin/users?search=&page=&pageSize=` returns `{ items, page, pageSize, total }`.
- Debounced (300 ms) email search, server-side pagination (page size 25, maximum 100).
- Columns: email, status badge (Active, Disabled, Locked until hh:mm), created.

**FR-9: User detail (`/admin/users/:id`, `users.read`)**
- `GET /api/admin/users/{id}` returns `{ user, roles, permissions, failedLoginCount, passwordChangedUtc }`.
- **Account actions** (need `users.manage`), each behind a confirm dialog:
  - **Disable**: `POST …/disable`. Warn: "This immediately signs the user out everywhere."
  - **Enable**: `POST …/enable`.
  - **Unlock**: `POST …/unlock`. Shown only when the user is locked out.
  - Error mapping:
    - `400`: cannot disable yourself. Also hide the Disable button on your own record.
    - `409`: cannot disable the last active admin.
- **Roles editor** (needs `roles.assign`):
  - Multi-select of all roles from `GET /api/admin/roles` (that list needs `roles.read`; if the user lacks it, show the current roles read-only).
  - Save with `PUT …/roles` and body `{ roles: [...] }`.
  - Hidden on your own record (the backend returns `400`). `409` means the last admin can't be demoted.
  - Info text: "Changes take effect on the user's next request. No re-login needed."
- **Sessions panel** (needs `sessions.read`):
  - `GET …/sessions`, same table as FR-6.
  - Per-row revoke: `DELETE /api/admin/sessions/{sessionId}`.
  - "Revoke all": `POST …/sessions/revoke-all`.
  - Both revoke actions need `sessions.revoke`.

**FR-10: Roles and permissions (`/admin/roles`, `roles.read`)**
- `GET /api/admin/roles` and `GET /api/admin/permissions`.
- Matrix view: roles as rows, permissions as columns, with descriptions shown in a tooltip.
- **Create role** (needs `roles.manage`):
  - Name matches `^[A-Za-z][A-Za-z0-9_.-]{1,63}$`; optional description.
  - `409`: "Role already exists."
- **Edit permissions** (needs `roles.manage`): checkbox editing, saved with `PUT /api/admin/roles/{name}/permissions`.
  - The **Admin** row is read-only, with a lock icon and the tooltip "The Admin role always has every permission."
  - System roles (`isSystem`) get a badge.

**FR-11: Audit log (`/admin/audit`, `audit.read`)**
- `GET /api/admin/audit?userId=&eventType=&page=&pageSize=50`.
- Filters:
  - event type, a select of the known events listed below
  - user id, pre-filled when opened from a user's detail page
- Columns: time, event, subject user (linked), actor user (linked), session id (shortened), IP, user agent, details.
- `details` arrives as a **JSON string**. Parse it safely, show it pretty-printed in an expandable row, and never render it as HTML.
- The endpoint returns no total, so use a "Load more" control that stops when a page returns fewer than `pageSize` rows.
- Known event types:
  - `user.registered`
  - `login.succeeded`, `login.failed`, `login.blocked_locked_out`, `login.blocked_disabled`
  - `account.locked_out`, `account.disabled`, `account.enabled`, `account.unlocked`
  - `password.changed`, `password.change_failed`
  - `session.logout`, `session.revoked`, `session.revoked_all`, `session.evicted`
  - `user.roles_changed`, `role.created`, `role.permissions_changed`

## 6. Cross-cutting behaviour

### 6.1 Global error handling (in `apiFetch`)

| Response | Meaning | Frontend behaviour |
|---|---|---|
| `401` on any call except login | The session is invalid, expired, revoked or disabled. | 1. Clear the query cache and CSRF token.<br>2. Redirect to `/login?returnTo=<current>&reason=expired`.<br>3. Login shows "Your session has ended. Please sign in again." |
| `403` with title `CSRF validation failed` | The CSRF token is missing or stale. | 1. Refetch `/me` to get a fresh token.<br>2. Retry the original request **once**.<br>3. If it fails again, treat it as `401`. |
| `403` (other) | Missing permission. | Toast "You don't have permission to do that." Refetch `['me']`, since permissions may have changed, which updates the navigation. |
| `404` on admin detail routes | The resource was not found. | Show a not-found state. |
| `409` | Business-rule conflict. | Show `title` inline next to the action. |
| `429` | Rate limited. | Show "Too many attempts. Try again in N s." using `Retry-After`, and disable the submit button until then. |
| `5xx` or network error | Server or network failure. | Generic error toast; leave the form state intact; allow a manual retry. |

### 6.2 Session lifetime UX
- The server enforces a **30-minute idle timeout** (sliding) and a **12-hour absolute lifetime**. The client does not enforce either; it only informs the user.
- Track the time of the last successful API call. After 25 minutes without one, show a modal: "You'll be signed out soon due to inactivity", with **Stay signed in** (calls `/me`) and **Sign out**.
- Within 10 minutes of `absoluteExpiresUtc`, show a non-blocking banner: "Your session ends at hh:mm. Save your work."
- Multi-tab: use a `BroadcastChannel('auth')` to broadcast `logout` and `login`, so every tab clears state or refetches `/me` together.

### 6.3 Security requirements
- **SR-1:** No tokens in web storage. The CSRF token is held in memory only, and the session token is never accessible to JS.
- **SR-2:** Never use `dangerouslySetInnerHTML` with API data (emails, user agents, audit details, role descriptions).
- **SR-3:** Accept the `returnTo` redirect only when it is a relative path starting with a single `/`.
- **SR-4:** Production build: no source maps published publicly, and no secrets in `VITE_*` env vars.
- **SR-5:** The reverse proxy serving the SPA sets a CSP of `default-src 'self'; frame-ancestors 'none'; object-src 'none'`. (The API already sends its own restrictive headers.)
- **SR-6:** Password fields use `autocomplete="current-password"` or `autocomplete="new-password"`, and allow paste and password managers.
- **SR-7:** Never log request bodies, passwords or CSRF tokens to the console or to telemetry.

### 6.4 Accessibility and UX
- WCAG 2.1 AA: labelled inputs, visible focus, errors announced via `aria-live`, and focus-trapped dialogs.
- Every destructive action (revoke, disable, demote) needs a confirm dialog that names the target.
- Loading skeletons for tables, empty states for empty lists, and dates shown in the user's local time with the UTC value in a tooltip.

## 7. API reference (as implemented)

All bodies are JSON with camelCase fields. Errors are ProblemDetails.

| Method | Path | Request | Success |
|---|---|---|---|
| POST | `/api/auth/register` | `{ email, password }` | `201 { id, email }` |
| POST | `/api/auth/login` | `{ email, password, transport: "cookie" }` | `200 LoginResponse` + `Set-Cookie` |
| POST | `/api/auth/logout` | – | `204` |
| POST | `/api/auth/logout-all` | – | `200 { revoked }` |
| GET | `/api/auth/me` | – | `200 MeResponse` |
| POST | `/api/account/change-password` | `{ currentPassword, newPassword }` | `204` |
| GET | `/api/account/sessions` | – | `200 SessionResponse[]` |
| DELETE | `/api/account/sessions/{id}` | – | `204` |
| POST | `/api/account/sessions/revoke-others` | – | `200 { revoked }` |
| GET | `/api/admin/users?search&page&pageSize` | – | `200 { items: UserSummary[], page, pageSize, total }` |
| GET | `/api/admin/users/{id}` | – | `200 { user: UserSummary, roles, permissions, failedLoginCount, passwordChangedUtc }` |
| POST | `/api/admin/users/{id}/disable` \| `enable` \| `unlock` | – | `204` |
| PUT | `/api/admin/users/{id}/roles` | `{ roles: string[] }` | `204` |
| GET | `/api/admin/users/{id}/sessions` | – | `200 SessionResponse[]` |
| POST | `/api/admin/users/{id}/sessions/revoke-all` | – | `200 { revoked }` |
| DELETE | `/api/admin/sessions/{id}` | – | `204` |
| GET | `/api/admin/roles` | – | `200 { name, description, isSystem, permissions[] }[]` |
| GET | `/api/admin/permissions` | – | `200 { id, name, description }[]` |
| POST | `/api/admin/roles` | `{ name, description? }` | `201` |
| PUT | `/api/admin/roles/{name}/permissions` | `{ permissions: string[] }` | `204` |
| GET | `/api/admin/audit?userId&eventType&page&pageSize` | – | `200 AuditRecord[]` |

```ts
type LoginResponse = {
  userId: string; sessionId: string; transport: 'cookie';
  token: null; csrfToken: string;
  idleExpiresUtc: string; absoluteExpiresUtc: string;
};
type MeResponse = {
  userId: string; email: string; roles: string[]; permissions: string[];
  sessionId: string; transport: 'cookie' | 'bearer'; csrfToken: string | null;
  absoluteExpiresUtc: string;
};
type SessionResponse = {
  id: string; transport: string; createdUtc: string; lastSeenUtc: string;
  idleExpiresUtc: string; absoluteExpiresUtc: string;
  revokedUtc: string | null; revokedReason: string | null;
  ipAddress: string | null; userAgent: string | null; isCurrent: boolean;
};
type UserSummary = {
  id: string; email: string; isDisabled: boolean; disabledAtUtc: string | null;
  isLockedOut: boolean; lockoutEndUtc: string | null; createdUtc: string;
};
type AuditRecord = {
  id: number; occurredUtc: string; eventType: string;
  userId: string | null; actorUserId: string | null; sessionId: string | null;
  ipAddress: string | null; userAgent: string | null; details: string | null; // JSON string
};
type ProblemDetails = {
  status: number; title: string; detail?: string; errors?: Record<string, string[]>;
};
```

Generate these types from the backend's OpenAPI document (`GET /openapi/v1.json` in Development), for example with `openapi-typescript`, rather than maintaining them by hand. Keep the snippet above as the reference.

## 8. Routes

| Path | Access | Screen |
|---|---|---|
| `/login`, `/register` | Anonymous only (redirect to `/` if signed in) | FR-1, FR-2 |
| `/` | Authenticated | FR-4 |
| `/account` | Authenticated | FR-5 |
| `/account/sessions` | Authenticated | FR-6 |
| `/admin/users` | `users.read` | FR-8 |
| `/admin/users/:id` | `users.read` | FR-9 |
| `/admin/roles` | `roles.read` | FR-10 |
| `/admin/audit` | `audit.read` | FR-11 |
| `*` | – | 404 |

Implementation: `<RequireAuth>` and `<RequirePermission perm="…">` route wrappers that read `['me']`. Admin routes are lazy-loaded so regular users never download the admin bundle.

## 9. Suggested project structure

```
src/
  api/          apiFetch.ts, csrf.ts, endpoints/*.ts, types.ts (generated)
  auth/         useMe.ts, RequireAuth.tsx, RequirePermission.tsx, authChannel.ts, idleMonitor.ts
  features/
    auth/       LoginPage, RegisterPage
    account/    AccountPage, ChangePasswordForm, SessionsPage
    admin/      users/, roles/, audit/
  components/   AppShell, ConfirmDialog, ProblemAlert, SessionsTable, DataTable
  routes.tsx
  main.tsx
```

## 10. Testing and acceptance

### 10.1 Acceptance criteria (Playwright, against the real backend + SQL Server)
1. A new user registers, logs in, and sees their email on Home. After a reload they are still signed in (`/me`). There is no token in `localStorage` or `sessionStorage`, and `document.cookie` does not contain `__Host-sid`.
2. Five wrong passwords followed by the correct one shows the same generic error each time. An admin unlocks the user, and login then succeeds.
3. Signing in from 6 browser contexts leaves 5 sessions in the list; the first context is redirected to login on its next action.
4. User A revokes session B from the sessions page; B's next request redirects to login with the "session ended" message.
5. An admin disables a user; that user's open tab is redirected to login on its next request, and logging in again shows "Account disabled."
6. An admin removes `users.read` from a custom role; that user's admin navigation disappears after window refocus or their next request, and direct navigation to `/admin/users` shows 403.
7. A POST with the CSRF header removed (via a test hook) returns 403; the client refetches `/me`, retries, and succeeds.
8. Changing the password signs out all other contexts, and the current one stays signed in.
9. The Admin role's permissions are not editable in the UI. An admin cannot disable or demote themselves; the controls are hidden.
10. Logging out in one tab logs out all tabs.
11. Rapid failed logins (more than 10 per minute) show the rate-limit countdown.

### 10.2 Unit and integration (Vitest + MSW)
- `apiFetch`:
  - adds the CSRF header only on unsafe methods
  - performs the 401 redirect
  - retries a CSRF 403 exactly once
  - parses `429` `Retry-After`
- The `returnTo` sanitizer.
- Permission-gated rendering for each admin action.
- Form validation parity with the backend rules.

### 10.3 Quality gates
- TypeScript strict, ESLint (including `react-hooks`), Prettier.
- Lighthouse accessibility score ≥ 95 on the login, account and users pages.
- Initial JS for non-admin routes ≤ 200 KB gzipped.

## 11. Milestones

| # | Scope | Exit criteria |
|---|---|---|
| M1 | Scaffold, Vite proxy, `apiFetch`, `/me` bootstrap, Login, Register, Sign out, app shell | AC 1, 10 |
| M2 | Account, change password, my sessions, idle and absolute expiry UX, multi-tab sync | AC 3, 4, 8 |
| M3 | Admin users list and detail: disable, enable, unlock, roles, sessions | AC 2, 5, 9 |
| M4 | Roles and permissions matrix, audit log | AC 6 |
| M5 | Hardening: CSRF retry, rate-limit UX, accessibility pass, Playwright suite in CI | All ACs green |

## 12. Open questions and optional backend enhancements

1. **Idle expiry in `/me`:** `/me` returns only `absoluteExpiresUtc`. Adding `idleExpiresUtc` would let the inactivity warning be exact instead of estimated. *(Small backend change.)*
2. **Roles in the users list:** `GET /api/admin/users` doesn't include roles, so a "Role" column would require N detail calls. Add roles to `UserSummary` if the column is wanted.
3. **Audit pagination total:** the audit endpoint has no total count; "Load more" is the v1 UX.
4. **Registration enumeration:** `409` on a taken email reveals that the account exists. Accepted for v1. Revisit if email verification is added.
5. **Self-service account deletion:** not supported by the backend. Out of scope for v1.
6. **Hosting:** confirm the production reverse proxy (IIS, Nginx or YARP) that serves the SPA and `/api` on one origin.
