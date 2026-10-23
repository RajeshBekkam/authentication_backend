using System.Threading.RateLimiting;
using DatabaseSessions.Data;
using DatabaseSessions.Options;
using DatabaseSessions.Security;
using DatabaseSessions.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using SessionOptions = DatabaseSessions.Options.SessionOptions;

var builder = WebApplication.CreateBuilder(args);

// Options
builder.Services.AddOptions<SessionOptions>().BindConfiguration(SessionOptions.Section).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<LockoutOptions>().BindConfiguration(LockoutOptions.Section).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<PasswordHashingOptions>().BindConfiguration(PasswordHashingOptions.Section).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<BootstrapAdminOptions>().BindConfiguration(BootstrapAdminOptions.Section);

// Infrastructure
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<SqlConnectionFactory>();
builder.Services.AddSingleton<DatabaseMigrator>();
builder.Services.AddSingleton<UserRepository>();
builder.Services.AddSingleton<SessionRepository>();
builder.Services.AddSingleton<RoleRepository>();
builder.Services.AddSingleton<AuditRepository>();
builder.Services.AddSingleton<Argon2PasswordHasher>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuditLogger>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<AdminBootstrapper>();
builder.Services.AddHostedService<SessionCleanupService>();

// Authentication: database-backed sessions only.
builder.Services.AddAuthentication(AuthSchemes.Session)
    .AddScheme<AuthenticationSchemeOptions, SessionAuthenticationHandler>(AuthSchemes.Session, null);

// Authorization: every endpoint requires a valid session unless marked [AllowAnonymous].
builder.Services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder(AuthSchemes.Session).RequireAuthenticatedUser().Build());

// Rate limiting for credential endpoints, partitioned by client IP.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(RateLimitPolicies.Auth, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.ClientIp() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = builder.Configuration.GetValue("Auth:RateLimit:PermitLimit", 10),
                Window = TimeSpan.FromSeconds(builder.Configuration.GetValue("Auth:RateLimit:WindowSeconds", 60)),
                QueueLimit = 0,
            }));
    options.OnRejected = (ctx, _) =>
    {
        if (ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            ctx.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
        }
        return ValueTask.CompletedTask;
    };
});

// CORS (only needed if a browser client is served from a different origin).
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
    .WithOrigins(allowedOrigins)
    .AllowCredentials()
    .WithMethods("GET", "POST", "PUT", "DELETE")
    .WithHeaders("Content-Type", "Authorization", CsrfProtectionMiddleware.HeaderName)));

builder.Services.AddProblemDetails();
builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    if (app.Configuration.GetValue<bool>("Database:MigrateOnStartup"))
    {
        await scope.ServiceProvider.GetRequiredService<DatabaseMigrator>().MigrateAsync();
    }
    await scope.ServiceProvider.GetRequiredService<AdminBootstrapper>().RunAsync();
}

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();
}
else
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers.XContentTypeOptions = "nosniff";
    headers.XFrameOptions = "DENY";
    headers.CacheControl = "no-store";
    headers["Referrer-Policy"] = "no-referrer";
    headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
    await next();
});

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseMiddleware<CsrfProtectionMiddleware>();
app.UseAuthorization();

app.MapControllers();

app.Run();
