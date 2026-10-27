using System.Threading.RateLimiting;
using DatabaseSessions.Data;
using DatabaseSessions.Options;
using DatabaseSessions.Security;
using DatabaseSessions.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SessionOptions = DatabaseSessions.Options.SessionOptions;

var builder = WebApplication.CreateBuilder(args);

// Options
builder.Services.AddOptions<SessionOptions>().BindConfiguration(SessionOptions.Section).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<LockoutOptions>().BindConfiguration(LockoutOptions.Section).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<PasswordHashingOptions>().BindConfiguration(PasswordHashingOptions.Section).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<BootstrapAdminOptions>().BindConfiguration(BootstrapAdminOptions.Section);

// Infrastructure. Repositories create a short-lived DbContext per operation via the factory.
builder.Services.AddSingleton(TimeProvider.System); //This is used to get the current time in a testable way. We can inject a fake TimeProvider in tests to control the current time.
builder.Services.AddDbContextFactory<AuthDbContext>(options => options.UseSqlServer( //A regular AddDbContext would create a long-lived DbContext that is shared across requests, which is not recommended for web applications. Using a factory allows us to create a new DbContext for each operation, which is safer and more efficient.
    builder.Configuration.GetConnectionString("AuthDb"),
    sql => sql.UseQuerySplittingBehavior(QuerySplittingBehavior.SingleQuery))); //singleQeuery is more efficient for our data model, which has many one-to-many relationships, splitting queries can result in a lot of duplicate data being returned from the database and can cause performance issues.
builder.Services.AddSingleton<UserRepository>();
builder.Services.AddSingleton<SessionRepository>();
builder.Services.AddSingleton<RoleRepository>(); //As we are using AddDbContextFactory for the DbContext, we can safely register the repositories as singletons. They will create a new DbContext for each operation, so they don't hold onto any state between requests.
builder.Services.AddSingleton<AuditRepository>();
builder.Services.AddSingleton<Argon2PasswordHasher>();
builder.Services.AddHttpContextAccessor(); // to get the current request's IP address for rate limiting and logging
builder.Services.AddScoped<AuditLogger>(); //AuditLogger and AuthService are scoped, one per request, because they use the request’s HttpContext (IP, user agent). A scoped service can depend on singletons, but a singleton can’t depend on scoped ones, which is why the repositories can’t take them.
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

if (string.IsNullOrWhiteSpace(app.Configuration.GetConnectionString("AuthDb")))
{
    throw new InvalidOperationException("Connection string 'AuthDb' is not configured.");
}

using (var scope = app.Services.CreateScope())
{
    if (app.Configuration.GetValue<bool>("Database:MigrateOnStartup"))
    {
        // Creates the database if needed; EF Core 9 takes a database lock so concurrent instances are safe.
        await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AuthDbContext>>().CreateDbContextAsync();
        await db.Database.MigrateAsync();
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
