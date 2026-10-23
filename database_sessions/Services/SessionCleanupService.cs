using DatabaseSessions.Data;
using Microsoft.Extensions.Options;
using SessionOptions = DatabaseSessions.Options.SessionOptions;

namespace DatabaseSessions.Services;

/// <summary>Periodically deletes sessions that were revoked or expired longer ago than the retention period.</summary>
public sealed class SessionCleanupService(
    SessionRepository sessions,
    IOptions<SessionOptions> options,
    TimeProvider clock,
    ILogger<SessionCleanupService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, clock);
        do
        {
            try
            {
                var cutoff = clock.GetUtcNow().AddDays(-options.Value.RetentionDays);
                var purged = await sessions.PurgeAsync(cutoff, stoppingToken);
                if (purged > 0) logger.LogInformation("Purged {Count} stale sessions", purged);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Session cleanup failed");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
