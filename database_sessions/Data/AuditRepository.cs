using Dapper;

namespace DatabaseSessions.Data;

public sealed class AuditRepository(SqlConnectionFactory db)
{
    public async Task InsertAsync(AuditRecord record, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("""
            INSERT INTO auth.AuditLog (OccurredUtc, EventType, UserId, ActorUserId, SessionId, IpAddress, UserAgent, Details)
            VALUES (@OccurredUtc, @EventType, @UserId, @ActorUserId, @SessionId, @IpAddress, @UserAgent, @Details);
            """, record, cancellationToken: ct));
    }

    public async Task<IReadOnlyList<AuditRecord>> QueryAsync(Guid? userId, string? eventType, int page, int pageSize,
        CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        return (await conn.QueryAsync<AuditRecord>(new CommandDefinition("""
            SELECT Id, OccurredUtc, EventType, UserId, ActorUserId, SessionId, IpAddress, UserAgent, Details
            FROM auth.AuditLog
            WHERE (@userId IS NULL OR UserId = @userId) AND (@eventType IS NULL OR EventType = @eventType)
            ORDER BY Id DESC
            OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY;
            """, new { userId, eventType, offset = (page - 1) * pageSize, pageSize }, cancellationToken: ct))).AsList();
    }
}
