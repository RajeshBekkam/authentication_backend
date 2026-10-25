using Microsoft.EntityFrameworkCore;

namespace DatabaseSessions.Data;

public sealed class AuditRepository(IDbContextFactory<AuthDbContext> dbFactory)
{
    public async Task InsertAsync(AuditLogEntry entry, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        db.AuditLog.Add(entry);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AuditLogEntry>> QueryAsync(Guid? userId, string? eventType, int page, int pageSize,
        CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var query = db.AuditLog.AsNoTracking();
        if (userId is { } uid) query = query.Where(a => a.UserId == uid);
        if (!string.IsNullOrEmpty(eventType)) query = query.Where(a => a.EventType == eventType);
        return await query
            .OrderByDescending(a => a.Id)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(ct);
    }
}
