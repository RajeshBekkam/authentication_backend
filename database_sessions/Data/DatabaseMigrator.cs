using System.Reflection;
using System.Text.RegularExpressions;
using Dapper;
using Microsoft.Data.SqlClient;

namespace DatabaseSessions.Data;

/// <summary>
/// Applies the embedded, versioned SQL scripts in Data/Scripts in name order.
/// Each script runs in its own transaction and is recorded in dbo.SchemaVersions.
/// </summary>
public sealed partial class DatabaseMigrator(SqlConnectionFactory connectionFactory, ILogger<DatabaseMigrator> logger)
{
    private const string ScriptPrefix = "DatabaseSessions.Data.Scripts.";

    [GeneratedRegex(@"^\s*GO\s*;?\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex BatchSeparator();

    [GeneratedRegex(@"^[A-Za-z0-9_]+$")]
    private static partial Regex SafeIdentifier();

    public async Task MigrateAsync(CancellationToken ct = default)
    {
        await EnsureDatabaseExistsAsync(ct);

        await using var connection = await connectionFactory.OpenAsync(ct);

        // Serialize migrators across multiple app instances.
        await connection.ExecuteAsync(
            "EXEC sp_getapplock @Resource = 'SchemaMigrations', @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = 60000;");
        try
        {
            await connection.ExecuteAsync("""
                IF OBJECT_ID(N'dbo.SchemaVersions', N'U') IS NULL
                CREATE TABLE dbo.SchemaVersions
                (
                    ScriptName  nvarchar(256)     NOT NULL CONSTRAINT PK_SchemaVersions PRIMARY KEY,
                    AppliedUtc  datetimeoffset(7) NOT NULL
                );
                """);

            var applied = (await connection.QueryAsync<string>("SELECT ScriptName FROM dbo.SchemaVersions"))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var assembly = Assembly.GetExecutingAssembly();
            var scripts = assembly.GetManifestResourceNames()
                .Where(n => n.StartsWith(ScriptPrefix, StringComparison.Ordinal) && n.EndsWith(".sql", StringComparison.OrdinalIgnoreCase))
                .OrderBy(n => n, StringComparer.Ordinal);

            foreach (var resource in scripts)
            {
                var scriptName = resource[ScriptPrefix.Length..];
                if (applied.Contains(scriptName)) continue;

                logger.LogInformation("Applying database script {Script}", scriptName);

                await using var stream = assembly.GetManifestResourceStream(resource)!;
                using var reader = new StreamReader(stream);
                var sql = await reader.ReadToEndAsync(ct);

                await using var tx = (SqlTransaction)await connection.BeginTransactionAsync(ct);
                foreach (var batch in BatchSeparator().Split(sql).Where(b => !string.IsNullOrWhiteSpace(b)))
                {
                    await connection.ExecuteAsync(new CommandDefinition(batch, transaction: tx, cancellationToken: ct));
                }
                await connection.ExecuteAsync(
                    "INSERT INTO dbo.SchemaVersions (ScriptName, AppliedUtc) VALUES (@scriptName, SYSUTCDATETIME())",
                    new { scriptName }, tx);
                await tx.CommitAsync(ct);
            }
        }
        finally
        {
            await connection.ExecuteAsync(
                "EXEC sp_releaseapplock @Resource = 'SchemaMigrations', @LockOwner = 'Session';");
        }
    }

    private async Task EnsureDatabaseExistsAsync(CancellationToken ct)
    {
        var builder = new SqlConnectionStringBuilder(connectionFactory.ConnectionString);
        var databaseName = builder.InitialCatalog;
        if (string.IsNullOrEmpty(databaseName) || !SafeIdentifier().IsMatch(databaseName))
        {
            throw new InvalidOperationException("The 'AuthDb' connection string must specify a Database containing only letters, digits and underscores.");
        }

        builder.InitialCatalog = "master";
        await using var master = new SqlConnection(builder.ConnectionString);
        await master.OpenAsync(ct);
        await master.ExecuteAsync($"IF DB_ID(N'{databaseName}') IS NULL CREATE DATABASE [{databaseName}];");
    }
}
