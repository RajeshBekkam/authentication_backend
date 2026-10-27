using Microsoft.EntityFrameworkCore;

namespace DatabaseSessions.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<UserAccount> Users => Set<UserAccount>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<UserSession> Sessions => Set<UserSession>();
    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.HasDefaultSchema("auth");  //puts every table in the auth schema (auth.Users, auth.Roles, and so on)

        model.Entity<UserAccount>(e =>
        {
            e.ToTable("Users");  //maps this to the Users table in the auth schema
            e.Property(u => u.Id).ValueGeneratedNever(); //we generate the Id in code, not the database
            e.Property(u => u.Email).HasMaxLength(256); //we limit the email length to 256 characters nvarchar(256)
            e.Property(u => u.NormalizedEmail).HasMaxLength(256);
            e.Property(u => u.PasswordHash).HasMaxLength(512);
            e.HasIndex(u => u.NormalizedEmail).IsUnique(); //we create a unique index on NormalizedEmail to enforce uniqueness and speed up lookups
        });

        model.Entity<Role>(e =>
        {
            e.ToTable("Roles");
            e.Property(r => r.Name).HasMaxLength(64);
            e.Property(r => r.Description).HasMaxLength(256);
            e.HasIndex(r => r.Name).IsUnique();
        });

        model.Entity<Permission>(e =>
        {
            e.ToTable("Permissions");
            e.Property(p => p.Name).HasMaxLength(128);
            e.Property(p => p.Description).HasMaxLength(256);
            e.HasIndex(p => p.Name).IsUnique();
        });

        model.Entity<UserRole>(e =>
        {
            e.ToTable("UserRoles");
            e.HasKey(ur => new { ur.UserId, ur.RoleId }); //composite primary key
            e.HasOne(ur => ur.User).WithMany(u => u.UserRoles).HasForeignKey(ur => ur.UserId).OnDelete(DeleteBehavior.Cascade); //when a user is deleted, their roles are also deleted, one-to-many relationship
            e.HasOne(ur => ur.Role).WithMany(r => r.UserRoles).HasForeignKey(ur => ur.RoleId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<RolePermission>(e =>
        {
            e.ToTable("RolePermissions");
            e.HasKey(rp => new { rp.RoleId, rp.PermissionId });
            e.HasOne(rp => rp.Role).WithMany(r => r.RolePermissions).HasForeignKey(rp => rp.RoleId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(rp => rp.Permission).WithMany(p => p.RolePermissions).HasForeignKey(rp => rp.PermissionId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<UserSession>(e =>
        {
            e.ToTable("Sessions", t => t.HasCheckConstraint("CK_Sessions_Transport", "[Transport] IN ('cookie', 'bearer')")); //we add a check constraint to ensure that the Transport column can only have the values 'cookie' or 'bearer'
            e.Property(s => s.Id).ValueGeneratedNever();
            e.Property(s => s.TokenHash).HasMaxLength(32).IsFixedLength();
            e.Property(s => s.Transport).HasMaxLength(16).IsUnicode(false); //IsUnicode(false) makes these varchar instead of nvarchar 
            e.Property(s => s.CsrfToken).HasMaxLength(64).IsUnicode(false);
            e.Property(s => s.RevokedReason).HasMaxLength(64).IsUnicode(false);
            e.Property(s => s.IpAddress).HasMaxLength(45).IsUnicode(false);
            e.Property(s => s.UserAgent).HasMaxLength(512);
            e.HasIndex(s => s.TokenHash).IsUnique();
            e.HasIndex(s => new { s.UserId, s.CreatedUtc })
                .IncludeProperties(s => new { s.IdleExpiresUtc, s.AbsoluteExpiresUtc }) //IncludeProperties is used to include additional columns in the index to avoid lookups when querying for active sessions
                .HasFilter("[RevokedUtc] IS NULL") //Only index active sessions (RevokedUtc is null)
                .HasDatabaseName("IX_Sessions_UserId_Active"); //Name the index explicitly to avoid EF Core generating a long name that exceeds SQL Server's limit
            e.HasIndex(s => s.AbsoluteExpiresUtc);
            e.HasOne(s => s.User).WithMany(u => u.Sessions).HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<AuditLogEntry>(e =>
        {
            e.ToTable("AuditLog");
            e.Property(a => a.EventType).HasMaxLength(64).IsUnicode(false);
            e.Property(a => a.IpAddress).HasMaxLength(45).IsUnicode(false);
            e.Property(a => a.UserAgent).HasMaxLength(512);
            e.Property(a => a.Details).HasMaxLength(2000);
            e.HasIndex(a => new { a.UserId, a.OccurredUtc });
        });

        Seed(model);
    }

    /// <summary>System roles and permissions. The Admin role is granted every permission.</summary>
    private static void Seed(ModelBuilder model)
    {
        const int adminRoleId = 1, userRoleId = 2;
        model.Entity<Role>().HasData(
            new Role { Id = adminRoleId, Name = Security.Roles.Admin, Description = "Full administrative access", IsSystem = true },
            new Role { Id = userRoleId, Name = Security.Roles.User, Description = "Standard authenticated user", IsSystem = true });

        (string Name, string Description)[] permissions =
        [
            (Security.Permissions.UsersRead, "View user accounts"),
            (Security.Permissions.UsersManage, "Disable, enable and unlock user accounts"),
            (Security.Permissions.RolesRead, "View roles and permissions"),
            (Security.Permissions.RolesManage, "Create roles and change role permissions"),
            (Security.Permissions.RolesAssign, "Assign roles to users"),
            (Security.Permissions.SessionsRead, "View any user's sessions"),
            (Security.Permissions.SessionsRevoke, "Revoke any user's sessions"),
            (Security.Permissions.AuditRead, "View the security audit log"),
        ];

        model.Entity<Permission>().HasData(permissions.Select((p, i) =>
            new Permission { Id = i + 1, Name = p.Name, Description = p.Description }));
        model.Entity<RolePermission>().HasData(permissions.Select((_, i) =>
            new RolePermission { RoleId = adminRoleId, PermissionId = i + 1 }));
    }
}
