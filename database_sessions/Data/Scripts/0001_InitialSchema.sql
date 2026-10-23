-- Initial authentication schema: users, roles, permissions, sessions, audit log.
-- All timestamps are UTC (datetimeoffset with zero offset).

IF SCHEMA_ID(N'auth') IS NULL EXEC(N'CREATE SCHEMA auth');
GO

CREATE TABLE auth.Users
(
    Id                  uniqueidentifier  NOT NULL CONSTRAINT PK_Users PRIMARY KEY,
    Email               nvarchar(256)     NOT NULL,
    NormalizedEmail     nvarchar(256)     NOT NULL,
    PasswordHash        nvarchar(512)     NOT NULL,
    IsDisabled          bit               NOT NULL CONSTRAINT DF_Users_IsDisabled DEFAULT (0),
    DisabledAtUtc       datetimeoffset(7) NULL,
    FailedLoginCount    int               NOT NULL CONSTRAINT DF_Users_FailedLoginCount DEFAULT (0),
    LockoutEndUtc       datetimeoffset(7) NULL,
    PasswordChangedUtc  datetimeoffset(7) NOT NULL,
    CreatedUtc          datetimeoffset(7) NOT NULL,
    UpdatedUtc          datetimeoffset(7) NOT NULL,
    CONSTRAINT UQ_Users_NormalizedEmail UNIQUE (NormalizedEmail)
);
GO

CREATE TABLE auth.Roles
(
    Id           int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Roles PRIMARY KEY,
    Name         nvarchar(64)      NOT NULL CONSTRAINT UQ_Roles_Name UNIQUE,
    Description  nvarchar(256)     NULL,
    IsSystem     bit               NOT NULL CONSTRAINT DF_Roles_IsSystem DEFAULT (0)
);
GO

CREATE TABLE auth.Permissions
(
    Id           int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Permissions PRIMARY KEY,
    Name         nvarchar(128)     NOT NULL CONSTRAINT UQ_Permissions_Name UNIQUE,
    Description  nvarchar(256)     NULL
);
GO

CREATE TABLE auth.RolePermissions
(
    RoleId        int NOT NULL CONSTRAINT FK_RolePermissions_Roles REFERENCES auth.Roles (Id) ON DELETE CASCADE,
    PermissionId  int NOT NULL CONSTRAINT FK_RolePermissions_Permissions REFERENCES auth.Permissions (Id) ON DELETE CASCADE,
    CONSTRAINT PK_RolePermissions PRIMARY KEY (RoleId, PermissionId)
);
GO

CREATE TABLE auth.UserRoles
(
    UserId  uniqueidentifier NOT NULL CONSTRAINT FK_UserRoles_Users REFERENCES auth.Users (Id) ON DELETE CASCADE,
    RoleId  int              NOT NULL CONSTRAINT FK_UserRoles_Roles REFERENCES auth.Roles (Id) ON DELETE CASCADE,
    CONSTRAINT PK_UserRoles PRIMARY KEY (UserId, RoleId)
);
GO

CREATE INDEX IX_UserRoles_RoleId ON auth.UserRoles (RoleId);
GO

-- The raw session token is never stored; only its SHA-256 hash.
CREATE TABLE auth.Sessions
(
    Id                 uniqueidentifier  NOT NULL CONSTRAINT PK_Sessions PRIMARY KEY,
    TokenHash          binary(32)        NOT NULL,
    UserId             uniqueidentifier  NOT NULL CONSTRAINT FK_Sessions_Users REFERENCES auth.Users (Id) ON DELETE CASCADE,
    Transport          varchar(16)       NOT NULL CONSTRAINT CK_Sessions_Transport CHECK (Transport IN ('cookie', 'bearer')),
    CsrfToken          varchar(64)       NULL,
    CreatedUtc         datetimeoffset(7) NOT NULL,
    LastSeenUtc        datetimeoffset(7) NOT NULL,
    IdleExpiresUtc     datetimeoffset(7) NOT NULL,
    AbsoluteExpiresUtc datetimeoffset(7) NOT NULL,
    RevokedUtc         datetimeoffset(7) NULL,
    RevokedReason      varchar(64)       NULL,
    IpAddress          varchar(45)       NULL,
    UserAgent          nvarchar(512)     NULL,
    CONSTRAINT UQ_Sessions_TokenHash UNIQUE (TokenHash)
);
GO

CREATE INDEX IX_Sessions_UserId_Active ON auth.Sessions (UserId, CreatedUtc)
    INCLUDE (IdleExpiresUtc, AbsoluteExpiresUtc)
    WHERE RevokedUtc IS NULL;
GO

CREATE INDEX IX_Sessions_AbsoluteExpiresUtc ON auth.Sessions (AbsoluteExpiresUtc);
GO

CREATE TABLE auth.AuditLog
(
    Id           bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
    OccurredUtc  datetimeoffset(7)    NOT NULL,
    EventType    varchar(64)          NOT NULL,
    UserId       uniqueidentifier     NULL,
    ActorUserId  uniqueidentifier     NULL,
    SessionId    uniqueidentifier     NULL,
    IpAddress    varchar(45)          NULL,
    UserAgent    nvarchar(512)        NULL,
    Details      nvarchar(2000)       NULL
);
GO

CREATE INDEX IX_AuditLog_UserId_OccurredUtc ON auth.AuditLog (UserId, OccurredUtc);
GO

-- Seed system roles and permissions.
INSERT INTO auth.Roles (Name, Description, IsSystem) VALUES
    (N'Admin', N'Full administrative access', 1),
    (N'User',  N'Standard authenticated user', 1);

INSERT INTO auth.Permissions (Name, Description) VALUES
    (N'users.read',      N'View user accounts'),
    (N'users.manage',    N'Disable, enable and unlock user accounts'),
    (N'roles.read',      N'View roles and permissions'),
    (N'roles.manage',    N'Create roles and change role permissions'),
    (N'roles.assign',    N'Assign roles to users'),
    (N'sessions.read',   N'View any user''s sessions'),
    (N'sessions.revoke', N'Revoke any user''s sessions'),
    (N'audit.read',      N'View the security audit log');

INSERT INTO auth.RolePermissions (RoleId, PermissionId)
SELECT r.Id, p.Id
FROM auth.Roles r CROSS JOIN auth.Permissions p
WHERE r.Name = N'Admin';
GO
