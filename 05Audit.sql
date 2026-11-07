USE master;
GO

EXEC master.dbo.xp_create_subdir N'C:\SmartBank\Audit\';
GO

CREATE SERVER AUDIT SmartBank_Audit
TO FILE
(
    FILEPATH = N'C:\SmartBank\Audit\',
    MAXSIZE = 100 MB,
    MAX_ROLLOVER_FILES = 10
)
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO

ALTER SERVER AUDIT SmartBank_Audit
WITH (STATE = ON);
GO


USE SmartBankDB;
GO

/* DML/DDL/permission changes on schema objects, plus user/role/
   database-level permission changes */
CREATE DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec
FOR SERVER AUDIT SmartBank_Audit
ADD (SCHEMA_OBJECT_ACCESS_GROUP),
ADD (SCHEMA_OBJECT_CHANGE_GROUP),
ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
ADD (DATABASE_PERMISSION_CHANGE_GROUP)
WITH (STATE = ON);
GO


/* Login/logout auditing - Windows Application Log, viewed via
   Event Viewer */

USE master;
GO

CREATE SERVER AUDIT SmartBank_LoginAudit
TO APPLICATION_LOG
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO

ALTER SERVER AUDIT SmartBank_LoginAudit
WITH (STATE = ON);
GO

/* Login/logout plus login/role/server-level permission changes */
CREATE SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec
FOR SERVER AUDIT SmartBank_LoginAudit
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (FAILED_LOGIN_GROUP),
ADD (LOGOUT_GROUP),
ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP)
WITH (STATE = ON);
GO



USE SmartBankDB;
GO

CREATE TABLE dbo.BusinessFailureLog
(
    LogID           int           IDENTITY(1,1) PRIMARY KEY,
    LoginName       sysname       NOT NULL,
    ProcedureName   sysname       NOT NULL,
    PrimaryKeyValue nvarchar(50)  NULL,
    ErrorNumber     int           NOT NULL,
    ErrorMessage    nvarchar(500) NOT NULL,
    LogDateMYT      datetime2(0)  NOT NULL CONSTRAINT DF_BusinessFailureLog_LogDateMYT DEFAULT (DATEADD(HOUR, 8, SYSUTCDATETIME()))
);
GO

REVOKE SELECT ON dbo.BusinessFailureLog FROM public;
GO

GRANT SELECT ON dbo.BusinessFailureLog TO DBA;
GO

CREATE PROCEDURE dbo.LogBusinessFailure
    @ProcedureName   sysname,
    @PrimaryKeyValue nvarchar(50) = NULL,
    @ErrorNumber     int,
    @ErrorMessage    nvarchar(500)
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO dbo.BusinessFailureLog (LoginName, ProcedureName, PrimaryKeyValue, ErrorNumber, ErrorMessage)
    VALUES (ORIGINAL_LOGIN(), @ProcedureName, @PrimaryKeyValue, @ErrorNumber, @ErrorMessage);
END;
GO

CREATE TABLE dbo.AuditLog_DDL
(
    LogID        int           IDENTITY(1,1) PRIMARY KEY,
    EventType    nvarchar(100) NOT NULL,
    ObjectName   nvarchar(256) NULL,
    CommandText  nvarchar(max) NULL,
    ChangedBy    sysname       NOT NULL CONSTRAINT DF_AuditLog_DDL_ChangedBy DEFAULT ORIGINAL_LOGIN(),
    ChangedAtMYT datetime2(0)  NOT NULL CONSTRAINT DF_AuditLog_DDL_ChangedAtMYT DEFAULT (DATEADD(HOUR, 8, SYSUTCDATETIME()))
);
GO

REVOKE SELECT ON dbo.AuditLog_DDL FROM public;
GRANT SELECT ON dbo.AuditLog_DDL TO DBA;
GO

CREATE TRIGGER trg_SmartBankDB_DDLAudit
ON DATABASE
WITH EXECUTE AS 'dbo'
FOR CREATE_TABLE, ALTER_TABLE, DROP_TABLE, CREATE_VIEW, ALTER_VIEW, DROP_VIEW,
    CREATE_PROCEDURE, ALTER_PROCEDURE, DROP_PROCEDURE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @EventData xml = EVENTDATA();

    INSERT INTO dbo.AuditLog_DDL (EventType, ObjectName, CommandText)
    VALUES
    (
        @EventData.value('(/EVENT_INSTANCE/EventType)[1]', 'nvarchar(100)'),
        @EventData.value('(/EVENT_INSTANCE/ObjectName)[1]', 'nvarchar(256)'),
        @EventData.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]', 'nvarchar(max)')
    );
END;
GO

/* READING THE AUDIT DATA - reference only, requires CONTROL SERVER

DECLARE @AuditFilePath varchar(8000);
SELECT @AuditFilePath = audit_file_path
FROM sys.dm_server_audit_status
WHERE name = 'SmartBank_Audit';

/* fix: event_time from sys.fn_get_audit_file is always UTC - SQL
   Server Audit gives no option to change that at the source, so
   convert for display here instead. +8 hours, no DST in Malaysia */
SELECT
    DATEADD(HOUR, 8, event_time) AS EventTime_MYT,
    server_principal_name,
    object_name,
    statement,
    succeeded,
    action_id,
    CASE
        WHEN action_id IN ('SL','IN','UP','DL') THEN 'DML'
        WHEN action_id IN ('CR','AL','DR')       THEN 'DDL'
        WHEN action_id IN ('GR','DN','RV')        THEN 'Permission Change'
        WHEN action_id = 'EX'                     THEN 'Execute'
        ELSE 'Other'
    END AS AuditCategory
FROM sys.fn_get_audit_file(@AuditFilePath, DEFAULT, DEFAULT)
ORDER BY event_time DESC;

-- PowerShell (not SSMS), reads login/logout from Event Viewer:
-- Windows Event Viewer TimeCreated is already local machine time,
-- not UTC, so no conversion needed here as long as the server's
-- OS timezone is set to Malaysia/Singapore time.

Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'MSSQL$DBS'
    Id = 18453,18454,18456
} | Select-Object TimeCreated, Id, Message | Format-Table -Wrap
*/
/* ===================================================================
   DML Trigger Demo - dedicated standalone table
   TriggerDMLDemo mirrors dbo.Staff's columns/self-contained
   constraints for a realistic entity shape, but carries no FK to any
   working table (Customer/Account/Staff) and no temporal versioning,
   so it can be freely inserted/updated/deleted purely to exercise
   the trigger below. AuditLog_TriggerDMLDemo logs every INSERT,
   UPDATE, and DELETE against it, with old and new values side by
   side per changed record, plus who made the change and when. */

USE SmartBankDB;
GO

CREATE TABLE dbo.TriggerDMLDemo
(
    StaffID   varchar(6)     NOT NULL,
    StaffName nvarchar(100)  NOT NULL,
    Position  varchar(20)    NOT NULL,
    Branch    nvarchar(50)   NOT NULL,
    Phone     varchar(20)    NOT NULL,
    Salary    decimal(12,2)  NOT NULL,
    LoginName sysname        NOT NULL,
    CONSTRAINT PK_TriggerDMLDemo PRIMARY KEY (StaffID),
    CONSTRAINT UQ_TriggerDMLDemo_LoginName UNIQUE (LoginName),
    CONSTRAINT CK_TriggerDMLDemo_IDPosition CHECK
    (
        (StaffID LIKE 'D[0-9][0-9][0-9][0-9][0-9]' AND Position = 'DBA')
        OR
        (StaffID LIKE 'M[0-9][0-9][0-9][0-9][0-9]' AND Position = 'Bank Manager')
        OR
        (StaffID LIKE 'O[0-9][0-9][0-9][0-9][0-9]' AND Position = 'Bank Officer')
    ),
    CONSTRAINT CK_TriggerDMLDemo_Position CHECK (Position IN ('DBA','Bank Manager','Bank Officer')),
    CONSTRAINT CK_TriggerDMLDemo_Salary CHECK (Salary BETWEEN 1.00 AND 100000.00),
    CONSTRAINT CK_TriggerDMLDemo_Phone CHECK (LEN(Phone) BETWEEN 9 AND 20)
);
GO


/* fix: ChangedAt -> ChangedAtMYT, same reasoning as BusinessFailureLog */
CREATE TABLE dbo.AuditLog_TriggerDMLDemo
(
    LogID         int           IDENTITY(1,1) PRIMARY KEY,
    Action        varchar(10)   NOT NULL,
    StaffID       varchar(6)    NOT NULL,

    Old_StaffName nvarchar(100) NULL,
    New_StaffName nvarchar(100) NULL,
    Old_Position  varchar(20)   NULL,
    New_Position  varchar(20)   NULL,
    Old_Branch    nvarchar(50)  NULL,
    New_Branch    nvarchar(50)  NULL,
    Old_Phone     varchar(20)   NULL,
    New_Phone     varchar(20)   NULL,
    Old_Salary    decimal(12,2) NULL,
    New_Salary    decimal(12,2) NULL,
    Old_LoginName sysname       NULL,
    New_LoginName sysname       NULL,

    ChangedBy     sysname       NOT NULL CONSTRAINT DF_AuditLog_TriggerDMLDemo_ChangedBy DEFAULT ORIGINAL_LOGIN(),
    ChangedAtMYT  datetime2(0)  NOT NULL CONSTRAINT DF_AuditLog_TriggerDMLDemo_ChangedAtMYT DEFAULT (DATEADD(HOUR, 8, SYSUTCDATETIME())),

    CONSTRAINT CK_AuditLog_TriggerDMLDemo_Action CHECK (Action IN ('INSERT','UPDATE','DELETE'))
);
GO

REVOKE SELECT ON dbo.AuditLog_TriggerDMLDemo FROM public;
GO

GRANT SELECT ON dbo.AuditLog_TriggerDMLDemo TO StaffOp;
GO


CREATE OR ALTER TRIGGER dbo.trg_TriggerDMLDemo_Audit
ON dbo.TriggerDMLDemo
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @HasInserted bit = CASE WHEN EXISTS (SELECT 1 FROM INSERTED) THEN 1 ELSE 0 END;
    DECLARE @HasDeleted  bit = CASE WHEN EXISTS (SELECT 1 FROM DELETED)  THEN 1 ELSE 0 END;

    IF @HasInserted = 1 AND @HasDeleted = 1
    BEGIN
        INSERT INTO dbo.AuditLog_TriggerDMLDemo
        (
            Action, StaffID,
            Old_StaffName, New_StaffName,
            Old_Position,  New_Position,
            Old_Branch,    New_Branch,
            Old_Phone,     New_Phone,
            Old_Salary,    New_Salary,
            Old_LoginName, New_LoginName
        )
        SELECT
            'UPDATE', i.StaffID,
            d.StaffName, i.StaffName,
            d.Position,  i.Position,
            d.Branch,    i.Branch,
            d.Phone,     i.Phone,
            d.Salary,    i.Salary,
            d.LoginName, i.LoginName
        FROM INSERTED i
        JOIN DELETED d ON i.StaffID = d.StaffID;
    END
    ELSE IF @HasInserted = 1
    BEGIN
        INSERT INTO dbo.AuditLog_TriggerDMLDemo
        (
            Action, StaffID,
            New_StaffName, New_Position, New_Branch,
            New_Phone, New_Salary, New_LoginName
        )
        SELECT
            'INSERT', i.StaffID,
            i.StaffName, i.Position, i.Branch,
            i.Phone, i.Salary, i.LoginName
        FROM INSERTED i;
    END
    ELSE IF @HasDeleted = 1
    BEGIN
        INSERT INTO dbo.AuditLog_TriggerDMLDemo
        (
            Action, StaffID,
            Old_StaffName, Old_Position, Old_Branch,
            Old_Phone, Old_Salary, Old_LoginName
        )
        SELECT
            'DELETE', d.StaffID,
            d.StaffName, d.Position, d.Branch,
            d.Phone, d.Salary, d.LoginName
        FROM DELETED d;
    END;
END;
GO

/* 

-- INSERT
INSERT INTO dbo.TriggerDMLDemo (StaffID, StaffName, Position, Branch, Phone, Salary, LoginName)
VALUES ('O99999', 'Test Officer', 'Bank Officer', 'Demo Branch', '0123456789', 3000.00, 'demo_officer');

-- UPDATE
UPDATE dbo.TriggerDMLDemo SET Salary = 3200.00, Phone = '0198765432' WHERE StaffID = 'O99999';

-- DELETE
DELETE FROM dbo.TriggerDMLDemo WHERE StaffID = 'O99999';

-- Review
SELECT * FROM dbo.AuditLog_TriggerDMLDemo ORDER BY LogID;

*/