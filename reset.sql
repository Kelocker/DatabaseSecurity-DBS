/* SmartBankDB reset2.sql - full teardown for the remastered project.
   Covers everything the original reset.sql didn't know about yet:
   RLS objects, Cert_LoginProvisioning/Login_LoginProvisioning,
   both audit specifications, and every SQL login dynamically created
   by AddCustomer/AddStaff (these are server-scoped and do NOT get
   removed just by dropping the database).

   Run top to bottom, same session throughout (uses a #temp table
   that must survive across the USE switches below). Every step is
   guarded with IF EXISTS, safe to rerun even if a previous attempt
   only got partway through. */


/* Step 1: disable and drop the logon trigger FIRST, before anything
   else. This is server-scoped, DROP DATABASE will never remove it,
   and leaving it enabled with no matching database behind it is
   what caused the lockout the first time this happened */
IF EXISTS (SELECT 1 FROM sys.server_triggers WHERE name = 'trg_AuditLogin')
BEGIN
    DISABLE TRIGGER trg_AuditLogin ON ALL SERVER;
    DROP TRIGGER trg_AuditLogin ON ALL SERVER;
END;
GO


/* Step 2: capture every dynamically-created customer/staff login
   BEFORE the database goes away - AddCustomer/AddStaff create these
   as real SQL logins, and dropping the database only removes the
   database USER half of that pairing, not the server-scoped LOGIN.
   type = 'S' is exactly the SQL_USER principals created that way;
   User_PIIModuleSigning/User_AuditLogging are type 'C' (certificate
   mapped) and are excluded automatically */
IF DB_ID('SmartBankDB') IS NOT NULL
BEGIN
    USE SmartBankDB;

    IF OBJECT_ID('tempdb..#LoginsToDrop') IS NOT NULL
        DROP TABLE #LoginsToDrop;

    CREATE TABLE #LoginsToDrop (LoginName sysname);

    INSERT INTO #LoginsToDrop (LoginName)
    SELECT name
    FROM sys.database_principals
    WHERE type = 'S'
      AND name NOT IN ('dbo', 'guest', 'sys', 'INFORMATION_SCHEMA');
END;
GO


/* Step 3: stop and drop the SQL Server Audit and both specifications */
IF DB_ID('SmartBankDB') IS NOT NULL
BEGIN
    USE SmartBankDB;

    IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'SmartBank_DatabaseAuditSpec')
    BEGIN
        ALTER DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec WITH (STATE = OFF);
        DROP DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec;
    END;
END;
GO

USE master;
GO

IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = 'SmartBank_ServerAuditSpec')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION SmartBank_ServerAuditSpec WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION SmartBank_ServerAuditSpec;
END;
GO

IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = 'SmartBank_Audit')
BEGIN
    ALTER SERVER AUDIT SmartBank_Audit WITH (STATE = OFF);
    DROP SERVER AUDIT SmartBank_Audit;
END;
GO


/* Step 4: turn off TDE and wait for decryption before dropping the key */
IF DB_ID('SmartBankDB') IS NOT NULL
BEGIN
    USE SmartBankDB;

    IF EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID() AND encryption_state <> 1)
    BEGIN
        ALTER DATABASE SmartBankDB SET ENCRYPTION OFF;
    END;
END;
GO

WHILE EXISTS (
    SELECT 1 FROM sys.dm_database_encryption_keys
    WHERE database_id = DB_ID('SmartBankDB') AND encryption_state <> 1
)
BEGIN
    WAITFOR DELAY '00:00:02';
END;
GO

IF DB_ID('SmartBankDB') IS NOT NULL
BEGIN
    USE SmartBankDB;

    IF EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID())
    BEGIN
        DROP DATABASE ENCRYPTION KEY;
    END;
END;
GO


/* Step 5: drop the database itself. This removes every DB-scoped
   object in one shot - tables, views, procedures, RLS security
   policies and predicate functions, triggers, Cert_SmartBank_CLE,
   SK_SmartBank_CustomerPII, Cert_PIIModuleSigning, Cert_AuditLogging,
   the SmartBankDB copy of Cert_LoginProvisioning, roles, and every
   database user - including the users mapped to the logins captured
   in Step 2, though not the logins themselves */
USE master;
GO

IF DB_ID('SmartBankDB') IS NOT NULL
BEGIN
    ALTER DATABASE SmartBankDB SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE SmartBankDB;
END;
GO


/* Step 5b: SQL Agent jobs - msdb-scoped, DROP DATABASE never touches
   these. Left alone, SmartBank_LogBackup keeps firing every 15
   minutes against a database that no longer exists, failing
   silently in the background until someone notices or rebuilds the
   project on top of it mid-schedule. Stop and drop all four. */
USE msdb;
GO

IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_FullBackup')
    EXEC sp_delete_job @job_name = N'SmartBank_FullBackup';
GO

IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_DiffBackup')
    EXEC sp_delete_job @job_name = N'SmartBank_DiffBackup';
GO

IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_LogBackup')
    EXEC sp_delete_job @job_name = N'SmartBank_LogBackup';
GO

IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_BackupCleanup')
    EXEC sp_delete_job @job_name = N'SmartBank_BackupCleanup';
GO

USE master;
GO


/* Step 6: server-scoped leftovers that DROP DATABASE cannot touch */
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'Login_LoginProvisioning')
BEGIN
    DROP LOGIN Login_LoginProvisioning;
END;
GO

IF EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'Cert_LoginProvisioning')
BEGIN
    DROP CERTIFICATE Cert_LoginProvisioning;
END;
GO


/* Step 7: drop every dynamically-created customer/staff login
   captured in Step 2. Runs last since these logins had no reason to
   block anything earlier, and the temp table only needs to survive
   until here */
IF OBJECT_ID('tempdb..#LoginsToDrop') IS NOT NULL
BEGIN
    DECLARE @LoginName sysname;
    DECLARE @DropSQL   nvarchar(max);

    DECLARE login_cursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT LoginName FROM #LoginsToDrop;

    OPEN login_cursor;
    FETCH NEXT FROM login_cursor INTO @LoginName;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = @LoginName)
        BEGIN
            SET @DropSQL = N'DROP LOGIN ' + QUOTENAME(@LoginName) + N';';
            EXEC sp_executesql @DropSQL;
        END;

        FETCH NEXT FROM login_cursor INTO @LoginName;
    END;

    CLOSE login_cursor;
    DEALLOCATE login_cursor;

    DROP TABLE #LoginsToDrop;
END;
GO


/* Not handled by this script - filesystem cleanup is manual:
   C:\SmartBank\Audit\   (SQL Server Audit .sqlaudit files)
   C:\SmartBank\Certs\   (Cert_LoginProvisioning .cer/.pvk export)
   Safe to delete both folders by hand once this script completes,
   or leave them - rerunning the setup scripts will just write into
   the same folders again since xp_create_subdir is a no-op if the
   folder already exists */