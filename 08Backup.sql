USE master;
GO

ALTER DATABASE SmartBankDB
SET RECOVERY FULL;
GO

IF CERT_ID(N'SmartBank_TDE_Cert') IS NULL
BEGIN
    THROW 50001,
          'SmartBank_TDE_Cert is missing. Run 01EncryptionSetup.sql first.',
          1;
END;
GO

IF EXISTS
(
    SELECT 1
    FROM sys.certificates
    WHERE name = N'SmartBank_TDE_Cert'
      AND pvt_key_encryption_type_desc = N'NO_PRIVATE_KEY'
)
BEGIN
    THROW 50002,
          'SmartBank_TDE_Cert does not have a private key and cannot encrypt backups.',
          1;
END;
GO

SELECT
    name,
    subject,
    expiry_date,
    pvt_key_encryption_type_desc
FROM sys.certificates
WHERE name = N'SmartBank_TDE_Cert';
GO

EXEC master.dbo.xp_create_subdir N'C:\SmartBank\Backup\';
GO


/* Manual backups - full, differential, log */

DECLARE @FullFile nvarchar(260) =
    N'C:\SmartBank\Backup\SmartBankDB_Full_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + N'.bak';

BACKUP DATABASE SmartBankDB
TO DISK = @FullFile
WITH COMPRESSION, CHECKSUM, STATS = 10,
ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = SmartBank_TDE_Cert);

RESTORE VERIFYONLY
FROM DISK = @FullFile
WITH LOADHISTORY, CHECKSUM;
GO

DECLARE @DiffFile nvarchar(260) =
    N'C:\SmartBank\Backup\SmartBankDB_Diff_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + N'.bak';

BACKUP DATABASE SmartBankDB
TO DISK = @DiffFile
WITH DIFFERENTIAL, COMPRESSION, CHECKSUM, STATS = 10,
ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = SmartBank_TDE_Cert);

RESTORE VERIFYONLY
FROM DISK = @DiffFile
WITH LOADHISTORY, CHECKSUM;
GO

DECLARE @LogFile nvarchar(260) =
    N'C:\SmartBank\Backup\SmartBankDB_Log_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + N'.trn';

BACKUP LOG SmartBankDB
TO DISK = @LogFile
WITH COMPRESSION, CHECKSUM, STATS = 10,
ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = SmartBank_TDE_Cert);

RESTORE VERIFYONLY
FROM DISK = @LogFile
WITH LOADHISTORY, CHECKSUM;
GO


/* SQL Server Agent automation */

USE msdb;
GO

/* Full backup: daily 1:00 AM */
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_FullBackup')
    EXEC sp_delete_job @job_name = N'SmartBank_FullBackup';
GO

EXEC sp_add_job
    @job_name = N'SmartBank_FullBackup',
    @enabled = 1,
    @description = N'Daily full backup of SmartBankDB, encrypted, verified';

EXEC sp_add_jobstep
    @job_name = N'SmartBank_FullBackup',
    @step_id = 1,
    @step_name = N'Run full backup',
    @subsystem = N'TSQL',
    @database_name = N'master',
    @on_success_action = 3,
    @on_fail_action = 2,
    @command = N'
DECLARE @FullFile nvarchar(260) =
    N''C:\SmartBank\Backup\SmartBankDB_Full_'' + FORMAT(GETDATE(), ''yyyyMMdd_HHmmss'') + N''.bak'';

BACKUP DATABASE SmartBankDB
TO DISK = @FullFile
WITH COMPRESSION, CHECKSUM, STATS = 10,
ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = SmartBank_TDE_Cert);';

EXEC sp_add_jobstep
    @job_name = N'SmartBank_FullBackup',
    @step_id = 2,
    @step_name = N'Verify full backup',
    @subsystem = N'TSQL',
    @database_name = N'master',
    @on_success_action = 1,
    @on_fail_action = 2,
    @command = N'
DECLARE @VerifyFile nvarchar(260);
DECLARE @Files TABLE (FileName nvarchar(260), Depth int, IsFile int);

INSERT INTO @Files
EXEC master.dbo.xp_dirtree ''C:\SmartBank\Backup\'', 1, 1;

SELECT @VerifyFile = MAX(FileName)
FROM @Files
WHERE IsFile = 1 AND FileName LIKE ''SmartBankDB_Full_%.bak'';

IF @VerifyFile IS NULL
    THROW 60101, ''No Full backup file found to verify.'', 1;

SET @VerifyFile = N''C:\SmartBank\Backup\'' + @VerifyFile;

RESTORE VERIFYONLY
FROM DISK = @VerifyFile
WITH LOADHISTORY, CHECKSUM;';

EXEC sp_add_schedule
    @schedule_name = N'SmartBank_FullBackup_Daily',
    @freq_type = 4,
    @freq_interval = 1,
    @active_start_time = 010000;

EXEC sp_attach_schedule
    @job_name = N'SmartBank_FullBackup',
    @schedule_name = N'SmartBank_FullBackup_Daily';

EXEC sp_add_jobserver
    @job_name = N'SmartBank_FullBackup',
    @server_name = N'(local)';
GO


/* Differential backup: every 6 hours */
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_DiffBackup')
    EXEC sp_delete_job @job_name = N'SmartBank_DiffBackup';
GO

EXEC sp_add_job
    @job_name = N'SmartBank_DiffBackup',
    @enabled = 1,
    @description = N'Differential backup of SmartBankDB every 6 hours, encrypted, verified';

EXEC sp_add_jobstep
    @job_name = N'SmartBank_DiffBackup',
    @step_id = 1,
    @step_name = N'Run differential backup',
    @subsystem = N'TSQL',
    @database_name = N'master',
    @on_success_action = 3,
    @on_fail_action = 2,
    @command = N'
DECLARE @DiffFile nvarchar(260) =
    N''C:\SmartBank\Backup\SmartBankDB_Diff_'' + FORMAT(GETDATE(), ''yyyyMMdd_HHmmss'') + N''.bak'';

BACKUP DATABASE SmartBankDB
TO DISK = @DiffFile
WITH DIFFERENTIAL, COMPRESSION, CHECKSUM, STATS = 10,
ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = SmartBank_TDE_Cert);';

EXEC sp_add_jobstep
    @job_name = N'SmartBank_DiffBackup',
    @step_id = 2,
    @step_name = N'Verify differential backup',
    @subsystem = N'TSQL',
    @database_name = N'master',
    @on_success_action = 1,
    @on_fail_action = 2,
    @command = N'
DECLARE @VerifyFile nvarchar(260);
DECLARE @Files TABLE (FileName nvarchar(260), Depth int, IsFile int);

INSERT INTO @Files
EXEC master.dbo.xp_dirtree ''C:\SmartBank\Backup\'', 1, 1;

SELECT @VerifyFile = MAX(FileName)
FROM @Files
WHERE IsFile = 1 AND FileName LIKE ''SmartBankDB_Diff_%.bak'';

IF @VerifyFile IS NULL
    THROW 60102, ''No Differential backup file found to verify.'', 1;

SET @VerifyFile = N''C:\SmartBank\Backup\'' + @VerifyFile;

RESTORE VERIFYONLY
FROM DISK = @VerifyFile
WITH LOADHISTORY, CHECKSUM;';

EXEC sp_add_schedule
    @schedule_name = N'SmartBank_DiffBackup_Every6Hours',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 8,
    @freq_subday_interval = 6,
    @active_start_time = 000000;

EXEC sp_attach_schedule
    @job_name = N'SmartBank_DiffBackup',
    @schedule_name = N'SmartBank_DiffBackup_Every6Hours';

EXEC sp_add_jobserver
    @job_name = N'SmartBank_DiffBackup',
    @server_name = N'(local)';
GO


/* Transaction log backup: every 15 minutes */
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_LogBackup')
    EXEC sp_delete_job @job_name = N'SmartBank_LogBackup';
GO

EXEC sp_add_job
    @job_name = N'SmartBank_LogBackup',
    @enabled = 1,
    @description = N'Transaction log backup of SmartBankDB every 15 minutes, encrypted, verified';

EXEC sp_add_jobstep
    @job_name = N'SmartBank_LogBackup',
    @step_id = 1,
    @step_name = N'Run transaction log backup',
    @subsystem = N'TSQL',
    @database_name = N'master',
    @on_success_action = 3,
    @on_fail_action = 2,
    @command = N'
DECLARE @LogFile nvarchar(260) =
    N''C:\SmartBank\Backup\SmartBankDB_Log_'' + FORMAT(GETDATE(), ''yyyyMMdd_HHmmss'') + N''.trn'';

BACKUP LOG SmartBankDB
TO DISK = @LogFile
WITH COMPRESSION, CHECKSUM, STATS = 10,
ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = SmartBank_TDE_Cert);';

EXEC sp_add_jobstep
    @job_name = N'SmartBank_LogBackup',
    @step_id = 2,
    @step_name = N'Verify transaction log backup',
    @subsystem = N'TSQL',
    @database_name = N'master',
    @on_success_action = 1,
    @on_fail_action = 2,
    @command = N'
DECLARE @VerifyFile nvarchar(260);
DECLARE @Files TABLE (FileName nvarchar(260), Depth int, IsFile int);

INSERT INTO @Files
EXEC master.dbo.xp_dirtree ''C:\SmartBank\Backup\'', 1, 1;

SELECT @VerifyFile = MAX(FileName)
FROM @Files
WHERE IsFile = 1 AND FileName LIKE ''SmartBankDB_Log_%.trn'';

IF @VerifyFile IS NULL
    THROW 60103, ''No Log backup file found to verify.'', 1;

SET @VerifyFile = N''C:\SmartBank\Backup\'' + @VerifyFile;

RESTORE VERIFYONLY
FROM DISK = @VerifyFile
WITH LOADHISTORY, CHECKSUM;';

EXEC sp_add_schedule
    @schedule_name = N'SmartBank_LogBackup_Every15Min',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 4,
    @freq_subday_interval = 15,
    @active_start_time = 000000;

EXEC sp_attach_schedule
    @job_name = N'SmartBank_LogBackup',
    @schedule_name = N'SmartBank_LogBackup_Every15Min';

EXEC sp_add_jobserver
    @job_name = N'SmartBank_LogBackup',
    @server_name = N'(local)';
GO


/* Backup retention cleanup: daily 2:30 AM */
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBank_BackupCleanup')
    EXEC sp_delete_job @job_name = N'SmartBank_BackupCleanup';
GO

EXEC sp_add_job
    @job_name = N'SmartBank_BackupCleanup',
    @enabled = 1,
    @description = N'Deletes backup files older than the retention window: 7 days for Full/Diff, 2 days for Log';

EXEC sp_add_jobstep
    @job_name = N'SmartBank_BackupCleanup',
    @step_id = 1,
    @step_name = N'Delete expired backup files',
    @subsystem = N'TSQL',
    @database_name = N'master',
    @on_success_action = 1,
    @on_fail_action = 2,
    @command = N'
DECLARE @FullDiffCutoff datetime = DATEADD(DAY, -7, GETDATE());
DECLARE @LogCutoff      datetime = DATEADD(DAY, -2, GETDATE());

EXEC master.dbo.xp_delete_file 0, N''C:\SmartBank\Backup\'', N''BAK'', @FullDiffCutoff;
EXEC master.dbo.xp_delete_file 0, N''C:\SmartBank\Backup\'', N''TRN'', @LogCutoff;';

EXEC sp_add_schedule
    @schedule_name = N'SmartBank_BackupCleanup_Daily',
    @freq_type = 4,
    @freq_interval = 1,
    @active_start_time = 023000;

EXEC sp_attach_schedule
    @job_name = N'SmartBank_BackupCleanup',
    @schedule_name = N'SmartBank_BackupCleanup_Daily';

EXEC sp_add_jobserver
    @job_name = N'SmartBank_BackupCleanup',
    @server_name = N'(local)';
GO

USE SmartBankDB;
GO


USE master;
GO

CREATE OR ALTER PROCEDURE dbo.Backup_SmartBank_TailLog
AS
BEGIN
    SET NOCOUNT ON;

    IF IS_SRVROLEMEMBER('sysadmin') <> 1
    BEGIN
        THROW 50001,
              'Access denied. Only sysadmin can perform a tail-log backup.',
              1;
    END;

    BEGIN TRY

        ALTER DATABASE SmartBankDB
        SET SINGLE_USER
        WITH ROLLBACK IMMEDIATE;

        BACKUP LOG SmartBankDB
        TO DISK = 'C:\SmartBank\Backup\SmartBankDB_TailLog.trn'
        WITH
            NORECOVERY,
            CHECKSUM,
            INIT;

        PRINT 'Tail-log backup completed successfully.';
        PRINT 'SmartBankDB is now in RESTORING state.';

    END TRY
    BEGIN CATCH

        PRINT 'Tail-log backup FAILED.';
        THROW;

    END CATCH;
END;
GO