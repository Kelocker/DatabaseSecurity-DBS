/* master */
/* Create encryption key */
USE master;
GO

IF NOT EXISTS (
	SELECT 1 
	FROM sys.symmetric_keys
	WHERE name = N'##MS_DatabaseMasterKey##'
)
BEGIN
    CREATE MASTER KEY 
	ENCRYPTION BY PASSWORD = 'P@ssw0rd_ServerMK_2026!';
END;
GO

OPEN MASTER KEY DECRYPTION BY PASSWORD = 'P@ssw0rd_ServerMK_2026!';
GO

IF NOT EXISTS (
	SELECT 1 
	FROM sys.certificates 
	WHERE name = N'SmartBank_TDE_Cert'
)
BEGIN
    CREATE CERTIFICATE [SmartBank_TDE_Cert]
        WITH SUBJECT = N'SmartBankDB TDE protector',
		EXPIRY_DATE = '20351231';
END;
GO

/* Export SmartBank_TDE_Cert and its private key. Without this, a
   TDE-encrypted backup can only ever be restored on THIS server -
   if this machine is lost, every backup becomes permanently
   unrestorable even if the .bak files themselves are intact.
   Stored in a separate folder from both the database backups
   (C:\SmartBank\Backup\) and the login-provisioning cert
   (C:\SmartBank\Certs\), so a single folder/disk loss can't take
   out both the backups and the only key that can decrypt them. */
EXEC master.dbo.xp_create_subdir N'C:\SmartBank\TDECert\';
GO

BACKUP CERTIFICATE SmartBank_TDE_Cert
    TO FILE = 'C:\SmartBank\TDECert\SmartBank_TDE_Cert.cer'
    WITH PRIVATE KEY
    (
        FILE = 'C:\SmartBank\TDECert\SmartBank_TDE_Cert.pvk',
        ENCRYPTION BY PASSWORD = 'P@ssw0rd_TDECertExport_2026!'
    );
GO

/* To ansel we can no need use EXEC function
if we open new file i put here because want to encrypt eveything at once
can delete this comment after reading this*/
IF DB_ID('SmartBankDB') IS NULL
BEGIN
	EXEC(N'CREATE DATABASE SmartBankDB;');
END;
GO

/* SmartBankDB database */
USE SmartBankDB;
GO

IF NOT EXISTS (
	SELECT 1 
	FROM sys.symmetric_keys
	WHERE name = N'##MS_DatabaseMasterKey##'
)
BEGIN
    CREATE MASTER KEY 
	ENCRYPTION BY PASSWORD = 'P@ssw0rd_DbMK_2026!';
END;
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.dm_database_encryption_keys
    WHERE database_id = DB_ID()
)
BEGIN
    CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE [SmartBank_TDE_Cert];
END;
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.dm_database_encryption_keys
    WHERE database_id = DB_ID()
      AND encryption_state = 3
)
BEGIN
    ALTER DATABASE SmartBankDB
    SET ENCRYPTION ON;
END;
GO


/* Column-level encryption */
IF NOT EXISTS (
	SELECT 1 
	FROM sys.certificates 
	WHERE name = N'Cert_SmartBank_CLE')
BEGIN
    CREATE CERTIFICATE [Cert_SmartBank_CLE]
        WITH SUBJECT = N'Protects restricted SmartBank customer identifiers',
             EXPIRY_DATE = '20351231';
END;
GO

IF NOT EXISTS (
	SELECT 1 
	FROM sys.symmetric_keys 
	WHERE name = N'SK_SmartBank_CustomerPII')
BEGIN
    CREATE SYMMETRIC KEY [SK_SmartBank_CustomerPII]
        WITH ALGORITHM = AES_256
        ENCRYPTION BY CERTIFICATE [Cert_SmartBank_CLE];
END;
GO

USE SmartBankDB;
GO
ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY;
GO