USE master;
GO

OPEN MASTER KEY DECRYPTION BY PASSWORD = 'P@ssw0rd_ServerMK_2026!';
GO

USE SmartBankDB;
GO

CREATE CERTIFICATE Cert_LoginProvisioning
    WITH SUBJECT = N'Signs modules permitted to create SQL logins during onboarding',
         EXPIRY_DATE = '20351231';
GO


EXEC master.dbo.xp_create_subdir N'C:\SmartBank\Certs\';
GO

BACKUP CERTIFICATE Cert_LoginProvisioning
    TO FILE = 'C:\SmartBank\Certs\Cert_LoginProvisioning.cer'
    WITH PRIVATE KEY
    (
        FILE = 'C:\SmartBank\Certs\Cert_LoginProvisioning.pvk',
        ENCRYPTION BY PASSWORD = 'P@ssw0rd_CertExport_2026!'
    );
GO

USE master;
GO

CREATE CERTIFICATE Cert_LoginProvisioning
    FROM FILE = 'C:\SmartBank\Certs\Cert_LoginProvisioning.cer'
    WITH PRIVATE KEY
    (
        FILE = 'C:\SmartBank\Certs\Cert_LoginProvisioning.pvk',
        DECRYPTION BY PASSWORD = 'P@ssw0rd_CertExport_2026!'
    );
GO

CREATE LOGIN Login_LoginProvisioning
    FROM CERTIFICATE Cert_LoginProvisioning;
GO

GRANT ALTER ANY LOGIN TO Login_LoginProvisioning;
GO

USE SmartBankDB;
GO

CREATE USER User_LoginProvisioning
    FROM CERTIFICATE Cert_LoginProvisioning;
GO

GRANT ALTER ANY USER
    TO User_LoginProvisioning;
GO

GRANT ALTER ON ROLE::Customer TO User_LoginProvisioning;
GRANT ALTER ON ROLE::DBA TO User_LoginProvisioning;
GRANT ALTER ON ROLE::BankManager TO User_LoginProvisioning;
GRANT ALTER ON ROLE::BankOfficer TO User_LoginProvisioning;
GO
