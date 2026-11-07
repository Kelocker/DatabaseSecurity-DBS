USE SmartBankDB;
GO

/* =========================================================
   CLEANUP FOR RE-RUN
   ========================================================= */

IF OBJECT_ID('dbo.AddCustomer', 'P') IS NOT NULL
    DROP PROCEDURE dbo.AddCustomer;
GO

IF OBJECT_ID('dbo.AddStaff', 'P') IS NOT NULL
    DROP PROCEDURE dbo.AddStaff;
GO


/* =========================================================
   ADD CUSTOMER
   ========================================================= */

CREATE PROCEDURE dbo.AddCustomer
    @CustomerName   nvarchar(100),
    @ICNumber       varchar(20),
    @Phone          varchar(20),
    @AddressDetail  nvarchar(200),
    @LoginName      sysname,
    @TransactionPIN varchar(6),
    @AccountType    varchar(20)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @CustomerID   varchar(6);
    DECLARE @AccountID    varchar(10);
    DECLARE @Salt         varbinary(16);
    DECLARE @Hash         varbinary(32);
    DECLARE @ICEncrypted  varbinary(256);
    DECLARE @SQL          nvarchar(max);
    DECLARE @DefaultPwd   sysname;

    SET @DefaultPwd = CONVERT(sysname, @LoginName) + N'@123';

    BEGIN TRY
        BEGIN TRANSACTION;

        /* ---------------------------------------------
           Validate login name
           --------------------------------------------- */

        IF @LoginName IS NULL OR LTRIM(RTRIM(@LoginName)) = ''
        BEGIN
            THROW 51000, 'Login name cannot be empty.', 1;
        END;

        IF EXISTS (
            SELECT 1
            FROM sys.database_principals
            WHERE name = @LoginName
        )
        BEGIN
            THROW 51003, 'Database user already exists.', 1;
        END;

        /* ---------------------------------------------
           Validate IC number
           --------------------------------------------- */

        IF @ICNumber IS NULL
           OR @ICNumber LIKE '%[^0-9]%'
           OR LEN(@ICNumber) < 4
        BEGIN
            THROW 51001, 'Invalid IC number.', 1;
        END;

        /* ---------------------------------------------
           Validate PIN
           --------------------------------------------- */

        IF @TransactionPIN IS NULL
           OR (
                @TransactionPIN NOT LIKE '[0-9][0-9][0-9][0-9]'
                AND
                @TransactionPIN NOT LIKE
                    '[0-9][0-9][0-9][0-9][0-9][0-9]'
              )
        BEGIN
            THROW 51002, 'PIN must be 4 or 6 digits.', 1;
        END;

        /* ---------------------------------------------
           Generate Customer ID
           --------------------------------------------- */

        SELECT @CustomerID =
            'C' +
            RIGHT(
                '00000' +
                CAST(
                    ISNULL(
                        MAX(
                            CAST(
                                SUBSTRING(CustomerID, 2, 5)
                                AS int
                            )
                        ),
                        0
                    ) + 1
                    AS varchar(5)
                ),
                5
            )
        FROM dbo.Customer WITH (TABLOCKX, HOLDLOCK);

        /* ---------------------------------------------
           Generate Account ID
           --------------------------------------------- */

        SELECT @AccountID =
            'A' +
            RIGHT(
                '000000000' +
                CAST(
                    ISNULL(
                        MAX(
                            CAST(
                                SUBSTRING(AccountID, 2, 9)
                                AS int
                            )
                        ),
                        0
                    ) + 1
                    AS varchar(9)
                ),
                9
            )
        FROM dbo.Account WITH (TABLOCKX, HOLDLOCK);

        /* ---------------------------------------------
           Hash transaction PIN
           --------------------------------------------- */

        SET @Salt = CRYPT_GEN_RANDOM(16);

        SET @Hash =
            HASHBYTES(
                'SHA2_256',
                @Salt +
                CONVERT(varbinary(10), @TransactionPIN)
            );

        /* ---------------------------------------------
           Encrypt IC number
           Permission supplied by:
           Cert_PIIModuleSigning
           --------------------------------------------- */

        OPEN SYMMETRIC KEY SK_SmartBank_CustomerPII
            DECRYPTION BY CERTIFICATE Cert_SmartBank_CLE;

        SET @ICEncrypted =
            ENCRYPTBYKEY(KEY_GUID('SK_SmartBank_CustomerPII'), 
            @ICNumber, 
            1, 
            @CustomerID
            );

        CLOSE SYMMETRIC KEY SK_SmartBank_CustomerPII;

        /* ---------------------------------------------
           Insert customer
           --------------------------------------------- */

        INSERT INTO dbo.Customer
        (
            CustomerID,
            CustomerName,
            ICNumberEncrypted,
            Phone,
            AddressDetail,
            LoginName,
            TransactionPINSalt,
            TransactionPINHash
        )
        VALUES
        (
            @CustomerID,
            @CustomerName,
            @ICEncrypted,
            @Phone,
            @AddressDetail,
            @LoginName,
            @Salt,
            @Hash
        );

        /* ---------------------------------------------
           Insert account
           --------------------------------------------- */

        INSERT INTO dbo.Account
        (
            AccountID,
            CustomerID,
            AccountType
        )
        VALUES
        (
            @AccountID,
            @CustomerID,
            @AccountType
        );

        /* ---------------------------------------------
           Create SQL Server login
           Permission supplied by:
           Cert_LoginProvisioning
           --------------------------------------------- */

        SET @SQL =
            N'CREATE LOGIN ' +
            QUOTENAME(@LoginName) +
            N' WITH PASSWORD = ' +
            QUOTENAME(@DefaultPwd, '''') +
            N', CHECK_POLICY = OFF;';

        EXEC sys.sp_executesql @SQL;

        /* ---------------------------------------------
           Create database user
           --------------------------------------------- */

        SET @SQL =
            N'CREATE USER ' +
            QUOTENAME(@LoginName) +
            N' FOR LOGIN ' +
            QUOTENAME(@LoginName) +
            N';';

        EXEC sys.sp_executesql @SQL;

        /* ---------------------------------------------
           Add user to Customer role
           --------------------------------------------- */

        SET @SQL =
            N'ALTER ROLE Customer ADD MEMBER ' +
            QUOTENAME(@LoginName) +
            N';';

        EXEC sys.sp_executesql @SQL;

        COMMIT TRANSACTION;

        SELECT
            @CustomerID AS CustomerID,
            @AccountID AS AccountID,
            @LoginName AS LoginName;

    END TRY

    BEGIN CATCH

        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;

        /* Close key if error occurred after OPEN KEY */
        BEGIN TRY
            CLOSE SYMMETRIC KEY SK_SmartBank_CustomerPII;
        END TRY
        BEGIN CATCH
        END CATCH;

        DECLARE @ErrNum int;
        DECLARE @ErrMsg nvarchar(500);

        SET @ErrNum = ERROR_NUMBER();
        SET @ErrMsg = ERROR_MESSAGE();

        BEGIN TRY
            EXEC dbo.LogBusinessFailure
                @ProcedureName   = 'AddCustomer',
                @PrimaryKeyValue = @LoginName,
                @ErrorNumber     = @ErrNum,
                @ErrorMessage    = @ErrMsg;
        END TRY

        BEGIN CATCH
            /* Logging failure must not hide original error */
        END CATCH;

        THROW;

    END CATCH;
END;
GO


/* =========================================================
   ADD CUSTOMER CERTIFICATE SIGNATURES
   ========================================================= */

/*
    Allows AddCustomer to access the customer PII
    encryption key/certificate without granting the
    BankOfficer direct encryption permissions.
*/
ADD SIGNATURE TO OBJECT::dbo.AddCustomer
BY CERTIFICATE Cert_PIIModuleSigning;
GO

/*
    Allows AddCustomer to perform server-level
    login provisioning without granting BankOfficer
    ALTER ANY LOGIN.
*/
ADD SIGNATURE TO OBJECT::dbo.AddCustomer
BY CERTIFICATE Cert_LoginProvisioning;
GO


/* Bank Officers may execute the onboarding procedure */
GRANT EXECUTE
ON OBJECT::dbo.AddCustomer
TO BankOfficer;
GO


/* =========================================================
   ADD STAFF
   ========================================================= */

CREATE PROCEDURE dbo.AddStaff
    @StaffName nvarchar(100),
    @Position  varchar(20),
    @Branch    nvarchar(50),
    @Phone     varchar(20),
    @Salary    decimal(12,2),
    @LoginName sysname
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @Prefix      char(1);
    DECLARE @StaffID     varchar(6);
    DECLARE @RoleName    sysname;
    DECLARE @SQL         nvarchar(max);
    DECLARE @DefaultPwd  sysname;

    SET @DefaultPwd =
        CONVERT(sysname, @LoginName) + N'@123';

    BEGIN TRY
        BEGIN TRANSACTION;

        /* ---------------------------------------------
           Validate login name
           --------------------------------------------- */

        IF @LoginName IS NULL OR LTRIM(RTRIM(@LoginName)) = ''
        BEGIN
            THROW 52000, 'Login name cannot be empty.', 1;
        END;

        IF EXISTS (
            SELECT 1
            FROM sys.database_principals
            WHERE name = @LoginName
        )
        BEGIN
            THROW 52002, 'Database user already exists.', 1;
        END;

        SET @Position = LTRIM(RTRIM(@Position));

        /* ---------------------------------------------
           Determine Staff ID prefix and RBAC role
           --------------------------------------------- */

        IF @Position = 'DBA'
        BEGIN
            SET @Prefix = 'D';
            SET @RoleName = 'DBA';
        END

        ELSE IF @Position = 'Bank Manager'
        BEGIN
            SET @Prefix = 'M';
            SET @RoleName = 'BankManager';
        END

        ELSE IF @Position = 'Bank Officer'
        BEGIN
            SET @Prefix = 'O';
            SET @RoleName = 'BankOfficer';
        END

        ELSE
        BEGIN
            THROW 52001,
                'Invalid Position. Must be DBA, Bank Manager, or Bank Officer.',
                1;
        END;

        /* ---------------------------------------------
           Generate Staff ID
           --------------------------------------------- */

        EXEC dbo.sys_GetNextStaffID
            @Prefix  = @Prefix,
            @StaffID = @StaffID OUTPUT;

        /* ---------------------------------------------
           Insert Staff
           --------------------------------------------- */

        INSERT INTO dbo.Staff
        (
            StaffID,
            StaffName,
            Position,
            Branch,
            Phone,
            Salary,
            LoginName
        )
        VALUES
        (
            @StaffID,
            @StaffName,
            @Position,
            @Branch,
            @Phone,
            @Salary,
            @LoginName
        );

        /* ---------------------------------------------
           Create SQL Server login
           --------------------------------------------- */

        SET @SQL =
            N'CREATE LOGIN ' +
            QUOTENAME(@LoginName) +
            N' WITH PASSWORD = ' +
            QUOTENAME(@DefaultPwd, '''') +
            N', CHECK_POLICY = OFF;';

        EXEC sys.sp_executesql @SQL;

        /* ---------------------------------------------
           Create database user
           --------------------------------------------- */

        SET @SQL =
            N'CREATE USER ' +
            QUOTENAME(@LoginName) +
            N' FOR LOGIN ' +
            QUOTENAME(@LoginName) +
            N';';

        EXEC sys.sp_executesql @SQL;

        /* ---------------------------------------------
           Add database user to selected role
           --------------------------------------------- */

        SET @SQL =
            N'ALTER ROLE ' +
            QUOTENAME(@RoleName) +
            N' ADD MEMBER ' +
            QUOTENAME(@LoginName) +
            N';';

        EXEC sys.sp_executesql @SQL;

        COMMIT TRANSACTION;

        SELECT
            @StaffID AS StaffID,
            @LoginName AS LoginName,
            @RoleName AS AssignedRole;

    END TRY

    BEGIN CATCH

        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;

        DECLARE @ErrNum int;
        DECLARE @ErrMsg nvarchar(500);

        SET @ErrNum = ERROR_NUMBER();
        SET @ErrMsg = ERROR_MESSAGE();

        BEGIN TRY
            EXEC dbo.LogBusinessFailure
                @ProcedureName   = 'AddStaff',
                @PrimaryKeyValue = @LoginName,
                @ErrorNumber     = @ErrNum,
                @ErrorMessage    = @ErrMsg;
        END TRY

        BEGIN CATCH
            /* Logging failure must not hide original error */
        END CATCH;

        THROW;

    END CATCH;
END;
GO


/* =========================================================
   ADD STAFF CERTIFICATE SIGNATURE
   ========================================================= */

ADD SIGNATURE TO OBJECT::dbo.AddStaff
BY CERTIFICATE Cert_LoginProvisioning;
GO


/* Only DBA can provision staff */
GRANT EXECUTE
ON OBJECT::dbo.AddStaff
TO DBA;
GO


/* =========================================================
   VERIFICATION
   ========================================================= */

SELECT
    OBJECT_NAME(cp.major_id) AS ModuleName,
    cert.name AS CertificateName
FROM sys.crypt_properties AS cp
INNER JOIN sys.certificates AS cert
    ON cp.thumbprint = cert.thumbprint
WHERE cp.major_id IN
(
    OBJECT_ID('dbo.AddCustomer'),
    OBJECT_ID('dbo.AddStaff')
)
ORDER BY ModuleName, CertificateName;
GO