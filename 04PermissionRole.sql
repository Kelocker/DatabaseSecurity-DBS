USE SmartBankDB;
GO

/* Create Role */
CREATE ROLE Staff AUTHORIZATION dbo;
CREATE ROLE StaffOp AUTHORIZATION dbo;
CREATE ROLE DBA AUTHORIZATION dbo;
CREATE ROLE BankManager AUTHORIZATION dbo;
CREATE ROLE BankOfficer AUTHORIZATION dbo;
CREATE ROLE Customer AUTHORIZATION dbo;
GO

ALTER ROLE Staff ADD MEMBER DBA;
ALTER ROLE Staff ADD MEMBER StaffOp;
ALTER ROLE StaffOp ADD MEMBER BankManager;
ALTER ROLE StaffOp ADD MEMBER BankOfficer;
GO


/* Encryption for IC */
CREATE CERTIFICATE Cert_PIIModuleSigning
    WITH SUBJECT = N'Signs modules permitted to decrypt SmartBank customer PII',
         EXPIRY_DATE = '20351231';
GO

CREATE USER User_PIIModuleSigning
FROM CERTIFICATE Cert_PIIModuleSigning;
GO

/* Allow signed PII modules to use the CLE certificate */
GRANT CONTROL
ON CERTIFICATE::Cert_SmartBank_CLE
TO User_PIIModuleSigning;
GO

/* Allow signed PII modules to access the customer PII symmetric key */
GRANT VIEW DEFINITION
ON SYMMETRIC KEY::SK_SmartBank_CustomerPII
TO User_PIIModuleSigning;
GO

/* fix: renamed from GetOwnICNumber and extended to the full customer
   profile, since it now covers all Customer fields (not just IC).
   Stays a signed procedure - not a view - because DECRYPTBYKEYAUTOCERT
   needs signing, and views cannot be signed */
/* fix: trimmed to core identity fields only. LoginName/FailedPINAttempts/
   PINLockedUntilMYT are security/account-status metadata, not profile
   data - excluding them keeps this endpoint to strictly minimal PII
   exposure */
CREATE OR ALTER PROCEDURE dbo.CustomerViewOwnProfile
AS
BEGIN
    SET NOCOUNT ON;

    OPEN SYMMETRIC KEY SK_SmartBank_CustomerPII
        DECRYPTION BY CERTIFICATE Cert_SmartBank_CLE;

    SELECT
        C.CustomerID,
        C.CustomerName,
        CONVERT(varchar(50), DecryptByKey(C.ICNumberEncrypted, 1, C.CustomerID)) AS ICNumber,
        C.Phone,
        C.AddressDetail,
        C.LoginName
    FROM dbo.Customer AS C
    WHERE C.LoginName = SUSER_SNAME();

    CLOSE SYMMETRIC KEY SK_SmartBank_CustomerPII;
END;
GO

ADD SIGNATURE TO dbo.CustomerViewOwnProfile
BY CERTIFICATE Cert_PIIModuleSigning;
GO

GRANT EXECUTE ON OBJECT::dbo.CustomerViewOwnProfile TO Customer;
GO



/* Public Permission */
/* Create view for StaffName and Phone */
CREATE VIEW dbo.PublicView
AS
SELECT
    StaffName,
    Phone,
    Position
FROM dbo.Staff
WHERE Position IN ('Bank Manager', 'Bank Officer');
GO

GRANT SELECT
ON OBJECT::dbo.PublicView
TO public;
GO


/* Role View Permission */
/* Staff View own record */
CREATE VIEW dbo.StaffViewOwnRecord
AS 
SELECT StaffID, StaffName, Position, Branch, Phone, Salary, LoginName
FROM dbo.Staff
WHERE LoginName = SUSER_SNAME();
GO

GRANT SELECT
ON OBJECT::dbo.StaffViewOwnRecord
TO Staff;
GO

/* Bank Manager View */
CREATE VIEW dbo.ManagerViewBankOfficer
AS
SELECT
    StaffID,
    StaffName,
    Position,
    Branch,
    Phone,
    Salary,
    LoginName
FROM dbo.Staff
WHERE Position = 'Bank Officer';
GO

GRANT SELECT
ON OBJECT::dbo.ManagerViewBankOfficer
TO BankManager;
GO

/* Bank Manager and Bank Officer View */
CREATE VIEW dbo.ViewCustomerRecord
AS
SELECT
    CustomerID,
    CustomerName,
    Phone,
    AddressDetail,
    FailedPINAttempts,
    PINLockedUntilMYT
FROM dbo.Customer;
GO



CREATE VIEW dbo.ViewCustomerAccount
AS
SELECT AccountID, CustomerID, AccountType, Balance, AccountStatus
FROM dbo.Account;
GO

CREATE VIEW dbo.ViewTransaction
AS
SELECT
    TransID,
    InitiatedByLogin,
    TransactionType,
    AccountID,
    CustomerID,
    RelatedAccountID,
    TransDateMYT,
    Amount
FROM dbo.TransactionRecord;
GO

GRANT SELECT
ON OBJECT::dbo.ViewCustomerRecord
TO StaffOp;
GO

GRANT SELECT
ON OBJECT::dbo.ViewCustomerAccount
TO StaffOp;
GO

GRANT SELECT
ON OBJECT::dbo.ViewTransaction
TO StaffOp;
GO

/* Bank officer Update customer dertails */
GRANT UPDATE (CustomerName, Phone, AddressDetail)
ON OBJECT::dbo.ViewCustomerRecord
TO BankOfficer;
GO

/* Customer View */
CREATE VIEW dbo.CustomerViewOwnAccount
AS
SELECT
    AccountID,
    CustomerID,
    AccountType,
    Balance,
    AccountStatus
FROM dbo.Account;
GO

CREATE VIEW dbo.CustomerViewTransaction
AS
SELECT
    TransID,
    InitiatedByLogin,
    TransactionType,
    AccountID,
    CustomerID,
    RelatedAccountID,
    TransDateMYT,
    Amount
FROM dbo.TransactionRecord;
GO

GRANT SELECT
ON OBJECT::dbo.CustomerViewOwnAccount
TO Customer;
GO

GRANT SELECT
ON OBJECT::dbo.CustomerViewTransaction
TO Customer;
GO


/* Role Action Permission */
/* DBA create and manage table only */
GRANT CREATE TABLE TO dba;

GRANT ALTER ON SCHEMA::dbo TO dba;
GO

DENY ALTER ON OBJECT::dbo.PublicView             TO dba;
DENY ALTER ON OBJECT::dbo.StaffViewOwnRecord      TO dba;
DENY ALTER ON OBJECT::dbo.ManagerViewBankOfficer  TO dba;
DENY ALTER ON OBJECT::dbo.ViewCustomerRecord      TO dba;
DENY ALTER ON OBJECT::dbo.ViewCustomerAccount     TO dba;
DENY ALTER ON OBJECT::dbo.ViewTransaction         TO dba;
DENY ALTER ON OBJECT::dbo.CustomerViewOwnAccount  TO dba;
DENY ALTER ON OBJECT::dbo.CustomerViewTransaction TO dba;

/* Staff updates own record except for salary */
GRANT UPDATE (StaffName, Phone)
ON OBJECT::dbo.StaffViewOwnRecord
TO Staff;
GO
    

/* Bank Manager manage Officer account, includes salary */
GRANT UPDATE
(
    StaffName,
    Branch,
    Phone,
    Salary
)
ON OBJECT::dbo.ManagerViewBankOfficer
TO BankManager;
GO

/* Bank Officer manage customer account, Balance excluded on purpose
   since Balance may only change via dbo.CustomerTransaction */
GRANT UPDATE (AccountType, AccountStatus)
ON OBJECT::dbo.ViewCustomerAccount
TO BankOfficer;
GO


/* Customer only perform transaction,
valid transaction: deposit, withdrawwal and transfer.*/
CREATE PROCEDURE dbo.CustomerTransaction
    @AccountID        varchar(10),
    @Amount           decimal(18,6),
    @TransactionType  varchar(20),
    @TransactionPIN   varchar(6),
    @RelatedAccountID varchar(10) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @CustomerID varchar(6);

    SET @TransactionType =
        LOWER(LTRIM(RTRIM(@TransactionType)));

    SET @RelatedAccountID =
        NULLIF(LTRIM(RTRIM(@RelatedAccountID)), '');

    BEGIN TRY
        /* Verify the supplied account actually belongs to the
           logged-in customer, rather than assuming a single account.
           Visible under the RLS predicate since it belongs to the
           caller. Read-only, kept outside any explicit transaction */
        SELECT @CustomerID = A.CustomerID
        FROM dbo.Account AS A
        INNER JOIN dbo.Customer AS C
            ON A.CustomerID = C.CustomerID
        WHERE A.AccountID = @AccountID
          AND C.LoginName = SUSER_SNAME();

        IF @CustomerID IS NULL
        BEGIN
            THROW 50001,
                  'The selected account does not belong to the logged-in customer.',
                  1;
        END;

        /* PIN verification, own row, RLS allows it via LoginName = SUSER_SNAME() */
        DECLARE @Salt              varbinary(16);
        DECLARE @StoredHash        varbinary(32);
        DECLARE @FailedAttempts    tinyint;
        DECLARE @PINLockedUntilMYT datetime2(0);
        DECLARE @ComputedHash      varbinary(32);
        DECLARE @NewFailedAttempts tinyint;

        SELECT
            @Salt              = TransactionPINSalt,
            @StoredHash        = TransactionPINHash,
            @FailedAttempts    = FailedPINAttempts,
            @PINLockedUntilMYT = PINLockedUntilMYT
        FROM dbo.Customer
        WHERE CustomerID = @CustomerID;

        IF @PINLockedUntilMYT IS NOT NULL
        BEGIN
            THROW 50011,
                  'Your account is locked due to too many failed PIN attempts. Contact a Bank Officer to unlock it.',
                  1;
        END;

        SET @ComputedHash = HASHBYTES('SHA2_256', @Salt + CONVERT(varbinary(10), @TransactionPIN));

        IF @ComputedHash <> @StoredHash
        BEGIN
            SET @NewFailedAttempts = @FailedAttempts + 1;

            /* single UPDATE statement, auto-commits immediately since
               no explicit transaction is open yet - this persists
               even though the procedure throws right after */
            UPDATE dbo.Customer
            SET FailedPINAttempts = @NewFailedAttempts,
                PINLockedUntilMYT = CASE WHEN @NewFailedAttempts >= 5
                                         THEN DATEADD(HOUR, 8, SYSUTCDATETIME())
                                         ELSE NULL END
            WHERE CustomerID = @CustomerID;

            IF @NewFailedAttempts >= 5
            BEGIN
                THROW 50012,
                      'Incorrect PIN. Your account has been locked due to too many failed attempts. Contact a Bank Officer to unlock it.',
                      1;
            END
            ELSE
            BEGIN
                THROW 50012,
                      'Incorrect PIN.',
                      1;
            END;
        END;

        /* correct PIN, reset any accumulated failed attempts, also
           auto-commits immediately outside any explicit transaction */
        IF @FailedAttempts > 0
        BEGIN
            UPDATE dbo.Customer
            SET FailedPINAttempts = 0,
                PINLockedUntilMYT = NULL
            WHERE CustomerID = @CustomerID;
        END;

        BEGIN TRANSACTION;

        IF @TransactionType NOT IN
           ('deposit', 'withdrawal', 'transfer')
        BEGIN
            THROW 50002,
                  'Customers may only perform deposit, withdrawal, or transfer transactions.',
                  1;
        END;

        IF @Amount <= 0
        BEGIN
            THROW 50003,
                  'Transaction amount must be greater than zero.',
                  1;
        END;

        IF @Amount <> ROUND(@Amount, 2)
        BEGIN
            THROW 51002, 'Amount cannot contain more than 2 decimal places.', 1;
        END;

        IF @Amount > 99999999.99
        BEGIN
            THROW 51003, 'Transaction amount exceeds the permitted limit.', 1;
        END;


        /* RelatedAccountID is only allowed for transfers */
        IF @TransactionType <> 'transfer'
        BEGIN
            SET @RelatedAccountID = NULL;
        END;

        /* Transfer validation */
        IF @TransactionType = 'transfer'
        BEGIN
            IF @RelatedAccountID IS NULL
            BEGIN
                THROW 50004,
                      'You need to provide an account ID for a transfer.',
                      1;
            END;

            /* destination belongs to someone else, invisible under
               Account's RLS predicate, checked via the RLS-bypassing
               helper instead of a direct EXISTS on dbo.Account */
            IF dbo.fn_sys_AccountExists(@RelatedAccountID) = 0
            BEGIN
                THROW 50005,
                      'The destination account was not found.',
                      1;
            END;

            IF @AccountID = @RelatedAccountID
            BEGIN
                THROW 50006,
                      'You cannot transfer to the same account.',
                      1;
            END;

            

        END;

        /* Deposit */
        IF @TransactionType = 'deposit'
        BEGIN
            UPDATE dbo.Account
            SET Balance = Balance + @Amount
            WHERE AccountID = @AccountID
              AND AccountStatus = 'Active';

            IF @@ROWCOUNT = 0
            BEGIN
                THROW 50007,
                      'The account is not active.',
                      1;
            END;
        END;

        /* Withdrawal */
        ELSE IF @TransactionType = 'withdrawal'
        BEGIN
            UPDATE dbo.Account
            SET Balance = Balance - @Amount
            WHERE AccountID = @AccountID
              AND AccountStatus = 'Active'
              AND Balance >= @Amount;

            IF @@ROWCOUNT = 0
            BEGIN
                THROW 50008,
                      'The account is inactive or has insufficient balance.',
                      1;
            END;
        END;

        /* Transfer */
        ELSE IF @TransactionType = 'transfer'
        BEGIN
            /* Deduct from the customer's own account, visible normally */
            UPDATE dbo.Account
            SET Balance = Balance - @Amount
            WHERE AccountID = @AccountID
              AND AccountStatus = 'Active'
              AND Balance >= @Amount;

            IF @@ROWCOUNT = 0
            BEGIN
                THROW 50009,
                      'The source account is inactive or has insufficient balance.',
                      1;
            END;

            /* credit routed through the RLS-bypassing helper, a
               direct UPDATE here would silently affect 0 rows since
               the destination is invisible under the RLS predicate */
            DECLARE @DestCredited bit;
            EXEC dbo.sys_CreditDestinationAccount
                @AccountID = @RelatedAccountID,
                @Amount    = @Amount,
                @Credited  = @DestCredited OUTPUT;

            IF @DestCredited = 0
            BEGIN
                THROW 50010,
                      'The destination account is not active.',
                      1;
            END;
        END;

        /* Record the successful transaction */
        INSERT INTO dbo.TransactionRecord
        (
            InitiatedByLogin,
            TransactionType,
            AccountID,
            CustomerID,
            RelatedAccountID,
            Amount
        )
        VALUES
        (
            SUSER_SNAME(),
            @TransactionType,
            @AccountID,
            @CustomerID,
            @RelatedAccountID,
            @Amount
        );
 
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;

        DECLARE @ErrNum int = ERROR_NUMBER();
        DECLARE @ErrMsg nvarchar(500) = ERROR_MESSAGE();

        BEGIN TRY
            EXEC dbo.LogBusinessFailure
                @ProcedureName   = 'CustomerTransaction',
                @PrimaryKeyValue = @AccountID,
                @ErrorNumber     = @ErrNum,
                @ErrorMessage    = @ErrMsg;
        END TRY
        BEGIN CATCH
            /* fail-open: a logging problem must not mask the original error */
        END CATCH;

        THROW;
    END CATCH
END;
GO
 
GRANT EXECUTE
ON OBJECT::dbo.CustomerTransaction
TO Customer;
GO


/* Required companion to the indefinite lock above - without this,
   a locked customer has no way back in. Ownership chaining lets
   this UPDATE dbo.Customer without StaffOp needing a direct GRANT,
   and RLS already allows it via IS_ROLEMEMBER('StaffOp') = 1 */
CREATE PROCEDURE dbo.UnlockCustomerPIN
    @CustomerID varchar(6)
AS
BEGIN
    SET NOCOUNT ON;

    BEGIN TRY
        UPDATE dbo.Customer
        SET FailedPINAttempts = 0,
            PINLockedUntilMYT = NULL
        WHERE CustomerID = @CustomerID;

        IF @@ROWCOUNT = 0
        BEGIN
            THROW 60001, 'Customer not found.', 1;
        END;
    END TRY
    BEGIN CATCH
        DECLARE @ErrNum int = ERROR_NUMBER();
        DECLARE @ErrMsg nvarchar(500) = ERROR_MESSAGE();

        BEGIN TRY
            EXEC dbo.LogBusinessFailure
                @ProcedureName   = 'UnlockCustomerPIN',
                @PrimaryKeyValue = @CustomerID,
                @ErrorNumber     = @ErrNum,
                @ErrorMessage    = @ErrMsg;
        END TRY
        BEGIN CATCH
        END CATCH;

        THROW;
    END CATCH
END;
GO

GRANT EXECUTE ON OBJECT::dbo.UnlockCustomerPIN TO BankOfficer;
GO

GRANT UNMASK ON dbo.Customer (Phone) TO BankOfficer;
GRANT UNMASK ON dbo.Customer (AddressDetail) TO BankOfficer;
GRANT UNMASK ON dbo.Account (Balance) TO BankOfficer;

GRANT UNMASK ON dbo.Customer (Phone) TO Customer;
GRANT UNMASK ON dbo.Customer (AddressDetail) TO Customer;
GRANT UNMASK ON dbo.Customer (ICNumberEncrypted) TO Customer;
GRANT UNMASK ON dbo.Account (Balance) TO Customer
GO

DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Customer TO DBA;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Account TO DBA;
DENY CONTROL ON dbo.Customer TO BankManager;
DENY CONTROL ON dbo.Account TO BankManager;
DENY CONTROL ON dbo.TransactionRecord TO StaffOp, Customer;
DENY CONTROL ON dbo.Staff TO StaffOp, Customer;
GO


/* Self-service permission lookup - lets any logged-in actor
   (Customer, DBA, BankManager, BankOfficer) see their own effective
   access, without needing StaffOp/sysadmin rights to query
   sys.database_permissions directly. Uses the built-in
   fn_my_permissions(), which reports whatever the CALLING session
   actually has, automatically accounting for role membership.

   Deliberately runs as the caller (no WITH EXECUTE AS OWNER) - that
   impersonation pattern is used elsewhere in this project specifically
   to bypass the caller's own identity, which is the opposite of what
   this needs. If this ran as owner, everyone would just see dbo's
   permissions instead of their own. */
CREATE OR ALTER PROCEDURE dbo.MyPermission
AS
BEGIN
    SET NOCOUNT ON;

    /* who am I, and which roles do I belong to */
    SELECT DISTINCT
        SUSER_SNAME() AS LoginName,
        USER_NAME()   AS DatabaseUser,
        dp.name       AS RoleName
    FROM sys.database_role_members AS drm
    JOIN sys.database_principals AS dp ON drm.role_principal_id = dp.principal_id
    JOIN sys.database_principals AS mp ON drm.member_principal_id = mp.principal_id
    WHERE mp.name = USER_NAME();

    /* database-level permissions (e.g. CREATE TABLE, ALTER ON SCHEMA) */
    SELECT DISTINCT permission_name
    FROM sys.fn_my_permissions(NULL, 'DATABASE');

    /* effective permissions on every table/view/procedure/function,
       skipping system objects */
    SELECT DISTINCT
        SCHEMA_NAME(o.schema_id) + '.' + o.name AS ObjectName,
        o.type_desc                             AS ObjectType,
        p.permission_name
    FROM sys.objects AS o
    CROSS APPLY sys.fn_my_permissions(
        SCHEMA_NAME(o.schema_id) + '.' + o.name,
        'OBJECT'
    ) AS p
    WHERE o.type IN ('U','V','P','FN','TF','IF')
      AND o.is_ms_shipped = 0
    ORDER BY ObjectName, p.permission_name;
END;
GO

GRANT EXECUTE ON OBJECT::dbo.MyPermission TO public;
GO