USE SmartBankDB;
GO

/* ===================================================================
   Row-Level Security predicate functions.
   USER_NAME() = 'dbo' is the escape hatch for system-internal helper
   procedures/functions running WITH EXECUTE AS OWNER - it lets those
   see the full table regardless of who originally called them,
   which legitimate cross-customer operations (transfers, sequential
   ID generation) need. Ordinary logins never run as 'dbo'. */

CREATE FUNCTION dbo.fn_CustomerRLSPredicate(@LoginName sysname)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_result
WHERE @LoginName = SUSER_SNAME()
   OR IS_ROLEMEMBER('StaffOp') = 1
   OR USER_NAME() = 'dbo';
GO

/* Account has no LoginName column, ownership is resolved via
   Customer. This is the row visible to a Customer if it's their
   own account; StaffOp and the 'dbo' helper context see everything */
CREATE FUNCTION dbo.fn_AccountRLSPredicate(@CustomerID varchar(6))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_result
WHERE IS_ROLEMEMBER('StaffOp') = 1
   OR USER_NAME() = 'dbo'
   OR EXISTS (
        SELECT 1 FROM dbo.Customer
        WHERE CustomerID = @CustomerID AND LoginName = SUSER_SNAME()
      );
GO

/* Customers see transactions they initiated. Also lets the RECIPIENT
   of a transfer see the incoming transaction - RelatedAccountID is an
   account ID, not a login, so ownership has to be resolved through
   Account -> Customer, same pattern as fn_AccountRLSPredicate. Without
   this, only the sender's side of a transfer was ever visible, even
   though the recipient's own money moved */
CREATE FUNCTION dbo.fn_TransactionRLSPredicate
(
    @InitiatedByLogin sysname,
    @RelatedAccountID varchar(10)
)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_result
WHERE @InitiatedByLogin = SUSER_SNAME()
   OR IS_ROLEMEMBER('StaffOp') = 1
   OR USER_NAME() = 'dbo'
   OR EXISTS (
        SELECT 1 FROM dbo.Account AS A
        INNER JOIN dbo.Customer AS C
            ON A.CustomerID = C.CustomerID
        WHERE A.AccountID = @RelatedAccountID
          AND C.LoginName = SUSER_SNAME()
      );
GO

/* Bank Manager/Officer rows are already meant to be broadly visible
   (PublicView exposes them to everyone). BankManager sees their own
   record plus all Bank Officer records, per assignment scope - not
   DBA rows. The previous IS_ROLEMEMBER('BankManager') = 1 exception
   existed only so AddStaff's ID generation could see hidden DBA
   rows; that's now handled internally by sys_GetNextStaffID
   (WITH EXECUTE AS OWNER), so the exception is no longer needed */
CREATE FUNCTION dbo.fn_StaffRLSPredicate(@LoginName sysname, @Position varchar(20))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_result
WHERE @LoginName = SUSER_SNAME()
   OR @Position IN ('Bank Manager', 'Bank Officer')
   OR USER_NAME() = 'dbo';
GO


/* ===================================================================
   Security policies, attach each predicate to its base table.
   Default filter predicate scope is SELECT/UPDATE/DELETE, INSERT is
   unaffected and stays governed by the existing GRANT/DENY structure */

CREATE SECURITY POLICY dbo.CustomerRLSPolicy
ADD FILTER PREDICATE dbo.fn_CustomerRLSPredicate(LoginName) ON dbo.Customer
WITH (STATE = ON);
GO

CREATE SECURITY POLICY dbo.AccountRLSPolicy
ADD FILTER PREDICATE dbo.fn_AccountRLSPredicate(CustomerID) ON dbo.Account
WITH (STATE = ON);
GO

CREATE SECURITY POLICY dbo.TransactionRLSPolicy
ADD FILTER PREDICATE dbo.fn_TransactionRLSPredicate(InitiatedByLogin, RelatedAccountID) ON dbo.TransactionRecord
WITH (STATE = ON);
GO

CREATE SECURITY POLICY dbo.StaffRLSPolicy
ADD FILTER PREDICATE dbo.fn_StaffRLSPredicate(LoginName, Position) ON dbo.Staff
WITH (STATE = ON);
GO


/* ===================================================================
   Transfer-safe helpers. A Customer's own account is visible under
   the predicate above, but a transfer destination belongs to someone
   else and would otherwise be invisible to both the existence check
   and the credit UPDATE. These run WITH EXECUTE AS OWNER so
   USER_NAME() = 'dbo' inside them, satisfying the predicate's escape
   hatch regardless of who actually called CustomerTransaction */

CREATE FUNCTION dbo.fn_sys_AccountExists(@AccountID varchar(10))
RETURNS bit
WITH EXECUTE AS OWNER
AS
BEGIN
    RETURN CASE WHEN EXISTS (SELECT 1 FROM dbo.Account WHERE AccountID = @AccountID)
                THEN 1 ELSE 0 END;
END;
GO

/* only performs the update, existence is checked separately first so
   a non-existent destination fails with 50005 rather than a silent
   0-row update reported as 50010 */
CREATE PROCEDURE dbo.sys_CreditDestinationAccount
    @AccountID varchar(10),
    @Amount    decimal(14,2),
    @Credited  bit OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE dbo.Account
    SET Balance = Balance + @Amount
    WHERE AccountID = @AccountID
      AND AccountStatus = 'Active';

    SET @Credited = CASE WHEN @@ROWCOUNT > 0 THEN 1 ELSE 0 END;
END;
GO

/* fix: AddStaff's sequential StaffID generation was computing MAX(...)
   directly against dbo.Staff, which is RLS-filtered. Now that DBA adds
   staff (not BankManager), a DBA calling AddStaff only sees their own
   row under StaffRLSPolicy's self-only default - the BankManager
   escape hatch there doesn't apply to them. MAX() over an incomplete
   view could compute a StaffID that collides with an existing row the
   caller can't see. Routed through the same WITH EXECUTE AS OWNER
   pattern as the transfer helpers above, so USER_NAME() = 'dbo'
   satisfies the RLS predicate's escape hatch and this sees every
   existing StaffID for the given prefix - narrowly, for ID generation
   only, not general Staff browsing */
CREATE PROCEDURE dbo.sys_GetNextStaffID
    @Prefix  char(1),
    @StaffID varchar(6) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    SELECT @StaffID =
        @Prefix +
        RIGHT(
            '00000' +
            CAST(
                ISNULL(
                    MAX(CAST(SUBSTRING(StaffID, 2, 5) AS int)),
                    0
                ) + 1 AS varchar(5)
            ),
            5
        )
    FROM dbo.Staff WITH (TABLOCKX, HOLDLOCK)
    WHERE StaffID LIKE @Prefix + '_____';
END;
GO