CREATE TABLE dbo.RollbackLog
(
    LogID           int           IDENTITY(1,1) PRIMARY KEY,
    EntityType      varchar(20)   NOT NULL,
    EntityKey       varchar(10)   NOT NULL,
    ColumnName      sysname       NOT NULL,
    OldValue        nvarchar(200) NULL,
    RestoredValue   nvarchar(200) NULL,
    RestoredAsOfUTC datetime2(0)  NOT NULL,
    ChangedBy       sysname       NOT NULL CONSTRAINT DF_RollbackLog_ChangedBy DEFAULT ORIGINAL_LOGIN(),
    ChangedAtMYT    datetime2(0)  NOT NULL CONSTRAINT DF_RollbackLog_ChangedAtMYT DEFAULT (DATEADD(HOUR, 8, SYSUTCDATETIME())),
    CONSTRAINT CK_RollbackLog_EntityType CHECK (EntityType IN ('Staff','Customer'))
);
GO
 
REVOKE SELECT ON dbo.RollbackLog FROM public;
GO
 
GRANT SELECT ON dbo.RollbackLog TO DBA;
GO
 
 
/* =========================================================
   1. STAFF - REVERT OWN DETAILS
   Mirrors: GRANT UPDATE (StaffName, Phone)
            ON dbo.StaffViewOwnRecord TO Staff
   Scoped by SUSER_SNAME() - cannot target anyone else's row.
   ========================================================= */
 
CREATE PROCEDURE dbo.RestoreOwnStaffRecord
    @AsOf datetime2(0)   -- UTC
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
 
    BEGIN TRY
        IF @AsOf >= SYSUTCDATETIME()
            THROW 53000, 'AsOf must be a point in the past.', 1;
 
        DECLARE @StaffID varchar(6);
        DECLARE @Cur_StaffName nvarchar(100), @Cur_Phone varchar(20);
        DECLARE @Old_StaffName nvarchar(100), @Old_Phone varchar(20);
 
        SELECT @StaffID = StaffID, @Cur_StaffName = StaffName, @Cur_Phone = Phone
        FROM dbo.Staff
        WHERE LoginName = SUSER_SNAME();
 
        IF @StaffID IS NULL
            THROW 53001, 'No staff record found for the calling login.', 1;
 
        SELECT @Old_StaffName = StaffName, @Old_Phone = Phone
        FROM dbo.Staff FOR SYSTEM_TIME AS OF @AsOf
        WHERE StaffID = @StaffID;
 
        IF @Old_StaffName IS NULL AND @Old_Phone IS NULL
            THROW 53002, 'No historical version of this record exists as of that time.', 1;
 
        BEGIN TRANSACTION;
 
        IF @Old_StaffName IS NOT NULL AND @Old_StaffName <> @Cur_StaffName
        BEGIN
            UPDATE dbo.Staff SET StaffName = @Old_StaffName WHERE StaffID = @StaffID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Staff', @StaffID, 'StaffName', @Cur_StaffName, @Old_StaffName, @AsOf);
        END;
 
        IF @Old_Phone IS NOT NULL AND @Old_Phone <> @Cur_Phone
        BEGIN
            UPDATE dbo.Staff SET Phone = @Old_Phone WHERE StaffID = @StaffID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Staff', @StaffID, 'Phone', @Cur_Phone, @Old_Phone, @AsOf);
        END;
 
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
 
        DECLARE @ErrNum1 int = ERROR_NUMBER();
        DECLARE @ErrMsg1 nvarchar(500) = ERROR_MESSAGE();
 
        BEGIN TRY
            EXEC dbo.LogBusinessFailure
                @ProcedureName = 'RestoreOwnStaffRecord',
                @PrimaryKeyValue = NULL,
                @ErrorNumber = @ErrNum1,
                @ErrorMessage = @ErrMsg1;
        END TRY
        BEGIN CATCH END CATCH;
 
        THROW;
    END CATCH
END;
GO
 
GRANT EXECUTE ON OBJECT::dbo.RestoreOwnStaffRecord TO Staff;
GO
 
 
/* =========================================================
   2. BANK MANAGER - REVERT A (BANK OFFICER) STAFF RECORD
   Mirrors: GRANT UPDATE (StaffName, Branch, Phone, Salary)
            ON dbo.ManagerViewBankOfficer TO BankManager
   Still checked against Position = 'Bank Officer', same as the
   view it mirrors - a manager's UPDATE grant never covered DBA or
   other manager rows, so the rollback doesn't either.
   ========================================================= */
 
CREATE PROCEDURE dbo.RestoreStaffRecord
    @StaffID varchar(6),
    @AsOf    datetime2(0)   -- UTC
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
 
    BEGIN TRY
        IF @AsOf >= SYSUTCDATETIME()
            THROW 53010, 'AsOf must be a point in the past.', 1;
 
        DECLARE @Cur_StaffName nvarchar(100), @Cur_Branch nvarchar(50),
                @Cur_Phone varchar(20), @Cur_Salary decimal(12,2);
        DECLARE @Old_StaffName nvarchar(100), @Old_Branch nvarchar(50),
                @Old_Phone varchar(20), @Old_Salary decimal(12,2);
 
        SELECT
            @Cur_StaffName = StaffName, @Cur_Branch = Branch,
            @Cur_Phone = Phone, @Cur_Salary = Salary
        FROM dbo.Staff
        WHERE StaffID = @StaffID AND Position = 'Bank Officer';
 
        IF @@ROWCOUNT = 0
            THROW 53011, 'No Bank Officer record found for that StaffID.', 1;
 
        SELECT
            @Old_StaffName = StaffName, @Old_Branch = Branch,
            @Old_Phone = Phone, @Old_Salary = Salary
        FROM dbo.Staff FOR SYSTEM_TIME AS OF @AsOf
        WHERE StaffID = @StaffID AND Position = 'Bank Officer';
 
        IF @Old_StaffName IS NULL AND @Old_Branch IS NULL
           AND @Old_Phone IS NULL AND @Old_Salary IS NULL
            THROW 53012, 'No historical version of this record exists as of that time (or it was not a Bank Officer then).', 1;
 
        BEGIN TRANSACTION;
 
        IF @Old_StaffName IS NOT NULL AND @Old_StaffName <> @Cur_StaffName
        BEGIN
            UPDATE dbo.Staff SET StaffName = @Old_StaffName WHERE StaffID = @StaffID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Staff', @StaffID, 'StaffName', @Cur_StaffName, @Old_StaffName, @AsOf);
        END;
 
        IF @Old_Branch IS NOT NULL AND @Old_Branch <> @Cur_Branch
        BEGIN
            UPDATE dbo.Staff SET Branch = @Old_Branch WHERE StaffID = @StaffID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Staff', @StaffID, 'Branch', @Cur_Branch, @Old_Branch, @AsOf);
        END;
 
        IF @Old_Phone IS NOT NULL AND @Old_Phone <> @Cur_Phone
        BEGIN
            UPDATE dbo.Staff SET Phone = @Old_Phone WHERE StaffID = @StaffID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Staff', @StaffID, 'Phone', @Cur_Phone, @Old_Phone, @AsOf);
        END;
 
        IF @Old_Salary IS NOT NULL AND @Old_Salary <> @Cur_Salary
        BEGIN
            UPDATE dbo.Staff SET Salary = @Old_Salary WHERE StaffID = @StaffID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Staff', @StaffID, 'Salary', CAST(@Cur_Salary AS nvarchar(50)), CAST(@Old_Salary AS nvarchar(50)), @AsOf);
        END;
 
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
 
        DECLARE @ErrNum2 int = ERROR_NUMBER();
        DECLARE @ErrMsg2 nvarchar(500) = ERROR_MESSAGE();
 
        BEGIN TRY
            EXEC dbo.LogBusinessFailure
                @ProcedureName = 'RestoreStaffRecord',
                @PrimaryKeyValue = @StaffID,
                @ErrorNumber = @ErrNum2,
                @ErrorMessage = @ErrMsg2;
        END TRY
        BEGIN CATCH END CATCH;
 
        THROW;
    END CATCH
END;
GO
 
GRANT EXECUTE ON OBJECT::dbo.RestoreStaffRecord TO BankManager;
GO
 
/* =========================================================
   4. BANK OFFICER - REVERT A CUSTOMER'S DETAILS
   Mirrors: GRANT UPDATE (CustomerName, Phone, AddressDetail)
            ON dbo.ViewCustomerRecord TO BankOfficer
   ========================================================= */
 
CREATE PROCEDURE dbo.RestoreCustomerRecord
    @CustomerID varchar(6),
    @AsOf       datetime2(0)   -- UTC
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
 
    BEGIN TRY
        IF @AsOf >= SYSUTCDATETIME()
            THROW 53030, 'AsOf must be a point in the past.', 1;
 
        DECLARE @Cur_Name nvarchar(100), @Cur_Phone varchar(20), @Cur_Address nvarchar(200);
        DECLARE @Old_Name nvarchar(100), @Old_Phone varchar(20), @Old_Address nvarchar(200);
 
        SELECT @Cur_Name = CustomerName, @Cur_Phone = Phone, @Cur_Address = AddressDetail
        FROM dbo.Customer
        WHERE CustomerID = @CustomerID;
 
        IF @@ROWCOUNT = 0
            THROW 53031, 'Customer not found.', 1;
 
        SELECT @Old_Name = CustomerName, @Old_Phone = Phone, @Old_Address = AddressDetail
        FROM dbo.Customer FOR SYSTEM_TIME AS OF @AsOf
        WHERE CustomerID = @CustomerID;
 
        IF @Old_Name IS NULL AND @Old_Phone IS NULL AND @Old_Address IS NULL
            THROW 53032, 'No historical version of this record exists as of that time.', 1;
 
        BEGIN TRANSACTION;
 
        IF @Old_Name IS NOT NULL AND @Old_Name <> @Cur_Name
        BEGIN
            UPDATE dbo.Customer SET CustomerName = @Old_Name WHERE CustomerID = @CustomerID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Customer', @CustomerID, 'CustomerName', @Cur_Name, @Old_Name, @AsOf);
        END;
 
        IF @Old_Phone IS NOT NULL AND @Old_Phone <> @Cur_Phone
        BEGIN
            UPDATE dbo.Customer SET Phone = @Old_Phone WHERE CustomerID = @CustomerID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Customer', @CustomerID, 'Phone', @Cur_Phone, @Old_Phone, @AsOf);
        END;
 
        IF @Old_Address IS NOT NULL AND @Old_Address <> @Cur_Address
        BEGIN
            UPDATE dbo.Customer SET AddressDetail = @Old_Address WHERE CustomerID = @CustomerID;
            INSERT INTO dbo.RollbackLog (EntityType, EntityKey, ColumnName, OldValue, RestoredValue, RestoredAsOfUTC)
            VALUES ('Customer', @CustomerID, 'AddressDetail', @Cur_Address, @Old_Address, @AsOf);
        END;
 
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
 
        DECLARE @ErrNum4 int = ERROR_NUMBER();
        DECLARE @ErrMsg4 nvarchar(500) = ERROR_MESSAGE();
 
        BEGIN TRY
            EXEC dbo.LogBusinessFailure
                @ProcedureName = 'RestoreCustomerRecord',
                @PrimaryKeyValue = @CustomerID,
                @ErrorNumber = @ErrNum4,
                @ErrorMessage = @ErrMsg4;
        END TRY
        BEGIN CATCH END CATCH;
 
        THROW;
    END CATCH
END;
GO
 
GRANT EXECUTE ON OBJECT::dbo.RestoreCustomerRecord TO BankOfficer;
GO