Use SmartBankDB; 
GO

CREATE TABLE dbo.Staff
(
    StaffID       varchar(6)     NOT NULL,
    StaffName     nvarchar(100)  NOT NULL,
    Position      varchar(20)    NOT NULL,
    Branch        nvarchar(50)   NOT NULL,
    Phone         varchar(20)    NOT NULL,
    Salary        decimal(12,2)  NOT NULL,
    LoginName     sysname        NOT NULL,
    ValidFrom     DATETIME2 GENERATED ALWAYS AS ROW START NOT NULL,
    ValidTo       DATETIME2 GENERATED ALWAYS AS ROW END NOT NULL,
    CONSTRAINT PK_Staff PRIMARY KEY (StaffID),
    CONSTRAINT UQ_Staff_LoginName UNIQUE (LoginName),
    CONSTRAINT CK_Staff_IDPosition CHECK
    (
        (StaffID LIKE 'D[0-9][0-9][0-9][0-9][0-9]' AND Position = 'DBA')
        OR
        (StaffID LIKE 'M[0-9][0-9][0-9][0-9][0-9]' AND Position = 'Bank Manager')
        OR
        (StaffID LIKE 'O[0-9][0-9][0-9][0-9][0-9]' AND Position = 'Bank Officer')
    ),
    CONSTRAINT CK_Staff_Position CHECK (Position IN ('DBA','Bank Manager','Bank Officer')),
    CONSTRAINT CK_Staff_Salary CHECK (Salary BETWEEN 1.00 AND 100000.00),
    CONSTRAINT CK_Staff_Phone CHECK (LEN(Phone) BETWEEN 9 AND 20),
    PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo)
)
WITH (SYSTEM_VERSIONING = ON
    (HISTORY_TABLE = dbo.StaffHistory));


CREATE TABLE dbo.Customer
(
    CustomerID        varchar(6)      NOT NULL,
    CustomerName      nvarchar(100)   NOT NULL,
    ICNumberEncrypted varbinary(256)  NOT NULL,
    Phone             varchar(20)     NOT NULL,
    AddressDetail           nvarchar(200)   NOT NULL,
    LoginName         sysname         NOT NULL,
    TransactionPINSalt varbinary(16)  NOT NULL,
    TransactionPINHash varbinary(32)  NOT NULL,
    FailedPINAttempts  tinyint         NOT NULL CONSTRAINT DF_Customer_FailedPINAttempts DEFAULT (0),
    PINLockedUntilMYT datetime2(0) NULL,
    ValidFrom          DATETIME2 GENERATED ALWAYS AS ROW START NOT NULL,
    ValidTo             DATETIME2 GENERATED ALWAYS AS ROW END NOT NULL,
    CONSTRAINT PK_Customer PRIMARY KEY (CustomerID),
    CONSTRAINT UQ_Customer_LoginName UNIQUE (LoginName),
    CONSTRAINT CK_Customer_ID CHECK (CustomerID LIKE 'C[0-9][0-9][0-9][0-9][0-9]'),
    CONSTRAINT CK_Customer_Phone CHECK (LEN(Phone) BETWEEN 9 AND 20),
    CONSTRAINT CK_Customer_PINHashLength CHECK (DATALENGTH(TransactionPINHash) = 32),
    CONSTRAINT CK_Customer_PINSaltLength CHECK (DATALENGTH(TransactionPINSalt) = 16),
    CONSTRAINT CK_Customer_FailedPINAttempts CHECK (FailedPINAttempts BETWEEN 0 AND 5),
    CONSTRAINT CK_Customer_PINLockConsistency CHECK
    (
        (FailedPINAttempts < 5 AND PINLockedUntilMYT IS NULL)
        OR (FailedPINAttempts = 5 AND PINLockedUntilMYT IS NOT NULL)
    ),
    PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo)
)
WITH (SYSTEM_VERSIONING = ON
    (HISTORY_TABLE = dbo.CustomerHistory));


CREATE TABLE dbo.Account
(
    AccountID    varchar(10)    NOT NULL,
    CustomerID   varchar(6)     NOT NULL,
    AccountType  varchar(20)    NOT NULL,
    Balance      decimal(14,2)  NOT NULL CONSTRAINT DF_Account_Balance DEFAULT (0),
    AccountStatus varchar(10)   NOT NULL CONSTRAINT DF_Account_Status DEFAULT ('Active'),
    ValidFrom    DATETIME2 GENERATED ALWAYS AS ROW START NOT NULL,
    ValidTo      DATETIME2 GENERATED ALWAYS AS ROW END NOT NULL,
    CONSTRAINT PK_Account PRIMARY KEY (AccountID),
    CONSTRAINT UQ_Account_AccountCustomer UNIQUE (AccountID, CustomerID),
    CONSTRAINT CK_Account_ID CHECK (AccountID LIKE 'A[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]'),
    CONSTRAINT FK_Account_Customer FOREIGN KEY (CustomerID)
        REFERENCES dbo.Customer(CustomerID),
    CONSTRAINT CK_Account_Type CHECK (AccountType IN ('Savings','Current')),
    CONSTRAINT CK_Account_Balance CHECK (Balance >= 0),
    CONSTRAINT CK_Account_Status CHECK (AccountStatus IN ('Active','Frozen','Closed')),
    PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo)
)
WITH (SYSTEM_VERSIONING = ON
    (HISTORY_TABLE = dbo.AccountHistory));
GO

CREATE TABLE dbo.TransactionRecord
(
    TransID             bigint           IDENTITY(1,1) NOT NULL,
    InitiatedByLogin    sysname          NOT NULL,
    TransactionType     varchar(20)      NOT NULL,
    AccountID           varchar(10)      NOT NULL,
    CustomerID          varchar(6)       NOT NULL,
    RelatedAccountID    varchar(10)      NULL,
    TransDateMYT        datetime2(0)     NOT NULL CONSTRAINT DF_Transaction_TransDateMYT DEFAULT (DATEADD(HOUR, 8, SYSUTCDATETIME())),
    Amount              decimal(14,2)    NOT NULL,
    ValidFrom            DATETIME2 GENERATED ALWAYS AS ROW START NOT NULL,
    ValidTo              DATETIME2 GENERATED ALWAYS AS ROW END NOT NULL,
    CONSTRAINT PK_TransactionRecord PRIMARY KEY (TransID),
    CONSTRAINT FK_Transaction_AccountCustomer FOREIGN KEY (AccountID, CustomerID)
        REFERENCES dbo.Account(AccountID, CustomerID),
    CONSTRAINT FK_Transaction_RelatedAccount FOREIGN KEY (RelatedAccountID)
        REFERENCES dbo.Account(AccountID),
    CONSTRAINT CK_Transaction_Amount CHECK (Amount > 0),
    CONSTRAINT CK_Transaction_Type CHECK (TransactionType IN ('Deposit','Withdrawal','Transfer')),
    CONSTRAINT CK_Transaction_RelatedAccount CHECK
    (
        (TransactionType IN ('Deposit','Withdrawal') AND RelatedAccountID IS NULL) OR
        (TransactionType = 'Transfer' AND RelatedAccountID IS NOT NULL AND RelatedAccountID <> AccountID)
    ),
    PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo)
)
WITH (SYSTEM_VERSIONING = ON
    (HISTORY_TABLE = dbo.TransactionRecordHistory));
GO

ALTER TABLE dbo.Customer
ALTER COLUMN ICNumberEncrypted ADD MASKED WITH (FUNCTION = 'default()');
GO

ALTER TABLE dbo.Customer
ALTER COLUMN Phone ADD MASKED WITH (FUNCTION = 'partial(0,"XXXXXX",4)');
GO

ALTER TABLE dbo.Customer
ALTER COLUMN AddressDetail ADD MASKED WITH (FUNCTION = 'default()');
GO

ALTER TABLE dbo.Account
ALTER COLUMN Balance ADD MASKED WITH (FUNCTION = 'random(1, 500000)');
GO