USE SmartBankDB;
GO

CREATE SCHEMA reporting;
GO

/* Static, one-time copy for a non-prod/test environment.
   Sensitive columns (IC, PIN hash/salt) are excluded entirely rather
   than masked - simplest and safest for a non-prod copy */
CREATE TABLE reporting.CustomerMasking
(
    CustomerID    varchar(6)     NOT NULL,
    CustomerName  nvarchar(100)  NOT NULL,
    Phone         varchar(20)    NOT NULL,
    AddressDetail nvarchar(200)  NOT NULL,
    LoginName     sysname        NOT NULL
);
GO

INSERT INTO reporting.CustomerMasking
    (CustomerID, CustomerName, Phone, AddressDetail, LoginName)
SELECT
    CustomerID,
    LEFT(CustomerName, 1) + REPLICATE('*', LEN(CustomerName) - 1),
    'XXX-XXX-' + RIGHT(Phone, 4),
    'REDACTED',
    'anon_' + CustomerID
FROM dbo.Customer;
GO


select * from reporting.CustomerMasking
