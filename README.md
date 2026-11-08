# SmartBank Database Security (DBS)

A SQL Server security project based on **SmartBankDB** Assignment. Containing database-security controls on one schema: transparent data encryption (TDE), column-level encryption, row-level security (RLS), dynamic data masking, role-based access control (RBAC), certificate-signed procedures, auditing, temporal rollback, and encrypted backups with automated jobs.

> **Author(s):** `Chong Kelvin, Ansel Yew Ik Min`

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Repository Structure](#repository-structure)
4. [Setup (Execution Order)](#setup-execution-order)
5. [Database Design](#database-design)
6. [Security Controls](#security-controls)
7. [Roles and Permissions](#roles-and-permissions)
8. [Stored Procedures](#stored-procedures)
9. [Auditing](#auditing)
10. [Backup and Recovery](#backup-and-recovery)
11. [Static Data Masking](#static-data-masking)
12. [Resetting the Environment](#resetting-the-environment)
13. [Error Code Reference](#error-code-reference)
14. [Security Notes and Known Limitations](#security-notes-and-known-limitations)

---

## Features

| Area | Implementation |
|---|---|
| Encryption at rest | TDE (AES-256) with `SmartBank_TDE_Cert` |
| Column-level encryption | Customer IC numbers encrypted with `SK_SmartBank_CustomerPII` (AES-256 symmetric key protected by `Cert_SmartBank_CLE`) |
| Row-level security | Filter predicates on `Customer`, `Account`, `TransactionRecord`, `Staff` |
| Dynamic data masking | Masks on phone, address, IC and balance, with selective `UNMASK` grants |
| RBAC | Six database roles with a role hierarchy, view-based access, and column-level `UPDATE` grants |
| Privilege elevation without over-granting | Certificate-signed procedures and `EXECUTE AS OWNER` helpers |
| PIN protection | Salted SHA-256 hashed transaction PINs, with lockout after 5 failed attempts |
| Auditing | SQL Server Audit (file and Windows Application Log), a DDL trigger, a DML trigger demo, and a business-failure log |
| Temporal history | System-versioned tables on all core entities, used for point-in-time rollback |
| Backup | Encrypted, verified full, differential and log backups, automated with SQL Server Agent jobs |
| Static masking | An anonymised copy of customer data for non-production use |

## Requirements

- SQL Server with support for temporal tables, RLS, dynamic data masking, TDE and encrypted backups. The audit script reads the Event Viewer provider `MSSQL$DBS`, so it assumes a **named instance called `DBS`**.
- SQL Server Agent running (for the backup jobs).
- A **sysadmin** login to run the setup scripts.
- Windows host paths. The scripts create and write to:
  - `C:\SmartBank\TDECert\`: exported TDE certificate and private key
  - `C:\SmartBank\Certs\`: exported login-provisioning certificate and private key
  - `C:\SmartBank\Audit\`: SQL Server Audit files
  - `C:\SmartBank\Backup\`: backup files
- SSMS or Azure Data Studio to run the scripts.

## Repository Structure

```
DatabaseSecurity-DBS/
├── 01EncryptionSetup.sql         # Master key, TDE cert (exported), SmartBankDB, TDE, column-level encryption key
├── 02TableCreation.sql           # Temporal tables, constraints, dynamic data masking
├── 03Rowlevelsecurity.sql        # RLS predicate functions, security policies, RLS-bypassing helper modules
├── 04PermissionRole.sql          # Roles, signing cert, views, grants/denies, CustomerTransaction, UnlockCustomerPIN, MyPermission
├── 04BRollback.sql               # RollbackLog and temporal point-in-time restore procedures
├── 05Audit.sql                   # Server/database audits, failure log, DDL audit trigger, DML trigger demo
├── 06LoginEncryption.sql         # Login-provisioning certificate, certificate-mapped login/user
├── 07LoginSetup.sql              # AddCustomer and AddStaff onboarding procedures
├── 08Backup.sql                  # Encrypted backups, Agent jobs, retention cleanup, tail-log procedure
├── StaticMaskingShowcase.sql     # Static (one-time) masked copy of customer data
└── reset.sql                     # Full teardown script
```

## Setup (Execution Order)

Run the scripts **in this order**, as a sysadmin:

| Step | Script | Purpose |
|---|---|---|
| 1 | `01EncryptionSetup.sql` | Encryption foundation and the database |
| 2 | `02TableCreation.sql` | Schema |
| 3 | `03Rowlevelsecurity.sql` | RLS policies and helpers |
| 4 | `04PermissionRole.sql` | Roles, views, permissions, transaction logic |
| 5 | `04BRollback.sql` | Rollback procedures |
| 6 | `05Audit.sql` | Auditing and the failure log |
| 7 | `06LoginEncryption.sql` | Login provisioning certificate |
| 8 | `07LoginSetup.sql` | Onboarding procedures |
| 9 | `08Backup.sql` | Backups and jobs |
| Optional | `StaticMaskingShowcase.sql` | Masked reporting copy |

Notes:

- `dbo.LogBusinessFailure` is created in `05Audit.sql` but is called by procedures created earlier. Run `05Audit.sql` before exercising those procedures.
- The scripts contain **no seed data**. The first DBA, officers and customers must be created through `AddStaff` / `AddCustomer` (or inserted manually as sysadmin).
- Before backing up, copy the exported `.cer` / `.pvk` files off the server. See [Backup and Recovery](#backup-and-recovery).

## Database Design

### Tables

| Table | Key | Purpose |
|---|---|---|
| `Staff` | `StaffID` (`D`/`M`/`O` + 5 digits) | DBAs, Bank Managers and Bank Officers. The ID prefix must match `Position`. Salary is limited to 1.00–100,000.00. |
| `Customer` | `CustomerID` (`C` + 5 digits) | Customer profile, encrypted IC number, salted PIN hash, failed-attempt counter and lock timestamp |
| `Account` | `AccountID` (`A` + 9 digits) | Savings or Current account. Status is Active, Frozen or Closed. Balance cannot go below 0. |
| `TransactionRecord` | `TransID` (identity) | Deposit, Withdrawal or Transfer. Amount must be positive, and transfers require a different related account. |
| `BusinessFailureLog` | `LogID` | Failures captured from stored procedures |
| `AuditLog_DDL` | `LogID` | DDL changes captured by a database trigger |
| `RollbackLog` | `LogID` | Every value restored by the rollback procedures |
| `TriggerDMLDemo` / `AuditLog_TriggerDMLDemo` | | Standalone table and old/new-value audit trail for demonstrating a DML trigger |
| `reporting.CustomerMasking` | | Static anonymised customer data |

`Staff`, `Customer`, `Account` and `TransactionRecord` are **system-versioned temporal tables** with history tables `StaffHistory`, `CustomerHistory`, `AccountHistory` and `TransactionRecordHistory`.

Timestamps stored in the application tables are Malaysia Time (MYT), computed as `SYSUTCDATETIME() + 8 hours`. Malaysia has no daylight saving.

## Security Controls

### 1. Transparent Data Encryption
`SmartBank_TDE_Cert` protects a database encryption key (AES-256) on `SmartBankDB`. The certificate and its private key are exported to `C:\SmartBank\TDECert\`, a separate folder from the backups, so that losing one disk cannot destroy both the backups and the only key able to decrypt them.

### 2. Column-level encryption
`Customer.ICNumberEncrypted` is encrypted with `SK_SmartBank_CustomerPII`, using the `CustomerID` as an authenticator. Procedures that need the key (`AddCustomer`, `CustomerViewOwnProfile`) are **signed** with `Cert_PIIModuleSigning`, so callers get access to the key only inside those procedures and never directly.

### 3. Row-level security
| Policy | Rows a user can see |
|---|---|
| `CustomerRLSPolicy` | Own customer row; all rows for `StaffOp` |
| `AccountRLSPolicy` | Accounts owned by the caller; all for `StaffOp` |
| `TransactionRLSPolicy` | Transactions the caller initiated **or received as a transfer recipient**; all for `StaffOp` |
| `StaffRLSPolicy` | Own staff row, plus all Bank Manager / Bank Officer rows (DBA rows stay hidden from others) |

Each predicate also allows `USER_NAME() = 'dbo'`. Internal helpers running `WITH EXECUTE AS OWNER` use this for legitimate cross-row work:

- `fn_sys_AccountExists` and `sys_CreditDestinationAccount` support transfers to other customers' accounts.
- `sys_GetNextStaffID` generates sequential staff IDs without exposing the Staff table in general.

### 4. Dynamic data masking
| Column | Mask |
|---|---|
| `Customer.ICNumberEncrypted` | `default()` |
| `Customer.Phone` | `partial(0,"XXXXXX",4)` |
| `Customer.AddressDetail` | `default()` |
| `Account.Balance` | `random(1, 500000)` |

`UNMASK` is granted per column to `BankOfficer` (Phone, AddressDetail, Balance) and `Customer` (Phone, AddressDetail, IC, Balance).

### 5. PIN protection
Transaction PINs (4 or 6 digits) are stored as `SHA2_256(salt + PIN)` with a 16-byte random salt from `CRYPT_GEN_RANDOM`. Five consecutive wrong PINs lock the customer. A table constraint keeps `FailedPINAttempts` and `PINLockedUntilMYT` consistent. A Bank Officer unlocks the account with `UnlockCustomerPIN`. A successful PIN resets the counter.

### 6. Certificate-signed privilege elevation
| Certificate | Purpose |
|---|---|
| `Cert_PIIModuleSigning` | Lets signed modules use the PII encryption key |
| `Cert_LoginProvisioning` | Lets signed modules create logins, users and role memberships, without giving `BankOfficer` or `DBA` the rights `ALTER ANY LOGIN` or `ALTER ANY USER` |

## Roles and Permissions

### Role hierarchy
```
Staff
├── DBA
└── StaffOp
    ├── BankManager
    └── BankOfficer
Customer   (separate)
```

### Permission summary

| Role | Can do | Cannot do |
|---|---|---|
| **public** | Read `PublicView` (name, phone, position of managers and officers) and run `MyPermission` | |
| **Customer** | View own profile (`CustomerViewOwnProfile`), own accounts and transactions; run `CustomerTransaction` | Direct table access, view others' data |
| **BankOfficer** | View customer, account and transaction records; update customer name/phone/address and account type/status; onboard customers (`AddCustomer`); unlock PINs; restore customer details | Change balances directly, view encrypted IC |
| **BankManager** | View Bank Officer records; update officers' name, branch, phone and salary; restore officer records | Control `Customer` or `Account` tables |
| **DBA** | Create and alter schema objects; onboard staff (`AddStaff`); read audit and rollback logs | Read or modify `Customer` and `Account` data |
| **Staff** (DBA + managers + officers) | View own record; update own name and phone (not salary); restore own record | |

### Views
`PublicView`, `StaffViewOwnRecord`, `ManagerViewBankOfficer`, `ViewCustomerRecord`, `ViewCustomerAccount`, `ViewTransaction`, `CustomerViewOwnAccount`, `CustomerViewTransaction`. The DBA is explicitly denied `ALTER` on each view.

## Stored Procedures

| Procedure | Run by | Description |
|---|---|---|
| `CustomerTransaction` | Customer | Deposit, withdrawal or transfer. Verifies account ownership and PIN, validates the amount (positive, max 2 decimals, at most 99,999,999.99), and moves money atomically. |
| `CustomerViewOwnProfile` | Customer | Returns the caller's profile with the IC number decrypted |
| `UnlockCustomerPIN` | BankOfficer | Resets failed attempts and the lock |
| `AddCustomer` | BankOfficer | Creates the customer, first account, SQL login, database user and `Customer` role membership in one transaction |
| `AddStaff` | DBA | Creates the staff record, login, user and role from the chosen position |
| `RestoreOwnStaffRecord` | Staff | Reverts own name/phone to a past UTC time |
| `RestoreStaffRecord` | BankManager | Reverts a Bank Officer's name, branch, phone and salary |
| `RestoreCustomerRecord` | BankOfficer | Reverts a customer's name, phone and address |
| `MyPermission` | public | Lists the caller's roles and effective permissions |
| `LogBusinessFailure` | internal | Writes failures to `BusinessFailureLog` |
| `Backup_SmartBank_TailLog` | sysadmin | Tail-log backup, which leaves the database in the RESTORING state |

The restore procedures read the temporal history with `FOR SYSTEM_TIME AS OF @AsOf` (UTC) and write each restored column to `RollbackLog`.

## Auditing

- **`SmartBank_Audit`** (file, `C:\SmartBank\Audit\`, 100 MB × 10 rollover files) with `SmartBank_DatabaseAuditSpec`: schema object access, change and permission change, database principal changes, role membership changes and database permission changes.
- **`SmartBank_LoginAudit`** (Windows Application Log) with `SmartBank_LoginAuditSpec`: successful and failed logins, logouts, and server principal, role and permission changes. View it in Event Viewer.
- **`trg_SmartBankDB_DDLAudit`**: database DDL trigger that logs table, view and procedure create/alter/drop to `AuditLog_DDL`.
- **`BusinessFailureLog`**: business-rule failures with the original login, procedure name, key and error.
- **`trg_TriggerDMLDemo_Audit`**: logs INSERT, UPDATE and DELETE with old and new values on `TriggerDMLDemo`.

Audit file times are UTC. Convert to MYT with `DATEADD(HOUR, 8, event_time)`. A ready-made query for `sys.fn_get_audit_file` and a PowerShell `Get-WinEvent` command (event IDs 18453, 18454 and 18456) are included in comments at the bottom of `05Audit.sql`.

## Backup and Recovery

`08Backup.sql` sets the database to the FULL recovery model and takes encrypted (AES-256, `SmartBank_TDE_Cert`), compressed, checksummed backups, each followed by `RESTORE VERIFYONLY`.

| Agent job | Schedule | Retention |
|---|---|---|
| `SmartBank_FullBackup` | Daily at 01:00 | 7 days |
| `SmartBank_DiffBackup` | Every 6 hours | 7 days |
| `SmartBank_LogBackup` | Every 15 minutes | 2 days |
| `SmartBank_BackupCleanup` | Daily at 02:30 | Deletes expired `.bak` and `.trn` files |

**Restoring on another server requires the exported TDE certificate and private key** from `C:\SmartBank\TDECert\`. Store a copy somewhere separate from the backups.

## Static Data Masking

`StaticMaskingShowcase.sql` creates `reporting.CustomerMasking`, a one-time anonymised copy of `dbo.Customer` for test environments:

- IC number and PIN data are excluded entirely.
- Names keep the first letter, and the rest becomes `*`.
- Phones become `XXX-XXX-` plus the last four digits.
- Addresses become `REDACTED`.
- Login names become `anon_<CustomerID>`.

## Resetting the Environment

`reset.sql` tears down the project: it disables the logon trigger, captures dynamically created logins, drops the audit objects, turns TDE off, drops `SmartBankDB`, deletes the four Agent jobs, drops `Login_LoginProvisioning` and `Cert_LoginProvisioning`, and finally drops every captured customer/staff login. Run it top to bottom in a single session, because it uses a `#temp` table across batches. Every step is guarded with `IF EXISTS`, so it is safe to re-run.

Cleanup of the `C:\SmartBank\` folders is manual.

## Error Code Reference

| Range | Source |
|---|---|
| 50001–50012 | `CustomerTransaction` (ownership, type, amount, transfer, balance and PIN errors; 50011 and 50012 cover PIN lock and incorrect PIN) |
| 51000–51003 | `AddCustomer` validation (login, IC, PIN, duplicate user) and `CustomerTransaction` amount limits (51002, 51003) |
| 52000–52002 | `AddStaff` validation |
| 53000–53032 | Restore procedures |
| 60001 | `UnlockCustomerPIN` (customer not found) |
| 60101–60103 | Backup job verification steps |

## Security Notes and Known Limitations

- **Hard-coded secrets:** the master key, TDE certificate export and login-provisioning certificate export passwords are written in plain text in the scripts. Replace them and keep them out of version control.
- **Default login passwords:** `AddCustomer` and `AddStaff` create logins with the password `<LoginName>@123` and `CHECK_POLICY = OFF`. There is no forced password change.
- **PIN hashing:** PINs use a single salted SHA-256 pass. With only 4–6 digits the keyspace is small, so a stronger key-derivation function would be needed for production.
- **`reset.sql` is partly out of sync with the setup scripts.** It refers to objects the scripts never create (`trg_AuditLogin`, `SmartBank_ServerAuditSpec`, `Cert_AuditLogging`). It does not drop `SmartBank_LoginAudit` or `SmartBank_LoginAuditSpec`, and it does not remove `SmartBank_TDE_Cert` or the master-database keys.
- **Fixed file paths:** all paths are hard-coded to `C:\SmartBank\...`.
- **Fixed time zone:** MYT is a fixed +8 hour offset from UTC, so the scripts are not portable to zones with daylight saving.
- **Single-account assumption:** `AddCustomer` creates one account per customer. Additional accounts must be added separately.
- **Demo-only objects:** `TriggerDMLDemo` and `AuditLog_TriggerDMLDemo` exist only to demonstrate the DML trigger and are not part of the banking workflow.
