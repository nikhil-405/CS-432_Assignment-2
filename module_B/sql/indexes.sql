-- Run this once after data setup or use in migrations.
-- SubTask 4: Database Indexing for Query Optimization

-- Documents table indexes (optimize list operations)
CREATE INDEX `idx_documents_org_lastmodified`
ON `Documents` (`OrganizationID`, `LastModifiedAt`);

CREATE INDEX `idx_documents_owner_lastmodified`
ON `Documents` (`OwnerUserID`, `LastModifiedAt`);

-- Permissions table indexes (critical for access control - called on every request)
-- Note: AccessType is TEXT, so we specify a prefix length of 10 characters (covers 'View', 'Edit', 'Delete')
CREATE INDEX `idx_permissions_user_doc_access`
ON `Permissions` (`UserID`, `DocID`, `AccessType`(10));

CREATE INDEX `idx_permissions_doc_access`
ON `Permissions` (`DocID`, `AccessType`(10));

-- Logs table indexes (optimize audit queries)
-- Note: ActionType is TEXT, so we specify a 10-character prefix length (covers 'CREATE', 'UPDATE', 'DELETE', etc.)
CREATE INDEX `idx_logs_doc_action_time`
ON `Logs` (`DocID`, `ActionType`(10), `ActionTimestamp`);

CREATE INDEX `idx_logs_user_time`
ON `Logs` (`UserID`, `ActionTimestamp`);

-- Users table indexes (optimize user lookups)
-- Note: AccountStatus is TEXT, so we specify a 10-character prefix length (covers 'Active', 'Inactive')
CREATE INDEX `idx_users_org_role_status`
ON `Users` (`OrganizationID`, `RoleID`, `AccountStatus`(10));
