-- Run this once after data setup or use in migrations.

CREATE INDEX `idx_documents_org_lastmodified`
ON `Documents` (`OrganizationID`, `LastModifiedAt`);

CREATE INDEX `idx_documents_owner_lastmodified`
ON `Documents` (`OwnerUserID`, `LastModifiedAt`);

CREATE INDEX `idx_permissions_user_doc_access`
ON `Permissions` (`UserID`, `DocID`, `AccessType`);

CREATE INDEX `idx_permissions_doc_access`
ON `Permissions` (`DocID`, `AccessType`);

CREATE INDEX `idx_logs_doc_action_time`
ON `Logs` (`DocID`, `ActionType`, `ActionTimestamp`);

CREATE INDEX `idx_logs_user_time`
ON `Logs` (`UserID`, `ActionTimestamp`);

CREATE INDEX `idx_users_org_role_status`
ON `Users` (`OrganizationID`, `RoleID`, `AccountStatus`);
