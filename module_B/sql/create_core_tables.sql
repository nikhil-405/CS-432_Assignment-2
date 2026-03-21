CREATE TABLE IF NOT EXISTS `CoreUsers` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(80) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` VARCHAR(20) NOT NULL DEFAULT 'Regular',
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_coreusers_username` (`username`)
);

CREATE TABLE IF NOT EXISTS `CoreSessions` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `core_user_id` INT NOT NULL,
    `session_token` VARCHAR(700) NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_coresessions_token` (`session_token`),
    KEY `idx_coresessions_user` (`core_user_id`),
    KEY `idx_coresessions_expiry` (`expires_at`),
    CONSTRAINT `fk_coresessions_user` FOREIGN KEY (`core_user_id`) REFERENCES `CoreUsers` (`id`)
);

CREATE TABLE IF NOT EXISTS `CoreMemberLinks` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `core_user_id` INT NOT NULL,
    `project_user_id` INT NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_corememberlinks_core_user` (`core_user_id`),
    UNIQUE KEY `uq_corememberlinks_project_user` (`project_user_id`),
    CONSTRAINT `fk_corememberlinks_user` FOREIGN KEY (`core_user_id`) REFERENCES `CoreUsers` (`id`)
);

CREATE TABLE IF NOT EXISTS `CoreGroupMemberships` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `core_user_id` INT NOT NULL,
    `group_name` VARCHAR(80) NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_core_user_group` (`core_user_id`, `group_name`),
    CONSTRAINT `fk_coregroup_user` FOREIGN KEY (`core_user_id`) REFERENCES `CoreUsers` (`id`)
);

CREATE TABLE IF NOT EXISTS `CoreAuditLogs` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `actor_core_user_id` INT NULL,
    `session_token` VARCHAR(700) NULL,
    `action` VARCHAR(80) NOT NULL,
    `entity` VARCHAR(80) NOT NULL,
    `entity_id` VARCHAR(80) NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'SUCCESS',
    `details_json` TEXT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_coreauditlogs_actor` (`actor_core_user_id`),
    KEY `idx_coreauditlogs_action` (`action`),
    KEY `idx_coreauditlogs_entity` (`entity`),
    KEY `idx_coreauditlogs_created` (`created_at`),
    CONSTRAINT `fk_coreauditlogs_user` FOREIGN KEY (`actor_core_user_id`) REFERENCES `CoreUsers` (`id`)
);

CREATE TABLE IF NOT EXISTS `CoreAuditState` (
    `state_key` VARCHAR(100) NOT NULL,
    `state_value` TEXT NOT NULL,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`state_key`)
);
