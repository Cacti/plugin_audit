<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDTool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/**
 * Creates this plugin's audit_log table (the core event store), plus its
 * Syslog delivery and user-log deduplication state tables. Called from
 * plugin_audit_install() during plugin installation.
 *
 * @return bool Always returns true.
 *
 * @global array  $config           Cacti global configuration array;
 *                                   used to load database.php.
 * @global object $database_default Cacti's default database connection
 *                                   handle (unused directly here;
 *                                   declared for parity with other
 *                                   database-touching functions in this
 *                                   file).
 */
function audit_setup_table(): bool {
	global $config, $database_default;
	include_once($config['library_path'] . '/database.php');

	db_execute("CREATE TABLE IF NOT EXISTS `audit_log` (
		`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		`page` varchar(40) DEFAULT NULL,
		`user_id` int(10) unsigned DEFAULT NULL,
		`action` varchar(20) DEFAULT NULL,
		`request_status` varchar(20) NOT NULL DEFAULT 'unknown',
		`ip_address` varchar(40) DEFAULT NULL,
		`user_agent` varchar(256) DEFAULT NULL,
		`event_time` timestamp DEFAULT CURRENT_TIMESTAMP,
		`post` longblob,
		`object_data` longblob,
		`external_status` varchar(20) NOT NULL DEFAULT 'unknown',
		`external_error` varchar(1024) DEFAULT NULL,
		`event_uuid` char(36) DEFAULT NULL,
		`correlation_id` char(36) DEFAULT NULL,
		`event_type` varchar(100) NOT NULL DEFAULT 'cacti.request',
		`event_category` varchar(40) NOT NULL DEFAULT 'configuration',
		`severity` varchar(12) NOT NULL DEFAULT 'info',
		`actor_type` varchar(20) NOT NULL DEFAULT 'user',
		`target_type` varchar(64) DEFAULT NULL,
		`target_id` varchar(128) DEFAULT NULL,
		`operation_outcome` varchar(20) NOT NULL DEFAULT 'unknown',
		`outcome_reason` varchar(255) DEFAULT NULL,
		`http_method` varchar(10) DEFAULT NULL,
		`http_status` smallint unsigned DEFAULT NULL,
		`completed_time` datetime(6) DEFAULT NULL,
		`duration_ms` bigint unsigned DEFAULT NULL,
		`details` longblob,
		`previous_hash` char(64) DEFAULT NULL,
		`integrity_hash` char(64) DEFAULT NULL,
		`external_attempts` int unsigned NOT NULL DEFAULT 0,
		`external_last_attempt` datetime(6) DEFAULT NULL,
		`external_delivered_time` datetime(6) DEFAULT NULL,
		PRIMARY KEY (`id`),
		KEY `user_id` (`user_id`),
		KEY `page` (`page`),
		KEY `ip_address` (`ip_address`),
		KEY `event_time` (`event_time`),
		KEY `action` (`action`),
		UNIQUE KEY `event_uuid` (`event_uuid`),
		KEY `correlation_id` (`correlation_id`),
		KEY `event_type` (`event_type`),
		KEY `operation_outcome` (`operation_outcome`),
		KEY `external_status` (`external_status`))
		ENGINE=InnoDB
		COMMENT='Audit Log for all GUI activities'");

	audit_setup_syslog_table();
	audit_setup_user_log_state_table();

	return true;
}

/**
 * Creates the durable, database-backed deduplication table used to track
 * which user_log rows have already been ingested as audit events
 * (dropping a legacy foreign key constraint if still present, since
 * audit_id is deliberately not a real foreign key so state survives
 * audit-log purges). Called from audit_setup_table() during
 * installation, from audit_check_upgrade() during upgrades, and from
 * audit_replicate_out() to replicate the table to a remote poller.
 *
 * Durable, database-backed deduplication table for user_log ingestion.
 *
 * The source tuple is stored in typed columns, so identity has one
 * canonical representation and remains stable across session-timezone
 * changes. audit_id is deliberately not a foreign key so state survives
 * audit-log purges. The tuple mirrors user_log's own (username, user_id,
 * time) primary key; Cacti cannot store two source rows with the same
 * tuple.
 *
 * @param mixed $cnn_id The remote connection id to apply the DDL against,
 *                      or false for the local database; defaults to
 *                      false.
 *
 * @return void
 */
function audit_setup_user_log_state_table(mixed $cnn_id = false): void {
	// DDL has no values to bind; Cacti's schema helpers use db_execute() for
	// CREATE/ALTER statements and prepared calls for data queries.
	db_execute("CREATE TABLE IF NOT EXISTS `audit_user_log_state` (
			`source_username` varchar(50) NOT NULL DEFAULT '0',
			`source_user_id` mediumint(8) NOT NULL DEFAULT '0',
			`source_epoch` bigint(20) unsigned NOT NULL,
			`source_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
			`audit_id` bigint(20) unsigned NOT NULL,
			`retry_count` int(10) unsigned NOT NULL DEFAULT '0',
			`processed_time` datetime(6) NOT NULL,
			PRIMARY KEY (`source_username`, `source_user_id`, `source_epoch`),
			KEY `pending_retry` (`audit_id`, `retry_count`, `processed_time`),
			KEY `source_time` (`source_time`))
		ENGINE=InnoDB
		COMMENT='Durable deduplication state for user_log ingestion'",
		true,
		$cnn_id
	);

	$has_foreign_key = (int) db_fetch_cell_prepared(
		'SELECT COUNT(*)
			FROM information_schema.TABLE_CONSTRAINTS
			WHERE CONSTRAINT_SCHEMA = DATABASE()
			AND TABLE_NAME = ?
			AND CONSTRAINT_NAME = ?
			AND CONSTRAINT_TYPE = ?',
		['audit_user_log_state', 'fk_audit_user_log_state_event', 'FOREIGN KEY'],
		'',
		true,
		$cnn_id
	);

	if ($has_foreign_key > 0) {
		db_execute(
			'ALTER TABLE audit_user_log_state
				DROP FOREIGN KEY fk_audit_user_log_state_event',
			true,
			$cnn_id
		);
	}
}

/**
 * Adds the two indexes this plugin's per-cycle authentication queries
 * need on Cacti core's user_log table (creating only the ones missing,
 * and journaling ownership in the 'audit_user_log_indexes_owned' setting
 * before each ALTER so a timeout can't orphan a plugin-created index).
 * Only operates on the local database (never on a remote connection).
 * Called from the audit_auth_indexes.php CLI maintenance script when an
 * administrator explicitly opts in to authentication auditing.
 *
 * Add the access paths required by the per-cycle authentication queries.
 *
 * @param mixed $cnn_id Must be false (local database); any other value
 *                      causes this function to no-op and return false.
 *
 * @return bool True once both required indexes exist on user_log.
 */
function audit_setup_user_log_indexes(mixed $cnn_id = false): bool {
	if ($cnn_id !== false) {
		return false;
	}

	if (!db_table_exists('user_log', false, $cnn_id)) {
		return false;
	}

	$allowed = ['plugin_audit_time', 'plugin_audit_result_time'];
	$owned   = array_intersect(
		array_filter(explode(',', (string) read_config_option('audit_user_log_indexes_owned', true))),
		$allowed
	);

	$definitions = [
		'plugin_audit_time'        => ['time', 'username', 'user_id'],
		'plugin_audit_result_time' => ['result', 'time']
	];

	foreach ($definitions as $index => $columns) {
		if (!db_index_exists('user_log', $index, false, $cnn_id)) {
			// Journal intent before DDL so a timeout after ALTER cannot orphan a
			// plugin-created index on the core table.
			$owned[] = $index;
			$owned   = array_values(array_unique($owned));
			set_config_option('audit_user_log_indexes_owned', implode(',', $owned));
			db_add_index('user_log', 'INDEX', $index, $columns, true, $cnn_id);
		}
	}

	$owned = array_values(array_filter(
		array_unique($owned),
		static fn (string $index): bool => db_index_exists('user_log', $index, false, $cnn_id)
	));
	set_config_option('audit_user_log_indexes_owned', implode(',', $owned));

	return audit_user_log_indexes_available($cnn_id);
}

/**
 * Determines whether both of this plugin's required user_log indexes
 * (plugin_audit_time, plugin_audit_result_time) currently exist on the
 * local database. Called from audit_setup_user_log_indexes() after
 * creating them, and from audit_enforce_syslog_settings_request() before
 * allowing authentication auditing to be enabled.
 *
 * @param mixed $cnn_id Must be false (local database); any other value
 *                      causes this function to report unavailable.
 *
 * @return bool True when user_log exists and both required indexes are
 *              present.
 */
function audit_user_log_indexes_available(mixed $cnn_id = false): bool {
	return $cnn_id === false &&
		db_table_exists('user_log', false, $cnn_id) &&
		db_index_exists('user_log', 'plugin_audit_time', false, $cnn_id) &&
		db_index_exists('user_log', 'plugin_audit_result_time', false, $cnn_id);
}

/**
 * Determines whether user_log's primary key is still the expected
 * (username, user_id, time) tuple that this plugin's deduplication logic
 * relies on, so a future Cacti schema change can be detected rather than
 * silently mis-deduplicating events. Called from
 * audit_enforce_syslog_settings_request() before allowing authentication
 * auditing to be enabled.
 *
 * @param mixed $cnn_id The remote connection id to check against, or
 *                      false for the local database; defaults to false.
 *
 * @return bool True when user_log's primary key matches the expected
 *              column order.
 */
function audit_user_log_identity_supported(mixed $cnn_id = false): bool {
	$columns = db_fetch_assoc_prepared(
		'SELECT COLUMN_NAME
			FROM information_schema.STATISTICS
			WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = ?
			AND INDEX_NAME = ?
			ORDER BY SEQ_IN_INDEX',
		['user_log', 'PRIMARY'],
		true,
		$cnn_id
	);

	if ($columns === false) {
		return false;
	}

	return array_column($columns, 'COLUMN_NAME') === ['username', 'user_id', 'time'];
}

/**
 * Removes only the user_log indexes this plugin created (per the
 * 'audit_user_log_indexes_owned' setting), leaving any indexes not owned
 * by this plugin untouched, and updates the ownership setting to reflect
 * any that could not be dropped. Only operates on the local database.
 * Called from plugin_audit_uninstall() during uninstallation.
 *
 * @param mixed $cnn_id Must be false (local database); any other value
 *                      causes this function to no-op and return false.
 *
 * @return bool True when every owned index was removed (or none were
 *              owned, or the user_log table doesn't exist).
 */
function audit_remove_user_log_indexes(mixed $cnn_id = false): bool {
	if ($cnn_id !== false) {
		return false;
	}

	if (!db_table_exists('user_log', false, $cnn_id)) {
		set_config_option('audit_user_log_indexes_owned', '');

		return true;
	}

	$allowed = ['plugin_audit_time', 'plugin_audit_result_time'];
	$owned   = array_intersect(
		array_filter(explode(',', (string) read_config_option('audit_user_log_indexes_owned', true))),
		$allowed
	);

	$failed = [];

	foreach ($owned as $index) {
		if (db_index_exists('user_log', $index, false, $cnn_id)) {
			// DDL identifiers cannot be bound; the name is restricted to the
			// static plugin-owned allowlist above before raw execution.
			if (!db_execute('ALTER TABLE `user_log` DROP INDEX `' . $index . '`', true, $cnn_id)) {
				$failed[] = $index;
			}
		}
	}

	set_config_option('audit_user_log_indexes_owned', implode(',', $failed));

	if ($failed !== []) {
		cacti_log(
			'ERROR: Audit plugin could not remove owned user_log indexes: ' . implode(', ', $failed),
			false,
			'POLLER'
		);
	}

	return $failed === [];
}

/**
 * Creates this plugin's audit_syslog_delivery table (the Syslog delivery
 * queue/tracking table), and adds the node_id/poller_id columns when
 * upgrading from an older schema that lacked them. Called from
 * audit_setup_table() during installation and audit_check_upgrade()
 * during upgrades.
 *
 * @return void
 */
function audit_setup_syslog_table(): void {
	db_execute("CREATE TABLE IF NOT EXISTS `audit_syslog_delivery` (
		`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		`audit_id` bigint(20) unsigned NOT NULL,
		`event_uuid` char(36) NOT NULL,
		`destination_fingerprint` char(64) NOT NULL,
		`node_id` varchar(255) NOT NULL,
		`poller_id` varchar(64) DEFAULT NULL,
		`state` varchar(20) NOT NULL DEFAULT 'pending',
		`attempts` int unsigned NOT NULL DEFAULT 0,
		`next_attempt` datetime(6) NOT NULL,
		`last_attempt` datetime(6) DEFAULT NULL,
		`sent_time` datetime(6) DEFAULT NULL,
		`last_error` varchar(1024) DEFAULT NULL,
		`created_time` datetime(6) NOT NULL,
		`updated_time` datetime(6) NOT NULL,
		PRIMARY KEY (`id`),
		UNIQUE KEY `audit_destination` (`audit_id`, `destination_fingerprint`),
		KEY `event_uuid` (`event_uuid`),
		KEY `state_next_attempt` (`state`, `next_attempt`),
		KEY `destination_state` (`destination_fingerprint`, `state`),
		CONSTRAINT `fk_audit_syslog_event`
			FOREIGN KEY (`audit_id`) REFERENCES `audit_log` (`id`)
			ON DELETE CASCADE)
		ENGINE=InnoDB
		COMMENT='Remote Syslog delivery queue for audit events'");

	db_execute("ALTER TABLE audit_syslog_delivery
		ADD COLUMN IF NOT EXISTS node_id varchar(255) NOT NULL DEFAULT 'cacti'
		AFTER destination_fingerprint");
	db_execute('ALTER TABLE audit_syslog_delivery
		ADD COLUMN IF NOT EXISTS poller_id varchar(64) DEFAULT NULL
		AFTER node_id');
}

/**
 * Adds every column and index that audit_log has accumulated since its
 * original schema (uuid/correlation id, event classification fields,
 * outcome/target fields, timing fields, integrity hash, external-
 * delivery counters), each guarded by an existence check so it is safe
 * to run repeatedly. Called from audit_check_upgrade() during local
 * upgrades and from audit_replicate_out() when replicating the schema to
 * a remote poller.
 *
 * @param mixed $rcnn_id The remote connection id to apply the DDL
 *                       against, or false for the local database;
 *                       defaults to false.
 *
 * @return void
 */
function audit_upgrade_event_schema(mixed $rcnn_id = false): void {
	$remote  = $rcnn_id !== false;
	$args    = $remote ? [true, $rcnn_id] : [];
	$columns = [
		'event_uuid char(36) DEFAULT NULL',
		'correlation_id char(36) DEFAULT NULL',
		"event_type varchar(100) NOT NULL DEFAULT 'cacti.request'",
		"event_category varchar(40) NOT NULL DEFAULT 'configuration'",
		"severity varchar(12) NOT NULL DEFAULT 'info'",
		"actor_type varchar(20) NOT NULL DEFAULT 'user'",
		'target_type varchar(64) DEFAULT NULL',
		'target_id varchar(128) DEFAULT NULL',
		"operation_outcome varchar(20) NOT NULL DEFAULT 'unknown'",
		'outcome_reason varchar(255) DEFAULT NULL',
		'http_method varchar(10) DEFAULT NULL',
		'http_status smallint unsigned DEFAULT NULL',
		'completed_time datetime(6) DEFAULT NULL',
		'duration_ms bigint unsigned DEFAULT NULL',
		'details longblob',
		'previous_hash char(64) DEFAULT NULL',
		'integrity_hash char(64) DEFAULT NULL',
		'external_attempts int unsigned NOT NULL DEFAULT 0',
		'external_last_attempt datetime(6) DEFAULT NULL',
		'external_delivered_time datetime(6) DEFAULT NULL'
	];

	foreach ($columns as $definition) {
		call_user_func_array('db_execute', array_merge(
			['ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS ' . $definition],
			$args
		));
	}

	$indexes = [
		'event_uuid'        => ['UNIQUE INDEX', ['event_uuid']],
		'correlation_id'    => ['INDEX', ['correlation_id']],
		'event_type'        => ['INDEX', ['event_type']],
		'operation_outcome' => ['INDEX', ['operation_outcome']],
		'external_status'   => ['INDEX', ['external_status']]
	];

	foreach ($indexes as $name => $definition) {
		if (!db_index_exists('audit_log', $name, false, $remote ? $rcnn_id : false)) {
			db_add_index('audit_log', $definition[0], $name, $definition[1], true, $remote ? $rcnn_id : false);
		}
	}
}
