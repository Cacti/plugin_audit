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

include_once('audit_functions.php');

function plugin_audit_install(): void {
	api_plugin_register_hook('audit', 'config_arrays',        'audit_config_arrays',        'setup.php');
	api_plugin_register_hook('audit', 'config_settings',      'audit_config_settings',      'setup.php');
	api_plugin_register_hook('audit', 'config_insert',        'audit_config_insert',        'setup.php');
	api_plugin_register_hook('audit', 'poller_bottom',        'audit_poller_bottom',        'setup.php');
	api_plugin_register_hook('audit', 'draw_navigation_text', 'audit_draw_navigation_text', 'setup.php');
	api_plugin_register_hook('audit', 'utilities_array',      'audit_utilities_array',      'setup.php');
	api_plugin_register_hook('audit', 'is_console_page',      'audit_is_console_page',      'setup.php');
	api_plugin_register_hook('audit', 'logout_pre_session_destroy', 'audit_logout_pre_session_destroy', 'setup.php');
	api_plugin_register_hook('audit', 'logout_post_session_destroy', 'audit_logout_post_session_destroy', 'audit_functions.php');
	api_plugin_register_hook('audit', 'custom_denied',        'audit_custom_denied',        'audit_functions.php');

	// hook for table replication
	api_plugin_register_hook('audit', 'replicate_out',        'audit_replicate_out',        'setup.php');

	audit_setup_realms(true);

	audit_setup_table();
	audit_persist_auth_defaults();
}

/**
 * Persist authentication auditing defaults without overwriting existing
 * administrator choices. Called on fresh install and upgrade so that
 * existing installations begin at the current time with authentication
 * auditing disabled until an Audit Log Admin explicitly opts in.
 */
function audit_persist_auth_defaults(): void {
	$defaults = [
		'audit_auth_log_enabled'           => 'off',
		'audit_auth_log_last_state'        => 'off',
		'audit_brute_force_enabled'        => 'off',
		'audit_brute_force_window_minutes' => '5',
		'audit_brute_force_threshold'      => '10',
		'audit_brute_force_last_alert'     => '',
		'audit_user_log_batch_size'        => '1000',
		'audit_user_log_watermark_epoch'   => (string) time(),
		'audit_user_log_indexes_owned'     => '',
		'audit_user_log_activation_epoch'  => '0',
		'audit_auth_ingestion_last_alert'  => '0'
	];

	foreach ($defaults as $name => $value) {
		$exists = (int) db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM settings WHERE name = ?',
			[$name]
		);

		if ($exists === 0) {
			set_config_option($name, $value);
		}
	}
}

function audit_setup_realms(bool $grant_installing_user = false): void {
	$realms = [
		'audit.php'        => __('Audit Log User', 'audit'),
		'audit_manage.php' => __('Audit Log Admin', 'audit')
	];

	foreach ($realms as $file => $display) {
		api_plugin_register_realm('audit', $file, $display, $grant_installing_user ? 1 : 0);
	}

	if (!$grant_installing_user) {
		$admin_user = (int) read_config_option('admin_user');

		if ($admin_user > 0) {
			$realm_ids = db_fetch_assoc_prepared('SELECT id + 100 AS realm_id
				FROM plugin_realms
				WHERE plugin = ?
				AND file IN (?, ?)',
				['audit', 'audit.php', 'audit_manage.php']);

			if (is_array($realm_ids)) {
				foreach ($realm_ids as $realm) {
					db_execute_prepared('REPLACE INTO user_auth_realm
					(user_id, realm_id)
					VALUES (?, ?)',
						[$admin_user, $realm['realm_id']]);
				}
			}
		}
	}
}

function audit_remove_obsolete_realms(): void {
	$realms = db_fetch_assoc_prepared('SELECT id
		FROM plugin_realms
		WHERE plugin = ?
		AND file = ?',
		['audit', 'audit_purge.php']);

	if (is_array($realms)) {
		foreach ($realms as $realm) {
			$realm_id = $realm['id'] + 100;

			db_execute_prepared('DELETE FROM user_auth_realm
				WHERE realm_id = ?',
				[$realm_id]);

			db_execute_prepared('DELETE FROM user_auth_group_realm
				WHERE realm_id = ?',
				[$realm_id]);

			db_execute_prepared('DELETE FROM plugin_realms
				WHERE id = ?',
				[$realm['id']]);
		}
	}

	if (cacti_sizeof($realms)) {
		api_plugin_replicate_config();
	}
}

/**
 * @return list<string>
 */
function audit_owned_setting_names(): array {
	return [
		'audit_enabled',
		'audit_retention',
		'audit_log_external',
		'audit_log_external_format',
		'audit_log_external_path',
		'audit_last_check',
		'audit_auth_log_enabled',
		'audit_auth_log_last_state',
		'audit_brute_force_enabled',
		'audit_brute_force_window_minutes',
		'audit_brute_force_threshold',
		'audit_brute_force_last_alert',
		'audit_user_log_batch_size',
		'audit_user_log_watermark_epoch',
		'audit_user_log_indexes_owned',
		'audit_user_log_activation_epoch',
		'audit_auth_ingestion_last_alert',
		'audit_syslog_enabled',
		'audit_syslog_receiver',
		'audit_syslog_port',
		'audit_syslog_transport',
		'audit_syslog_format',
		'audit_syslog_facility',
		'audit_syslog_application',
		'audit_syslog_node_id',
		'audit_syslog_timeout',
		'audit_syslog_udp_max_size',
		'audit_syslog_tls_ca_file',
		'audit_syslog_tls_client_cert',
		'audit_syslog_tls_client_key',
		'audit_syslog_retry_base',
		'audit_syslog_retry_max',
		'audit_syslog_max_attempts',
		'audit_syslog_batch_size',
		'audit_syslog_pending_age_warning',
		'audit_syslog_dead_letter_warning',
		'audit_syslog_health_state'
	];
}

function plugin_audit_uninstall(): bool {
	// Static DDL contains no values to bind; data deletion below remains prepared.
	$indexes_removed = audit_remove_user_log_indexes();
	db_execute('DROP TABLE IF EXISTS audit_user_log_state');
	db_execute('DROP TABLE IF EXISTS audit_syslog_delivery');
	db_execute('DROP TABLE IF EXISTS audit_log');
	$setting_names = audit_owned_setting_names();

	if (!$indexes_removed) {
		$setting_names = array_values(array_diff($setting_names, ['audit_user_log_indexes_owned']));
	}

	db_execute_prepared(
		'DELETE FROM settings WHERE name IN (' . implode(', ', array_fill(0, count($setting_names), '?')) . ')',
		$setting_names
	);

	return $indexes_removed;
}

function audit_is_console_page(string $url): bool {
	return str_contains($url, 'audit.php');
}

function plugin_audit_check_config(): bool {
	return true;
}

function plugin_audit_upgrade(): bool {
	return true;
}

function audit_check_upgrade(): void {
	global $config, $database_default;
	include_once($config['library_path'] . '/database.php');
	include_once($config['library_path'] . '/functions.php');

	$files = ['plugins.php', 'audit.php'];

	if (isset($_SERVER['PHP_SELF']) && !in_array(basename($_SERVER['PHP_SELF']), $files, true)) {
		return;
	}

	$info    = plugin_audit_version();
	$current = $info['version'];
	$old     = db_fetch_cell_prepared('SELECT version FROM plugin_config WHERE directory = ?', ['audit']);

	if ($current != $old) {
		if (api_plugin_is_enabled('audit')) {
			// may sound ridiculous, but enables new hooks
			api_plugin_enable_hooks('audit');
		}

		db_execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS object_data LONGBLOB');

		if (db_column_exists('audit_log', 'outcome')) {
			if (!db_column_exists('audit_log', 'request_status')) {
				db_execute("ALTER TABLE audit_log CHANGE COLUMN outcome request_status varchar(20) NOT NULL DEFAULT 'unknown'");
			} else {
				db_execute("UPDATE audit_log SET request_status = outcome WHERE request_status = 'unknown'");
				db_execute('ALTER TABLE audit_log DROP COLUMN outcome');
			}
		} elseif (!db_column_exists('audit_log', 'request_status')) {
			db_execute("ALTER TABLE audit_log ADD COLUMN request_status varchar(20) NOT NULL DEFAULT 'unknown' AFTER action");
		}

		db_execute("UPDATE audit_log SET request_status = CASE request_status
			WHEN 'attempted' THEN 'started'
			WHEN 'request_completed' THEN 'completed'
			WHEN 'request_failed' THEN 'failed'
			ELSE request_status END");
		db_execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS external_status varchar(20) NOT NULL DEFAULT 'unknown' AFTER object_data");
		db_execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS external_error varchar(1024) DEFAULT NULL AFTER external_status');
		audit_upgrade_event_schema();
		audit_setup_syslog_table();
		audit_setup_user_log_state_table();
		audit_persist_auth_defaults();
		audit_setup_realms();
		audit_remove_obsolete_realms();

		db_execute_prepared('UPDATE plugin_config
			SET version = ?
			WHERE directory = ?',
			[$current, 'audit']);

		db_execute_prepared('UPDATE plugin_config SET
			version = ?,
			name = ?,
			author = ?,
			webpage = ?
			WHERE directory = ?',
			[$info['version'], $info['longname'], $info['author'], $info['homepage'], $info['name']]);

		// hook for table replication
		api_plugin_register_hook('audit', 'replicate_out', 'audit_replicate_out', 'setup.php', 1);
		api_plugin_register_hook('audit', 'is_console_page', 'audit_is_console_page', 'setup.php', 1);
		api_plugin_register_hook('audit', 'logout_pre_session_destroy', 'audit_logout_pre_session_destroy', 'setup.php', 1);
		api_plugin_register_hook('audit', 'logout_post_session_destroy', 'audit_logout_post_session_destroy', 'audit_functions.php', 1);
		api_plugin_register_hook('audit', 'custom_denied', 'audit_custom_denied', 'audit_functions.php', 1);
	}
}

/**
 * @param  array<string,mixed> $data
 * @return array<string,mixed>
 */
function audit_replicate_out(array $data): array {
	$rcnn_id          = $data['rcnn_id'];
	$class            = $data['class'];

	cacti_log('INFO: Replicating for the Audit Plugin', false, 'REPLICATE');

	if ($class == 'all') {
		if (!db_table_exists('audit_log', false, $rcnn_id)) {
			cacti_log('INFO: Audit Log table does not exist creating', false, 'REPLICATE');

			$table  = 'audit_log';
			$create = db_fetch_row("SHOW CREATE TABLE $table");

			if (isset($create["CREATE TABLE `$table`"]) || isset($create['Create Table'])) {
				if (isset($create["CREATE TABLE `$table`"])) {
					db_execute($create["CREATE TABLE `$table`"], true, $rcnn_id);
				} else {
					db_execute($create['Create Table'], true, $rcnn_id);
				}
			}
		} else {
			cacti_log('INFO: Audit Log table exists, checking schema', false, 'REPLICATE');
		}

		db_execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS object_data LONGBLOB', true, $rcnn_id);

		if (db_column_exists('audit_log', 'outcome', false, $rcnn_id)) {
			if (!db_column_exists('audit_log', 'request_status', false, $rcnn_id)) {
				db_execute("ALTER TABLE audit_log CHANGE COLUMN outcome request_status varchar(20) NOT NULL DEFAULT 'unknown'", true, $rcnn_id);
			} else {
				db_execute("UPDATE audit_log SET request_status = outcome WHERE request_status = 'unknown'", true, $rcnn_id);
				db_execute('ALTER TABLE audit_log DROP COLUMN outcome', true, $rcnn_id);
			}
		} elseif (!db_column_exists('audit_log', 'request_status', false, $rcnn_id)) {
			db_execute("ALTER TABLE audit_log ADD COLUMN request_status varchar(20) NOT NULL DEFAULT 'unknown' AFTER action", true, $rcnn_id);
		}

		db_execute("UPDATE audit_log SET request_status = CASE request_status
			WHEN 'attempted' THEN 'started'
			WHEN 'request_completed' THEN 'completed'
			WHEN 'request_failed' THEN 'failed'
			ELSE request_status END", true, $rcnn_id);
		db_execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS external_status varchar(20) NOT NULL DEFAULT 'unknown' AFTER object_data", true, $rcnn_id);
		db_execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS external_error varchar(1024) DEFAULT NULL AFTER external_status', true, $rcnn_id);
		audit_upgrade_event_schema($rcnn_id);

		// Replicate the plugin-owned deduplication state. Core user_log indexes
		// are local-only and are never left behind on remote collectors.
		audit_setup_user_log_state_table($rcnn_id);
	}

	return $data;
}

function audit_poller_bottom(): void {
	$last_check = read_config_option('audit_last_check');
	$now        = gmdate('Y-m-d');
	$is_daily   = $last_check != $now;

	// Reclaim marker rows at the same maximum rate as ingestion so sustained
	// unauthenticated login traffic cannot create an unbounded state backlog.
	audit_cleanup_user_log_state(5, null, $is_daily);
	audit_retry_external_logs();
	audit_process_syslog_queue();

	// Authentication events are captured by polling Cacti's user_log table,
	// which is authoritative across all auth methods (local, LDAP, basic,
	// domains) and stable across the 1.2.x and develop branches. Ingestion
	// runs every poller cycle with a bounded workload so login failures and
	// authorization events appear promptly; the deduplication table prevents
	// duplicate events across repeated and concurrent pollers.
	audit_poll_user_log();

	// Detect aggregate failed-login volume after importing the current batch.
	audit_detect_failed_login_volume();

	if ($is_daily) {
		$retention = read_config_option('audit_retention');

		if ($retention > 0) {
			$cutoff = audit_retention_cutoff($retention);

			db_execute_prepared("DELETE FROM audit_log
				WHERE event_time < ?
				AND NOT EXISTS (
					SELECT 1
					FROM audit_syslog_delivery
					WHERE audit_syslog_delivery.audit_id = audit_log.id
					AND audit_syslog_delivery.state IN ('pending', 'retry', 'dead_letter')
				)",
				[$cutoff->format('Y-m-d H:i:s')]);
			$rows = db_affected_rows();
			cacti_log('NOTE: Purged ' . $rows . ' Audit Log Records from Cacti', false, 'POLLER');
		}
	}

	set_config_option('audit_last_check', $now);
}

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
 * Durable, database-backed deduplication table for user_log ingestion.
 *
 * The source tuple is stored in typed columns, so identity has one canonical
 * representation and remains stable across session-timezone changes. audit_id
 * is deliberately not a foreign key so state survives audit-log purges. The
 * tuple mirrors user_log's own (username, user_id, time) primary key; Cacti
 * cannot store two source rows with the same tuple.
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
 * Add the access paths required by the per-cycle authentication queries.
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

/** @phpstan-impure */
function audit_user_log_indexes_available(mixed $cnn_id = false): bool {
	return $cnn_id === false &&
		db_table_exists('user_log', false, $cnn_id) &&
		db_index_exists('user_log', 'plugin_audit_time', false, $cnn_id) &&
		db_index_exists('user_log', 'plugin_audit_result_time', false, $cnn_id);
}

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

/**
 * @return array<string,mixed>
 */
function plugin_audit_version(): array {
	global $config;
	$info        = parse_ini_file($config['base_path'] . '/plugins/audit/INFO', true);
	$plugin_info = is_array($info) ? ($info['info'] ?? null) : null;

	return is_array($plugin_info) ? $plugin_info : [];
}

function audit_log_valid_event(): bool {
	global $action;

	$valid = false;

	if (read_config_option('audit_enabled') == 'on') {
		if (strpos($_SERVER['SCRIPT_NAME'], 'graph_view.php') !== false) {
			$valid = false;
		} elseif (strpos($_SERVER['SCRIPT_NAME'], 'user_admin.php') !== false &&
			isset_request_var('action') && get_nfilter_request_var('action') == 'checkpass') {
			$valid = false;
		} elseif (strpos($_SERVER['SCRIPT_NAME'], 'plugins.php') !== false) {
			if (isset_request_var('mode')) {
				$valid  = true;
				$action = get_nfilter_request_var('mode');
			}
		} elseif (strpos($_SERVER['SCRIPT_NAME'], 'auth_profile.php') !== false) {
			$valid = false;
		} elseif (strpos($_SERVER['SCRIPT_NAME'], 'index.php') !== false) {
			$valid = false;
		} elseif (strpos($_SERVER['SCRIPT_NAME'], 'auth_changepassword.php') !== false) {
			$valid = false;
		} elseif (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' &&
			cacti_sizeof(filter_input_array(INPUT_POST, FILTER_UNSAFE_RAW))) {
			$valid = true;
		} elseif (isset_request_var('purge_continue')) {
			$valid  = true;
			$action = 'purge';
		}
	}

	return $valid;
}

function audit_utilities_array(): void {
	global $utilities;

	if (version_compare(CACTI_VERSION, '1.3.0', '<')) {
		if (api_plugin_user_realm_auth('audit.php')) {
			$utilities[__('Technical Support', 'audit')] = array_merge(
				$utilities[__('Technical Support', 'audit')],
				[
					__('View Audit Log', 'audit') => [
						'link'        => 'plugins/audit/audit.php',
						'description' => __('Allows Administrators to view change activity on the Cacti server.  Administrators can also export the audit log for analysis purposes.', 'audit')
					]
				]
			);
		}
	}
}

function audit_config_arrays(): void {
	global $menu, $messages, $audit_retentions, $utilities;

	if (isset($_SESSION['audit_message']) && $_SESSION['audit_message'] != '') {
		$messages['audit_message'] = ['message' => $_SESSION['audit_message'], 'type' => 'info'];
	}

	$audit_retentions = [
		-1   => __('Indefinitely', 'audit'),
		14   => __('%d Weeks',  2, 'audit'),
		30   => __('%d Month',  1, 'audit'),
		60   => __('%d Months', 2, 'audit'),
		90   => __('%d Months', 3, 'audit'),
		120  => __('%d Months', 4, 'audit'),
		183  => __('%d Months', 6, 'audit'),
		365  => __('%d Year',   1, 'audit'),
		730  => __('%d Years',  2, 'audit'),
		1095 => __('%d Years',  3, 'audit')
	];

	$menu[__('Utilities')]['plugins/audit/audit.php'] = __('Audit Log', 'audit');

	if (function_exists('auth_augment_roles')) {
		auth_augment_roles(__('Audit Plugin', 'audit'), ['audit.php', 'audit_manage.php']);
	}

	audit_check_upgrade();
}

function audit_config_settings(): void {
	global $tabs, $settings, $item_rows, $audit_retentions;

	$temp = [];

	if (php_sapi_name() === 'cli' || audit_user_is_admin()) {
		$temp = [
		'audit_header' => [
			'friendly_name' => __('Audit Log Settings', 'audit'),
			'method'        => 'spacer',
		],
		'audit_enabled' => [
			'friendly_name' => __('Enable Audit Log', 'audit'),
			'description'   => __('Check this box, if you want the Audit Log to track GUI activities.', 'audit'),
			'method'        => 'checkbox',
			'default'       => 'on'
		],
		'audit_retention' => [
			'friendly_name' => __('Audit Log Retention', 'audit'),
			'description'   => __('How long do you wish Audit Log entries to be retained?', 'audit'),
			'method'        => 'drop_array',
			'default'       => '90',
			'array'         => $audit_retentions
		],
		'audit_log_external' => [
			'friendly_name' => __('External Audit Log', 'audit'),
			'description'   => __('Check this box, if you want the Audit Log to be written to an external file.', 'audit'),
			'method'        => 'checkbox',
			'default'       => 'off'
		],
		'audit_log_external_format' => [
			'friendly_name' => __('External Audit Log Format', 'audit'),
			'description'   => __('Select the output format for external audit log records.', 'audit'),
			'method'        => 'drop_array',
			'default'       => 'json',
			'array'         => [
				'text' => __('Text', 'audit'),
				'json' => __('JSON', 'audit')
			]
		],
		'audit_log_external_path' => [
			'friendly_name' => __('External Audit Log Log file  Path', 'audit'),
			'description'   => __('Enter the path to the external audit log file.', 'audit'),
			'method'        => 'filepath',
			'default'       => '/var/www/html/cacti/log/audit.log',
			'max_length'    => '255'
		],
		];

		$auth_settings = [
			'audit_auth_header' => [
				'friendly_name' => __('Authentication Auditing', 'audit'),
				'method'        => 'spacer',
			],
			'audit_auth_log_enabled' => [
				'friendly_name' => __('Enable Authentication Auditing', 'audit'),
				'description'   => __('Opt in to capture new login, logout, token, password-change, and authorization-denied events from this point forward.', 'audit'),
				'method'        => 'checkbox',
				'default'       => 'off'
			],
			'audit_brute_force_enabled' => [
				'friendly_name' => __('Enable Failed-login Volume Detection', 'audit'),
				'description'   => __('Emit a global anomaly event when installation-wide failed-login volume exceeds the configured threshold.', 'audit'),
				'method'        => 'checkbox',
				'default'       => 'off'
			],
			'audit_brute_force_window_minutes' => [
				'friendly_name' => __('Failed-login Window (minutes)', 'audit'),
				'description'   => __('Rolling window in minutes, from 1 through 1440, used to count failed logins.', 'audit'),
				'method'        => 'textbox',
				'default'       => '5',
				'max_length'    => '4',
				'size'          => '8'
			],
			'audit_brute_force_threshold' => [
				'friendly_name' => __('Failed-login Volume Threshold', 'audit'),
				'description'   => __('Installation-wide failed-login count, from 1 through 1000, that triggers a global anomaly event.', 'audit'),
				'method'        => 'textbox',
				'default'       => '10',
				'max_length'    => '4',
				'size'          => '8'
			],
			'audit_user_log_batch_size' => [
				'friendly_name' => __('User Log Ingestion Batch Size', 'audit'),
				'description'   => __('Maximum user_log rows ingested and expired markers reclaimed per poller cycle, from 1 through 5000. Marker state is retained for seven days, so larger batches increase both peak poller work and the bounded seven-day state-table size.', 'audit'),
				'method'        => 'textbox',
				'default'       => '1000',
				'max_length'    => '4',
				'size'          => '8'
			],
		];

		$facility_options = [];

		foreach (audit_syslog_facilities() as $facility => $code) {
			$facility_options[$facility] = strtoupper($facility) . ' (' . $code . ')';
		}

		$syslog = [
			'audit_syslog_header' => [
				'friendly_name' => __('Remote Syslog', 'audit'),
				'method'        => 'spacer'
			],
			'audit_syslog_enabled' => [
				'friendly_name' => __('Enable Remote Syslog', 'audit'),
				'description'   => __('Queue finalized audit events for remote Syslog delivery. The existing external file output remains independent.', 'audit'),
				'method'        => 'checkbox',
				'default'       => 'off'
			],
			'audit_syslog_receiver' => [
				'friendly_name' => __('Syslog Receiver', 'audit'),
				'description'   => __('Enter a receiver hostname or IP address without a URI scheme, path, or credentials.', 'audit'),
				'method'        => 'textbox',
				'default'       => '',
				'max_length'    => '253',
				'size'          => '60'
			],
			'audit_syslog_port' => [
				'friendly_name' => __('Syslog Port', 'audit'),
				'description'   => __('Enter 1-65535, or leave blank to use 514 for UDP/TCP and 6514 for TLS.', 'audit'),
				'method'        => 'textbox',
				'default'       => '',
				'max_length'    => '5',
				'size'          => '8'
			],
			'audit_syslog_transport' => [
				'friendly_name' => __('Syslog Transport', 'audit'),
				'description'   => __('UDP sends one datagram without acknowledgement. TCP and TLS use RFC 6587 octet-count framing.', 'audit'),
				'method'        => 'drop_array',
				'default'       => 'udp',
				'array'         => [
					'udp' => __('UDP', 'audit'),
					'tcp' => __('TCP', 'audit'),
					'tls' => __('TLS', 'audit')
				]
			],
			'audit_syslog_format' => [
				'friendly_name' => __('Syslog Payload Format', 'audit'),
				'description'   => __('All formats use an RFC 5424 header. Select RFC 5424 structured data, CEF, or compact JSON for the message.', 'audit'),
				'method'        => 'drop_array',
				'default'       => 'json',
				'array'         => [
					'rfc5424' => __('RFC 5424', 'audit'),
					'cef'     => __('CEF', 'audit'),
					'json'    => __('JSON', 'audit')
				]
			],
			'audit_syslog_facility' => [
				'friendly_name' => __('Syslog Facility', 'audit'),
				'description'   => __('Select the facility used to calculate the RFC 5424 priority.', 'audit'),
				'method'        => 'drop_array',
				'default'       => 'local0',
				'array'         => $facility_options
			],
			'audit_syslog_application' => [
				'friendly_name' => __('Syslog Application Name', 'audit'),
				'description'   => __('RFC 5424 APP-NAME. Printable non-space ASCII, up to 48 characters.', 'audit'),
				'method'        => 'textbox',
				'default'       => 'cacti-audit',
				'max_length'    => '48',
				'size'          => '30'
			],
			'audit_syslog_node_id' => [
				'friendly_name' => __('Audit Node Identity', 'audit'),
				'description'   => __('Stable RFC 5424 hostname identity for this Cacti node. Do not use a value that changes on restart.', 'audit'),
				'method'        => 'textbox',
				'default'       => php_uname('n'),
				'max_length'    => '255',
				'size'          => '60'
			],
			'audit_syslog_timeout' => [
				'friendly_name' => __('Connection and Write Timeout', 'audit'),
				'description'   => __('Timeout in seconds, from 1 through 30.', 'audit'),
				'method'        => 'textbox',
				'default'       => '5',
				'max_length'    => '2',
				'size'          => '8'
			],
			'audit_syslog_udp_max_size' => [
				'friendly_name' => __('Maximum UDP Record Size', 'audit'),
				'description'   => __('Records larger than this byte limit are dead-lettered and are never truncated or split. TCP or TLS is recommended for large events.', 'audit'),
				'method'        => 'textbox',
				'default'       => '8192',
				'max_length'    => '5',
				'size'          => '10'
			],
			'audit_syslog_tls_header' => [
				'friendly_name' => __('Syslog TLS', 'audit'),
				'method'        => 'spacer'
			],
			'audit_syslog_tls_ca_file' => [
				'friendly_name' => __('TLS CA File', 'audit'),
				'description'   => __('Optional PEM CA bundle. Peer and hostname verification are always enabled.', 'audit'),
				'method'        => 'filepath',
				'default'       => '',
				'max_length'    => '255'
			],
			'audit_syslog_tls_client_cert' => [
				'friendly_name' => __('TLS Client Certificate', 'audit'),
				'description'   => __('Optional PEM client certificate. A client key must also be configured.', 'audit'),
				'method'        => 'filepath',
				'default'       => '',
				'max_length'    => '255'
			],
			'audit_syslog_tls_client_key' => [
				'friendly_name' => __('TLS Client Private Key', 'audit'),
				'description'   => __('Optional readable PEM private-key path. The key contents are never stored in audit events.', 'audit'),
				'method'        => 'filepath',
				'default'       => '',
				'max_length'    => '255'
			],
			'audit_syslog_delivery_header' => [
				'friendly_name' => __('Syslog Delivery Queue', 'audit'),
				'method'        => 'spacer'
			],
			'audit_syslog_retry_base' => [
				'friendly_name' => __('Retry Base Delay', 'audit'),
				'description'   => __('Initial retry delay in seconds, from 1 through 3600.', 'audit'),
				'method'        => 'textbox',
				'default'       => '30',
				'max_length'    => '4',
				'size'          => '8'
			],
			'audit_syslog_retry_max' => [
				'friendly_name' => __('Maximum Retry Delay', 'audit'),
				'description'   => __('Maximum retry delay in seconds, from the base delay through 86400.', 'audit'),
				'method'        => 'textbox',
				'default'       => '3600',
				'max_length'    => '5',
				'size'          => '8'
			],
			'audit_syslog_max_attempts' => [
				'friendly_name' => __('Maximum Delivery Attempts', 'audit'),
				'description'   => __('Move a record to dead-letter after this many attempts, from 1 through 100.', 'audit'),
				'method'        => 'textbox',
				'default'       => '10',
				'max_length'    => '3',
				'size'          => '8'
			],
			'audit_syslog_batch_size' => [
				'friendly_name' => __('Poller Batch Size', 'audit'),
				'description'   => __('Maximum due records processed per poller cycle, from 1 through 1000.', 'audit'),
				'method'        => 'textbox',
				'default'       => '100',
				'max_length'    => '4',
				'size'          => '8'
			],
			'audit_syslog_pending_age_warning' => [
				'friendly_name' => __('Pending Age Warning', 'audit'),
				'description'   => __('Show an unhealthy warning when the oldest queued record reaches this age in seconds.', 'audit'),
				'method'        => 'textbox',
				'default'       => '900',
				'max_length'    => '6',
				'size'          => '10'
			],
			'audit_syslog_dead_letter_warning' => [
				'friendly_name' => __('Dead-letter Warning Count', 'audit'),
				'description'   => __('Show an unhealthy warning when this many records are dead-lettered.', 'audit'),
				'method'        => 'textbox',
				'default'       => '1',
				'max_length'    => '7',
				'size'          => '10'
			]
		];

		$temp = array_merge($temp, $auth_settings, $syslog);
	}

	$tabs['audit'] = __('Audit', 'audit');

	if (isset($settings['audit'])) {
		$settings['audit'] = array_merge($settings['audit'], $temp);
	} else {
		$settings['audit'] = $temp;
	}
}

/**
 * @param  array<string,mixed> $nav
 * @return array<string,mixed>
 */
function audit_draw_navigation_text(array $nav): array {
	$nav['audit.php:'] = [
		'title'   => __('Audit Event Log', 'audit'),
		'mapping' => 'index.php:',
		'url'     => 'audit.php',
		'level'   => '1'
	];

	return $nav;
}
