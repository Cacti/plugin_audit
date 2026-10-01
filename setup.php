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

require_once(__DIR__ . '/includes/database.php');

/**
 * Return the CSP nonce attribute for inline <script> tags, safely across
 * Cacti versions. Newer Cacti releases enforce a Content-Security-Policy that
 * requires a per-request nonce on parser-inserted scripts; older releases lack
 * the CactiSecureHeaders class, so this returns an empty string there.
 *
 * @return string The nonce attribute when supported, otherwise empty string.
 */
function plugin_audit_csp_nonce(): string {
	if (class_exists('CactiSecureHeaders')) {
		return CactiSecureHeaders::getNonceAttribute();
	}

	return '';
}

include_once(__DIR__ . '/includes/functions.php');

/**
 * Installs the Audit plugin: registers its Cacti hooks (config_arrays,
 * config_settings, config_insert, poller_bottom, draw_navigation_text,
 * utilities_array, is_console_page, logout_pre_session_destroy,
 * logout_post_session_destroy, custom_denied, replicate_out), registers
 * its two realms (Audit Log User/Admin), and creates its database tables
 * and default settings. Invoked by Cacti's plugin architecture when an
 * administrator installs this plugin from Console > Plugin Management.
 *
 * @return void
 */
function plugin_audit_install(): void {
	api_plugin_register_hook('audit', 'config_arrays',        'audit_config_arrays',        'setup.php');
	api_plugin_register_hook('audit', 'config_settings',      'audit_config_settings',      'setup.php');
	api_plugin_register_hook('audit', 'config_insert',        'audit_config_insert',        'setup.php');
	api_plugin_register_hook('audit', 'poller_bottom',        'audit_poller_bottom',        'setup.php');
	api_plugin_register_hook('audit', 'draw_navigation_text', 'audit_draw_navigation_text', 'setup.php');
	api_plugin_register_hook('audit', 'utilities_array',      'audit_utilities_array',      'setup.php');
	api_plugin_register_hook('audit', 'is_console_page',      'audit_is_console_page',      'setup.php');
	api_plugin_register_hook('audit', 'logout_pre_session_destroy', 'audit_logout_pre_session_destroy', 'setup.php');
	api_plugin_register_hook('audit', 'logout_post_session_destroy', 'audit_logout_post_session_destroy', 'includes/functions.php');
	api_plugin_register_hook('audit', 'custom_denied',        'audit_custom_denied',        'includes/functions.php');

	// hook for table replication
	api_plugin_register_hook('audit', 'replicate_out',        'audit_replicate_out',        'setup.php');

	audit_setup_realms(true);

	audit_setup_table();
	audit_persist_auth_defaults();
}

/**
 * Persists authentication auditing defaults without overwriting existing
 * administrator choices. Called on fresh install and upgrade so that
 * existing installations begin at the current time with authentication
 * auditing disabled until an Audit Log Admin explicitly opts in. Called
 * from plugin_audit_install() during installation.
 *
 * @return void
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

/**
 * Registers this plugin's two access realms ('Audit Log User' for
 * audit.php, 'Audit Log Admin' for audit_manage.php), granting them to
 * the installing user on a fresh install, or otherwise (e.g. after a
 * realm-list change) re-granting them to the configured admin user.
 * Called from plugin_audit_install() during installation, and from
 * audit_check_upgrade() when this plugin's realm set changes.
 *
 * @param bool $grant_installing_user Whether to grant both realms to the
 *                                    currently installing user (fresh
 *                                    install); when false, instead
 *                                    re-grants them to the configured
 *                                    'admin_user' setting; defaults to
 *                                    false.
 *
 * @return void
 */
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

/**
 * Removes a since-removed legacy realm ('audit_purge.php') and its user/
 * group permission assignments, then triggers a plugin-config replication
 * so the removal propagates to any remote pollers. Called from
 * audit_check_upgrade() when upgrading from a version that registered
 * the obsolete realm.
 *
 * @return void
 */
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
 * Lists every Cacti settings-table option name owned by this plugin, used
 * to identify which rows to remove on uninstall. Called from
 * plugin_audit_uninstall() before deleting this plugin's settings.
 *
 * @return list<string> The owned setting names.
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

/**
 * Uninstalls the Audit plugin: removes the authentication-auditing
 * database indexes it added to user_log (when it owns them), drops all
 * of its database tables, and removes its owned settings-table rows
 * (keeping the 'audit_user_log_indexes_owned' marker only when the
 * indexes could not be removed). Invoked by Cacti's plugin architecture
 * when an administrator uninstalls this plugin from Console > Plugin
 * Management.
 *
 * @return bool True when the user_log indexes were successfully removed
 *              (or were never owned by this plugin).
 */
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

/**
 * Hook implementation for Cacti's 'is_console_page' filter. Identifies
 * whether a given URL is one of this plugin's own console pages. Called
 * by Cacti core via api_plugin_hook('is_console_page', ...) while
 * determining page classification for navigation/auth purposes.
 *
 * @param string $url The URL to classify.
 *
 * @return bool True when $url refers to audit.php.
 */
function audit_is_console_page(string $url): bool {
	return str_contains($url, 'audit.php');
}

/**
 * Verifies the plugin's configuration; currently a no-op placeholder.
 * Invoked by Cacti's plugin architecture on relevant page loads.
 *
 * @return bool Always returns true.
 */
function plugin_audit_check_config(): bool {
	return true;
}

/**
 * Performs any schema/data migrations needed when upgrading to a newer
 * version of this plugin; currently a no-op placeholder (the real
 * upgrade logic runs unconditionally via audit_check_upgrade() rather
 * than this hook). Invoked by Cacti's plugin architecture when an
 * installed plugin's version increases.
 *
 * @return bool Always returns true.
 */
function plugin_audit_upgrade(): bool {
	return true;
}

/**
 * Detects whether the installed plugin_config version differs from this
 * plugin's INFO file version and, if so, applies audit_log schema
 * migrations (renaming/adding the request_status/external_status/
 * external_error columns, normalizing legacy status values), upgrades
 * the Syslog/user-log-state tables and event schema, re-persists auth
 * defaults/realms, updates the stored plugin_config record, and
 * re-registers newer hooks. Only runs on plugins.php/audit.php. Called
 * from this plugin's page-load flow on every relevant page load.
 *
 * @return void
 *
 * @global array  $config           Cacti global configuration array;
 *                                   used to load database.php/
 *                                   functions.php.
 * @global object $database_default Cacti's default database connection
 *                                   handle (unused directly here;
 *                                   declared for parity with other
 *                                   database-touching functions in this
 *                                   file).
 */
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

		// Remove files tombstoned in manifest.json plus the dev-only tests/ tree.
		plugin_audit_prune_files();

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
		api_plugin_register_hook('audit', 'logout_post_session_destroy', 'audit_logout_post_session_destroy', 'includes/functions.php', 1);
		api_plugin_register_hook('audit', 'custom_denied', 'audit_custom_denied', 'includes/functions.php', 1);
	}
}

/**
 * Hook implementation for Cacti's 'replicate_out' filter. Replicates this
 * plugin's audit_log table (creating it and applying the same schema
 * migrations as audit_check_upgrade() if missing/outdated) and its
 * user-log deduplication state table out to a remote poller; core
 * user_log indexes are local-only and are never replicated. Called by
 * Cacti core via api_plugin_hook('replicate_out', ...) during remote
 * poller data replication.
 *
 * @param array<string,mixed> $data The replication context, including
 *                                  'rcnn_id' (the remote connection id)
 *                                  and 'class' ('all' triggers this
 *                                  plugin's replication).
 *
 * @return array<string,mixed> The unmodified $data array.
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

/**
 * Hook implementation for Cacti's 'poller_bottom' filter. Runs this
 * plugin's per-cycle maintenance: reclaims stale user-log-state marker
 * rows, retries external-log/Syslog deliveries, polls Cacti's user_log
 * table for new authentication events, detects aggregate failed-login
 * volume anomalies, and (once per day) purges audit_log rows past the
 * configured retention period (preserving any still in-flight Syslog
 * delivery). Called by Cacti's poller via
 * api_plugin_hook('poller_bottom', ...) at the end of each polling
 * cycle.
 *
 * Authentication events are captured by polling Cacti's user_log table,
 * which is authoritative across all auth methods (local, LDAP, basic,
 * domains) and stable across the 1.2.x and develop branches. Ingestion
 * runs every poller cycle with a bounded workload so login failures and
 * authorization events appear promptly; the deduplication table prevents
 * duplicate events across repeated and concurrent pollers.
 *
 * @return void
 */
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


/**
 * Reads this plugin's INFO file and returns its [info] section. Used by
 * Cacti's plugin architecture via the api_plugin_version hook, and
 * internally by audit_check_upgrade() to detect/report the plugin's
 * version.
 *
 * @return array<string,mixed> The parsed [info] section of the plugin's
 *                             INFO file (keys such as name, version,
 *                             author, homepage, longname), or an empty
 *                             array if the file is missing/malformed.
 *
 * @global array $config Cacti global configuration array; used to locate
 *                        the plugin's base path.
 */
function plugin_audit_version(): array {
	global $config;
	$info        = parse_ini_file($config['base_path'] . '/plugins/audit/INFO', true);
	$plugin_info = is_array($info) ? ($info['info'] ?? null) : null;

	return is_array($plugin_info) ? $plugin_info : [];
}

/**
 * Determines whether the current request represents a "valid" auditable
 * event for this plugin's configuration-change logging (e.g. a POST
 * submission or a plugins.php mode change), excluding known noisy/
 * irrelevant pages such as graph_view.php and the login/password pages.
 * Called from audit_config_insert() to decide whether to build and
 * insert an audit_log row for the current request.
 *
 * @return bool True when the current request should be logged as a
 *              valid configuration-change event.
 *
 * @global string $action Set to the detected action ('purge', or the
 *                         plugins.php 'mode' value) for the caller to
 *                         include in its log entry.
 */
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

/**
 * Hook implementation for Cacti's 'utilities_array' filter, active only
 * on Cacti versions before 1.3.0 (where the Utilities menu is populated
 * via this hook rather than config_arrays). Adds a "View Audit Log" entry
 * under Technical Support for users with access to audit.php. Called by
 * Cacti core via api_plugin_hook('utilities_array', ...) while building
 * the legacy Utilities menu.
 *
 * @return void
 *
 * @global array $utilities Cacti's Utilities menu array, extended here
 *                          with this plugin's entry.
 */
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

/**
 * Hook implementation for Cacti's 'config_arrays' filter. Surfaces any
 * pending session message, populates the shared $audit_retentions
 * lookup used by the Settings page, adds the Audit Log page to the
 * Utilities menu, augments the Audit Plugin role with this plugin's
 * pages where supported, and triggers this plugin's upgrade check.
 * Called by Cacti core via api_plugin_hook('config_arrays', ...) while
 * building the navigation menu.
 *
 * @return void
 *
 * @global array $menu             Cacti's main navigation menu array,
 *                                 extended here with this plugin's entry.
 * @global array $messages         Cacti's pending UI message queue, used
 *                                 here to surface a session-stored audit
 *                                 message.
 * @global array $audit_retentions Populated here with this plugin's
 *                                 retention-period options, used by
 *                                 audit_config_settings().
 * @global array $utilities        Reserved/declared for parity with
 *                                 audit_utilities_array(); not used
 *                                 directly here.
 */
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

/**
 * Hook implementation for Cacti's 'config_settings' filter. Registers the
 * "Audit" Settings tab's fields (enable/retention/external-log settings,
 * always visible to CLI/audit admins; the authentication-auditing,
 * brute-force-detection, and remote-Syslog delivery fields are further
 * gated within this function by admin status and prerequisite checks).
 * Called by Cacti core via api_plugin_hook('config_settings', ...) while
 * building the Settings page.
 *
 * @return void
 *
 * @global array $tabs             Cacti's registered Settings page tabs,
 *                                 extended here with the 'audit' tab.
 * @global array $settings         Cacti's registered Settings page
 *                                 fields, extended here with this
 *                                 plugin's settings under the 'audit'
 *                                 tab.
 * @global array $item_rows        Reserved/declared for parity with
 *                                 other config_settings hook
 *                                 implementations; not used directly
 *                                 here.
 * @global array $audit_retentions Map of retention-period options,
 *                                 populated by audit_config_arrays() and
 *                                 used here for the retention field.
 */
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
 * Hook implementation for Cacti's 'draw_navigation_text' filter. Adds a
 * breadcrumb entry for audit.php's default view. Called by Cacti core
 * via api_plugin_hook('draw_navigation_text', ...) while rendering the
 * page breadcrumb trail.
 *
 * @param  array<string,mixed> $nav The existing breadcrumb map
 *                                  contributed by Cacti core and other
 *                                  plugins.
 * @return array<string,mixed> The $nav array with this plugin's
 *                             breadcrumb entry added.
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

/**
 * Removes files and directories that a previous version of this plugin
 * shipped but that have since moved or been deleted, using the tombstone
 * and whitelist lists in manifest.json. Whitelisted (user-data) paths and
 * any VCS metadata (.git*) are never touched; the dev-only tests/ tree is
 * removed. Any path that resolves outside the plugin directory (a tampered
 * manifest.json) is refused, and any file/directory that cannot be removed
 * (e.g. read-only) is reported to the Cacti log. Any top-level entry that is
 * neither expected nor a tombstone nor whitelisted is logged to the Cacti
 * log and left in place. Called on a plugin version change.
 *
 * @return void
 *
 * @global array $config Cacti global configuration array; used to resolve
 *                       the plugin directory.
 */
function plugin_audit_prune_files(): void {
	global $config;

	$plugin_dir    = $config['base_path'] . '/plugins/audit';
	$manifest_path = $plugin_dir . '/manifest.json';

	if (!is_readable($manifest_path)) {
		return;
	}

	$manifest = json_decode((string) file_get_contents($manifest_path), true);

	if (!is_array($manifest)) {
		cacti_log('WARNING: audit manifest.json could not be parsed; skipping file prune', false, 'AUDIT');

		return;
	}

	$tombstones = isset($manifest['tombstones']) && is_array($manifest['tombstones']) ? $manifest['tombstones'] : [];
	$expected   = isset($manifest['expected'])   && is_array($manifest['expected'])   ? $manifest['expected']   : [];
	$whitelist  = isset($manifest['whitelist'])  && is_array($manifest['whitelist'])  ? $manifest['whitelist']  : [];

	$protected = function (string $rel) use ($whitelist): bool {
		if (strncmp($rel, '.git', 4) === 0 || strncmp($rel, '.md', 3) === 0) {
			return true;
		}

		foreach ($whitelist as $entry) {
			$entry = trim((string) $entry, '/');

			if ($entry !== '' && ($rel === $entry
				|| strncmp($rel, $entry . '/', strlen($entry) + 1) === 0
				|| strncmp($entry, $rel . '/', strlen($rel) + 1) === 0)) {
				return true;
			}
		}

		return false;
	};

	// Security: resolve the plugin directory so a tampered manifest.json
	// cannot steer the prune outside of it.
	$plugin_real = realpath($plugin_dir);

	// Remove tombstoned (moved/deleted) paths plus the dev-only tests/
	// tree and the phpunit.xml test configuration.
	$remove   = $tombstones;
	$remove[] = 'tests/';
	$remove[] = 'phpunit.xml';

	foreach ($remove as $rel) {
		$rel = trim((string) $rel, '/');

		if ($rel === '' || $protected($rel)) {
			continue;
		}

		// A tombstone must never contain '.'/'..' segments; a tampered manifest
		// could use them to escape the plugin directory or target its root.
		$segments = explode('/', $rel);

		if (in_array('.', $segments, true) || in_array('..', $segments, true)) {
			cacti_log(sprintf('WARNING: audit prune refused to remove %s: path contains a traversal segment (tampered manifest.json?)', $rel), false, 'AUDIT');

			continue;
		}

		$path = $plugin_dir . '/' . $rel;

		if (!is_link($path) && !file_exists($path)) {
			continue;
		}

		// Refuse any path that, after resolving symlinks and ../ segments,
		// escapes the plugin directory (protects user data from a tampered
		// manifest.json).
		$anchor = is_link($path) ? dirname($path) : $path;
		$real   = realpath($anchor);

		if ($real === false || ($real !== $plugin_real && strncmp($real, $plugin_real . DIRECTORY_SEPARATOR, strlen((string) $plugin_real) + 1) !== 0)) {
			cacti_log(sprintf('WARNING: audit prune refused to remove %s: path resolves outside the plugin directory (tampered manifest.json?)', $rel), false, 'AUDIT');

			continue;
		}

		if (is_dir($path) && !is_link($path)) {
			$removed = plugin_audit_rmtree($path);
		} else {
			$removed = @unlink($path);
		}

		if (!$removed) {
			cacti_log(sprintf('WARNING: audit upgrade could not remove %s (check file/directory permissions)', $rel), false, 'AUDIT');
		}
	}

	// Surface any top-level entry the manifest does not account for.
	$known = [];

	foreach (array_merge($expected, $tombstones) as $entry) {
		$top = explode('/', trim((string) $entry, '/'))[0];

		if ($top !== '') {
			$known[$top] = true;
		}
	}

	$entries = scandir($plugin_dir);

	foreach (($entries !== false ? $entries : []) as $entry) {
		if ($entry === '.' || $entry === '..' || $entry === 'tests' || $entry === 'phpunit.xml' || $protected($entry) || isset($known[$entry])) {
			continue;
		}

		cacti_log(sprintf('WARNING: audit upgrade found a file/directory not described in manifest.json: %s (left in place)', $entry), false, 'AUDIT');
	}
}

/**
 * Recursively deletes a directory and its contents. Symlinks are removed
 * without being followed. Helper for plugin_audit_prune_files().
 *
 * @param string $dir Absolute path to the directory to remove.
 *
 * @return bool True if the directory and everything under it was removed;
 *              false if any entry could not be deleted.
 */
function plugin_audit_rmtree(string $dir): bool {
	$entries = scandir($dir);
	$ok      = true;

	foreach (($entries !== false ? $entries : []) as $entry) {
		if ($entry === '.' || $entry === '..') {
			continue;
		}

		$path = $dir . '/' . $entry;

		if (is_dir($path) && !is_link($path)) {
			if (!plugin_audit_rmtree($path)) {
				$ok = false;
			}
		} elseif (!@unlink($path)) {
			$ok = false;
		}
	}

	if (!@rmdir($dir)) {
		$ok = false;
	}

	return $ok;
}
