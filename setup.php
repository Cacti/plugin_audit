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

function plugin_audit_install() {
	api_plugin_register_hook('audit', 'config_arrays',        'audit_config_arrays',        'setup.php');
	api_plugin_register_hook('audit', 'config_settings',      'audit_config_settings',      'setup.php');
	api_plugin_register_hook('audit', 'config_insert',        'audit_config_insert',        'setup.php');
	api_plugin_register_hook('audit', 'poller_bottom',        'audit_poller_bottom',        'setup.php');
	api_plugin_register_hook('audit', 'draw_navigation_text', 'audit_draw_navigation_text', 'setup.php');
	api_plugin_register_hook('audit', 'utilities_array',      'audit_utilities_array',      'setup.php');
	api_plugin_register_hook('audit', 'is_console_page',      'audit_is_console_page',      'setup.php');

	/* hook for table replication */
	api_plugin_register_hook('audit', 'replicate_out',        'audit_replicate_out',        'setup.php');

	api_plugin_register_realm('audit', 'audit.php', __('View Cacti Audit Log', 'audit'), 1);
	api_plugin_register_realm('audit', 'audit_manage.php', __('Manage Cacti Audit Log', 'audit'), 1);

	audit_setup_table();
}

function plugin_audit_uninstall() {
	db_execute('DROP TABLE IF EXISTS audit_log');
	return true;
}

function audit_is_console_page($url) {
	if (strpos($url, 'audit.php') !== false) {
		return true;
	}

	return false;
}

function plugin_audit_check_config() {
	return true;
}

function plugin_audit_upgrade() {
	return true;
}

function audit_check_upgrade() {
	global $config, $database_default;
	include_once($config['library_path'] . '/database.php');
	include_once($config['library_path'] . '/functions.php');

	$files = array('plugins.php', 'audit.php');
	if (isset($_SERVER['PHP_SELF']) && !in_array(basename($_SERVER['PHP_SELF']), $files)) {
		return;
	}

	$info    = plugin_audit_version();
	$current = $info['version'];
	$old     = db_fetch_cell_prepared('SELECT version FROM plugin_config WHERE directory = ?', array('audit'));
	if ($current != $old) {
		if (api_plugin_is_enabled('audit')) {
			# may sound ridiculous, but enables new hooks
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

		db_execute_prepared('UPDATE plugin_config
			SET version = ?
			WHERE directory = ?',
			array($current, 'audit'));

		db_execute_prepared('UPDATE plugin_config SET
			version = ?,
			name = ?,
			author = ?,
			webpage = ?
			WHERE directory = ?',
			array($info['version'], $info['longname'], $info['author'], $info['homepage'], $info['name']));

		/* hook for table replication */
		api_plugin_register_hook('audit', 'replicate_out', 'audit_replicate_out', 'setup.php', '1');
		api_plugin_register_hook('audit', 'is_console_page', 'audit_is_console_page', 'setup.php', 1);
		api_plugin_register_realm('audit', 'audit_manage.php', __('Manage Cacti Audit Log', 'audit'), 1);
	}
}

function audit_replicate_out($data) {
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
	}

	return $data;
}

function audit_poller_bottom() {
	audit_retry_external_logs();

	$last_check = read_config_option('audit_last_check');
	$now        = gmdate('Y-m-d');

	if ($last_check != $now) {
		$retention = read_config_option('audit_retention');

		if ($retention > 0) {
			$cutoff = audit_retention_cutoff($retention);

			db_execute_prepared('DELETE FROM audit_log WHERE event_time < ?', array($cutoff->format('Y-m-d H:i:s')));
			$rows = db_affected_rows();
			cacti_log('NOTE: Purged ' . $rows . ' Audit Log Records from Cacti', false, 'POLLER');
		}
	}

	set_config_option('audit_last_check', $now);
}

function audit_setup_table() {
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
		PRIMARY KEY (`id`),
		KEY `user_id` (`user_id`),
		KEY `page` (`page`),
		KEY `ip_address` (`ip_address`),
		KEY `event_time` (`event_time`),
		KEY `action` (`action`))
		ENGINE=InnoDB
		COMMENT='Audit Log for all GUI activities'");

	return true;
}

function plugin_audit_version() {
	global $config;
	$info = parse_ini_file($config['base_path'] . '/plugins/audit/INFO', true);
	return $info['info'];
}

function audit_log_valid_event() {
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

function audit_utilities_array() {
	global $utilities;

	if (version_compare(CACTI_VERSION, '1.3.0', '<')) {
		if (api_plugin_user_realm_auth('audit.php')) {
			$utilities[__('Technical Support', 'audit')] = array_merge(
				$utilities[__('Technical Support', 'audit')],
				array(
					__('View Audit Log', 'audit') => array(
						'link'  => 'plugins/audit/audit.php',
						'description' => __('Allows Administrators to view change activity on the Cacti server.  Administrators can also export the audit log for analysis purposes.', 'audit')
					)
				)
			);
		}
	}
}

function audit_config_arrays() {
	global $menu, $messages, $audit_retentions, $utilities;

	if (isset($_SESSION['audit_message']) && $_SESSION['audit_message'] != '') {
		$messages['audit_message'] = array('message' => $_SESSION['audit_message'], 'type' => 'info');
	}

	$audit_retentions = array(
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
	);

	$menu[__('Utilities')]['plugins/audit/audit.php'] = __('Audit Log', 'audit');

	if (function_exists('auth_augment_roles')) {
		auth_augment_roles(__('System Administration'), array('audit.php'));
	}

	audit_check_upgrade();
}

function audit_config_settings() {
	global $tabs, $settings, $item_rows, $audit_retentions;

	$temp = array(
		'audit_header' => array(
			'friendly_name' => __('Audit Log Settings', 'audit'),
			'method' => 'spacer',
		),
		'audit_enabled' => array(
			'friendly_name' => __('Enable Audit Log', 'audit'),
			'description' => __('Check this box, if you want the Audit Log to track GUI activities.', 'audit'),
			'method' => 'checkbox',
			'default' => 'on'
		),
		'audit_retention' => array(
			'friendly_name' => __('Audit Log Retention', 'audit'),
			'description' => __('How long do you wish Audit Log entries to be retained?', 'audit'),
			'method' => 'drop_array',
			'default' => '90',
			'array' => $audit_retentions
		),
		'audit_log_external' => array(
			'friendly_name' => __('External Audit Log', 'audit'),
			'description' => __('Check this box, if you want the Audit Log to be written to an external file.', 'audit'),
			'method' => 'checkbox',
			'default' => 'off'
		),
		'audit_log_external_format' => array(
			'friendly_name' => __('External Audit Log Format', 'audit'),
			'description' => __('Select the output format for external audit log records.', 'audit'),
			'method' => 'drop_array',
			'default' => 'json',
			'array' => array(
				'text' => __('Text', 'audit'),
				'json' => __('JSON', 'audit')
			)
		),
		'audit_log_external_path' => array(
			'friendly_name' => __('External Audit Log Log file  Path', 'audit'),
			'description' => __('Enter the path to the external audit log file.', 'audit'),
			'method' => 'filepath',
			'default' => '/var/www/html/cacti/log/audit.log',
			'max_length' => '255'
		),
	);

	$tabs['audit'] = __('Audit', 'audit');

	if (isset($settings['audit'])) {
		$settings['audit'] = array_merge($settings['audit'], $temp);
	} else {
		$settings['audit'] = $temp;
	}
}

function audit_draw_navigation_text($nav) {
	$nav['audit.php:'] = array(
		'title'   => __('Audit Event Log', 'audit'),
		'mapping' => 'index.php:',
		'url'     => 'audit.php',
		'level'   => '1'
	);

	return $nav;
}
