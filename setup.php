<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2007-2023 The Cacti Group                                 |
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

	/* hook for table replication */
	api_plugin_register_hook('audit', 'replicate_out',        'audit_replicate_out',        'setup.php');

	api_plugin_register_realm('audit', 'audit.php', __('View Cacti Audit Log', 'audit'), 1);

	audit_setup_table();
}

function plugin_audit_uninstall() {
	db_execute('DROP TABLE IF EXISTS audit_log');
	return true;
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
	$old     = db_fetch_cell("SELECT version FROM plugin_config WHERE directory='audit'");
	if ($current != $old) {
		if (api_plugin_is_enabled('audit')) {
			# may sound ridiculous, but enables new hooks
			api_plugin_enable_hooks('audit');

			db_execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS object_data LONGBLOB');
		}

		db_execute("UPDATE plugin_config
			SET version='$current'
			WHERE directory='audit'");

		db_execute("UPDATE plugin_config SET
			version='" . $info['version']  . "',
			name='"    . $info['longname'] . "',
			author='"  . $info['author']   . "',
			webpage='" . $info['homepage'] . "'
			WHERE directory='" . $info['name'] . "' ");

		/* hook for table replication */
		api_plugin_register_hook('audit', 'replicate_out', 'audit_replicate_out', 'setup.php', '1');
	}
}

function audit_check_dependencies($data) {
	$remote_poller_id = $data['remote_poller_id'];
	$rcnn_id          = $data['rcnn_id'];
	$class            = $data['class'];

	if ($class == 'all') {
		if (!db_table_exists('alert_log', false, $rcnn_id)) {
			$create = db_fetch_cell('SHOW CREATE TABLE autid_log');

			db_execute($create, false, $rcnn_id);
		}
	}

	return $data;
}

function audit_replicate_out($data) {
	$remote_poller_id = $data['remote_poller_id'];
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
			cacti_log('INFO: Audit Log table exists skipping', false, 'REPLICATE');
		}
	}

	return $data;
}

function audit_poller_bottom() {
	$last_check = read_config_option('audit_last_check');

	$now = date('d');

	if ($last_check != $now) {
		$retention = read_config_option('audit_retention');

		if ($retention > 0) {
			db_execute('DELETE FROM audit_log WHERE event_time < FROM_UNIXTIME(' . (time() - ($retention * 86400)) . ')');
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
		`ip_address` varchar(40) DEFAULT NULL,
		`user_agent` varchar(256) DEFAULT NULL,
		`event_time` timestamp DEFAULT CURRENT_TIMESTAMP,
		`post` longblob,
		`object_data` longblob,
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

function plugin_audit_version () {
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
		} elseif (isset($_POST) && sizeof($_POST)) {
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

	/* append technical support page */
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

	if (function_exists('auth_augment_roles')) {
		auth_augment_roles(__('System Administration'), array('audit.php'));
	}

	audit_check_upgrade();
}

function audit_config_settings () {
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
		'audit_log_external_path' => array(
			'friendly_name' => __('External Audit Log Log file  Path', 'audit'),
			'description' => __('Enter the path to the external audit log file.', 'audit'),
			'method' => 'textbox',
			'default' => '/var/www/cacti/log/audit.log',
			'max_length' => '255'

			),
		);

	$tabs['Audit'] = __('Audit', 'Audit');

	if (isset($settings['Audit'])) {
		$settings['Audit'] = array_merge($settings['Audit'], $temp);
	} else {
		$settings['Audit'] = $temp;
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
