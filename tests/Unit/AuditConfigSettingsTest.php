<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for audit_config_settings() in setup.php.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

it('registers audit settings including External Audit Log File Path', function () {
	global $tabs, $settings, $item_rows, $audit_retentions;

	$tabs             = array();
	$settings         = array();
	$item_rows        = array();
	$audit_retentions = array(90 => '90 Days');

	audit_config_settings();

	expect($settings['audit'])->toHaveKey('audit_log_external_path');
	expect($settings['audit']['audit_log_external_path']['friendly_name'])
		->toBe('External Audit Log File Path');
});
