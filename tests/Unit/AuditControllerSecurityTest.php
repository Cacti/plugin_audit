<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Verify controller/setup source carries the security guards audit_manage.php
 * and setup.php are expected to enforce (CSRF, admin checks, CSV escaping,
 * POST-only actions, and the schema/replication requirements they rely on).
 */

describe('audit controller and schema security guards', function () {
	$controller = plugin_test_read_source('audit.php');
	$functions  = plugin_test_read_source('audit_functions.php');
	$javascript = plugin_test_read_source('js/functions.js');
	$setup      = plugin_test_read_source('setup.php');

	it('enforces required controller guards', function () use ($controller) {
		$required_controller_guards = array(
			"\$_SERVER['REQUEST_METHOD'] !== 'POST'",
			'audit_user_is_admin()',
			'csrf_check(false)',
			'html_escape($data',
			"__('Outcome Reason:', 'audit')",
			"header('Content-Type: text/csv; charset=UTF-8')",
			'fputcsv(',
			"case 'syslog_test':",
			"case 'syslog_retry':",
			'audit_syslog_test_delivery()',
			'audit_syslog_retry_dead_letters($delivery_ids)'
		);

		foreach ($required_controller_guards as $guard) {
			expect($controller)->toContain($guard);
		}
	});

	it('defines the required schema and replication fragments', function () use ($setup) {
		$required_schema_fragments = array(
			"'audit.php'        => __('Audit Log User'",
			"'audit_manage.php' => __('Audit Log Admin'",
			'audit_setup_realms(true)',
			'audit_setup_realms()',
			'audit_remove_deprecated_realms()',
			"auth_augment_roles(__('Audit Plugin', 'audit'), ['audit.php', 'audit_manage.php'])",
			'api_plugin_register_hook(\'audit\', \'replicate_out\'',
			'request_status',
			'ADD COLUMN IF NOT EXISTS external_status',
			'ADD COLUMN IF NOT EXISTS external_error',
			'SHOW CREATE TABLE $table',
			'audit_retry_external_logs()',
			'audit_process_syslog_queue()',
			'logout_pre_session_destroy',
			'event_uuid char(36)',
			'operation_outcome',
			'external_attempts',
			'CREATE TABLE IF NOT EXISTS `audit_syslog_delivery`',
			'DROP TABLE IF EXISTS audit_syslog_delivery'
		);

		foreach ($required_schema_fragments as $fragment) {
			expect($setup)->toContain($fragment);
		}
	});

	it('requires operation verification fragments', function () use ($functions) {
		$required_verifier_fragments = array(
			'audit_operation_verifier_for_request',
			"'user_realm_permissions'",
			"'realm_permissions_verified'",
			"register_shutdown_function('audit_finalize_request', \$audit_id, \$started_at, \$verifier)"
		);

		foreach ($required_verifier_fragments as $fragment) {
			expect($functions)->toContain($fragment);
		}
	});

	it('authorizes only the current realm to purge', function () use ($functions) {
		expect($functions)->toContain("api_plugin_user_realm_auth('audit_manage.php')");
		expect($functions)->not->toContain("api_plugin_user_realm_auth('audit_purge.php')");
	});

	it('protects the purge action and its UI control', function () use ($controller) {
		expect(substr_count($controller, 'audit_user_is_admin()'))->toBeGreaterThanOrEqual(2,
			'Purge authorization must protect both the action and its UI control.');
	});

	it('validates CSRF on purge, Syslog test, and Syslog retry actions', function () use ($controller) {
		expect(substr_count($controller, 'csrf_check(false)'))->toBeGreaterThanOrEqual(3,
			'Purge, Syslog test, and Syslog retry actions must each validate CSRF.');
	});

	it('enforces Audit Log Admin on remote Syslog settings saves', function () use ($functions) {
		expect($functions)->toContain('audit_enforce_syslog_settings_request()');
		expect($functions)->toContain("'audit.syslog.configuration.denied'");
	});

	it('uses POST-only request paths for administrative actions', function () use ($javascript) {
		expect($javascript)->not->toContain("loadPageNoHeader('audit.php?action=purge");
		expect($javascript)->toContain("loadPageUsingPost('audit.php?action=purge");
		expect($javascript)->toContain("loadPageUsingPost('audit.php?action=syslog_test");
		expect($javascript)->toContain("loadPageUsingPost('audit.php?action=syslog_retry");
	});
});
