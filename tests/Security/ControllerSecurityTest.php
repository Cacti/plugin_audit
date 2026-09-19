<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Static content checks confirming audit.php, audit_functions.php, setup.php
 * and js/functions.js still contain the guard fragments that keep the
 * Audit controller and its admin actions safe (POST-only mutation, CSRF
 * checks, admin realm authorization, schema/replication requirements, and
 * request-operation verification bookkeeping).
 */

$controller = plugin_test_read_source('audit.php');
$functions  = plugin_test_read_source('audit_functions.php');
$javascript = plugin_test_read_source('js/functions.js');
$setup      = plugin_test_read_source('setup.php');

$required_controller_guards = [
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
	'audit_syslog_retry_dead_letters($delivery_ids)',
];

it('keeps the required controller security guards in audit.php', function () use ($controller, $required_controller_guards) {
	foreach ($required_controller_guards as $guard) {
		expect($controller)->toContain($guard);
	}
});

$required_schema_fragments = [
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
	'DROP TABLE IF EXISTS audit_syslog_delivery',
];

it('keeps the required schema and replication requirements in setup.php', function () use ($setup, $required_schema_fragments) {
	foreach ($required_schema_fragments as $fragment) {
		expect($setup)->toContain($fragment);
	}
});

$required_verifier_fragments = [
	'audit_operation_verifier_for_request',
	"'user_realm_permissions'",
	"'realm_permissions_verified'",
	"register_shutdown_function('audit_finalize_request', \$audit_id, \$started_at, \$verifier)",
];

it('keeps the required operation verification requirements in audit_functions.php', function () use ($functions, $required_verifier_fragments) {
	foreach ($required_verifier_fragments as $fragment) {
		expect($functions)->toContain($fragment);
	}
});

it('requires Audit Log Admin authorization to purge', function () use ($functions) {
	expect($functions)->toContain("api_plugin_user_realm_auth('audit_manage.php')");
});

it('does not let the deprecated delegated purge permission authorize purge', function () use ($functions) {
	expect($functions)->not->toContain("api_plugin_user_realm_auth('audit_purge.php')");
});

it('protects both the purge action and its UI control with an admin check', function () use ($controller) {
	expect(substr_count($controller, 'audit_user_is_admin()'))->toBeGreaterThanOrEqual(2);
});

it('validates CSRF for purge, syslog test, and syslog retry actions', function () use ($controller) {
	expect(substr_count($controller, 'csrf_check(false)'))->toBeGreaterThanOrEqual(3);
});

it('enforces Audit Log Admin on remote Syslog settings save', function () use ($functions) {
	expect($functions)->toContain('audit_enforce_syslog_settings_request()');
	expect($functions)->toContain("'audit.syslog.configuration.denied'");
});

it('does not use the legacy GET request path for purge', function () use ($javascript) {
	expect($javascript)->not->toContain("loadPageNoHeader('audit.php?action=purge");
});

it('uses the POST request path for purge', function () use ($javascript) {
	expect($javascript)->toContain("loadPageUsingPost('audit.php?action=purge");
});

it('uses POST request paths for Syslog administration actions', function () use ($javascript) {
	expect($javascript)->toContain("loadPageUsingPost('audit.php?action=syslog_test");
	expect($javascript)->toContain("loadPageUsingPost('audit.php?action=syslog_retry");
});
