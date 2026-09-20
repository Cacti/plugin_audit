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
	'if ($data === false || cacti_sizeof($data) === 0)',
	"if (db_table_exists('audit_syslog_delivery'))",
	'cacti_sizeof($syslog) > 0',
	'$syslog[\'state\'] ?? \'unknown\'',
	'$syslog[\'attempts\'] ?? 0',
	'$syslog[\'sent_time\'] ?? \'\'',
	'$syslog[\'last_error\'] ?? \'\'',
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
	'audit_remove_obsolete_realms()',
	"auth_augment_roles(__('Audit Plugin', 'audit'), ['audit.php', 'audit_manage.php'])",
	'api_plugin_register_hook(\'audit\', \'replicate_out\'',
	'request_status',
	'ADD COLUMN IF NOT EXISTS external_status',
	'ADD COLUMN IF NOT EXISTS external_error',
	'SHOW CREATE TABLE $table',
	'audit_retry_external_logs()',
	'audit_process_syslog_queue()',
	'logout_pre_session_destroy',
	'logout_post_session_destroy',
	'custom_denied',
	'audit_poll_user_log()',
	'audit_detect_failed_login_volume()',
	'audit_auth_log_enabled',
	'audit_brute_force_enabled',
	'audit_user_log_batch_size',
	'array_merge($temp, $auth_settings, $syslog)',
	"'audit_user_log_batch_size'        => '1000'",
	'audit_persist_auth_defaults',
	'audit_setup_user_log_indexes',
	'audit_remove_user_log_indexes',
	"'plugin_audit_time'",
	"'plugin_audit_result_time'",
	'CREATE TABLE IF NOT EXISTS `audit_user_log_state`',
	'KEY `pending_retry` (`audit_id`, `retry_count`, `processed_time`)',
	'DROP TABLE IF EXISTS audit_user_log_state',
	'function audit_owned_setting_names(): array',
	"'DELETE FROM settings WHERE name IN ('",
	'audit_owned_setting_names()',
	"array_diff(\$setting_names, ['audit_user_log_indexes_owned'])",
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

it('ships authentication auditing through the 1.6 upgrade path', function () {
	$info      = parse_ini_file(realpath(__DIR__ . '/../../INFO'), true);
	$changelog = plugin_test_read_source('CHANGELOG.md');

	expect($info['info']['version'] ?? null)->toBe('1.6');
	expect($changelog)->toContain('--- 1.6 ---');
});

it('does not index core user_log on fresh installation while auditing is disabled', function () use ($setup) {
	preg_match('/function plugin_audit_install\(\): void \{(?<body>.*?)\n\}/s', $setup, $install_match);

	expect($install_match['body'] ?? null)->not->toBeNull();
	expect($install_match['body'])->not->toContain('audit_setup_user_log_indexes()');
});

it('adds authentication auditing state and hooks on upgrade', function () use ($setup) {
	preg_match('/function audit_check_upgrade\(\): void \{(?<body>.*?)\n\}/s', $setup, $upgrade_match);

	expect($upgrade_match['body'] ?? null)->not->toBeNull();

	foreach (['audit_setup_user_log_state_table()', 'audit_persist_auth_defaults()', "'logout_post_session_destroy'", "'custom_denied'"] as $upgrade_requirement) {
		expect($upgrade_match['body'])->toContain($upgrade_requirement);
	}
});

it('gates the master and external audit controls behind Audit Log Admin', function () use ($setup) {
	preg_match('/function audit_config_settings\(\): void \{(?<body>.*?)\n\}/s', $setup, $settings_match);

	expect($settings_match['body'] ?? null)->not->toBeNull();
	expect(strpos($settings_match['body'], 'audit_user_is_admin()'))->toBeLessThan(strpos($settings_match['body'], "'audit_enabled'"));
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

$required_auth_fragments = [
	'function audit_poll_user_log',
	'function audit_detect_failed_login_volume',
	'function audit_custom_denied',
	'function audit_logout_post_session_destroy',
	'function audit_user_log_event_descriptor',
	"'cacti.auth.login.failed'",
	"'cacti.auth.login.credentials_accepted'",
	"'cacti.auth.login.token'",
	"'cacti.auth.password.changed'",
	"'cacti.auth.password_change_or_2fa_failed'",
	"'cacti.auth.login.unknown'",
	"'cacti.auth.failed_login_volume_anomaly'",
	"'authentication_environment'",
	"'distinct_usernames'",
	"'distinct_ips'",
	"'cacti.auth.authorization.denied'",
	"'authentication.logout.completed'",
	"'audit.configuration.denied'",
	'UNIX_TIMESTAMP(ul.time) AS source_epoch',
	'source_username, source_user_id, source_epoch',
	'INNER JOIN user_log AS ul',
	'audit_auth_log_last_state',
	'retry_count = retry_count + ?',
	'VALUES (?, ?, ?, UTC_TIMESTAMP(), 0, 0, UTC_TIMESTAMP(6))',
	"LIMIT ' .",
	'UPDATE audit_user_log_state',
	'audit_user_log_watermark_epoch',
	'function audit_user_log_event_uuid',
	'SELECT id FROM audit_log WHERE event_uuid = ?',
	'AND auls.retry_count < ?',
	"'defer_delivery'",
	'LEFT JOIN audit_user_log_state AS auls',
	'ON DUPLICATE KEY UPDATE value = GREATEST',
];

it('keeps the required authentication auditing requirements in audit_functions.php', function () use ($functions, $required_auth_fragments) {
	foreach ($required_auth_fragments as $fragment) {
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
