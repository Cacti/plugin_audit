<?php

$controller = file_get_contents(dirname(__DIR__) . '/audit.php');
$functions  = file_get_contents(dirname(__DIR__) . '/audit_functions.php');
$javascript = file_get_contents(dirname(__DIR__) . '/js/functions.js');
$setup      = file_get_contents(dirname(__DIR__) . '/setup.php');

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
	'if (!is_array($data) || $data === [])',
	"if (!audit_syslog_enabled()) {\n\t\treturn;",
	"if (audit_syslog_enabled() && db_table_exists('audit_syslog_delivery'))",
	'cacti_sizeof($syslog) > 0',
	'$syslog[\'state\'] ?? \'unknown\'',
	'$syslog[\'attempts\'] ?? 0',
	'$syslog[\'sent_time\'] ?? \'\'',
	'$syslog[\'last_error\'] ?? \'\''
];

foreach ($required_controller_guards as $guard) {
	if (strpos($controller, $guard) === false) {
		fwrite(STDERR, 'Missing controller security guard: ' . $guard . PHP_EOL);
		exit(1);
	}
}

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
	'logout_post_session_destroy',
	'custom_denied',
	'audit_poll_user_log()',
	'audit_detect_brute_force()',
	'audit_auth_log_enabled',
	'audit_brute_force_enabled',
	'audit_user_log_batch_size',
	'array_merge($temp, $auth_settings, $syslog)',
	"'audit_user_log_batch_size'        => '1000'",
	'audit_persist_auth_defaults',
	'CREATE TABLE IF NOT EXISTS `audit_user_log_state`',
	'DROP TABLE IF EXISTS audit_user_log_state',
	"'DELETE FROM settings WHERE LEFT(name, 6) = ?'",
	"['audit_']",
	'event_uuid char(36)',
	'operation_outcome',
	'external_attempts',
	'CREATE TABLE IF NOT EXISTS `audit_syslog_delivery`',
	'DROP TABLE IF EXISTS audit_syslog_delivery',
	"auth_augment_roles(__('Audit Plugin', 'audit'), ['audit.php', 'audit_manage.php'])"
];

foreach ($required_schema_fragments as $fragment) {
	if (strpos($setup, $fragment) === false) {
		fwrite(STDERR, 'Missing schema or replication requirement: ' . $fragment . PHP_EOL);
		exit(1);
	}
}

$required_verifier_fragments = [
	'audit_operation_verifier_for_request',
	"'user_realm_permissions'",
	"'realm_permissions_verified'",
	"register_shutdown_function('audit_finalize_request', \$audit_id, \$started_at, \$verifier)"
];

$required_auth_fragments = [
	'function audit_poll_user_log',
	'function audit_detect_brute_force',
	'function audit_custom_denied',
	'function audit_logout_post_session_destroy',
	'function audit_user_log_event_descriptor',
	"'cacti.auth.login.failed'",
	"'cacti.auth.login.credentials_accepted'",
	"'cacti.auth.login.token'",
	"'cacti.auth.password.changed'",
	"'cacti.auth.password_change_or_2fa_failed'",
	"'cacti.auth.login.unknown'",
	"'cacti.auth.brute_force_suspected'",
	"'cacti.auth.authorization.denied'",
	"'authentication.logout.completed'",
	"'audit.configuration.denied'",
	"'START TRANSACTION'",
	"'ROLLBACK'",
	"'COMMIT'",
	"'defer_delivery'",
	'FROM audit_user_log_state AS auls',
	'INSERT IGNORE INTO settings (name, value)'
];

foreach ($required_auth_fragments as $fragment) {
	if (strpos($functions, $fragment) === false) {
		fwrite(STDERR, 'Missing authentication audit requirement: ' . $fragment . PHP_EOL);
		exit(1);
	}
}

foreach ($required_verifier_fragments as $fragment) {
	if (strpos($functions, $fragment) === false) {
		fwrite(STDERR, 'Missing operation verification requirement: ' . $fragment . PHP_EOL);
		exit(1);
	}
}

if (strpos($functions, "api_plugin_user_realm_auth('audit_manage.php')") === false) {
	fwrite(STDERR, 'Audit administrators must be authorized to purge.' . PHP_EOL);
	exit(1);
}

if (strpos($functions, "api_plugin_user_realm_auth('audit_purge.php')") !== false) {
	fwrite(STDERR, 'The deprecated delegated purge permission must not authorize purge.' . PHP_EOL);
	exit(1);
}

if (substr_count($controller, 'audit_user_is_admin()') < 2) {
	fwrite(STDERR, 'Purge authorization must protect both the action and its UI control.' . PHP_EOL);
	exit(1);
}

if (substr_count($controller, 'csrf_check(false)') < 3) {
	fwrite(STDERR, 'Purge, Syslog test, and Syslog retry actions must each validate CSRF.' . PHP_EOL);
	exit(1);
}

if (strpos($functions, 'audit_enforce_syslog_settings_request()') === false ||
	strpos($functions, "'audit.syslog.configuration.denied'")        === false) {
	fwrite(STDERR, 'Remote Syslog settings must enforce Audit Log Admin on save.' . PHP_EOL);
	exit(1);
}

if (strpos($javascript, "loadPageNoHeader('audit.php?action=purge") !== false) {
	fwrite(STDERR, 'Purge must not use the legacy GET request path.' . PHP_EOL);
	exit(1);
}

if (strpos($javascript, "loadPageUsingPost('audit.php?action=purge") === false) {
	fwrite(STDERR, 'Purge must use the POST request path.' . PHP_EOL);
	exit(1);
}

if (strpos($javascript, "loadPageUsingPost('audit.php?action=syslog_test") === false ||
	strpos($javascript, "loadPageUsingPost('audit.php?action=syslog_retry")   === false) {
	fwrite(STDERR, 'Syslog administration actions must use POST request paths.' . PHP_EOL);
	exit(1);
}

print "Controller security checks passed.\n";
