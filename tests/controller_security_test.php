<?php

$controller = file_get_contents(dirname(__DIR__) . '/audit.php') ?: '';
$functions  = file_get_contents(dirname(__DIR__) . '/audit_functions.php') ?: '';
$javascript = file_get_contents(dirname(__DIR__) . '/js/functions.js') ?: '';
$setup      = file_get_contents(dirname(__DIR__) . '/setup.php') ?: '';
$info       = parse_ini_file(dirname(__DIR__) . '/INFO', true);
$changelog  = file_get_contents(dirname(__DIR__) . '/CHANGELOG.md') ?: '';

if (($info['info']['version'] ?? null) !== '1.6' || !str_contains($changelog, '--- 1.6 ---')) {
	fwrite(STDERR, 'Authentication auditing must ship through the 1.6 upgrade path.' . PHP_EOL);
	exit(1);
}

if (preg_match('/function plugin_audit_install\(\): void \{(?<body>.*?)\n\}/s', $setup, $install_match) !== 1 ||
	str_contains($install_match['body'], 'audit_setup_user_log_indexes()')) {
	fwrite(STDERR, 'Fresh installation must not index core user_log while authentication auditing is disabled.' . PHP_EOL);
	exit(1);
}

if (preg_match('/function audit_check_upgrade\(\): void \{(?<body>.*?)\n\}/s', $setup, $upgrade_match) !== 1) {
	fwrite(STDERR, 'Unable to inspect the plugin upgrade path.' . PHP_EOL);
	exit(1);
}

foreach (['audit_setup_user_log_state_table()', 'audit_persist_auth_defaults()', "'logout_post_session_destroy'", "'custom_denied'"] as $upgrade_requirement) {
	if (!str_contains($upgrade_match['body'], $upgrade_requirement)) {
		fwrite(STDERR, 'Missing 1.6 upgrade requirement: ' . $upgrade_requirement . PHP_EOL);
		exit(1);
	}
}

if (preg_match('/function audit_config_settings\(\): void \{(?<body>.*?)\n\}/s', $setup, $settings_match) !== 1 ||
	strpos($settings_match['body'], "'audit_enabled'") < strpos($settings_match['body'], 'audit_user_is_admin()')) {
	fwrite(STDERR, 'Master and external audit controls must only be exposed to Audit Log Admin.' . PHP_EOL);
	exit(1);
}

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
	"!\$enabled ? __('Disabled', 'audit')",
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
	'ON DUPLICATE KEY UPDATE value = GREATEST'
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
