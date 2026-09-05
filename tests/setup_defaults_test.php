<?php

// Behavioral checks for safe authentication-audit install/upgrade defaults.

$audit_default_settings = [
	'audit_auth_log_enabled' => 'on'
];

function db_fetch_cell_prepared(string $sql, array $params = []): int {
	global $audit_default_settings;

	return array_key_exists((string) ($params[0] ?? ''), $audit_default_settings) ? 1 : 0;
}

function set_config_option(string $name, string $value): void {
	global $audit_default_settings;

	$audit_default_settings[$name] = $value;
}

function audit_default_setting(string $name): string {
	global $audit_default_settings;

	return (string) ($audit_default_settings[$name] ?? '');
}

require_once dirname(__DIR__) . '/setup.php';

function audit_default_assert_same(mixed $expected, mixed $actual, string $message): void {
	if ($expected !== $actual) {
		fwrite(STDERR, $message . PHP_EOL);
		fwrite(STDERR, 'Expected: ' . var_export($expected, true) . PHP_EOL);
		fwrite(STDERR, 'Actual:   ' . var_export($actual, true) . PHP_EOL);
		exit(1);
	}
}

$before = time();
audit_persist_auth_defaults();
$after = time();

audit_default_assert_same('on', audit_default_setting('audit_auth_log_enabled'), 'An existing administrator choice must not be overwritten.');
audit_default_assert_same('off', audit_default_setting('audit_brute_force_enabled'), 'Failed-login volume detection must be opt-in.');

$watermark = (int) audit_default_setting('audit_user_log_watermark_epoch');

if ($watermark < $before || $watermark > $after) {
	fwrite(STDERR, 'A new install or upgrade must start authentication ingestion at the current time.' . PHP_EOL);
	exit(1);
}

$seeded = set_config_option('audit_user_log_watermark_epoch', '12345');
audit_persist_auth_defaults();
audit_default_assert_same('12345', audit_default_setting('audit_user_log_watermark_epoch'), 'A persisted ingestion watermark must survive upgrades.');

$owned_settings = audit_owned_setting_names();
audit_default_assert_same(count($owned_settings), count(array_unique($owned_settings)), 'Owned setting names must be unique.');

foreach (['audit_enabled', 'audit_auth_log_enabled', 'audit_syslog_health_state'] as $owned_setting) {
	if (!in_array($owned_setting, $owned_settings, true)) {
		fwrite(STDERR, 'Missing plugin-owned setting: ' . $owned_setting . PHP_EOL);
		exit(1);
	}
}

if (in_array('audit_unrelated_extension_setting', $owned_settings, true)) {
	fwrite(STDERR, 'Uninstall must not claim settings owned by another extension.' . PHP_EOL);
	exit(1);
}

print "Setup default tests passed.\n";
