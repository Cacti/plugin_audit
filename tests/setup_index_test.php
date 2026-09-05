<?php

// Behavioral coverage for plugin-owned user_log indexes.

$audit_index_table_exists  = true;
$audit_indexes             = [];
$audit_index_operations    = [];
$audit_index_settings      = [];
$audit_index_drop_failures = [];
$audit_index_logs          = [];
$audit_identity_connection = null;

function set_config_option(string $name, string $value): void {
	global $audit_index_settings;

	$audit_index_settings[$name] = $value;
}

function read_config_option(string $name, bool $force = false): string {
	global $audit_index_settings;

	return $audit_index_settings[$name] ?? '';
}

function db_table_exists(string $table, bool $log = true, mixed $db_conn = false): bool {
	global $audit_index_table_exists;

	return $table === 'user_log' && $audit_index_table_exists;
}

function db_index_exists(string $table, string $index, bool $log = true, mixed $db_conn = false): bool {
	global $audit_indexes;

	return $table === 'user_log' && isset($audit_indexes[$index]);
}

function db_add_index(string $table, string $type, string $key, array $columns, bool $log = true, mixed $db_conn = false): bool {
	global $audit_indexes, $audit_index_operations;
	$audit_indexes[$key]      = $columns;
	$audit_index_operations[] = ['add', $table, $key, $columns, $db_conn];

	return true;
}

function db_execute(string $sql, bool $log = true, mixed $db_conn = false): bool {
	global $audit_indexes, $audit_index_operations, $audit_index_drop_failures;

	if (preg_match('/DROP INDEX `([^`]+)`/', $sql, $matches) === 1) {
		$audit_index_operations[] = ['drop', 'user_log', $matches[1], [], $db_conn];

		if (in_array($matches[1], $audit_index_drop_failures, true)) {
			return false;
		}

		unset($audit_indexes[$matches[1]]);
	}

	return true;
}

function db_fetch_assoc_prepared(string $sql, array $params = [], bool $log = true, mixed $db_conn = false): array {
	global $audit_identity_connection;
	$audit_identity_connection = $db_conn;

	return [
		['COLUMN_NAME' => 'username'],
		['COLUMN_NAME' => 'user_id'],
		['COLUMN_NAME' => 'time']
	];
}

function cacti_log(string $message, bool $also_print = false, string $log_type = '', int $level = 0): void {
	global $audit_index_logs;
	$audit_index_logs[] = $message;
}

require_once dirname(__DIR__) . '/setup.php';

function audit_index_assert_same(mixed $expected, mixed $actual, string $message): void {
	if ($expected !== $actual) {
		fwrite(STDERR, $message . PHP_EOL);
		fwrite(STDERR, 'Expected: ' . var_export($expected, true) . PHP_EOL);
		fwrite(STDERR, 'Actual:   ' . var_export($actual, true) . PHP_EOL);
		exit(1);
	}
}

/**
 * @return array<int,string>|null
 */
function audit_index_columns(string $index): ?array {
	global $audit_indexes;

	return isset($audit_indexes[$index]) ? $audit_indexes[$index] : null;
}

function audit_index_log_contains(string $needle): bool {
	global $audit_index_logs;

	foreach ($audit_index_logs as $message) {
		if (str_contains($message, $needle)) {
			return true;
		}
	}

	return false;
}

audit_setup_user_log_indexes();
audit_index_assert_same(['time', 'username', 'user_id'], audit_index_columns('plugin_audit_time'), 'The ingestion index must lead with time.');
audit_index_assert_same(['result', 'time'], audit_index_columns('plugin_audit_result_time'), 'The failed-login index must cover result and time.');
audit_index_assert_same(2, count($audit_index_operations), 'Both indexes must be added exactly once.');
audit_index_assert_same(true, audit_user_log_indexes_available(), 'Both confirmed local indexes must report available.');
audit_index_assert_same(true, audit_user_log_identity_supported('identity-connection'), 'The real prepared-query signature must accept the identity query.');
audit_index_assert_same('identity-connection', $audit_identity_connection, 'The identity query must pass the database connection in the fourth argument.');

audit_setup_user_log_indexes();
audit_index_assert_same(2, count($audit_index_operations), 'Existing indexes must not be rebuilt.');

audit_remove_user_log_indexes();
audit_index_assert_same([], $audit_indexes, 'Plugin-owned indexes must be removed during uninstall.');
audit_index_assert_same(4, count($audit_index_operations), 'Both indexes must be removed exactly once.');
audit_index_assert_same('', read_config_option('audit_user_log_indexes_owned'), 'Disabling the feature must clear stale index ownership.');

$audit_indexes = [
	'plugin_audit_time' => ['time', 'username', 'user_id']
];
$audit_index_settings = [
	'audit_user_log_indexes_owned' => 'plugin_audit_time'
];
$audit_index_operations = [];
audit_setup_user_log_indexes();
audit_index_assert_same('plugin_audit_time,plugin_audit_result_time', $audit_index_settings['audit_user_log_indexes_owned'], 'A repair run must preserve prior ownership while recording a recreated index.');
audit_remove_user_log_indexes();
audit_index_assert_same([], $audit_indexes, 'Uninstall must remove every index accumulated in the ownership record.');

$audit_indexes          = ['plugin_audit_time' => ['time', 'username', 'user_id']];
$audit_index_settings   = [];
$audit_index_operations = [];
audit_setup_user_log_indexes();
audit_index_assert_same('plugin_audit_result_time', read_config_option('audit_user_log_indexes_owned'), 'A pre-existing index with the same name must not become plugin-owned.');
audit_remove_user_log_indexes();
audit_index_assert_same(['plugin_audit_time' => ['time', 'username', 'user_id']], $audit_indexes, 'An unowned pre-existing index must never be removed.');

$audit_indexes = [
	'plugin_audit_time' => ['time', 'username', 'user_id'],
	'hostile_setting'   => ['unexpected']
];
$audit_index_settings = [
	'audit_user_log_indexes_owned' => 'plugin_audit_time,hostile_setting'
];
$audit_index_operations = [];
audit_remove_user_log_indexes();
audit_index_assert_same(['hostile_setting' => ['unexpected']], $audit_indexes, 'Settings data must not authorize arbitrary index names in DDL.');

$audit_indexes = [
	'plugin_audit_time'        => ['time', 'username', 'user_id'],
	'plugin_audit_result_time' => ['result', 'time']
];
$audit_index_settings = [
	'audit_user_log_indexes_owned' => 'plugin_audit_time,plugin_audit_result_time'
];
$audit_index_drop_failures = ['plugin_audit_time'];
$audit_index_logs          = [];
audit_index_assert_same(false, audit_remove_user_log_indexes(), 'A failed core-table index removal must fail closed.');
audit_index_assert_same(['plugin_audit_time' => ['time', 'username', 'user_id']], $audit_indexes, 'A failed index removal must leave the index intact.');
audit_index_assert_same('plugin_audit_time', read_config_option('audit_user_log_indexes_owned'), 'Failed index ownership must remain journaled.');
audit_index_assert_same(true, audit_index_log_contains('plugin_audit_time'), 'The removal failure must name the orphaned index in the operator log.');
$audit_index_drop_failures = [];

$audit_index_operations = [];
audit_setup_user_log_indexes('remote');
audit_remove_user_log_indexes('remote');
audit_index_assert_same([], $audit_index_operations, 'Remote collector indexes must not be created or removed.');
audit_index_assert_same(false, audit_user_log_indexes_available('remote'), 'Remote collectors must never report local ingestion indexes available.');

$audit_index_table_exists = false;
audit_setup_user_log_indexes();
audit_remove_user_log_indexes();
audit_index_assert_same([], $audit_index_operations, 'Missing user_log must be a no-op.');

print "Setup index tests passed.\n";
