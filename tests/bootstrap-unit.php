<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*
 * Test bootstrap.
 *
 * Audit's sources expect to be included by Cacti, which has already
 * defined the db_*, request-variable, and logging helpers as plain global
 * functions. Nothing here talks to a database or a network: each Cacti
 * function is declared as a stub that records the call in
 * $GLOBALS['__test_db_calls'] and hands back either a queued fixture (see
 * audit_test_mock_db() below) or a safe default.
 *
 * The CI workflow checks out a pinned Cacti release next to this plugin so
 * Pest runs against Cacti's own Composer-managed vendor tree (Pest/PHPUnit)
 * instead of a vendor tree local to this plugin. The version check below
 * makes sure that checkout actually matches what tests/.cacti-version
 * expects before any plugin source is loaded.
 *
 * Guarding every declaration with function_exists() keeps this file usable
 * if a future integration suite loads real Cacti first.
 */

$cacti_root = dirname(__DIR__, 3);
$autoload   = $cacti_root . '/include/vendor/autoload.php';
$version    = $cacti_root . '/include/cacti_version';
$expected   = __DIR__ . '/.cacti-version';

if (!is_readable($autoload)) {
	throw new RuntimeException("Cacti Composer autoloader is not readable: $autoload");
}

if (!is_readable($version)) {
	throw new RuntimeException("Cacti version file is not readable: $version");
}

if (!is_readable($expected)) {
	throw new RuntimeException("Expected Cacti version file is not readable: $expected");
}

$cacti_version     = trim((string) file_get_contents($version));
$expected_version  = trim((string) file_get_contents($expected));

if ($cacti_version === '') {
	throw new RuntimeException("Cacti version file is empty: $version");
}

if ($expected_version === '') {
	throw new RuntimeException("Expected Cacti version file is empty: $expected");
}

// The CI workflow tracks a moving branch (1.2.x or develop) rather than a pinned release, so any actual version is accepted.
if (!in_array($expected_version, ['1.2.x', 'develop'], true) && $cacti_version !== $expected_version) {
	throw new RuntimeException("Expected Cacti $expected_version, found $cacti_version in $version");
}

require_once $autoload;

/*
 * base_path has to point at the Cacti root two levels above this plugin:
 * audit's source files build include paths from it at runtime.
 */
$GLOBALS['config'] = [
	'base_path'       => $cacti_root,
	'url_path'        => '/cacti/',
	'cacti_version'   => $cacti_version,
	'cacti_server_os' => 'unix',
];

$GLOBALS['__test_db_calls']    = [];
$GLOBALS['__test_db_fixtures'] = [];

/**
 * Queues a canned return value for the next matching call to a stubbed
 * db_* function, so a test can control exactly what a plugin function
 * reads back without redeclaring the global db_* stub itself.
 *
 * @param string          $fn     Stubbed function name, e.g. 'db_fetch_row_prepared'.
 * @param string|callable $match  Substring the SQL must contain, or a callable(string $sql, array $params): bool.
 * @param mixed           $result Value to hand back when matched.
 *
 * @return void
 */
function audit_test_mock_db($fn, $match, $result) {
	$GLOBALS['__test_db_fixtures'][$fn][] = ['match' => $match, 'result' => $result];
}

/**
 * Clears queued db_* fixtures, the call log, and stubbed config options.
 * Safe to call between tests.
 *
 * @return void
 */
function audit_test_reset_db_mocks() {
	$GLOBALS['__test_db_fixtures']       = [];
	$GLOBALS['__test_db_calls']          = [];
	$GLOBALS['__test_config_options']    = [];
	$GLOBALS['__test_db_affected_rows']  = 0;
	$GLOBALS['__test_logs']              = [];
}

/**
 * Records a stubbed db_* call and resolves it against any queued fixtures.
 * Most-recently-registered fixture wins, so a test can override an earlier
 * default without it winning by being checked first.
 *
 * @param string $fn      Stubbed function name.
 * @param string $sql     SQL text passed to the stub.
 * @param array  $params  Bind parameters passed to the stub (empty for non-prepared calls).
 * @param mixed  $default Value to return when no fixture matches.
 *
 * @return mixed
 * A fixture's result may itself be a callable(string $sql, array $params),
 * for cases where the return value depends on mutable test state rather
 * than a fixed value decided at registration time; it is invoked to
 * produce the actual return value.
 */
function audit_test_db_result($fn, $sql, $params, $default) {
	$GLOBALS['__test_db_calls'][] = ['fn' => $fn, 'sql' => $sql, 'params' => $params];

	if (!empty($GLOBALS['__test_db_fixtures'][$fn])) {
		foreach (array_reverse($GLOBALS['__test_db_fixtures'][$fn]) as $fixture) {
			$matched = is_callable($fixture['match'])
				? $fixture['match']($sql, $params)
				: (strpos($sql, $fixture['match']) !== false);

			if ($matched) {
				return is_callable($fixture['result']) ? $fixture['result']($sql, $params) : $fixture['result'];
			}
		}
	}

	return $default;
}

if (!function_exists('db_execute')) {
	/**
	 * @param string $sql
	 *
	 * @return bool
	 */
	function db_execute($sql) {
		return audit_test_db_result('db_execute', $sql, [], true);
	}
}

if (!function_exists('db_execute_prepared')) {
	/**
	 * @param string $sql
	 * @param array  $params
	 *
	 * @return bool
	 */
	function db_execute_prepared($sql, $params = []) {
		return audit_test_db_result('db_execute_prepared', $sql, $params, true);
	}
}

if (!function_exists('db_fetch_assoc')) {
	/**
	 * @param string $sql
	 *
	 * @return array
	 */
	function db_fetch_assoc($sql) {
		return audit_test_db_result('db_fetch_assoc', $sql, [], []);
	}
}

if (!function_exists('db_fetch_assoc_prepared')) {
	/**
	 * @param string $sql
	 * @param array  $params
	 *
	 * @return array
	 */
	function db_fetch_assoc_prepared($sql, $params = []) {
		return audit_test_db_result('db_fetch_assoc_prepared', $sql, $params, []);
	}
}

if (!function_exists('db_fetch_row')) {
	/**
	 * @param string $sql
	 *
	 * @return array
	 */
	function db_fetch_row($sql) {
		return audit_test_db_result('db_fetch_row', $sql, [], []);
	}
}

if (!function_exists('db_fetch_row_prepared')) {
	/**
	 * @param string $sql
	 * @param array  $params
	 *
	 * @return array
	 */
	function db_fetch_row_prepared($sql, $params = []) {
		return audit_test_db_result('db_fetch_row_prepared', $sql, $params, []);
	}
}

if (!function_exists('db_fetch_cell')) {
	/**
	 * @param string $sql
	 *
	 * @return mixed
	 */
	function db_fetch_cell($sql) {
		// GET_LOCK() defaults to "acquired" so tests exercising the
		// off->on activation transition don't all need to stub it
		// individually; a test can still override with
		// audit_test_mock_db('db_fetch_cell', 'GET_LOCK', 0) to simulate
		// lock contention.
		$default = (stripos($sql, 'GET_LOCK') !== false) ? 1 : '';

		return audit_test_db_result('db_fetch_cell', $sql, [], $default);
	}
}

if (!function_exists('db_fetch_cell_prepared')) {
	/**
	 * @param string $sql
	 * @param array  $params
	 *
	 * @return mixed
	 */
	function db_fetch_cell_prepared($sql, $params = []) {
		return audit_test_db_result('db_fetch_cell_prepared', $sql, $params, '');
	}
}

if (!function_exists('db_index_exists')) {
	/**
	 * @param string $table
	 * @param string $index
	 * @param bool   $type
	 * @param mixed  $cnn_id
	 *
	 * @return bool
	 */
	function db_index_exists($table, $index, $type = false, $cnn_id = false) {
		return audit_test_db_result('db_index_exists', $table . '|' . $index, [], false);
	}
}

if (!function_exists('db_add_index')) {
	/**
	 * @param string $table
	 * @param string $type
	 * @param string $name
	 * @param array  $columns
	 * @param bool   $unique
	 * @param mixed  $cnn_id
	 *
	 * @return bool
	 */
	function db_add_index($table, $type, $name, $columns, $unique = false, $cnn_id = false) {
		return audit_test_db_result('db_add_index', $table . '|' . $name . '|' . implode(',', (array) $columns), [], true);
	}
}

if (!function_exists('db_column_exists')) {
	/**
	 * @param string $table
	 * @param string $column
	 *
	 * @return bool
	 */
	function db_column_exists($table, $column) {
		return false;
	}
}

if (!function_exists('db_table_exists')) {
	/**
	 * @param string $table
	 *
	 * @return bool
	 */
	function db_table_exists($table) {
		return audit_test_db_result('db_table_exists', (string) $table, [], true);
	}
}

if (!function_exists('db_affected_rows')) {
	/**
	 * @return int
	 */
	function db_affected_rows() {
		return $GLOBALS['__test_db_affected_rows'] ?? 0;
	}
}

if (!function_exists('db_fetch_insert_id')) {
	/**
	 * @return int
	 */
	function db_fetch_insert_id() {
		return audit_test_db_result('db_fetch_insert_id', '', [], 0);
	}
}

/**
 * Sets the value the next db_affected_rows() call should return.
 *
 * @param int $rows Affected row count to report.
 *
 * @return void
 */
function audit_test_set_affected_rows($rows) {
	$GLOBALS['__test_db_affected_rows'] = $rows;
}

if (!function_exists('api_plugin_db_add_column')) {
	/**
	 * @param string $plugin
	 * @param string $table
	 * @param array  $data
	 *
	 * @return bool
	 */
	function api_plugin_db_add_column($plugin, $table, $data) {
		return true;
	}
}

if (!function_exists('api_plugin_db_table_create')) {
	/**
	 * @param string $plugin
	 * @param string $table
	 * @param array  $data
	 *
	 * @return bool
	 */
	function api_plugin_db_table_create($plugin, $table, $data) {
		return true;
	}
}

$GLOBALS['__test_registered_hooks'] = [];

if (!function_exists('api_plugin_register_hook')) {
	function api_plugin_register_hook($plugin, $hook, $function, $file, $subtype = '') {
		$GLOBALS['__test_registered_hooks'][] = [
			'name'     => $plugin,
			'hook'     => $hook,
			'function' => $function,
			'file'     => $file,
		];

		return true;
	}
}

$GLOBALS['__test_registered_realms'] = [];

if (!function_exists('api_plugin_register_realm')) {
	function api_plugin_register_realm($plugin, $file, $description, $enabled) {
		$GLOBALS['__test_registered_realms'][] = [
			'name'        => $plugin,
			'file'        => $file,
			'description' => $description,
			'enabled'     => $enabled,
		];

		return true;
	}
}

if (!function_exists('api_plugin_replicate_config')) {
	function api_plugin_replicate_config() {
		return true;
	}
}

$GLOBALS['__test_config_options'] = [];

/**
 * Sets a canned value for the next read_config_option() call with this name.
 *
 * @param string $name  Config option name.
 * @param mixed  $value Value read_config_option() should return for that name.
 *
 * @return void
 */
function audit_test_set_config_option($name, $value) {
	$GLOBALS['__test_config_options'][$name] = $value;
}

if (!function_exists('read_config_option')) {
	/**
	 * @param string $name
	 * @param bool   $force
	 *
	 * @return mixed
	 */
	function read_config_option($name, $force = false) {
		return $GLOBALS['__test_config_options'][$name] ?? '';
	}
}

if (!function_exists('set_config_option')) {
	/**
	 * @param string $name
	 * @param mixed  $value
	 *
	 * @return void
	 */
	function set_config_option($name, $value) {
		$GLOBALS['__test_config_options'][$name] = $value;
	}
}

if (!function_exists('html_escape')) {
	/**
	 * @param string $string
	 *
	 * @return string
	 */
	function html_escape($string) {
		return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
	}
}

if (!function_exists('__')) {
	// Mirrors Cacti's variadic __(): trailing args are sprintf substitutions,
	// with an optional domain in the final position that sprintf just ignores.
	/**
	 * @param mixed ...$args
	 *
	 * @return string
	 */
	function __(...$args) {
		return vsprintf((string) $args[0], array_slice($args, 1));
	}
}

if (!function_exists('__esc')) {
	/**
	 * @param string $text
	 * @param string $domain
	 *
	 * @return string
	 */
	function __esc($text, $domain = '') {
		return htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
	}
}

$GLOBALS['__test_logs'] = [];

if (!function_exists('cacti_log')) {
	/**
	 * @param string $message
	 * @param bool   $also_print
	 * @param string $log_type
	 * @param int    $level
	 *
	 * @return void
	 */
	function cacti_log($message, $also_print = false, $log_type = '', $level = 0) {
		$GLOBALS['__test_logs'][] = $message;
	}
}

if (!function_exists('cacti_sizeof')) {
	/**
	 * @param mixed $array
	 *
	 * @return int
	 */
	function cacti_sizeof($array) {
		return is_array($array) ? count($array) : 0;
	}
}

if (!function_exists('is_realm_allowed')) {
	/**
	 * @param string $realm
	 *
	 * @return bool
	 */
	function is_realm_allowed($realm) {
		return true;
	}
}

if (!function_exists('raise_message')) {
	/**
	 * @param string $id
	 * @param string $text
	 * @param int    $level
	 *
	 * @return void
	 */
	function raise_message($id, $text = '', $level = 0) {
	}
}

$GLOBALS['__test_request'] = [];

/**
 * Seeds the fake $_REQUEST-backed store read by get_request_var() et al.
 *
 * @param array $vars Request variables to seed.
 *
 * @return void
 */
function audit_test_set_request(array $vars) {
	$GLOBALS['__test_request'] = $vars;
}

if (!function_exists('get_request_var')) {
	/**
	 * @param string $name
	 *
	 * @return mixed
	 */
	function get_request_var($name) {
		return $GLOBALS['__test_request'][$name] ?? '';
	}
}

if (!function_exists('isset_request_var')) {
	function isset_request_var($name) {
		return isset($GLOBALS['__test_request'][$name]);
	}
}

if (!function_exists('get_nfilter_request_var')) {
	/**
	 * @param string $name
	 *
	 * @return mixed
	 */
	function get_nfilter_request_var($name) {
		return $GLOBALS['__test_request'][$name] ?? '';
	}
}

if (!function_exists('get_filter_request_var')) {
	/**
	 * @param string $name
	 *
	 * @return mixed
	 */
	function get_filter_request_var($name) {
		return $GLOBALS['__test_request'][$name] ?? '';
	}
}

if (!function_exists('form_input_validate')) {
	/**
	 * @param mixed  $value
	 * @param string $name
	 * @param string $regex
	 * @param bool   $optional
	 * @param string $error
	 *
	 * @return mixed
	 */
	function form_input_validate($value, $name, $regex, $optional, $error) {
		return $value;
	}
}

if (!function_exists('is_error_message')) {
	/**
	 * @return bool
	 */
	function is_error_message() {
		return false;
	}
}

if (!function_exists('sql_save')) {
	/**
	 * @param array  $array
	 * @param string $table
	 * @param string $key
	 *
	 * @return mixed
	 */
	function sql_save($array, $table, $key = 'id') {
		return isset($array['id']) ? $array['id'] : 1;
	}
}

if (!defined('CACTI_PATH_BASE')) {
	define('CACTI_PATH_BASE', $GLOBALS['config']['base_path']);
}

if (!defined('POLLER_ID')) {
	define('POLLER_ID', 1);
}

if (!defined('POLLER_VERBOSITY_LOW')) {
	define('POLLER_VERBOSITY_LOW', 2);
}

if (!defined('POLLER_VERBOSITY_MEDIUM')) {
	define('POLLER_VERBOSITY_MEDIUM', 3);
}

if (!defined('POLLER_VERBOSITY_DEBUG')) {
	define('POLLER_VERBOSITY_DEBUG', 5);
}

if (!defined('POLLER_VERBOSITY_NONE')) {
	define('POLLER_VERBOSITY_NONE', 6);
}

if (!defined('MESSAGE_LEVEL_ERROR')) {
	define('MESSAGE_LEVEL_ERROR', 1);
}

if (!function_exists('plugin_test_read_source')) {
	/**
	 * @param string $relative_file
	 *
	 * @return string
	 */
	function plugin_test_read_source($relative_file) {
		$path = realpath(__DIR__ . '/../' . $relative_file);

		if ($path === false) {
			throw new RuntimeException("Unable to resolve required file: {$relative_file}");
		}

		$contents = file_get_contents($path);

		if ($contents === false) {
			throw new RuntimeException("Unable to read required file: {$relative_file}");
		}

		return $contents;
	}
}

/**
 * Load a plugin source file at global scope.
 *
 * Some plugin files define data as file-scope variables that the rest of
 * the plugin reads as globals, and they read $config while doing so.
 * Requiring them from inside a method would make both halves of that
 * method-local, so the require happens here and any variable the file
 * introduced is published to $GLOBALS.
 *
 * @param string $path Absolute path to the file.
 *
 * @return void
 */
function audit_test_load($path) {
	global $config;

	$__before = get_defined_vars();

	require_once $path;

	foreach (get_defined_vars() as $__name => $__value) {
		if (!array_key_exists($__name, $__before) && strncmp($__name, '__', 2) !== 0) {
			$GLOBALS[$__name] = $__value;
		}
	}
}
