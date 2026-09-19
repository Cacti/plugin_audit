<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Behavioral coverage for plugin-owned user_log indexes: creation,
 * idempotent re-creation, ownership journaling, uninstall removal, and the
 * remote-collector/missing-table no-op guards in setup.php.
 */

require_once dirname(__DIR__, 2) . '/setup.php';

/**
 * Wire up the index-management stub environment shared by every test in
 * this file. Returns the mutable state array so a test can inspect and
 * seed it directly.
 *
 * @param bool  $tableExists  Whether user_log is reported as present.
 * @param array $dropFailures Index names whose DROP INDEX call should fail.
 *
 * @return array{indexes: array, operations: array}
 */
function &audit_index_test_environment(bool $tableExists = true, array $dropFailures = []): array {
	audit_test_reset_db_mocks();

	$state = [
		'indexes'    => [],
		'operations' => [],
	];

	audit_test_mock_db('db_table_exists', '', function ($table) use ($tableExists) {
		return $table === 'user_log' && $tableExists;
	});

	audit_test_mock_db('db_index_exists', '', function ($sql) use (&$state) {
		[$table, $index] = explode('|', $sql, 2);

		return $table === 'user_log' && isset($state['indexes'][$index]);
	});

	audit_test_mock_db('db_add_index', '', function ($sql) use (&$state) {
		[$table, $name, $columns] = explode('|', $sql, 3);

		$state['indexes'][$name] = explode(',', $columns);
		$state['operations'][]   = ['add', $table, $name, $state['indexes'][$name]];

		return true;
	});

	audit_test_mock_db('db_execute', '', function ($sql) use (&$state, $dropFailures) {
		if (preg_match('/DROP INDEX `([^`]+)`/', $sql, $matches) === 1) {
			$state['operations'][] = ['drop', 'user_log', $matches[1], []];

			if (in_array($matches[1], $dropFailures, true)) {
				return false;
			}

			unset($state['indexes'][$matches[1]]);
		}

		return true;
	});

	audit_test_mock_db('db_fetch_assoc_prepared', 'information_schema.STATISTICS', [
		['COLUMN_NAME' => 'username'],
		['COLUMN_NAME' => 'user_id'],
		['COLUMN_NAME' => 'time'],
	]);

	return $state;
}

it('creates both authentication indexes and reports them available', function () {
	$state = &audit_index_test_environment();

	audit_setup_user_log_indexes();

	expect($state['indexes']['plugin_audit_time'])->toBe(['time', 'username', 'user_id']);
	expect($state['indexes']['plugin_audit_result_time'])->toBe(['result', 'time']);
	expect($state['operations'])->toHaveCount(2);
	expect(audit_user_log_indexes_available())->toBeTrue();
	expect(audit_user_log_identity_supported())->toBeTrue();
});

it('does not rebuild indexes that already exist', function () {
	$state = &audit_index_test_environment();

	audit_setup_user_log_indexes();
	audit_setup_user_log_indexes();

	expect($state['operations'])->toHaveCount(2);
});

it('removes plugin-owned indexes during uninstall', function () {
	$state = &audit_index_test_environment();

	audit_setup_user_log_indexes();
	audit_remove_user_log_indexes();

	expect($state['indexes'])->toBe([]);
	expect($state['operations'])->toHaveCount(4);
	expect($GLOBALS['__test_config_options']['audit_user_log_indexes_owned'] ?? '')->toBe('');
});

it('preserves prior ownership while recording a recreated index on repair', function () {
	$state = &audit_index_test_environment();

	$state['indexes']['plugin_audit_time'] = ['time', 'username', 'user_id'];
	audit_test_set_config_option('audit_user_log_indexes_owned', 'plugin_audit_time');

	audit_setup_user_log_indexes();

	expect($GLOBALS['__test_config_options']['audit_user_log_indexes_owned'])->toBe('plugin_audit_time,plugin_audit_result_time');

	audit_remove_user_log_indexes();

	expect($state['indexes'])->toBe([]);
});

it('never claims or removes a pre-existing unowned index of the same name', function () {
	$state = &audit_index_test_environment();

	$state['indexes']['plugin_audit_time'] = ['time', 'username', 'user_id'];

	audit_setup_user_log_indexes();

	expect($GLOBALS['__test_config_options']['audit_user_log_indexes_owned'] ?? '')->toBe('plugin_audit_result_time');

	audit_remove_user_log_indexes();

	expect($state['indexes'])->toBe(['plugin_audit_time' => ['time', 'username', 'user_id']]);
});

it('never authorizes arbitrary index names via settings data', function () {
	$state = &audit_index_test_environment();

	$state['indexes'] = [
		'plugin_audit_time' => ['time', 'username', 'user_id'],
		'hostile_setting'   => ['unexpected'],
	];
	audit_test_set_config_option('audit_user_log_indexes_owned', 'plugin_audit_time,hostile_setting');

	audit_remove_user_log_indexes();

	expect($state['indexes'])->toBe(['hostile_setting' => ['unexpected']]);
});

it('fails closed and journals ownership when a core-table index removal fails', function () {
	$state = &audit_index_test_environment(true, ['plugin_audit_time']);

	$state['indexes'] = [
		'plugin_audit_time'        => ['time', 'username', 'user_id'],
		'plugin_audit_result_time' => ['result', 'time'],
	];
	audit_test_set_config_option('audit_user_log_indexes_owned', 'plugin_audit_time,plugin_audit_result_time');

	$result = audit_remove_user_log_indexes();

	expect($result)->toBeFalse();
	expect($state['indexes'])->toBe(['plugin_audit_time' => ['time', 'username', 'user_id']]);
	expect($GLOBALS['__test_config_options']['audit_user_log_indexes_owned'])->toBe('plugin_audit_time');

	$foundInLog = false;

	foreach ($GLOBALS['__test_logs'] as $message) {
		if (str_contains($message, 'plugin_audit_time')) {
			$foundInLog = true;
			break;
		}
	}

	expect($foundInLog)->toBeTrue();
});

it('never creates or removes indexes for remote collectors', function () {
	$state = &audit_index_test_environment();

	audit_setup_user_log_indexes('remote');
	audit_remove_user_log_indexes('remote');

	expect($state['operations'])->toBe([]);
	expect(audit_user_log_indexes_available('remote'))->toBeFalse();
});

it('is a no-op when user_log is missing', function () {
	$state = &audit_index_test_environment(false);

	audit_setup_user_log_indexes();
	audit_remove_user_log_indexes();

	expect($state['operations'])->toBe([]);
});
