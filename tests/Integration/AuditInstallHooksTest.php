<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Integration coverage for plugin_audit_install(): verifies every hook and
 * realm the plugin depends on at runtime are actually registered,
 * together with the tables and default settings it needs, in a single
 * end-to-end pass.
 *
 * audit_setup_table() include_once()s Cacti core's database.php via
 * $config['library_path'], so that is pointed at a throwaway empty stub
 * file for the duration of this test.
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/setup.php';

	$stubLibraryPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'audit-test-lib-stub';

	if (!is_dir($stubLibraryPath)) {
		mkdir($stubLibraryPath, 0777, true);
	}

	file_put_contents($stubLibraryPath . '/database.php', "<?php\n");

	$GLOBALS['config']['library_path'] = $stubLibraryPath;
});

beforeEach(function () {
	audit_test_reset_db_mocks();
	$GLOBALS['__test_registered_hooks']  = [];
	$GLOBALS['__test_registered_realms'] = [];
});

it('registers every hook audit depends on, its realms, provisions its tables, and persists auth defaults', function () {
	plugin_audit_install();

	$hooks = [];
	foreach ($GLOBALS['__test_registered_hooks'] as $registered) {
		$hooks[$registered['hook']] = $registered;
	}

	foreach (['config_arrays', 'config_settings', 'config_insert', 'poller_bottom', 'draw_navigation_text', 'utilities_array', 'is_console_page', 'logout_pre_session_destroy', 'logout_post_session_destroy', 'custom_denied', 'replicate_out'] as $expected) {
		expect($hooks)->toHaveKey($expected);
		expect($hooks[$expected]['name'])->toBe('audit');
	}

	$realms = array_column($GLOBALS['__test_registered_realms'], 'file');

	expect($realms)->toContain('audit.php');
	expect($realms)->toContain('audit_manage.php');

	$sql = implode("\n", array_column($GLOBALS['__test_db_calls'], 'sql'));

	expect($sql)->toContain('audit_log');
	expect($sql)->toContain('audit_syslog_delivery');
	expect($sql)->toContain('audit_user_log_state');

	expect($GLOBALS['__test_config_options']['audit_auth_log_enabled'])->toBe('off');
	expect($GLOBALS['__test_config_options']['audit_user_log_batch_size'])->toBe('1000');
});
