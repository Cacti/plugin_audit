<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for audit_check_upgrade()'s version-drift path in setup.php,
 * including the upgrade-time manifest prune (plugin_audit_prune_files()).
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/setup.php';

	$stub = sys_get_temp_dir() . '/audit-lib-stub';

	if (!is_dir($stub)) {
		mkdir($stub, 0777, true);
	}

	file_put_contents($stub . '/database.php', "<?php\n");
	file_put_contents($stub . '/functions.php', "<?php\n");
	$GLOBALS['__audit_lib_stub'] = $stub;
});

beforeEach(function () {
	audit_test_reset_db_mocks();
	$GLOBALS['__test_db_calls']        = array();
	$GLOBALS['__test_cacti_log']       = array();
	$GLOBALS['config']['library_path'] = $GLOBALS['__audit_lib_stub'];
});

it('runs the schema upgrade and prune on a version drift', function () {
	$oldSelf             = $_SERVER['PHP_SELF'] ?? null;
	$_SERVER['PHP_SELF'] = '/plugins.php';

	// Sandbox base_path so plugin_audit_version() reads a temp INFO and the
	// upgrade-time prune runs against a throwaway tree, never the real checkout.
	$restore = $GLOBALS['config']['base_path'];
	$base    = sys_get_temp_dir() . '/audit-upg-' . uniqid();
	mkdir($base . '/plugins/audit', 0777, true);
	file_put_contents($base . '/plugins/audit/INFO', "[info]\nversion = 9.9.9\nname = audit\nlongname = Audit\nauthor = x\nhomepage = x\n");
	$GLOBALS['config']['base_path'] = $base;

	try {
		audit_check_upgrade();
	} finally {
		$GLOBALS['config']['base_path'] = $restore;

		if ($oldSelf === null) {
			unset($_SERVER['PHP_SELF']);
		} else {
			$_SERVER['PHP_SELF'] = $oldSelf;
		}
	}

	$updates = array_values(array_filter($GLOBALS['__test_db_calls'], function ($call) {
		return ($call['fn'] ?? '') === 'db_execute_prepared' && stripos($call['sql'] ?? '', 'UPDATE plugin_config') !== false;
	}));

	expect($updates)->not->toBeEmpty();
});
