<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for audit_utilities_array() in setup.php.
 *
 * The CI matrix runs against a Cacti build without the 1.3-only
 * CactiTableFilter class, so these tests exercise the legacy Utilities
 * hook body: the section-preserving merge and the realm-authorization
 * gate. Realm access is driven through the same api_plugin_user_realm_auth()
 * stub used by the security suite (controllable via $__audit_test_realms);
 * the guard below keeps this file runnable on its own.
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/setup.php';
});

if (!function_exists('api_plugin_user_realm_auth')) {
	function api_plugin_user_realm_auth(string $filename = ''): bool {
		return !empty($GLOBALS['__audit_test_realms'][$filename]);
	}
}

beforeEach(function () {
	$GLOBALS['__audit_test_realms'] = [];
	$GLOBALS['utilities']           = [];
});

it('adds the Audit Log entry when the Technical Support section is absent', function () {
	$GLOBALS['__audit_test_realms']['audit.php'] = true;

	audit_utilities_array();

	$section = __('Technical Support', 'audit');

	expect($GLOBALS['utilities'])->toHaveKey($section);
	expect($GLOBALS['utilities'][$section])->toHaveKey(__('View Audit Log', 'audit'));
	expect($GLOBALS['utilities'][$section][__('View Audit Log', 'audit')]['link'])
		->toBe('plugins/audit/audit.php');
});

it('preserves existing Technical Support entries when access is granted', function () {
	$GLOBALS['__audit_test_realms']['audit.php'] = true;

	$section  = __('Technical Support', 'audit');
	$existing = __('Existing Entry', 'audit');

	$GLOBALS['utilities'][$section] = [
		$existing => ['link' => 'plugins/other/other.php'],
	];

	audit_utilities_array();

	expect($GLOBALS['utilities'][$section])->toHaveKey($existing);
	expect($GLOBALS['utilities'][$section][$existing]['link'])->toBe('plugins/other/other.php');
	expect($GLOBALS['utilities'][$section])->toHaveKey(__('View Audit Log', 'audit'));
});

it('adds nothing when the user lacks audit.php realm access', function () {
	$section = __('Technical Support', 'audit');

	$GLOBALS['utilities'][$section] = [];

	audit_utilities_array();

	expect($GLOBALS['utilities'][$section])->toBe([]);
	expect($GLOBALS['utilities'][$section])->not->toHaveKey(__('View Audit Log', 'audit'));
});
