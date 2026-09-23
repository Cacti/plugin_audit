<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for audit_log_valid_event() in setup.php - decides whether
 * the current request should be recorded in the audit log.
 *
 * The POST-detection branch reads filter_input_array(INPUT_POST, ...),
 * which always returns NULL under the CLI SAPI regardless of $_POST, so
 * only its false path is reachable here; the other branches (checked via
 * $_SERVER['SCRIPT_NAME'] and request vars) are fully testable.
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/setup.php';
});

beforeEach(function () {
	audit_test_set_request([]);
	audit_test_set_config_option('audit_enabled', 'on');
	$_SERVER['SCRIPT_NAME']    = '/some_page.php';
	$_SERVER['REQUEST_METHOD'] = 'GET';
});

it('is never valid when the plugin is disabled', function () {
	audit_test_set_config_option('audit_enabled', '');

	expect(audit_log_valid_event())->toBeFalse();
});

it('is not valid on graph_view.php', function () {
	$_SERVER['SCRIPT_NAME'] = '/graph_view.php';

	expect(audit_log_valid_event())->toBeFalse();
});

it('is not valid on a checkpass request to user_admin.php', function () {
	$_SERVER['SCRIPT_NAME'] = '/user_admin.php';
	audit_test_set_request(['action' => 'checkpass']);

	expect(audit_log_valid_event())->toBeFalse();
});

it('is valid on plugins.php when a mode is present, and records the mode as the action', function () {
	global $action;

	$_SERVER['SCRIPT_NAME'] = '/plugins.php';
	audit_test_set_request(['mode' => 'enable']);

	expect(audit_log_valid_event())->toBeTrue();
	expect($action)->toBe('enable');
});

it('is not valid on auth_profile.php, index.php, or auth_changepassword.php', function () {
	foreach (['/auth_profile.php', '/index.php', '/auth_changepassword.php'] as $script) {
		$_SERVER['SCRIPT_NAME'] = $script;

		expect(audit_log_valid_event())->toBeFalse();
	}
});

it('is valid for a purge_continue request and records the purge action', function () {
	global $action;

	audit_test_set_request(['purge_continue' => '1']);

	expect(audit_log_valid_event())->toBeTrue();
	expect($action)->toBe('purge');
});

it('is not valid when nothing matches', function () {
	expect(audit_log_valid_event())->toBeFalse();
});
