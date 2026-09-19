<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Behavioral coverage for audit_persist_auth_defaults() and
 * audit_owned_setting_names() in setup.php: safe authentication-audit
 * install/upgrade defaults must never overwrite an administrator's
 * existing choice or a previously persisted ingestion watermark, and the
 * plugin's owned-setting inventory must stay unique and well-known.
 */

require_once dirname(__DIR__, 2) . '/setup.php';

/**
 * Registers a fixture that reports which setting names already "exist" in
 * a fake settings table, mirroring audit_persist_auth_defaults()'s
 * exists-check query.
 *
 * @param array $existing Reference to the map of setting name => value already persisted.
 *
 * @return void
 */
function audit_defaults_test_track_existing(array &$existing): void {
	audit_test_mock_db('db_fetch_cell_prepared', 'SELECT COUNT(*) FROM settings WHERE name = ?', function ($sql, $params) use (&$existing) {
		return array_key_exists((string) ($params[0] ?? ''), $existing) ? 1 : 0;
	});
}

beforeEach(function () {
	audit_test_reset_db_mocks();
	audit_test_set_config_option('audit_auth_log_enabled', 'on');
});

it('does not overwrite an existing administrator choice', function () {
	$existing = ['audit_auth_log_enabled' => 'on'];
	audit_defaults_test_track_existing($existing);

	$before = time();
	audit_persist_auth_defaults();
	$after = time();

	expect($GLOBALS['__test_config_options']['audit_auth_log_enabled'])->toBe('on');
	expect($GLOBALS['__test_config_options']['audit_brute_force_enabled'])->toBe('off');

	$watermark = (int) $GLOBALS['__test_config_options']['audit_user_log_watermark_epoch'];
	expect($watermark)->toBeGreaterThanOrEqual($before);
	expect($watermark)->toBeLessThanOrEqual($after);
});

it('preserves a persisted ingestion watermark across upgrades', function () {
	$existing = ['audit_auth_log_enabled' => 'on'];
	audit_defaults_test_track_existing($existing);

	audit_persist_auth_defaults();

	// Simulate the watermark now being a persisted setting on a second,
	// upgrade-time call.
	$existing['audit_user_log_watermark_epoch'] = '12345';
	audit_test_set_config_option('audit_user_log_watermark_epoch', '12345');

	audit_persist_auth_defaults();

	expect($GLOBALS['__test_config_options']['audit_user_log_watermark_epoch'])->toBe('12345');
});

it('declares unique, well-known plugin-owned setting names', function () {
	$owned_settings = audit_owned_setting_names();

	expect(count($owned_settings))->toBe(count(array_unique($owned_settings)));

	foreach (['audit_enabled', 'audit_auth_log_enabled', 'audit_syslog_health_state'] as $owned_setting) {
		expect($owned_settings)->toContain($owned_setting);
	}

	expect($owned_settings)->not->toContain('audit_unrelated_extension_setting');
});
