<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the plugin lifecycle contract functions in setup.php:
 * plugin_audit_check_config(), plugin_audit_upgrade(), and
 * audit_is_console_page().
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/setup.php';
});

it('reports the config as always valid', function () {
	expect(plugin_audit_check_config())->toBeTrue();
});

it('reports that no upgrade is pending', function () {
	expect(plugin_audit_upgrade())->toBeTrue();
});

it('recognizes audit.php as a console page', function () {
	expect(audit_is_console_page('/cacti/plugins/audit/audit.php'))->toBeTrue();
});

it('does not recognize an unrelated page as a console page', function () {
	expect(audit_is_console_page('/cacti/graph_view.php'))->toBeFalse();
});

it('preserves events while a Syslog delivery is claimed by a poller', function () {
	audit_test_reset_db_mocks();
	audit_test_set_config_option('audit_enabled', 'off');
	audit_test_set_config_option('audit_auth_log_enabled', 'off');
	audit_test_set_config_option('audit_brute_force_enabled', 'off');
	audit_test_set_config_option('audit_log_external', 'off');
	audit_test_set_config_option('audit_syslog_enabled', 'off');
	audit_test_set_config_option('audit_last_check', '');
	audit_test_set_config_option('audit_retention', '90');

	audit_poller_bottom();

	$purge_queries = array_values(array_filter($GLOBALS['__test_db_calls'], function ($call) {
		return str_contains($call['sql'], 'DELETE FROM audit_log');
	}));

	expect($purge_queries)->toHaveCount(1);
	expect($purge_queries[0]['sql'])->toContain("'sending'");
});
