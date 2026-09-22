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
