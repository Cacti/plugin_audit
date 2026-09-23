<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for audit_draw_navigation_text() in setup.php.
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/setup.php';
});

it('adds the audit breadcrumb entry without disturbing existing ones', function () {
	$nav = audit_draw_navigation_text(['other.php:' => ['title' => 'Other']]);

	expect($nav)->toHaveKey('other.php:');
	expect($nav)->toHaveKey('audit.php:');
	expect($nav['audit.php:'])->toBe([
		'title'   => 'Audit Event Log',
		'mapping' => 'index.php:',
		'url'     => 'audit.php',
		'level'   => '1',
	]);
});
