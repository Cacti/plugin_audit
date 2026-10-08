<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for audit_utilities_array() in setup.php.
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/setup.php';
});

it('runs the legacy Utilities hook and preserves the Technical Support section', function () {
	$section = __('Technical Support', 'audit');

	$GLOBALS['utilities'] = [$section => []];

	audit_utilities_array();

	expect($GLOBALS['utilities'])->toHaveKey($section);
});
