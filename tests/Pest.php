<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Pest configuration file. The bootstrap is loaded via phpunit.xml's
 * bootstrap attribute (tests/bootstrap-unit.php), which requires Cacti's
 * own Composer-managed vendor tree checked out by the CI workflow.
 *
 * A bare beforeEach() call here only applies within this file, not to
 * other test files in this directory tree - uses()->beforeEach()->in()
 * is required to register a hook that actually runs before every test
 * in every nested test file.
 */

uses()->beforeEach(function () {
	audit_test_reset_db_mocks();
})->in(__DIR__);
