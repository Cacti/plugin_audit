<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

/*
 * Covers the audit_log schema-readiness guard added so CLI/poller and
 * shutdown callbacks skip logging until the request_status migration has run:
 * audit_event_schema_ready() and the three write entry points it protects
 * (audit_record_event(), audit_finalize_request(), audit_config_insert()).
 */

require_once dirname(__DIR__, 2) . '/audit_functions.php';

beforeEach(function () {
	audit_test_reset_db_mocks();
});

it('reports the schema ready when the table and request_status column exist', function () {
	// The unit bootstrap defaults db_table_exists()/db_column_exists() to true.
	expect(audit_event_schema_ready())->toBeTrue();
});

it('reports the schema not ready when the request_status column is missing', function () {
	audit_test_mock_db('db_column_exists', 'audit_log|request_status', false);

	expect(audit_event_schema_ready())->toBeFalse();
});

it('reports the schema not ready when the audit_log table is missing', function () {
	audit_test_mock_db('db_table_exists', 'audit_log', false);

	expect(audit_event_schema_ready())->toBeFalse();
});

it('records no event while the schema is not ready', function () {
	audit_test_mock_db('db_table_exists', 'audit_log', false);

	expect(audit_record_event('audit.test.schema_guard'))->toBe(0);
});

it('finalizes nothing while the schema is not ready', function () {
	audit_test_mock_db('db_table_exists', 'audit_log', false);

	audit_finalize_request(123);

	$writes = array_filter($GLOBALS['__test_db_calls'], function ($call) {
		return in_array($call['fn'], ['db_execute_prepared', 'db_fetch_row_prepared'], true)
			&& strpos($call['sql'], 'audit_log') !== false;
	});

	expect($writes)->toBeEmpty();
});

it('inserts no config event while the schema is not ready', function () {
	audit_test_mock_db('db_table_exists', 'audit_log', false);

	audit_config_insert();

	$writes = array_filter($GLOBALS['__test_db_calls'], function ($call) {
		return strpos($call['sql'], 'INSERT INTO audit_log') !== false;
	});

	expect($writes)->toBeEmpty();
});
