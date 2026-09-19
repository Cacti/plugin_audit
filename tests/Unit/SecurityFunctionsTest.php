<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Behavioral coverage for the audit_* security helper functions in
 * audit_functions.php: admin/realm authorization, request operation
 * verification, sensitive-data redaction, bounded JSON encode/decode,
 * DST-safe retention cutoffs, request status classification, UUIDv4
 * generation, event type normalization, event integrity hashing, and
 * external log formatting/delivery.
 *
 * db_* and read_config_option() calls are resolved through the fixture
 * helpers declared in tests/bootstrap-unit.php (audit_test_mock_db(),
 * audit_test_set_config_option()) instead of redeclaring those globals,
 * since bootstrap-unit.php already provides guarded stubs for them.
 */

require_once dirname(__DIR__, 2) . '/audit_functions.php';

if (!function_exists('api_plugin_user_realm_auth')) {
	function api_plugin_user_realm_auth(string $filename = ''): bool {
		return !empty($GLOBALS['__audit_test_realms'][$filename]);
	}
}

beforeEach(function () {
	$GLOBALS['__audit_test_realms'] = [];
});

it('does not treat plain audit users as audit administrators', function () {
	expect(audit_user_is_admin())->toBeFalse();
});

it('treats audit_manage.php realm holders as audit administrators', function () {
	$GLOBALS['__audit_test_realms']['audit_manage.php'] = true;

	expect(audit_user_is_admin())->toBeTrue();
});

it('captures a normalized post-condition verifier for user realm permission saves', function () {
	$verifier = audit_operation_verifier_for_request('user_admin.php', [
		'action'                     => 'save',
		'id'                         => '4',
		'save_component_realm_perms' => '1',
		'section110'                 => 'on',
		'section106'                 => 'on',
	]);

	expect($verifier)->toBe([
		'type'               => 'user_realm_permissions',
		'target_user_id'     => 4,
		'expected_realm_ids' => [106, 110],
	]);
});

it('does not verify unrelated requests with a user realm verifier', function () {
	expect(audit_operation_verifier_for_request('host.php', ['id' => '4']))->toBeNull();
});

it('does not verify invalid realm permission requests as successful', function () {
	$invalid_verifier = audit_operation_verifier_for_request('user_admin.php', [
		'id'                         => 'invalid',
		'save_component_realm_perms' => '1',
	]);

	expect($invalid_verifier['type'])->toBe('invalid');
});

it('verifies stored realm permissions against the captured verifier', function () {
	$verifier = audit_operation_verifier_for_request('user_admin.php', [
		'action'                     => 'save',
		'id'                         => '4',
		'save_component_realm_perms' => '1',
		'section110'                 => 'on',
		'section106'                 => 'on',
	]);

	$existing_users = [4];
	$user_realms    = [4 => [110, 106]];
	$user_query_ok  = true;
	$realm_query_ok = true;

	audit_test_mock_db('db_fetch_cell_prepared', '', function ($sql, $params) use (&$existing_users, &$user_query_ok) {
		if (!$user_query_ok) {
			return false;
		}

		return in_array((int) ($params[0] ?? 0), $existing_users, true) ? 1 : 0;
	});

	audit_test_mock_db('db_fetch_assoc_prepared', '', function ($sql, $params) use (&$user_realms, &$realm_query_ok) {
		if (!$realm_query_ok) {
			return false;
		}

		$user_id   = (int) ($params[0] ?? 0);
		$realm_ids = $user_realms[$user_id] ?? [];

		return array_map(fn ($realm_id) => ['realm_id' => $realm_id], $realm_ids);
	});

	// Matching stored realm permissions must produce a verified success outcome.
	expect(audit_verify_operation($verifier))->toBe(['outcome' => 'success', 'reason' => 'realm_permissions_verified']);

	// Mismatched stored realm permissions must produce a failure outcome.
	$user_realms = [4 => [106]];
	expect(audit_verify_operation($verifier))->toBe(['outcome' => 'failure', 'reason' => 'realm_permissions_mismatch']);

	// A missing target user must produce a failure outcome.
	$existing_users = [];
	expect(audit_verify_operation($verifier))->toBe(['outcome' => 'failure', 'reason' => 'target_user_not_found']);

	// A failed target-user query must preserve an unknown outcome.
	$existing_users = [4];
	$user_query_ok  = false;
	expect(audit_verify_operation($verifier))->toBe(['outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed']);
	$user_query_ok = true;

	// A failed verification query must preserve an unknown outcome.
	$realm_query_ok = false;
	expect(audit_verify_operation($verifier))->toBe(['outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed']);
});

it('does not add false entries to object data for failed automation-device queries', function () {
	audit_test_mock_db('db_fetch_assoc_prepared', '', false);

	expect(json_decode(audit_process_page_data('automation_devices.php', '1', ['42']), true))->toBe([]);
});

it('redacts sensitive request data while preserving non-secret context', function () {
	$request = [
		'username' => 'operator',
		'password' => 'top-secret',
		'nested'   => [
			'api_token'    => 'nested-secret',
			'description'  => '<script>alert(1)</script>',
			'opaque_value' => 'Bearer abcdefghijklmnopqrstuvwxyz',
		],
	];

	$redacted = audit_redact_sensitive_data($request);

	expect($redacted['password'])->toBe('[REDACTED]');
	expect($redacted['nested']['api_token'])->toBe('[REDACTED]');
	expect($redacted['nested']['opaque_value'])->toBe('[REDACTED]');
	expect($redacted['nested']['description'])->toBe('<script>alert(1)</script>');
});

it('redacts secrets from CLI arguments, including inline and URI-embedded credentials', function () {
	$arguments = audit_redact_cli_arguments([
		'cli/example.php',
		'--password=secret-one',
		'--api-token',
		'secret-two',
		'https://user:secret-three@example.com/path',
		'--description=test',
	]);

	expect($arguments[1])->toBe('--password=[REDACTED]');
	expect($arguments[3])->toBe('[REDACTED]');
	expect($arguments[4])->toBe('https://user:[REDACTED]@example.com/path');
});

it('neutralizes spreadsheet formulas in CSV cells', function () {
	expect(audit_csv_safe_cell('=1+1'))->toBe("'=1+1");
});

it('bounds deeply nested request structures when JSON encoding', function () {
	$deep   = [];
	$cursor = &$deep;

	for ($i = 0; $i < 15; $i++) {
		$cursor['nested'] = [];
		$cursor           = &$cursor['nested'];
	}
	unset($cursor);

	expect(audit_json_encode($deep))->toContain('MAXIMUM DEPTH REACHED');
});

it('returns a controlled null result and a useful error for malformed JSON', function () {
	$invalid_json = audit_json_decode('{invalid', $json_error);

	expect($invalid_json)->toBeNull();
	expect($json_error)->not->toBeNull();
	expect($json_error)->not->toBe('');
});

it('subtracts full UTC days consistently across a DST boundary for retention cutoffs', function () {
	$now    = new DateTimeImmutable('2026-03-09 12:00:00', new DateTimeZone('America/New_York'));
	$cutoff = audit_retention_cutoff(1, $now);

	expect($cutoff->format('Y-m-d H:i:s'))->toBe('2026-03-08 16:00:00');
});

it('classifies request outcomes as completed or failed', function () {
	expect(audit_request_status(null, 302))->toBe('completed');
	expect(audit_request_status(['type' => E_ERROR], 200))->toBe('failed');
});

it('generates RFC 4122 version 4 UUIDs for event identifiers', function () {
	$uuid = audit_uuid_v4();

	expect($uuid)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/');
});

it('normalizes request event types for downstream consumers', function () {
	expect(audit_event_type_for_request('user_admin.php', 'Save'))->toBe('cacti.user_admin.save');
	expect(audit_event_type_for_request('host.php', 'none'))->toBe('cacti.host.submitted');
});

it('changes the integrity hash when a protected event field changes', function () {
	$hash_event = [
		'event_uuid'        => audit_uuid_v4(),
		'correlation_id'    => audit_uuid_v4(),
		'event_type'        => 'cacti.test.completed',
		'user_id'           => 1,
		'action'            => 'test',
		'event_time'        => '2026-07-24 10:00:00',
		'operation_outcome' => 'success',
		'details'           => '{}',
	];

	$first_hash                      = audit_event_integrity_hash($hash_event);
	$hash_event['operation_outcome'] = 'failure';

	expect(audit_event_integrity_hash($hash_event))->not->toBe($first_hash);
});

it('formats external log records as newline-terminated JSON or text', function () {
	$external_record = [
		'event_time'  => '2026-07-24 10:00:00',
		'action'      => "Update\nDevice",
		'post'        => '{"id":42}',
		'object_data' => '[]',
	];

	$json_record = audit_external_log_format($external_record, 'json');

	expect(substr($json_record, -1))->toBe("\n");
	expect(json_decode(trim($json_record), true))->toBe([
		'event_time'  => '2026-07-24 10:00:00',
		'action'      => "Update\nDevice",
		'post'        => ['id' => 42],
		'object_data' => [],
	]);

	expect(audit_external_log_format($external_record, 'text'))->toBe(
		'event_time="2026-07-24 10:00:00" action="Update\nDevice" post="{\"id\":42}" object_data="[]"' . "\n"
	);

	expect(audit_external_log_format(['post' => 'not-json'], 'json'))->toBe('{"post":"not-json"}' . "\n");

	// Unknown external formats must safely fall back to JSON.
	expect(audit_external_log_format($external_record, 'unsupported'))->toBe($json_record);
});

it('delivers a complete external log write and reports delivery', function () {
	$temporary_log = tempnam(sys_get_temp_dir(), 'audit-test-');

	try {
		$delivery = audit_append_external_log($temporary_log, "test-record\n");

		expect($delivery['status'])->toBe('delivered');
		expect(file_get_contents($temporary_log))->toBe("test-record\n");
	} finally {
		unlink($temporary_log);
	}
});

it('does not create external records or update delivery status for missing or empty audit events', function () {
	$temporary_log = tempnam(sys_get_temp_dir(), 'audit-test-');

	try {
		audit_test_set_config_option('audit_log_external', 'on');
		audit_test_set_config_option('audit_log_external_path', $temporary_log);
		audit_test_set_config_option('audit_log_external_format', 'json');

		$external_updates = [];
		audit_test_mock_db('db_execute_prepared', '', function ($sql, $params) use (&$external_updates) {
			$external_updates[] = ['sql' => $sql, 'params' => $params];

			return true;
		});

		audit_test_mock_db('db_fetch_row_prepared', '', false);
		file_put_contents($temporary_log, '');
		audit_deliver_external_event(999);
		expect(file_get_contents($temporary_log))->toBe('');
		expect($external_updates)->toBe([]);

		audit_test_mock_db('db_fetch_row_prepared', '', []);
		audit_deliver_external_event(999);
		expect(file_get_contents($temporary_log))->toBe('');
		expect($external_updates)->toBe([]);

		audit_test_mock_db('db_fetch_row_prepared', '', [
			'request_status'  => 'completed',
			'external_status' => 'delivered',
		]);
		audit_deliver_external_event(999);
		expect(file_get_contents($temporary_log))->toBe('', 'A delivered event must not be appended to the external file again.');
		expect($external_updates)->toBe([], 'A delivered event must not update delivery status again.');
	} finally {
		unlink($temporary_log);
	}
});
