<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the security-sensitive helpers in audit_functions.php:
 * admin authorization, operation verification, sensitive-data redaction,
 * CSV/JSON safety, retention math, event identity, and external delivery.
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/audit_functions.php';
});

beforeEach(function () {
	$GLOBALS['__test_db_calls']                       = array();
	$GLOBALS['__test_api_plugin_user_realm_auth']      = null;
	$GLOBALS['__test_db_fetch_cell_prepared']          = null;
	$GLOBALS['__test_db_fetch_assoc_prepared']         = null;
	$GLOBALS['__test_db_fetch_row_prepared']           = null;
	$GLOBALS['__test_db_execute_prepared']              = null;
	$GLOBALS['__test_read_config_option']              = null;
});

it('only treats audit administrators as audit administrators', function () {
	$GLOBALS['__test_api_plugin_user_realm_auth'] = function ($filename) {
		return false;
	};
	expect(audit_user_is_admin())->toBeFalse('Audit users must not be treated as audit administrators.');

	$GLOBALS['__test_api_plugin_user_realm_auth'] = function ($filename) {
		return $filename === 'audit_manage.php';
	};
	expect(audit_user_is_admin())->toBeTrue('Audit plugin administrators must be able to purge.');
});

it('captures a normalized post-condition verifier for user realm permission saves', function () {
	$verifier = audit_operation_verifier_for_request('user_admin.php', array(
		'action'                     => 'save',
		'id'                         => '4',
		'save_component_realm_perms' => '1',
		'section110'                 => 'on',
		'section106'                 => 'on'
	));

	expect($verifier)->toBe(array(
		'type'               => 'user_realm_permissions',
		'target_user_id'     => 4,
		'expected_realm_ids' => array(106, 110)
	), 'User realm permission saves must capture a normalized post-condition verifier.');
});

it('does not verify unrelated requests', function () {
	expect(audit_operation_verifier_for_request('host.php', array('id' => '4')))->toBeNull(
		'Unrelated requests must not receive a user realm verifier.'
	);
});

it('does not treat invalid realm permission requests as verified', function () {
	$invalid_verifier = audit_operation_verifier_for_request('user_admin.php', array(
		'id'                         => 'invalid',
		'save_component_realm_perms' => '1'
	));

	expect($invalid_verifier['type'])->toBe('invalid', 'Invalid realm permission requests must not be verified as successful.');
});

it('verifies stored realm permissions against the requested verifier', function () {
	$verifier = array(
		'type'               => 'user_realm_permissions',
		'target_user_id'     => 4,
		'expected_realm_ids' => array(106, 110)
	);

	$GLOBALS['__test_db_fetch_cell_prepared'] = function ($sql, $params) {
		return ((int) ($params[0] ?? 0)) === 4 ? 1 : 0;
	};
	$GLOBALS['__test_db_fetch_assoc_prepared'] = function ($sql, $params) {
		return array_map(function ($realm_id) {
			return array('realm_id' => $realm_id);
		}, array(110, 106));
	};
	expect(audit_verify_operation($verifier))->toBe(
		array('outcome' => 'success', 'reason' => 'realm_permissions_verified'),
		'Matching stored realm permissions must produce a verified success outcome.'
	);

	$GLOBALS['__test_db_fetch_assoc_prepared'] = function ($sql, $params) {
		return array_map(function ($realm_id) {
			return array('realm_id' => $realm_id);
		}, array(106));
	};
	expect(audit_verify_operation($verifier))->toBe(
		array('outcome' => 'failure', 'reason' => 'realm_permissions_mismatch'),
		'Mismatched stored realm permissions must produce a failure outcome.'
	);

	$GLOBALS['__test_db_fetch_cell_prepared'] = function ($sql, $params) {
		return 0;
	};
	expect(audit_verify_operation($verifier))->toBe(
		array('outcome' => 'failure', 'reason' => 'target_user_not_found'),
		'A missing target user must produce a failure outcome.'
	);

	$GLOBALS['__test_db_fetch_cell_prepared'] = function ($sql, $params) {
		return false;
	};
	expect(audit_verify_operation($verifier))->toBe(
		array('outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed'),
		'A failed target-user query must preserve an unknown outcome.'
	);

	$GLOBALS['__test_db_fetch_cell_prepared'] = function ($sql, $params) {
		return 1;
	};
	$GLOBALS['__test_db_fetch_assoc_prepared'] = function ($sql, $params) {
		return false;
	};
	expect(audit_verify_operation($verifier))->toBe(
		array('outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed'),
		'A failed verification query must preserve an unknown outcome.'
	);
});

it('does not add false entries when automation-device queries fail', function () {
	$GLOBALS['__test_db_fetch_assoc_prepared'] = function ($sql, $params) {
		return false;
	};
	$result = json_decode(audit_process_page_data('automation_devices.php', '1', array('42')), true);
	expect($result)->toBe(array(), 'Failed automation-device queries must not add false entries to object data.');
});

it('redacts sensitive request data while preserving non-secret context', function () {
	$request = array(
		'username' => 'operator',
		'password' => 'top-secret',
		'nested'   => array(
			'api_token'    => 'nested-secret',
			'description'  => '<script>alert(1)</script>',
			'opaque_value' => 'Bearer abcdefghijklmnopqrstuvwxyz'
		)
	);

	$redacted = audit_redact_sensitive_data($request);

	expect($redacted['password'])->toBe('[REDACTED]', 'Top-level passwords must be redacted.');
	expect($redacted['nested']['api_token'])->toBe('[REDACTED]', 'Nested tokens must be redacted.');
	expect($redacted['nested']['opaque_value'])->toBe('[REDACTED]',
		'Secret-shaped values must be redacted even when their key is unknown.');
	expect($redacted['nested']['description'])->toBe('<script>alert(1)</script>',
		'Non-secret data must remain available for later context-aware output escaping.');
});

it('redacts secrets embedded in CLI arguments', function () {
	$arguments = audit_redact_cli_arguments(array(
		'cli/example.php',
		'--password=secret-one',
		'--api-token',
		'secret-two',
		'https://user:secret-three@example.com/path',
		'--description=test'
	));

	expect($arguments[1])->toBe('--password=[REDACTED]', 'Inline CLI passwords must be redacted.');
	expect($arguments[3])->toBe('[REDACTED]', 'Separate CLI secret values must be redacted.');
	expect($arguments[4])->toBe('https://user:[REDACTED]@example.com/path',
		'Credentials embedded in a URI must be redacted.');
});

it('neutralizes spreadsheet formulas', function () {
	expect(audit_csv_safe_cell('=1+1'))->toBe("'=1+1", 'Spreadsheet formulas must be neutralized.');
});

it('bounds deeply nested request structures when encoding JSON', function () {
	$deep   = array();
	$cursor = &$deep;

	for ($i = 0; $i < 15; $i++) {
		$cursor['nested'] = array();
		$cursor           = &$cursor['nested'];
	}
	unset($cursor);

	$bounded_json = audit_json_encode($deep);

	expect($bounded_json)->toContain('MAXIMUM DEPTH REACHED');
});

it('returns a controlled null result and a useful error for malformed JSON', function () {
	$invalid_json = audit_json_decode('{invalid', $json_error);

	expect($invalid_json)->toBeNull('Malformed JSON must return a controlled null result.');
	expect($json_error)->not->toBeEmpty('Malformed JSON must return a useful error.');
});

it('subtracts full UTC days consistently across DST for retention', function () {
	$now    = new DateTimeImmutable('2026-03-09 12:00:00', new DateTimeZone('America/New_York'));
	$cutoff = audit_retention_cutoff(1, $now);

	expect($cutoff->format('Y-m-d H:i:s'))->toBe('2026-03-08 16:00:00',
		'Retention must subtract full UTC days consistently across DST.');
});

it('finalizes request status from errors and response codes', function () {
	expect(audit_request_status(null, 302))->toBe('completed',
		'Successful redirects must finalize as completed requests.');
	expect(audit_request_status(array('type' => E_ERROR), 200))->toBe('failed',
		'Fatal errors must finalize as failed requests.');
});

it('generates RFC 4122 version 4 UUIDs for event identifiers', function () {
	$uuid = audit_uuid_v4();

	expect($uuid)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
		'Event identifiers must be RFC 4122 version 4 UUIDs.');
});

it('normalizes request event types for downstream consumers', function () {
	expect(audit_event_type_for_request('user_admin.php', 'Save'))->toBe('cacti.user_admin.save',
		'Request event types must be normalized for downstream consumers.');
	expect(audit_event_type_for_request('host.php', 'none'))->toBe('cacti.host.submitted',
		'Requests without a specific action must use the submitted event verb.');
});

it('changes integrity hashes when protected event fields change', function () {
	$hash_event = array(
		'event_uuid'        => audit_uuid_v4(),
		'correlation_id'    => audit_uuid_v4(),
		'event_type'        => 'cacti.test.completed',
		'user_id'           => 1,
		'action'            => 'test',
		'event_time'        => '2026-07-24 10:00:00',
		'operation_outcome' => 'success',
		'details'           => '{}'
	);
	$first_hash                      = audit_event_integrity_hash($hash_event);
	$hash_event['operation_outcome'] = 'failure';

	expect(audit_event_integrity_hash($hash_event))->not->toBe($first_hash,
		'Integrity hashes must change when protected event fields change.');
});

it('formats external log records for json and text delivery', function () {
	$external_record = array(
		'event_time'  => '2026-07-24 10:00:00',
		'action'      => "Update\nDevice",
		'post'        => '{"id":42}',
		'object_data' => '[]'
	);

	$json_record = audit_external_log_format($external_record, 'json');
	expect(substr($json_record, -1))->toBe("\n", 'JSON external records must end with a newline.');
	expect(json_decode(trim($json_record), true))->toBe(array(
		'event_time'  => '2026-07-24 10:00:00',
		'action'      => "Update\nDevice",
		'post'        => array('id' => 42),
		'object_data' => array()
	), 'JSON external records must expose stored JSON fields as native structures.');

	expect(audit_external_log_format($external_record, 'text'))->toBe(
		'event_time="2026-07-24 10:00:00" action="Update\nDevice" post="{\"id\":42}" object_data="[]"' . "\n",
		'Text external records must be single-line key/value data with escaped values.'
	);

	expect(audit_external_log_format(array('post' => 'not-json'), 'json'))->toBe('{"post":"not-json"}' . "\n",
		'Malformed stored JSON fields must remain available as strings.');

	expect(audit_external_log_format($external_record, 'unsupported'))->toBe($json_record,
		'Unknown external formats must safely fall back to JSON.');
});

it('writes complete external log records to disk', function () {
	$temporary_log = tempnam(sys_get_temp_dir(), 'audit-test-');

	$delivery = audit_append_external_log($temporary_log, "test-record\n");
	expect($delivery['status'])->toBe('delivered', 'A complete external log write must report delivery.');
	expect(file_get_contents($temporary_log))->toBe("test-record\n", 'External log content must be complete.');

	unlink($temporary_log);
});

it('does not deliver external events that are missing or empty', function () {
	$temporary_log = tempnam(sys_get_temp_dir(), 'audit-test-');

	$GLOBALS['__test_read_config_option'] = function ($name) use ($temporary_log) {
		$options = array(
			'audit_log_external'        => 'on',
			'audit_log_external_path'   => $temporary_log,
			'audit_log_external_format' => 'json'
		);

		return $options[$name] ?? '';
	};

	$updates = array();
	$GLOBALS['__test_db_execute_prepared'] = function ($sql, $params) use (&$updates) {
		$updates[] = array('sql' => $sql, 'params' => $params);

		return true;
	};

	$GLOBALS['__test_db_fetch_row_prepared'] = function ($sql, $params) {
		return false;
	};
	file_put_contents($temporary_log, '');
	audit_deliver_external_event(999);
	expect(file_get_contents($temporary_log))->toBe('', 'Missing audit events must not create external records.');
	expect($updates)->toBe(array(), 'Missing audit events must not update delivery status.');

	$GLOBALS['__test_db_fetch_row_prepared'] = function ($sql, $params) {
		return array();
	};
	audit_deliver_external_event(999);
	expect(file_get_contents($temporary_log))->toBe('', 'Empty audit events must not create external records.');
	expect($updates)->toBe(array(), 'Empty audit events must not update delivery status.');

	unlink($temporary_log);
});
