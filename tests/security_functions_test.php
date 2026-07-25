<?php

require_once dirname(__DIR__) . '/audit_functions.php';

$audit_test_realms = array();
$audit_test_existing_users = array();
$audit_test_user_realms = array();
$audit_test_user_query_failure = false;
$audit_test_realm_query_failure = false;

function api_plugin_user_realm_auth($filename = '') {
	global $audit_test_realms;

	return !empty($audit_test_realms[$filename]);
}

function db_fetch_cell_prepared($sql, $params = array()) {
	global $audit_test_existing_users, $audit_test_user_query_failure;

	if ($audit_test_user_query_failure) {
		return false;
	}

	$user_id = (int) ($params[0] ?? 0);

	return in_array($user_id, $audit_test_existing_users, true) ? 1 : 0;
}

function db_fetch_assoc_prepared($sql, $params = array()) {
	global $audit_test_user_realms, $audit_test_realm_query_failure;

	if ($audit_test_realm_query_failure) {
		return false;
	}

	$user_id = (int) ($params[0] ?? 0);
	$realm_ids = $audit_test_user_realms[$user_id] ?? array();

	return array_map(function($realm_id) {
		return array('realm_id' => $realm_id);
	}, $realm_ids);
}

function audit_test_assert_same($expected, $actual, $message) {
	if ($expected !== $actual) {
		fwrite(STDERR, $message . PHP_EOL);
		fwrite(STDERR, 'Expected: ' . var_export($expected, true) . PHP_EOL);
		fwrite(STDERR, 'Actual:   ' . var_export($actual, true) . PHP_EOL);
		exit(1);
	}
}

audit_test_assert_same(false, audit_user_is_admin(), 'Audit users must not be treated as audit administrators.');
$audit_test_realms['audit_manage.php'] = true;
audit_test_assert_same(true, audit_user_is_admin(), 'Audit plugin administrators must be able to purge.');
$audit_test_realms = array();

$verifier = audit_operation_verifier_for_request('user_admin.php', array(
	'action' => 'save',
	'id' => '4',
	'save_component_realm_perms' => '1',
	'section110' => 'on',
	'section106' => 'on'
));
audit_test_assert_same(
	array(
		'type' => 'user_realm_permissions',
		'target_user_id' => 4,
		'expected_realm_ids' => array(106, 110)
	),
	$verifier,
	'User realm permission saves must capture a normalized post-condition verifier.'
);

audit_test_assert_same(
	null,
	audit_operation_verifier_for_request('host.php', array('id' => '4')),
	'Unrelated requests must not receive a user realm verifier.'
);

$invalid_verifier = audit_operation_verifier_for_request('user_admin.php', array(
	'id' => 'invalid',
	'save_component_realm_perms' => '1'
));
audit_test_assert_same(
	'invalid',
	$invalid_verifier['type'],
	'Invalid realm permission requests must not be verified as successful.'
);

$audit_test_existing_users = array(4);
$audit_test_user_realms = array(4 => array(110, 106));
audit_test_assert_same(
	array('outcome' => 'success', 'reason' => 'realm_permissions_verified'),
	audit_verify_operation($verifier),
	'Matching stored realm permissions must produce a verified success outcome.'
);

$audit_test_user_realms = array(4 => array(106));
audit_test_assert_same(
	array('outcome' => 'failure', 'reason' => 'realm_permissions_mismatch'),
	audit_verify_operation($verifier),
	'Mismatched stored realm permissions must produce a failure outcome.'
);

$audit_test_existing_users = array();
audit_test_assert_same(
	array('outcome' => 'failure', 'reason' => 'target_user_not_found'),
	audit_verify_operation($verifier),
	'A missing target user must produce a failure outcome.'
);

$audit_test_existing_users = array(4);
$audit_test_user_query_failure = true;
audit_test_assert_same(
	array('outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed'),
	audit_verify_operation($verifier),
	'A failed target-user query must preserve an unknown outcome.'
);
$audit_test_user_query_failure = false;

$audit_test_existing_users = array(4);
$audit_test_realm_query_failure = true;
audit_test_assert_same(
	array('outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed'),
	audit_verify_operation($verifier),
	'A failed verification query must preserve an unknown outcome.'
);
$audit_test_realm_query_failure = false;

$request = array(
	'username' => 'operator',
	'password' => 'top-secret',
	'nested' => array(
		'api_token' => 'nested-secret',
		'description' => '<script>alert(1)</script>',
		'opaque_value' => 'Bearer abcdefghijklmnopqrstuvwxyz'
	)
);

$redacted = audit_redact_sensitive_data($request);

audit_test_assert_same('[REDACTED]', $redacted['password'], 'Top-level passwords must be redacted.');
audit_test_assert_same('[REDACTED]', $redacted['nested']['api_token'], 'Nested tokens must be redacted.');
audit_test_assert_same('[REDACTED]', $redacted['nested']['opaque_value'], 'Secret-shaped values must be redacted even when their key is unknown.');
audit_test_assert_same(
	'<script>alert(1)</script>',
	$redacted['nested']['description'],
	'Non-secret data must remain available for later context-aware output escaping.'
);

$arguments = audit_redact_cli_arguments(array(
	'cli/example.php',
	'--password=secret-one',
	'--api-token',
	'secret-two',
	'https://user:secret-three@example.com/path',
	'--description=test'
));

audit_test_assert_same('--password=[REDACTED]', $arguments[1], 'Inline CLI passwords must be redacted.');
audit_test_assert_same('[REDACTED]', $arguments[3], 'Separate CLI secret values must be redacted.');
audit_test_assert_same(
	'https://user:[REDACTED]@example.com/path',
	$arguments[4],
	'Credentials embedded in a URI must be redacted.'
);

audit_test_assert_same("'=1+1", audit_csv_safe_cell('=1+1'), 'Spreadsheet formulas must be neutralized.');

$deep = array();
$cursor = &$deep;
for ($i = 0; $i < 15; $i++) {
	$cursor['nested'] = array();
	$cursor = &$cursor['nested'];
}
unset($cursor);

$bounded_json = audit_json_encode($deep);
if (strpos($bounded_json, 'MAXIMUM DEPTH REACHED') === false) {
	fwrite(STDERR, 'Deep request structures must be bounded.' . PHP_EOL);
	exit(1);
}

$invalid_json = audit_json_decode('{invalid', $json_error);
audit_test_assert_same(null, $invalid_json, 'Malformed JSON must return a controlled null result.');
if ($json_error === null || $json_error === '') {
	fwrite(STDERR, 'Malformed JSON must return a useful error.' . PHP_EOL);
	exit(1);
}

$now    = new DateTimeImmutable('2026-03-09 12:00:00', new DateTimeZone('America/New_York'));
$cutoff = audit_retention_cutoff(1, $now);
audit_test_assert_same(
	'2026-03-08 16:00:00',
	$cutoff->format('Y-m-d H:i:s'),
	'Retention must subtract full UTC days consistently across DST.'
);

audit_test_assert_same(
	'completed',
	audit_request_status(null, 302),
	'Successful redirects must finalize as completed requests.'
);
audit_test_assert_same(
	'failed',
	audit_request_status(array('type' => E_ERROR), 200),
	'Fatal errors must finalize as failed requests.'
);

$uuid = audit_uuid_v4();
if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $uuid)) {
	fwrite(STDERR, 'Event identifiers must be RFC 4122 version 4 UUIDs.' . PHP_EOL);
	exit(1);
}

audit_test_assert_same(
	'cacti.user_admin.save',
	audit_event_type_for_request('user_admin.php', 'Save'),
	'Request event types must be normalized for downstream consumers.'
);
audit_test_assert_same(
	'cacti.host.submitted',
	audit_event_type_for_request('host.php', 'none'),
	'Requests without a specific action must use the submitted event verb.'
);

$hash_event = array(
	'event_uuid' => $uuid,
	'correlation_id' => audit_uuid_v4(),
	'event_type' => 'cacti.test.completed',
	'user_id' => 1,
	'action' => 'test',
	'event_time' => '2026-07-24 10:00:00',
	'operation_outcome' => 'success',
	'details' => '{}'
);
$first_hash = audit_event_integrity_hash($hash_event);
$hash_event['operation_outcome'] = 'failure';
if ($first_hash === audit_event_integrity_hash($hash_event)) {
	fwrite(STDERR, 'Integrity hashes must change when protected event fields change.' . PHP_EOL);
	exit(1);
}

$external_record = array(
	'event_time' => '2026-07-24 10:00:00',
	'action' => "Update\nDevice",
	'post' => '{"id":42}',
	'object_data' => '[]'
);
$json_record = audit_external_log_format($external_record, 'json');
audit_test_assert_same("\n", substr($json_record, -1), 'JSON external records must end with a newline.');
audit_test_assert_same(
	array(
		'event_time' => '2026-07-24 10:00:00',
		'action' => "Update\nDevice",
		'post' => array('id' => 42),
		'object_data' => array()
	),
	json_decode(trim($json_record), true),
	'JSON external records must expose stored JSON fields as native structures.'
);
audit_test_assert_same(
	'event_time="2026-07-24 10:00:00" action="Update\nDevice" post="{\"id\":42}" object_data="[]"' . "\n",
	audit_external_log_format($external_record, 'text'),
	'Text external records must be single-line key/value data with escaped values.'
);
audit_test_assert_same(
	'{"post":"not-json"}' . "\n",
	audit_external_log_format(array('post' => 'not-json'), 'json'),
	'Malformed stored JSON fields must remain available as strings.'
);
audit_test_assert_same(
	$json_record,
	audit_external_log_format($external_record, 'unsupported'),
	'Unknown external formats must safely fall back to JSON.'
);

$temporary_log = tempnam(sys_get_temp_dir(), 'audit-test-');
$delivery      = audit_append_external_log($temporary_log, "test-record\n");
audit_test_assert_same('delivered', $delivery['status'], 'A complete external log write must report delivery.');
audit_test_assert_same("test-record\n", file_get_contents($temporary_log), 'External log content must be complete.');
unlink($temporary_log);

print "Security helper tests passed.\n";
