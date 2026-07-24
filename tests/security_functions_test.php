<?php

require_once dirname(__DIR__) . '/audit_functions.php';

function audit_test_assert_same($expected, $actual, $message) {
	if ($expected !== $actual) {
		fwrite(STDERR, $message . PHP_EOL);
		fwrite(STDERR, 'Expected: ' . var_export($expected, true) . PHP_EOL);
		fwrite(STDERR, 'Actual:   ' . var_export($actual, true) . PHP_EOL);
		exit(1);
	}
}

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

$temporary_log = tempnam(sys_get_temp_dir(), 'audit-test-');
$delivery      = audit_append_external_log($temporary_log, "test-record\n");
audit_test_assert_same('delivered', $delivery['status'], 'A complete external log write must report delivery.');
audit_test_assert_same("test-record\n", file_get_contents($temporary_log), 'External log content must be complete.');
unlink($temporary_log);

print "Security helper tests passed.\n";
