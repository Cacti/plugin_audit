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
		'description' => '<script>alert(1)</script>'
	)
);

$redacted = audit_redact_sensitive_data($request);

audit_test_assert_same('[REDACTED]', $redacted['password'], 'Top-level passwords must be redacted.');
audit_test_assert_same('[REDACTED]', $redacted['nested']['api_token'], 'Nested tokens must be redacted.');
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

print "Security helper tests passed.\n";
