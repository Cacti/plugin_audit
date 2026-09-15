<?php

/*
 * Enforce complete executable-line coverage for the authentication/session
 * auditing feature without adding a third-party coverage dependency.
 */

if (!function_exists('phpdbg_start_oplog') || !function_exists('phpdbg_get_executable')) {
	fwrite(STDERR, "Run this coverage gate with phpdbg -qrr tests/auth_audit_coverage_test.php\n");
	exit(1);
}

phpdbg_start_oplog();
require __DIR__ . '/auth_audit_test.php';
$executed = phpdbg_end_oplog();

$source_file = realpath(dirname(__DIR__) . '/audit_functions.php');

if ($source_file === false) {
	fwrite(STDERR, "Unable to resolve audit_functions.php.\n");
	exit(1);
}

$executable = phpdbg_get_executable()[$source_file] ?? [];
$hit_lines  = $executed[$source_file] ?? [];
$functions  = [
	'audit_logout_pre_session_destroy',
	'audit_logout_stash',
	'audit_logout_post_session_destroy',
	'audit_user_log_event_descriptor',
	'audit_user_log_event_uuid',
	'audit_log_ingestion_warning',
	'audit_report_ingestion_unavailable',
	'audit_report_dropped_user_log_row',
	'audit_cleanup_user_log_state',
	'audit_poll_user_log',
	'audit_detect_failed_login_volume',
	'audit_custom_denied', 'audit_settings_field_groups'
];
$covered = 0;
$total   = 0;
$missed  = [];

foreach ($functions as $function) {
	$reflection = new ReflectionFunction($function);

	foreach ($executable as $line => $_opcode) {
		if ($line < $reflection->getStartLine() || $line > $reflection->getEndLine()) {
			continue;
		}

		$total++;

		if (isset($hit_lines[$line])) {
			$covered++;
		} else {
			$missed[$function][] = $line;
		}
	}
}

$percentage = $total === 0 ? 0.0 : ($covered / $total) * 100;

if ($missed !== []) {
	foreach ($missed as $function => $lines) {
		fwrite(STDERR, sprintf('%s missed executable lines: %s%s', $function, implode(', ', $lines), PHP_EOL));
	}

	fwrite(STDERR, sprintf("Authentication audit line coverage: %.2f%% (%d/%d)\n", $percentage, $covered, $total));
	exit(1);
}

printf("Authentication audit line coverage: 100.00%% (%d/%d)\n", $covered, $total);
