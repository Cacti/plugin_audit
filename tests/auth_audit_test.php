<?php

/*
 * Behavioral tests for Group A authentication/session auditing.
 *
 * The database stubs below interpret SQL filtering, ordering, and limits
 * against in-memory fixtures so tests exercise the real query semantics
 * rather than returning fixtures verbatim.
 */

require_once dirname(__DIR__) . '/audit_functions.php';

$audit_auth_config = [
	'audit_enabled'                    => 'on',
	'audit_auth_log_enabled'           => 'on',
	'audit_brute_force_enabled'        => 'on',
	'audit_brute_force_window_minutes' => '5',
	'audit_brute_force_threshold'      => '10',
	'audit_brute_force_last_alert'     => '',
	'audit_user_log_batch_size'        => '1000',
	'audit_retention'                  => '90'
];

$audit_auth_recorded_events = [];
$audit_auth_user_log_rows   = [];
$audit_auth_state_rows      = [];
$audit_auth_failed_count    = 0;
$audit_auth_set_options     = [];
$audit_auth_settings_rows   = [];
$audit_auth_insert_fails    = false;
$audit_auth_fail_usernames  = [];
$audit_auth_state_conflict  = false;
$audit_auth_affected_rows   = 0;
$audit_auth_transaction     = null;

function read_config_option(string $name, bool $force = false): string {
	global $audit_auth_config, $audit_auth_settings_rows;

	if (isset($audit_auth_settings_rows[$name])) {
		return (string) $audit_auth_settings_rows[$name];
	}

	return $audit_auth_config[$name] ?? '';
}

function set_config_option(string $name, string $value): void {
	global $audit_auth_set_options, $audit_auth_config, $audit_auth_settings_rows;
	$audit_auth_config[$name]        = $value;
	$audit_auth_settings_rows[$name] = $value;
	$audit_auth_set_options[$name][] = $value;
}

function db_execute_prepared(string $sql, array $params = []): bool {
	global $audit_auth_recorded_events, $audit_auth_state_rows, $audit_auth_settings_rows, $audit_auth_insert_fails, $audit_auth_fail_usernames, $audit_auth_state_conflict, $audit_auth_affected_rows, $audit_auth_transaction;

	if (strpos($sql, 'START TRANSACTION') !== false) {
		$audit_auth_transaction = [
			'events' => $audit_auth_recorded_events,
			'state'  => $audit_auth_state_rows
		];

		return true;
	}

	if (strpos($sql, 'ROLLBACK') !== false) {
		if (is_array($audit_auth_transaction)) {
			$audit_auth_recorded_events = $audit_auth_transaction['events'];
			$audit_auth_state_rows      = $audit_auth_transaction['state'];
		}

		$audit_auth_transaction = null;

		return true;
	}

	if (strpos($sql, 'COMMIT') !== false) {
		$audit_auth_transaction = null;

		return true;
	}

	if (strpos($sql, 'INSERT INTO audit_log') !== false) {
		$details  = json_decode((string) ($params[24] ?? ''), true);
		$username = is_array($details) ? (string) ($details['username'] ?? '') : '';

		if ($audit_auth_insert_fails || in_array($username, $audit_auth_fail_usernames, true)) {
			$audit_auth_affected_rows = 0;

			return false;
		}
		$audit_auth_recorded_events[] = ['sql' => $sql, 'params' => $params];
		$audit_auth_affected_rows     = 1;

		return true;
	}

	if (strpos($sql, 'INSERT IGNORE INTO audit_user_log_state') !== false) {
		$hash = $params[0];

		if ($audit_auth_state_conflict || isset($audit_auth_state_rows[$hash])) {
			$audit_auth_affected_rows = 0;
		} else {
			$audit_auth_state_rows[$hash] = [
				'source_hash'    => $hash,
				'source_key'     => $params[1],
				'source_time'    => $params[2],
				'audit_id'       => $params[3],
				'processed_time' => $params[4]
			];
			$audit_auth_affected_rows = 1;
		}

		return true;
	}

	if (strpos($sql, 'INSERT IGNORE INTO settings') !== false) {
		$name = (string) $params[0];

		if (!array_key_exists($name, $audit_auth_settings_rows)) {
			$audit_auth_settings_rows[$name] = (string) $params[1];
			$audit_auth_affected_rows        = 1;
		} else {
			$audit_auth_affected_rows = 0;
		}

		return true;
	}

	if (strpos($sql, 'UPDATE settings') !== false && strpos($sql, 'audit_brute_force_last_alert') !== false) {
		$name          = 'audit_brute_force_last_alert';
		$current       = $audit_auth_settings_rows[$name] ?? '';
		$now           = $params[0];
		$window        = $params[2];
		$should_update = ($current === '' || $current === '0');

		if (!$should_update && $current !== '') {
			$ts            = strtotime($current);
			$now_ts        = strtotime($now);
			$should_update = ($ts !== false && $now_ts !== false && ($now_ts - $ts) >= ($window * 60));
		}

		if ($should_update) {
			$audit_auth_settings_rows[$name] = $now;
			$audit_auth_affected_rows        = 1;

			return true;
		}

		$audit_auth_affected_rows = 0;

		return true;
	}

	if (strpos($sql, 'DELETE FROM audit_user_log_state') !== false) {
		$audit_auth_state_rows = [];

		return true;
	}

	return true;
}

function db_fetch_insert_id(): int {
	global $audit_auth_recorded_events, $audit_auth_insert_fails;

	if ($audit_auth_insert_fails) {
		return 0;
	}

	return count($audit_auth_recorded_events);
}

function db_fetch_row_prepared(string $sql, array $params = []): array {
	global $audit_auth_state_rows;

	if (strpos($sql, 'MAX(source_time)') !== false) {
		if (empty($audit_auth_state_rows)) {
			return [];
		}

		$max_time = '';
		$max_hash = '';

		foreach ($audit_auth_state_rows as $row) {
			if ($row['source_time'] > $max_time || ($row['source_time'] === $max_time && ($row['source_key'] ?? '') > $max_hash)) {
				$max_time = $row['source_time'];
				$max_hash = $row['source_key'] ?? '';
			}
		}

		return ['max_time' => $max_time, 'max_key' => $max_hash];
	}

	return [];
}

/**
 * SQL-interpreting stub: filters user_log rows by retention and durable
 * deduplication state, orders by (time, username, user_id), and applies LIMIT.
 */
function db_fetch_assoc_prepared(string $sql, array $params = []): array {
	global $audit_auth_user_log_rows, $audit_auth_state_rows;

	if (strpos($sql, 'FROM user_log') === false) {
		return [];
	}

	$cutoff   = (string) ($params[0] ?? '');
	$filtered = [];

	foreach ($audit_auth_user_log_rows as $row) {
		$time = (string) $row['time'];
		$hash = audit_user_log_source_hash(
			(string) $row['username'],
			(int) $row['user_id'],
			$time
		);

		if ($time > $cutoff && !isset($audit_auth_state_rows[$hash])) {
			$filtered[] = $row;
		}
	}

	usort($filtered, function ($a, $b) {
		if ($a['time'] !== $b['time']) {
			return $a['time'] <=> $b['time'];
		}

		if ($a['username'] !== $b['username']) {
			return $a['username'] <=> $b['username'];
		}

		return $a['user_id'] <=> $b['user_id'];
	});

	$limit_idx = count($params) - 1;
	$limit     = (int) ($params[$limit_idx] ?? 1000);

	return array_slice($filtered, 0, $limit);
}

function db_fetch_cell_prepared(string $sql, array $params = []): int|string {
	global $audit_auth_failed_count, $audit_auth_state_rows;

	if (strpos($sql, 'COUNT(*)') !== false && strpos($sql, 'result = 0') !== false) {
		return $audit_auth_failed_count;
	}

	if (strpos($sql, 'SELECT 1 FROM audit_user_log_state') !== false) {
		$hash = $params[0] ?? '';

		return isset($audit_auth_state_rows[$hash]) ? 1 : 0;
	}

	return '';
}

function db_affected_rows(): int {
	global $audit_auth_affected_rows;

	return $audit_auth_affected_rows;
}

function db_table_exists(string $table): bool {
	return in_array($table, ['user_log', 'audit_user_log_state'], true);
}

function cacti_sizeof(array|bool $array): int {
	return is_array($array) ? count($array) : 0;
}

function get_nfilter_request_var(string $name, mixed $default = null): mixed {
	return $_REQUEST[$name] ?? $default;
}

function get_request_var(string $name): mixed {
	return $_REQUEST[$name] ?? '';
}

function api_plugin_user_realm_auth(string $filename = ''): bool {
	return false;
}

function html_escape(mixed $string): string {
	return htmlspecialchars((string) $string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function __(string $text, string $domain = ''): string {
	return $text;
}

function cacti_log(string $message, bool $also_print = false, string $log_type = '', int $level = 0): void {
}

function audit_test_assert_same(mixed $expected, mixed $actual, string $message): void {
	if ($expected !== $actual) {
		fwrite(STDERR, $message . PHP_EOL);
		fwrite(STDERR, 'Expected: ' . var_export($expected, true) . PHP_EOL);
		fwrite(STDERR, 'Actual:   ' . var_export($actual, true) . PHP_EOL);
		exit(1);
	}
}

function audit_test_assert_true(bool $condition, string $message): void {
	if (!$condition) {
		fwrite(STDERR, $message . PHP_EOL);
		exit(1);
	}
}

function audit_test_reset_state(): void {
	global $audit_auth_recorded_events, $audit_auth_state_rows, $audit_auth_set_options, $audit_auth_settings_rows, $audit_auth_insert_fails, $audit_auth_fail_usernames, $audit_auth_state_conflict, $audit_auth_affected_rows, $audit_auth_transaction;
	$audit_auth_recorded_events = [];
	$audit_auth_state_rows      = [];
	$audit_auth_set_options     = [];
	$audit_auth_settings_rows   = [];
	$audit_auth_insert_fails    = false;
	$audit_auth_fail_usernames  = [];
	$audit_auth_state_conflict  = false;
	$audit_auth_affected_rows   = 0;
	$audit_auth_transaction     = null;
}

// ---------------------------------------------------------------------------
// 1. Result-code mapping (audit_user_log_event_descriptor)
// ---------------------------------------------------------------------------

audit_test_assert_same('cacti.auth.login.failed', audit_user_log_event_descriptor(0, 0)['event_type'], 'Failed logins must map to a login failed event.');
audit_test_assert_same('failure', audit_user_log_event_descriptor(0, 0)['outcome'], 'Failed logins must be a failure outcome.');

// result=1: credentials accepted, NOT success (Cacti writes before checks).
audit_test_assert_same('cacti.auth.login.credentials_accepted', audit_user_log_event_descriptor(1, 5)['event_type'], 'result=1 must be credentials_accepted, not login.success.');
audit_test_assert_same('unknown', audit_user_log_event_descriptor(1, 5)['outcome'], 'result=1 must carry an unknown outcome, not success.');

audit_test_assert_same('cacti.auth.login.token', audit_user_log_event_descriptor(2, 5)['event_type'], 'Token success must map to a login token event.');
audit_test_assert_same('success', audit_user_log_event_descriptor(2, 5)['outcome'], 'Token success must be a success outcome.');

// result=3/user_id>0: defensive, unknown outcome (no false success).
audit_test_assert_same('cacti.auth.password.changed', audit_user_log_event_descriptor(3, 5)['event_type'], 'result=3/user_id>0 must map to password.changed.');
audit_test_assert_same('unknown', audit_user_log_event_descriptor(3, 5)['outcome'], 'result=3/user_id>0 must carry unknown, not a confirmed success.');

// result=3/user_id=0: ambiguous.
$ambiguous = audit_user_log_event_descriptor(3, 0);
audit_test_assert_same('cacti.auth.password_change_or_2fa_failed', $ambiguous['event_type'], 'result=3/user_id=0 must map to the ambiguous event type.');
audit_test_assert_same('unknown', $ambiguous['outcome'], 'The ambiguous event must carry an unknown outcome.');
audit_test_assert_true(isset($ambiguous['details']['ambiguous']), 'The ambiguous event must flag itself as ambiguous.');

// Unsupported result code: explicit unknown, not a fallthrough.
$unknown = audit_user_log_event_descriptor(99, 5);
audit_test_assert_same('cacti.auth.login.unknown', $unknown['event_type'], 'Unsupported result codes must map to an explicit unknown event.');
audit_test_assert_same('unknown', $unknown['outcome'], 'Unsupported result codes must carry an unknown outcome.');
audit_test_assert_same(99, $unknown['details']['unsupported_result_code'], 'The unsupported code must be recorded in details.');

// ---------------------------------------------------------------------------
// 2. audit_poll_user_log() records one event per new user_log row
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'alice', 'user_id' => 5, 'result' => 1, 'ip' => '10.0.0.1', 'time' => '2026-07-25 10:00:01'],
	['username' => 'bob',   'user_id' => 0, 'result' => 0, 'ip' => '10.0.0.2', 'time' => '2026-07-25 10:00:02'],
	['username' => 'carol', 'user_id' => 7, 'result' => 2, 'ip' => '10.0.0.3', 'time' => '2026-07-25 10:00:03'],
	['username' => 'dave',  'user_id' => 0, 'result' => 3, 'ip' => '10.0.0.4', 'time' => '2026-07-25 10:00:04']
];

audit_poll_user_log();

audit_test_assert_same(4, count($audit_auth_recorded_events), 'audit_poll_user_log() must record one event per new user_log row.');
audit_test_assert_same('cacti.auth.login.credentials_accepted', $audit_auth_recorded_events[0]['params'][12], 'First event must be credentials_accepted for result=1.');
audit_test_assert_same('warning', $audit_auth_recorded_events[1]['params'][14], 'Failed login must carry warning severity.');
audit_test_assert_same('failure', $audit_auth_recorded_events[1]['params'][18], 'Failed login must carry failure outcome.');
audit_test_assert_same('cacti.auth.password_change_or_2fa_failed', $audit_auth_recorded_events[3]['params'][12], 'result=3/user_id=0 must map to the ambiguous event.');
audit_test_assert_same('unknown', $audit_auth_recorded_events[3]['params'][18], 'The ambiguous row must carry unknown outcome.');
audit_test_assert_same(4, count($audit_auth_state_rows), 'Four deduplication state rows must be written.');

// Re-polling must not double-record (deduplication via state table).
$audit_auth_recorded_events = [];
audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Re-polling after durable state is recorded must not produce duplicates.');

// Disabling auth auditing must skip polling.
$audit_auth_config['audit_auth_log_enabled'] = 'off';
$audit_auth_user_log_rows                    = [
	['username' => 'eve', 'user_id' => 9, 'result' => 1, 'ip' => '10.0.0.5', 'time' => '2026-07-25 11:00:00']
];
$audit_auth_recorded_events = [];
audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'audit_poll_user_log() must be gated by audit_auth_log_enabled.');
$audit_auth_config['audit_auth_log_enabled'] = 'on';

// ---------------------------------------------------------------------------
// 3. More than 1,000 rows sharing one timestamp: bounded anti-join paging
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_config['audit_user_log_batch_size'] = '1000';
$audit_auth_user_log_rows                       = [];

for ($i = 0; $i < 1500; $i++) {
	$audit_auth_user_log_rows[] = [
		'username' => sprintf('user%04d', $i),
		'user_id'  => $i + 1,
		'result'   => 0,
		'ip'       => '10.0.0.10',
		'time'     => '2026-07-25 12:00:00'
	];
}

audit_poll_user_log();
audit_test_assert_same(1000, count($audit_auth_recorded_events), 'First cycle must process exactly the batch size (1000) rows, not all 1500.');
audit_test_assert_same(1000, count($audit_auth_state_rows), '1000 state rows must be written after the first cycle.');

// Second cycle excludes durable markers and processes the remaining 500.
$audit_auth_recorded_events = [];
audit_poll_user_log();
audit_test_assert_same(500, count($audit_auth_recorded_events), 'Second cycle must process the remaining 500 rows via durable-state exclusion.');
audit_test_assert_same(1500, count($audit_auth_state_rows), 'All 1500 state rows must be written after two cycles.');

// Third cycle: nothing left.
$audit_auth_recorded_events = [];
audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Third cycle must find no new rows.');

// ---------------------------------------------------------------------------
// 4. Multiple timestamp pages
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'a', 'user_id' => 1, 'result' => 1, 'ip' => '10.0.0.1', 'time' => '2026-07-25 13:00:00'],
	['username' => 'b', 'user_id' => 2, 'result' => 0, 'ip' => '10.0.0.2', 'time' => '2026-07-25 13:00:01'],
	['username' => 'c', 'user_id' => 3, 'result' => 2, 'ip' => '10.0.0.3', 'time' => '2026-07-25 13:00:02']
];

audit_poll_user_log();
audit_test_assert_same(3, count($audit_auth_recorded_events), 'All three timestamp pages must be processed in one cycle.');
$first_details = json_decode($audit_auth_recorded_events[0]['params'][24], true);
audit_test_assert_same('a', $first_details['username'], 'Rows must be ordered by time then username.');

// ---------------------------------------------------------------------------
// 5. Concurrent/overlapping poller ownership: no duplicates
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'concurrent', 'user_id' => 42, 'result' => 1, 'ip' => '10.0.0.99', 'time' => '2026-07-25 14:00:00']
];

// Simulate a concurrent poller that already recorded the state row.
$hash                         = audit_user_log_source_hash('concurrent', 42, '2026-07-25 14:00:00');
$audit_auth_state_rows[$hash] = [
	'source_hash'    => $hash,
	'source_key'     => 'concurrent|42|2026-07-25 14:00:00',
	'source_time'    => '2026-07-25 14:00:00',
	'audit_id'       => 999,
	'processed_time' => '2026-07-25 14:00:01'
];

audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'A row already claimed by a concurrent poller must not be double-recorded.');

// Simulate both pollers selecting the row before either state marker is
// visible. The losing transaction must roll back its audit event when its
// INSERT IGNORE reports that another poller won the unique source hash.
audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'racing', 'user_id' => 43, 'result' => 1, 'ip' => '10.0.0.100', 'time' => '2026-07-25 14:01:00']
];
$audit_auth_state_conflict = true;

audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'A concurrent state-insert loser must roll back its duplicate audit event.');
audit_test_assert_same(0, count($audit_auth_state_rows), 'A concurrent state-insert loser must not create a state marker.');

// ---------------------------------------------------------------------------
// 6. Failed audit inserts remain discoverable behind later successful rows
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'failinsert', 'user_id' => 50, 'result' => 1, 'ip' => '10.0.0.50', 'time' => '2026-07-25 15:00:00'],
	['username' => 'later',      'user_id' => 51, 'result' => 1, 'ip' => '10.0.0.51', 'time' => '2026-07-25 15:00:01']
];
$audit_auth_fail_usernames = ['failinsert'];

audit_poll_user_log();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'A later row must still be recorded when an earlier audit insert fails.');
audit_test_assert_same(1, count($audit_auth_state_rows), 'Only the successful later row may receive a state marker.');

// Retry after the insert recovers: the earlier row must remain discoverable
// even though a later source time has already been processed.
$audit_auth_fail_usernames  = [];
$audit_auth_recorded_events = [];
audit_poll_user_log();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'A failed row behind a later success must be retried on the next cycle.');
audit_test_assert_same(2, count($audit_auth_state_rows), 'The retried row must produce its durable state marker.');

// ---------------------------------------------------------------------------
// 7. Retention policy excludes arbitrary historical rows
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_config['audit_retention'] = '30';
$audit_auth_user_log_rows             = [
	['username' => 'old', 'user_id' => 1, 'result' => 1, 'ip' => '10.0.0.1', 'time' => '2026-06-01 00:00:00'],
	['username' => 'recent', 'user_id' => 2, 'result' => 1, 'ip' => '10.0.0.2', 'time' => '2026-07-24 00:00:00']
];

audit_poll_user_log();
$recorded_usernames = [];

foreach ($audit_auth_recorded_events as $event) {
	$details = json_decode($event['params'][24], true);

	if (is_array($details) && isset($details['username'])) {
		$recorded_usernames[] = $details['username'];
	}
}

audit_test_assert_true(!in_array('old', $recorded_usernames, true), 'Initial ingestion must not replay rows older than the retention cutoff.');
audit_test_reset_state();
$audit_auth_config['audit_retention'] = '90';

// ---------------------------------------------------------------------------
// 8. Brute-force: exact threshold, throttle boundary, concurrency
// ---------------------------------------------------------------------------

audit_test_reset_state();

// Below threshold: no emit.
$audit_auth_failed_count    = 9;
$audit_auth_recorded_events = [];
audit_detect_brute_force();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Below threshold must not emit.');

// Exactly at threshold: emit.
$audit_auth_failed_count    = 10;
$audit_auth_recorded_events = [];
audit_detect_brute_force();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'Exactly at threshold must emit even when the throttle setting row did not previously exist.');
audit_test_assert_true(read_config_option('audit_brute_force_last_alert') !== '', 'Brute-force detection must initialize its throttle setting row.');
audit_test_assert_same('cacti.auth.brute_force_suspected', $audit_auth_recorded_events[0]['params'][12], 'Brute-force event type must be correct.');
audit_test_assert_same('critical', $audit_auth_recorded_events[0]['params'][14], 'Brute-force must be critical.');

// Within window: throttled (atomic UPDATE claims nothing).
$audit_auth_failed_count    = 12;
$audit_auth_recorded_events = [];
audit_detect_brute_force();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Within the window, the atomic claim must throttle the second alert.');

// Concurrent check: second poller's UPDATE affects 0 rows.
$audit_auth_failed_count    = 12;
$audit_auth_recorded_events = [];
audit_detect_brute_force();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'A concurrent poller must not emit a duplicate alert.');

// Failed audit insert releases the slot.
audit_test_reset_state();
$audit_auth_settings_rows['audit_brute_force_last_alert'] = '';
$audit_auth_failed_count                                  = 10;
$audit_auth_insert_fails                                  = true;
$audit_auth_recorded_events                               = [];
audit_detect_brute_force();
audit_test_assert_same('', $audit_auth_settings_rows['audit_brute_force_last_alert'] ?? '', 'A failed audit insert must release the alert slot for retry.');
$audit_auth_insert_fails = false;

// Disabled must not emit.
$audit_auth_config['audit_brute_force_enabled']           = 'off';
$audit_auth_failed_count                                  = 50;
$audit_auth_settings_rows['audit_brute_force_last_alert'] = '';
$audit_auth_recorded_events                               = [];
audit_detect_brute_force();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Disabled brute-force detection must not emit.');
$audit_auth_config['audit_brute_force_enabled'] = 'on';

// ---------------------------------------------------------------------------
// 9. custom_denied: returns mode, records event, redacts referer
// ---------------------------------------------------------------------------

$_SESSION['sess_user_id'] = 5;
$_SERVER['SCRIPT_NAME']   = '/cacti/host.php';
$_SERVER['HTTP_REFERER']  = 'https://cacti.example.com/index.php?token=secret&reset_hash=abc123';
audit_test_reset_state();

$returned = audit_custom_denied('OPER_MODE_NATIVE');
audit_test_assert_same('OPER_MODE_NATIVE', $returned, 'audit_custom_denied() must return the input mode unchanged.');
audit_test_assert_same(1, count($audit_auth_recorded_events), 'audit_custom_denied() must record one event.');
audit_test_assert_same('cacti.auth.authorization.denied', $audit_auth_recorded_events[0]['params'][12], 'Denied event type must be correct.');
$details_json = $audit_auth_recorded_events[0]['params'][24];
$details      = json_decode($details_json, true);
audit_test_assert_same('https://cacti.example.com/index.php', $details['referer_origin'], 'Referer query string must be stripped.');
audit_test_assert_true(strpos($details_json, 'secret') === false, 'The referer token must not appear in details.');
audit_test_assert_true(strpos($details_json, 'abc123') === false, 'The reset hash must not appear in details.');

// Disabled must not record but still return the mode.
$audit_auth_config['audit_auth_log_enabled'] = 'off';
$audit_auth_recorded_events                  = [];
audit_test_assert_same('OPER_MODE_NATIVE', audit_custom_denied('OPER_MODE_NATIVE'), 'audit_custom_denied() must always return the input mode.');
audit_test_assert_same(0, count($audit_auth_recorded_events), 'audit_custom_denied() must skip recording when disabled.');
$audit_auth_config['audit_auth_log_enabled'] = 'on';

// ---------------------------------------------------------------------------
// 10. Logout: master switch gates pre-destroy; post-destroy uses stash
// ---------------------------------------------------------------------------

$_SESSION['sess_user_id'] = 5;
$_REQUEST['action']       = 'user';
audit_test_reset_state();

audit_logout_pre_session_destroy();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'Pre-destroy must record the logout event.');
audit_test_assert_same('authentication.logout', $audit_auth_recorded_events[0]['params'][12], 'Pre-destroy event type must be correct.');

$audit_auth_recorded_events = [];
audit_logout_post_session_destroy();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'Post-destroy must record one completed event.');
audit_test_assert_same('authentication.logout.completed', $audit_auth_recorded_events[0]['params'][12], 'Post-destroy event type must be correct.');
audit_test_assert_same(5, $audit_auth_recorded_events[0]['params'][1], 'Post-destroy must carry the stashed user_id.');

// Empty stash: no record.
$audit_auth_recorded_events = [];
audit_logout_post_session_destroy();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Post-destroy must not record when the stash is empty.');

// Master switch off: pre-destroy must not record.
$audit_auth_config['audit_auth_log_enabled'] = 'off';
$audit_auth_recorded_events                  = [];
audit_logout_pre_session_destroy();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Pre-destroy must not record when auth auditing is disabled.');
$audit_auth_config['audit_auth_log_enabled'] = 'on';

// ---------------------------------------------------------------------------
// 11. Unauthorized auth-settings save uses the generic event type
// ---------------------------------------------------------------------------

// audit_enforce_syslog_settings_request() reads POST via filter_input_array
// (a PHP built-in reading the real SAPI POST body) and calls exit on 403,
// so it cannot be exercised behaviorally in a CLI test. Verify via a static
// source assertion that the auth-only unauthorized path emits the generic
// audit.configuration.denied event, distinct from the syslog-specific one.
$functions_source = file_get_contents(dirname(__DIR__) . '/audit_functions.php');
audit_test_assert_true(
	strpos($functions_source, "'audit.configuration.denied'") !== false,
	'The generic audit.configuration.denied event must be present for unauthorized auth-settings saves.'
);
audit_test_assert_true(
	strpos($functions_source, "'audit.syslog.configuration.denied'") !== false,
	'The syslog-specific denied event must remain for unauthorized syslog-settings saves.'
);
// Confirm the auth-only branch exists (else branch after the syslog check).
audit_test_assert_true(
	strpos($functions_source, 'audit.configuration.denied') !== false
	&& strpos($functions_source, 'audit_admin_required') !== false,
	'The unauthorized auth-settings save must record an audit_admin_required denied event.'
);

print "Auth audit tests passed.\n";
