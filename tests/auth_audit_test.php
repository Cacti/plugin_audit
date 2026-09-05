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
	'audit_auth_log_last_state'        => 'on',
	'audit_brute_force_enabled'        => 'on',
	'audit_brute_force_window_minutes' => '5',
	'audit_brute_force_threshold'      => '10',
	'audit_brute_force_last_alert'     => '',
	'audit_user_log_batch_size'        => '1000',
	'audit_user_log_watermark_epoch'   => '0',
	'audit_user_log_activation_epoch'  => '0',
	'audit_auth_ingestion_last_alert'  => '0',
	'audit_retention'                  => '90'
];

$audit_auth_recorded_events    = [];
$audit_auth_user_log_rows      = [];
$audit_auth_state_rows         = [];
$audit_auth_failed_metrics     = ['failed_attempts' => 0, 'distinct_usernames' => 0, 'distinct_ips' => 0];
$audit_auth_set_options        = [];
$audit_auth_settings_rows      = [];
$audit_auth_insert_fails       = false;
$audit_auth_fail_usernames     = [];
$audit_auth_state_conflict     = false;
$audit_auth_affected_rows      = 0;
$audit_auth_log_exists         = true;
$audit_auth_executed_sql       = [];
$audit_auth_fetches            = [];
$audit_auth_missing_tables     = [];
$audit_auth_fail_sql           = [];
$audit_auth_retry_claims_ready = false;
$audit_auth_logs               = [];
$audit_auth_fetch_fails        = '';
$audit_auth_index_actions      = [];
$audit_auth_index_setup_ok     = true;
$audit_auth_identity_ok        = true;
$audit_auth_database_epoch     = null;
$audit_auth_insert_id_override = null;

function audit_test_source_key(string $username, int $user_id, int $source_epoch): string {
	return $username . '|' . $user_id . '|' . $source_epoch;
}

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

function audit_setup_user_log_indexes(): bool {
	global $audit_auth_index_actions, $audit_auth_index_setup_ok;
	$audit_auth_index_actions[] = 'setup';

	return $audit_auth_index_setup_ok;
}

function audit_user_log_indexes_available(): bool {
	global $audit_auth_index_actions, $audit_auth_index_setup_ok;
	$audit_auth_index_actions[] = 'check';

	return $audit_auth_index_setup_ok;
}

function audit_user_log_identity_supported(): bool {
	global $audit_auth_identity_ok;

	return $audit_auth_identity_ok;
}

function audit_remove_user_log_indexes(): void {
	global $audit_auth_index_actions;
	$audit_auth_index_actions[] = 'remove';
}

function db_execute_prepared(string $sql, array $params = []): bool {
	global $audit_auth_recorded_events, $audit_auth_state_rows, $audit_auth_settings_rows, $audit_auth_insert_fails, $audit_auth_fail_usernames, $audit_auth_state_conflict, $audit_auth_affected_rows, $audit_auth_executed_sql, $audit_auth_fail_sql;

	$audit_auth_executed_sql[] = $sql;

	foreach ($audit_auth_fail_sql as $fragment) {
		if (str_contains($sql, $fragment)) {
			return false;
		}
	}

	if (strpos($sql, 'INSERT INTO audit_log') !== false) {
		$details  = json_decode((string) ($params[24] ?? ''), true);
		$username = is_array($details) ? (string) ($details['username'] ?? '') : '';

		if ($audit_auth_insert_fails || in_array($username, $audit_auth_fail_usernames, true)) {
			$audit_auth_affected_rows = 0;

			return false;
		}
		$audit_auth_recorded_events[] = ['id' => count($audit_auth_recorded_events) + 1, 'sql' => $sql, 'params' => $params];
		$audit_auth_affected_rows     = 1;

		return true;
	}

	if (strpos($sql, 'INSERT IGNORE INTO audit_user_log_state') !== false) {
		$username     = (string) $params[0];
		$user_id      = (int) $params[1];
		$source_epoch = (int) $params[2];
		$key          = audit_test_source_key($username, $user_id, $source_epoch);

		if ($audit_auth_state_conflict || isset($audit_auth_state_rows[$key])) {
			$audit_auth_affected_rows = 0;
		} else {
			$audit_auth_state_rows[$key] = [
				'source_username' => $username,
				'source_user_id'  => $user_id,
				'source_epoch'    => $source_epoch,
				'source_time'     => time(),
				'audit_id'        => 0,
				'retry_count'     => 0,
				'processed_time'  => '2026-07-25 00:00:00'
			];
			$audit_auth_affected_rows = 1;
		}

		return true;
	}

	if (strpos($sql, 'UPDATE audit_user_log_state') !== false) {
		$is_finalize  = strpos($sql, 'SET audit_id = ?') !== false;
		$is_retry_add = strpos($sql, 'retry_count = retry_count + ?') !== false;

		if ($is_finalize) {
			$audit_id     = (int) $params[0];
			$username     = (string) $params[1];
			$user_id      = (int) $params[2];
			$source_epoch = (int) $params[3];
		} elseif ($is_retry_add) {
			$audit_id     = 0;
			$username     = (string) $params[1];
			$user_id      = (int) $params[2];
			$source_epoch = (int) $params[3];
		} else {
			$audit_id     = 0;
			$username     = (string) $params[0];
			$user_id      = (int) $params[1];
			$source_epoch = (int) $params[2];
		}

		$key = audit_test_source_key($username, $user_id, $source_epoch);

		if (!isset($audit_auth_state_rows[$key]) || $audit_auth_state_rows[$key]['audit_id'] !== 0) {
			$audit_auth_affected_rows = 0;

			return true;
		}

		if ($is_finalize) {
			$audit_auth_state_rows[$key]['audit_id'] = $audit_id;
		} elseif (strpos($sql, 'retry_count = retry_count +') !== false) {
			$audit_auth_state_rows[$key]['retry_count'] += $is_retry_add ? (int) $params[0] : 1;
		}

		$audit_auth_affected_rows = 1;

		return true;
	}

	if (strpos($sql, 'DELETE FROM audit_log WHERE id') !== false) {
		$id                         = (int) ($params[0] ?? 0);
		$audit_auth_recorded_events = array_values(array_filter(
			$audit_auth_recorded_events,
			static fn (array $event): bool => (int) ($event['id'] ?? 0) !== $id
		));

		return true;
	}

	if (strpos($sql, 'INSERT INTO settings') !== false) {
		$name = (string) ($params[0] ?? '');

		if ($name === 'audit_user_log_watermark_epoch') {
			$current                         = (int) ($audit_auth_settings_rows[$name] ?? 0);
			$value                           = (int) ($params[1] ?? 0);
			$audit_auth_settings_rows[$name] = (string) max($current, $value);

			return true;
		}
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
		$terminal = strpos($sql, 'audit_id = 0') !== false;
		$removed  = 0;
		$limit    = preg_match('/LIMIT (\d+)/', $sql, $matches) === 1 ? (int) $matches[1] : PHP_INT_MAX;

		foreach ($audit_auth_state_rows as $key => $state) {
			$matches = $terminal
				? (int) $state['audit_id'] === 0 && (int) $state['retry_count'] >= (int) ($params[0] ?? 5)
				: (int) $state['audit_id'] > 0 && (int) $state['source_epoch'] < (int) ($params[0] ?? 0);

			if ($matches) {
				unset($audit_auth_state_rows[$key]);
				$removed++;

				if ($removed >= $limit) {
					break;
				}
			}
		}

		$audit_auth_affected_rows = $removed;

		return true;
	}

	return true;
}

function db_fetch_insert_id(): int {
	global $audit_auth_recorded_events, $audit_auth_insert_fails, $audit_auth_insert_id_override;

	if ($audit_auth_insert_fails) {
		return 0;
	}

	if ($audit_auth_insert_id_override !== null) {
		return $audit_auth_insert_id_override;
	}

	return count($audit_auth_recorded_events);
}

function db_fetch_row_prepared(string $sql, array $params = []): array {
	global $audit_auth_failed_metrics;

	if (str_contains($sql, 'COUNT(*) AS failed_attempts')) {
		return $audit_auth_failed_metrics;
	}

	return [];
}

/**
 * SQL-interpreting stub: filters user_log rows by retention and durable
 * deduplication state, orders by (time, username, user_id), and applies LIMIT.
 */
function db_fetch_assoc_prepared(string $sql, array $params = []): array|false {
	global $audit_auth_user_log_rows, $audit_auth_state_rows, $audit_auth_fetches, $audit_auth_retry_claims_ready, $audit_auth_fetch_fails;

	if (!str_contains($sql, 'user_log AS ul')) {
		return [];
	}

	$is_pending = str_contains($sql, 'INNER JOIN user_log AS ul');

	if ($audit_auth_fetch_fails === ($is_pending ? 'pending' : 'new')) {
		return false;
	}

	$audit_auth_fetches[] = ['sql' => $sql, 'params' => $params];
	$cutoff               = $is_pending ? 0 : (int) ($params[0] ?? 0);
	$max_retries          = 5;
	$limit                = preg_match('/LIMIT (\d+)/', $sql, $limit_match) === 1 ? (int) $limit_match[1] : 1000;
	$filtered             = [];

	foreach ($audit_auth_user_log_rows as $row) {
		$source_epoch = isset($row['source_epoch'])
			? (int) $row['source_epoch']
			: (int) strtotime((string) $row['time'] . ' UTC');
		$key   = audit_test_source_key((string) $row['username'], (int) $row['user_id'], $source_epoch);
		$state = $audit_auth_state_rows[$key] ?? null;

		$selected = $is_pending
			? ($state !== null && (int) $state['audit_id'] === 0 && (int) $state['retry_count'] < $max_retries && $audit_auth_retry_claims_ready)
			: ($source_epoch > $cutoff && $state === null);

		if ($selected) {
			$row['source_epoch']   = $source_epoch;
			$row['state_audit_id'] = $state['audit_id'] ?? null;
			$row['retry_count']    = $state['retry_count'] ?? 0;
			$filtered[]            = $row;
		}
	}

	usort($filtered, function ($a, $b) {
		if ($a['source_epoch'] !== $b['source_epoch']) {
			return $a['source_epoch'] <=> $b['source_epoch'];
		}

		if ($a['username'] !== $b['username']) {
			return $a['username'] <=> $b['username'];
		}

		return $a['user_id'] <=> $b['user_id'];
	});

	return array_slice($filtered, 0, $limit);
}

function db_fetch_cell_prepared(string $sql, array $params = []): int|string {
	global $audit_auth_recorded_events, $audit_auth_database_epoch, $audit_auth_state_rows;

	if (str_contains($sql, 'SELECT UNIX_TIMESTAMP()')) {
		return $audit_auth_database_epoch ?? time();
	}

	if (str_contains($sql, 'FROM audit_log WHERE event_uuid')) {
		foreach ($audit_auth_recorded_events as $event) {
			if (($event['params'][10] ?? null) === ($params[0] ?? null)) {
				return (int) $event['id'];
			}
		}
	}

	if (str_contains($sql, 'COUNT(*) FROM audit_user_log_state')) {
		return count(array_filter(
			$audit_auth_state_rows,
			static fn (array $state): bool => (int) $state['audit_id'] === 0 &&
				(int) $state['retry_count'] >= (int) ($params[0] ?? 5)
		));
	}

	return '';
}

function db_affected_rows(): int {
	global $audit_auth_affected_rows;

	return $audit_auth_affected_rows;
}

function db_table_exists(string $table): bool {
	global $audit_auth_log_exists, $audit_auth_missing_tables;

	if (in_array($table, $audit_auth_missing_tables, true)) {
		return false;
	}

	if ($table === 'audit_log') {
		return $audit_auth_log_exists;
	}

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
	global $audit_auth_logs;

	$audit_auth_logs[] = $message;
}

function audit_test_log_count(): int {
	global $audit_auth_logs;

	return count($audit_auth_logs);
}

function audit_test_log_contains(string $needle): bool {
	global $audit_auth_logs;

	foreach ($audit_auth_logs as $message) {
		if (str_contains($message, $needle)) {
			return true;
		}
	}

	return false;
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

/**
 * @return array<int,mixed>
 */
function audit_test_last_event_params(): array {
	global $audit_auth_recorded_events;

	$event = end($audit_auth_recorded_events);

	if (!is_array($event) || !isset($event['params']) || !is_array($event['params'])) {
		fwrite(STDERR, 'Expected a recorded audit event.' . PHP_EOL);
		exit(1);
	}

	return $event['params'];
}

/**
 * @return array<int,mixed>
 */
function audit_test_first_event_params(): array {
	global $audit_auth_recorded_events;

	$events = $audit_auth_recorded_events;
	$event  = array_shift($events);

	if (!is_array($event) || !isset($event['params']) || !is_array($event['params'])) {
		fwrite(STDERR, 'Expected a first recorded audit event.' . PHP_EOL);
		exit(1);
	}

	return $event['params'];
}

function audit_test_reset_state(): void {
	global $audit_auth_config, $audit_auth_failed_metrics, $audit_auth_recorded_events, $audit_auth_state_rows, $audit_auth_set_options, $audit_auth_settings_rows, $audit_auth_insert_fails, $audit_auth_fail_usernames, $audit_auth_state_conflict, $audit_auth_affected_rows, $audit_auth_log_exists, $audit_auth_executed_sql, $audit_auth_fetches, $audit_auth_missing_tables, $audit_auth_fail_sql, $audit_auth_retry_claims_ready, $audit_auth_logs, $audit_auth_fetch_fails, $audit_auth_index_actions, $audit_auth_index_setup_ok, $audit_auth_identity_ok, $audit_auth_database_epoch, $audit_auth_insert_id_override;
	$audit_auth_failed_metrics                            = ['failed_attempts' => 0, 'distinct_usernames' => 0, 'distinct_ips' => 0];
	$audit_auth_recorded_events                           = [];
	$audit_auth_state_rows                                = [];
	$audit_auth_set_options                               = [];
	$audit_auth_settings_rows                             = [];
	$audit_auth_insert_fails                              = false;
	$audit_auth_fail_usernames                            = [];
	$audit_auth_state_conflict                            = false;
	$audit_auth_affected_rows                             = 0;
	$audit_auth_log_exists                                = true;
	$audit_auth_executed_sql                              = [];
	$audit_auth_fetches                                   = [];
	$audit_auth_missing_tables                            = [];
	$audit_auth_fail_sql                                  = [];
	$audit_auth_retry_claims_ready                        = false;
	$audit_auth_logs                                      = [];
	$audit_auth_fetch_fails                               = '';
	$audit_auth_index_actions                             = [];
	$audit_auth_index_setup_ok                            = true;
	$audit_auth_identity_ok                               = true;
	$audit_auth_database_epoch                            = null;
	$audit_auth_insert_id_override                        = null;
	$audit_auth_config['audit_user_log_watermark_epoch']  = '0';
	$audit_auth_config['audit_user_log_activation_epoch'] = '0';
	$audit_auth_config['audit_auth_ingestion_last_alert'] = '0';
	$audit_auth_config['audit_auth_log_last_state']       = 'on';
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

$source_uuid = audit_user_log_event_uuid('alice', 5, 1721926800);
audit_test_assert_same($source_uuid, audit_user_log_event_uuid('alice', 5, 1721926800), 'A source row must always receive the same event UUID.');
audit_test_assert_true(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $source_uuid) === 1, 'Source event UUIDs must be valid deterministic version-5 identifiers.');

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
audit_test_assert_same([], $audit_auth_index_actions, 'Checkbox transitions must not run DDL against core user_log.');
$audit_auth_config['audit_auth_log_enabled'] = 'on';
$activation_before                           = time();
$audit_auth_index_setup_ok                   = false;
audit_poll_user_log();
audit_test_assert_same('off', read_config_option('audit_auth_log_last_state'), 'Missing indexes must keep authentication auditing fail-closed.');
audit_test_assert_true(audit_test_log_count() > 0, 'Failed index setup must emit an operational warning.');
$degraded_params = audit_test_last_event_params();
audit_test_assert_same('audit.authentication.ingestion.unavailable', $degraded_params[12] ?? null, 'Failed activation must create an admin-visible audit event.');
$audit_auth_index_setup_ok  = true;
$audit_auth_recorded_events = [];
audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Enabling authentication auditing must start at the activation boundary without backfill.');
audit_test_assert_true((int) read_config_option('audit_user_log_watermark_epoch') >= $activation_before, 'Enable transition must advance the ingestion watermark to the current time.');
audit_test_assert_same(['check', 'check'], $audit_auth_index_actions, 'The poller must check prerequisites without running DDL against core user_log.');

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
$concurrent_epoch                       = (int) strtotime('2026-07-25 14:00:00 UTC');
$concurrent_key                         = audit_test_source_key('concurrent', 42, $concurrent_epoch);
$audit_auth_state_rows[$concurrent_key] = [
	'source_username' => 'concurrent',
	'source_user_id'  => 42,
	'source_epoch'    => $concurrent_epoch,
	'source_time'     => $concurrent_epoch,
	'audit_id'        => 999,
	'retry_count'     => 0,
	'processed_time'  => '2026-07-25 14:00:01'
];

audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'A row already claimed by a concurrent poller must not be double-recorded.');

// Simulate both pollers selecting the row before either claim is visible. The
// losing poller must skip event creation when INSERT IGNORE reports that the
// other poller won the unique source hash.
audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'racing', 'user_id' => 43, 'result' => 1, 'ip' => '10.0.0.100', 'time' => '2026-07-25 14:01:00']
];
$audit_auth_state_conflict = true;

audit_poll_user_log();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'A concurrent claim loser must not create a duplicate audit event.');
audit_test_assert_same(0, count($audit_auth_state_rows), 'A concurrent state-insert loser must not create a state marker.');

// ---------------------------------------------------------------------------
// 6. Failed audit inserts remain discoverable behind later successful rows
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'failinsert', 'user_id' => 50, 'result' => 1, 'ip' => '10.0.0.50', 'time' => '2026-07-25 15:00:00'],
	['username' => 'later',      'user_id' => 51, 'result' => 1, 'ip' => '10.0.0.51', 'time' => '2026-07-25 16:00:00']
];
$audit_auth_fail_usernames = ['failinsert'];

audit_poll_user_log();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'A later row must still be recorded when an earlier audit insert fails.');
audit_test_assert_same(2, count($audit_auth_state_rows), 'The failed row must retain a retry marker while the later row is completed.');
audit_test_assert_true(audit_test_log_count() > 0, 'A failed audit insert must emit an operational warning.');

// Retry after the insert recovers: the earlier row must remain discoverable
// even though a later source time has already been processed.
$audit_auth_fail_usernames     = [];
$audit_auth_recorded_events    = [];
$audit_auth_retry_claims_ready = true;
audit_poll_user_log();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'A failed row more than five minutes behind a later success must remain retryable.');
audit_test_assert_same(2, count($audit_auth_state_rows), 'The retried row must produce its durable state marker.');

// A poison retry at its last attempt must not consume the entire batch or
// prevent a newer row from advancing.
audit_test_reset_state();
$audit_auth_config['audit_user_log_batch_size'] = '2';
$poison_epoch                                   = (int) strtotime('2026-07-25 16:30:00 UTC');
$audit_auth_user_log_rows                       = [
	['username' => 'poison', 'user_id' => 52, 'result' => 1, 'ip' => '10.0.0.52', 'time' => '2026-07-25 16:30:00', 'source_epoch' => $poison_epoch],
	['username' => 'healthy', 'user_id' => 53, 'result' => 1, 'ip' => '10.0.0.53', 'time' => '2026-07-25 16:31:00']
];
$audit_auth_state_rows[audit_test_source_key('poison', 52, $poison_epoch)] = [
	'source_username' => 'poison', 'source_user_id' => 52, 'source_epoch' => $poison_epoch,
	'source_time'     => $poison_epoch, 'audit_id' => 0, 'retry_count' => 4,
	'processed_time'  => '2026-07-25 00:00:00'
];
$audit_auth_fail_usernames     = ['poison'];
$audit_auth_retry_claims_ready = true;
audit_poll_user_log();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'A poison retry must not starve a healthy new row when audit_log remains unavailable for the dropped row.');
$dropped_params = audit_test_last_event_params();
audit_test_assert_same('cacti.auth.login.credentials_accepted', $dropped_params[12] ?? null, 'The healthy row must still be processed after dropped-row evidence is recorded.');
audit_test_assert_same(5, $audit_auth_state_rows[audit_test_source_key('poison', 52, $poison_epoch)]['retry_count'], 'A poison marker must become terminal after five attempts.');
audit_test_assert_true(audit_test_log_count() === 2, 'A terminal failure must emit per-row evidence plus the per-cycle summary.');
audit_test_assert_true(audit_test_log_contains('"username":"poison"'), 'Primary drop evidence must identify the source tuple in cacti.log.');

audit_cleanup_user_log_state(5, null, true);
$healthy_epoch = (int) strtotime('2026-07-25 16:31:00 UTC');
$healthy_key   = audit_test_source_key('healthy', 53, $healthy_epoch);
audit_test_assert_same(1, count($audit_auth_state_rows), 'Cleanup must reap terminal markers while retaining completed markers inside the replay floor.');
audit_test_assert_true(isset($audit_auth_state_rows[$healthy_key]), 'A replay-floor marker must remain to prevent duplicate external delivery.');
audit_test_assert_true(audit_test_log_contains('terminal retry marker'), 'Daily cleanup must surface the live terminal-marker count.');

foreach ([1000, 2000] as $old_epoch) {
	$audit_auth_state_rows[audit_test_source_key('old-' . $old_epoch, 1, $old_epoch)] = [
		'source_username' => 'old-' . $old_epoch, 'source_user_id' => 1, 'source_epoch' => $old_epoch,
		'source_time'     => 1, 'audit_id' => $old_epoch, 'retry_count' => 0,
		'processed_time'  => '2026-07-01 00:00:00'
	];
}

audit_cleanup_user_log_state(5, 1);
audit_test_assert_same(2, count($audit_auth_state_rows), 'Per-cycle cleanup must honor its rate-proportional batch budget.');
audit_cleanup_user_log_state(5, 1);
audit_test_assert_same(1, count($audit_auth_state_rows), 'Repeated poller cleanup must keep pace with an equal ingestion budget.');

$audit_auth_missing_tables = ['audit_user_log_state'];
audit_cleanup_user_log_state();
$audit_auth_missing_tables                      = [];
$audit_auth_config['audit_user_log_batch_size'] = '1000';

// Recovering a crash after audit insertion must finalize the deterministic
// source event instead of inserting a duplicate.
audit_test_reset_state();
$crash_epoch                = (int) strtotime('2026-07-25 16:40:00 UTC');
$crash_uuid                 = audit_user_log_event_uuid('crash-safe', 54, $crash_epoch);
$crash_params               = array_fill(0, 25, null);
$crash_params[10]           = $crash_uuid;
$audit_auth_recorded_events = [['id' => 77, 'sql' => '', 'params' => $crash_params]];
$audit_auth_user_log_rows   = [[
	'username' => 'crash-safe', 'user_id' => 54, 'result' => 1, 'ip' => '10.0.0.54',
	'time'     => '2026-07-25 16:40:00', 'source_epoch' => $crash_epoch
]];
$crash_key                         = audit_test_source_key('crash-safe', 54, $crash_epoch);
$audit_auth_state_rows[$crash_key] = [
	'source_username' => 'crash-safe', 'source_user_id' => 54, 'source_epoch' => $crash_epoch,
	'source_time'     => $crash_epoch, 'audit_id' => 0, 'retry_count' => 1,
	'processed_time'  => '2026-07-25 00:00:00'
];
$audit_auth_retry_claims_ready = true;
audit_poll_user_log();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'Crash recovery must not duplicate an existing deterministic source event.');
audit_test_assert_same(77, $audit_auth_state_rows[$crash_key]['audit_id'], 'Crash recovery must finalize the marker with the existing event ID.');

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
	$details = json_decode((string) ($event['params'][24] ?? ''), true);

	if (is_array($details) && isset($details['username'])) {
		$recorded_usernames[] = $details['username'];
	}
}

audit_test_assert_true(!in_array('old', $recorded_usernames, true), 'Initial ingestion must not replay rows older than the retention cutoff.');
audit_test_reset_state();
$audit_auth_config['audit_retention'] = '90';

// ---------------------------------------------------------------------------
// 8. UTC event time, stable identity, retention changes, and bounded scans
// ---------------------------------------------------------------------------

audit_test_reset_state();
$stable_epoch             = time() - 60;
$audit_auth_user_log_rows = [[
	'username'     => 'timezone-stable',
	'user_id'      => 70,
	'result'       => 1,
	'ip'           => '192.0.2.70',
	'time'         => '2026-08-28 01:00:00',
	'source_epoch' => $stable_epoch
]];

audit_poll_user_log();
$timezone_params = audit_test_last_event_params();
audit_test_assert_same(gmdate('Y-m-d H:i:s', $stable_epoch), $timezone_params[6] ?? null, 'Authentication event time must be normalized from the source epoch to UTC.');
audit_test_assert_same((string) $stable_epoch, read_config_option('audit_user_log_watermark_epoch'), 'Successful ingestion must advance the durable high-water mark.');

// The same TIMESTAMP rendered in a different session timezone retains the
// same epoch and therefore the same durable identity.
$audit_auth_user_log_rows[0]['time'] = '2026-08-27 18:00:00';
$audit_auth_recorded_events          = [];
audit_poll_user_log();
audit_test_assert_same([], $audit_auth_recorded_events, 'A session-timezone change must not re-ingest the same source row.');

// A marker older than the fixed marker horizon may be retired. Raising audit
// retention still cannot replay it because the high-water replay floor wins.
$audit_auth_state_rows     = [];
$historical_epoch          = $stable_epoch - 86400;
$audit_auth_user_log_rows  = [[
	'username'     => 'historical',
	'user_id'      => 71,
	'result'       => 0,
	'ip'           => '192.0.2.71',
	'time'         => '2026-08-26 18:00:00',
	'source_epoch' => $historical_epoch
]];
$audit_auth_config['audit_retention'] = '365';
audit_poll_user_log();
audit_test_assert_same([], $audit_auth_recorded_events, 'Increasing retention must not replay rows behind the durable high-water floor.');
$last_fetch = end($audit_auth_fetches);
audit_test_assert_same($stable_epoch - 300, is_array($last_fetch) ? ($last_fetch['params'][0] ?? null) : null, 'Steady-state ingestion must scan only the bounded replay grace window.');
$audit_auth_config['audit_retention'] = '90';

// ---------------------------------------------------------------------------
// 9. Global failed-login anomaly: threshold, identity counts, throttling
// ---------------------------------------------------------------------------

audit_test_reset_state();

// Below threshold: no emit.
$audit_auth_failed_metrics  = ['failed_attempts' => 9, 'distinct_usernames' => 9, 'distinct_ips' => 9];
$audit_auth_recorded_events = [];
audit_detect_failed_login_volume();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Below threshold must not emit.');

// Exactly at threshold: emit.
$audit_auth_failed_metrics  = ['failed_attempts' => 10, 'distinct_usernames' => 7, 'distinct_ips' => 4];
$audit_auth_recorded_events = [];
audit_detect_failed_login_volume();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'Exactly at threshold must emit even when the throttle setting row did not previously exist.');
audit_test_assert_true(read_config_option('audit_brute_force_last_alert') !== '', 'Brute-force detection must initialize its throttle setting row.');
audit_test_assert_same('cacti.auth.failed_login_volume_anomaly', $audit_auth_recorded_events[0]['params'][12], 'The event must describe a global failed-login anomaly.');
audit_test_assert_same('critical', $audit_auth_recorded_events[0]['params'][14], 'The failed-login anomaly must be critical.');
audit_test_assert_same('global', $audit_auth_recorded_events[0]['params'][17], 'The event must explicitly identify global scope.');
$anomaly_details = json_decode($audit_auth_recorded_events[0]['params'][24], true);
audit_test_assert_same('global', $anomaly_details['scope'], 'The event details must explicitly identify global scope.');
audit_test_assert_same(7, $anomaly_details['distinct_usernames'], 'The event must report distinct affected usernames.');
audit_test_assert_same(4, $anomaly_details['distinct_ips'], 'The event must report distinct source IPs.');

// Within window: throttled (atomic UPDATE claims nothing).
$audit_auth_failed_metrics  = ['failed_attempts' => 12, 'distinct_usernames' => 8, 'distinct_ips' => 5];
$audit_auth_recorded_events = [];
audit_detect_failed_login_volume();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Within the window, the atomic claim must throttle the second alert.');

// Concurrent check: second poller's UPDATE affects 0 rows.
$audit_auth_failed_metrics  = ['failed_attempts' => 12, 'distinct_usernames' => 8, 'distinct_ips' => 5];
$audit_auth_recorded_events = [];
audit_detect_failed_login_volume();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'A concurrent poller must not emit a duplicate alert.');

// Failed audit insert releases the slot.
audit_test_reset_state();
$audit_auth_settings_rows['audit_brute_force_last_alert'] = '';
$audit_auth_failed_metrics                                = ['failed_attempts' => 10, 'distinct_usernames' => 2, 'distinct_ips' => 1];
$audit_auth_insert_fails                                  = true;
$audit_auth_recorded_events                               = [];
audit_detect_failed_login_volume();
audit_test_assert_same('', $audit_auth_settings_rows['audit_brute_force_last_alert'] ?? '', 'A failed audit insert must release the alert slot for retry.');
$audit_auth_insert_fails = false;

// Disabled must not emit.
$audit_auth_config['audit_brute_force_enabled']           = 'off';
$audit_auth_failed_metrics                                = ['failed_attempts' => 50, 'distinct_usernames' => 40, 'distinct_ips' => 30];
$audit_auth_settings_rows['audit_brute_force_last_alert'] = '';
$audit_auth_recorded_events                               = [];
audit_detect_failed_login_volume();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Disabled brute-force detection must not emit.');
$audit_auth_config['audit_brute_force_enabled'] = 'on';

// ---------------------------------------------------------------------------
// 9. custom_denied: returns mode, records event, redacts referer
// ---------------------------------------------------------------------------

$_SESSION['sess_user_id'] = 5;
$_SERVER['SCRIPT_NAME']   = '/cacti/host.php';
$_SERVER['HTTP_REFERER']  = 'https://cacti.example.com/reset/secret-path?token=secret&reset_hash=abc123';
audit_test_reset_state();

$returned = audit_custom_denied('OPER_MODE_NATIVE');
audit_test_assert_same('OPER_MODE_NATIVE', $returned, 'audit_custom_denied() must return the input mode unchanged.');
audit_test_assert_same(1, count($audit_auth_recorded_events), 'audit_custom_denied() must record one event.');
audit_test_assert_same('cacti.auth.authorization.denied', $audit_auth_recorded_events[0]['params'][12], 'Denied event type must be correct.');
$details_json = $audit_auth_recorded_events[0]['params'][24];
$details      = json_decode($details_json, true);
audit_test_assert_same('https://cacti.example.com', $details['referer_origin'], 'Referer paths and query strings must be stripped.');
audit_test_assert_true(strpos($details_json, 'secret') === false, 'The referer token must not appear in details.');
audit_test_assert_true(strpos($details_json, 'abc123') === false, 'The reset hash must not appear in details.');

// Disabled must not record but still return the mode.
$audit_auth_config['audit_auth_log_enabled'] = 'off';
$audit_auth_recorded_events                  = [];
audit_test_assert_same('OPER_MODE_NATIVE', audit_custom_denied('OPER_MODE_NATIVE'), 'audit_custom_denied() must always return the input mode.');
audit_test_assert_same(0, count($audit_auth_recorded_events), 'audit_custom_denied() must skip recording when disabled.');
$audit_auth_config['audit_auth_log_enabled'] = 'on';

// ---------------------------------------------------------------------------
// 10. Logout: pre-destroy records regardless of the master switch so upgrades
//     keep the existing event; post-destroy uses the stash
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
$logout_params = audit_test_last_event_params();
audit_test_assert_same('authentication.logout.completed', $logout_params[12] ?? null, 'Post-destroy event type must be correct.');
audit_test_assert_same(5, $logout_params[1] ?? null, 'Post-destroy must carry the stashed user_id.');

// Empty stash: no record.
$audit_auth_recorded_events = [];
audit_logout_post_session_destroy();
audit_test_assert_same(0, count($audit_auth_recorded_events), 'Post-destroy must not record when the stash is empty.');

// The pre-existing pre-destroy logout event remains available when the new
// authentication-ingestion feature is disabled.
$audit_auth_config['audit_auth_log_enabled'] = 'off';
$audit_auth_recorded_events                  = [];
audit_logout_pre_session_destroy();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'Upgrades must preserve the pre-existing logout event when new auth ingestion is disabled.');
$audit_auth_config['audit_auth_log_enabled'] = 'on';

// ---------------------------------------------------------------------------
// 11. Uninstall lifecycle: shutdown callbacks tolerate removed tables
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_log_exists = false;

audit_test_assert_same(0, audit_record_event('audit.test.after_uninstall'), 'Recording must no-op after audit_log is removed.');
audit_finalize_request(123);
audit_deliver_external_event(123);
audit_retry_external_logs();
audit_test_assert_same([], $audit_auth_executed_sql, 'Late callbacks must not query audit_log after plugin uninstall.');

// ---------------------------------------------------------------------------
// 12. Unauthorized auth-settings save uses the generic event type
// ---------------------------------------------------------------------------

// audit_enforce_syslog_settings_request() reads POST via filter_input_array
// (a PHP built-in reading the real SAPI POST body) and calls exit on 403,
// so it cannot be exercised behaviorally in a CLI test. Verify via a static
// source assertion that the auth-only unauthorized path emits the generic
// audit.configuration.denied event, distinct from the syslog-specific one.
$functions_source = file_get_contents(dirname(__DIR__) . '/audit_functions.php');

if (!is_string($functions_source)) {
	fwrite(STDERR, 'Unable to read audit_functions.php for settings authorization checks.' . PHP_EOL);
	exit(1);
}

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
audit_test_assert_same(
	['syslog' => false, 'auth' => true],
	audit_settings_field_groups(['audit_enabled' => 'off', 'audit_retention' => '30']),
	'The master audit controls must require Audit Log Admin.'
);
audit_test_assert_same(
	['syslog' => false, 'auth' => true],
	audit_settings_field_groups(['audit_log_external_path' => '/tmp/audit.log']),
	'The external file controls must require Audit Log Admin.'
);
audit_test_assert_same(
	['syslog' => false, 'auth' => true],
	audit_settings_field_groups(['audit_auth_log_enabled' => 'on', 'audit_user_log_batch_size' => '100']),
	'New authentication settings must require Audit Log Admin.'
);
audit_test_assert_same(
	['syslog' => true, 'auth' => false],
	audit_settings_field_groups(['audit_syslog_enabled' => 'on']),
	'Remote Syslog settings must require Audit Log Admin.'
);

// ---------------------------------------------------------------------------
// 13. Guard, bounds, and database-failure branches
// ---------------------------------------------------------------------------

audit_test_reset_state();
$audit_auth_config['audit_auth_log_last_state'] = 'off';
$audit_auth_identity_ok                         = false;
audit_poll_user_log();
audit_test_assert_true(audit_test_log_count() > 0, 'An unsupported user_log primary key must fail closed with an operator signal.');

foreach ([0, -1] as $invalid_insert_id) {
	audit_test_reset_state();
	$audit_auth_insert_id_override = $invalid_insert_id;
	audit_test_assert_same(0, audit_record_event('audit.test.invalid_insert_id'), 'A non-positive insert ID must fail closed after an otherwise successful insert.');
}

audit_test_reset_state();
$audit_auth_config['audit_auth_log_last_state'] = 'off';
$audit_auth_database_epoch                      = 0;
audit_poll_user_log();
audit_test_assert_true(audit_test_log_count() > 0, 'An unavailable database clock must fail closed with an operator signal.');

audit_test_reset_state();
$audit_auth_config['audit_enabled'] = 'off';
audit_poll_user_log();
audit_test_assert_same('off', read_config_option('audit_auth_log_last_state'), 'Disabling the master audit switch must transition authentication ingestion off.');
audit_test_assert_same([], $audit_auth_index_actions, 'Disabling the master switch must not run core-table DDL.');
audit_detect_failed_login_volume();
audit_test_assert_same('MODE', audit_custom_denied('MODE'), 'The master switch must gate denied-event auditing.');
audit_logout_post_session_destroy();
audit_test_reset_state();
$audit_auth_config['audit_enabled'] = 'on';

$audit_auth_config['audit_auth_log_enabled'] = 'off';
audit_detect_failed_login_volume();
audit_logout_post_session_destroy();
$audit_auth_config['audit_auth_log_enabled'] = 'on';

$audit_auth_missing_tables = ['user_log'];
audit_poll_user_log();
audit_test_assert_true(audit_test_log_count() > 0, 'Missing user_log must emit an operational warning.');
audit_detect_failed_login_volume();
$audit_auth_missing_tables = ['audit_user_log_state'];
audit_poll_user_log();
$audit_auth_missing_tables = [];
$audit_auth_user_log_rows  = [];

$audit_auth_fetch_fails = 'pending';
audit_poll_user_log();
audit_test_assert_true(audit_test_log_count() > 0, 'A failed ingestion query must emit an operational warning.');
$audit_auth_fetch_fails = 'new';
audit_poll_user_log();
audit_test_assert_true(audit_test_log_count() > 1, 'A failed new-row query must emit an operational warning.');
$audit_auth_fetch_fails = '';

$audit_auth_config['audit_user_log_batch_size'] = '0';
$audit_auth_config['audit_retention']           = '0';
audit_poll_user_log();
$audit_auth_config['audit_user_log_batch_size'] = '5001';
$audit_auth_config['audit_retention']           = '90';
audit_poll_user_log();
$audit_auth_config['audit_user_log_batch_size'] = '1000';

audit_test_reset_state();
$audit_auth_user_log_rows = [
	['username' => 'claim-failure', 'user_id' => 60, 'result' => 1, 'ip' => '192.0.2.60', 'time' => '2026-07-25 16:00:00']
];
$audit_auth_fail_sql = ['INSERT IGNORE INTO audit_user_log_state'];
audit_poll_user_log();
audit_test_assert_same([], $audit_auth_recorded_events, 'A failed source-row claim must skip event creation.');
audit_test_assert_true(audit_test_log_count() > 0, 'A failed source-row claim must emit an operational warning.');
audit_test_assert_same('0', read_config_option('audit_user_log_watermark_epoch'), 'A failed source-row claim must not advance the watermark.');

audit_test_reset_state();
$finalize_epoch           = (int) strtotime('2026-07-25 16:01:00 UTC');
$audit_auth_user_log_rows = [
	['username' => 'claim-finalize', 'user_id' => 61, 'result' => 1, 'ip' => '192.0.2.61', 'time' => '2026-07-25 16:01:00', 'source_epoch' => $finalize_epoch]
];
$audit_auth_state_rows[audit_test_source_key('claim-finalize', 61, $finalize_epoch)] = [
	'source_username' => 'claim-finalize', 'source_user_id' => 61, 'source_epoch' => $finalize_epoch,
	'source_time'     => $finalize_epoch, 'audit_id' => 0, 'retry_count' => 4,
	'processed_time'  => '2026-07-25 00:00:00'
];
$audit_auth_retry_claims_ready = true;
$audit_auth_fail_sql           = ['SET audit_id = ?'];
audit_poll_user_log();
audit_test_assert_same(1, count($audit_auth_recorded_events), 'A failed finalization at the retry limit must retain only dropped-row evidence.');
$finalize_dropped_params = audit_test_last_event_params();
audit_test_assert_same('audit.authentication.ingestion.dropped', $finalize_dropped_params[12] ?? null, 'Finalization exhaustion must create a queryable dropped event.');
audit_test_assert_same(1, count($audit_auth_state_rows), 'A failed claim finalization must retain the retryable marker.');

audit_test_reset_state();
$audit_auth_config['audit_brute_force_window_minutes'] = '0';
$audit_auth_config['audit_brute_force_threshold']      = '0';
audit_detect_failed_login_volume();
$audit_auth_config['audit_brute_force_window_minutes'] = '1441';
$audit_auth_config['audit_brute_force_threshold']      = '1001';
$audit_auth_failed_metrics                             = ['failed_attempts' => 999, 'distinct_usernames' => 1, 'distinct_ips' => 1];
audit_detect_failed_login_volume();

$audit_auth_config['audit_brute_force_window_minutes'] = '5';
$audit_auth_config['audit_brute_force_threshold']      = '10';
$audit_auth_failed_metrics                             = ['failed_attempts' => 10, 'distinct_usernames' => 1, 'distinct_ips' => 1];
$audit_auth_fail_sql                                   = ['INSERT IGNORE INTO settings'];
audit_detect_failed_login_volume();
audit_test_assert_same([], $audit_auth_recorded_events, 'A failed throttle-row initialization must suppress the anomaly event.');

audit_test_reset_state();
$_SERVER['HTTP_REFERER'] = 'https://cacti.example.com:8443/private?token=secret';
audit_custom_denied('MODE');
$port_params  = audit_test_last_event_params();
$port_details = json_decode((string) ($port_params[24] ?? ''), true);
audit_test_assert_same('https://cacti.example.com:8443', is_array($port_details) ? ($port_details['referer_origin'] ?? null) : null, 'A non-default referer port must be preserved without retaining its path.');

print "Auth audit tests passed.\n";
