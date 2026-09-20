<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Behavioral coverage for authentication/session auditing: result-code
 * mapping, ingestion polling (batching, retries, retention, timezone
 * stability), brute-force detection, logout/denied-access recording, and
 * uninstall-safety of late poller callbacks.
 *
 * The stubs below interpret SQL filtering/ordering/limits against
 * in-memory fixtures so tests exercise real query semantics rather than
 * fixtures returned verbatim.
 */

require_once dirname(__DIR__, 2) . '/setup.php';
require_once dirname(__DIR__, 2) . '/audit_functions.php';

/*
 * The tests below exercise privileged code paths (settings saves,
 * ingestion setup) that call api_plugin_user_realm_auth(). That helper is
 * declared once, guarded by function_exists(), in
 * tests/Unit/SecurityFunctionsTest.php and reads
 * $GLOBALS['__audit_test_realms']; grant the audit_manage.php realm here
 * so this file's scenarios are treated as an authorized admin regardless
 * of which test file happens to load first.
 */
beforeEach(function () {
	$GLOBALS['__audit_test_realms']['audit_manage.php'] = true;
});

/**
 * @param string $username
 * @param int    $user_id
 * @param int    $source_epoch
 *
 * @return string
 */
function audit_auth_test_source_key(string $username, int $user_id, int $source_epoch): string {
	return $username . '|' . $user_id . '|' . $source_epoch;
}

/**
 * @param array $state
 *
 * @return array
 */
function audit_auth_test_last_event_params(array $state): array {
	$event = end($state['recorded_events']);

	expect($event)->not->toBeFalse();

	return $event['params'];
}

/**
 * Fresh stub environment for one authentication-auditing scenario. Returns
 * the mutable state array so a test can seed fixtures and inspect results.
 * Config is read/written through bootstrap-unit.php's shared
 * $GLOBALS['__test_config_options'] store via read_config_option()/
 * set_config_option(), not through this array.
 *
 * @return array
 */
function &audit_auth_test_environment(): array {
	audit_test_reset_db_mocks();

	foreach ([
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
		'audit_retention'                  => '90',
	] as $name => $value) {
		audit_test_set_config_option($name, $value);
	}

	$state = [
		'recorded_events'    => [],
		'user_log_rows'      => [],
		'state_rows'         => [],
		'failed_metrics'     => ['failed_attempts' => 0, 'distinct_usernames' => 0, 'distinct_ips' => 0],
		'insert_fails'       => false,
		'fail_usernames'     => [],
		'state_conflict'     => false,
		'affected_rows'      => 0,
		'log_exists'         => true,
		'fetches'            => [],
		'missing_tables'     => [],
		'fail_sql'           => [],
		'retry_claims_ready' => false,
		'fetch_fails'        => '',
		'index_actions'      => [],
		'index_setup_ok'     => true,
		'identity_ok'        => true,
		'database_epoch'     => null,
		'insert_id_override' => null,
	];

	audit_test_mock_db('db_execute', '', true);

	audit_test_mock_db('db_execute_prepared', '', function ($sql, $params) use (&$state) {
		foreach ($state['fail_sql'] as $fragment) {
			if (str_contains($sql, $fragment)) {
				return false;
			}
		}

		if (str_contains($sql, 'INSERT INTO audit_log')) {
			$details  = json_decode((string) ($params[24] ?? ''), true);
			$username = is_array($details) ? (string) ($details['username'] ?? '') : '';

			if ($state['insert_fails'] || in_array($username, $state['fail_usernames'], true)) {
				$state['affected_rows'] = 0;
				audit_test_set_affected_rows(0);

				return false;
			}
			$state['recorded_events'][] = ['id' => count($state['recorded_events']) + 1, 'sql' => $sql, 'params' => $params];
			$state['affected_rows']     = 1;
			audit_test_set_affected_rows(1);

			return true;
		}

		if (str_contains($sql, 'INSERT IGNORE INTO audit_user_log_state')) {
			$username     = (string) $params[0];
			$user_id      = (int) $params[1];
			$source_epoch = (int) $params[2];
			$key          = audit_auth_test_source_key($username, $user_id, $source_epoch);

			if ($state['state_conflict'] || isset($state['state_rows'][$key])) {
				$state['affected_rows'] = 0;
				audit_test_set_affected_rows(0);
			} else {
				$state['state_rows'][$key] = [
					'source_username' => $username,
					'source_user_id'  => $user_id,
					'source_epoch'    => $source_epoch,
					'source_time'     => time(),
					'audit_id'        => 0,
					'retry_count'     => 0,
					'processed_time'  => '2026-07-25 00:00:00',
				];
				$state['affected_rows'] = 1;
				audit_test_set_affected_rows(1);
			}

			return true;
		}

		if (str_contains($sql, 'UPDATE audit_user_log_state')) {
			$is_finalize  = str_contains($sql, 'SET audit_id = ?');
			$is_retry_add = str_contains($sql, 'retry_count = retry_count + ?');

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

			$key = audit_auth_test_source_key($username, $user_id, $source_epoch);

			if (!isset($state['state_rows'][$key]) || $state['state_rows'][$key]['audit_id'] !== 0) {
				$state['affected_rows'] = 0;
				audit_test_set_affected_rows(0);

				return true;
			}

			if ($is_finalize) {
				$state['state_rows'][$key]['audit_id'] = $audit_id;
			} elseif (str_contains($sql, 'retry_count = retry_count +')) {
				$state['state_rows'][$key]['retry_count'] += $is_retry_add ? (int) $params[0] : 1;
			}

			$state['affected_rows'] = 1;
			audit_test_set_affected_rows(1);

			return true;
		}

		if (str_contains($sql, 'DELETE FROM audit_log WHERE id')) {
			$id                       = (int) ($params[0] ?? 0);
			$state['recorded_events'] = array_values(array_filter(
				$state['recorded_events'],
				static fn (array $event): bool => (int) ($event['id'] ?? 0) !== $id
			));

			return true;
		}

		if (str_contains($sql, 'INSERT INTO settings')) {
			$name = (string) ($params[0] ?? '');

			if ($name === 'audit_user_log_watermark_epoch') {
				$current = (int) ($GLOBALS['__test_config_options'][$name] ?? 0);
				$value   = (int) ($params[1] ?? 0);
				audit_test_set_config_option($name, (string) max($current, $value));

				return true;
			}
		}

		if (str_contains($sql, 'INSERT IGNORE INTO settings')) {
			$name = (string) $params[0];

			if (!array_key_exists($name, $GLOBALS['__test_config_options'])) {
				audit_test_set_config_option($name, (string) $params[1]);
				$state['affected_rows'] = 1;
				audit_test_set_affected_rows(1);
			} else {
				$state['affected_rows'] = 0;
				audit_test_set_affected_rows(0);
			}

			return true;
		}

		if (str_contains($sql, 'UPDATE settings') && str_contains($sql, 'audit_brute_force_last_alert')) {
			$name          = 'audit_brute_force_last_alert';
			$current       = $GLOBALS['__test_config_options'][$name] ?? '';
			$now           = $params[0];
			$window        = $params[2];
			$should_update = ($current === '' || $current === '0');

			if (!$should_update && $current !== '') {
				$ts            = strtotime($current);
				$now_ts        = strtotime($now);
				$should_update = ($ts !== false && $now_ts !== false && ($now_ts - $ts) >= ($window * 60));
			}

			if ($should_update) {
				audit_test_set_config_option($name, $now);
				$state['affected_rows'] = 1;
				audit_test_set_affected_rows(1);

				return true;
			}

			$state['affected_rows'] = 0;
			audit_test_set_affected_rows(0);

			return true;
		}

		if (str_contains($sql, 'DELETE FROM audit_user_log_state')) {
			$terminal = str_contains($sql, 'audit_id = 0');
			$removed  = 0;
			$limit    = preg_match('/LIMIT (\d+)/', $sql, $limit_matches) === 1 ? (int) $limit_matches[1] : PHP_INT_MAX;

			foreach ($state['state_rows'] as $key => $row) {
				$matches = $terminal
					? (int) $row['audit_id'] === 0 && (int) $row['retry_count'] >= (int) ($params[0] ?? 5)
					: (int) $row['audit_id'] > 0 && (int) $row['source_epoch'] < (int) ($params[0] ?? 0);

				if ($matches) {
					unset($state['state_rows'][$key]);
					$removed++;

					if ($removed >= $limit) {
						break;
					}
				}
			}

			$state['affected_rows'] = $removed;
			audit_test_set_affected_rows($removed);

			return true;
		}

		return true;
	});

	audit_test_mock_db('db_fetch_insert_id', '', function () use (&$state) {
		if ($state['insert_fails']) {
			return 0;
		}

		if ($state['insert_id_override'] !== null) {
			return $state['insert_id_override'];
		}

		return count($state['recorded_events']);
	});

	audit_test_mock_db('db_table_exists', '', function ($table) use (&$state) {
		if (in_array($table, $state['missing_tables'], true)) {
			return false;
		}

		if ($table === 'audit_log') {
			return $state['log_exists'];
		}

		return in_array($table, ['user_log', 'audit_user_log_state'], true);
	});

	audit_test_mock_db('db_index_exists', '', function () use (&$state) {
		return $state['index_setup_ok'];
	});

	audit_test_mock_db('db_fetch_row_prepared', '', function ($sql) use (&$state) {
		if (str_contains($sql, 'COUNT(*) AS failed_attempts')) {
			return $state['failed_metrics'];
		}

		return [];
	});

	audit_test_mock_db('db_fetch_assoc_prepared', '', function ($sql, $params) use (&$state) {
		if (str_contains($sql, 'information_schema.STATISTICS')) {
			return $state['identity_ok']
				? [
					['COLUMN_NAME' => 'username'],
					['COLUMN_NAME' => 'user_id'],
					['COLUMN_NAME' => 'time'],
				]
				: [];
		}

		if (!str_contains($sql, 'user_log AS ul')) {
			return [];
		}

		$is_pending = str_contains($sql, 'INNER JOIN user_log AS ul');

		if ($state['fetch_fails'] === ($is_pending ? 'pending' : 'new')) {
			return false;
		}

		$state['fetches'][] = ['sql' => $sql, 'params' => $params];
		$cutoff      = $is_pending ? 0 : (int) ($params[0] ?? 0);
		$max_retries = 5;
		$limit       = preg_match('/LIMIT (\d+)/', $sql, $limit_match) === 1 ? (int) $limit_match[1] : 1000;
		$filtered    = [];

		foreach ($state['user_log_rows'] as $row) {
			$source_epoch = isset($row['source_epoch'])
				? (int) $row['source_epoch']
				: (int) strtotime((string) $row['time'] . ' UTC');
			$key       = audit_auth_test_source_key((string) $row['username'], (int) $row['user_id'], $source_epoch);
			$state_row = $state['state_rows'][$key] ?? null;

			$selected = $is_pending
				? ($state_row !== null && (int) $state_row['audit_id'] === 0 && (int) $state_row['retry_count'] < $max_retries && $state['retry_claims_ready'])
				: ($source_epoch > $cutoff && $state_row === null);

			if ($selected) {
				$row['source_epoch']   = $source_epoch;
				$row['state_audit_id'] = $state_row['audit_id'] ?? null;
				$row['retry_count']    = $state_row['retry_count'] ?? 0;
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
	});

	audit_test_mock_db('db_fetch_cell_prepared', '', function ($sql, $params) use (&$state) {
		if (str_contains($sql, 'SELECT UNIX_TIMESTAMP()')) {
			return $state['database_epoch'] ?? time();
		}

		if (str_contains($sql, 'FROM audit_log WHERE event_uuid')) {
			foreach ($state['recorded_events'] as $event) {
				if (($event['params'][10] ?? null) === ($params[0] ?? null)) {
					return (int) $event['id'];
				}
			}
		}

		if (str_contains($sql, 'COUNT(*) FROM audit_user_log_state')) {
			return count(array_filter(
				$state['state_rows'],
				static fn (array $s): bool => (int) $s['audit_id'] === 0 &&
					(int) $s['retry_count'] >= (int) ($params[0] ?? 5)
			));
		}

		return '';
	});

	return $state;
}

it('maps authentication result codes to the correct event type and outcome', function () {
	audit_auth_test_environment();

	expect(audit_user_log_event_descriptor(0, 0)['event_type'])->toBe('cacti.auth.login.failed');
	expect(audit_user_log_event_descriptor(0, 0)['outcome'])->toBe('failure');

	// result=1: credentials accepted, NOT success (Cacti writes before checks).
	expect(audit_user_log_event_descriptor(1, 5)['event_type'])->toBe('cacti.auth.login.credentials_accepted');
	expect(audit_user_log_event_descriptor(1, 5)['outcome'])->toBe('unknown');

	expect(audit_user_log_event_descriptor(2, 5)['event_type'])->toBe('cacti.auth.login.token');
	expect(audit_user_log_event_descriptor(2, 5)['outcome'])->toBe('success');

	// result=3/user_id>0: defensive, unknown outcome (no false success).
	expect(audit_user_log_event_descriptor(3, 5)['event_type'])->toBe('cacti.auth.password.changed');
	expect(audit_user_log_event_descriptor(3, 5)['outcome'])->toBe('unknown');

	// result=3/user_id=0: ambiguous.
	$ambiguous = audit_user_log_event_descriptor(3, 0);
	expect($ambiguous['event_type'])->toBe('cacti.auth.password_change_or_2fa_failed');
	expect($ambiguous['outcome'])->toBe('unknown');
	expect($ambiguous['details']['ambiguous'] ?? null)->not->toBeNull();

	// Unsupported result code: explicit unknown, not a fallthrough.
	$unknown = audit_user_log_event_descriptor(99, 5);
	expect($unknown['event_type'])->toBe('cacti.auth.login.unknown');
	expect($unknown['outcome'])->toBe('unknown');
	expect($unknown['details']['unsupported_result_code'])->toBe(99);
});

it('derives a stable deterministic UUID from the same source row', function () {
	audit_auth_test_environment();

	$source_uuid = audit_user_log_event_uuid('alice', 5, 1721926800);

	expect(audit_user_log_event_uuid('alice', 5, 1721926800))->toBe($source_uuid);
	expect(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $source_uuid))->toBe(1);
});

it('records one event per new user_log row and deduplicates on re-poll', function () {
	$state = &audit_auth_test_environment();

	$state['user_log_rows'] = [
		['username' => 'alice', 'user_id' => 5, 'result' => 1, 'ip' => '10.0.0.1', 'time' => '2026-07-25 10:00:01'],
		['username' => 'bob',   'user_id' => 0, 'result' => 0, 'ip' => '10.0.0.2', 'time' => '2026-07-25 10:00:02'],
		['username' => 'carol', 'user_id' => 7, 'result' => 2, 'ip' => '10.0.0.3', 'time' => '2026-07-25 10:00:03'],
		['username' => 'dave',  'user_id' => 0, 'result' => 3, 'ip' => '10.0.0.4', 'time' => '2026-07-25 10:00:04'],
	];

	audit_poll_user_log();

	expect($state['recorded_events'])->toHaveCount(4);
	expect($state['recorded_events'][0]['params'][12])->toBe('cacti.auth.login.credentials_accepted');
	expect($state['recorded_events'][1]['params'][14])->toBe('warning');
	expect($state['recorded_events'][1]['params'][18])->toBe('failure');
	expect($state['recorded_events'][3]['params'][12])->toBe('cacti.auth.password_change_or_2fa_failed');
	expect($state['recorded_events'][3]['params'][18])->toBe('unknown');
	expect($state['state_rows'])->toHaveCount(4);

	// Re-polling must not double-record (deduplication via state table).
	$state['recorded_events'] = [];
	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);
});

it('gates polling on audit_auth_log_enabled and fails closed when indexes are missing', function () {
	$state = &audit_auth_test_environment();

	audit_test_set_config_option('audit_auth_log_enabled', 'off');
	$state['user_log_rows'] = [
		['username' => 'eve', 'user_id' => 9, 'result' => 1, 'ip' => '10.0.0.5', 'time' => '2026-07-25 11:00:00'],
	];
	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);
	expect($state['index_actions'])->toBe([]);

	audit_test_set_config_option('audit_auth_log_enabled', 'on');
	$activation_before        = time();
	$state['index_setup_ok'] = false;
	audit_poll_user_log();
	expect($GLOBALS['__test_config_options']['audit_auth_log_last_state'])->toBe('off');
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(0);
	$degraded_params = audit_auth_test_last_event_params($state);
	expect($degraded_params[12] ?? null)->toBe('audit.authentication.ingestion.unavailable');

	$state['index_setup_ok']  = true;
	$state['recorded_events'] = [];
	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);
	expect((int) ($GLOBALS['__test_config_options']['audit_user_log_watermark_epoch'] ?? 0))->toBeGreaterThanOrEqual($activation_before);
});

it('bounds a single poll cycle to the batch size and pages the remainder', function () {
	$state = &audit_auth_test_environment();

	audit_test_set_config_option('audit_user_log_batch_size', '1000');

	for ($i = 0; $i < 1500; $i++) {
		$state['user_log_rows'][] = [
			'username' => sprintf('user%04d', $i),
			'user_id'  => $i + 1,
			'result'   => 0,
			'ip'       => '10.0.0.10',
			'time'     => '2026-07-25 12:00:00',
		];
	}

	audit_poll_user_log();
	expect($state['recorded_events'])->toHaveCount(1000);
	expect($state['state_rows'])->toHaveCount(1000);

	$state['recorded_events'] = [];
	audit_poll_user_log();
	expect($state['recorded_events'])->toHaveCount(500);
	expect($state['state_rows'])->toHaveCount(1500);

	$state['recorded_events'] = [];
	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);
});

it('processes all rows across multiple timestamp pages in order', function () {
	$state = &audit_auth_test_environment();

	$state['user_log_rows'] = [
		['username' => 'a', 'user_id' => 1, 'result' => 1, 'ip' => '10.0.0.1', 'time' => '2026-07-25 13:00:00'],
		['username' => 'b', 'user_id' => 2, 'result' => 0, 'ip' => '10.0.0.2', 'time' => '2026-07-25 13:00:01'],
		['username' => 'c', 'user_id' => 3, 'result' => 2, 'ip' => '10.0.0.3', 'time' => '2026-07-25 13:00:02'],
	];

	audit_poll_user_log();
	expect($state['recorded_events'])->toHaveCount(3);
	$first_details = json_decode($state['recorded_events'][0]['params'][24], true);
	expect($first_details['username'])->toBe('a');
});

it('does not double-record rows claimed by a concurrent poller', function () {
	$state = &audit_auth_test_environment();

	$state['user_log_rows'] = [
		['username' => 'concurrent', 'user_id' => 42, 'result' => 1, 'ip' => '10.0.0.99', 'time' => '2026-07-25 14:00:00'],
	];

	$concurrent_epoch                     = (int) strtotime('2026-07-25 14:00:00 UTC');
	$concurrent_key                       = audit_auth_test_source_key('concurrent', 42, $concurrent_epoch);
	$state['state_rows'][$concurrent_key] = [
		'source_username' => 'concurrent',
		'source_user_id'  => 42,
		'source_epoch'    => $concurrent_epoch,
		'source_time'     => $concurrent_epoch,
		'audit_id'        => 999,
		'retry_count'     => 0,
		'processed_time'  => '2026-07-25 14:00:01',
	];

	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);
});

it('does not create a duplicate event when a concurrent claim is lost', function () {
	$state = &audit_auth_test_environment();

	$state['user_log_rows'] = [
		['username' => 'racing', 'user_id' => 43, 'result' => 1, 'ip' => '10.0.0.100', 'time' => '2026-07-25 14:01:00'],
	];
	$state['state_conflict'] = true;

	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);
	expect($state['state_rows'])->toBe([]);
});

it('keeps a failed audit insert discoverable behind later successful rows and retries it', function () {
	$state = &audit_auth_test_environment();

	$state['user_log_rows'] = [
		['username' => 'failinsert', 'user_id' => 50, 'result' => 1, 'ip' => '10.0.0.50', 'time' => '2026-07-25 15:00:00'],
		['username' => 'later',      'user_id' => 51, 'result' => 1, 'ip' => '10.0.0.51', 'time' => '2026-07-25 16:00:00'],
	];
	$state['fail_usernames'] = ['failinsert'];

	audit_poll_user_log();
	expect($state['recorded_events'])->toHaveCount(1);
	expect($state['state_rows'])->toHaveCount(2);
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(0);

	$state['fail_usernames']     = [];
	$state['recorded_events']    = [];
	$state['retry_claims_ready'] = true;
	audit_poll_user_log();
	expect($state['recorded_events'])->toHaveCount(1);
	expect($state['state_rows'])->toHaveCount(2);
});

it('does not let a poison retry at its last attempt starve a healthy new row', function () {
	$state = &audit_auth_test_environment();

	audit_test_set_config_option('audit_user_log_batch_size', '2');
	$poison_epoch            = (int) strtotime('2026-07-25 16:30:00 UTC');
	$state['user_log_rows']  = [
		['username' => 'poison', 'user_id' => 52, 'result' => 1, 'ip' => '10.0.0.52', 'time' => '2026-07-25 16:30:00', 'source_epoch' => $poison_epoch],
		['username' => 'healthy', 'user_id' => 53, 'result' => 1, 'ip' => '10.0.0.53', 'time' => '2026-07-25 16:31:00'],
	];
	$state['state_rows'][audit_auth_test_source_key('poison', 52, $poison_epoch)] = [
		'source_username' => 'poison', 'source_user_id' => 52, 'source_epoch' => $poison_epoch,
		'source_time'     => $poison_epoch, 'audit_id' => 0, 'retry_count' => 4,
		'processed_time'  => '2026-07-25 00:00:00',
	];
	$state['fail_usernames']     = ['poison'];
	$state['retry_claims_ready'] = true;

	audit_poll_user_log();
	expect($state['recorded_events'])->toHaveCount(1);
	$dropped_params = audit_auth_test_last_event_params($state);
	expect($dropped_params[12] ?? null)->toBe('cacti.auth.login.credentials_accepted');
	expect($state['state_rows'][audit_auth_test_source_key('poison', 52, $poison_epoch)]['retry_count'])->toBe(5);
	expect(count($GLOBALS['__test_logs']))->toBe(2);

	$foundPoison = false;

	foreach ($GLOBALS['__test_logs'] as $message) {
		if (str_contains($message, '"username":"poison"')) {
			$foundPoison = true;
		}
	}
	expect($foundPoison)->toBeTrue();

	audit_cleanup_user_log_state(5, null, true);
	$healthy_epoch = (int) strtotime('2026-07-25 16:31:00 UTC');
	$healthy_key   = audit_auth_test_source_key('healthy', 53, $healthy_epoch);
	expect($state['state_rows'])->toHaveCount(1);
	expect(isset($state['state_rows'][$healthy_key]))->toBeTrue();

	$foundTerminal = false;

	foreach ($GLOBALS['__test_logs'] as $message) {
		if (str_contains($message, 'terminal retry marker')) {
			$foundTerminal = true;
		}
	}
	expect($foundTerminal)->toBeTrue();
});

it('honors a rate-proportional cleanup batch budget across cycles', function () {
	$state = &audit_auth_test_environment();

	// Establish a watermark well past both fixture rows so they fall below
	// the replay floor and become eligible for reclamation.
	audit_test_set_config_option('audit_user_log_watermark_epoch', '3000');

	foreach ([1000, 2000] as $old_epoch) {
		$state['state_rows'][audit_auth_test_source_key('old-' . $old_epoch, 1, $old_epoch)] = [
			'source_username' => 'old-' . $old_epoch, 'source_user_id' => 1, 'source_epoch' => $old_epoch,
			'source_time'     => 1, 'audit_id' => $old_epoch, 'retry_count' => 0,
			'processed_time'  => '2026-07-01 00:00:00',
		];
	}

	// A budget of one row per cycle reclaims exactly one stale row per call.
	audit_cleanup_user_log_state(5, 1);
	expect($state['state_rows'])->toHaveCount(1);
	audit_cleanup_user_log_state(5, 1);
	expect($state['state_rows'])->toHaveCount(0);

	$state['missing_tables'] = ['audit_user_log_state'];
	audit_cleanup_user_log_state();
});

it('finalizes a deterministic source event on crash recovery instead of duplicating it', function () {
	$state = &audit_auth_test_environment();

	$crash_epoch              = (int) strtotime('2026-07-25 16:40:00 UTC');
	$crash_uuid               = audit_user_log_event_uuid('crash-safe', 54, $crash_epoch);
	$crash_params             = array_fill(0, 25, null);
	$crash_params[10]         = $crash_uuid;
	$state['recorded_events'] = [['id' => 77, 'sql' => '', 'params' => $crash_params]];
	$state['user_log_rows']   = [[
		'username' => 'crash-safe', 'user_id' => 54, 'result' => 1, 'ip' => '10.0.0.54',
		'time'     => '2026-07-25 16:40:00', 'source_epoch' => $crash_epoch,
	]];
	$crash_key                       = audit_auth_test_source_key('crash-safe', 54, $crash_epoch);
	$state['state_rows'][$crash_key] = [
		'source_username' => 'crash-safe', 'source_user_id' => 54, 'source_epoch' => $crash_epoch,
		'source_time'     => $crash_epoch, 'audit_id' => 0, 'retry_count' => 1,
		'processed_time'  => '2026-07-25 00:00:00',
	];
	$state['retry_claims_ready'] = true;

	audit_poll_user_log();
	expect($state['recorded_events'])->toHaveCount(1);
	expect($state['state_rows'][$crash_key]['audit_id'])->toBe(77);
});

it('excludes rows older than the retention cutoff from initial ingestion', function () {
	$state = &audit_auth_test_environment();

	audit_test_set_config_option('audit_retention', '30');
	$state['user_log_rows'] = [
		['username' => 'old', 'user_id' => 1, 'result' => 1, 'ip' => '10.0.0.1', 'time' => '2026-06-01 00:00:00'],
		['username' => 'recent', 'user_id' => 2, 'result' => 1, 'ip' => '10.0.0.2', 'time' => '2026-07-24 00:00:00'],
	];

	audit_poll_user_log();

	$recorded_usernames = [];

	foreach ($state['recorded_events'] as $event) {
		$details = json_decode((string) ($event['params'][24] ?? ''), true);

		if (is_array($details) && isset($details['username'])) {
			$recorded_usernames[] = $details['username'];
		}
	}

	expect($recorded_usernames)->not->toContain('old');
});

it('normalizes event time to UTC, preserves identity across timezone rendering, and bounds replay scans', function () {
	$state = &audit_auth_test_environment();

	$stable_epoch           = time() - 60;
	$state['user_log_rows'] = [[
		'username'     => 'timezone-stable',
		'user_id'      => 70,
		'result'       => 1,
		'ip'           => '192.0.2.70',
		'time'         => '2026-08-28 01:00:00',
		'source_epoch' => $stable_epoch,
	]];

	audit_poll_user_log();
	$timezone_params = audit_auth_test_last_event_params($state);
	expect($timezone_params[6] ?? null)->toBe(gmdate('Y-m-d H:i:s', $stable_epoch));
	expect($GLOBALS['__test_config_options']['audit_user_log_watermark_epoch'] ?? null)->toBe((string) $stable_epoch);

	// The same TIMESTAMP rendered in a different session timezone retains the
	// same epoch and therefore the same durable identity.
	$state['user_log_rows'][0]['time'] = '2026-08-27 18:00:00';
	$state['recorded_events']          = [];
	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);

	// A marker older than the fixed marker horizon may be retired. Raising
	// audit retention still cannot replay it because the high-water replay
	// floor wins.
	$state['state_rows']    = [];
	$historical_epoch       = $stable_epoch - 86400;
	$state['user_log_rows'] = [[
		'username'     => 'historical',
		'user_id'      => 71,
		'result'       => 0,
		'ip'           => '192.0.2.71',
		'time'         => '2026-08-26 18:00:00',
		'source_epoch' => $historical_epoch,
	]];
	audit_test_set_config_option('audit_retention', '365');
	audit_poll_user_log();
	expect($state['recorded_events'])->toBe([]);
	$last_fetch = end($state['fetches']);
	expect(is_array($last_fetch) ? ($last_fetch['params'][0] ?? null) : null)->toBe($stable_epoch - 300);
});

it('detects a global failed-login volume anomaly with identity counts and throttling', function () {
	$state = &audit_auth_test_environment();

	// Below threshold: no emit.
	$state['failed_metrics'] = ['failed_attempts' => 9, 'distinct_usernames' => 9, 'distinct_ips' => 9];
	audit_detect_failed_login_volume();
	expect($state['recorded_events'])->toBe([]);

	// Exactly at threshold: emit.
	$state['failed_metrics'] = ['failed_attempts' => 10, 'distinct_usernames' => 7, 'distinct_ips' => 4];
	audit_detect_failed_login_volume();
	expect($state['recorded_events'])->toHaveCount(1);
	expect($GLOBALS['__test_config_options']['audit_brute_force_last_alert'] ?? '')->not->toBe('');
	expect($state['recorded_events'][0]['params'][12])->toBe('cacti.auth.failed_login_volume_anomaly');
	expect($state['recorded_events'][0]['params'][14])->toBe('critical');
	expect($state['recorded_events'][0]['params'][17])->toBe('global');
	$anomaly_details = json_decode($state['recorded_events'][0]['params'][24], true);
	expect($anomaly_details['scope'])->toBe('global');
	expect($anomaly_details['distinct_usernames'])->toBe(7);
	expect($anomaly_details['distinct_ips'])->toBe(4);

	// Within window: throttled (atomic UPDATE claims nothing).
	$state['failed_metrics']  = ['failed_attempts' => 12, 'distinct_usernames' => 8, 'distinct_ips' => 5];
	$state['recorded_events'] = [];
	audit_detect_failed_login_volume();
	expect($state['recorded_events'])->toBe([]);

	// Failed audit insert releases the slot.
	$state2 = &audit_auth_test_environment();
	audit_test_set_config_option('audit_brute_force_last_alert', '');
	$state2['failed_metrics'] = ['failed_attempts' => 10, 'distinct_usernames' => 2, 'distinct_ips' => 1];
	$state2['insert_fails']   = true;
	audit_detect_failed_login_volume();
	expect($GLOBALS['__test_config_options']['audit_brute_force_last_alert'] ?? '')->toBe('');

	// Disabled must not emit.
	$state3 = &audit_auth_test_environment();
	audit_test_set_config_option('audit_brute_force_enabled', 'off');
	$state3['failed_metrics'] = ['failed_attempts' => 50, 'distinct_usernames' => 40, 'distinct_ips' => 30];
	audit_detect_failed_login_volume();
	expect($state3['recorded_events'])->toBe([]);
});

it('records a denied-access event with the returned mode and redacts the referer', function () {
	$state = &audit_auth_test_environment();

	$_SESSION['sess_user_id'] = 5;
	$_SERVER['SCRIPT_NAME']   = '/cacti/host.php';
	$_SERVER['HTTP_REFERER']  = 'https://cacti.example.com/reset/secret-path?token=secret&reset_hash=abc123';

	$returned = audit_custom_denied('OPER_MODE_NATIVE');
	expect($returned)->toBe('OPER_MODE_NATIVE');
	expect($state['recorded_events'])->toHaveCount(1);
	expect($state['recorded_events'][0]['params'][12])->toBe('cacti.auth.authorization.denied');
	$details_json = $state['recorded_events'][0]['params'][24];
	$details      = json_decode($details_json, true);
	expect($details['referer_origin'])->toBe('https://cacti.example.com');
	expect($details_json)->not->toContain('secret');
	expect($details_json)->not->toContain('abc123');

	// Disabled must not record but still return the mode.
	audit_test_set_config_option('audit_auth_log_enabled', 'off');
	$state['recorded_events'] = [];
	expect(audit_custom_denied('OPER_MODE_NATIVE'))->toBe('OPER_MODE_NATIVE');
	expect($state['recorded_events'])->toBe([]);
});

it('records logout events pre- and post-destroy, preserving the pre-existing event on upgrades', function () {
	$state = &audit_auth_test_environment();

	$_SESSION['sess_user_id'] = 5;
	$_REQUEST['action']       = 'user';

	audit_logout_pre_session_destroy();
	expect($state['recorded_events'])->toHaveCount(1);
	expect($state['recorded_events'][0]['params'][12])->toBe('authentication.logout');

	$state['recorded_events'] = [];
	audit_logout_post_session_destroy();
	expect($state['recorded_events'])->toHaveCount(1);
	$logout_params = audit_auth_test_last_event_params($state);
	expect($logout_params[12] ?? null)->toBe('authentication.logout.completed');
	expect($logout_params[1] ?? null)->toBe(5);

	// Empty stash: no record.
	$state['recorded_events'] = [];
	audit_logout_post_session_destroy();
	expect($state['recorded_events'])->toBe([]);

	// The pre-existing pre-destroy logout event remains available when the
	// new authentication-ingestion feature is disabled.
	audit_test_set_config_option('audit_auth_log_enabled', 'off');
	$state['recorded_events'] = [];
	audit_logout_pre_session_destroy();
	expect($state['recorded_events'])->toHaveCount(1);
});

it('no-ops late poller callbacks after audit_log has been removed', function () {
	$state = &audit_auth_test_environment();

	$state['log_exists'] = false;

	expect(audit_record_event('audit.test.after_uninstall'))->toBe(0);
	audit_finalize_request(123);
	audit_deliver_external_event(123);
	audit_retry_external_logs();
});

it('requires Audit Log Admin for unauthorized auth and syslog settings saves', function () {
	audit_auth_test_environment();

	$functions_source = plugin_test_read_source('audit_functions.php');

	expect($functions_source)->toContain("'audit.configuration.denied'");
	expect($functions_source)->toContain("'audit.syslog.configuration.denied'");
	expect($functions_source)->toContain('audit_admin_required');

	expect(audit_settings_field_groups(['audit_enabled' => 'off', 'audit_retention' => '30']))
		->toBe(['syslog' => false, 'auth' => true]);
	expect(audit_settings_field_groups(['audit_log_external_path' => '/tmp/audit.log']))
		->toBe(['syslog' => false, 'auth' => true]);
	expect(audit_settings_field_groups(['audit_auth_log_enabled' => 'on', 'audit_user_log_batch_size' => '100']))
		->toBe(['syslog' => false, 'auth' => true]);
	expect(audit_settings_field_groups(['audit_syslog_enabled' => 'on']))
		->toBe(['syslog' => true, 'auth' => false]);
});

it('fails closed on guard, bounds, and database-failure branches', function () {
	$state = &audit_auth_test_environment();

	audit_test_set_config_option('audit_auth_log_last_state', 'off');
	$state['identity_ok'] = false;
	audit_poll_user_log();
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(0);

	foreach ([0, -1] as $invalid_insert_id) {
		audit_auth_test_environment();
		audit_test_mock_db('db_fetch_insert_id', '', $invalid_insert_id);
		expect(audit_record_event('audit.test.invalid_insert_id'))->toBe(0);
	}

	$state2 = &audit_auth_test_environment();
	audit_test_set_config_option('audit_auth_log_last_state', 'off');
	$state2['database_epoch'] = 0;
	audit_poll_user_log();
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(0);

	$state3 = &audit_auth_test_environment();
	audit_test_set_config_option('audit_enabled', 'off');
	audit_poll_user_log();
	expect($GLOBALS['__test_config_options']['audit_auth_log_last_state'])->toBe('off');
	expect($state3['index_actions'])->toBe([]);
	audit_detect_failed_login_volume();
	expect(audit_custom_denied('MODE'))->toBe('MODE');
	audit_logout_post_session_destroy();

	$state4 = &audit_auth_test_environment();
	$state4['missing_tables'] = ['user_log'];
	audit_poll_user_log();
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(0);

	$state5 = &audit_auth_test_environment();
	$state5['fetch_fails'] = 'pending';
	audit_poll_user_log();
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(0);
	$state5['fetch_fails'] = 'new';
	audit_poll_user_log();
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(1);

	$state6 = &audit_auth_test_environment();
	$state6['user_log_rows'] = [
		['username' => 'claim-failure', 'user_id' => 60, 'result' => 1, 'ip' => '192.0.2.60', 'time' => '2026-07-25 16:00:00'],
	];
	$state6['fail_sql'] = ['INSERT IGNORE INTO audit_user_log_state'];
	audit_poll_user_log();
	expect($state6['recorded_events'])->toBe([]);
	expect(count($GLOBALS['__test_logs']))->toBeGreaterThan(0);
	expect($GLOBALS['__test_config_options']['audit_user_log_watermark_epoch'])->toBe('0');

	$state7 = &audit_auth_test_environment();
	$finalize_epoch          = (int) strtotime('2026-07-25 16:01:00 UTC');
	$state7['user_log_rows'] = [
		['username' => 'claim-finalize', 'user_id' => 61, 'result' => 1, 'ip' => '192.0.2.61', 'time' => '2026-07-25 16:01:00', 'source_epoch' => $finalize_epoch],
	];
	$state7['state_rows'][audit_auth_test_source_key('claim-finalize', 61, $finalize_epoch)] = [
		'source_username' => 'claim-finalize', 'source_user_id' => 61, 'source_epoch' => $finalize_epoch,
		'source_time'     => $finalize_epoch, 'audit_id' => 0, 'retry_count' => 4,
		'processed_time'  => '2026-07-25 00:00:00',
	];
	$state7['retry_claims_ready'] = true;
	$state7['fail_sql']           = ['SET audit_id = ?'];
	audit_poll_user_log();
	expect($state7['recorded_events'])->toHaveCount(1);
	$finalize_dropped_params = audit_auth_test_last_event_params($state7);
	expect($finalize_dropped_params[12] ?? null)->toBe('audit.authentication.ingestion.dropped');
	expect($state7['state_rows'])->toHaveCount(1);

	$state8 = &audit_auth_test_environment();
	audit_test_set_config_option('audit_brute_force_window_minutes', '0');
	audit_test_set_config_option('audit_brute_force_threshold', '0');
	audit_detect_failed_login_volume();
	audit_test_set_config_option('audit_brute_force_window_minutes', '1441');
	audit_test_set_config_option('audit_brute_force_threshold', '1001');
	$state8['failed_metrics'] = ['failed_attempts' => 999, 'distinct_usernames' => 1, 'distinct_ips' => 1];
	audit_detect_failed_login_volume();

	$state9 = &audit_auth_test_environment();
	audit_test_set_config_option('audit_brute_force_window_minutes', '5');
	audit_test_set_config_option('audit_brute_force_threshold', '10');
	$state9['failed_metrics'] = ['failed_attempts' => 10, 'distinct_usernames' => 1, 'distinct_ips' => 1];
	$state9['fail_sql']       = ['INSERT IGNORE INTO settings'];
	audit_detect_failed_login_volume();
	expect($state9['recorded_events'])->toBe([]);

	$state10 = &audit_auth_test_environment();
	$_SERVER['HTTP_REFERER'] = 'https://cacti.example.com:8443/private?token=secret';
	audit_custom_denied('MODE');
	$port_params  = audit_auth_test_last_event_params($state10);
	$port_details = json_decode((string) ($port_params[24] ?? ''), true);
	expect(is_array($port_details) ? ($port_details['referer_origin'] ?? null) : null)->toBe('https://cacti.example.com:8443');
});
