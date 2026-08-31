<?php

declare(strict_types = 1);

require_once __DIR__ . '/audit_syslog.php';

function audit_user_is_admin(): bool {
	return api_plugin_user_realm_auth('audit_manage.php');
}

/**
 * @param array<int,string> $selected_items
 */
function audit_process_page_data(string $page, mixed $drop_action, array $selected_items): string {
	$objects = [];

	if ($page === '') {
		return audit_json_encode($objects);
	}

	if ($drop_action !== false) {
		switch ($page) {
			case 'host.php':
				// loop over array and perform query for each item
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT id AS host_id,site_id,description,hostname,status,status_fail_date AS last_failed_date,status_rec_date AS last_recovered_date
							FROM host
							WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'host_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM host_template
						WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'templates_export.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name  FROM graph_templates
							WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'automation_devices.php':
				foreach ($selected_items as $item) {
					$result = db_fetch_assoc_prepared('SELECT id, network_id,hostname,ip,sysName,syslocation,snmp,up
							FROM automation_devices
							WHERE id IN (?)',
						[$item]);

					if (is_array($result)) {
						foreach ($result as &$row) {
							$row['snmp'] = ($row['snmp'] == 1) ? 'UP' : 'Down';
							$row['up']   = ($row['up'] == 1) ? 'Yes' : 'No';
						}

						$objects[] = $result;
					}
				}

				break;
			case 'graph_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM graph_templates
						WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'thold.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT id,name_cache AS THOLD_NAME,data_source_name AS Data_Source
						FROM thold_data
						WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'data_sources.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('select name_cache AS Data_Source_Name,active  from data_template_data
						WHERE local_data_id IN (?)',
						[$item]);
				}

				break;
			case 'data_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM data_template
						WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'aggregate_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM aggregate_graph_template
						WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'thold_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM thold_template
						WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'user_admin.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT username
						FROM user_auth
						WHERE id IN (?)',
						[$item]);
				}

				break;
			case 'user_group_admin.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM user_auth_group
						WHERE id IN (?)',
						[$item]);
				}

				break;
		}
	}

	return audit_json_encode($objects);
}

function audit_is_sensitive_key(mixed $key): int|false {
	return preg_match('/(?:pass(?:word)?|phrase|token|secret|api[_-]?key|private[_-]?key|community|credential|authorization|authentication)/i', (string) $key);
}

function audit_redact_sensitive_data(mixed $data): mixed {
	if (!is_array($data)) {
		return $data;
	}

	$redacted = [];

	foreach ($data as $key => $value) {
		if (audit_is_sensitive_key($key)) {
			$redacted[$key] = '[REDACTED]';
		} elseif (is_array($value)) {
			$redacted[$key] = audit_redact_sensitive_data($value);
		} else {
			$redacted[$key] = audit_redact_sensitive_value($value);
		}
	}

	return $redacted;
}

function audit_redact_sensitive_value(mixed $value): mixed {
	if (!is_string($value)) {
		return $value;
	}

	if (preg_match('/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/', $value) ||
		preg_match('/^(?:Bearer|Basic)\s+[A-Za-z0-9+\/_=.-]+$/i', trim($value)) ||
		preg_match('/^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/', trim($value))) {
		return '[REDACTED]';
	}

	return preg_replace('#^([a-z][a-z0-9+.-]*://[^:/@\s]+):[^@\s]+@#i', '$1:[REDACTED]@', $value);
}

function audit_bound_log_data(mixed $data, int $depth = 0, ?object $state = null): mixed {
	if ($state === null) {
		$state = (object) ['fields' => 0];
	}

	if ($depth >= 12) {
		return '[MAXIMUM DEPTH REACHED]';
	}

	if (is_array($data)) {
		$bounded = [];

		foreach ($data as $key => $value) {
			// @phpstan-ignore-next-line (property.notFound: dynamic property on stdClass state object)
			if ($state->fields >= 1000) {
				$bounded['audit_truncated'] = 'Additional fields were omitted.';

				break;
			}

			$state->fields++;
			$bounded[$key] = audit_bound_log_data($value, $depth + 1, $state);
		}

		return $bounded;
	}

	if (is_string($data) && strlen($data) > 65536) {
		return substr($data, 0, 65536) . '[TRUNCATED]';
	}

	return $data;
}

/**
 * @param  array<int,string> $arguments
 * @return array<int,string>
 */
function audit_redact_cli_arguments(array $arguments): array {
	$redacted    = [];
	$redact_next = false;

	foreach ($arguments as $argument) {
		if ($redact_next) {
			$redacted[]  = '[REDACTED]';
			$redact_next = false;

			continue;
		}

		if (preg_match('/^(--?[^=]*(?:pass(?:word)?|phrase|token|secret|api[_-]?key|private[_-]?key|community|credential|authorization|authentication)[^=]*)=(.*)$/i', $argument, $matches)) {
			$redacted[] = $matches[1] . '=[REDACTED]';

			continue;
		}

		if (preg_match('/^--?[^=]*(?:pass(?:word)?|phrase|token|secret|api[_-]?key|private[_-]?key|community|credential|authorization|authentication)/i', $argument)) {
			$redacted[]  = $argument;
			$redact_next = true;

			continue;
		}

		$redacted[] = preg_replace('#^([a-z][a-z0-9+.-]*://[^:/@\s]+):[^@\s]+@#i', '$1:[REDACTED]@', $argument) ?? $argument;
	}

	return $redacted;
}

function audit_json_encode(mixed $data, int $options = 0): string {
	$json = json_encode(audit_bound_log_data($data), JSON_INVALID_UTF8_SUBSTITUTE | $options, 16);

	if ($json === false) {
		$fallback = json_encode(['audit_encoding_error' => json_last_error_msg()]);

		return $fallback !== false ? $fallback : '{}';
	}

	return $json;
}

function audit_json_decode(mixed $json, ?string &$error = null): mixed {
	$error = null;

	try {
		return json_decode($json, true, 16, JSON_THROW_ON_ERROR);
	} catch (Throwable $exception) {
		$error = $exception->getMessage();

		return null;
	}
}

function audit_uuid_v4(): string {
	$bytes    = random_bytes(16);
	$bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
	$bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
	$hex      = bin2hex($bytes);

	return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' .
		substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
}

function audit_request_correlation_id(): string {
	static $correlation_id;

	if ($correlation_id === null) {
		$correlation_id = audit_uuid_v4();
	}

	return $correlation_id;
}

function audit_utc_time(?float $microtime = null): string {
	$microtime = $microtime === null ? microtime(true) : $microtime;
	$seconds   = (int) $microtime;
	$micros    = (int) round(($microtime - $seconds) * 1000000);

	if ($micros >= 1000000) {
		$seconds++;
		$micros = 0;
	}

	return gmdate('Y-m-d H:i:s', $seconds) . '.' . sprintf('%06d', $micros);
}

/**
 * @param array<string,mixed> $event
 */
function audit_event_integrity_hash(array $event): string {
	$material = [
		'event_uuid'       => $event['event_uuid'] ?? '',
		'correlation_id'   => $event['correlation_id'] ?? '',
		'event_type'       => $event['event_type'] ?? '',
		'user_id'          => $event['user_id'] ?? 0,
		'action'           => $event['action'] ?? '',
		'event_time'       => $event['event_time'] ?? '',
		'operation_outcome'=> $event['operation_outcome'] ?? '',
		'target_type'      => $event['target_type'] ?? '',
		'target_id'        => $event['target_id'] ?? '',
		'details'          => $event['details'] ?? ''
	];

	return hash('sha256', audit_json_encode($material, JSON_UNESCAPED_SLASHES));
}

function audit_event_type_for_request(mixed $page, mixed $action): string {
	$page_name = preg_replace('/\.php$/', '', (string) $page);
	$page_name = preg_replace('/[^a-z0-9_]+/i', '_', $page_name ?? '');
	$verb      = preg_replace('/[^a-z0-9_]+/i', '_', strtolower((string) $action));
	$verb      = trim($verb ?? '', '_');

	return 'cacti.' . ($page_name !== '' ? $page_name : 'request') . '.' .
		($verb !== '' && $verb !== 'none' ? $verb : 'submitted');
}

/**
 * @param  array<string,mixed> $event
 * @return array<string,mixed>
 */
function audit_external_event_data(array $event): array {
	$fields = [
		'id', 'event_uuid', 'correlation_id', 'event_type', 'event_category',
		'severity', 'actor_type', 'page', 'user_id', 'action', 'request_status',
		'operation_outcome', 'outcome_reason', 'target_type', 'target_id',
		'ip_address', 'user_agent', 'http_method', 'http_status', 'event_time',
		'completed_time', 'duration_ms', 'post', 'object_data', 'details',
		'previous_hash', 'integrity_hash'
	];
	$data = [];

	foreach ($fields as $field) {
		$data[$field] = $event[$field] ?? null;
	}

	return $data;
}

/**
 * @param array<string,mixed> $data
 */
function audit_external_log_format(array $data, string $format = 'json'): string {
	if ($format === 'text') {
		$fields = [];

		foreach ($data as $name => $value) {
			if (is_array($value) || is_object($value)) {
				$value = audit_json_encode($value);
			} elseif ($value === null) {
				$value = '';
			} elseif (is_bool($value)) {
				$value = $value ? 'true' : 'false';
			}

			$value = str_replace(
				['\\', "\r", "\n", "\t", '"'],
				['\\\\', '\r', '\n', '\t', '\"'],
				(string) $value
			);
			$fields[] = $name . '="' . $value . '"';
		}

		return implode(' ', $fields) . "\n";
	}

	foreach (['post', 'object_data', 'details'] as $name) {
		if (isset($data[$name]) && is_string($data[$name])) {
			$decoded = audit_json_decode($data[$name], $error);

			if ($error === null) {
				$data[$name] = $decoded;
			}
		}
	}

	return audit_json_encode($data, JSON_UNESCAPED_SLASHES) . "\n";
}

function audit_csv_safe_cell(mixed $value): string {
	$value = (string) $value;

	if (preg_match('/^[=+\-@]/', ltrim($value))) {
		return "'" . $value;
	}

	return $value;
}

function audit_retention_cutoff(mixed $retention, ?DateTimeImmutable $now = null): DateTimeImmutable {
	$now = $now instanceof DateTimeImmutable
		? $now->setTimezone(new DateTimeZone('UTC'))
		: new DateTimeImmutable('now', new DateTimeZone('UTC'));

	return $now->sub(new DateInterval('P' . max(0, (int) $retention) . 'D'));
}

/**
 * @return array<string,string>
 */
function audit_append_external_log(string $path, string $message): array {
	if ($path == '' || !is_file($path) || is_link($path)) {
		return ['status' => 'failed', 'error' => 'Destination is not a regular file or is a symbolic link.'];
	}

	$written = file_put_contents($path, $message, FILE_APPEND | LOCK_EX);

	if ($written !== strlen($message)) {
		return ['status' => 'failed', 'error' => 'Unable to append a complete record.'];
	}

	return ['status' => 'delivered', 'error' => ''];
}

function audit_set_external_status(int $id, string $status, string $error = ''): void {
	db_execute_prepared('UPDATE audit_log
		SET external_status = ?,
			external_error = ?,
			external_attempts = external_attempts + 1,
			external_last_attempt = UTC_TIMESTAMP(6),
			external_delivered_time = CASE WHEN ? = "delivered" THEN UTC_TIMESTAMP(6) ELSE external_delivered_time END
		WHERE id = ?',
		[$status, $error, $status, $id]);
}

function audit_deliver_external_event(int $id): void {
	if (read_config_option('audit_log_external') != 'on') {
		return;
	}

	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', [$id]);

	if (!is_array($event) || $event === [] || ($event['request_status'] ?? '') === 'started') {
		return;
	}

	$path = read_config_option('audit_log_external_path');

	if ($path == '' || !is_file($path) || is_link($path)) {
		audit_set_external_status($id, 'failed', 'Destination is not a regular file or is a symbolic link.');

		return;
	}

	$format   = read_config_option('audit_log_external_format') === 'text' ? 'text' : 'json';
	$message  = audit_external_log_format(audit_external_event_data($event), $format);
	$delivery = audit_append_external_log($path, $message);
	audit_set_external_status($id, $delivery['status'], $delivery['error']);
}

function audit_retry_external_logs(): void {
	if (read_config_option('audit_log_external') != 'on') {
		return;
	}

	$path = read_config_option('audit_log_external_path');

	if ($path == '' || !is_file($path) || is_link($path)) {
		return;
	}

	$format = read_config_option('audit_log_external_format');
	$format = $format === 'text' ? 'text' : 'json';

	$events = db_fetch_assoc("SELECT *
		FROM audit_log
		WHERE external_status IN ('pending', 'failed')
		AND request_status <> 'started'
		ORDER BY id
		LIMIT 100");

	if (is_array($events)) {
		foreach ($events as $event) {
			$message  = audit_external_log_format(audit_external_event_data($event), $format);
			$delivery = audit_append_external_log($path, $message);
			audit_set_external_status($event['id'], $delivery['status'], $delivery['error']);

			if ($delivery['status'] != 'delivered') {
				break;
			}
		}
	}
}

/**
 * @param array<string,mixed> $error
 */
function audit_request_status(?array $error = null, int $status_code = 200): string {
	$fatal_types = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR];

	if ((is_array($error) && in_array($error['type'] ?? null, $fatal_types, true)) ||
		$status_code >= 400) {
		return 'failed';
	}

	return 'completed';
}

/**
 * @param  array<string,mixed>      $post
 * @return array<string,mixed>|null
 */
function audit_operation_verifier_for_request(string $page, array $post): ?array {
	if ($page != 'user_admin.php' || !array_key_exists('save_component_realm_perms', $post)) {
		return null;
	}

	$target_user_id = $post['id'] ?? null;

	if (!is_scalar($target_user_id) ||
		!preg_match('/^[1-9][0-9]*$/', (string) $target_user_id)) {
		return [
			'type'           => 'invalid',
			'outcome_reason' => 'realm_permissions_request_invalid'
		];
	}

	$expected_realm_ids = [];

	foreach ($post as $field => $value) {
		$field = (string) $field;

		if (strpos($field, 'section') !== 0) {
			continue;
		}

		if (!preg_match('/^section([1-9][0-9]*)$/', $field, $matches)) {
			return [
				'type'           => 'invalid',
				'outcome_reason' => 'realm_permissions_request_invalid'
			];
		}

		$expected_realm_ids[] = (int) $matches[1];
	}

	$expected_realm_ids = array_values(array_unique($expected_realm_ids));
	sort($expected_realm_ids, SORT_NUMERIC);

	return [
		'type'               => 'user_realm_permissions',
		'target_user_id'     => (int) $target_user_id,
		'expected_realm_ids' => $expected_realm_ids
	];
}

/**
 * @return array<string,mixed>
 */
function audit_verify_operation(mixed $verifier): array {
	if (!is_array($verifier) || empty($verifier['type'])) {
		return ['outcome' => 'unknown', 'reason' => null];
	}

	if ($verifier['type'] == 'invalid') {
		return [
			'outcome' => 'unknown',
			'reason'  => $verifier['outcome_reason'] ?? 'verification_request_invalid'
		];
	}

	if ($verifier['type'] != 'user_realm_permissions') {
		return ['outcome' => 'unknown', 'reason' => 'verification_type_unsupported'];
	}

	$target_user_id     = (int) ($verifier['target_user_id'] ?? 0);
	$expected_realm_ids = $verifier['expected_realm_ids'] ?? [];
	$user_count         = db_fetch_cell_prepared('SELECT COUNT(*) FROM user_auth WHERE id = ?', [$target_user_id]);

	if ($user_count === false) {
		return ['outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed'];
	}

	if ((int) $user_count !== 1) {
		return ['outcome' => 'failure', 'reason' => 'target_user_not_found'];
	}

	$rows = db_fetch_assoc_prepared('SELECT realm_id
		FROM user_auth_realm
		WHERE user_id = ?
		ORDER BY realm_id',
		[$target_user_id]);

	if (!is_array($rows)) {
		return ['outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed'];
	}

	$actual_realm_ids = [];

	foreach ($rows as $row) {
		if (!isset($row['realm_id']) || !is_numeric($row['realm_id'])) {
			return ['outcome' => 'unknown', 'reason' => 'realm_permissions_verification_failed'];
		}

		$actual_realm_ids[] = (int) $row['realm_id'];
	}

	$actual_realm_ids = array_values(array_unique($actual_realm_ids));
	sort($actual_realm_ids, SORT_NUMERIC);

	if ($actual_realm_ids === $expected_realm_ids) {
		return ['outcome' => 'success', 'reason' => 'realm_permissions_verified'];
	}

	return ['outcome' => 'failure', 'reason' => 'realm_permissions_mismatch'];
}

/**
 * @param array<string,mixed>|null $verifier
 */
function audit_finalize_request(int $id, ?float $started_at = null, ?array $verifier = null): void {
	$status_code    = http_response_code();
	$status_code    = is_int($status_code) ? $status_code : 200;
	$request_status = audit_request_status(error_get_last(), $status_code);
	$outcome        = $request_status == 'failed' ? 'failure' : 'unknown';
	$outcome_reason = $request_status == 'failed' ? 'request_failed' : null;

	if ($request_status == 'completed' && $verifier !== null) {
		$verification   = audit_verify_operation($verifier);
		$outcome        = $verification['outcome'];
		$outcome_reason = $verification['reason'];
	}

	$duration_ms    = $started_at === null ? null : max(0, (int) round((microtime(true) - $started_at) * 1000));
	$completed_time = audit_utc_time();

	db_execute_prepared("UPDATE audit_log
		SET request_status = ?,
			outcome_reason = CASE WHEN operation_outcome = 'unknown' THEN ? ELSE outcome_reason END,
			operation_outcome = CASE WHEN operation_outcome = 'unknown' THEN ? ELSE operation_outcome END,
			http_status = ?,
			completed_time = ?,
			duration_ms = ?
		WHERE id = ?
		AND request_status = 'started'",
		[$request_status, $outcome_reason, $outcome, $status_code, $completed_time, $duration_ms, $id]);

	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', [$id]);

	if (is_array($event)) {
		db_execute_prepared('UPDATE audit_log SET integrity_hash = ? WHERE id = ?',
			[audit_event_integrity_hash($event), $id]);
	}

	audit_deliver_external_event($id);
	audit_enqueue_syslog_event($id);
}

/**
 * @param array<string,mixed> $options
 */
function audit_record_event(string $event_type, array $options = []): int {
	if (read_config_option('audit_enabled') != 'on') {
		return 0;
	}

	$event_uuid     = audit_uuid_v4();
	$correlation_id = $options['correlation_id'] ?? audit_request_correlation_id();
	$user_id        = $options['user_id'] ?? ($_SESSION['sess_user_id'] ?? 0);
	$page           = $options['page'] ?? basename($_SERVER['SCRIPT_NAME'] ?? 'cli');
	$event_suffix   = strrchr($event_type, '.');
	$action         = $options['action'] ?? ($event_suffix === false ? $event_type : substr($event_suffix, 1));
	$event_time     = $options['event_time'] ?? audit_utc_time();
	$details        = audit_json_encode(audit_redact_sensitive_data($options['details'] ?? []));
	$external       = read_config_option('audit_log_external') == 'on';
	$ip_address     = $options['ip_address'] ?? (function_exists('get_client_addr') ? get_client_addr() : '');
	$user_agent     = $options['user_agent'] ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');

	db_execute_prepared('INSERT INTO audit_log (
			page, user_id, action, request_status, ip_address, user_agent, event_time,
			post, object_data, external_status, event_uuid, correlation_id, event_type,
			event_category, severity, actor_type, target_type, target_id,
			operation_outcome, outcome_reason, http_method, http_status,
			completed_time, duration_ms, details
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
		[
			$page, $user_id, $action, 'completed', $ip_address, $user_agent, $event_time,
			'{}', '[]', $external ? 'pending' : 'disabled', $event_uuid, $correlation_id,
			$event_type, $options['event_category'] ?? 'security',
			$options['severity'] ?? 'info', $options['actor_type'] ?? ($user_id ? 'user' : 'system'),
			$options['target_type'] ?? null, isset($options['target_id']) ? (string) $options['target_id'] : null,
			$options['operation_outcome'] ?? 'success', $options['outcome_reason'] ?? null,
			$options['http_method'] ?? ($_SERVER['REQUEST_METHOD'] ?? null),
			$options['http_status'] ?? null, $options['completed_time'] ?? $event_time,
			$options['duration_ms'] ?? 0, $details
		]);

	$id    = db_fetch_insert_id();
	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', [$id]);

	if (is_array($event)) {
		db_execute_prepared('UPDATE audit_log SET integrity_hash = ? WHERE id = ?',
			[audit_event_integrity_hash($event), $id]);
	}
	audit_deliver_external_event($id);
	audit_enqueue_syslog_event($id);

	return $id;
}

function audit_logout_pre_session_destroy(): void {
	$reason = get_nfilter_request_var('action', 'user');
	$type   = $reason == 'timeout' ? 'authentication.session.expired' : 'authentication.logout';

	audit_record_event($type, [
		'event_category' => 'authentication',
		'action'         => $reason == 'timeout' ? 'timeout' : 'logout',
		'details'        => ['reason' => $reason]
	]);
}

function audit_enforce_syslog_settings_request(): void {
	$page   = basename($_SERVER['SCRIPT_NAME'] ?? '');
	$method = $_SERVER['REQUEST_METHOD'] ?? '';

	if ($page !== 'settings.php' || $method !== 'POST') {
		return;
	}

	$post = filter_input_array(INPUT_POST, FILTER_UNSAFE_RAW);
	$post = is_array($post) ? $post : [];

	if (($post['action'] ?? '') !== 'save' || ($post['tab'] ?? '') !== 'audit') {
		return;
	}

	$has_syslog_fields = false;

	foreach ($post as $name => $value) {
		if (strpos((string) $name, 'audit_syslog_') === 0) {
			$has_syslog_fields = true;

			break;
		}
	}

	if (!$has_syslog_fields) {
		return;
	}

	if (!audit_user_is_admin()) {
		audit_record_event('audit.syslog.configuration.denied', [
			'event_category'    => 'audit',
			'severity'          => 'warning',
			'action'            => 'save',
			'target_type'       => 'syslog_configuration',
			'operation_outcome' => 'failure',
			'outcome_reason'    => 'audit_admin_required'
		]);
		http_response_code(403);
		exit;
	}

	$names = [
		'receiver', 'port', 'transport', 'format', 'facility', 'application',
		'node_id', 'timeout', 'udp_max_size', 'retry_base', 'retry_max',
		'max_attempts', 'batch_size', 'pending_age_warning',
		'dead_letter_warning', 'tls_ca_file', 'tls_client_cert',
		'tls_client_key'
	];
	$overrides = [];

	foreach ($names as $name) {
		$setting          = 'audit_syslog_' . $name;
		$overrides[$name] = isset($post[$setting]) && is_scalar($post[$setting])
			? (string) $post[$setting]
			: '';
	}

	$config      = audit_syslog_config($overrides);
	$enabling    = isset($post['audit_syslog_enabled']) && $post['audit_syslog_enabled'] === 'on';
	$configuring = trim($overrides['receiver'] ?? '') !== '';

	if (($enabling || $configuring) && !$config['valid']) {
		audit_record_event('audit.syslog.configuration.rejected', [
			'event_category'    => 'audit',
			'severity'          => 'warning',
			'action'            => 'save',
			'target_type'       => 'syslog_configuration',
			'operation_outcome' => 'failure',
			'outcome_reason'    => 'configuration_invalid',
			'details'           => ['errors' => $config['errors']]
		]);

		raise_message(
			'audit_syslog_configuration',
			__('Remote Syslog settings were not saved: %s', implode(', ', $config['errors']), 'audit'),
			MESSAGE_LEVEL_ERROR
		);
		header('Location: settings.php?tab=audit');
		exit;
	}
}

function audit_config_insert(): void {
	global $action, $config;

	audit_enforce_syslog_settings_request();

	if (audit_log_valid_event()) {
		$started_at = microtime(true);
		// prepare post
		$post = filter_input_array(INPUT_POST, FILTER_UNSAFE_RAW);
		$post = is_array($post) ? $post : [];

		// remove unsafe variables
		unset($post['__csrf_magic']);
		unset($post['header']);
		$post = audit_redact_sensitive_data($post);

		// check if drp_action is present and update action accordingly
		if (isset($post['drp_action']) && $post['drp_action'] == 1) {
			$action = 'delete';
		} elseif (isset($post['drp_action']) && $post['drp_action'] == 4) {
			$action = 'disable';
		}

		// sanitize and serialize selected items
		if (isset($post['selected_items']) && is_string($post['selected_items'])) {
			$selected_items = @unserialize(stripslashes($post['selected_items']), ['allowed_classes' => false]);
			$selected_items = is_array($selected_items) ? $selected_items : [];
			$drop_action    = $post['drp_action'] ?? false;
		} else {
			$selected_items = [];
			$drop_action    = false;
		}

		$target_id   = $post['id'] ?? null;
		$page        = basename($_SERVER['SCRIPT_NAME']);
		$verifier    = audit_operation_verifier_for_request($page, $post);
		$post        = audit_json_encode($post);
		$user_id     = (isset($_SESSION['sess_user_id']) ? $_SESSION['sess_user_id'] : 0);
		$event_time  = audit_utc_time($started_at);

		// Retrieve IP address
		$ip_address  = get_client_addr();

		// Get the User Agent
		$user_agent  = $_SERVER['HTTP_USER_AGENT'] ?? '';

		if (empty($action) && isset_request_var('action')) {
			$action = get_nfilter_request_var('action');
		} elseif (empty($action)) {
			$action = 'none';
		}

		$object_data = audit_process_page_data($page, $drop_action, $selected_items);

		switch ($page) {
			case 'automation_devices.php':
				switch ($drop_action) {
					case 2:
						$action = 'Delete Device';

						break;
					case 1:
						$action = 'Create Device';

						break;
				}

				break;
			case 'host.php':
				switch ($drop_action) {
					case 2:
						$action = 'Host Enabled';

						break;
					case 3:
						$action = 'Host Disabled';

						break;
				}

				break;
		}

		$audit_log        = read_config_option('audit_log_external_path');
		$external_logging = read_config_option('audit_log_external') == 'on';
		$external_status  = $external_logging ? 'pending' : 'disabled';

		if (!defined('CACTI_PATH_BASE')) {
			$base = $config['base_path'];
		} else {
			$base = CACTI_PATH_BASE;
		}

		$event_uuid     = audit_uuid_v4();
		$correlation_id = audit_request_correlation_id();
		$event_type     = audit_event_type_for_request($page, $action);
		$category       = in_array($page, ['user_admin.php', 'user_group_admin.php'], true) ? 'identity_access' : 'configuration';
		db_execute_prepared('INSERT INTO audit_log (
				page, user_id, action, request_status, ip_address, user_agent, event_time,
				post, object_data, external_status, event_uuid, correlation_id, event_type,
				event_category, severity, actor_type, target_type, target_id,
				operation_outcome, http_method
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			[
				$page, $user_id, $action, 'started', $ip_address, $user_agent, $event_time,
				$post, $object_data, $external_status, $event_uuid, $correlation_id,
				$event_type, $category, 'info', $user_id ? 'user' : 'system',
				preg_replace('/\.php$/', '', $page), $target_id, 'unknown',
				$_SERVER['REQUEST_METHOD'] ?? null
			]);
		$audit_id = db_fetch_insert_id();
		register_shutdown_function('audit_finalize_request', $audit_id, $started_at, $verifier);

		if ($external_logging && $audit_log == '') {
			set_config_option('audit_log_external_path', $base . '/log/audit.log');
			$audit_log = $base . '/log/audit.log';
		}

		if ($external_logging && $audit_log != '' && !file_exists($audit_log)) {
			if (is_writable(dirname($audit_log))) {
				cacti_log(sprintf('NOTE: The Audit Log file \'%s\' does not exist.  Creating it.', $audit_log), false, 'AUDIT');

				if (!touch($audit_log)) {
					cacti_log(sprintf('ERROR: Unable to create Audit Log file \'%s\'.', $audit_log), false, 'AUDIT');
				} else {
					@chmod($audit_log, 0600);
				}
			} else {
				cacti_log(sprintf('ERROR: Audit Log file path \'%s\' does not exist and the path is not writeable.', $audit_log), false, 'AUDIT');
			}
		}

		if ($external_logging && $audit_log != '' && (!is_file($audit_log) || is_link($audit_log))) {
			$error = 'Destination is not a regular file or is a symbolic link.';
			audit_set_external_status($audit_id, 'failed', $error);
			cacti_log(sprintf('ERROR: Audit Log file \'%s\' is not a regular file or is a symbolic link.', $audit_log), false, 'AUDIT');
		}
	} elseif (isset($_SERVER['argv']) && cacti_sizeof($_SERVER['argv'])) {
		$started_at = microtime(true);
		$arguments  = audit_redact_cli_arguments($_SERVER['argv']);
		$page       = basename($arguments[0]);
		$user_id    = 0;
		$action     = 'cli';
		$ip_address = gethostbyname(php_uname('n'));
		$user_agent = get_current_user();
		$event_time = audit_utc_time($started_at);
		$post       = implode(' ', $arguments);

		// don't insert poller records
		if (strpos($arguments[0], 'poller')         === false &&
			strpos($arguments[0], 'cmd.php')           === false &&
			strpos($arguments[0], '/scripts/')         === false &&
			strpos($arguments[0], 'script_server.php') === false &&
			strpos($arguments[0], '_process.php')      === false) {
			$external_status = read_config_option('audit_log_external') == 'on' ? 'pending' : 'disabled';
			db_execute_prepared('INSERT INTO audit_log (
					page, user_id, action, request_status, ip_address, user_agent, event_time,
					post, object_data, external_status, event_uuid, correlation_id, event_type,
					event_category, severity, actor_type, target_type, target_id,
					operation_outcome
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
				[
					$page, $user_id, $action, 'started', $ip_address, $user_agent,
					$event_time, $post, '[]', $external_status, audit_uuid_v4(),
					audit_request_correlation_id(), 'cacti.cli.executed', 'system',
					'info', 'system', 'cli_command', $page, 'unknown'
				]);
			$audit_id = db_fetch_insert_id();
			register_shutdown_function('audit_finalize_request', $audit_id, $started_at);
		}
	}
}
