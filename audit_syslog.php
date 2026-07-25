<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
*/

function audit_syslog_enabled(): bool {
	return read_config_option('audit_syslog_enabled') == 'on';
}

function audit_syslog_read_setting(string $name, mixed $default): mixed {
	$value = read_config_option($name);

	return $value === '' || $value === null ? $default : $value;
}

/**
 * @param array<int,string> $errors
 */
function audit_syslog_bounded_integer(mixed $value, int $default, int $minimum, int $maximum, array &$errors, string $name): int {
	if (!is_scalar($value) || !preg_match('/^[0-9]+$/', (string) $value)) {
		$errors[] = $name . '_invalid';

		return $default;
	}

	$value = (int) $value;

	if ($value < $minimum || $value > $maximum) {
		$errors[] = $name . '_out_of_range';

		return $default;
	}

	return $value;
}

function audit_syslog_valid_receiver(string $receiver): bool {
	if ($receiver === '' || strlen($receiver) > 253 ||
		preg_match('/[[:cntrl:][:space:]\\/@]/', $receiver) ||
		strpos($receiver, '://') !== false) {
		return false;
	}

	if (filter_var($receiver, FILTER_VALIDATE_IP) !== false) {
		return true;
	}

	if (substr($receiver, -1) === '.') {
		$receiver = substr($receiver, 0, -1);
	}

	if ($receiver === '' || strlen($receiver) > 253) {
		return false;
	}

	$labels = explode('.', $receiver);

	foreach ($labels as $label) {
		if ($label === '' || strlen($label) > 63 ||
			!preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i', $label)) {
			return false;
		}
	}

	return true;
}

function audit_syslog_valid_header_value(string $value, int $maximum): bool {
	return $value !== '' && strlen($value) <= $maximum &&
		!preg_match('/[^\\x21-\\x7e]|[\\[\\]="]/', $value);
}

/**
 * @param array<int,string> $errors
 */
function audit_syslog_validate_optional_file(string $path, string $name, array &$errors): string {
	if ($path === '') {
		return '';
	}

	if ($path[0] !== '/' || !is_file($path) || is_link($path) || !is_readable($path)) {
		$errors[] = $name . '_invalid';
	}

	return $path;
}

/**
 * @param  array<string,mixed> $overrides
 * @return array<string,mixed>
 */
function audit_syslog_config(array $overrides = []): array {
	$defaults = [
		'receiver'            => '',
		'port'                => '',
		'transport'           => 'udp',
		'format'              => 'json',
		'facility'            => 'local0',
		'application'         => 'cacti-audit',
		'node_id'             => php_uname('n'),
		'timeout'             => '5',
		'udp_max_size'        => '8192',
		'retry_base'          => '30',
		'retry_max'           => '3600',
		'max_attempts'        => '10',
		'batch_size'          => '100',
		'pending_age_warning' => '900',
		'dead_letter_warning' => '1',
		'tls_ca_file'         => '',
		'tls_client_cert'     => '',
		'tls_client_key'      => ''
	];
	$values = [];

	foreach ($defaults as $name => $default) {
		$setting       = 'audit_syslog_' . $name;
		$values[$name] = array_key_exists($name, $overrides)
			? $overrides[$name]
			: audit_syslog_read_setting($setting, $default);
	}

	$errors   = [];
	$receiver = trim((string) ($values['receiver'] ?? ''));

	if (!audit_syslog_valid_receiver($receiver)) {
		$errors[] = 'receiver_invalid';
	}

	$transport = strtolower((string) ($values['transport'] ?? ''));

	if (!in_array($transport, ['udp', 'tcp', 'tls'], true)) {
		$errors[]  = 'transport_invalid';
		$transport = 'udp';
	}

	$format = strtolower((string) ($values['format'] ?? ''));

	if (!in_array($format, ['rfc5424', 'cef', 'json'], true)) {
		$errors[] = 'format_invalid';
		$format   = 'json';
	}

	$facility_map = audit_syslog_facilities();
	$facility     = strtolower((string) ($values['facility'] ?? ''));

	if (!isset($facility_map[$facility])) {
		$errors[] = 'facility_invalid';
		$facility = 'local0';
	}

	$application = trim((string) ($values['application'] ?? ''));

	if (!audit_syslog_valid_header_value($application, 48)) {
		$errors[]    = 'application_invalid';
		$application = 'cacti-audit';
	}

	$node_id = trim((string) ($values['node_id'] ?? ''));

	if (!audit_syslog_valid_header_value($node_id, 255)) {
		$errors[] = 'node_id_invalid';
		$node_id  = 'cacti';
	}

	$port = trim((string) ($values['port'] ?? '')) === ''
		? ($transport === 'tls' ? 6514 : 514)
		: audit_syslog_bounded_integer($values['port'] ?? '', $transport === 'tls' ? 6514 : 514, 1, 65535, $errors, 'port');
	$timeout             = audit_syslog_bounded_integer($values['timeout'] ?? 5, 5, 1, 30, $errors, 'timeout');
	$udp_max_size        = audit_syslog_bounded_integer($values['udp_max_size'] ?? 8192, 8192, 512, 65507, $errors, 'udp_max_size');
	$retry_base          = audit_syslog_bounded_integer($values['retry_base'] ?? 30, 30, 1, 3600, $errors, 'retry_base');
	$retry_max           = audit_syslog_bounded_integer($values['retry_max'] ?? 3600, 3600, 1, 86400, $errors, 'retry_max');
	$max_attempts        = audit_syslog_bounded_integer($values['max_attempts'] ?? 10, 10, 1, 100, $errors, 'max_attempts');
	$batch_size          = audit_syslog_bounded_integer($values['batch_size'] ?? 100, 100, 1, 1000, $errors, 'batch_size');
	$pending_age_warning = audit_syslog_bounded_integer($values['pending_age_warning'] ?? 900, 900, 60, 604800, $errors, 'pending_age_warning');
	$dead_letter_warning = audit_syslog_bounded_integer($values['dead_letter_warning'] ?? 1, 1, 1, 1000000, $errors, 'dead_letter_warning');

	if ($retry_max < $retry_base) {
		$errors[]  = 'retry_max_less_than_base';
		$retry_max = $retry_base;
	}

	$tls_ca_file     = trim((string) ($values['tls_ca_file'] ?? ''));
	$tls_client_cert = trim((string) ($values['tls_client_cert'] ?? ''));
	$tls_client_key  = trim((string) ($values['tls_client_key'] ?? ''));

	if ($transport === 'tls') {
		audit_syslog_validate_optional_file($tls_ca_file, 'tls_ca_file', $errors);
		audit_syslog_validate_optional_file($tls_client_cert, 'tls_client_cert', $errors);
		audit_syslog_validate_optional_file($tls_client_key, 'tls_client_key', $errors);

		if (($tls_client_cert === '') !== ($tls_client_key === '')) {
			$errors[] = 'tls_client_identity_incomplete';
		}
	}

	$config = [
		'receiver'             => $receiver,
		'port'                 => $port,
		'transport'            => $transport,
		'format'               => $format,
		'facility'             => $facility,
		'application'          => $application,
		'node_id'              => $node_id,
		'timeout'              => $timeout,
		'udp_max_size'         => $udp_max_size,
		'retry_base'           => $retry_base,
		'retry_max'            => $retry_max,
		'max_attempts'         => $max_attempts,
		'batch_size'           => $batch_size,
		'pending_age_warning'  => $pending_age_warning,
		'dead_letter_warning'  => $dead_letter_warning,
		'tls_ca_file'          => $tls_ca_file,
		'tls_client_cert'      => $tls_client_cert,
		'tls_client_key'       => $tls_client_key,
		'poller_id'            => defined('POLLER_ID') ? (string) POLLER_ID : '',
		'tls_verify_peer'      => true,
		'tls_verify_peer_name' => true,
		'errors'               => array_values(array_unique($errors))
	];
	$config['valid']       = empty($config['errors']);
	$config['fingerprint'] = audit_syslog_destination_fingerprint($config);

	return $config;
}

/**
 * @param array<string,mixed> $config
 */
function audit_syslog_destination_fingerprint(array $config): string {
	$identity = [
		'receiver'        => $config['receiver'],
		'port'            => (int) $config['port'],
		'transport'       => $config['transport'],
		'format'          => $config['format'],
		'facility'        => $config['facility'],
		'application'     => $config['application'],
		'node_id'         => $config['node_id'],
		'tls_ca_file'     => $config['tls_ca_file'],
		'tls_client_cert' => $config['tls_client_cert']
	];

	return hash('sha256', audit_json_encode($identity, JSON_UNESCAPED_SLASHES));
}

/**
 * @return array<string,int>
 */
function audit_syslog_facilities(): array {
	return [
		'kern'   => 0, 'user' => 1, 'mail' => 2, 'daemon' => 3,
		'auth'   => 4, 'syslog' => 5, 'lpr' => 6, 'news' => 7,
		'uucp'   => 8, 'cron' => 9, 'authpriv' => 10, 'ftp' => 11,
		'ntp'    => 12, 'audit' => 13, 'alert' => 14, 'clock' => 15,
		'local0' => 16, 'local1' => 17, 'local2' => 18, 'local3' => 19,
		'local4' => 20, 'local5' => 21, 'local6' => 22, 'local7' => 23
	];
}

function audit_syslog_severity_code(mixed $severity): int {
	$map = [
		'emergency' => 0, 'emerg' => 0, 'alert' => 1, 'critical' => 2,
		'crit'      => 2, 'error' => 3, 'err' => 3, 'warning' => 4,
		'warn'      => 4, 'notice' => 5, 'info' => 6, 'debug' => 7
	];
	$severity = strtolower((string) $severity);

	return isset($map[$severity]) ? $map[$severity] : 6;
}

function audit_syslog_header_token(mixed $value, int $maximum, string $fallback): string {
	$value = preg_replace('/[^\\x21-\\x3c\\x3e-\\x5a\\x5e-\\x7e]/', '_', (string) $value);
	$value = substr($value ?? '', 0, $maximum);

	return $value === '' ? $fallback : $value;
}

function audit_syslog_structured_value(mixed $value): string {
	$value = preg_replace('/[\\x00-\\x1f\\x7f]/', ' ', (string) $value);

	return str_replace(['\\', '"', ']'], ['\\\\', '\\"', '\\]'], $value ?? '');
}

function audit_syslog_timestamp(mixed $value): string {
	$value = (string) $value;

	if (preg_match('/^([0-9]{4}-[0-9]{2}-[0-9]{2})[ T]([0-9]{2}:[0-9]{2}:[0-9]{2})(\\.[0-9]{1,6})?/', $value, $matches)) {
		return $matches[1] . 'T' . $matches[2] . (isset($matches[3]) ? $matches[3] : '') . 'Z';
	}

	return gmdate('Y-m-d\\TH:i:s\\Z');
}

/**
 * @param  array<string,mixed> $event
 * @param  array<string,mixed> $config
 * @return array<string,mixed>
 */
function audit_syslog_normalized_data(array $event, array $config): array {
	$data              = audit_external_event_data($event);
	$data['node_id']   = $config['node_id'];
	$data['poller_id'] = $config['poller_id'] !== '' ? $config['poller_id'] : null;

	return $data;
}

function audit_syslog_cef_escape_header(mixed $value): string {
	return str_replace(['\\', '|', "\r", "\n"], ['\\\\', '\\|', ' ', ' '], (string) $value);
}

function audit_syslog_cef_escape_extension(mixed $value): string {
	return str_replace(
		['\\', '=', "\r", "\n"],
		['\\\\', '\\=', '\\r', '\\n'],
		(string) $value
	);
}

function audit_syslog_cef_severity(mixed $severity): int {
	$map = [
		'emergency' => 10, 'emerg' => 10, 'alert' => 10,
		'critical'  => 9, 'crit' => 9, 'error' => 8, 'err' => 8,
		'warning'   => 6, 'warn' => 6, 'notice' => 5,
		'info'      => 3, 'debug' => 1
	];
	$severity = strtolower((string) $severity);

	return isset($map[$severity]) ? $map[$severity] : 3;
}

function audit_syslog_cef_event_field(mixed $value): string {
	if (is_string($value) && $value !== '') {
		$decoded = audit_json_decode($value, $error);

		if ($error === null) {
			$value = $decoded;
		}
	}

	if (is_array($value)) {
		return audit_json_encode(
			audit_redact_sensitive_data($value),
			JSON_UNESCAPED_SLASHES
		);
	}

	if ($value === null) {
		return '';
	}

	if (is_bool($value)) {
		return $value ? 'true' : 'false';
	}

	return audit_redact_sensitive_value((string) $value);
}

/**
 * @param array<string,mixed> $event
 * @param array<string,mixed> $config
 */
function audit_syslog_cef_payload(array $event, array $config): string {
	$severity = audit_syslog_cef_severity($event['severity'] ?? 'info');
	$header   = [
		'CEF:0',
		'Cacti',
		'Audit Plugin',
		'1.5',
		$event['event_type'] ?? 'cacti.audit',
		$event['action'] ?? 'audit',
		$severity
	];
	$extension = [
		'externalId' => $event['event_uuid'] ?? '',
		'suser'      => $event['user_id'] ?? '',
		'src'        => $event['ip_address'] ?? '',
		'act'        => $event['action'] ?? '',
		'outcome'    => $event['operation_outcome'] ?? '',
		'cs1Label'   => 'Correlation ID',
		'cs1'        => $event['correlation_id'] ?? '',
		'cs2Label'   => 'Target',
		'cs2'        => trim(($event['target_type'] ?? '') . ':' . ($event['target_id'] ?? ''), ':'),
		'cs3Label'   => 'Node ID',
		'cs3'        => $config['node_id'],
		'cn1Label'   => 'Poller ID',
		'cn1'        => $config['poller_id'],
		'cs4Label'   => 'Submitted Data',
		'cs4'        => audit_syslog_cef_event_field($event['post'] ?? ''),
		'cs5Label'   => 'Object Data',
		'cs5'        => audit_syslog_cef_event_field($event['object_data'] ?? ''),
		'cs6Label'   => 'Details',
		'cs6'        => audit_syslog_cef_event_field($event['details'] ?? '')
	];
	$encoded_header    = array_map('audit_syslog_cef_escape_header', $header);
	$encoded_extension = [];

	foreach ($extension as $name => $value) {
		$encoded_extension[] = $name . '=' . audit_syslog_cef_escape_extension($value);
	}

	return implode('|', $encoded_header) . '|' . implode(' ', $encoded_extension);
}

/**
 * @param array<string,mixed> $event
 * @param array<string,mixed> $config
 */
function audit_syslog_message_payload(array $event, array $config): string {
	if ($config['format'] === 'cef') {
		return audit_syslog_cef_payload($event, $config);
	}

	if ($config['format'] === 'json') {
		return audit_json_encode(audit_syslog_normalized_data($event, $config), JSON_UNESCAPED_SLASHES);
	}

	return 'Audit event ' . (string) ($event['event_uuid'] ?? '');
}

/**
 * @param  array<string,mixed> $event
 * @param  array<string,mixed> $config
 * @return array<string,mixed>
 */
function audit_syslog_record(array $event, array $config): array {
	if (empty($config['valid'])) {
		return [
			'status'     => 'failed',
			'permanent'  => true,
			'error_code' => 'configuration_invalid',
			'error'      => implode(',', $config['errors']),
			'record'     => ''
		];
	}

	$facilities = audit_syslog_facilities();
	$priority   = ($facilities[$config['facility']] * 8) +
		audit_syslog_severity_code($event['severity'] ?? 'info');
	$timestamp         = audit_syslog_timestamp($event['event_time'] ?? '');
	$hostname          = audit_syslog_header_token($config['node_id'], 255, 'cacti');
	$application       = audit_syslog_header_token($config['application'], 48, 'cacti-audit');
	$poller_id         = $config['poller_id'] !== '' ? $config['poller_id'] : '-';
	$process           = audit_syslog_header_token($poller_id, 128, '-');
	$message_id        = audit_syslog_header_token($event['event_type'] ?? 'cacti.audit', 32, 'cacti.audit');
	$structured_values = [
		'eventUuid'     => $event['event_uuid'] ?? '',
		'correlationId' => $event['correlation_id'] ?? '',
		'nodeId'        => $config['node_id'],
		'pollerId'      => $config['poller_id'],
		'outcome'       => $event['operation_outcome'] ?? '',
		'targetType'    => $event['target_type'] ?? '',
		'targetId'      => $event['target_id'] ?? '',
		'integrityHash' => $event['integrity_hash'] ?? ''
	];
	$structured = [];

	foreach ($structured_values as $name => $value) {
		$structured[] = $name . '="' . audit_syslog_structured_value($value) . '"';
	}

	$record = '<' . $priority . '>1 ' . $timestamp . ' ' . $hostname . ' ' .
		$application . ' ' . $process . ' ' . $message_id .
		' [cactiAudit@23925 ' . implode(' ', $structured) . '] ' .
		audit_syslog_message_payload($event, $config);

	if (strlen($record) > 262144) {
		return [
			'status'     => 'failed',
			'permanent'  => true,
			'error_code' => 'message_too_large',
			'error'      => 'The formatted Syslog record exceeds 262144 bytes.',
			'record'     => ''
		];
	}

	if ($config['transport'] === 'udp' && strlen($record) > $config['udp_max_size']) {
		return [
			'status'     => 'failed',
			'permanent'  => true,
			'error_code' => 'udp_message_too_large',
			'error'      => 'The formatted Syslog record exceeds the configured UDP maximum.',
			'record'     => ''
		];
	}

	return [
		'status'     => 'ready',
		'permanent'  => false,
		'error_code' => '',
		'error'      => '',
		'record'     => $record
	];
}

function audit_syslog_frame(string $record, string $transport): string {
	if ($transport === 'tcp' || $transport === 'tls') {
		return strlen($record) . ' ' . $record;
	}

	return $record;
}

/**
 * @param array<string,mixed> $config
 */
function audit_syslog_socket_target(array $config): string {
	$receiver = $config['receiver'];

	if (filter_var($receiver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
		$receiver = '[' . $receiver . ']';
	}

	$scheme = $config['transport'] === 'tls' ? 'tls' : $config['transport'];

	return $scheme . '://' . $receiver . ':' . $config['port'];
}

function audit_syslog_stream_operation(callable $operation, string &$warning = ''): mixed {
	$warning = '';
	$handler = function ($severity, $message) use (&$warning) {
		$warning = audit_syslog_bounded_error($message);

		return true;
	};

	set_error_handler($handler);

	try {
		return call_user_func($operation);
	} catch (Throwable $exception) {
		$warning = audit_syslog_bounded_error($exception->getMessage());

		return false;
	} finally {
		restore_error_handler();
	}
}

/**
 * @param  array<string,mixed> $config
 * @return array<string,mixed>
 */
function audit_syslog_open_socket(array $config): array {
	$context_options = [];

	if ($config['transport'] === 'tls') {
		$context_options['ssl'] = [
			'verify_peer'         => true,
			'verify_peer_name'    => true,
			'allow_self_signed'   => false,
			'peer_name'           => $config['receiver'],
			'SNI_enabled'         => true,
			'disable_compression' => true
		];

		if ($config['tls_ca_file'] !== '') {
			$context_options['ssl']['cafile'] = $config['tls_ca_file'];
		}

		if ($config['tls_client_cert'] !== '') {
			$context_options['ssl']['local_cert'] = $config['tls_client_cert'];
			$context_options['ssl']['local_pk']   = $config['tls_client_key'];
		}
	}

	$context        = stream_context_create($context_options);
	$error_number   = 0;
	$error_message  = '';
	$flags          = STREAM_CLIENT_CONNECT;
	$stream_warning = '';
	$socket         = audit_syslog_stream_operation(function () use (
		$config,
		&$error_number,
		&$error_message,
		$flags,
		$context
	) {
		return stream_socket_client(
			audit_syslog_socket_target($config),
			$error_number,
			$error_message,
			$config['timeout'],
			$flags,
			$context
		);
	}, $stream_warning);

	if ($socket === false) {
		$error = $error_message !== ''
			? $error_message
			: ($stream_warning !== '' ? $stream_warning : 'Unable to connect to Syslog receiver.');

		return [
			'socket'     => null,
			'error_code' => 'connection_failed',
			'error'      => audit_syslog_bounded_error($error)
		];
	}

	stream_set_timeout($socket, $config['timeout']);
	stream_set_blocking($socket, true);

	return ['socket' => $socket, 'error_code' => '', 'error' => ''];
}

function audit_syslog_bounded_error(mixed $error): string {
	$error = preg_replace('/[\\x00-\\x1f\\x7f]+/', ' ', (string) $error);

	return substr(trim($error ?? ''), 0, 1024);
}

function audit_syslog_fwrite(mixed $socket, string $message, string &$warning = ''): int|false {
	return audit_syslog_stream_operation(function () use ($socket, $message) {
		return fwrite($socket, $message);
	}, $warning);
}

/**
 * @return array<string,mixed>
 */
function audit_syslog_write(mixed $socket, string $message, string $transport): array {
	if (!is_resource($socket)) {
		return ['status' => 'failed', 'error_code' => 'socket_unavailable', 'error' => 'Syslog socket is unavailable.'];
	}

	if ($transport === 'udp') {
		$stream_warning = '';
		$written        = audit_syslog_fwrite($socket, $message, $stream_warning);

		if ($written !== strlen($message)) {
			$error = $stream_warning !== ''
				? $stream_warning
				: 'Unable to write the complete Syslog datagram.';

			return ['status' => 'failed', 'error_code' => 'write_failed', 'error' => $error];
		}
	} else {
		$length = strlen($message);
		$offset = 0;

		while ($offset < $length) {
			$stream_warning = '';
			$written        = audit_syslog_fwrite($socket, substr($message, $offset), $stream_warning);

			if ($written === false || $written === 0) {
				$metadata = stream_get_meta_data($socket);
				$error    = !empty($metadata['timed_out'])
					? 'Syslog write timed out.'
					: ($stream_warning !== '' ? $stream_warning : 'Unable to write the complete Syslog record.');

				return ['status' => 'failed', 'error_code' => 'write_failed', 'error' => $error];
			}

			$offset += $written;
		}
	}

	return ['status' => 'sent_unconfirmed', 'error_code' => '', 'error' => ''];
}

/**
 * @param  array<string,mixed> $event
 * @param  array<string,mixed> $config
 * @return array<string,mixed>
 */
function audit_syslog_send_event(array $event, array $config, mixed &$socket = null): array {
	$formatted = audit_syslog_record($event, $config);

	if ($formatted['status'] !== 'ready') {
		return $formatted;
	}

	if (!is_resource($socket)) {
		$opened = audit_syslog_open_socket($config);

		if (!is_resource($opened['socket'])) {
			return [
				'status'     => 'failed',
				'permanent'  => false,
				'error_code' => $opened['error_code'],
				'error'      => $opened['error']
			];
		}

		$socket = $opened['socket'];
	}

	$message             = audit_syslog_frame($formatted['record'], $config['transport']);
	$result              = audit_syslog_write($socket, $message, $config['transport']);
	$result['permanent'] = false;

	if ($result['status'] !== 'sent_unconfirmed' && is_resource($socket)) {
		fclose($socket);
		$socket = null;
	}

	return $result;
}

function audit_enqueue_syslog_event(int $audit_id): void {
	if (!audit_syslog_enabled() || !db_table_exists('audit_syslog_delivery')) {
		return;
	}

	$event = db_fetch_row_prepared('SELECT id, event_uuid, request_status
		FROM audit_log
		WHERE id = ?',
		[$audit_id]);

	if (!is_array($event) || $event['request_status'] === 'started' || $event['event_uuid'] === '') {
		return;
	}

	$config = audit_syslog_config();
	$state  = $config['valid'] ? 'pending' : 'dead_letter';
	$error  = $config['valid'] ? null : audit_syslog_bounded_error('configuration_invalid: ' . implode(',', $config['errors']));

	db_execute_prepared('INSERT IGNORE INTO audit_syslog_delivery (
			audit_id, event_uuid, destination_fingerprint, node_id, poller_id, state, attempts,
			next_attempt, last_error, created_time, updated_time
		) VALUES (?, ?, ?, ?, ?, ?, 0, UTC_TIMESTAMP(6), ?, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))',
		[
			$event['id'], $event['event_uuid'], $config['fingerprint'],
			$config['node_id'], $config['poller_id'], $state, $error
		]);
}

/**
 * @param  array<string,mixed> $config
 * @param  array<string,mixed> $delivery
 * @return array<string,mixed>
 */
function audit_syslog_delivery_config(array $config, array $delivery): array {
	if (isset($delivery['delivery_node_id']) && $delivery['delivery_node_id'] !== '') {
		$config['node_id'] = $delivery['delivery_node_id'];
	}

	if (array_key_exists('delivery_poller_id', $delivery)) {
		$config['poller_id'] = (string) $delivery['delivery_poller_id'];
	}

	$config['fingerprint'] = audit_syslog_destination_fingerprint($config);

	return $config;
}

/**
 * @param array<string,mixed> $config
 */
function audit_syslog_retry_delay(mixed $attempt, array $config): int {
	$exponent = min(max(0, (int) $attempt - 1), 30);
	$delay    = $config['retry_base'] * pow(2, $exponent);

	return (int) min($config['retry_max'], $delay);
}

/**
 * @param array<string,mixed> $delivery
 * @param array<string,mixed> $result
 * @param array<string,mixed> $config
 */
function audit_syslog_update_delivery(array $delivery, array $result, array $config): void {
	$attempts = (int) $delivery['attempts'] + 1;
	$error    = isset($result['error']) ? audit_syslog_bounded_error($result['error']) : '';

	if ($result['status'] === 'sent_unconfirmed') {
		db_execute_prepared("UPDATE audit_syslog_delivery
			SET state = 'sent_unconfirmed',
				destination_fingerprint = ?,
				attempts = ?,
				last_attempt = UTC_TIMESTAMP(6),
				sent_time = UTC_TIMESTAMP(6),
				last_error = NULL,
				updated_time = UTC_TIMESTAMP(6)
			WHERE id = ?",
			[$config['fingerprint'], $attempts, $delivery['delivery_id']]);

		return;
	}

	$permanent    = !empty($result['permanent']) || $attempts >= $config['max_attempts'];
	$state        = $permanent ? 'dead_letter' : 'retry';
	$delay        = $permanent ? 0 : audit_syslog_retry_delay($attempts, $config);
	$error_code   = isset($result['error_code']) ? $result['error_code'] : 'delivery_failed';
	$stored_error = audit_syslog_bounded_error($error_code . ': ' . $error);

	db_execute_prepared('UPDATE audit_syslog_delivery
		SET state = ?,
			destination_fingerprint = ?,
			attempts = ?,
			next_attempt = CASE WHEN ? = 0 THEN next_attempt ELSE DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND) END,
			last_attempt = UTC_TIMESTAMP(6),
			last_error = ?,
			updated_time = UTC_TIMESTAMP(6)
		WHERE id = ?',
		[$state, $config['fingerprint'], $attempts, $delay, $delay, $stored_error, $delivery['delivery_id']]);
}

function audit_process_syslog_queue(): void {
	if (!audit_syslog_enabled() || !db_table_exists('audit_syslog_delivery')) {
		return;
	}

	$config = audit_syslog_config();

	if (!$config['valid']) {
		audit_syslog_check_health($config);

		return;
	}

	$batch_size = (int) $config['batch_size'];
	$deliveries = db_fetch_assoc_prepared("SELECT
			d.id AS delivery_id, d.attempts, d.event_uuid AS delivery_event_uuid,
			d.node_id AS delivery_node_id, d.poller_id AS delivery_poller_id,
			a.*
		FROM audit_syslog_delivery AS d
		INNER JOIN audit_log AS a
		ON a.id = d.audit_id
		WHERE d.state IN ('pending', 'retry')
		AND d.next_attempt <= UTC_TIMESTAMP(6)
		AND a.request_status <> 'started'
		ORDER BY d.next_attempt, d.id
		LIMIT " . $batch_size,
		[]);
	$socket = null;

	if (is_array($deliveries)) {
		foreach ($deliveries as $delivery) {
			$delivery_config = audit_syslog_delivery_config($config, $delivery);
			$result          = audit_syslog_send_event($delivery, $delivery_config, $socket);
			audit_syslog_update_delivery($delivery, $result, $delivery_config);

			if ($result['status'] !== 'sent_unconfirmed' && empty($result['permanent'])) {
				break;
			}
		}
	}

	if (is_resource($socket)) {
		fclose($socket);
	}

	audit_syslog_check_health($config);
}

/**
 * @return array<string,mixed>
 */
function audit_syslog_health(): array {
	if (!db_table_exists('audit_syslog_delivery')) {
		return [
			'pending'      => 0, 'retry' => 0, 'sent_unconfirmed' => 0,
			'dead_letter'  => 0, 'oldest_pending_seconds' => 0,
			'last_attempt' => null, 'last_sent' => null, 'last_error' => null
		];
	}

	$row = db_fetch_row("SELECT
			SUM(state = 'pending') AS pending,
			SUM(state = 'retry') AS retry,
			SUM(state = 'sent_unconfirmed') AS sent_unconfirmed,
			SUM(state = 'dead_letter') AS dead_letter,
			COALESCE(MAX(CASE WHEN state IN ('pending', 'retry')
				THEN TIMESTAMPDIFF(SECOND, created_time, UTC_TIMESTAMP(6)) ELSE 0 END), 0) AS oldest_pending_seconds,
			MAX(last_attempt) AS last_attempt,
			MAX(sent_time) AS last_sent
		FROM audit_syslog_delivery");
	$last_error = db_fetch_cell("SELECT last_error
		FROM audit_syslog_delivery
		WHERE last_error IS NOT NULL
		AND last_error <> ''
		ORDER BY last_attempt DESC, id DESC
		LIMIT 1");

	return [
		'pending'                => (int) ($row['pending'] ?? 0),
		'retry'                  => (int) ($row['retry'] ?? 0),
		'sent_unconfirmed'       => (int) ($row['sent_unconfirmed'] ?? 0),
		'dead_letter'            => (int) ($row['dead_letter'] ?? 0),
		'oldest_pending_seconds' => (int) ($row['oldest_pending_seconds'] ?? 0),
		'last_attempt'           => $row['last_attempt'] ?? null,
		'last_sent'              => $row['last_sent'] ?? null,
		'last_error'             => $last_error !== false && $last_error !== '' ? $last_error : null
	];
}

/**
 * @param array<string,mixed>|null $config
 */
function audit_syslog_check_health(?array $config = null): void {
	if (!audit_syslog_enabled()) {
		return;
	}

	$config    = $config === null ? audit_syslog_config() : $config;
	$health    = audit_syslog_health();
	$unhealthy = !$config['valid'] ||
		$health['dead_letter'] >= $config['dead_letter_warning'] ||
		$health['oldest_pending_seconds'] >= $config['pending_age_warning'];
	$state    = $unhealthy ? 'unhealthy' : 'healthy';
	$previous = read_config_option('audit_syslog_health_state');

	if ($previous !== $state) {
		$message = $unhealthy
			? 'WARNING: Audit Syslog delivery is unhealthy.'
			: 'NOTICE: Audit Syslog delivery has recovered.';
		cacti_log($message, false, 'AUDIT');
		set_config_option('audit_syslog_health_state', $state);
	}
}

/**
 * @param array<int,int> $delivery_ids
 */
function audit_syslog_retry_dead_letters(array $delivery_ids = []): int {
	if (!db_table_exists('audit_syslog_delivery')) {
		return 0;
	}

	$normalized_ids = [];

	foreach ($delivery_ids as $delivery_id) {
		$delivery_id = (int) $delivery_id;

		if ($delivery_id > 0) {
			$normalized_ids[] = $delivery_id;
		}
	}
	$delivery_ids = array_values(array_unique($normalized_ids));

	if (cacti_sizeof($delivery_ids) > 1000) {
		$delivery_ids = array_slice($delivery_ids, 0, 1000);
	}

	if (cacti_sizeof($delivery_ids)) {
		$placeholders = implode(',', array_fill(0, cacti_sizeof($delivery_ids), '?'));
		db_execute_prepared("UPDATE audit_syslog_delivery
			SET state = 'pending',
				attempts = 0,
				next_attempt = UTC_TIMESTAMP(6),
				last_error = NULL,
				updated_time = UTC_TIMESTAMP(6)
			WHERE state = 'dead_letter'
			AND id IN ($placeholders)",
			$delivery_ids);
	} else {
		db_execute("UPDATE audit_syslog_delivery
			SET state = 'pending',
				attempts = 0,
				next_attempt = UTC_TIMESTAMP(6),
				last_error = NULL,
				updated_time = UTC_TIMESTAMP(6)
			WHERE state = 'dead_letter'");
	}

	return db_affected_rows();
}

/**
 * @return array<string,mixed>
 */
function audit_syslog_test_delivery(): array {
	$config = audit_syslog_config();
	$event  = [
		'event_uuid'        => audit_uuid_v4(),
		'correlation_id'    => audit_request_correlation_id(),
		'event_type'        => 'audit.syslog.test',
		'event_category'    => 'audit',
		'severity'          => 'notice',
		'user_id'           => $_SESSION['sess_user_id'] ?? 0,
		'action'            => 'test',
		'request_status'    => 'completed',
		'operation_outcome' => 'success',
		'target_type'       => 'syslog_receiver',
		'target_id'         => $config['receiver'],
		'ip_address'        => function_exists('get_client_addr') ? get_client_addr() : '',
		'event_time'        => audit_utc_time(),
		'details'           => audit_json_encode(['test' => true])
	];
	$socket = null;
	$result = audit_syslog_send_event($event, $config, $socket);

	if (is_resource($socket)) {
		fclose($socket);
	}

	return $result;
}
