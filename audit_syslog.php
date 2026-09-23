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

/**
 * Determines whether remote Syslog delivery is enabled via the
 * 'audit_syslog_enabled' setting. Called throughout this file and
 * audit.php before attempting to queue/send/report on Syslog delivery.
 *
 * @return bool True when remote Syslog delivery is enabled.
 */
function audit_syslog_enabled(): bool {
	return read_config_option('audit_syslog_enabled') == 'on';
}

/**
 * Reads a Cacti setting, substituting a caller-supplied default when the
 * stored value is empty/unset. Called from audit_syslog_config() to load
 * each Syslog configuration field.
 *
 * @param string $name    The setting name to read.
 * @param mixed  $default The value to use when the setting is empty or
 *                        unset.
 *
 * @return mixed The setting's value, or $default.
 */
function audit_syslog_read_setting(string $name, mixed $default): mixed {
	$value = read_config_option($name);

	return $value === '' || $value === null ? $default : $value;
}

/**
 * Validates that a value is a non-negative integer within an inclusive
 * range, appending an '<name>_invalid'/'<name>_out_of_range' error code
 * and falling back to a default when it is not. Called from
 * audit_syslog_config() for each numeric Syslog setting (port, timeout,
 * retry parameters, etc.).
 *
 * @param mixed              $value   The candidate value to validate.
 * @param int                $default The value to return when validation
 *                                    fails.
 * @param int                $minimum The inclusive minimum accepted
 *                                    value.
 * @param int                $maximum The inclusive maximum accepted
 *                                    value.
 * @param array<int,string>  $errors  Reference to the running list of
 *                                    validation error codes; appended to
 *                                    on failure.
 * @param string             $name    The setting's name, used to build
 *                                    its error code.
 *
 * @return int The validated integer, or $default when validation fails.
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

/**
 * Validates that a string is a syntactically plausible Syslog receiver
 * hostname or IP address (rejecting control/whitespace characters,
 * embedded URLs, and malformed DNS labels). Called from
 * audit_syslog_config() to validate the configured receiver address.
 *
 * @param string $receiver The candidate receiver hostname/IP.
 *
 * @return bool True when $receiver looks like a valid hostname or IP
 *              address.
 */
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

/**
 * Validates that a string is safe to embed as an RFC 5424 Syslog header
 * field (APP-NAME/HOSTNAME/etc.): non-empty, within a maximum length,
 * and containing only printable ASCII with no '[', ']', or '=' (which
 * would corrupt structured-data parsing). Called from
 * audit_syslog_config() to validate the application/node_id fields.
 *
 * @param string $value   The candidate header value.
 * @param int    $maximum The maximum allowed length.
 *
 * @return bool True when $value is safe to use as a Syslog header field.
 */
function audit_syslog_valid_header_value(string $value, int $maximum): bool {
	return $value !== '' && strlen($value) <= $maximum &&
		!preg_match('/[^\\x21-\\x7e]|[\\[\\]="]/', $value);
}

/**
 * Validates that an optional TLS file path setting (CA/client cert/client
 * key), when non-empty, is an absolute path to a readable, non-symlink
 * regular file, appending a '<name>_invalid' error code otherwise. Called
 * from audit_syslog_config() when the configured transport is 'tls'.
 *
 * @param string             $path   The candidate absolute file path, or
 *                                   '' when not configured.
 * @param string             $name   The setting's name, used to build
 *                                   its error code.
 * @param array<int,string>  $errors Reference to the running list of
 *                                   validation error codes; appended to
 *                                   on failure.
 *
 * @return string The unmodified $path (validation failures are reported
 *                via $errors, not the return value).
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
 * Loads, validates, and normalizes this plugin's complete remote-Syslog
 * configuration (receiver, port, transport, format, facility, TLS
 * material, retry/batching parameters), collecting a list of validation
 * error codes and an overall 'valid' flag plus a stable destination
 * fingerprint. This is the central configuration entry point used
 * throughout this file and audit.php/setup.php wherever Syslog settings
 * are needed.
 *
 * @param  array<string,mixed> $overrides Setting values to use instead of
 *                                        reading from Cacti config,
 *                                        keyed by the unprefixed setting
 *                                        name (e.g. 'receiver', 'port');
 *                                        used when previewing/validating
 *                                        a submitted settings form before
 *                                        it is saved.
 * @return array<string,mixed> The normalized configuration array,
 *                             including 'errors' (validation error
 *                             codes), 'valid' (bool), and 'fingerprint'.
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
 * Computes a stable SHA-256 fingerprint identifying a Syslog
 * configuration's delivery destination/identity (receiver, port,
 * transport, format, facility, application, node id, TLS cert paths),
 * used to detect when the configured destination has changed. Called
 * from audit_syslog_config() after normalizing the configuration.
 *
 * @param array<string,mixed> $config The normalized Syslog configuration.
 *
 * @return string The computed SHA-256 hex fingerprint.
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
 * Returns the map of supported Syslog facility names to their RFC 5424
 * numeric codes. Called from audit_syslog_config() to validate/resolve
 * the configured facility, and from audit_syslog_severity_code() when
 * computing a message's PRI value.
 *
 * @return array<string,int> Map of facility name to its numeric code.
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

/**
 * Maps an audit event severity name (e.g. 'warning', 'critical') to its
 * RFC 5424 numeric severity level. Called from audit_syslog_record()
 * when computing an RFC 5424 message's PRI value.
 *
 * @param mixed $severity The severity name to map.
 *
 * @return int The RFC 5424 severity level (0-7), defaulting to 6 (info)
 *              for an unrecognized name.
 */
function audit_syslog_severity_code(mixed $severity): int {
	$map = [
		'emergency' => 0, 'emerg' => 0, 'alert' => 1, 'critical' => 2,
		'crit'      => 2, 'error' => 3, 'err' => 3, 'warning' => 4,
		'warn'      => 4, 'notice' => 5, 'info' => 6, 'debug' => 7
	];
	$severity = strtolower((string) $severity);

	return isset($map[$severity]) ? $map[$severity] : 6;
}

/**
 * Sanitizes a value for use as an RFC 5424 header token (HOSTNAME/APP-
 * NAME/PROCID/MSGID): replaces disallowed bytes with '_', truncates to a
 * maximum length, and substitutes a fallback when the result is empty.
 * Called from audit_syslog_record() when building each header field.
 *
 * @param mixed  $value    The candidate header value.
 * @param int    $maximum  The maximum allowed length.
 * @param string $fallback The value to use when sanitization yields an
 *                        empty string.
 *
 * @return string The sanitized header token.
 */
function audit_syslog_header_token(mixed $value, int $maximum, string $fallback): string {
	$value = preg_replace('/[^\\x21-\\x3c\\x3e-\\x5a\\x5e-\\x7e]/', '_', (string) $value);
	$value = substr($value ?? '', 0, $maximum);

	return $value === '' ? $fallback : $value;
}

/**
 * Escapes a value for safe embedding as an RFC 5424 structured-data
 * parameter value (replacing control characters with spaces and
 * escaping backslash/quote/closing-bracket). Called from
 * audit_syslog_record() for each structured-data field.
 *
 * @param mixed $value The value to escape.
 *
 * @return string The escaped value.
 */
function audit_syslog_structured_value(mixed $value): string {
	$value = preg_replace('/[\\x00-\\x1f\\x7f]/', ' ', (string) $value);

	return str_replace(['\\', '"', ']'], ['\\\\', '\\"', '\\]'], $value ?? '');
}

/**
 * Converts an audit event's stored timestamp string to RFC 5424's
 * 'Y-m-d\TH:i:s[.u]\Z' timestamp format, falling back to the current UTC
 * time when the input doesn't match the expected pattern. Called from
 * audit_syslog_record() when building the RFC 5424 header's TIMESTAMP
 * field.
 *
 * @param mixed $value The stored event timestamp (e.g.
 *                      'Y-m-d H:i:s.uuuuuu').
 *
 * @return string The RFC 5424-formatted UTC timestamp.
 */
function audit_syslog_timestamp(mixed $value): string {
	$value = (string) $value;

	if (preg_match('/^([0-9]{4}-[0-9]{2}-[0-9]{2})[ T]([0-9]{2}:[0-9]{2}:[0-9]{2})(\\.[0-9]{1,6})?/', $value, $matches)) {
		return $matches[1] . 'T' . $matches[2] . (isset($matches[3]) ? $matches[3] : '') . 'Z';
	}

	return gmdate('Y-m-d\\TH:i:s\\Z');
}

/**
 * Builds the normalized field set forwarded to a Syslog receiver in JSON
 * format, extending audit_external_event_data() with the configured
 * node/poller identifiers. Called from audit_syslog_message_payload()
 * when the configured format is 'json'.
 *
 * @param  array<string,mixed> $event  The full audit_log event row.
 * @param  array<string,mixed> $config The normalized Syslog
 *                                     configuration.
 * @return array<string,mixed> The event data plus 'node_id' and
 *                             'poller_id'.
 */
function audit_syslog_normalized_data(array $event, array $config): array {
	$data              = audit_external_event_data($event);
	$data['node_id']   = $config['node_id'];
	$data['poller_id'] = $config['poller_id'] !== '' ? $config['poller_id'] : null;

	return $data;
}

/**
 * Escapes a value for safe embedding in a CEF header field (backslash,
 * pipe, and newline characters). Called from audit_syslog_cef_payload()
 * for each CEF header field.
 *
 * @param mixed $value The value to escape.
 *
 * @return string The escaped value.
 */
function audit_syslog_cef_escape_header(mixed $value): string {
	return str_replace(['\\', '|', "\r", "\n"], ['\\\\', '\\|', ' ', ' '], (string) $value);
}

/**
 * Escapes a value for safe embedding as a CEF extension field value
 * (backslash, equals sign, and newline characters). Called from
 * audit_syslog_cef_payload() for each CEF extension value.
 *
 * @param mixed $value The value to escape.
 *
 * @return string The escaped value.
 */
function audit_syslog_cef_escape_extension(mixed $value): string {
	return str_replace(
		['\\', '=', "\r", "\n"],
		['\\\\', '\\=', '\\r', '\\n'],
		(string) $value
	);
}

/**
 * Maps an audit event severity name to its CEF (0-10) severity scale.
 * Called from audit_syslog_cef_payload() when building a CEF message's
 * header.
 *
 * @param mixed $severity The severity name to map.
 *
 * @return int The CEF severity (0-10), defaulting to 3 (info-equivalent)
 *              for an unrecognized name.
 */
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

/**
 * Prepares an audit event's post/object_data/details field for inclusion
 * as a CEF extension value: decodes it from JSON when possible (then
 * re-encodes with sensitive data redacted), and normalizes null/bool
 * scalars to readable strings. Called from audit_syslog_cef_payload()
 * for each of the cs4/cs5/cs6 custom string fields.
 *
 * @param mixed $value The raw field value (often a JSON string).
 *
 * @return string The prepared, redacted string value.
 */
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
 * Formats an audit event as a CEF (Common Event Format) message body,
 * mapping event fields to CEF's standard and custom string/number
 * extension fields. Called from audit_syslog_message_payload() when the
 * configured format is 'cef'.
 *
 * @param array<string,mixed> $event  The full audit_log event row.
 * @param array<string,mixed> $config The normalized Syslog configuration.
 *
 * @return string The formatted CEF message body.
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
 * Formats an audit event's message body according to the configured
 * Syslog format (CEF, JSON, or a minimal fallback for plain RFC 5424).
 * Called from audit_syslog_record() when assembling a complete Syslog
 * record.
 *
 * @param array<string,mixed> $event  The full audit_log event row.
 * @param array<string,mixed> $config The normalized Syslog configuration.
 *
 * @return string The formatted message body.
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
 * Assembles a complete RFC 5424 Syslog record for an audit event (PRI,
 * header fields, structured-data element, and message body), rejecting
 * the record if the configuration is invalid or the formatted record
 * exceeds RFC/UDP size limits. Called from audit_syslog_send_event() and
 * audit_syslog_test_delivery() before transmitting an event.
 *
 * @param  array<string,mixed> $event  The full audit_log event row.
 * @param  array<string,mixed> $config The normalized Syslog
 *                                     configuration.
 * @return array<string,mixed> An array with 'status' ('ready' or
 *                             'failed'), 'permanent' (bool), 'error_code',
 *                             'error', and 'record' (the formatted
 *                             record, or '' on failure).
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

/**
 * Applies the transport-specific message framing to a formatted Syslog
 * record: octet-counting (length-prefixed) framing for TCP/TLS per RFC
 * 6587, or no framing for UDP datagrams. Called from
 * audit_syslog_send_event() before writing a record to the socket.
 *
 * @param string $record    The formatted Syslog record.
 * @param string $transport The transport in use ('udp', 'tcp', or
 *                          'tls').
 *
 * @return string The framed message ready to write to the socket.
 */
function audit_syslog_frame(string $record, string $transport): string {
	if ($transport === 'tcp' || $transport === 'tls') {
		return strlen($record) . ' ' . $record;
	}

	return $record;
}

/**
 * Builds the stream_socket_client() target URI for a Syslog
 * configuration, bracketing IPv6 receiver addresses as required. Called
 * from audit_syslog_open_socket() before opening a connection.
 *
 * @param array<string,mixed> $config The normalized Syslog configuration.
 *
 * @return string The 'scheme://host:port' socket target URI.
 */
function audit_syslog_socket_target(array $config): string {
	$receiver = $config['receiver'];

	if (filter_var($receiver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
		$receiver = '[' . $receiver . ']';
	}

	$scheme = $config['transport'] === 'tls' ? 'tls' : $config['transport'];

	return $scheme . '://' . $receiver . ':' . $config['port'];
}

/**
 * Runs a stream-related callable with a temporary error handler that
 * captures any PHP warning/notice as a sanitized string instead of
 * letting it surface as an uncaught diagnostic, also catching thrown
 * exceptions. Called from audit_syslog_open_socket()/audit_syslog_fwrite()
 * to safely wrap stream_socket_client()/fwrite() calls that may emit
 * warnings on failure.
 *
 * @param callable $operation The stream operation to invoke.
 * @param string   $warning   Reference, set to a sanitized warning/error
 *                            message when one occurs, or left as '' on
 *                            success.
 *
 * @return mixed The operation's return value, or false when an exception
 *               was caught.
 */
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
 * Opens a client socket to the configured Syslog receiver, applying TLS
 * context options (peer verification, SNI, optional CA/client cert) when
 * the transport is 'tls'. Called from audit_syslog_send_event() when no
 * existing socket was supplied for a delivery attempt.
 *
 * @param  array<string,mixed> $config The normalized Syslog
 *                                     configuration.
 * @return array<string,mixed> An array with 'socket' (the opened stream
 *                             resource, or null on failure), 'error_code',
 *                             and 'error'.
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

/**
 * Strips control characters from an error message and truncates it to a
 * bounded length, so socket/stream errors can be safely stored and
 * displayed. Called from audit_syslog_open_socket() and
 * audit_syslog_write() when reporting a delivery failure.
 *
 * @param mixed $error The raw error message.
 *
 * @return string The sanitized, length-bounded error message.
 */
function audit_syslog_bounded_error(mixed $error): string {
	$error = preg_replace('/[\\x00-\\x1f\\x7f]+/', ' ', (string) $error);

	return substr(trim($error ?? ''), 0, 1024);
}

/**
 * Writes to a socket via audit_syslog_stream_operation(), capturing any
 * warning instead of raising it. Called from audit_syslog_write() for
 * each chunk written to the Syslog socket.
 *
 * @param mixed  $socket  The open socket resource to write to.
 * @param string $message The data to write.
 * @param string $warning Reference, set to a sanitized warning message on
 *                        failure.
 *
 * @return int|false The number of bytes written, or false on failure.
 */
function audit_syslog_fwrite(mixed $socket, string $message, string &$warning = ''): int|false {
	return audit_syslog_stream_operation(function () use ($socket, $message) {
		return fwrite($socket, $message);
	}, $warning);
}

/**
 * Writes a framed Syslog message to an open socket: a single write for
 * UDP datagrams, or a write loop handling partial writes/timeouts for
 * stream-based TCP/TLS transports. Called from audit_syslog_send_event()
 * after opening/reusing a socket.
 *
 * @param  mixed                $socket    The open socket resource to
 *                                         write to.
 * @param  string               $message   The framed message to write.
 * @param  string               $transport The transport in use ('udp',
 *                                         'tcp', or 'tls').
 * @return array<string,mixed>  An array with 'status'
 *                              ('sent_unconfirmed' or 'failed'),
 *                              'error_code', and 'error'.
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
 * Formats and transmits a single audit event to the configured Syslog
 * receiver over a (possibly newly opened) socket, closing the socket
 * after any non-'sent_unconfirmed' outcome. This is the core delivery
 * primitive used by both the queued-delivery path
 * (audit_process_syslog_queue()) and the manual "Test Syslog" action
 * (audit_syslog_test_delivery()).
 *
 * @param array<string,mixed> $event  The full audit_log event row to
 *                                    send.
 * @param array<string,mixed> $config The normalized Syslog configuration.
 * @param mixed               $socket Reference to an existing open
 *                                    socket to reuse (e.g. across a batch
 *                                    of deliveries); opened automatically
 *                                    when not already a resource, and set
 *                                    to null after the socket is closed.
 *
 * @return array<string,mixed> The delivery result: 'status'
 *                             ('sent_unconfirmed' or 'failed'),
 *                             'permanent' (bool), 'error_code', and
 *                             'error'.
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

/**
 * Enqueues a completed audit event for remote Syslog delivery by
 * inserting a tracking row into audit_syslog_delivery (state 'pending',
 * or 'dead_letter' immediately when the current Syslog configuration is
 * invalid), tagged with the current destination fingerprint so a later
 * configuration change is detected. Called from audit_record_event() and
 * audit_finalize_request() right after an event is recorded/completed,
 * when Syslog delivery is enabled.
 *
 * @param int $audit_id The audit_log.id to enqueue for delivery.
 *
 * @return void
 */
function audit_enqueue_syslog_event(int $audit_id): void {
	if (!audit_syslog_enabled() ||
		!audit_log_table_available() ||
		!db_table_exists('audit_syslog_delivery')) {
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
 * Overlays a delivery row's originally-recorded node/poller identity onto
 * the current Syslog configuration, and recomputes the destination
 * fingerprint accordingly, so retried deliveries are tagged consistently
 * with how they were originally enqueued. Called from
 * audit_process_syslog_queue() for each delivery about to be sent.
 *
 * @param array<string,mixed> $config   The current normalized Syslog
 *                                      configuration.
 * @param array<string,mixed> $delivery The audit_syslog_delivery row
 *                                      (joined with its audit_log
 *                                      event), including
 *                                      'delivery_node_id' and
 *                                      'delivery_poller_id'.
 *
 * @return array<string,mixed> The configuration with node_id/poller_id
 *                             overridden and fingerprint recomputed.
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
 * Computes an exponential backoff delay (in seconds) for the next
 * delivery retry attempt, doubling from the configured base delay up to
 * a configured maximum. Called from audit_syslog_update_delivery() when
 * scheduling a failed, non-permanent delivery's next attempt.
 *
 * @param mixed               $attempt The 1-based attempt number just
 *                                     completed.
 * @param array<string,mixed> $config  The normalized Syslog
 *                                     configuration (retry_base,
 *                                     retry_max).
 *
 * @return int The computed delay in seconds, capped at retry_max.
 */
function audit_syslog_retry_delay(mixed $attempt, array $config): int {
	$exponent = min(max(0, (int) $attempt - 1), 30);
	$delay    = $config['retry_base'] * pow(2, $exponent);

	return (int) min($config['retry_max'], $delay);
}

/**
 * Records the outcome of a Syslog delivery attempt on its
 * audit_syslog_delivery row: marks it 'sent_unconfirmed' on success, or
 * 'retry' (with a scheduled next_attempt) / 'dead_letter' (when
 * permanently failed or attempts are exhausted) on failure. Called from
 * audit_process_syslog_queue() after each delivery attempt.
 *
 * @param array<string,mixed> $delivery The audit_syslog_delivery row
 *                                      being updated.
 * @param array<string,mixed> $result   The delivery result from
 *                                      audit_syslog_send_event().
 * @param array<string,mixed> $config   The normalized Syslog
 *                                      configuration used for the
 *                                      attempt.
 *
 * @return void
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

/**
 * Processes a bounded batch of pending/retry-due Syslog deliveries in
 * next_attempt order, reusing a single open socket across the batch and
 * stopping early on the first non-permanent failure so a broken
 * connection doesn't burn through the whole batch, then refreshes the
 * delivery health state. Called from this plugin's poller routine on
 * every polling cycle when Syslog delivery is enabled.
 *
 * @return void
 */
function audit_process_syslog_queue(): void {
	if (!audit_log_table_available() || !audit_syslog_enabled() || !db_table_exists('audit_syslog_delivery')) {
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
 * Summarizes the current state of the Syslog delivery queue: counts of
 * pending/retry/sent-unconfirmed/dead-letter rows, the age of the oldest
 * still-pending row, and the most recent attempt/sent times and error
 * message. Called from audit_render_syslog_health() and
 * audit_syslog_check_health() to assess delivery health.
 *
 * @return array<string,mixed> The health summary fields.
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
 * Evaluates whether Syslog delivery has transitioned between healthy and
 * unhealthy (invalid config, too many dead-letters, or pending items
 * aging past the warning threshold) and, on a state change, logs a
 * one-time NOTICE/WARNING and persists the new state so repeated cycles
 * don't re-log the same transition. Called from
 * audit_process_syslog_queue() after each queue-processing pass.
 *
 * @param array<string,mixed>|null $config The normalized Syslog
 *                                         configuration to evaluate;
 *                                         loaded automatically when null.
 *
 * @return void
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
 * Resets dead-letter Syslog deliveries back to 'pending' (clearing their
 * attempt count/error and scheduling an immediate retry), either for a
 * specific set of delivery ids or, when none are given, every dead-
 * letter row. Called from audit.php's dispatcher when the request's
 * 'action' is 'syslog_retry' (admin-only, via the Retry Dead-letter
 * button).
 *
 * @param array<int,int> $delivery_ids The specific audit_syslog_delivery
 *                                     ids to retry (capped at 1000); when
 *                                     empty, every dead-letter row is
 *                                     retried.
 *
 * @return int The number of rows reset for retry.
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
 * Builds and immediately sends a synthetic 'audit.syslog.test' event to
 * the currently configured Syslog receiver, bypassing the delivery
 * queue, so an administrator can confirm connectivity/configuration.
 * Called from audit.php's dispatcher when the request's 'action' is
 * 'syslog_test' (admin-only, via the Test Syslog button).
 *
 * @return array<string,mixed> The delivery result from
 *                             audit_syslog_send_event() ('status',
 *                             'error_code', 'error', etc.).
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
