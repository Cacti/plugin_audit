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
 | Cacti: The Complete RRDTool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

declare(strict_types = 1);

require_once __DIR__ . '/audit_syslog.php';

/**
 * Determines whether the current session user has access to this
 * plugin's audit_manage.php realm (i.e. is an audit administrator).
 * Called from audit.php to gate the admin-only syslog test/retry/purge
 * actions.
 *
 * @return bool True when the current user is an audit administrator.
 */
function audit_user_is_admin(): bool {
	return api_plugin_user_realm_auth('audit_manage.php');
}

/**
 * Determines whether the audit_log table currently exists, so callers can
 * skip logging safely during install/upgrade before the table has been
 * created. Called throughout this plugin's event-recording functions
 * before writing to audit_log.
 *
 * Cacti 1.2.20 and develop both use a request-scoped static cache in
 * lib/database.php::db_table_exists() outside install mode.
 *
 * @return bool True when the audit_log table exists.
 */
function audit_log_table_available(): bool {
	// Cacti 1.2.20 and develop both use a request-scoped static cache in
	// lib/database.php::db_table_exists() outside install mode.
	return function_exists('db_table_exists') && db_table_exists('audit_log');
}

/**
 * Looks up display-friendly details (name/description/status, etc.) for
 * a bulk-selected set of Cacti objects (devices, templates, thresholds,
 * users, etc.) on a given admin page, for inclusion in that action's
 * audit event as human-readable context. Called from Cacti core's bulk-
 * action pages (via this plugin's page-level integration) before
 * recording an audit event for a 'drp_action' submission.
 *
 * @param string             $page           The originating admin page's
 *                                            filename (e.g. 'host.php').
 * @param mixed              $drop_action    The submitted bulk action
 *                                            value; lookups are skipped
 *                                            only when this is strictly
 *                                            `false` (0, null, and ''
 *                                            still trigger the
 *                                            page-specific queries).
 * @param array<int,string>  $selected_items The selected object ids to
 *                                            look up.
 *
 * @return string A JSON-encoded array of per-item detail rows for the
 *                recognized $page, or an empty JSON array ('[]') when
 *                $page is '' or unrecognized.
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

/**
 * Determines whether a field name looks like it holds a credential/secret
 * (password, token, API key, community string, etc.), based on a
 * case-insensitive keyword match. Called from audit_redact_sensitive_data()
 * to decide which fields to redact before logging request data.
 *
 * @param mixed $key The field name to check.
 *
 * @return int|false The number of regex matches (1 when sensitive), or
 *                    false on a regex engine error.
 */
function audit_is_sensitive_key(mixed $key): int|false {
	return preg_match('/(?:pass(?:word)?|phrase|token|secret|api[_-]?key|private[_-]?key|community|credential|authorization|authentication)/i', (string) $key);
}

/**
 * Recursively redacts sensitive fields (per audit_is_sensitive_key()) and
 * sensitive-looking values (per audit_redact_sensitive_value()) within an
 * array of request/response data before it is persisted to the audit
 * log. Called from audit_record_event() and this plugin's CLI/request
 * capture functions before storing submitted data.
 *
 * @param mixed $data The data to redact; non-array values are returned
 *                     unchanged.
 *
 * @return mixed The redacted data, or the original value when $data is
 *               not an array.
 */
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

/**
 * Redacts an individual scalar value that looks like a credential even
 * though its field name didn't match (PEM private keys, Bearer/Basic
 * auth headers, JWT-shaped tokens), and masks any embedded userinfo
 * password in URL-like strings. Called from audit_redact_sensitive_data()
 * for each non-array field value.
 *
 * @param mixed $value The value to inspect and possibly redact.
 *
 * @return mixed The redacted value, or the original value when it is not
 *               a string or doesn't look sensitive.
 */
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

/**
 * Recursively bounds a data structure to safe limits before it is
 * logged: truncates any string longer than 64KB, caps the total number
 * of array fields visited across the whole structure at 1000, and caps
 * recursion depth at 12. Called from audit_json_encode() before encoding
 * any data for storage, to prevent unbounded/adversarial payloads from
 * exhausting resources.
 *
 * @param mixed        $data  The data to bound.
 * @param int          $depth The current recursion depth; defaults to 0
 *                            for the initial call.
 * @param object|null  $state Shared mutable state (a field counter)
 *                            threaded through the recursion; created
 *                            automatically on the initial call.
 *
 * @return mixed The bounded data, with oversized strings truncated and
 *               an 'audit_truncated' marker added to arrays that exceeded
 *               the field-count limit.
 */
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
 * Redacts CLI argument values that look like credentials, handling both
 * '--flag=value' and separate '--flag value' forms, and masks any
 * embedded userinfo password in URL-like arguments. Called when logging
 * a CLI script's invocation arguments to the audit log.
 *
 * @param array<int,string> $arguments The raw CLI arguments to redact.
 *
 * @return array<int,string> The redacted arguments, in the same order.
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

/**
 * Encodes data as JSON after bounding it via audit_bound_log_data(),
 * falling back to a minimal error object when encoding itself fails.
 * Used throughout this plugin whenever data is persisted to the audit
 * log or rendered for export/display.
 *
 * @param mixed $data    The data to encode.
 * @param int   $options Additional json_encode() option flags to OR in;
 *                        defaults to 0.
 *
 * @return string The encoded JSON, or a fallback
 *                '{"audit_encoding_error":...}' object when encoding
 *                fails.
 */
function audit_json_encode(mixed $data, int $options = 0): string {
	$json = json_encode(audit_bound_log_data($data), JSON_INVALID_UTF8_SUBSTITUTE | $options, 16);

	if ($json === false) {
		$fallback = json_encode(['audit_encoding_error' => json_last_error_msg()]);

		return $fallback !== false ? $fallback : '{}';
	}

	return $json;
}

/**
 * Safely decodes a JSON string, capturing any decoding error message
 * instead of throwing, for callers that need to distinguish a
 * successfully-decoded null from a decoding failure. Used throughout
 * this plugin when reading back previously stored audit_log JSON
 * columns.
 *
 * @param mixed       $json  The JSON string to decode.
 * @param string|null $error Reference, set to the decoding error message
 *                            on failure, or null on success.
 *
 * @return mixed The decoded value, or null when decoding failed.
 */
function audit_json_decode(mixed $json, ?string &$error = null): mixed {
	$error = null;

	try {
		return json_decode($json, true, 16, JSON_THROW_ON_ERROR);
	} catch (Throwable $exception) {
		$error = $exception->getMessage();

		return null;
	}
}

/**
 * Generates a cryptographically random RFC 4122 version-4 UUID. Called
 * from audit_request_correlation_id() and this plugin's event-recording
 * functions to assign each audit event a unique identifier.
 *
 * @return string A version-4 UUID in canonical
 *                8-4-4-4-12 hyphenated hex form.
 */
function audit_uuid_v4(): string {
	$bytes    = random_bytes(16);
	$bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
	$bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
	$hex      = bin2hex($bytes);

	return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' .
		substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
}

/**
 * Returns a UUID that is stable for the duration of the current request,
 * generating one on first use and reusing it for every subsequent call
 * within the same request. Called throughout this plugin's event-
 * recording functions so that multiple audit events from the same
 * request share a common correlation id.
 *
 * @return string The current request's correlation UUID.
 */
function audit_request_correlation_id(): string {
	static $correlation_id;

	if ($correlation_id === null) {
		$correlation_id = audit_uuid_v4();
	}

	return $correlation_id;
}

/**
 * Formats a Unix timestamp (with microsecond precision) as a UTC
 * 'Y-m-d H:i:s.uuuuuu' string, suitable for consistent, sortable event
 * timestamps regardless of the server's local timezone. Called
 * throughout this plugin's event-recording functions to timestamp audit
 * events.
 *
 * @param float|null $microtime The Unix timestamp (with fractional
 *                               seconds) to format; defaults to the
 *                               current time when null.
 *
 * @return string The formatted UTC timestamp.
 */
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
 * Computes a SHA-256 integrity hash over an audit event's stable
 * identifying fields (uuid, correlation id, type, user, action, time,
 * outcome, target, details), so tampering with a stored event can later
 * be detected. Called from audit_record_event() before an event is
 * inserted into audit_log.
 *
 * @param array<string,mixed> $event The event fields to hash.
 *
 * @return string The computed SHA-256 hex hash.
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

/**
 * Derives a normalized dotted event-type identifier (e.g.
 * 'cacti.host_php.save') from a request's page filename and action/mode
 * value, for use as an audit_log.event_type when no more specific type
 * is supplied. Called from this plugin's generic request-capture flow.
 *
 * @param mixed $page   The originating page's filename.
 * @param mixed $action The request's action/mode value.
 *
 * @return string The derived event type string.
 */
function audit_event_type_for_request(mixed $page, mixed $action): string {
	$page_name = preg_replace('/\.php$/', '', (string) $page);
	$page_name = preg_replace('/[^a-z0-9_]+/i', '_', $page_name ?? '');
	$verb      = preg_replace('/[^a-z0-9_]+/i', '_', strtolower((string) $action));
	$verb      = trim($verb ?? '', '_');

	return 'cacti.' . ($page_name !== '' ? $page_name : 'request') . '.' .
		($verb !== '' && $verb !== 'none' ? $verb : 'submitted');
}

/**
 * Extracts the subset of an audit event's fields that are forwarded to
 * external log destinations (file/Syslog), in a stable field order.
 * Called from audit_deliver_external_event() and Syslog delivery before
 * formatting an event for external shipment.
 *
 * @param array<string,mixed> $event The full audit_log event row.
 *
 * @return array<string,mixed> The subset of fields destined for external
 *                             delivery, each defaulting to null when
 *                             absent from $event.
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
 * Formats an external event data array as either a single-line
 * key="value" text record or a JSON line, decoding any nested JSON string
 * fields (post/object_data/details) back into structured data first when
 * formatting as JSON. Called from audit_deliver_external_event() before
 * appending an event to the configured external log file.
 *
 * @param array<string,mixed> $data   The event data to format, as
 *                                      returned by
 *                                      audit_external_event_data().
 * @param string               $format The output format: 'text' for a
 *                                      key="value" line, anything else
 *                                      for a JSON line; defaults to
 *                                      'json'.
 *
 * @return string The formatted record, terminated with a newline.
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

/**
 * Prefixes a value with a single quote when it begins with a character
 * (=, +, -, @) that spreadsheet applications interpret as the start of a
 * formula, preventing CSV formula-injection when the audit log is
 * exported and opened in Excel/LibreOffice/Sheets. Called from
 * audit_export_rows() for every exported cell value.
 *
 * @param mixed $value The cell value to sanitize.
 *
 * @return string The value as a string, prefixed with a single quote
 *                when it looks like it could be interpreted as a
 *                formula.
 */
function audit_csv_safe_cell(mixed $value): string {
	$value = (string) $value;

	if (preg_match('/^[=+\-@]/', ltrim($value))) {
		return "'" . $value;
	}

	return $value;
}

/**
 * Computes the UTC cutoff timestamp before which audit_log rows are
 * eligible for retention-based cleanup, given a retention period in
 * days. Called from this plugin's poller/cleanup routines to determine
 * which rows are old enough to purge.
 *
 * @param mixed                  $retention The retention period in days
 *                                          (coerced to a non-negative
 *                                          int).
 * @param DateTimeImmutable|null $now       The reference "now" to
 *                                          subtract from; defaults to the
 *                                          current UTC time when null.
 *
 * @return DateTimeImmutable The computed UTC cutoff instant.
 */
function audit_retention_cutoff(mixed $retention, ?DateTimeImmutable $now = null): DateTimeImmutable {
	$now = $now instanceof DateTimeImmutable
		? $now->setTimezone(new DateTimeZone('UTC'))
		: new DateTimeImmutable('now', new DateTimeZone('UTC'));

	return $now->sub(new DateInterval('P' . max(0, (int) $retention) . 'D'));
}

/**
 * Appends a message to an existing external log file under an exclusive
 * lock, refusing to write to a missing file, non-regular file, or
 * symlink (to avoid a misconfigured/tampered destination silently
 * dropping or redirecting audit data). Called from
 * audit_deliver_external_event() and audit_retry_external_logs() when
 * delivering an event to the configured external log path.
 *
 * @param string $path    The absolute path to the external log file;
 *                        must already exist as a regular file.
 * @param string $message The formatted record to append (including its
 *                        own trailing newline).
 *
 * @return array<string,string> An array with 'status' set to 'delivered'
 *                              (and empty 'error') on success, or
 *                              'failed' with a descriptive 'error'
 *                              message on failure.
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

/**
 * Records the outcome of an attempt to deliver an audit event to its
 * configured external log file, incrementing the attempt counter and
 * timestamping the last attempt/delivery time. Called from
 * audit_deliver_external_event() and audit_retry_external_logs() after
 * each delivery attempt.
 *
 * @param int    $id     The audit_log.id being updated.
 * @param string $status The new external_status value (e.g. 'delivered',
 *                        'failed').
 * @param string $error  The delivery error message, or '' on success;
 *                        defaults to ''.
 *
 * @return void
 */
function audit_set_external_status(int $id, string $status, string $error = ''): void {
	if (!audit_log_table_available()) {
		return;
	}

	db_execute_prepared('UPDATE audit_log
		SET external_status = ?,
			external_error = ?,
			external_attempts = external_attempts + 1,
			external_last_attempt = UTC_TIMESTAMP(6),
			external_delivered_time = CASE WHEN ? = \'delivered\' THEN UTC_TIMESTAMP(6) ELSE external_delivered_time END
		WHERE id = ?',
		[$status, $error, $status, $id]);
}

/**
 * Delivers a single audit event to its configured external log file, when
 * external logging is enabled, the event has finished processing, and it
 * hasn't already been delivered. Called from audit_record_event() and
 * audit_finalize_request() immediately after an event is recorded/
 * completed.
 *
 * @param int $id The audit_log.id to deliver.
 *
 * @return void
 */
function audit_deliver_external_event(int $id): void {
	if (!audit_log_table_available() || read_config_option('audit_log_external') != 'on') {
		return;
	}

	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', [$id]);

	if (!is_array($event) || $event    === [] ||
		($event['request_status'] ?? '')  === 'started' ||
		($event['external_status'] ?? '') === 'delivered') {
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

/**
 * Re-attempts delivery of up to 100 previously pending/failed external
 * log events (oldest first), stopping at the first delivery that still
 * fails so a persistently broken destination doesn't get hammered.
 * Called from this plugin's poller routine on each polling cycle when
 * external logging is enabled.
 *
 * @return void
 */
function audit_retry_external_logs(): void {
	if (!audit_log_table_available() || read_config_option('audit_log_external') != 'on') {
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
 * Classifies a completed request as 'completed' or 'failed', based on
 * whether a fatal PHP error occurred or the HTTP status code indicates a
 * client/server error. Called from audit_finalize_request() to determine
 * an event's final request_status.
 *
 * @param array<string,mixed>|null $error       The result of
 *                                               error_get_last(), or
 *                                               null when no error
 *                                               occurred.
 * @param int                       $status_code The response's HTTP
 *                                               status code; defaults to
 *                                               200.
 *
 * @return string 'failed' when a fatal error occurred or the status code
 *                is >= 400; otherwise 'completed'.
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
 * Builds a deferred "verifier" descriptor for requests whose real
 * outcome can only be confirmed by re-reading the database after the
 * request completes - currently, user_admin.php's realm-permissions save
 * form. Captures the target user id and the set of realm ids the
 * request expects to be granted, for later comparison by
 * audit_verify_operation(). Called from this plugin's generic request-
 * capture flow before a request is processed.
 *
 * @param string              $page The originating page's filename.
 * @param array<string,mixed> $post The submitted POST data.
 *
 * @return array<string,mixed>|null The verifier descriptor, or null when
 *                                  this request/page doesn't need
 *                                  deferred verification.
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
 * Confirms whether a deferred operation (currently only user realm-
 * permissions saves) actually took effect, by re-querying the database
 * and comparing actual state against the expected outcome captured by
 * audit_operation_verifier_for_request(). Called from
 * audit_finalize_request() after a request completes successfully.
 *
 * @param mixed $verifier The verifier descriptor produced by
 *                        audit_operation_verifier_for_request(), or
 *                        anything else to short-circuit as 'unknown'.
 *
 * @return array<string,mixed> An array with 'outcome' ('success',
 *                             'failure', or 'unknown') and 'reason' (a
 *                             machine-readable reason code, or null).
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
 * Finalizes the in-flight audit_log row for the current request: computes
 * its final request_status (and, when a verifier was captured, its
 * confirmed operation_outcome/outcome_reason), records the HTTP status
 * code, completion time, and duration, recomputes its integrity hash, and
 * triggers external log/Syslog delivery. Called once at the end of
 * request processing (e.g. via a shutdown handler) for every request
 * that started an audit event.
 *
 * @param int                        $id         The audit_log.id to
 *                                                finalize.
 * @param float|null                 $started_at The request's start time
 *                                                (from microtime(true)),
 *                                                used to compute
 *                                                duration_ms; defaults to
 *                                                null (no duration
 *                                                recorded).
 * @param array<string,mixed>|null   $verifier   The deferred verifier
 *                                                descriptor from
 *                                                audit_operation_verifier_for_request(),
 *                                                or null when the
 *                                                request's outcome was
 *                                                already known at insert
 *                                                time.
 *
 * @return void
 */
function audit_finalize_request(int $id, ?float $started_at = null, ?array $verifier = null): void {
	if (!audit_log_table_available()) {
		return;
	}

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
 * Inserts a new audit_log event row (assigning a UUID, correlation id,
 * timestamps, redacted/bounded details, and an integrity hash), then
 * (unless deferred) triggers external log/Syslog delivery for it. This is
 * the primary entry point used throughout Cacti core's plugin hooks and
 * this plugin's own pages/scripts to record a security-relevant event.
 *
 * @param string              $event_type A dotted event-type identifier
 *                                        (e.g. 'audit.log.purged').
 * @param array<string,mixed> $options   Optional overrides/extra fields:
 *                                        event_uuid, correlation_id,
 *                                        user_id, page, action,
 *                                        event_time, details,
 *                                        ip_address, user_agent,
 *                                        event_category, severity,
 *                                        actor_type, target_type,
 *                                        target_id, operation_outcome,
 *                                        outcome_reason, http_method,
 *                                        http_status, completed_time,
 *                                        duration_ms, and defer_delivery
 *                                        (skip immediate external/Syslog
 *                                        delivery when truthy).
 *
 * @return int The new audit_log.id, or 0 when auditing is disabled, the
 *             audit_log table doesn't exist yet, or the insert failed.
 */
function audit_record_event(string $event_type, array $options = []): int {
	if (!audit_log_table_available() || read_config_option('audit_enabled') != 'on') {
		return 0;
	}

	$event_uuid     = $options['event_uuid'] ?? audit_uuid_v4();
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

	$inserted = db_execute_prepared('INSERT INTO audit_log (
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

	if (!$inserted) {
		return 0;
	}

	$id = (int) db_fetch_insert_id();

	if ($id <= 0) {
		return 0;
	}

	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', [$id]);

	if (is_array($event)) {
		db_execute_prepared('UPDATE audit_log SET integrity_hash = ? WHERE id = ?',
			[audit_event_integrity_hash($event), $id]);
	}

	if (empty($options['defer_delivery'])) {
		audit_deliver_external_event($id);
		audit_enqueue_syslog_event($id);
	}

	return $id;
}

/**
 * Stashes the logging-out user's identity/correlation id (for the post-
 * destroy hook to confirm session teardown after $_SESSION is gone) and
 * records the initial 'authentication.logout'/'authentication.session.expired'
 * audit event. Called from Cacti core's logout flow just before the
 * session is destroyed, regardless of whether auth auditing is enabled,
 * so the stash is available if the setting is toggled on between this
 * hook and the post-destroy one.
 *
 * @return void
 */
function audit_logout_pre_session_destroy(): void {
	// Stash the logging-out user identity and request correlation id so the
	// post-destroy hook can confirm session teardown after $_SESSION is gone.
	// This runs regardless of the auth-audit switch so the stash is available
	// if the switch is toggled on between the two hooks (unlikely but safe).
	audit_logout_stash([
		'user_id'        => (int) ($_SESSION['sess_user_id'] ?? 0),
		'correlation_id' => audit_request_correlation_id(),
		'reason'         => get_nfilter_request_var('action', 'user')
	]);

	$reason = get_nfilter_request_var('action', 'user');
	$type   = $reason === 'timeout' ? 'authentication.session.expired' : 'authentication.logout';

	audit_record_event($type, [
		'event_category' => 'authentication',
		'action'         => $reason === 'timeout' ? 'timeout' : 'logout',
		'details'        => ['reason' => $reason]
	]);
}

/**
 * Per-request stash shared between the pre- and post-destroy logout
 * hooks, holding the logging-out user's id/correlation id/reason across
 * the point where $_SESSION is destroyed. Called from
 * audit_logout_pre_session_destroy() to set the stash, and from
 * audit_logout_post_session_destroy() to read (and later clear) it.
 *
 * @param array<string,mixed>|null $set When provided, replaces the
 *                                       stashed value; when null, the
 *                                       current stash is left unchanged.
 *
 * @return array<string,mixed> The current stashed value.
 */
function audit_logout_stash(?array $set = null): array {
	static $stash = [];

	if (is_array($set)) {
		$stash = $set;
	}

	return $stash;
}

/**
 * Records the 'authentication.logout.completed' audit event confirming
 * the session was actually destroyed, using the identity stashed by
 * audit_logout_pre_session_destroy(), then clears the stash. Called from
 * Cacti core's logout flow immediately after the session has been
 * destroyed, when both auditing and auth-event logging are enabled.
 *
 * @return void
 */
function audit_logout_post_session_destroy(): void {
	if (read_config_option('audit_enabled') !== 'on') {
		return;
	}

	if (read_config_option('audit_auth_log_enabled') !== 'on') {
		return;
	}

	$stash = audit_logout_stash();

	if (empty($stash)) {
		return;
	}

	audit_record_event('authentication.logout.completed', [
		'event_category'    => 'authentication',
		'action'            => 'logout_completed',
		'user_id'           => $stash['user_id'] ?? 0,
		'correlation_id'    => $stash['correlation_id'] ?? audit_request_correlation_id(),
		'operation_outcome' => 'success',
		'details'           => [
			'reason'            => $stash['reason'] ?? 'user',
			'session_destroyed' => true
		]
	]);

	audit_logout_stash([]);
}

/**
 * Maps a Cacti user_log result code to an audit event descriptor (event
 * type, severity, outcome, action, and explanatory details). Called from
 * audit_poll_user_log() for each newly observed user_log row.
 *
 * Cacti writes user_log rows with result codes:
 *   0 = Failed login
 *   1 = Credentials accepted (written BEFORE enabled/realm/2FA checks)
 *   2 = Success - Token (remember-me or 2FA)
 *   3 = Password Change OR failed 2FA (user_id is omitted, defaulting to 0)
 *
 * Cacti writes result=1 before verifying that the account is enabled,
 * authorized for any realm, or has completed 2FA, so it does not prove an
 * authenticated session was established. It is recorded as credentials
 * accepted with operation_outcome=unknown, not success.
 *
 * Cacti's password-change inserts and the develop branch's failed-2FA inserts
 * both write result=3 with user_id=0, so user_log alone cannot disambiguate
 * them; that combination is recorded as an ambiguous event with
 * operation_outcome=unknown. No current Cacti path writes result=3 with
 * user_id>0, but a future version may; that is treated defensively as a
 * password change with outcome=unknown rather than claiming a confirmed
 * password change.
 *
 * Any unsupported result code is recorded as an explicit unknown event rather
 * than falling through to a password-change or 2FA event.
 *
 * @param int $result  The user_log.result code to classify.
 * @param int $user_id The user_log.user_id associated with the row.
 *
 * @return array{event_type:string,severity:string,outcome:string,action:string,details:array<string,mixed>}
 */
function audit_user_log_event_descriptor(int $result, int $user_id): array {
	return match (true) {
		$result === 0 => [
			'event_type' => 'cacti.auth.login.failed',
			'severity'   => 'warning',
			'outcome'    => 'failure',
			'action'     => 'login_failed',
			'details'    => []
		],
		$result === 1 => [
			'event_type' => 'cacti.auth.login.credentials_accepted',
			'severity'   => 'info',
			'outcome'    => 'unknown',
			'action'     => 'credentials_accepted',
			'details'    => [
				'note' => __('Cacti records this outcome before verifying account enabled, realm authorization, or 2FA completion; a session may not have been established.', 'audit')
			]
		],
		$result === 2 => [
			'event_type' => 'cacti.auth.login.token',
			'severity'   => 'info',
			'outcome'    => 'success',
			'action'     => 'login_token',
			'details'    => []
		],
		$result === 3 && $user_id > 0 => [
			'event_type' => 'cacti.auth.password.changed',
			'severity'   => 'info',
			'outcome'    => 'unknown',
			'action'     => 'password_changed',
			'details'    => [
				'note' => __('No current Cacti path writes this signature; recorded defensively as a possible password change with an unconfirmed outcome.', 'audit')
			]
		],
		$result === 3 => [
			'event_type' => 'cacti.auth.password_change_or_2fa_failed',
			'severity'   => 'info',
			'outcome'    => 'unknown',
			'action'     => 'pwd_or_2fa_failed',
			'details'    => [
				'ambiguous' => true,
				'note'      => __('Cacti user_log result=3 with user_id=0 may be a password change or a failed 2FA challenge; the table cannot disambiguate.', 'audit')
			]
		],
		default => [
			'event_type' => 'cacti.auth.login.unknown',
			'severity'   => 'info',
			'outcome'    => 'unknown',
			'action'     => 'unknown_result',
			'details'    => [
				'unsupported_result_code' => $result
			]
		]
	};
}

/**
 * Deterministically derives a version-5-shaped UUID for a user_log row
 * from its stable identity (username, user_id, source epoch), so the
 * same source row always maps to the same audit event UUID even if
 * re-processed. Called from audit_poll_user_log() when recording an
 * audit event for a newly observed user_log row.
 *
 * @param string $username     The user_log.username value.
 * @param int    $user_id      The user_log.user_id value.
 * @param int    $source_epoch The user_log row's Unix timestamp.
 *
 * @return string The derived, deterministic UUID.
 */
function audit_user_log_event_uuid(string $username, int $user_id, int $source_epoch): string {
	$hex     = hash('sha256', "cacti-audit-user-log\0{$username}\0{$user_id}\0{$source_epoch}");
	$variant = dechex((hexdec($hex[16]) & 0x3) | 0x8);

	return substr($hex, 0, 8) . '-' .
		substr($hex, 8, 4) . '-5' .
		substr($hex, 13, 3) . '-' . $variant .
		substr($hex, 17, 3) . '-' .
		substr($hex, 20, 12);
}

/**
 * Writes a WARNING-level entry to the Cacti poller log for authentication
 * audit ingestion problems. Called from
 * audit_report_ingestion_unavailable() and elsewhere in the user_log
 * polling flow to surface ingestion issues in the standard Cacti log.
 *
 * @param string $message The warning message to log.
 *
 * @return void
 */
function audit_log_ingestion_warning(string $message): void {
	cacti_log('WARNING: ' . $message, false, 'POLLER');
}

/**
 * Logs (and, at most once per hour, also records as an audit event) that
 * authentication-event ingestion from user_log is currently unavailable
 * (e.g. because a required table is missing). Called from
 * audit_poll_user_log() when a precondition for polling isn't met.
 *
 * @param string $reason A short machine-readable reason code.
 *
 * @return void
 */
function audit_report_ingestion_unavailable(string $reason): void {
	audit_log_ingestion_warning('Authentication audit ingestion unavailable: ' . $reason);

	$now  = time();
	$last = (int) read_config_option('audit_auth_ingestion_last_alert', true);

	if ($last > 0 && ($now - $last) < 3600) {
		return;
	}

	set_config_option('audit_auth_ingestion_last_alert', (string) $now);
	audit_record_event('audit.authentication.ingestion.unavailable', [
		'event_category'    => 'audit',
		'severity'          => 'warning',
		'action'            => 'ingest',
		'target_type'       => 'authentication_auditing',
		'operation_outcome' => 'failure',
		'outcome_reason'    => $reason
	]);
}

/**
 * Records that a user_log row's ingestion was permanently abandoned after
 * exhausting its retry budget, both as a Cacti ERROR log entry (the
 * primary, always-available evidence channel) and as a best-effort
 * 'audit.authentication.ingestion.dropped' audit event. Called from
 * audit_poll_user_log() at its two retry-exhaustion paths, when a
 * retry marker reaches its terminal retry count.
 *
 * @param string $username     The dropped row's user_log.username.
 * @param int    $user_id      The dropped row's user_log.user_id.
 * @param int    $source_epoch The dropped row's Unix timestamp.
 * @param int    $result       The dropped row's user_log.result code.
 *
 * @return void
 */
function audit_report_dropped_user_log_row(string $username, int $user_id, int $source_epoch, int $result): void {
	$details = compact('username', 'user_id', 'source_epoch', 'result');

	// The primary evidence channel must remain available when audit_log writes
	// are the failure that exhausted retries. The structured event is best effort.
	cacti_log(
		'ERROR: Authentication audit dropped user_log row after retry exhaustion ' . audit_json_encode($details),
		false,
		'POLLER'
	);
	audit_record_event('audit.authentication.ingestion.dropped', [
		'event_category'    => 'audit',
		'severity'          => 'error',
		'action'            => 'drop',
		'target_type'       => 'user_log_row',
		'target_id'         => $username,
		'operation_outcome' => 'failure',
		'outcome_reason'    => 'maximum_retries_exhausted',
		'details'           => $details
	]);
}

/**
 * Reaps stale audit_user_log_state tracking rows: retry markers that have
 * exhausted their retry budget and aged past 7 days (optionally warning
 * about terminal markers first), and already-processed markers that have
 * fallen behind the replay floor and aged past 7 days. Called from
 * audit_poll_user_log() at the start of every polling cycle to bound the
 * tracking table's growth.
 *
 * Reaps at least one ingestion batch per poller cycle. Marker age is
 * based on claim time, while source_epoch remains the immutable source-
 * row identity.
 *
 * @param int      $max_retries     The retry count at which a marker is
 *                                  considered terminal; defaults to 5.
 * @param int|null $budget          The maximum number of rows to delete
 *                                  per query, clamped to [1, 5000];
 *                                  defaults to the
 *                                  'audit_user_log_batch_size' setting
 *                                  when null.
 * @param bool     $report_terminal Whether to log a warning when terminal
 *                                  retry markers are found; defaults to
 *                                  false.
 *
 * @return void
 */
function audit_cleanup_user_log_state(int $max_retries = 5, ?int $budget = null, bool $report_terminal = false): void {
	if (!db_table_exists('audit_user_log_state')) {
		return;
	}

	$budget       = max(1, min(5000, $budget ?? (int) read_config_option('audit_user_log_batch_size')));
	$watermark    = max(0, (int) read_config_option('audit_user_log_watermark_epoch', true));
	$replay_floor = max(0, $watermark - 300);

	if ($report_terminal) {
		$terminal_count = (int) db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM audit_user_log_state WHERE audit_id = 0 AND retry_count >= ?',
			[$max_retries]
		);

		if ($terminal_count > 0) {
			cacti_log(
				'WARNING: Authentication audit has ' . $terminal_count . ' terminal retry marker(s)',
				false,
				'POLLER'
			);
		}
	}

	// Reap at least one ingestion batch per poller cycle. Marker age is based on
	// claim time, while source_epoch remains the immutable source-row identity.
	db_execute_prepared('DELETE FROM audit_user_log_state
			WHERE audit_id = 0
			AND retry_count >= ?
			AND source_time < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
			LIMIT ' . (int) $budget,
		[$max_retries]);

	db_execute_prepared('DELETE FROM audit_user_log_state
			WHERE audit_id > 0
			AND source_epoch < ?
			AND source_time < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
			LIMIT ' . (int) $budget,
		[$replay_floor]);
}

/**
 * Poll Cacti's user_log table for new login/logout/token/password-change
 * outcomes and record them as audit events. The user_log table is the
 * authoritative source across all auth methods (local, LDAP, basic, domains)
 * and is stable across the 1.2.x and develop branches, so this avoids
 * relying on the local-auth-only login_process hook. Called from this
 * plugin's poller routine on every polling cycle when authentication
 * auditing is enabled.
 *
 * Deduplication is durable and database-backed: each processed user_log
 * primary-key tuple (username, user_id, UNIX_TIMESTAMP(time)) is recorded in
 * audit_user_log_state. Explicit typed columns define identity once; a marker
 * with audit_id=0 claims the source row before event creation without relying
 * on transactions that Cacti's per-statement retry layer cannot preserve.
 *
 * Each cycle selects a bounded batch of stale retry markers followed by new
 * rows above the high-water floor. Pending markers never lower that floor.
 *
 * @return void
 */
function audit_poll_user_log(): void {
	$auth_enabled = read_config_option('audit_enabled') === 'on' &&
		read_config_option('audit_auth_log_enabled')       === 'on';
	$last_state   = (string) read_config_option('audit_auth_log_last_state', true);

	if (!$auth_enabled) {
		if ($last_state !== 'off') {
			set_config_option('audit_auth_log_last_state', 'off');
		}

		return;
	}

	if (!function_exists('db_table_exists') || !db_table_exists('user_log')) {
		audit_report_ingestion_unavailable('user_log_missing');

		return;
	}

	if (!db_table_exists('audit_user_log_state')) {
		audit_report_ingestion_unavailable('audit_user_log_state_missing');

		return;
	}

	if (!audit_user_log_identity_supported()) {
		audit_report_ingestion_unavailable('user_log_identity_unsupported');

		return;
	}

	if ($last_state !== 'on') {
		if (!audit_user_log_indexes_available()) {
			audit_report_ingestion_unavailable('user_log_indexes_unavailable');

			return;
		}

		// Serialize the off->on transition with a named lock so two pollers
		// racing on a concurrently-observed 'off' state can't each read a
		// different clock value and overwrite each other's watermark; rows
		// created between the two reads would otherwise fall below the
		// final activation floor and never be ingested.
		$lock_acquired = (bool) db_fetch_cell("SELECT GET_LOCK('audit_auth_log_activation', 5)");

		if (!$lock_acquired) {
			// Another poller is mid-transition; retry next cycle.
			return;
		}

		try {
			// Re-read state now that we hold the lock: the other poller may
			// have already completed the transition while we were waiting.
			$last_state = (string) read_config_option('audit_auth_log_last_state', true);

			if ($last_state === 'on') {
				return;
			}

			$activation_epoch = (int) db_fetch_cell_prepared('SELECT UNIX_TIMESTAMP()');

			if ($activation_epoch <= 0) {
				audit_report_ingestion_unavailable('database_clock_unavailable');

				return;
			}

			set_config_option('audit_auth_log_last_state', 'on');
			set_config_option('audit_user_log_watermark_epoch', (string) $activation_epoch);
			set_config_option('audit_user_log_activation_epoch', (string) $activation_epoch);
		} finally {
			db_execute("SELECT RELEASE_LOCK('audit_auth_log_activation')");
		}

		// Begin on the next cycle so every selected row is strictly newer than
		// the activation watermark.
		return;
	}

	$batch_size = (int) read_config_option('audit_user_log_batch_size');

	if ($batch_size < 1) {
		$batch_size = 1000;
	} elseif ($batch_size > 5000) {
		$batch_size = 5000;
	}

	$retention = (int) read_config_option('audit_retention');

	if ($retention <= 0) {
		$retention = 90;
	}

	$retention_epoch  = audit_retention_cutoff($retention)->getTimestamp();
	$watermark        = max(0, (int) read_config_option('audit_user_log_watermark_epoch', true));
	$replay_floor     = $watermark > 0 ? $watermark - 300 : 0;
	$activation_floor = max(0, (int) read_config_option('audit_user_log_activation_epoch', true));
	$lower_bound      = max($retention_epoch, $replay_floor, $activation_floor);
	$max_retries      = 5;
	$pending_limit    = $batch_size > 1 ? max(1, intdiv($batch_size, 2)) : 1;
	// MySQL LIMIT placeholders may be string-bound under emulated prepares.
	// These integers are fixed or clamped above before interpolation.
	$pending_rows    = db_fetch_assoc_prepared(
		'SELECT ul.username, ul.user_id, ul.result, ul.ip,
				UNIX_TIMESTAMP(ul.time) AS source_epoch,
				auls.audit_id AS state_audit_id,
				auls.retry_count
			FROM audit_user_log_state AS auls
			INNER JOIN user_log AS ul
				ON ul.username = auls.source_username
				AND ul.user_id = auls.source_user_id
				AND UNIX_TIMESTAMP(ul.time) = auls.source_epoch
			WHERE auls.audit_id = 0
			AND auls.retry_count < ?
			AND auls.processed_time < DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 5 MINUTE)
				ORDER BY ul.time ASC, ul.username ASC, ul.user_id ASC
				LIMIT ' . (int) $pending_limit,
		[$max_retries]
	);

	if ($pending_rows === false) {
		audit_log_ingestion_warning('Authentication audit retry query failed');

		return;
	}

	$remaining = max(0, $batch_size - count($pending_rows));
	$new_rows  = [];

	if ($remaining > 0) {
		$new_rows = db_fetch_assoc_prepared(
			'SELECT ul.username, ul.user_id, ul.result, ul.ip,
					UNIX_TIMESTAMP(ul.time) AS source_epoch,
					auls.audit_id AS state_audit_id
				FROM user_log AS ul
				LEFT JOIN audit_user_log_state AS auls
					ON auls.source_username = ul.username
					AND auls.source_user_id = ul.user_id
					AND auls.source_epoch = UNIX_TIMESTAMP(ul.time)
				WHERE ul.time > FROM_UNIXTIME(?)
				AND auls.source_username IS NULL
				ORDER BY ul.time ASC, ul.username ASC, ul.user_id ASC
				LIMIT ' . (int) $remaining,
			[$lower_bound]
		);

		if ($new_rows === false) {
			audit_log_ingestion_warning('Authentication audit new-row query failed');

			return;
		}
	}

	$rows = array_merge($pending_rows, $new_rows);

	if ($rows === []) {
		return;
	}

	$retry_failures  = 0;
	$retry_exhausted = 0;

	foreach ($rows as $row) {
		$result       = (int) $row['result'];
		$user_id      = (int) $row['user_id'];
		$source_epoch = (int) $row['source_epoch'];
		$username     = (string) $row['username'];

		if (isset($row['state_audit_id'])) {
			$claimed = db_execute_prepared('UPDATE audit_user_log_state
				SET processed_time = UTC_TIMESTAMP(6),
					retry_count = retry_count + 1
				WHERE source_username = ?
				AND source_user_id = ?
				AND source_epoch = ?
				AND audit_id = 0
				AND processed_time < DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 5 MINUTE)',
				[$username, $user_id, $source_epoch]);
		} else {
			$claimed = db_execute_prepared('INSERT IGNORE INTO audit_user_log_state
				(source_username, source_user_id, source_epoch, source_time, audit_id, retry_count, processed_time)
				VALUES (?, ?, ?, UTC_TIMESTAMP(), 0, 0, UTC_TIMESTAMP(6))',
				[$username, $user_id, $source_epoch]);
		}

		if (!$claimed) {
			audit_log_ingestion_warning('Authentication audit source-row claim failed; ingestion cycle stopped');

			return;
		}

		if (db_affected_rows() !== 1) {
			continue;
		}

		$descriptor = audit_user_log_event_descriptor($result, $user_id);
		$event_uuid = audit_user_log_event_uuid($username, $user_id, $source_epoch);
		$audit_id   = (int) db_fetch_cell_prepared(
			'SELECT id FROM audit_log WHERE event_uuid = ?',
			[$event_uuid]
		);
		$created = false;

		if ($audit_id <= 0) {
			$audit_id = audit_record_event($descriptor['event_type'], [
				'event_uuid'        => $event_uuid,
				'event_category'    => 'authentication',
				'action'            => $descriptor['action'],
				'severity'          => $descriptor['severity'],
				'operation_outcome' => $descriptor['outcome'],
				'actor_type'        => $user_id > 0 ? 'user' : 'anonymous',
				'target_type'       => 'user_account',
				'target_id'         => $user_id > 0 ? (string) $user_id : $username,
				'ip_address'        => (string) ($row['ip'] ?? ''),
				'user_agent'        => '',
				'page'              => 'user_log.php',
				'event_time'        => gmdate('Y-m-d H:i:s', $source_epoch),
				'defer_delivery'    => true,
				'details'           => [
					'username'     => $username,
					'result_code'  => $result,
					'source_table' => 'user_log',
					'descriptor'   => $descriptor['details']
				]
			]);
			$created = $audit_id > 0;
		}

		if ($audit_id <= 0) {
			$retry_increment = isset($row['state_audit_id']) ? 0 : 1;
			db_execute_prepared('UPDATE audit_user_log_state
				SET retry_count = retry_count + ?,
					processed_time = UTC_TIMESTAMP(6)
				WHERE source_username = ?
				AND source_user_id = ?
				AND source_epoch = ?
				AND audit_id = 0',
				[$retry_increment, $username, $user_id, $source_epoch]);
			$retry_failures++;

			if ((int) ($row['retry_count'] ?? 0) + 1 >= $max_retries) {
				$retry_exhausted++;
				audit_report_dropped_user_log_row($username, $user_id, $source_epoch, $result);
			}

			continue;
		}

		$finalized = db_execute_prepared(
			'UPDATE audit_user_log_state
				SET audit_id = ?
				WHERE source_username = ?
				AND source_user_id = ?
				AND source_epoch = ?
				AND audit_id = 0',
			[$audit_id, $username, $user_id, $source_epoch]
		);

		if (!$finalized || db_affected_rows() !== 1) {
			if ($created) {
				db_execute_prepared('DELETE FROM audit_log WHERE id = ?', [$audit_id]);
			}

			$retry_increment = isset($row['state_audit_id']) ? 0 : 1;
			db_execute_prepared('UPDATE audit_user_log_state
				SET retry_count = retry_count + ?,
					processed_time = UTC_TIMESTAMP(6)
				WHERE source_username = ?
				AND source_user_id = ?
				AND source_epoch = ?
				AND audit_id = 0',
				[$retry_increment, $username, $user_id, $source_epoch]);
			$retry_failures++;

			if ((int) ($row['retry_count'] ?? 0) + 1 >= $max_retries) {
				$retry_exhausted++;
				audit_report_dropped_user_log_row($username, $user_id, $source_epoch, $result);
			}

			continue;
		}

		db_execute_prepared(
			'INSERT INTO settings (name, value) VALUES (?, ?)
				ON DUPLICATE KEY UPDATE value = GREATEST(CAST(value AS UNSIGNED), VALUES(value))',
			['audit_user_log_watermark_epoch', (string) $source_epoch]
		);

		audit_deliver_external_event($audit_id);
		audit_enqueue_syslog_event($audit_id);
	}

	if ($retry_failures > 0) {
		audit_log_ingestion_warning(sprintf(
			'Authentication audit retained %d source row(s) for retry; %d exhausted the %d-attempt limit',
			$retry_failures,
			$retry_exhausted,
			$max_retries
		));
	}
}

/**
 * Detects a global spike in failed login attempts (per user_log) within a
 * configurable sliding window and, when it exceeds a configurable
 * threshold, records a single 'cacti.auth.failed_login_volume_anomaly'
 * critical audit event, using an atomic settings-table claim so
 * concurrent pollers cannot double-alert for the same window. Called
 * from this plugin's poller routine on every polling cycle when
 * authentication auditing and brute-force detection are both enabled.
 *
 * This intentionally describes aggregate installation-wide activity
 * rather than attributing unrelated failures to one attacker.
 *
 * @return void
 */
function audit_detect_failed_login_volume(): void {
	if (read_config_option('audit_enabled') !== 'on') {
		return;
	}

	if (read_config_option('audit_auth_log_enabled') !== 'on') {
		return;
	}

	if (read_config_option('audit_brute_force_enabled') !== 'on') {
		return;
	}

	if (!function_exists('db_table_exists') || !db_table_exists('user_log')) {
		return;
	}

	$window = (int) read_config_option('audit_brute_force_window_minutes');

	if ($window < 1) {
		$window = 5;
	} elseif ($window > 1440) {
		$window = 1440;
	}

	$threshold = (int) read_config_option('audit_brute_force_threshold');

	if ($threshold < 1) {
		$threshold = 10;
	} elseif ($threshold > 1000) {
		$threshold = 1000;
	}

	$metrics = db_fetch_row_prepared(
		'SELECT COUNT(*) AS failed_attempts,
				COUNT(DISTINCT username) AS distinct_usernames,
				COUNT(DISTINCT ip) AS distinct_ips
			FROM user_log
			WHERE result = 0
			AND time >= DATE_SUB(NOW(), INTERVAL ? MINUTE)',
		[$window]
	);
	$count = (int) ($metrics['failed_attempts'] ?? 0);

	if ($count < $threshold) {
		return;
	}

	// Atomically claim the alert slot so two concurrent pollers cannot both
	// emit for the same window. The conditional UPDATE only succeeds if the
	// last alert is empty or older than the window; the affected-row count
	// proves ownership. The settings row is created defensively first so a
	// fresh install can participate in the same atomic claim.
	$now = gmdate('Y-m-d H:i:s');

	$initialized = db_execute_prepared(
		'INSERT IGNORE INTO settings (name, value) VALUES (?, ?)',
		['audit_brute_force_last_alert', '']
	);

	if (!$initialized) {
		return;
	}

	$claimed = db_execute_prepared(
		"UPDATE settings
			SET value = ?
			WHERE name = 'audit_brute_force_last_alert'
			AND (value = '' OR value = '0'
				OR STR_TO_DATE(value, '%Y-%m-%d %H:%i:%s') < DATE_SUB(?, INTERVAL ? MINUTE))",
		[$now, $now, $window]
	);

	if (!$claimed || db_affected_rows() < 1) {
		return;
	}

	$audit_id = audit_record_event('cacti.auth.failed_login_volume_anomaly', [
		'event_category'    => 'authentication',
		'action'            => 'login_volume_anomaly',
		'severity'          => 'critical',
		'operation_outcome' => 'failure',
		'actor_type'        => 'system',
		'target_type'       => 'authentication_environment',
		'target_id'         => 'global',
		'details'           => [
			'scope'              => 'global',
			'failed_attempts'    => $count,
			'distinct_usernames' => (int) ($metrics['distinct_usernames'] ?? 0),
			'distinct_ips'       => (int) ($metrics['distinct_ips'] ?? 0),
			'window_minutes'     => $window,
			'threshold'          => $threshold
		]
	]);

	// Keep the claimed timestamp after a confirmed successful audit insert.
	// If the insert failed, release the slot so the next poller can retry.
	if ($audit_id > 0) {
		set_config_option('audit_brute_force_last_alert', $now);
	} else {
		set_config_option('audit_brute_force_last_alert', '');
	}
}

/**
 * Hook handler for Cacti's custom_denied hook. Records an authorization-
 * denied event and returns the input mode unchanged so Cacti continues
 * rendering its default permission-denied page. Called by Cacti core via
 * api_plugin_hook('custom_denied', ...) whenever a user is denied access
 * to a page.
 *
 * @param  mixed $mode
 * @return mixed
 */
function audit_custom_denied(mixed $mode): mixed {
	if (read_config_option('audit_enabled') !== 'on') {
		return $mode;
	}

	if (read_config_option('audit_auth_log_enabled') !== 'on') {
		return $mode;
	}

	$page     = basename($_SERVER['SCRIPT_NAME'] ?? '');
	$referer  = $_SERVER['HTTP_REFERER'] ?? '';
	$user_id  = (int) ($_SESSION['sess_user_id'] ?? 0);

	// Record only the referer origin. Paths and query strings can both contain
	// tokens, reset hashes, OAuth state, or session identifiers.
	$safe_referer = '';

	if ($referer !== '') {
		$parsed   = parse_url((string) $referer);
		$safe_ref = '';

		if (is_array($parsed)) {
			if (isset($parsed['scheme']) && isset($parsed['host'])) {
				$safe_ref = $parsed['scheme'] . '://' . $parsed['host'];

				if (isset($parsed['port'])) {
					$safe_ref .= ':' . $parsed['port'];
				}
			}
		}

		$safe_referer = $safe_ref !== '' ? $safe_ref : '[unparseable]';
	}

	audit_record_event('cacti.auth.authorization.denied', [
		'event_category'    => 'authentication',
		'action'            => 'authorization_denied',
		'severity'          => 'warning',
		'operation_outcome' => 'failure',
		'actor_type'        => $user_id > 0 ? 'user' : 'anonymous',
		'target_type'       => 'page',
		'target_id'         => $page,
		'page'              => $page,
		'details'           => [
			'requested_page'   => $page,
			'referer_origin'   => $safe_referer,
			'referer_redacted' => $referer !== $safe_referer
		]
	]);

	return $mode;
}

/**
 * Determines which logical groups of Audit settings fields (Syslog
 * delivery, authentication/brute-force) are present in a submitted
 * settings.php form, so the save-handling logic can apply the right
 * authorization/validation checks per group. Called from
 * audit_enforce_syslog_settings_request() when processing an Audit tab
 * settings save.
 *
 * @param  array<string,mixed>          $post
 * @return array{syslog:bool,auth:bool}
 */
function audit_settings_field_groups(array $post): array {
	$groups = ['syslog' => false, 'auth' => false];

	foreach ($post as $name => $value) {
		$name = (string) $name;

		if (str_starts_with($name, 'audit_syslog_')) {
			$groups['syslog'] = true;
		} elseif (
			str_starts_with($name, 'audit_auth_') ||
			str_starts_with($name, 'audit_brute_force_') ||
			str_starts_with($name, 'audit_log_external') ||
			$name === 'audit_enabled' ||
			$name === 'audit_retention' ||
			$name === 'audit_user_log_batch_size'
		) {
			$groups['auth'] = true;
		}
	}

	return $groups;
}

/**
 * Intercepts submissions of the Audit Settings tab (settings.php, action
 * 'save', tab 'audit') to enforce that only audit administrators can
 * change Syslog/authentication settings, that authentication auditing
 * can't be enabled without its required database prerequisites, and that
 * an invalid/incomplete Syslog configuration can't be saved while
 * enabled or actively being configured - recording a denial/rejection
 * audit event and redirecting back to the settings page for any
 * violation. Called from audit_config_insert() at the top of the
 * generic request-capture flow, before Cacti core processes the
 * settings save.
 *
 * @return void
 */
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

	$groups            = audit_settings_field_groups($post);
	$has_syslog_fields = $groups['syslog'];
	$has_auth_fields   = $groups['auth'];

	if (!$has_syslog_fields && !$has_auth_fields) {
		return;
	}

	if (!audit_user_is_admin()) {
		// Preserve the syslog-specific denied event when syslog fields are
		// part of the unauthorized save; use a generic audit-configuration
		// event when only authentication/brute-force fields are present.
		if ($has_syslog_fields) {
			audit_record_event('audit.syslog.configuration.denied', [
				'event_category'    => 'audit',
				'severity'          => 'warning',
				'action'            => 'save',
				'target_type'       => 'syslog_configuration',
				'operation_outcome' => 'failure',
				'outcome_reason'    => 'audit_admin_required'
			]);
		} else {
			audit_record_event('audit.configuration.denied', [
				'event_category'    => 'audit',
				'severity'          => 'warning',
				'action'            => 'save',
				'target_type'       => 'audit_configuration',
				'operation_outcome' => 'failure',
				'outcome_reason'    => 'audit_admin_required'
			]);
		}

		raise_message(
			'audit_configuration_authorization',
			__('Audit administration permission is required to save these settings.', 'audit'),
			MESSAGE_LEVEL_ERROR
		);
		header('Location: settings.php?tab=audit');
		exit;
	}

	$enabling_auth = isset($post['audit_auth_log_enabled']) && $post['audit_auth_log_enabled'] === 'on';

	if ($enabling_auth && (!audit_user_log_identity_supported() || !audit_user_log_indexes_available())) {
		raise_message(
			'audit_authentication_prerequisites',
			__('Authentication auditing was not enabled. Run the audit_auth_indexes.php CLI maintenance command first.', 'audit'),
			MESSAGE_LEVEL_ERROR
		);
		header('Location: settings.php?tab=audit');
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

/**
 * Generic request-capture entry point: enforces Audit Settings save
 * protections, then (for otherwise-eligible requests) builds and inserts
 * an in-flight audit_log event from the current page/action/POST data
 * (redacting sensitive fields, resolving bulk-action object details via
 * audit_process_page_data(), and capturing a deferred verifier for
 * requests whose outcome can only be confirmed later). Called from
 * Cacti core's generic page-processing hook near the start of every
 * page request, when this plugin determines the request is worth
 * auditing (via audit_log_valid_event()).
 *
 * @return void
 *
 * @global string $action Set to a derived human-readable action label
 *                         for certain bulk operations (e.g. 'Delete
 *                         Device', 'Host Enabled'), for the caller's use.
 * @global array  $config Cacti global configuration array; used to
 *                         resolve the base path when CACTI_PATH_BASE
 *                         isn't already defined.
 */
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
