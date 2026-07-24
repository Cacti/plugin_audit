<?php

function audit_process_page_data($page, $drop_action, $selected_items) {
	$objects = array();
	if ($drop_action !== false) {
		switch ($page) {
			case 'host.php':
				//loop over array and perform query for each item
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT id AS host_id,site_id,description,hostname,status,status_fail_date AS last_failed_date,status_rec_date AS last_recovered_date
							FROM host
							WHERE id IN (?)',
							array($item));
			}
				break;
			case 'host_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM host_template
						WHERE id IN (?)',
						array($item));
				}
				break;

				case 'templates_export.php':
					foreach ($selected_items as $item) {
						$objects[] = db_fetch_assoc_prepared('SELECT name  FROM graph_templates
							WHERE id IN (?)',
							array($item));
					}
					break;


				case 'automation_devices.php':
					foreach ($selected_items as $item) {
						$result = db_fetch_assoc_prepared('SELECT id, network_id,hostname,ip,sysName,syslocation,snmp,up
							FROM automation_devices
							WHERE id IN (?)',
							array($item));

						foreach ($result as &$row) {
							$row['snmp'] = ($row['snmp'] == 1) ? 'UP' : 'Down';
							$row['up'] = ($row['up'] == 1) ? 'Yes' : 'No';
						}

						$objects[] = $result;
					}
					break;


			case 'graph_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM graph_templates
						WHERE id IN (?)',
						array($item));
				}
				break;

			case 'thold.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT id,name_cache AS THOLD_NAME,data_source_name AS Data_Source
						FROM thold_data
						WHERE id IN (?)',
						array($item));
				}
				break;
			case 'data_sources.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('select name_cache AS Data_Source_Name,active  from data_template_data
						WHERE local_data_id IN (?)',
						array($item));
				}
				break;

			case 'data_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM data_template
						WHERE id IN (?)',
						array($item));
				}
				break;

			case 'aggregate_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM aggregate_graph_template
						WHERE id IN (?)',
						array($item));
				}
				break;

			case 'thold_templates.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM thold_template
						WHERE id IN (?)',
						array($item));
				}
				break;
			case 'user_admin.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT username
						FROM user_auth
						WHERE id IN (?)',
						array($item));
				}
				break;
			case 'user_group_admin.php':
				foreach ($selected_items as $item) {
					$objects[] = db_fetch_assoc_prepared('SELECT name
						FROM user_auth_group
						WHERE id IN (?)',
						array($item));
				}
				break;
		}
	}

	return audit_json_encode($objects);
}

function audit_is_sensitive_key($key) {
	return preg_match('/(?:pass(?:word)?|phrase|token|secret|api[_-]?key|private[_-]?key|community|credential|authorization|authentication)/i', (string) $key);
}

function audit_redact_sensitive_data($data) {
	if (!is_array($data)) {
		return $data;
	}

	$redacted = array();

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

function audit_redact_sensitive_value($value) {
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

function audit_bound_log_data($data, $depth = 0, $state = null) {
	if ($state === null) {
		$state = (object) array('fields' => 0);
	}

	if ($depth >= 12) {
		return '[MAXIMUM DEPTH REACHED]';
	}

	if (is_array($data)) {
		$bounded = array();

		foreach ($data as $key => $value) {
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

function audit_redact_cli_arguments($arguments) {
	$redacted = array();
	$redact_next = false;

	foreach ($arguments as $argument) {
		if ($redact_next) {
			$redacted[] = '[REDACTED]';
			$redact_next = false;
			continue;
		}

		if (preg_match('/^(--?[^=]*(?:pass(?:word)?|phrase|token|secret|api[_-]?key|private[_-]?key|community|credential|authorization|authentication)[^=]*)=(.*)$/i', $argument, $matches)) {
			$redacted[] = $matches[1] . '=[REDACTED]';
			continue;
		}

		if (preg_match('/^--?[^=]*(?:pass(?:word)?|phrase|token|secret|api[_-]?key|private[_-]?key|community|credential|authorization|authentication)/i', $argument)) {
			$redacted[] = $argument;
			$redact_next = true;
			continue;
		}

		$redacted[] = preg_replace('#^([a-z][a-z0-9+.-]*://[^:/@\s]+):[^@\s]+@#i', '$1:[REDACTED]@', $argument);
	}

	return $redacted;
}

function audit_json_encode($data, $options = 0) {
	$json = json_encode(audit_bound_log_data($data), JSON_INVALID_UTF8_SUBSTITUTE | $options, 16);

	if ($json === false) {
		return json_encode(array('audit_encoding_error' => json_last_error_msg()));
	}

	return $json;
}

function audit_json_decode($json, &$error = null) {
	$error = null;

	try {
		return json_decode($json, true, 16, JSON_THROW_ON_ERROR);
	} catch (Throwable $exception) {
		$error = $exception->getMessage();
		return null;
	}
}

function audit_uuid_v4() {
	$bytes = random_bytes(16);
	$bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
	$bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
	$hex = bin2hex($bytes);

	return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' .
		substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
}

function audit_request_correlation_id() {
	static $correlation_id;

	if ($correlation_id === null) {
		$correlation_id = audit_uuid_v4();
	}

	return $correlation_id;
}

function audit_utc_time($microtime = null) {
	$microtime = $microtime === null ? microtime(true) : $microtime;
	$seconds   = (int) $microtime;
	$micros    = (int) round(($microtime - $seconds) * 1000000);

	if ($micros >= 1000000) {
		$seconds++;
		$micros = 0;
	}

	return gmdate('Y-m-d H:i:s', $seconds) . '.' . sprintf('%06d', $micros);
}

function audit_event_integrity_hash($event) {
	$material = array(
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
	);

	return hash('sha256', audit_json_encode($material, JSON_UNESCAPED_SLASHES));
}

function audit_event_type_for_request($page, $action) {
	$page_name = preg_replace('/\.php$/', '', (string) $page);
	$page_name = preg_replace('/[^a-z0-9_]+/i', '_', $page_name);
	$verb      = preg_replace('/[^a-z0-9_]+/i', '_', strtolower((string) $action));
	$verb      = trim($verb, '_');

	return 'cacti.' . ($page_name !== '' ? $page_name : 'request') . '.' .
		($verb !== '' && $verb !== 'none' ? $verb : 'submitted');
}

function audit_external_event_data($event) {
	$fields = array(
		'id', 'event_uuid', 'correlation_id', 'event_type', 'event_category',
		'severity', 'actor_type', 'page', 'user_id', 'action', 'request_status',
		'operation_outcome', 'outcome_reason', 'target_type', 'target_id',
		'ip_address', 'user_agent', 'http_method', 'http_status', 'event_time',
		'completed_time', 'duration_ms', 'post', 'object_data', 'details',
		'previous_hash', 'integrity_hash'
	);
	$data = array();

	foreach ($fields as $field) {
		$data[$field] = $event[$field] ?? null;
	}

	return $data;
}

function audit_external_log_format($data, $format = 'json') {
	if ($format === 'text') {
		$fields = array();

		foreach ($data as $name => $value) {
			if (is_array($value) || is_object($value)) {
				$value = audit_json_encode($value);
			} elseif ($value === null) {
				$value = '';
			} elseif (is_bool($value)) {
				$value = $value ? 'true' : 'false';
			}

			$value = str_replace(
				array('\\', "\r", "\n", "\t", '"'),
				array('\\\\', '\r', '\n', '\t', '\"'),
				(string) $value
			);
			$fields[] = $name . '="' . $value . '"';
		}

		return implode(' ', $fields) . "\n";
	}

	foreach (array('post', 'object_data', 'details') as $name) {
		if (isset($data[$name]) && is_string($data[$name])) {
			$decoded = audit_json_decode($data[$name], $error);

			if ($error === null) {
				$data[$name] = $decoded;
			}
		}
	}

	return audit_json_encode($data, JSON_UNESCAPED_SLASHES) . "\n";
}

function audit_csv_safe_cell($value) {
	$value = (string) $value;

	if (preg_match('/^[=+\-@]/', ltrim($value))) {
		return "'" . $value;
	}

	return $value;
}

function audit_retention_cutoff($retention, $now = null) {
	$now = $now instanceof DateTimeImmutable
		? $now->setTimezone(new DateTimeZone('UTC'))
		: new DateTimeImmutable('now', new DateTimeZone('UTC'));

	return $now->sub(new DateInterval('P' . max(0, (int) $retention) . 'D'));
}

function audit_append_external_log($path, $message) {
	if ($path == '' || !is_file($path) || is_link($path)) {
		return array('status' => 'failed', 'error' => 'Destination is not a regular file or is a symbolic link.');
	}

	$written = file_put_contents($path, $message, FILE_APPEND | LOCK_EX);
	if ($written !== strlen($message)) {
		return array('status' => 'failed', 'error' => 'Unable to append a complete record.');
	}

	return array('status' => 'delivered', 'error' => '');
}

function audit_set_external_status($id, $status, $error = '') {
	db_execute_prepared('UPDATE audit_log
		SET external_status = ?,
			external_error = ?,
			external_attempts = external_attempts + 1,
			external_last_attempt = UTC_TIMESTAMP(6),
			external_delivered_time = CASE WHEN ? = "delivered" THEN UTC_TIMESTAMP(6) ELSE external_delivered_time END
		WHERE id = ?',
		array($status, $error, $status, $id));
}

function audit_deliver_external_event($id) {
	if (read_config_option('audit_log_external') != 'on') {
		return;
	}

	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', array($id));
	if (!cacti_sizeof($event) || $event['request_status'] == 'started') {
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

function audit_retry_external_logs() {
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

	foreach ($events as $event) {
		$message  = audit_external_log_format(audit_external_event_data($event), $format);
		$delivery = audit_append_external_log($path, $message);
		audit_set_external_status($event['id'], $delivery['status'], $delivery['error']);

		if ($delivery['status'] != 'delivered') {
			break;
		}
	}
}

function audit_request_status($error = null, $status_code = 200) {
	$fatal_types = array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR);

	if ((is_array($error) && in_array($error['type'] ?? null, $fatal_types, true)) ||
		$status_code >= 400) {
		return 'failed';
	}

	return 'completed';
}

function audit_finalize_request($id, $started_at = null) {
	$status_code = http_response_code();
	$status_code = is_int($status_code) ? $status_code : 200;
	$request_status = audit_request_status(error_get_last(), $status_code);
	$outcome = $request_status == 'failed' ? 'failure' : 'unknown';
	$duration_ms = $started_at === null ? null : max(0, (int) round((microtime(true) - $started_at) * 1000));
	$completed_time = audit_utc_time();

	db_execute_prepared("UPDATE audit_log
		SET request_status = ?,
			operation_outcome = CASE WHEN operation_outcome = 'unknown' THEN ? ELSE operation_outcome END,
			http_status = ?,
			completed_time = ?,
			duration_ms = ?
		WHERE id = ?
		AND request_status = 'started'",
		array($request_status, $outcome, $status_code, $completed_time, $duration_ms, $id));

	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', array($id));
	if (cacti_sizeof($event)) {
		db_execute_prepared('UPDATE audit_log SET integrity_hash = ? WHERE id = ?',
			array(audit_event_integrity_hash($event), $id));
	}

	audit_deliver_external_event($id);
}

function audit_record_event($event_type, $options = array()) {
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
	$details        = audit_json_encode(audit_redact_sensitive_data($options['details'] ?? array()));
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
		array(
			$page, $user_id, $action, 'completed', $ip_address, $user_agent, $event_time,
			'{}', '[]', $external ? 'pending' : 'disabled', $event_uuid, $correlation_id,
			$event_type, $options['event_category'] ?? 'security',
			$options['severity'] ?? 'info', $options['actor_type'] ?? ($user_id ? 'user' : 'system'),
			$options['target_type'] ?? null, isset($options['target_id']) ? (string) $options['target_id'] : null,
			$options['operation_outcome'] ?? 'success', $options['outcome_reason'] ?? null,
			$options['http_method'] ?? ($_SERVER['REQUEST_METHOD'] ?? null),
			$options['http_status'] ?? null, $options['completed_time'] ?? $event_time,
			$options['duration_ms'] ?? 0, $details
		));

	$id    = db_fetch_insert_id();
	$event = db_fetch_row_prepared('SELECT * FROM audit_log WHERE id = ?', array($id));
	if (cacti_sizeof($event)) {
		db_execute_prepared('UPDATE audit_log SET integrity_hash = ? WHERE id = ?',
			array(audit_event_integrity_hash($event), $id));
	}
	audit_deliver_external_event($id);

	return $id;
}

function audit_logout_pre_session_destroy() {
	$reason = get_nfilter_request_var('action', 'user');
	$type   = $reason == 'timeout' ? 'authentication.session.expired' : 'authentication.logout';

	audit_record_event($type, array(
		'event_category' => 'authentication',
		'action' => $reason == 'timeout' ? 'timeout' : 'logout',
		'details' => array('reason' => $reason)
	));
}



function audit_config_insert() {
	global $action, $config;

	if (audit_log_valid_event()) {
		$started_at = microtime(true);
		/* prepare post */
		$post = filter_input_array(INPUT_POST, FILTER_UNSAFE_RAW);
		$post = is_array($post) ? $post : array();

		/* remove unsafe variables */
		unset($post['__csrf_magic']);
		unset($post['header']);
		$post = audit_redact_sensitive_data($post);

		/* check if drp_action is present and update action accordingly */
		if (isset($post['drp_action']) && $post['drp_action'] == 1) {
			$action = 'delete';
		} else if (isset($post['drp_action']) && $post['drp_action'] == 4) {
			$action = 'disable';
		}

		/* sanitize and serialize selected items */
		if (isset($post['selected_items']) && is_string($post['selected_items'])) {
			$selected_items = @unserialize(stripslashes($post['selected_items']), array('allowed_classes' => false));
			$selected_items = is_array($selected_items) ? $selected_items : array();
			$drop_action    = $post['drp_action'] ?? false;
		} else {
			$selected_items = array();
			$drop_action    = false;
		}

		$target_id   = $post['id'] ?? null;
		$post        = audit_json_encode($post);
		$page        = basename($_SERVER['SCRIPT_NAME']);
		$user_id     = (isset($_SESSION['sess_user_id']) ? $_SESSION['sess_user_id'] : 0);
		$event_time  = audit_utc_time($started_at);

		/* Retrieve IP address */
		$ip_address  = get_client_addr();

		/* Get the User Agent */
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

		$audit_log = read_config_option('audit_log_external_path');
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
		$category       = in_array($page, array('user_admin.php', 'user_group_admin.php'), true) ? 'identity_access' : 'configuration';
		db_execute_prepared('INSERT INTO audit_log (
				page, user_id, action, request_status, ip_address, user_agent, event_time,
				post, object_data, external_status, event_uuid, correlation_id, event_type,
				event_category, severity, actor_type, target_type, target_id,
				operation_outcome, http_method
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			array(
				$page, $user_id, $action, 'started', $ip_address, $user_agent, $event_time,
				$post, $object_data, $external_status, $event_uuid, $correlation_id,
				$event_type, $category, 'info', $user_id ? 'user' : 'system',
				preg_replace('/\.php$/', '', $page), $target_id, 'unknown',
				$_SERVER['REQUEST_METHOD'] ?? null
			));
		$audit_id = db_fetch_insert_id();
		register_shutdown_function('audit_finalize_request', $audit_id, $started_at);

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
		$ip_address = getHostByName(php_uname('n'));
		$user_agent = get_current_user();
		$event_time = audit_utc_time($started_at);
		$post       = implode(' ', $arguments);

		/* don't insert poller records */
		if (strpos($arguments[0], 'poller') === false &&
			strpos($arguments[0], 'cmd.php') === false &&
			strpos($arguments[0], '/scripts/') === false &&
			strpos($arguments[0], 'script_server.php') === false &&
			strpos($arguments[0], '_process.php') === false) {

			$external_status = read_config_option('audit_log_external') == 'on' ? 'pending' : 'disabled';
			db_execute_prepared('INSERT INTO audit_log (
					page, user_id, action, request_status, ip_address, user_agent, event_time,
					post, object_data, external_status, event_uuid, correlation_id, event_type,
					event_category, severity, actor_type, target_type, target_id,
					operation_outcome
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
				array(
					$page, $user_id, $action, 'started', $ip_address, $user_agent,
					$event_time, $post, '[]', $external_status, audit_uuid_v4(),
					audit_request_correlation_id(), 'cacti.cli.executed', 'system',
					'info', 'system', 'cli_command', $page, 'unknown'
				));
			$audit_id = db_fetch_insert_id();
			register_shutdown_function('audit_finalize_request', $audit_id, $started_at);
		}
	}
}
