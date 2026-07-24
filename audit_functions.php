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

	foreach (array('post', 'object_data') as $name) {
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
		SET external_status = ?, external_error = ?
		WHERE id = ?',
		array($status, $error, $id));
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
		WHERE external_status = 'failed'
		ORDER BY id
		LIMIT 100");

	foreach ($events as $event) {
		$log_data = array(
			'page'        => $event['page'],
			'user_id'     => $event['user_id'],
			'action'      => $event['action'],
			'request_status' => $event['request_status'],
			'ip_address'  => $event['ip_address'],
			'user_agent'  => $event['user_agent'],
			'event_time'  => $event['event_time'],
			'post'        => $event['post'],
			'object_data' => $event['object_data']
		);

		$message  = audit_external_log_format($log_data, $format);
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

function audit_finalize_request($id) {
	$status_code = http_response_code();
	$status_code = is_int($status_code) ? $status_code : 200;
	$request_status = audit_request_status(error_get_last(), $status_code);

	db_execute_prepared("UPDATE audit_log
		SET request_status = ?
		WHERE id = ?
		AND request_status = 'started'",
		array($request_status, $id));
}



function audit_config_insert() {
	global $action, $config;

	if (audit_log_valid_event()) {
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

		$post        = audit_json_encode($post);
		$page        = basename($_SERVER['SCRIPT_NAME']);
		$user_id     = (isset($_SESSION['sess_user_id']) ? $_SESSION['sess_user_id'] : 0);
		$event_time  = date('Y-m-d H:i:s');

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
		$external_format  = read_config_option('audit_log_external_format');
		$external_format  = $external_format === 'text' ? 'text' : 'json';

		if (!defined('CACTI_PATH_BASE')) {
			$base = $config['base_path'];
		} else {
			$base = CACTI_PATH_BASE;
		}

		db_execute_prepared('INSERT INTO audit_log (page, user_id, action, request_status, ip_address, user_agent, event_time, post, object_data, external_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			array($page, $user_id, $action, 'started', $ip_address, $user_agent, $event_time, $post, $object_data, $external_status));
		$audit_id = db_fetch_insert_id();
		register_shutdown_function('audit_finalize_request', $audit_id);

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

		if ($external_logging && $audit_log != '' && is_file($audit_log) && !is_link($audit_log)) {
			$log_data = array(
				'page'        => $page,
				'user_id'     => $user_id,
				'action'      => $action,
				'request_status' => 'started',
				'ip_address'  => $ip_address,
				'user_agent'  => $user_agent,
				'event_time'  => $event_time,
				'post'        => $post,
				'object_data' => $object_data
			);

			$log_msg = audit_external_log_format($log_data, $external_format);
			$delivery = audit_append_external_log($audit_log, $log_msg);
			audit_set_external_status($audit_id, $delivery['status'], $delivery['error']);

			if ($delivery['status'] != 'delivered') {
				cacti_log(sprintf('ERROR: Unable to append a complete record to Audit Log file \'%s\': %s', $audit_log, $delivery['error']), false, 'AUDIT');
			}
		} elseif ($external_logging && $audit_log != '') {
			$error = 'Destination is not a regular file or is a symbolic link.';
			audit_set_external_status($audit_id, 'failed', $error);
			cacti_log(sprintf('ERROR: Audit Log file \'%s\' is not a regular file or is a symbolic link.', $audit_log), false, 'AUDIT');
		}
	} elseif (isset($_SERVER['argv']) && cacti_sizeof($_SERVER['argv'])) {
		$arguments  = audit_redact_cli_arguments($_SERVER['argv']);
		$page       = basename($arguments[0]);
		$user_id    = 0;
		$action     = 'cli';
		$ip_address = getHostByName(php_uname('n'));
		$user_agent = get_current_user();
		$event_time = date('Y-m-d H:i:s');
		$post       = implode(' ', $arguments);

		/* don't insert poller records */
		if (strpos($arguments[0], 'poller') === false &&
			strpos($arguments[0], 'cmd.php') === false &&
			strpos($arguments[0], '/scripts/') === false &&
			strpos($arguments[0], 'script_server.php') === false &&
			strpos($arguments[0], '_process.php') === false) {

			db_execute_prepared('INSERT INTO audit_log (page, user_id, action, request_status, ip_address, user_agent, event_time, post, external_status)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
				array($page, $user_id, $action, 'started', $ip_address, $user_agent, $event_time, $post, 'not_applicable'));
		}
	}
}
