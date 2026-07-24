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
			$redacted[$key] = $value;
		}
	}

	return $redacted;
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

function audit_json_encode($data) {
	$json = json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE);

	if ($json === false) {
		return json_encode(array('audit_encoding_error' => json_last_error_msg()));
	}

	return $json;
}

function audit_csv_safe_cell($value) {
	$value = (string) $value;

	if (preg_match('/^[=+\-@]/', ltrim($value))) {
		return "'" . $value;
	}

	return $value;
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

		if (!defined('CACTI_PATH_BASE')) {
			$base = $config['base_path'];
		} else {
			$base = CACTI_PATH_BASE;
		}

		db_execute_prepared('INSERT INTO audit_log (page, user_id, action, outcome, ip_address, user_agent, event_time, post, object_data)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
			array($page, $user_id, $action, 'attempted', $ip_address, $user_agent, $event_time, $post, $object_data));

		$external_logging = read_config_option('audit_log_external') == 'on';

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
				'outcome'     => 'attempted',
				'ip_address'  => $ip_address,
				'user_agent'  => $user_agent,
				'event_time'  => $event_time,
				'post'        => $post,
				'object_data' => $object_data
			);

			$log_msg = audit_json_encode($log_data) . "\n";
			$written = file_put_contents($audit_log, $log_msg, FILE_APPEND | LOCK_EX);

			if ($written !== strlen($log_msg)) {
				cacti_log(sprintf('ERROR: Unable to append a complete record to Audit Log file \'%s\'.', $audit_log), false, 'AUDIT');
			}
		} elseif ($external_logging && $audit_log != '') {
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

			db_execute_prepared('INSERT INTO audit_log (page, user_id, action, outcome, ip_address, user_agent, event_time, post)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
				array($page, $user_id, $action, 'attempted', $ip_address, $user_agent, $event_time, $post));
		}
	}
}
