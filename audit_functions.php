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
						FROM graph_template
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

	return json_encode($objects);
}



function audit_config_insert() {
	global $action;

	if (audit_log_valid_event()) {
		/* prepare post */
		$post = $_REQUEST;
		

		/* remove unsafe variables */
		unset($post['__csrf_magic']);
		unset($post['header']);
		foreach ($post as $key => $value) {
			if (preg_match('/pass|phrase/i', $key)) {
				unset($post[$key]);
			}
		}


		// Check if drp_action is present and update action accordingly
		if (isset($post['drp_action']) && $post['drp_action'] == 1) {
			$action = 'delete';
		} else if (isset($post['drp_action']) && $post['drp_action'] == 4) {
			$action = 'disable';
		}


		
		/* sanitize and serialize selected items */
		if (isset($post['selected_items'])) {
			$selected_items = sanitize_unserialize_selected_items($post['selected_items']);
			$drop_action    = $post['drp_action'];
		} else {
			$selected_items = array();
			$drop_action    = false;
		}

		$post        = json_encode($post);
		$page        = basename($_SERVER['SCRIPT_NAME']);
		$user_id     = (isset($_SESSION['sess_user_id']) ? $_SESSION['sess_user_id'] : 0);
		$event_time  = date('Y-m-d H:i:s');

		// Retrieve IP address
		if (isset($_SERVER['X-Forwarded-For'])) {
			$ip_address = $_SERVER['X-Forwarded-For'];
		} elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} elseif (isset($_SERVER['REMOTE_ADDR'])) {
			$ip_address = $_SERVER['REMOTE_ADDR'];
		} else {
			$ip_address = '';
		}

		$user_agent  = $_SERVER['HTTP_USER_AGENT'];

		if (empty($action) && isset_request_var('action')) {
			$action = get_nfilter_request_var('action');
		} elseif (empty($action)) {
			$action = 'none';
		}

		$object_data = audit_process_page_data($page, $drop_action, $selected_items);
		if ($page == 'automation_devices.php' && $drop_action == 2) {
			$action = 'Delete Device';
		}
		if ($page == 'automation_devices.php' && $drop_action == 1) {
			$action = 'Create Device';
		}

		db_execute_prepared('INSERT INTO audit_log (page, user_id, action, ip_address, user_agent, event_time, post, object_data)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			array($page, $user_id, $action, $ip_address, $user_agent, $event_time, $post, $object_data));

			if (!file_exists(read_config_option('audit_log_external_path'))) {
				cacti_log('ERROR: Audit Log External Path does not exist ', false, 'AUDIT');
			}
		
			if (read_config_option('audit_log_external') == 'on' && read_config_option('audit_log_external_path') != '' && file_exists(read_config_option('audit_log_external_path')))  {
				$audit_log_external_path = read_config_option('audit_log_external_path');
				$log_data = array(
					'page' => $page,
					'user_id' => $user_id,
					'action' => $action,
					'ip_address' => $ip_address,
					'user_agent' => $user_agent,
					'event_time' => $event_time,
					'post' => $post,
					'object_data' => $object_data
				);

				$log_msg = json_encode($log_data) . "\n";
				$file = fopen($audit_log_external_path, 'a');
				if ($file) {
					fwrite($file, $log_msg);
					fclose($file);
				}
			}


	} elseif (isset($_SERVER['argv'])) {
		$page       = basename($_SERVER['argv'][0]);
		$user_id    = 0;
		$action     = 'cli';
		$ip_address = getHostByName(php_uname('n'));
		$user_agent = get_current_user();
		$event_time = date('Y-m-d H:i:s');
		$post       = implode(' ', $_SERVER['argv']);

		/* don't insert poller records */
		if (strpos($_SERVER['argv'][0], 'poller') === false &&
			strpos($_SERVER['argv'][0], 'cmd.php') === false &&
			strpos($_SERVER['argv'][0], '/scripts/') === false &&
			strpos($_SERVER['argv'][0], 'script_server.php') === false &&
			strpos($_SERVER['argv'][0], '_process.php') === false) {
			db_execute_prepared('INSERT INTO audit_log (page, user_id, action, ip_address, user_agent, event_time, post)
				VALUES (?, ?, ?, ?, ?, ?, ?)',
				array($page, $user_id, $action, $ip_address, $user_agent, $event_time, $post));
		}
	}
}