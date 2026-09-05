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

chdir('../../');
include_once('./include/auth.php');

set_default_action();

switch(get_request_var('action')) {
	case 'export':
		audit_export_rows();

		break;
	case 'syslog_test':
		if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
			http_response_code(405);
			header('Allow: POST');
			exit;
		}

		if (!audit_user_is_admin() || !csrf_check(false)) {
			http_response_code(403);
			exit;
		}

		$result  = audit_syslog_test_delivery();
		$success = $result['status'] === 'sent_unconfirmed';
		audit_record_event('audit.syslog.test', [
			'event_category'    => 'audit',
			'severity'          => $success ? 'notice' : 'warning',
			'action'            => 'test',
			'target_type'       => 'syslog_receiver',
			'operation_outcome' => $success ? 'success' : 'failure',
			'outcome_reason'    => $success ? 'socket_write_completed' : ($result['error_code'] ?? 'delivery_failed'),
			'details'           => [
				'transport'  => audit_syslog_config()['transport'],
				'status'     => $result['status'],
				'error_code' => $result['error_code'] ?? ''
			]
		]);
		$_SESSION['audit_message'] = $success
			? __('Syslog test record was written to the local socket. Receiver storage is unconfirmed.', 'audit')
			: __('Syslog test failed: %s', html_escape($result['error'] ?? 'Unknown error'), 'audit');
		raise_message('audit_message');

		top_header();
		audit_log();
		bottom_footer();

		break;
	case 'syslog_retry':
		if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
			http_response_code(405);
			header('Allow: POST');
			exit;
		}

		if (!audit_user_is_admin() || !csrf_check(false)) {
			http_response_code(403);
			exit;
		}

		$post         = filter_input_array(INPUT_POST, FILTER_UNSAFE_RAW);
		$post         = is_array($post) ? $post : [];
		$delivery_ids = isset($post['delivery_ids']) && is_array($post['delivery_ids'])
			? $post['delivery_ids']
			: [];
		$retried = audit_syslog_retry_dead_letters($delivery_ids);
		audit_record_event('audit.syslog.dead_letter.retried', [
			'event_category'    => 'audit',
			'severity'          => 'notice',
			'action'            => 'retry',
			'target_type'       => 'syslog_delivery',
			'operation_outcome' => 'success',
			'details'           => ['row_count' => $retried]
		]);
		$_SESSION['audit_message'] = __('Reset %d dead-letter Syslog deliveries for retry.', $retried, 'audit');
		raise_message('audit_message');

		top_header();
		audit_log();
		bottom_footer();

		break;
	case 'purge':
		if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
			http_response_code(405);
			header('Allow: POST');
			exit;
		}

		if (!audit_user_is_admin() || !csrf_check(false)) {
			http_response_code(403);
			exit;
		}

		audit_purge();

		top_header();
		audit_log();
		bottom_footer();

		break;
	case 'getdata':
		$data = db_fetch_row_prepared('SELECT *
			FROM audit_log
			WHERE id = ?',
			[get_filter_request_var('id')]);

		if ($data === false || cacti_sizeof($data) === 0) {
			http_response_code(404);
			print html_escape(__('Audit event not found.', 'audit'));

			break;
		}

		audit_record_event('audit.event.viewed', [
			'event_category' => 'audit',
			'target_type'    => 'audit_event',
			'target_id'      => $data['event_uuid'] != '' ? $data['event_uuid'] : $data['id'],
			'details'        => ['record_id' => $data['id']]
		]);

		$output = audit_render_event_details($data);
		print $output;

		break;
	default:
		top_header();
		audit_log();
		bottom_footer();
}

/**
 * @param array<string,mixed> $data
 */
function audit_render_event_details(array $data): string {
	$width  = 'wide';
	$output = '<table style="width:100%" class="' . $width . '"><tr><td>';
	$output .= '<span><b>' . __('Page:', 'audit') . '</b>  <i>' . html_escape($data['page']) . '</i></span>';
	$output .= '<br><span><b>' . __('User:', 'audit') . '</b>  <i>' . html_escape($data['action'] == 'cli' ? $data['user_agent'] : get_username($data['user_id'])) . '</i></span>';
	$output .= '<br><span><b>' . __('IP Address:', 'audit') . '</b>  <i>' . html_escape($data['ip_address']) . '</i></span>';
	$output .= '<br><span><b>' . __('Date:', 'audit') . '</b>  <i>' . html_escape($data['event_time']) . '</i></span>';
	$output .= '<br><span><b>' . __('Action:', 'audit') . '</b>  <i>' . html_escape($data['action']) . '</i></span>';
	$output .= '<br><span><b>' . __('Event Type:', 'audit') . '</b>  <i>' . html_escape($data['event_type']) . '</i></span>';
	$output .= '<br><span><b>' . __('Event ID:', 'audit') . '</b>  <i>' . html_escape($data['event_uuid']) . '</i></span>';
	$output .= '<br><span><b>' . __('Request Status:', 'audit') . '</b>  <i>' . html_escape($data['request_status']) . '</i></span>';
	$output .= '<br><span><b>' . __('Operation Outcome:', 'audit') . '</b>  <i>' . html_escape($data['operation_outcome']) . '</i></span>';

	if ($data['outcome_reason'] != '') {
		$output .= '<br><span><b>' . __('Outcome Reason:', 'audit') . '</b>  <i>' . html_escape($data['outcome_reason']) . '</i></span>';
	}
	$output .= '<br><span><b>' . __('External File Delivery:', 'audit') . '</b>  <i>' . html_escape($data['external_status']) . '</i></span>';

	if ($data['external_error'] != '') {
		$output .= '<br><span><b>' . __('External File Error:', 'audit') . '</b>  <i>' . html_escape($data['external_error']) . '</i></span>';
	}

	if (db_table_exists('audit_syslog_delivery')) {
		$syslog = db_fetch_row_prepared('SELECT state, attempts, last_attempt, sent_time, last_error
			FROM audit_syslog_delivery
			WHERE audit_id = ?
			ORDER BY id DESC
			LIMIT 1',
			[$data['id']]);

		if (cacti_sizeof($syslog) > 0) {
			$state      = (string) ($syslog['state'] ?? 'unknown');
			$attempts   = (int) ($syslog['attempts'] ?? 0);
			$sent_time  = (string) ($syslog['sent_time'] ?? '');
			$last_error = (string) ($syslog['last_error'] ?? '');

			$output .= '<br><span><b>' . __('Remote Syslog Delivery:', 'audit') . '</b>  <i>' . html_escape($state) . '</i></span>';
			$output .= '<br><span><b>' . __('Syslog Attempts:', 'audit') . '</b>  <i>' . $attempts . '</i></span>';

			if ($sent_time != '') {
				$output .= '<br><span><b>' . __('Syslog Socket Write:', 'audit') . '</b>  <i>' . html_escape($sent_time) . '</i></span>';
			}

			if ($last_error != '') {
				$output .= '<br><span><b>' . __('Syslog Error:', 'audit') . '</b>  <i>' . html_escape($last_error) . '</i></span>';
			}
		}
	}
	$output .= '<hr>';

	if ($data['action'] == 'cli') {
		$output .= '<span><b>' . __('Script:', 'audit') . '</b>  <i>' . html_escape($data['post']) . '</i></span>';

		return $output . '</td></tr></table>';
	}

	$attribs = audit_json_decode($data['post'], $json_error);
	$attribs = is_array($attribs) ? $attribs : [
		__('Stored Data', 'audit') => __('The stored request data is not valid JSON: %s', $json_error, 'audit')
	];
	ksort($attribs);

	$columns = cacti_sizeof($attribs) > 16 ? 2 : 1;
	$output .= '<table style="width:100%">';
	$output .= $columns == 2
		? '<tr class="tableHeader"><th style="width:25%">' . __('Attrib', 'audit') . '</th><th style="width:25%">' . __('Value', 'audit') . '</th><th style="width:25%">' . __('Attrib', 'audit') . '</th><th style="width:25%">' . __('Value', 'audit') . '</th></tr>'
		: '<tr class="tableHeader"><th style="width:50%">' . __('Attrib', 'audit') . '</th><th style="width:50%">' . __('Value', 'audit') . '</th></tr>';

	$i = 0;

	foreach ($attribs as $field => $content) {
		if ($i % $columns == 0) {
			$output .= '<tr>';
		}

		$output .= '<td style="font-weight:bold;white-space:nowrap;">' . html_escape($field) . '</td><td>' . audit_render_value($content) . '</td>';
		$i++;

		if ($i % $columns == 0) {
			$output .= '</tr>';
		}
	}

	if ($i % $columns > 0) {
		$output .= '<td></td><td></td></tr>';
	}

	$record_data = audit_json_decode($data['object_data'], $object_error);

	if (is_array($record_data) && !empty($record_data)) {
		$output .= '<tr><td colspan="' . ($columns * 2) . '"><hr></td></tr>';
		$output .= '<tr><td colspan="' . ($columns * 2) . '"><b>' . __('Record Data:', 'audit') . '</b></td></tr>';

		foreach ($record_data as $record) {
			$output .= '<tr><td colspan="' . ($columns * 2) . '"><pre>' . html_escape(json_encode($record, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE)) . '</pre></td></tr>';
		}
	}

	return $output . '</table></td></tr></table>';
}

function audit_render_value(mixed $value): string {
	if (is_array($value) || is_object($value)) {
		return '<pre>' . html_escape(json_encode($value, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE)) . '</pre>';
	}

	if (is_bool($value)) {
		$value = $value ? 'true' : 'false';
	} elseif ($value === null) {
		$value = 'null';
	}

	return html_escape((string) $value);
}

function audit_purge(): void {
	$protected = db_fetch_cell("SELECT COUNT(*)
		FROM audit_log
		WHERE EXISTS (
			SELECT 1
			FROM audit_syslog_delivery
			WHERE audit_syslog_delivery.audit_id = audit_log.id
			AND audit_syslog_delivery.state IN ('pending', 'retry', 'dead_letter')
		)");

	db_execute("DELETE FROM audit_log
		WHERE NOT EXISTS (
			SELECT 1
			FROM audit_syslog_delivery
			WHERE audit_syslog_delivery.audit_id = audit_log.id
			AND audit_syslog_delivery.state IN ('pending', 'retry', 'dead_letter')
		)");
	$purged = db_affected_rows();

	audit_record_event('audit.log.purged', [
		'event_category' => 'audit',
		'severity'       => 'warning',
		'action'         => 'purge',
		'target_type'    => 'audit_log',
		'details'        => [
			'purged_count'    => $purged,
			'protected_count' => (int) $protected
		]
	]);

	$_SESSION['audit_message'] = __('Audit Log purge by %s removed %d events and protected %d events with unfinished Syslog delivery.',
		get_username($_SESSION['sess_user_id']), $purged, (int) $protected, 'audit');

	cacti_log('NOTE: Audit Log Purged by ' . get_username($_SESSION['sess_user_id']), false, 'WEBUI');

	raise_message('audit_message');
}

function audit_export_rows(): void {
	audit_process_request_vars();

	// form the 'where' clause for our main sql query
	$sql_clauses = [];
	$sql_params  = [];

	if (get_request_var('filter') != '') {
		$sql_clauses[] = '(page LIKE ? OR post LIKE ?)';
		$sql_params[]  = '%' . get_request_var('filter') . '%';
		$sql_params[]  = '%' . get_request_var('filter') . '%';
	}

	if (get_request_var('event_page') != '-1') {
		$sql_clauses[] = 'page = ?';
		$sql_params[]  = get_request_var('event_page');
	}

	if (!isempty_request_var('user_id') && get_request_var('user_id') > '-1') {
		$sql_clauses[] = 'user_id = ?';
		$sql_params[]  = get_request_var('user_id');
	}

	$sql_where = cacti_sizeof($sql_clauses) ? 'WHERE ' . implode(' AND ', $sql_clauses) : '';

	$events = db_fetch_assoc_prepared("SELECT audit_log.*, user_auth.username
			FROM audit_log
			LEFT JOIN user_auth
			ON audit_log.user_id=user_auth.id
			$sql_where",
		$sql_params);

	audit_record_event('audit.log.exported', [
		'event_category' => 'audit',
		'action'         => 'export',
		'target_type'    => 'audit_log',
		'details'        => [
			'row_count'  => cacti_sizeof($events),
			'filter'     => get_request_var('filter'),
			'event_page' => get_request_var('event_page'),
			'user_id'    => get_request_var('user_id')
		]
	]);

	if (cacti_sizeof($events)) {
		header('Content-Disposition: attachment; filename=audit_export.csv');
		header('Content-Type: text/csv; charset=UTF-8');
		header('X-Content-Type-Options: nosniff');

		$output = fopen('php://output', 'w');

		if ($output !== false) {
			fputcsv($output, ['event_uuid', 'correlation_id', 'event_type', 'event_category', 'severity', 'page', 'user_id', 'username', 'action', 'request_status', 'operation_outcome', 'outcome_reason', 'target_type', 'target_id', 'external_status', 'external_error', 'ip_address', 'user_agent', 'http_method', 'http_status', 'event_time', 'completed_time', 'duration_ms', 'integrity_hash', 'post', 'details'], ',', '"', '');

			if (is_array($events)) {
				foreach ($events as $event) {
					if ($event['action'] == 'cli') {
						$poster = $event['post'];
					} else {
						$post   = audit_json_decode($event['post'], $json_error);
						$poster = is_array($post) ? json_encode($post, JSON_INVALID_UTF8_SUBSTITUTE) : $event['post'];
					}

					fputcsv($output, array_map('audit_csv_safe_cell', [
						$event['event_uuid'],
						$event['correlation_id'],
						$event['event_type'],
						$event['event_category'],
						$event['severity'],
						$event['page'],
					$event['user_id'],
					get_username($event['user_id']),
					$event['action'],
						$event['request_status'],
						$event['operation_outcome'],
						$event['outcome_reason'],
						$event['target_type'],
						$event['target_id'],
						$event['external_status'],
					$event['external_error'],
					$event['ip_address'],
						$event['user_agent'],
						$event['http_method'],
						$event['http_status'],
						$event['event_time'],
						$event['completed_time'],
						$event['duration_ms'],
						$event['integrity_hash'],
						$poster,
						$event['details']
					]), ',', '"', '');
				}
			}

			fclose($output);
		}
	}
}

function audit_process_request_vars(): void {
	// ================= input validation and session storage =================
	$filters = [
		'rows' => [
			'filter'  => FILTER_VALIDATE_INT,
			'pageset' => true,
			'default' => '-1'
			],
		'page' => [
			'filter'  => FILTER_VALIDATE_INT,
			'default' => '1'
			],
		'filter' => [
			'filter'  => FILTER_DEFAULT,
			'pageset' => true,
			'default' => ''
			],
		'sort_column' => [
			'filter'  => FILTER_CALLBACK,
			'default' => 'event_time',
			'options' => ['options' => 'sanitize_search_string']
			],
		'sort_direction' => [
			'filter'  => FILTER_CALLBACK,
			'default' => 'DESC',
			'options' => ['options' => 'sanitize_search_string']
			],
		'user_id' => [
			'filter'  => FILTER_VALIDATE_INT,
			'pageset' => true,
			'default' => '-1'
			],
		'event_page' => [
			'filter'  => FILTER_CALLBACK,
			'pageset' => true,
			'default' => '-1',
			'options' => ['options' => 'sanitize_search_string']
			]
	];

	validate_store_request_vars($filters, 'sess_audit');
	// ================= input validation =================
}

function audit_log(): void {
	global $item_rows;

	audit_process_request_vars();
	$has_filters = get_request_var('filter') != '' ||
		get_request_var('event_page')           != '-1' ||
		(!isempty_request_var('user_id') && get_request_var('user_id') > '-1');
	audit_record_event($has_filters ? 'audit.log.searched' : 'audit.log.viewed', [
		'event_category' => 'audit',
		'action'         => $has_filters ? 'search' : 'view',
		'target_type'    => 'audit_log',
		'details'        => [
			'filter'     => get_request_var('filter'),
			'event_page' => get_request_var('event_page'),
			'user_id'    => get_request_var('user_id')
		]
	]);

	if (get_request_var('rows') == '-1') {
		$rows = read_config_option('num_rows_table');
	} else {
		$rows = get_request_var('rows');
	}

	if (audit_user_is_admin()) {
		audit_render_syslog_health();
	}

	html_start_box(__('Audit Log', 'audit'), '100%', '', '3', 'center', '');

	?>
	<tr class='even'>
		<td>
			<form id='form_audit' action='audit.php'>
			<table class='filterTable'>
				<tr>
					<td>
						<?php print __('Search', 'audit'); ?>
					</td>
					<td>
						<input id='filter' type='text' size='25' value='<?php print html_escape_request_var('filter'); ?>'>
					</td>
					<td>
						<?php print __('Page', 'audit'); ?>
					</td>
					<td>
						<select id='event_page'>
							<option value='-1'<?php print (get_request_var('event_page') == '-1' ? ' selected>' : '>') . __('All', 'audit'); ?></option>
							<?php
								$pages = array_rekey(db_fetch_assoc('SELECT DISTINCT page FROM audit_log ORDER BY page'), 'page', 'page');

	if (cacti_sizeof($pages)) {
		foreach ($pages as $page) {
			print "<option value='" . html_escape($page) . "'";

			if (get_request_var('event_page') == $page) {
				print ' selected';
			} print '>' . html_escape($page) . "</option>\n";
		}
	}
	?>
						</select>
					</td>
					<td>
						<?php print __('User', 'audit'); ?>
					</td>
					<td>
						<select id='user_id'>
							<option value='-1'<?php print (get_request_var('user_id') == '-1' ? ' selected>' : '>') . __('All', 'audit'); ?></option>
							<option value='0'<?php print (get_request_var('user_id') == '0' ? ' selected>' : '>') . __('cli', 'audit'); ?></option>
							<?php
	$users = array_rekey(db_fetch_assoc('SELECT DISTINCT user_id FROM audit_log ORDER BY user_id'), 'user_id', 'user_id');

	if (cacti_sizeof($users)) {
		foreach ($users as $user) {
			if ($user == 0) {
				continue;
			}
			print "<option value='" . (int) $user . "'";

			if (get_request_var('user_id') == $user) {
				print ' selected';
			} print '>' . html_escape(get_username($user)) . "</option>\n";
		}
	}
	?>
						</select>
					</td>
					<td>
						<?php print __('Events', 'audit'); ?>
					</td>
					<td>
						<select id='rows'>
							<option value='-1'<?php print (get_request_var('rows') == '-1' ? ' selected>' : '>') . __('Default', 'audit'); ?></option>
							<?php
	if (cacti_sizeof($item_rows)) {
		foreach ($item_rows as $key => $value) {
			print "<option value='" . (int) $key . "'";

			if (get_request_var('rows') == $key) {
				print ' selected';
			} print '>' . html_escape($value) . "</option>\n";
		}
	}
	?>
						</select>
					</td>
					<td>
						<span>
							<button type='submit' id='refresh' class='ui-button ui-corner-all ui-widget ui-state-active' title='<?php print __esc('Set/Refresh Filters', 'audit'); ?>'><?php print __esc('Go', 'audit'); ?></button>
							<button type='button' id='clear' class='ui-button ui-corner-all ui-widget' title='<?php print __esc('Clear Filters', 'audit'); ?>'><?php print __esc('Clear', 'audit'); ?></button>
							<button type='button' id='export' class='ui-button ui-corner-all ui-widget' title='<?php print __esc('Export Log Events', 'audit'); ?>'><?php print __esc('Export', 'audit'); ?></button>
							<?php if (audit_user_is_admin()) {?>
							<button type='button' id='purge' class='ui-button ui-corner-all ui-widget' data-confirm='<?php print __esc('Permanently purge all audit log events?', 'audit'); ?>' title='<?php print __esc('Purge Log Events', 'audit'); ?>'><?php print __esc('Purge', 'audit'); ?></button>
							<?php }?>
						</span>
					</td>
					</tr>
				</table>
				<input type='hidden' id='page' value='<?php print (int) get_request_var('page'); ?>'>
			</form>
		</td>
	</tr>
	<?php

	html_end_box();

	// form the 'where' clause for our main sql query
	$sql_clauses = [];
	$sql_params  = [];

	if (get_request_var('filter') != '') {
		$sql_clauses[] = '(page LIKE ? OR post LIKE ?)';
		$sql_params[]  = '%' . get_request_var('filter') . '%';
		$sql_params[]  = '%' . get_request_var('filter') . '%';
	}

	if (get_request_var('event_page') != '-1') {
		$sql_clauses[] = 'page = ?';
		$sql_params[]  = get_request_var('event_page');
	}

	if (!isempty_request_var('user_id') && get_request_var('user_id') > '-1') {
		$sql_clauses[] = 'user_id = ?';
		$sql_params[]  = get_request_var('user_id');
	}

	$sql_where = cacti_sizeof($sql_clauses) ? 'WHERE ' . implode(' AND ', $sql_clauses) : '';

	$total_rows = db_fetch_cell_prepared("SELECT
			COUNT(*)
			FROM audit_log
			LEFT JOIN user_auth
			ON audit_log.user_id=user_auth.id
			$sql_where",
		$sql_params);

	$sql_order = get_order_string();
	$sql_limit = ' LIMIT ' . ($rows * (get_request_var('page') - 1)) . ',' . $rows;

	$events = db_fetch_assoc_prepared("SELECT audit_log.*, user_auth.username
			FROM audit_log
			LEFT JOIN user_auth
			ON audit_log.user_id=user_auth.id
			$sql_where
			$sql_order
			$sql_limit",
		$sql_params);

	$nav = html_nav_bar('audit.php?filter=' . rawurlencode(get_request_var('filter')), MAX_DISPLAY_PAGES, get_request_var('page'), $rows, $total_rows, 5, __('Audit Events', 'audit'), 'page', 'main');

	print $nav;

	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = [
		'page' => [
			'display' => __('Page Name', 'audit'),
			'align'   => 'left',
			'sort'    => 'ASC',
			'tip'     => __('The page where the event was generated.', 'audit')
		],
		'username' => [
			'display' => __('User Name', 'audit'),
			'align'   => 'left',
			'sort'    => 'ASC',
			'tip'     => __('The user who generated the event.', 'audit')
		],
			'action' => [
				'display' => __('Requested Action', 'audit'),
				'align'   => 'left',
				'sort'    => 'ASC',
				'tip'     => __('The requested Cacti action. Hover over the action to see request data.', 'audit')
			],
			'request_status' => [
				'display' => __('Request Status', 'audit'),
				'align'   => 'left',
				'sort'    => 'ASC',
				'tip'     => __('Request processing state; completion does not guarantee that every operation succeeded.', 'audit')
			],
			'external_status' => [
				'display' => __('External File Delivery', 'audit'),
				'align'   => 'left',
				'sort'    => 'ASC',
				'tip'     => __('Delivery state for the optional external audit log file. Remote Syslog health is shown separately.', 'audit')
		],
		'user_agent'  => [
			'display' => __('User Agent', 'audit'),
			'align'   => 'left',
			'sort'    => 'ASC',
			'tip'     => __('The browser type of the requester.', 'audit')
		],
		'ip_address'  => [
			'display' => __('IP Address', 'audit'),
			'align'   => 'right',
			'sort'    => 'ASC',
			'tip'     => __('The IP Address of the requester.', 'audit')
		],
		'event_time'  => [
			'display' => __('Event Time', 'audit'),
			'align'   => 'right',
			'sort'    => 'DESC',
			'tip'     => __('The time the Event took place.', 'audit')
		]
	];

	html_header_sort($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	$i = 0;

	if (cacti_sizeof($events)) {
		if (is_array($events)) {
			foreach ($events as $e) {
				if ($e['action'] == 'cli') {
					form_alternate_row('line' . $e['id'], false);
					form_selectable_ecell($e['page'], $e['id']);
					form_selectable_ecell($e['user_agent'], $e['id']);
					form_selectable_cell('<span id="event' . (int) $e['id'] . '" class="linkEditMain">' . html_escape(ucfirst($e['action'])) . '</span>', $e['id']);
					form_selectable_ecell($e['request_status'], $e['id']);
					form_selectable_ecell($e['external_status'], $e['id']);
					form_selectable_cell(__('N/A', 'audit'), $e['id']);
					form_selectable_ecell($e['ip_address'], $e['id'], '', 'right');
					form_selectable_ecell($e['event_time'], $e['id'], '', 'right');
					form_end_row();
				} else {
					form_alternate_row('line' . $e['id'], false);
					form_selectable_cell(filter_value($e['page'], get_request_var('filter')), $e['id']);
					form_selectable_ecell($e['username'], $e['id']);
					form_selectable_cell('<span id="event' . (int) $e['id'] . '" class="linkEditMain">' . html_escape(ucfirst($e['action'])) . '</span>', $e['id']);
					form_selectable_ecell($e['request_status'], $e['id']);
					form_selectable_ecell($e['external_status'], $e['id']);
					form_selectable_ecell($e['user_agent'], $e['id']);
					form_selectable_ecell($e['ip_address'], $e['id'], '', 'right');
					form_selectable_ecell($e['event_time'], $e['id'], '', 'right');
					form_end_row();
				}
			}
		}
	} else {
		print "<tr class='tableRow'><td colspan='8'><em>" . __('No Audit Log Events Found', 'audit') . "</em></td></tr>\n";
	}

	html_end_box(false);

	if (cacti_sizeof($events)) {
		print $nav;
	}

	?>
	<script type='text/javascript' src='plugins/audit/js/functions.js'></script>
	<?php
}

function audit_render_syslog_health(): void {
	$config    = audit_syslog_config();
	$health    = audit_syslog_health();
	$enabled   = audit_syslog_enabled();
	$unhealthy = $enabled && (
		!$config['valid'] ||
		$health['dead_letter'] >= $config['dead_letter_warning'] ||
		$health['oldest_pending_seconds'] >= $config['pending_age_warning']
	);

	html_start_box(__('Remote Syslog Delivery', 'audit'), '100%', '', '3', 'center', '');

	print "<tr class='" . ($unhealthy ? 'error' : 'even') . "'>";
	print '<td><b>' . __('Status', 'audit') . '</b></td>';
	print '<td>' . html_escape(!$enabled ? __('Disabled', 'audit') : ($unhealthy ? __('Unhealthy', 'audit') : __('Healthy', 'audit'))) . '</td>';
	print '<td><b>' . __('Pending', 'audit') . '</b></td><td>' . (int) $health['pending'] . '</td>';
	print '<td><b>' . __('Retry', 'audit') . '</b></td><td>' . (int) $health['retry'] . '</td>';
	print '<td><b>' . __('Dead-letter', 'audit') . '</b></td><td>' . (int) $health['dead_letter'] . '</td>';
	print '<td><b>' . __('Sent (Unconfirmed)', 'audit') . '</b></td><td>' . (int) $health['sent_unconfirmed'] . '</td>';
	print '</tr>';

	print "<tr class='odd'>";
	print '<td><b>' . __('Oldest Pending', 'audit') . '</b></td><td>' . (int) $health['oldest_pending_seconds'] . ' ' . html_escape(__('seconds', 'audit')) . '</td>';
	print '<td><b>' . __('Last Attempt', 'audit') . '</b></td><td>' . html_escape($health['last_attempt'] ?? __('Never', 'audit')) . '</td>';
	print '<td><b>' . __('Last Socket Write', 'audit') . '</b></td><td>' . html_escape($health['last_sent'] ?? __('Never', 'audit')) . '</td>';
	print '<td colspan="4">';
	print "<button type='button' id='syslog_test' class='ui-button ui-corner-all ui-widget'>" . __esc('Test Syslog', 'audit') . '</button> ';

	if ($health['dead_letter'] > 0) {
		print "<button type='button' id='syslog_retry' class='ui-button ui-corner-all ui-widget' data-confirm='" .
			__esc('Retry all dead-letter Syslog events?', 'audit') . "'>" . __esc('Retry Dead-letter', 'audit') . '</button>';
	}
	print '</td></tr>';

	if ($enabled && !$config['valid']) {
		print "<tr class='error'><td colspan='10'><b>" . __esc('Configuration Error:', 'audit') . '</b> ' .
			html_escape(implode(', ', $config['errors'])) . '</td></tr>';
	} elseif ($health['last_error'] !== null) {
		print "<tr class='error'><td colspan='10'><b>" . __esc('Last Error:', 'audit') . '</b> ' .
			html_escape($health['last_error']) . '</td></tr>';
	}

	html_end_box();
}
