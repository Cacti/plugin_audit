<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2017 The Cacti Group                                 |
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
case 'purge':
	audit_purge();

	top_header();
	audit_log();
	bottom_footer();

	break;
case 'getdata':
	$data = db_fetch_row_prepared('SELECT *
		FROM audit_log 
		WHERE id = ?',
		array(get_filter_request_var('id')));

	$output = '';

	if ($data['action'] == 'cli') {
		$width = 'wide';
		$output .= '<table style="width:100%" class="' . $width . '"><tr><td>';
		$output .= '<span><b>' . __('Page:', 'audit') . '</b>  <i>' . $data['page'] . '</i></span>';
		$output .= '<br><span><b>' . __('User:', 'audit') . '</b>  <i>' . $data['user_agent'] . '</i></span>';
		$output .= '<br><span><b>' . __('IP Address:', 'audit') . '</b>  <i>' . $data['ip_address'] . '</i></span>';
		$output .= '<br><span><b>' . __('Date:', 'audit') . '</b>  <i>' . $data['event_time'] . '</i></span>';
		$output .= '<br><span><b>' . __('Action:', 'audit') . '</b>  <i>' . $data['action'] . '</i></span>';
		$output .= '<hr>';
		$output .= '<span><b>' . __('Script:', 'audit') . '</b>  <i>' . $data['post'] . '</i></span>';
	}elseif (sizeof($data)) {
		$attribs = json_decode($data['post']);

		$nattribs = array();
		foreach($attribs as $field => $content) {
			$nattribs[$field] = $content;
		}
		ksort($nattribs);

		if (sizeof($nattribs) > 16) {
			$width = 'wide';
		}else{
			$width = 'narrow';
		}

		$output .= '<table style="width:100%" class="' . $width . '"><tr><td>';
		$output .= '<span><b>' . __('Page:', 'audit') . '</b>  <i>' . $data['page'] . '</i></span>';
		$output .= '<br><span><b>' . __('User:', 'audit') . '</b>  <i>' . get_username($data['user_id']) . '</i></span>';
		$output .= '<br><span><b>' . __('IP Address:', 'audit') . '</b>  <i>' . $data['ip_address'] . '</i></span>';
		$output .= '<br><span><b>' . __('Date:', 'audit') . '</b>  <i>' . $data['event_time'] . '</i></span>';
		$output .= '<br><span><b>' . __('Action:', 'audit') . '</b>  <i>' . $data['action'] . '</i></span>';
		$output .= '<hr>';
		$output .= '<table style="width:100%">';

		if (sizeof($nattribs) > 16) {
			$columns = 2;
			$output .= '<tr class="tableHeader"><th style="width:25%">' . __('Attrib', 'audit') . '</th><th style="width:25%">' . __('Value', 'audit') . '</th><th style="width:25%">' . __('Attrib', 'audit') . '</th><th style="width:25%">' . __('Value', 'audit') . '</th></tr>';
		}else{
			$columns = 1;
			$output .= '<tr class="tableHeader"><th style="width:50%">' . __('Attrib', 'audit') . '</th><th style="width:50%">' . __('Value', 'audit') . '</th></tr>';
		}

		$i = 0;
		if (sizeof($nattribs)) {
			foreach($nattribs as $field => $content) {
				if ($i % $columns == 0) {
					$output .= ($output != '' ? '</tr>':'') . '<tr>';
				}

				if (is_array($content)) {
					$output .= '<td style="font-weight:bold;white-space:nowrap;">' . $field . '</td><td">' . implode(',', $content) . '</td>';
				}else{
					$output .= '<td style="font-weight:bold;white-space:nowrap;">' . $field . '</td><td>' . $content . '</td>';
				}

				$i++;
			}

			if ($i % $columns > 0) {
				$output . '<td></td><td></td></tr>';
			}
		}
		$output .= '</table>';
	}

	$output .= '</td></tr></table>';

	print $output;

	break;
default:
	top_header();
	audit_log();
	bottom_footer();
}

function audit_purge() {
	db_execute('TRUNCATE TABLE audit_log');

	$_SESSION['audit_message'] = __('Audit Log Purged by %s', get_username($_SESSION['sess_user_id']), 'audit');

	cacti_log('NOTE: Audit Log Purged by ' . get_username($_SESSION['sess_user_id']), false, 'WEBUI');

	raise_message('audit_message');
}

function audit_export_rows() {
	process_request_vars();

	/* form the 'where' clause for our main sql query */
	if (get_request_var('filter') != '') {
		$sql_where = "WHERE (page LIKE '%" . get_request_var('filter') . "%' 
			OR post LIKE '%" .  get_request_var('filter') . "%')";
	}else{
		$sql_where = '';
	}

	if (get_request_var('event_page') != '-1') {
		$sql_where .= ($sql_where != '' ? ' AND ':'WHERE ') . ' page = ' . db_qstr(get_request_var('event_page'));
	}

	if (!isempty_request_var('user_id') && get_request_var('user_id') > '-1') {
		$sql_where .= ($sql_where != '' ? ' AND ':'WHERE ') . ' user_id = ' . get_request_var('user_id');
	}

	$events = db_fetch_assoc("SELECT audit_log.*, user_auth.username
		FROM audit_log
		LEFT JOIN user_auth
		ON audit_log.user_id=user_auth.id
		$sql_where");

	if (sizeof($events)) {
		header('Content-Disposition: attachment; filename=audit_export.csv');

		print __x('Column Header used for CSV log export. Ensure that you do NOT(!) remove one of the commas. The output needs to be CSV compliant.','page, user_id, username, action, ip_address, user_agent, event_time, post', 'audit') . "\n";

		foreach($events as $event) {
			$post = json_decode($event['post']);
			$poster = '';
			foreach($post as $var => $value) {
				if (is_array($value)) {
					$poster .= ($poster != '' ? '|':'') . $var . ':' . implode('%', $value);
				}else{
					$poster .= ($poster != '' ? '|':'') . $var . ':' . $value;
				}
			}

			print 
				$event['page']                   . ', '  .
				$event['user_id']                . ', '  . 
				get_username($event['user_id'])  . ', '  .
				$event['action']                 . ', '  .
				$event['ip_address']             . ', '  .
				$event['user_agent']             . ', '  .
				$event['event_time']             . ', ' .
				$poster                          . "\n";
		}
	}
}

function audit_csv_escape($string) {
	$string = str_replace('"', '', $string);
	$string = str_replace(',', '|', $string);
	return $string;
}

function process_request_vars() {
	/* ================= input validation and session storage ================= */
	$filters = array(
		'rows' => array(
			'filter' => FILTER_VALIDATE_INT, 
			'pageset' => true,
			'default' => '-1'
			),
		'page' => array(
			'filter' => FILTER_VALIDATE_INT, 
			'default' => '1'
			),
		'filter' => array(
			'filter' => FILTER_CALLBACK, 
			'pageset' => true,
			'default' => '', 
			'options' => array('options' => 'sanitize_search_string')
			),
		'sort_column' => array(
			'filter' => FILTER_CALLBACK, 
			'default' => 'event_time', 
			'options' => array('options' => 'sanitize_search_string')
			),
		'sort_direction' => array(
			'filter' => FILTER_CALLBACK, 
			'default' => 'DESC', 
			'options' => array('options' => 'sanitize_search_string')
			),
		'user_id' => array(
			'filter' => FILTER_VALIDATE_INT, 
			'pageset' => true,
			'default' => '-1'
			),
		'event_page' => array(
			'filter' => FILTER_CALLBACK, 
			'pageset' => true,
			'default' => '-1', 
			'options' => array('options' => 'sanitize_search_string')
			)
	);

	validate_store_request_vars($filters, 'sess_audit');
	/* ================= input validation ================= */
}

function audit_log() {
	global $item_rows;

	process_request_vars();

	if (get_request_var('rows') == '-1') {
		$rows = read_config_option('num_rows_table');
	}else{
		$rows = get_request_var('rows');
	}

	html_start_box(__('Audit Log', 'audit'), '100%', '', '3', 'center', '');

	?>
	<tr class='even'>
		<td>
			<form id='form_audit' action='audit.php'>
			<table class='filterTable'>
				<tr>
					<td>
						<?php print __('Search', 'audit');?>
					</td>
					<td>
						<input id='filter' type='text' name='filter' size='25' value='<?php print htmlspecialchars(get_request_var('filter'));?>'>
					</td>
					<td>
						<?php print __('Page', 'audit');?>
					</td>
					<td>
						<select id='event_page'>
							<option value='-1'<?php print (get_request_var('event_page') == '-1' ? ' selected>':'>') . __('All', 'audit');?></option>
							<?php
							$pages = array_rekey(db_fetch_assoc('SELECT DISTINCT page FROM audit_log ORDER BY page'), 'page', 'page');
							if (sizeof($pages)) {
								foreach ($pages as $page) {
									print "<option value='" . $page . "'"; if (get_request_var('event_page') == $page) { print ' selected'; } print '>' . htmlspecialchars($page) . "</option>\n";
								}
							}
							?>
						</select>
					</td>
					<td>
						<?php print __('User', 'audit');?>
					</td>
					<td>
						<select id='user_id'>
							<option value='-1'<?php print (get_request_var('user_id') == '-1' ? ' selected>':'>') . __('All', 'audit');?></option>
							<option value='0'<?php print (get_request_var('user_id') == '0' ? ' selected>':'>') . __('cli', 'audit');?></option>
							<?php
							$users = array_rekey(db_fetch_assoc('SELECT DISTINCT user_id FROM audit_log ORDER BY user_id'), 'user_id', 'user_id');
							if (sizeof($users)) {
								foreach ($users as $user) {
									if ($user == 0) continue;
									print "<option value='" . $user . "'"; if (get_request_var('user_id') == $user) { print ' selected'; } print '>' . htmlspecialchars(get_username($user)) . "</option>\n";
								}
							}
							?>
						</select>
					<td>
						<?php print __('Events', 'audit');?>
					</td>
					<td>
						<select id='rows'>
							<option value='-1'<?php print (get_request_var('rows') == '-1' ? ' selected>':'>') . __('Default', 'audit');?></option>
							<?php
							if (sizeof($item_rows)) {
								foreach ($item_rows as $key => $value) {
									print "<option value='" . $key . "'"; if (get_request_var('rows') == $key) { print ' selected'; } print '>' . htmlspecialchars($value) . "</option>\n";
								}
							}
							?>
						</select>
					</td>
					<td>
						<input type='button' id='refresh' value='<?php print __esc('Go', 'audit');?>' title='<?php print __esc('Set/Refresh Filters', 'audit');?>'>
					</td>
					<td>
						<input type='button' id='clear' value='<?php print __esc('Clear', 'audit');?>' title='<?php print __esc('Clear Filters', 'audit');?>'>
					</td>
					<td>
						<input type='button' id='export' value='<?php print __esc('Export', 'audit');?>' title='<?php print __esc('Export Log Events', 'audit');?>'>
					</td>
					<td>
						<input type='button' id='purge' value='<?php print __esc('Purge', 'audit');?>' title='<?php print __esc('Purge Log Events', 'audit');?>'>
					</td>
				</tr>
				</tr>
			</table>
			<input type='hidden' id='page' value='<?php print get_request_var('page');?>'>
			</form>
			<script type='text/javascript'>
			function applyFilter() {
				strURL = 'audit.php' + 
					'?filter='+$('#filter').val()+
					'&rows='+$('#rows').val()+
					'&page='+$('#page').val()+
					'&event_page='+$('#event_page').val()+
					'&user_id='+$('#user_id').val()+
					'&header=false';
				loadPageNoHeader(strURL);
			}

			function clearFilter() {
				strURL = 'audit.php?clear=1&header=false';
				loadPageNoHeader(strURL);
			}

			$(function() {
				$('#event_page, #user_id, #rows').change(function() {
					applyFilter();
				});

				$('#refresh').click(function() {
					applyFilter();
				});

				$('#clear').click(function() {
					clearFilter();
				});

				$('#purge').click(function() {
					strURL = 'audit.php?action=purge&header=false';
					loadPageNoHeader(strURL);
				});

				$('#export').click(function() {
					document.location = 'audit.php?action=export' +
						'&filter='+$('#filter').val()+
						'&event_page='+$('#event_page').val()+
						'&user_id='+$('#user_id').val();
				});

				$('#form_audit').submit(function(event) {
					event.preventDefault();
					applyFilter();
				});
			});
			</script>
		</td>
	</tr>
	<?php

	html_end_box();

	/* form the 'where' clause for our main sql query */
	if (get_request_var('filter') != '') {
		$sql_where = "WHERE (page LIKE '%" . get_request_var('filter') . "%' 
			OR post LIKE '%" .  get_request_var('filter') . "%')";
	}else{
		$sql_where = '';
	}

	if (get_request_var('event_page') != '-1') {
		$sql_where .= ($sql_where != '' ? ' AND ':'WHERE ') . ' page = ' . db_qstr(get_request_var('event_page'));
	}

	if (!isempty_request_var('user_id') && get_request_var('user_id') > '-1') {
		$sql_where .= ($sql_where != '' ? ' AND ':'WHERE ') . ' user_id = ' . get_request_var('user_id');
	}

	$total_rows = db_fetch_cell("SELECT
		COUNT(*)
		FROM audit_log
		LEFT JOIN user_auth
		ON audit_log.user_id=user_auth.id
		$sql_where");

	$sql_order = get_order_string();
	$sql_limit = ' LIMIT ' . ($rows*(get_request_var('page')-1)) . ',' . $rows;

	$events = db_fetch_assoc("SELECT audit_log.*, user_auth.username
		FROM audit_log
		LEFT JOIN user_auth
		ON audit_log.user_id=user_auth.id
		$sql_where
		$sql_order
		$sql_limit");

    $nav = html_nav_bar('audit.php?filter=' . get_request_var('filter'), MAX_DISPLAY_PAGES, get_request_var('page'), $rows, $total_rows, 5, __('Audit Events', 'audit'), 'page', 'main');

    print $nav;

	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'page' => array(
			'display' => __('Page Name', 'audit'),
			'align' => 'left',
			'sort' => 'ASC',
			'tip' => __('The page where the event was generated.', 'audit')
		),
		'username' => array(
			'display' => __('User Name', 'audit'),
			'align' => 'left',
			'sort' => 'ASC',
			'tip' => __('The user who generated the event.', 'audit')
		),
		'action' => array(
			'display' => __('Action', 'audit'),
			'align' => 'left',
			'sort' => 'ASC',
			'tip' => __('The Cacti Action requested.  Hover over action to see $_POST data.', 'audit')
		),
		'user_agent'  => array(
			'display' => __('User Agent', 'audit'),
			'align' => 'left',
			'sort' => 'ASC',
			'tip' => __('The browser type of the requester.', 'audit')
		),
		'ip_address'  => array(
			'display' => __('IP Address', 'audit'),
			'align' => 'right',
			'sort' => 'ASC',
			'tip' => __('The IP Address of the requester.', 'audit')
		),
		'event_time'  => array(
			'display' => __('Event Time', 'audit'),
			'align' => 'right',
			'sort' => 'DESC',
			'tip' => __('The time the Event took place.', 'audit')
		)
	);

	html_header_sort($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	$i = 0;
	if (sizeof($events)) {
		foreach ($events as $e) {
			if ($e['action'] == 'cli') {
				form_alternate_row('line' . $e['id'], false);
				form_selectable_cell($e['page'], $e['id']);
				form_selectable_cell($e['user_agent'], $e['id']);
				form_selectable_cell('<span id="event' . $e['id'] . '" class="linkEditMain">' . ucfirst($e['action']) . '</span>', $e['id']);
				form_selectable_cell(__('N/A', 'audit'), $e['id']);
				form_selectable_cell($e['ip_address'], $e['id'], '', 'right');
				form_selectable_cell($e['event_time'], $e['id'], '', 'right');
				form_end_row();
			}else{
				form_alternate_row('line' . $e['id'], false);
				form_selectable_cell(filter_value($e['page'], get_request_var('filter')), $e['id']);
				form_selectable_cell($e['username'], $e['id']);
				form_selectable_cell('<span id="event' . $e['id'] . '" class="linkEditMain">' . ucfirst($e['action']) . '</span>', $e['id']);
				form_selectable_cell($e['user_agent'], $e['id']);
				form_selectable_cell($e['ip_address'], $e['id'], '', 'right');
				form_selectable_cell($e['event_time'], $e['id'], '', 'right');
				form_end_row();
			}
		}
	}else{
		print "<tr class='tableRow'><td colspan='5'><em>" . __('No Audit Log Events Found', 'audit') . "</em></td></tr>\n";
	}

	html_end_box(false);

	if (sizeof($events)) {
		print $nav;
	}

	?>
	<script type='text/javascript'>
	var auditTimer = null;

	function open_dialog(id) {
		$.get('audit.php?action=getdata&id='+id, function(data) {
			if (data.indexOf('narrow') > 0) {
				width = 400;
			}else{
				width = 700;
			}
			$('body').append('<div id="audit" style="display:block;display:none;" title="<?php print __esc('Audit Event Details', 'audit');?>">'+data+'</div>');
			$('#audit').dialog({
				minWidth: width,
				position: {
					my: 'left', 
					at: 'right', 
					of: $('span[id="event'+id+'"]')
				}
			});
		});
	}

	$('span[id^="event"]').hover(function() {
		close_dialog();

		id = $(this).attr('id').replace('event', '');

		if (auditTimer != null) {
			clearTimeout(auditTimer);
		}

		auditTimer = setTimeout(function() { open_dialog(id); }, 400);
	},
	function() {
		if (auditTimer != null) {
			clearTimeout(auditTimer);
		}

		close_dialog();
	});

	function close_dialog() {
		if ($('#audit').length) {
			if (typeof $('#audit').dialog() === 'function') {
				$('#audit').dialog('close');
			}
			$('#audit').remove();
		}
	}
	</script>
	<?php
}

