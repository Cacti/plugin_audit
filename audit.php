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
include_once './include/auth.php';

set_default_action();

switch (get_request_var('action')) {
case 'export':
    auditExportRows();

    break;
case 'purge':
    auditPurge();

    top_header();
    auditLog();
    bottom_footer();

    break;
    case 'getdata':
        $data = db_fetch_row_prepared('SELECT *
            FROM audit_log
            WHERE id = ?',
            [get_filter_request_var('id')]);

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
        } elseif (cacti_sizeof($data)) {
            $attribs = json_decode($data['post']);

            $nattribs = [];
            foreach ($attribs as $field => $content) {
                $nattribs[$field] = $content;
            }
            ksort($nattribs);

            if (cacti_sizeof($nattribs) > 16) {
                $width = 'wide';
            } else {
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

            if (cacti_sizeof($nattribs) > 16) {
                $columns = 2;
                $output .= '<tr class="tableHeader"><th style="width:25%">' . __('Attrib', 'audit') . '</th><th style="width:25%">' . __('Value', 'audit') . '</th><th style="width:25%">' . __('Attrib', 'audit') . '</th><th style="width:25%">' . __('Value', 'audit') . '</th></tr>';
            } else {
                $columns = 1;
                $output .= '<tr class="tableHeader"><th style="width:50%">' . __('Attrib', 'audit') . '</th><th style="width:50%">' . __('Value', 'audit') . '</th></tr>';
            }

            $i = 0;
            if (cacti_sizeof($nattribs)) {
                foreach ($nattribs as $field => $content) {
                    if ($i % $columns == 0) {
                        $output .= ($output != '' ? '</tr>':'') . '<tr>';
                    }

                    if (is_array($content)) {
                        $output .= '<td style="font-weight:bold;white-space:nowrap;">' . $field . '</td><td">' . implode(',', $content) . '</td>';
                    } else {
                        $output .= '<td style="font-weight:bold;white-space:nowrap;">' . $field . '</td><td>' . $content . '</td>';
                    }

                    $i++;
                }

                if ($i % $columns > 0) {
                    $output . '<td></td><td></td></tr>';
                }
            }

            // Display the Record Data under selected_items if it is not empty
            $recordData = json_decode($data['object_data']);
            if (!empty($recordData)) {
                $output .= '</table>';
                $output .= '<tr><td colspan="' . ($columns * 2) . '"><hr></td></tr>';
                $output .= '<tr><td colspan="' . ($columns * 2) . '"><b>' . __('Record Data:', 'audit') . '</b></td></tr>';

                foreach ($recordData as $record) {
                    $output .= '<tr><td colspan="' . ($columns * 2) . '"><pre>' . json_encode($record, JSON_PRETTY_PRINT) . '</pre></td></tr>';
                }
            } else {
                $output .= '</table>';
            }
        }

        // Output the final result
        echo $output;


    break;
default:
    top_header();
    auditLog();
    bottom_footer();
}

/**
 * Purge all audit records and raise a user-facing confirmation message.
 *
 * @return void
 */
function auditPurge(): void {
    db_execute('TRUNCATE TABLE audit_log');

    $_SESSION['audit_message'] = __('Audit Log Purged by %s', get_username($_SESSION['sess_user_id']), 'audit');

    cacti_log('NOTE: Audit Log Purged by ' . get_username($_SESSION['sess_user_id']), false, 'WEBUI');

    raise_message('audit_message');
}

/**
 * Build SQL filter conditions based on current request filters.
 *
 * @return string
 */
function auditBuildSqlWhereClause(): string {
    $sql_where = '';

    if (get_request_var('filter') != '') {
        $sql_where = 'WHERE (
            page LIKE '    . db_qstr('%' . get_request_var('filter') . '%') . '
            OR post LIKE ' . db_qstr('%' . get_request_var('filter') . '%') . ')';
    }

    if (get_request_var('event_page') != '-1') {
        $sql_where .= ($sql_where != '' ? ' AND ' : 'WHERE ') . ' page = ' . db_qstr(get_request_var('event_page'));
    }

    if (!isempty_request_var('user_id') && get_request_var('user_id') > '-1') {
        $sql_where .= ($sql_where != '' ? ' AND ' : 'WHERE ') . ' user_id = ' . get_request_var('user_id');
    }

    return $sql_where;
}

/**
 * Convert JSON-encoded POST payload into export-friendly key/value text.
 *
 * @param string $post_payload JSON payload stored in audit_log.post.
 *
 * @return string
 */
function auditBuildPosterString(string $post_payload): string {
    $post   = json_decode($post_payload);
    $poster = '';

    if (!is_object($post)) {
        return $poster;
    }

    foreach ($post as $var => $value) {
        if (is_array($value)) {
            $poster .= ($poster != '' ? '|' : '') . $var . ':' . implode('%', $value);
        } else {
            $poster .= ($poster != '' ? '|' : '') . $var . ':' . $value;
        }
    }

    return $poster;
}

/**
 * Render the audit list filter form.
 *
 * @param array<int, mixed> $item_rows Row-count options for pagination.
 *
 * @return void
 */
function auditRenderFilterForm(array $item_rows): void {
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
                        <input id='filter' type='text' size='25' value='<?php print html_escape_request_var('filter');?>'>
                    </td>
                    <td>
                        <?php print __('Page', 'audit');?>
                    </td>
                    <td>
                        <select id='event_page'>
                            <option value='-1'<?php print (get_request_var('event_page') == '-1' ? ' selected>':'>') . __('All', 'audit');?></option>
                            <?php
                            $pages = array_rekey(db_fetch_assoc('SELECT DISTINCT page FROM audit_log ORDER BY page'), 'page', 'page');
                            if (cacti_sizeof($pages)) {
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
                            if (cacti_sizeof($users)) {
                                foreach ($users as $user) {
                                    if ($user == 0) {
                                        continue;
                                    }
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
                            if (cacti_sizeof($item_rows)) {
                                foreach ($item_rows as $key => $value) {
                                    print "<option value='" . $key . "'"; if (get_request_var('rows') == $key) { print ' selected'; } print '>' . htmlspecialchars($value) . "</option>\n";
                                }
                            }
                            ?>
                        </select>
                    </td>
                    <td>
                        <span>
                            <button type='submit' id='refresh' class='ui-button ui-corner-all ui-widget ui-state-active' title='<?php print __esc('Set/Refresh Filters', 'audit');?>'><?php print __esc('Go', 'audit');?></button>
                            <button type='button' id='clear' class='ui-button ui-corner-all ui-widget' title='<?php print __esc('Clear Filters', 'audit');?>'><?php print __esc('Clear', 'audit');?></button>
                            <button type='button' id='export' class='ui-button ui-corner-all ui-widget' title='<?php print __esc('Export Log Events', 'audit');?>'><?php print __esc('Export', 'audit');?></button>
                            <button type='button' id='purge' class='ui-button ui-corner-all ui-widget' title='<?php print __esc('Purge Log Events', 'audit');?>'><?php print __esc('Purge', 'audit');?></button>
                        </span>
                    </td>
                </tr>
                </tr>
            </table>
            <input type='hidden' id='page' value='<?php print get_request_var('page');?>'>
            </form>
        </td>
    </tr>
    <?php
}

/**
 * Render HTML table rows for the current audit event result set.
 *
 * @param array<int, array<string, mixed>> $events Query result rows.
 *
 * @return void
 */
function auditRenderEventsRows(array $events): void {
    if (!cacti_sizeof($events)) {
        print "<tr class='tableRow'><td colspan='5'><em>" . __('No Audit Log Events Found', 'audit') . "</em></td></tr>\n";
        return;
    }

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
        } else {
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
}

/**
 * Return display metadata for sortable audit table columns.
 *
 * @return array<string, array<string, string>>
 */
function auditGetDisplayText(): array {
    return [
        'page' => [
            'display' => __('Page Name', 'audit'),
            'align' => 'left',
            'sort' => 'ASC',
            'tip' => __('The page where the event was generated.', 'audit')
        ],
        'username' => [
            'display' => __('User Name', 'audit'),
            'align' => 'left',
            'sort' => 'ASC',
            'tip' => __('The user who generated the event.', 'audit')
        ],
        'action' => [
            'display' => __('Action', 'audit'),
            'align' => 'left',
            'sort' => 'ASC',
            'tip' => __('The Cacti Action requested.  Hover over action to see $_POST data.', 'audit')
        ],
        'user_agent' => [
            'display' => __('User Agent', 'audit'),
            'align' => 'left',
            'sort' => 'ASC',
            'tip' => __('The browser type of the requester.', 'audit')
        ],
        'ip_address' => [
            'display' => __('IP Address', 'audit'),
            'align' => 'right',
            'sort' => 'ASC',
            'tip' => __('The IP Address of the requester.', 'audit')
        ],
        'event_time' => [
            'display' => __('Event Time', 'audit'),
            'align' => 'right',
            'sort' => 'DESC',
            'tip' => __('The time the Event took place.', 'audit')
        ]
    ];
}

/**
 * Export filtered audit events as CSV output.
 *
 * @return void
 */
function auditExportRows(): void {
    processRequestVars();
    $sql_where = auditBuildSqlWhereClause();

    $events = db_fetch_assoc("SELECT audit_log.*, user_auth.username
        FROM audit_log
        LEFT JOIN user_auth
        ON audit_log.user_id=user_auth.id
        $sql_where");

    if (cacti_sizeof($events)) {
        header('Content-Disposition: attachment; filename=audit_export.csv');

        print __x('Column Header used for CSV log export. Ensure that you do NOT(!) remove one of the commas. The output needs to be CSV compliant.','page, user_id, username, action, ip_address, user_agent, event_time, post', 'audit') . "\n";

        foreach ($events as $event) {
            $poster = auditBuildPosterString($event['post']);

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

/**
 * Escape unsafe CSV characters in a value.
 *
 * @param string $string Raw value.
 *
 * @return string
 */
function auditCsvEscape(string $string): string {
    $string = str_replace('"', '', $string);
    $string = str_replace(',', '|', $string);
    return $string;
}

/**
 * Validate and store request filter variables in session scope.
 *
 * @return void
 */
function processRequestVars(): void {
    /* ================= input validation and session storage ================= */
    $filters = [
        'rows' => [
            'filter' => FILTER_VALIDATE_INT,
            'pageset' => true,
            'default' => '-1'
            ],
        'page' => [
            'filter' => FILTER_VALIDATE_INT,
            'default' => '1'
            ],
        'filter' => [
            'filter' => FILTER_DEFAULT,
            'pageset' => true,
            'default' => ''
            ],
        'sort_column' => [
            'filter' => FILTER_CALLBACK,
            'default' => 'event_time',
            'options' => ['options' => 'sanitize_search_string']
            ],
        'sort_direction' => [
            'filter' => FILTER_CALLBACK,
            'default' => 'DESC',
            'options' => ['options' => 'sanitize_search_string']
            ],
        'user_id' => [
            'filter' => FILTER_VALIDATE_INT,
            'pageset' => true,
            'default' => '-1'
            ],
        'event_page' => [
            'filter' => FILTER_CALLBACK,
            'pageset' => true,
            'default' => '-1',
            'options' => ['options' => 'sanitize_search_string']
            ]
    ];

    validate_store_request_vars($filters, 'sess_audit');
    /* ================= input validation ================= */
}

/**
 * Render the audit log page with filters, navigation, and results.
 *
 * @return void
 */
function auditLog(): void {
    global $item_rows;

    processRequestVars();

    $rows = (get_request_var('rows') == '-1') ? read_config_option('num_rows_table') : get_request_var('rows');

    html_start_box(__('Audit Log', 'audit'), '100%', '', '3', 'center', '');
    auditRenderFilterForm($item_rows);

    html_end_box();

    $sql_where = auditBuildSqlWhereClause();

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

    $display_text = auditGetDisplayText();

    html_header_sort($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);
    auditRenderEventsRows($events);

    html_end_box(false);

    if (cacti_sizeof($events)) {
        print $nav;
    }

    ?>
    <script type='text/javascript' src='plugins/audit/js/functions.js'></script>
    <?php
}
