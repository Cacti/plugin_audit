<?php

/**
 * Build a lookup map of page names to SQL queries for selected item snapshots.
 *
 * @return array<string, string>
 */
function auditBuildPageQueryMap(): array {
    return [
        'host.php' => 'SELECT id AS host_id,site_id,description,hostname,status,status_fail_date AS last_failed_date,status_rec_date AS last_recovered_date FROM host WHERE id IN (?)',
        'host_templates.php' => 'SELECT name FROM host_template WHERE id IN (?)',
        'templates_export.php' => 'SELECT name FROM graph_templates WHERE id IN (?)',
        'automation_devices.php' => 'SELECT id, network_id,hostname,ip,sysName,syslocation,snmp,up FROM automation_devices WHERE id IN (?)',
        'graph_templates.php' => 'SELECT name FROM graph_templates WHERE id IN (?)',
        'thold.php' => 'SELECT id,name_cache AS THOLD_NAME,data_source_name AS Data_Source FROM thold_data WHERE id IN (?)',
        'data_sources.php' => 'SELECT name_cache AS Data_Source_Name,active FROM data_template_data WHERE local_data_id IN (?)',
        'data_templates.php' => 'SELECT name FROM data_template WHERE id IN (?)',
        'aggregate_templates.php' => 'SELECT name FROM aggregate_graph_template WHERE id IN (?)',
        'thold_templates.php' => 'SELECT name FROM thold_template WHERE id IN (?)',
        'user_admin.php' => 'SELECT username FROM user_auth WHERE id IN (?)',
        'user_group_admin.php' => 'SELECT name FROM user_auth_group WHERE id IN (?)'
    ];
}

/**
 * Normalize automation device fields before they are written to object_data.
 *
 * @param array<int, array<string, mixed>> $result Raw automation device rows.
 *
 * @return array<int, array<string, mixed>>
 */
function auditTransformAutomationDevices(array $result): array {
    foreach ($result as &$row) {
        $row['snmp'] = ($row['snmp'] == 1) ? 'UP' : 'Down';
        $row['up']   = ($row['up'] == 1) ? 'Yes' : 'No';
    }

    return $result;
}

/**
 * Collect page-specific object snapshots for selected IDs and return JSON.
 *
 * @param string    $page           Current page filename.
 * @param int|false $drop_action    Bulk action value or false when not applicable.
 * @param array     $selected_items Selected item identifiers from request payload.
 *
 * @return string JSON-encoded object snapshot list.
 */
function auditProcessPageData(string $page, int|false $drop_action, array $selected_items): string {
    if ($drop_action === false) {
        return json_encode([]);
    }

    $query_map = auditBuildPageQueryMap();
    if (!isset($query_map[$page])) {
        return json_encode([]);
    }

    $objects = [];
    foreach ($selected_items as $item) {
        $result = db_fetch_assoc_prepared($query_map[$page], [$item]);
        if ($page == 'automation_devices.php') {
            $result = auditTransformAutomationDevices($result);
        }

        $objects[] = $result;
    }

    return json_encode($objects);
}

/**
 * Sanitize request payload and infer action from bulk-operation request values.
 *
 * @param string $action Action value, updated by reference when a drop action is detected.
 *
 * @return array<string, mixed>
 */
function auditPrepareRequestPost(string &$action): array {
    $post = $_REQUEST;
    unset($post['__csrf_magic']);
    unset($post['header']);

    foreach ($post as $key => $value) {
        if (preg_match('/pass|phrase/i', $key)) {
            unset($post[$key]);
        }
    }

    if (isset($post['drp_action']) && $post['drp_action'] == 1) {
        $action = 'delete';
    } elseif (isset($post['drp_action']) && $post['drp_action'] == 4) {
        $action = 'disable';
    }

    return $post;
}

/**
 * Extract selected item IDs and the drop action from a sanitized request payload.
 *
 * @param array<string, mixed> $post Sanitized request payload.
 *
 * @return array{0: array, 1: int|false}
 */
function auditGetSelectedItemsData(array $post): array {
    if (!isset($post['selected_items'])) {
        return [[], false];
    }

    $selected_items = unserialize(stripslashes($post['selected_items']), ['allowed_classes' => false]);
    $drop_action    = isset($post['drp_action']) ? $post['drp_action'] : false;

    return [$selected_items, $drop_action];
}

/**
 * Resolve the runtime base path used by the plugin.
 *
 * @param array<string, mixed> $config Global Cacti config array.
 *
 * @return string
 */
function auditGetBasePath(array $config): string {
    if (defined('CACTI_PATH_BASE')) {
        return CACTI_PATH_BASE;
    }

    return $config['base_path'];
}

/**
 * Map known bulk actions to user-friendly labels for audit output.
 *
 * @param string    $page        Current page filename.
 * @param int|false $drop_action Drop action code from request payload.
 * @param string    $action      Fallback action label.
 *
 * @return string
 */
function auditResolveAction(string $page, int|false $drop_action, string $action): string {
    $action_map = [
        'automation_devices.php' => [
            2 => 'Delete Device',
            1 => 'Create Device'
        ],
        'host.php' => [
            2 => 'Host Enabled',
            3 => 'Host Disabled'
        ]
    ];

    if (isset($action_map[$page][$drop_action])) {
        return $action_map[$page][$drop_action];
    }

    return $action;
}

/**
 * Build a normalized GUI audit event payload for database and file logging.
 *
 * @param array<string, mixed> $config Global Cacti config array.
 * @param string               $action Current action value, updated by reference.
 *
 * @return array<string, mixed>
 */
function auditBuildGuiEventData(array $config, string &$action): array {
    $post = auditPrepareRequestPost($action);
    list($selected_items, $drop_action) = auditGetSelectedItemsData($post);

    if (empty($action) && isset_request_var('action')) {
        $action = get_nfilter_request_var('action');
    } elseif (empty($action)) {
        $action = 'none';
    }

    $page = basename($_SERVER['SCRIPT_NAME']);
    $action = auditResolveAction($page, $drop_action, $action);

    return [
        'page'        => $page,
        'user_id'     => isset($_SESSION['sess_user_id']) ? $_SESSION['sess_user_id'] : 0,
        'action'      => $action,
        'ip_address'  => get_client_addr(),
        'user_agent'  => $_SERVER['HTTP_USER_AGENT'],
        'event_time'  => date('Y-m-d H:i:s'),
        'post'        => json_encode($post),
        'object_data' => auditProcessPageData($page, $drop_action, $selected_items),
        'base_path'   => auditGetBasePath($config)
    ];
}

/**
 * Insert a GUI audit event into the audit_log table.
 *
 * @param array<string, mixed> $event Normalized GUI audit event payload.
 *
 * @return void
 */
function auditInsertGuiEvent(array $event): void {
    db_execute_prepared('INSERT INTO audit_log (page, user_id, action, ip_address, user_agent, event_time, post, object_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [$event['page'], $event['user_id'], $event['action'], $event['ip_address'], $event['user_agent'], $event['event_time'], $event['post'], $event['object_data']]);
}

/**
 * Resolve and initialize the external audit log path setting.
 *
 * @param string $base_path Cacti base path.
 *
 * @return string
 */
function auditGetExternalLogPath(string $base_path): string {
    $audit_log = read_config_option('audit_log_external_path');
    if ($audit_log == '') {
        $audit_log = $base_path . '/log/audit.log';
        set_config_option('audit_log_external_path', $audit_log);
    }

    return $audit_log;
}

/**
 * Create the external audit log file when configured and missing.
 *
 * @param string $audit_log External audit log file path.
 *
 * @return void
 */
function auditEnsureExternalLogFile(string $audit_log): void {
    if ($audit_log == '' || file_exists($audit_log)) {
        return;
    }

    if (is_writable(dirname($audit_log))) {
        cacti_log(sprintf('NOTE: The Audit Log file \'%s\' does not exist.  Creating it.', $audit_log), false, 'AUDIT');
        touch($audit_log);
    } else {
        cacti_log(sprintf('ERROR: Audit Log file path \'%s\' does not exist and the path is not writeable.', $audit_log), false, 'AUDIT');
    }
}

/**
 * Append an event record to the configured external audit log.
 *
 * @param string               $audit_log External audit log file path.
 * @param array<string, mixed> $event     Normalized GUI audit event payload.
 *
 * @return void
 */
function auditWriteExternalLog(string $audit_log, array $event): void {
    if (read_config_option('audit_log_external') != 'on' || $audit_log == '' || !file_exists($audit_log)) {
        return;
    }

    $log_data = [
        'page'        => $event['page'],
        'user_id'     => $event['user_id'],
        'action'      => $event['action'],
        'ip_address'  => $event['ip_address'],
        'user_agent'  => $event['user_agent'],
        'event_time'  => $event['event_time'],
        'post'        => $event['post'],
        'object_data' => $event['object_data']
    ];

    $log_msg = json_encode($log_data) . "\n";
    $file    = fopen($audit_log, 'a');
    if ($file) {
        fwrite($file, $log_msg);
        fclose($file);
    }
}

/**
 * Persist CLI audit events when the invoking script is not excluded.
 *
 * @return void
 */
function auditInsertCliEvent(): void {
    $page       = basename($_SERVER['argv'][0]);
    $user_id    = 0;
    $action     = 'cli';
    $ip_address = getHostByName(php_uname('n'));
    $user_agent = get_current_user();
    $event_time = date('Y-m-d H:i:s');
    $post       = implode(' ', $_SERVER['argv']);

    if (strpos($_SERVER['argv'][0], 'poller') !== false ||
        strpos($_SERVER['argv'][0], 'cmd.php') !== false ||
        strpos($_SERVER['argv'][0], '/scripts/') !== false ||
        strpos($_SERVER['argv'][0], 'script_server.php') !== false ||
        strpos($_SERVER['argv'][0], '_process.php') !== false) {
        return;
    }

    db_execute_prepared('INSERT INTO audit_log (page, user_id, action, ip_address, user_agent, event_time, post)
        VALUES (?, ?, ?, ?, ?, ?, ?)',
        [$page, $user_id, $action, $ip_address, $user_agent, $event_time, $post]);
}

/**
 * Hook callback for config_insert to capture GUI and CLI audit activity.
 *
 * @return void
 */
function auditConfigInsert(): void {
    global $action, $config;

    if (auditLogValidEvent()) {
        $event     = auditBuildGuiEventData($config, $action);
        $audit_log = auditGetExternalLogPath($event['base_path']);

        auditInsertGuiEvent($event);
        auditEnsureExternalLogFile($audit_log);
        auditWriteExternalLog($audit_log, $event);
        return;
    }

    if (isset($_SERVER['argv'])) {
        auditInsertCliEvent();
    }
}
