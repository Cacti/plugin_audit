<?php

$audit_queue_settings = array(
	'audit_syslog_enabled' => 'on',
	'audit_syslog_receiver' => '127.0.0.1',
	'audit_syslog_port' => '514',
	'audit_syslog_transport' => 'udp',
	'audit_syslog_format' => 'json',
	'audit_syslog_facility' => 'local0',
	'audit_syslog_application' => 'cacti-audit',
	'audit_syslog_node_id' => 'queue-test-node',
	'audit_syslog_timeout' => '5',
	'audit_syslog_udp_max_size' => '8192',
	'audit_syslog_retry_base' => '5',
	'audit_syslog_retry_max' => '60',
	'audit_syslog_max_attempts' => '5',
	'audit_syslog_batch_size' => '10',
	'audit_syslog_pending_age_warning' => '900',
	'audit_syslog_dead_letter_warning' => '1',
	'audit_syslog_tls_ca_file' => '',
	'audit_syslog_tls_client_cert' => '',
	'audit_syslog_tls_client_key' => ''
);
$audit_queue_calls = array();
$audit_queue_affected_rows = 0;

function read_config_option($name) {
	global $audit_queue_settings;

	return isset($audit_queue_settings[$name]) ? $audit_queue_settings[$name] : '';
}

function db_table_exists($table) {
	return $table === 'audit_syslog_delivery';
}

function db_fetch_row_prepared($sql, $params = array()) {
	return array(
		'id' => (int) $params[0],
		'event_uuid' => '32e0a97d-d9e8-4abc-8f41-2bbbc50793ca',
		'request_status' => 'completed'
	);
}

function db_execute_prepared($sql, $params = array()) {
	global $audit_queue_calls;

	$audit_queue_calls[] = array('sql' => $sql, 'params' => $params);
	return true;
}

function db_execute($sql) {
	global $audit_queue_calls;

	$audit_queue_calls[] = array('sql' => $sql, 'params' => array());
	return true;
}

function db_affected_rows() {
	global $audit_queue_affected_rows;

	return $audit_queue_affected_rows;
}

function cacti_sizeof($value) {
	return is_array($value) ? count($value) : 0;
}

require_once dirname(__DIR__) . '/audit_functions.php';

function audit_queue_assert($condition, $message) {
	if (!$condition) {
		fwrite(STDERR, $message . PHP_EOL);
		exit(1);
	}
}

audit_enqueue_syslog_event(42);
audit_queue_assert(count($audit_queue_calls) === 1, 'Finalization must enqueue one Syslog delivery row.');
audit_queue_assert(strpos($audit_queue_calls[0]['sql'], 'INSERT IGNORE INTO audit_syslog_delivery') !== false,
	'Queue insertion must be idempotent for one event and destination.');
audit_queue_assert($audit_queue_calls[0]['params'][0] === 42, 'Queue insertion must retain the audit event ID.');
audit_queue_assert($audit_queue_calls[0]['params'][1] === '32e0a97d-d9e8-4abc-8f41-2bbbc50793ca',
	'Queue insertion must retain the stable event UUID.');
audit_queue_assert($audit_queue_calls[0]['params'][3] === 'queue-test-node',
	'Queue insertion must snapshot the stable node identity.');
audit_queue_assert($audit_queue_calls[0]['params'][5] === 'pending',
	'A valid enabled destination must enqueue in pending state.');

$config = audit_syslog_config();
$retry_identity = audit_syslog_delivery_config($config, array(
	'delivery_node_id' => 'original-node',
	'delivery_poller_id' => '3'
));
audit_queue_assert($retry_identity['node_id'] === 'original-node' && $retry_identity['poller_id'] === '3',
	'Retries must use the node and poller identity captured when the event was queued.');

audit_queue_assert(audit_syslog_retry_delay(1, $config) === 5, 'The first retry must use the base delay.');
audit_queue_assert(audit_syslog_retry_delay(2, $config) === 10, 'Retry delay must increase exponentially.');
audit_queue_assert(audit_syslog_retry_delay(10, $config) === 60, 'Retry delay must be capped by the configured maximum.');

$audit_queue_calls = array();
$delivery = array('delivery_id' => 9, 'attempts' => 0);
$failure = array(
	'status' => 'failed',
	'permanent' => false,
	'error_code' => 'connection_failed',
	'error' => "receiver unavailable\nwith control text"
);
audit_syslog_update_delivery($delivery, $failure, $config);
audit_queue_assert($audit_queue_calls[0]['params'][0] === 'retry',
	'A transient failure before maximum attempts must enter retry state.');
audit_queue_assert($audit_queue_calls[0]['params'][2] === 1, 'A failed delivery must increment attempts.');
audit_queue_assert($audit_queue_calls[0]['params'][3] === 5 && $audit_queue_calls[0]['params'][4] === 5,
	'A transient failure must schedule the bounded exponential delay.');
audit_queue_assert(strpos($audit_queue_calls[0]['params'][5], "\n") === false,
	'Stored delivery errors must be bounded to one safe line.');

$audit_queue_calls = array();
$delivery['attempts'] = 4;
audit_syslog_update_delivery($delivery, $failure, $config);
audit_queue_assert($audit_queue_calls[0]['params'][0] === 'dead_letter',
	'The configured final failed attempt must enter dead-letter state.');

$audit_queue_calls = array();
$permanent = $failure;
$permanent['permanent'] = true;
$permanent['error_code'] = 'udp_message_too_large';
$delivery['attempts'] = 0;
audit_syslog_update_delivery($delivery, $permanent, $config);
audit_queue_assert($audit_queue_calls[0]['params'][0] === 'dead_letter',
	'A permanent formatting failure must enter dead-letter immediately.');

$audit_queue_calls = array();
$success = array('status' => 'sent_unconfirmed', 'error_code' => '', 'error' => '', 'permanent' => false);
audit_syslog_update_delivery($delivery, $success, $config);
audit_queue_assert(strpos($audit_queue_calls[0]['sql'], "state = 'sent_unconfirmed'") !== false,
	'A complete socket write must enter sent_unconfirmed state.');

$audit_queue_calls = array();
$audit_queue_affected_rows = 2;
$retried = audit_syslog_retry_dead_letters(array('2', 2, 0, -1, '7'));
audit_queue_assert($retried === 2, 'Manual retry must report the affected row count.');
audit_queue_assert($audit_queue_calls[0]['params'] === array(2, 7),
	'Manual retry must accept only unique positive selected delivery IDs.');
audit_queue_assert(strpos($audit_queue_calls[0]['sql'], "WHERE state = 'dead_letter'") !== false,
	'Manual retry must never reset a non-dead-letter delivery.');

$syslog_source = file_get_contents(dirname(__DIR__) . '/audit_syslog.php');
audit_queue_assert(
	strpos($syslog_source, "\$result['status'] !== 'sent_unconfirmed' && empty(\$result['permanent'])") !== false,
	'Poller batches must stop after one transient receiver failure to bound outage latency.'
);

print "Syslog queue tests passed.\n";
