<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the Syslog delivery queue in audit_functions.php:
 * enqueueing, retry identity, exponential backoff, and dead-letter
 * transitions for the audit_syslog_delivery table.
 */

beforeAll(function () {
	require_once dirname(__DIR__, 2) . '/audit_functions.php';
});

/**
 * @return array<string,string>
 */
function audit_syslog_queue_test_settings() {
	return array(
		'audit_syslog_enabled'             => 'on',
		'audit_syslog_receiver'            => '127.0.0.1',
		'audit_syslog_port'                => '514',
		'audit_syslog_transport'           => 'udp',
		'audit_syslog_format'              => 'json',
		'audit_syslog_facility'            => 'local0',
		'audit_syslog_application'         => 'cacti-audit',
		'audit_syslog_node_id'             => 'queue-test-node',
		'audit_syslog_timeout'             => '5',
		'audit_syslog_udp_max_size'        => '8192',
		'audit_syslog_retry_base'          => '5',
		'audit_syslog_retry_max'           => '60',
		'audit_syslog_max_attempts'        => '5',
		'audit_syslog_batch_size'          => '10',
		'audit_syslog_pending_age_warning' => '900',
		'audit_syslog_dead_letter_warning' => '1',
		'audit_syslog_tls_ca_file'         => '',
		'audit_syslog_tls_client_cert'     => '',
		'audit_syslog_tls_client_key'      => ''
	);
}

beforeEach(function () {
	$settings = audit_syslog_queue_test_settings();

	$GLOBALS['__test_read_config_option'] = function ($name) use ($settings) {
		return $settings[$name] ?? '';
	};
	$GLOBALS['__test_db_table_exists'] = function ($table) {
		return $table === 'audit_syslog_delivery';
	};
	$GLOBALS['__test_db_fetch_row_prepared'] = function ($sql, $params) {
		return array(
			'id'             => (int) $params[0],
			'event_uuid'     => '32e0a97d-d9e8-4abc-8f41-2bbbc50793ca',
			'request_status' => 'completed'
		);
	};
	$GLOBALS['__test_db_affected_rows'] = function () {
		return 0;
	};
	$GLOBALS['__test_db_calls'] = array();
});

it('enqueues one idempotent Syslog delivery row and retains event identity', function () {
	audit_enqueue_syslog_event(42);

	$calls = $GLOBALS['__test_db_calls'];
	expect($calls)->toHaveCount(1, 'Finalization must enqueue one Syslog delivery row.');
	expect($calls[0]['sql'])->toContain('INSERT IGNORE INTO audit_syslog_delivery');
	expect($calls[0]['params'][0])->toBe(42, 'Queue insertion must retain the audit event ID.');
	expect($calls[0]['params'][1])->toBe('32e0a97d-d9e8-4abc-8f41-2bbbc50793ca',
		'Queue insertion must retain the stable event UUID.');
	expect($calls[0]['params'][3])->toBe('queue-test-node',
		'Queue insertion must snapshot the stable node identity.');
	expect($calls[0]['params'][5])->toBe('pending',
		'A valid enabled destination must enqueue in pending state.');
});

it('retains the node and poller identity captured when the event was queued', function () {
	$config         = audit_syslog_config();
	$retry_identity = audit_syslog_delivery_config($config, array(
		'delivery_node_id'   => 'original-node',
		'delivery_poller_id' => '3'
	));

	expect($retry_identity['node_id'])->toBe('original-node');
	expect($retry_identity['poller_id'])->toBe('3',
		'Retries must use the node and poller identity captured when the event was queued.');
});

it('increases retry delay exponentially up to the configured maximum', function () {
	$config = audit_syslog_config();

	expect(audit_syslog_retry_delay(1, $config))->toBe(5, 'The first retry must use the base delay.');
	expect(audit_syslog_retry_delay(2, $config))->toBe(10, 'Retry delay must increase exponentially.');
	expect(audit_syslog_retry_delay(10, $config))->toBe(60, 'Retry delay must be capped by the configured maximum.');
});

it('enters retry state on a transient failure before the maximum attempts', function () {
	$config = audit_syslog_config();

	$delivery = array('delivery_id' => 9, 'attempts' => 0);
	$failure  = array(
		'status'     => 'failed',
		'permanent'  => false,
		'error_code' => 'connection_failed',
		'error'      => "receiver unavailable\nwith control text"
	);

	audit_syslog_update_delivery($delivery, $failure, $config);
	$calls = $GLOBALS['__test_db_calls'];

	expect($calls[0]['params'][0])->toBe('retry', 'A transient failure before maximum attempts must enter retry state.');
	expect($calls[0]['params'][2])->toBe(1, 'A failed delivery must increment attempts.');
	expect($calls[0]['params'][3])->toBe(5, 'A transient failure must schedule the bounded exponential delay.');
	expect($calls[0]['params'][4])->toBe(5, 'A transient failure must schedule the bounded exponential delay.');
	expect(strpos($calls[0]['params'][5], "\n"))->toBeFalse('Stored delivery errors must be bounded to one safe line.');
});

it('enters dead-letter state at the configured final failed attempt', function () {
	$config = audit_syslog_config();

	$delivery = array('delivery_id' => 9, 'attempts' => 4);
	$failure  = array(
		'status'     => 'failed',
		'permanent'  => false,
		'error_code' => 'connection_failed',
		'error'      => 'receiver unavailable'
	);

	audit_syslog_update_delivery($delivery, $failure, $config);
	$calls = $GLOBALS['__test_db_calls'];

	expect($calls[0]['params'][0])->toBe('dead_letter',
		'The configured final failed attempt must enter dead-letter state.');
});

it('enters dead-letter state immediately for a permanent formatting failure', function () {
	$config = audit_syslog_config();

	$delivery  = array('delivery_id' => 9, 'attempts' => 0);
	$permanent = array(
		'status'     => 'failed',
		'permanent'  => true,
		'error_code' => 'udp_message_too_large',
		'error'      => 'message too large'
	);

	audit_syslog_update_delivery($delivery, $permanent, $config);
	$calls = $GLOBALS['__test_db_calls'];

	expect($calls[0]['params'][0])->toBe('dead_letter',
		'A permanent formatting failure must enter dead-letter immediately.');
});

it('enters sent_unconfirmed state on a complete socket write', function () {
	$config = audit_syslog_config();

	$delivery = array('delivery_id' => 9, 'attempts' => 0);
	$success  = array('status' => 'sent_unconfirmed', 'error_code' => '', 'error' => '', 'permanent' => false);

	audit_syslog_update_delivery($delivery, $success, $config);
	$calls = $GLOBALS['__test_db_calls'];

	expect($calls[0]['sql'])->toContain("state = 'sent_unconfirmed'");
});

it('retries only unique positive selected dead-letter deliveries', function () {
	$GLOBALS['__test_db_affected_rows'] = function () {
		return 2;
	};

	$retried = audit_syslog_retry_dead_letters(array('2', 2, 0, -1, '7'));
	$calls   = $GLOBALS['__test_db_calls'];

	expect($retried)->toBe(2, 'Manual retry must report the affected row count.');
	expect($calls[0]['params'])->toBe(array(2, 7),
		'Manual retry must accept only unique positive selected delivery IDs.');
	expect($calls[0]['sql'])->toContain("WHERE state = 'dead_letter'");
});

it('stops a poller batch after one transient receiver failure', function () {
	$syslog_source = plugin_test_read_source('audit_syslog.php');

	expect($syslog_source)->toContain(
		"\$result['status'] !== 'sent_unconfirmed' && empty(\$result['permanent'])"
	);
});
