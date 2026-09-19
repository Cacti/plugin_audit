<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Behavioral coverage for the audit_* Syslog delivery queue in
 * audit_functions.php/audit_syslog.php: enqueueing a delivery row for a
 * finalized event, retry-identity/backoff calculation, failed-delivery
 * state transitions (retry, dead-letter, sent), manual dead-letter retry,
 * and the poller's stop-after-one-transient-failure batching guard.
 *
 * db_*, read_config_option(), and db_affected_rows() calls are resolved
 * through the fixture helpers declared in tests/bootstrap-unit.php instead
 * of redeclaring those globals, since bootstrap-unit.php already provides
 * guarded stubs for them.
 */

require_once dirname(__DIR__, 2) . '/audit_functions.php';

$audit_queue_settings = [
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
	'audit_syslog_tls_client_key'      => '',
];

beforeEach(function () use ($audit_queue_settings) {
	foreach ($audit_queue_settings as $name => $value) {
		audit_test_set_config_option($name, $value);
	}

	audit_test_mock_db('db_table_exists', '', function ($table) {
		return $table === 'audit_syslog_delivery';
	});

	audit_test_mock_db('db_fetch_row_prepared', '', function ($sql, $params) {
		return [
			'id'             => (int) $params[0],
			'event_uuid'     => '32e0a97d-d9e8-4abc-8f41-2bbbc50793ca',
			'request_status' => 'completed',
		];
	});
});

/**
 * Registers db_execute_prepared/db_execute fixtures that append every call
 * to $calls, mirroring the original script-level $audit_queue_calls log.
 *
 * @param array $calls Reference to the array calls should be appended to.
 *
 * @return void
 */
function audit_queue_test_track_calls(array &$calls): void {
	audit_test_mock_db('db_execute_prepared', '', function ($sql, $params) use (&$calls) {
		$calls[] = ['sql' => $sql, 'params' => $params];

		return true;
	});

	audit_test_mock_db('db_execute', '', function ($sql, $params) use (&$calls) {
		$calls[] = ['sql' => $sql, 'params' => []];

		return true;
	});
}

it('enqueues a Syslog delivery row with the event, uuid, node identity, and pending state', function () {
	$calls = [];
	audit_queue_test_track_calls($calls);

	audit_enqueue_syslog_event(42);

	expect($calls)->toHaveCount(1, 'Finalization must enqueue one Syslog delivery row.');
	expect($calls[0]['sql'])->toContain('INSERT IGNORE INTO audit_syslog_delivery');
	expect($calls[0]['params'][0])->toBe(42, 'Queue insertion must retain the audit event ID.');
	expect($calls[0]['params'][1])->toBe('32e0a97d-d9e8-4abc-8f41-2bbbc50793ca', 'Queue insertion must retain the stable event UUID.');
	expect($calls[0]['params'][3])->toBe('queue-test-node', 'Queue insertion must snapshot the stable node identity.');
	expect($calls[0]['params'][5])->toBe('pending', 'A valid enabled destination must enqueue in pending state.');
});

it('captures the retry node/poller identity and computes bounded exponential retry delay', function () {
	$config         = audit_syslog_config();
	$retry_identity = audit_syslog_delivery_config($config, [
		'delivery_node_id'   => 'original-node',
		'delivery_poller_id' => '3',
	]);

	expect($retry_identity['node_id'] === 'original-node' && $retry_identity['poller_id'] === '3')
		->toBeTrue('Retries must use the node and poller identity captured when the event was queued.');

	expect(audit_syslog_retry_delay(1, $config))->toBe(5, 'The first retry must use the base delay.');
	expect(audit_syslog_retry_delay(2, $config))->toBe(10, 'Retry delay must increase exponentially.');
	expect(audit_syslog_retry_delay(10, $config))->toBe(60, 'Retry delay must be capped by the configured maximum.');
});

it('transitions failed deliveries between retry, dead-letter, and sent states', function () {
	$config  = audit_syslog_config();
	$failure = [
		'status'     => 'failed',
		'permanent'  => false,
		'error_code' => 'connection_failed',
		'error'      => "receiver unavailable\nwith control text",
	];

	$calls    = [];
	$delivery = ['delivery_id' => 9, 'attempts' => 0];
	audit_queue_test_track_calls($calls);
	audit_syslog_update_delivery($delivery, $failure, $config);
	expect($calls[0]['params'][0])->toBe('retry', 'A transient failure before maximum attempts must enter retry state.');
	expect($calls[0]['params'][2])->toBe(1, 'A failed delivery must increment attempts.');
	expect($calls[0]['params'][3] === 5 && $calls[0]['params'][4] === 5)->toBeTrue('A transient failure must schedule the bounded exponential delay.');
	expect($calls[0]['params'][5])->not->toContain("\n");

	$calls                = [];
	$delivery['attempts'] = 4;
	audit_queue_test_track_calls($calls);
	audit_syslog_update_delivery($delivery, $failure, $config);
	expect($calls[0]['params'][0])->toBe('dead_letter', 'The configured final failed attempt must enter dead-letter state.');

	$calls                   = [];
	$permanent               = $failure;
	$permanent['permanent']  = true;
	$permanent['error_code'] = 'udp_message_too_large';
	$delivery['attempts']    = 0;
	audit_queue_test_track_calls($calls);
	audit_syslog_update_delivery($delivery, $permanent, $config);
	expect($calls[0]['params'][0])->toBe('dead_letter', 'A permanent formatting failure must enter dead-letter immediately.');

	$calls   = [];
	$success = ['status' => 'sent_unconfirmed', 'error_code' => '', 'error' => '', 'permanent' => false];
	audit_queue_test_track_calls($calls);
	audit_syslog_update_delivery($delivery, $success, $config);
	expect($calls[0]['sql'])->toContain("state = 'sent_unconfirmed'");
});

it('manually retries de-duplicated positive dead-letter delivery IDs and reports the affected row count', function () {
	$calls = [];
	audit_queue_test_track_calls($calls);
	audit_test_set_affected_rows(2);

	$retried = audit_syslog_retry_dead_letters(['2', 2, 0, -1, '7']);

	expect($retried)->toBe(2, 'Manual retry must report the affected row count.');
	expect($calls[0]['params'])->toBe([2, 7], 'Manual retry must accept only unique positive selected delivery IDs.');
	expect($calls[0]['sql'])->toContain("WHERE state = 'dead_letter'");
});

it('stops poller batches after one transient receiver failure to bound outage latency', function () {
	$syslog_source = plugin_test_read_source('audit_syslog.php');

	expect($syslog_source)->toContain(
		"\$result['status'] !== 'sent_unconfirmed' && empty(\$result['permanent'])"
	);
});
