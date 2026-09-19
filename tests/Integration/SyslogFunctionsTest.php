<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Integration coverage for the audit_syslog_* transport layer: RFC 5424,
 * CEF, and JSON formatting, RFC 6587 octet-count framing, and real
 * socket-level delivery over UDP, TCP, and TLS (including partial writes,
 * write timeouts, and untrusted-certificate rejection).
 *
 * This exercises real sockets/forked child processes and OpenSSL
 * certificates rather than mocked I/O, so the entire scenario runs inside
 * a single test to preserve the original sequential/stateful behavior
 * (later steps reuse $event/$config/$formatted from earlier steps) instead
 * of being split into independent, order-dependent cases.
 *
 * POLLER_ID is defined by tests/bootstrap-unit.php (as 1) before this file
 * loads, so that value - not a locally redefined one - is what appears in
 * formatted records below.
 */

require_once dirname(__DIR__, 2) . '/audit_functions.php';

/**
 * @param array $overrides
 *
 * @return array
 */
function audit_syslog_test_config($overrides = []) {
	$values = [
		'receiver'            => '127.0.0.1',
		'port'                => '514',
		'transport'           => 'udp',
		'format'              => 'json',
		'facility'            => 'local0',
		'application'         => 'cacti-audit',
		'node_id'             => 'cacti-node-1',
		'timeout'             => '1',
		'udp_max_size'        => '8192',
		'retry_base'          => '5',
		'retry_max'           => '60',
		'max_attempts'        => '5',
		'batch_size'          => '10',
		'pending_age_warning' => '900',
		'dead_letter_warning' => '1',
		'tls_ca_file'         => '',
		'tls_client_cert'     => '',
		'tls_client_key'      => '',
	];

	return audit_syslog_config(array_merge($values, $overrides));
}

/**
 * @return array
 */
function audit_syslog_test_event() {
	return [
		'id'                => 42,
		'event_uuid'        => '32e0a97d-d9e8-4abc-8f41-2bbbc50793ca',
		'correlation_id'    => '48f486c3-90d0-45a2-a50d-3b31e571aa91',
		'event_type'        => 'cacti.user_admin.save',
		'event_category'    => 'identity_access',
		'severity'          => 'info',
		'actor_type'        => 'user',
		'page'              => 'user_admin.php',
		'user_id'           => 1,
		'action'            => 'save',
		'request_status'    => 'completed',
		'operation_outcome' => 'success',
		'target_type'       => 'user',
		'target_id'         => '4',
		'ip_address'        => '192.0.2.10',
		'event_time'        => '2026-07-24 15:16:17.123456',
		'post'              => '{"id":4,"description":"new value","password":"must-not-leak"}',
		'object_data'       => '[{"id":4,"description":"old value"}]',
		'details'           => '{"test":true}',
		'integrity_hash'    => str_repeat('a', 64),
	];
}

/**
 * @param int   $port
 * @param mixed $error
 * @param mixed $error_message
 *
 * @return resource|false
 */
function audit_syslog_test_udp_server(&$port, &$error, &$error_message) {
	for ($attempt = 0; $attempt < 20; $attempt++) {
		$port   = random_int(20000, 50000);
		$server = @stream_socket_server(
			'udp://127.0.0.1:' . $port,
			$error,
			$error_message,
			STREAM_SERVER_BIND
		);

		if (is_resource($server)) {
			return $server;
		}
	}

	return false;
}

/**
 * @return array|false
 */
function audit_syslog_test_tls_material() {
	$directory = sys_get_temp_dir() . '/audit-syslog-' . bin2hex(random_bytes(8));

	if (!mkdir($directory, 0700)) {
		return false;
	}

	$config_path = $directory . '/openssl.cnf';
	$config_text = "[req]\n" .
		"distinguished_name=req_dn\n" .
		"req_extensions=v3_req\n" .
		"prompt=no\n" .
		"[req_dn]\n" .
		"CN=127.0.0.1\n" .
		"[v3_req]\n" .
		"subjectAltName=IP:127.0.0.1\n" .
		"keyUsage=digitalSignature,keyEncipherment\n" .
		"extendedKeyUsage=serverAuth\n";
	file_put_contents($config_path, $config_text);

	$options = [
		'config'           => $config_path,
		'digest_alg'       => 'sha256',
		'private_key_bits' => 2048,
		'private_key_type' => OPENSSL_KEYTYPE_RSA,
		'req_extensions'   => 'v3_req',
		'x509_extensions'  => 'v3_req',
	];
	$key = openssl_pkey_new($options);

	if ($key === false) {
		return false;
	}

	$csr = openssl_csr_new(['commonName' => '127.0.0.1'], $key, $options);

	if (!($csr instanceof OpenSSLCertificateSigningRequest)) {
		return false;
	}

	$certificate = openssl_csr_sign($csr, null, $key, 1, $options);

	if ($certificate === false ||
		!openssl_x509_export($certificate, $certificate_pem) ||
		!openssl_pkey_export($key, $key_pem, null, $options)) {
		return false;
	}

	$ca_path     = $directory . '/ca.pem';
	$server_path = $directory . '/server.pem';
	$result_path = $directory . '/received.log';
	file_put_contents($ca_path, $certificate_pem);
	file_put_contents($server_path, $certificate_pem . $key_pem);
	chmod($server_path, 0600);

	return [
		'directory' => $directory,
		'config'    => $config_path,
		'ca'        => $ca_path,
		'server'    => $server_path,
		'result'    => $result_path,
	];
}

/**
 * @param array $material
 * @param int   $port
 *
 * @return resource|false
 */
function audit_syslog_test_tls_server($material, &$port) {
	$context = stream_context_create([
		'ssl' => [
			'local_cert'        => $material['server'],
			'verify_peer'       => false,
			'allow_self_signed' => true,
		],
	]);
	$error         = 0;
	$error_message = '';
	$server        = stream_socket_server(
		'tls://127.0.0.1:0',
		$error,
		$error_message,
		STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
		$context
	);

	if (!is_resource($server)) {
		return false;
	}

	$name = stream_socket_get_name($server, false);

	if ($name === false) {
		return false;
	}

	$port = (int) substr($name, strrpos($name, ':') + 1);

	return $server;
}

/**
 * @param array $material
 *
 * @return void
 */
function audit_syslog_test_remove_tls_material($material) {
	foreach (['result', 'server', 'ca', 'config'] as $name) {
		if (is_file($material[$name])) {
			unlink($material[$name]);
		}
	}

	rmdir($material['directory']);
}

it('covers Syslog configuration, RFC 5424/CEF/JSON formatting, framing, and UDP/TCP/TLS transport delivery', function () {
	$config = audit_syslog_test_config();
	expect($config['valid'])->toBeTrue('A valid Syslog configuration must be accepted.');
	expect($config['tls_verify_peer'])->toBeTrue('TLS peer verification must always be enabled.');
	expect($config['tls_verify_peer_name'])->toBeTrue('TLS hostname verification must always be enabled.');
	expect(audit_syslog_test_config(['transport' => 'udp', 'port' => ''])['port'])->toBe(514, 'A blank UDP port must use the standard default of 514.');
	expect(audit_syslog_test_config(['transport' => 'tls', 'port' => ''])['port'])->toBe(6514, 'A blank TLS port must use the standard default of 6514.');

	$outer_warning_called = false;
	$captured_warning     = '';
	set_error_handler(function () use (&$outer_warning_called) {
		$outer_warning_called = true;

		return true;
	});
	$warning_result = audit_syslog_stream_operation(function () {
		trigger_error("expected stream warning\nwith control text", E_USER_WARNING);

		return false;
	}, $captured_warning);
	restore_error_handler();
	expect($warning_result === false && !$outer_warning_called)->toBeTrue('Expected stream warnings must not leak into Cacti global error handling.');
	expect($captured_warning)->toBe('expected stream warning with control text', 'Captured stream warnings must be normalized into a bounded one-line delivery error.');

	$invalid = audit_syslog_test_config(['receiver' => 'udp://user:secret@example.test']);
	expect($invalid['valid'])->toBeFalse('Receiver URIs and embedded credentials must be rejected.');

	$event     = audit_syslog_test_event();
	$formatted = audit_syslog_record($event, $config);
	expect($formatted['status'])->toBe('ready', 'A valid event must produce a Syslog record.');
	expect(strpos($formatted['record'], '<134>1 2026-07-24T15:16:17.123456Z cacti-node-1 cacti-audit 1 cacti.user_admin.save ') === 0)
		->toBeTrue('RFC 5424 headers must contain the calculated priority, UTC timestamp, node, app, poller, and message ID.');
	expect($formatted['record'])->toContain('eventUuid="32e0a97d-d9e8-4abc-8f41-2bbbc50793ca"');
	expect($formatted['record'])->toContain('[cactiAudit@23925 ');
	expect($formatted['record'])->toContain('"node_id":"cacti-node-1"');

	$frame = audit_syslog_frame($formatted['record'], 'tcp');
	expect($frame)->toBe(strlen($formatted['record']) . ' ' . $formatted['record'], 'TCP and TLS must use RFC 6587 octet-count framing.');
	expect(audit_syslog_frame($formatted['record'], 'udp'))->toBe($formatted['record'], 'UDP must send one unframed RFC 5424 record per datagram.');

	$cef_config = audit_syslog_test_config(['format' => 'cef']);
	$cef        = audit_syslog_record($event, $cef_config);
	expect($cef['record'])->toContain('CEF:0|Cacti|Audit Plugin|1.5|cacti.user_admin.save|save|3|');
	expect($cef['record'])->toContain('externalId=32e0a97d-d9e8-4abc-8f41-2bbbc50793ca');
	expect($cef['record'])->toContain('cs4Label=Submitted Data cs4={"id":4,"description":"new value","password":"[REDACTED]"}');
	expect($cef['record'])->toContain('cs5Label=Object Data cs5=[{"id":4,"description":"old value"}]');
	expect($cef['record'])->toContain('cs6Label=Details cs6={"test":true}');
	expect($cef['record'])->not->toContain('must-not-leak');

	$rfc_config = audit_syslog_test_config(['format' => 'rfc5424']);
	$rfc        = audit_syslog_record($event, $rfc_config);
	expect($rfc['record'])->toContain('Audit event 32e0a97d-d9e8-4abc-8f41-2bbbc50793ca');

	$escaped_event              = $event;
	$escaped_event['target_id'] = "value\\\"]\nnext";
	$escaped                    = audit_syslog_record($escaped_event, $config);
	expect($escaped['record'])->toContain('targetId="value\\\\\\"\\] next"');

	$small_udp              = audit_syslog_test_config(['udp_max_size' => '512']);
	$large_event            = $event;
	$large_event['details'] = audit_json_encode(['value' => str_repeat('x', 1024)]);
	$oversized              = audit_syslog_record($large_event, $small_udp);
	expect($oversized['error_code'] === 'udp_message_too_large' && $oversized['permanent'])
		->toBeTrue('Oversized UDP events must fail permanently without truncation or splitting.');

	$again = audit_syslog_record($event, $config);
	expect($again['record'])->toBe($formatted['record'], 'Repeated formatting of one event must preserve receiver deduplication identity.');

	$udp_error         = 0;
	$udp_error_message = '';
	$udp_port          = 0;
	$udp_server        = audit_syslog_test_udp_server($udp_port, $udp_error, $udp_error_message);
	expect(is_resource($udp_server))->toBeTrue('The UDP integration-test receiver must start.');
	$udp_config = audit_syslog_test_config(['port' => (string) $udp_port]);
	$udp_socket = null;
	$udp_result = audit_syslog_send_event($event, $udp_config, $udp_socket);
	expect($udp_result['status'])->toBe('sent_unconfirmed', 'A complete UDP socket write must be recorded as sent_unconfirmed.');
	stream_set_timeout($udp_server, 1);
	$udp_received = fread($udp_server, 65535);
	expect($udp_received)->toBe(audit_syslog_record($event, $udp_config)['record'], 'UDP transport must deliver exactly one complete untruncated record.');

	if (is_resource($udp_socket)) {
		fclose($udp_socket);
	}
	fclose($udp_server);

	$tcp_error         = 0;
	$tcp_error_message = '';
	$tcp_server        = stream_socket_server('tcp://127.0.0.1:0', $tcp_error, $tcp_error_message);
	expect(is_resource($tcp_server))->toBeTrue('The TCP integration-test receiver must start.');
	$tcp_name   = stream_socket_get_name($tcp_server, false);
	$tcp_port   = (int) substr($tcp_name, strrpos($tcp_name, ':') + 1);
	$tcp_config = audit_syslog_test_config(['transport' => 'tcp', 'port' => (string) $tcp_port]);
	$tcp_socket = null;
	$tcp_result = audit_syslog_send_event($event, $tcp_config, $tcp_socket);
	expect($tcp_result['status'])->toBe('sent_unconfirmed', 'A complete TCP socket write must be recorded as sent_unconfirmed.');
	$tcp_peer = stream_socket_accept($tcp_server, 1);
	expect(is_resource($tcp_peer))->toBeTrue('The TCP integration-test receiver must accept the connection.');
	stream_set_timeout($tcp_peer, 1);
	$tcp_received = fread($tcp_peer, 262144);
	$expected_tcp = audit_syslog_frame(audit_syslog_record($event, $tcp_config)['record'], 'tcp');
	expect($tcp_received)->toBe($expected_tcp, 'TCP transport must deliver one complete RFC 6587 octet-counted record.');
	fclose($tcp_peer);

	if (is_resource($tcp_socket)) {
		fclose($tcp_socket);
	}
	fclose($tcp_server);

	if (function_exists('stream_socket_pair') && function_exists('pcntl_fork') &&
		extension_loaded('sockets') && function_exists('socket_import_stream')) {
		$pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
		expect(is_array($pair))->toBeTrue('The partial-write test must create a local stream pair.');
		$native_socket = socket_import_stream($pair[0]);
		socket_set_option($native_socket, SOL_SOCKET, SO_SNDBUF, 1024);
		stream_set_timeout($pair[0], 2);
		$partial_payload = str_repeat('p', 262144);
		$partial_pid     = pcntl_fork();
		expect($partial_pid >= 0)->toBeTrue('The partial-write test must fork a local reader.');

		if ($partial_pid === 0) {
			fclose($pair[0]);
			$received_length = 0;

			while ($received_length < strlen($partial_payload)) {
				$chunk = fread($pair[1], 8192);

				if ($chunk === false || $chunk === '') {
					break;
				}
				$received_length += strlen($chunk);
			}
			fclose($pair[1]);
			exit($received_length === strlen($partial_payload) ? 0 : 1);
		}

		fclose($pair[1]);
		$partial_result = audit_syslog_write($pair[0], $partial_payload, 'tcp');
		fclose($pair[0]);
		pcntl_waitpid($partial_pid, $partial_status);
		expect($partial_result['status'] === 'sent_unconfirmed' && pcntl_wexitstatus($partial_status) === 0)
			->toBeTrue('TCP writes must loop until a record is complete when the socket accepts partial chunks.');

		$timeout_pair   = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
		$timeout_socket = socket_import_stream($timeout_pair[0]);
		socket_set_option($timeout_socket, SOL_SOCKET, SO_SNDBUF, 1024);
		stream_set_timeout($timeout_pair[0], 0, 100000);
		$timeout_result = audit_syslog_write($timeout_pair[0], str_repeat('t', 4194304), 'tcp');
		expect($timeout_result['status'] === 'failed' && $timeout_result['error_code'] === 'write_failed')
			->toBeTrue('A blocked stream must fail with a bounded write timeout instead of hanging indefinitely.');
		fclose($timeout_pair[0]);
		fclose($timeout_pair[1]);
	}

	if (extension_loaded('openssl') && function_exists('pcntl_fork')) {
		$tls_material = audit_syslog_test_tls_material();
		expect(is_array($tls_material))->toBeTrue('The TLS integration test must create temporary certificate material.');
		$tls_port   = 0;
		$tls_server = audit_syslog_test_tls_server($tls_material, $tls_port);
		expect(is_resource($tls_server))->toBeTrue('The TLS integration-test receiver must start.');
		$tls_pid = pcntl_fork();
		expect($tls_pid >= 0)->toBeTrue('The TLS integration test must fork a local receiver.');

		if ($tls_pid === 0) {
			$tls_peer = @stream_socket_accept($tls_server, 5);

			if (is_resource($tls_peer)) {
				stream_set_timeout($tls_peer, 2);
				$tls_received = fread($tls_peer, 262144);
				file_put_contents($tls_material['result'], $tls_received);
				fclose($tls_peer);
				exit(0);
			}

			exit(1);
		}

		fclose($tls_server);
		$tls_config = audit_syslog_test_config([
			'transport'   => 'tls',
			'port'        => (string) $tls_port,
			'tls_ca_file' => $tls_material['ca'],
		]);
		$tls_socket = null;
		$tls_result = audit_syslog_send_event($event, $tls_config, $tls_socket);

		if (is_resource($tls_socket)) {
			fclose($tls_socket);
		}
		pcntl_waitpid($tls_pid, $tls_status);
		expect($tls_result['status'])->toBe('sent_unconfirmed', 'A verified TLS socket write must be recorded as sent_unconfirmed.');
		expect(pcntl_wexitstatus($tls_status))->toBe(0, 'The verified TLS receiver must accept the connection.');
		$tls_received = is_file($tls_material['result']) ? file_get_contents($tls_material['result']) : '';
		$expected_tls = audit_syslog_frame(audit_syslog_record($event, $tls_config)['record'], 'tls');
		expect($tls_received)->toBe($expected_tls, 'TLS transport must deliver one complete RFC 6587 octet-counted record.');

		$untrusted_port   = 0;
		$untrusted_server = audit_syslog_test_tls_server($tls_material, $untrusted_port);
		expect(is_resource($untrusted_server))->toBeTrue('The untrusted TLS test receiver must start.');
		$untrusted_pid = pcntl_fork();
		expect($untrusted_pid >= 0)->toBeTrue('The untrusted TLS test must fork a local receiver.');

		if ($untrusted_pid === 0) {
			$untrusted_peer = @stream_socket_accept($untrusted_server, 5);

			if (is_resource($untrusted_peer)) {
				fclose($untrusted_peer);
			}
			exit(0);
		}

		fclose($untrusted_server);
		$untrusted_config = audit_syslog_test_config([
			'transport'   => 'tls',
			'port'        => (string) $untrusted_port,
			'tls_ca_file' => '',
		]);
		$untrusted_socket = null;
		$untrusted_result = audit_syslog_send_event($event, $untrusted_config, $untrusted_socket);

		if (is_resource($untrusted_socket)) {
			fclose($untrusted_socket);
		}
		pcntl_waitpid($untrusted_pid, $untrusted_status);
		expect($untrusted_result['status'] === 'failed' && $untrusted_result['error_code'] === 'connection_failed')
			->toBeTrue('TLS delivery must fail when the receiver certificate is not trusted.');

		audit_syslog_test_remove_tls_material($tls_material);
	}

	$outage_error   = 0;
	$outage_message = '';
	$outage_server  = stream_socket_server('tcp://127.0.0.1:0', $outage_error, $outage_message);
	$outage_name    = stream_socket_get_name($outage_server, false);
	$outage_port    = (int) substr($outage_name, strrpos($outage_name, ':') + 1);
	fclose($outage_server);
	$outage_config = audit_syslog_test_config(['transport' => 'tcp', 'port' => (string) $outage_port]);
	$outage_socket = null;
	$outage        = audit_syslog_send_event($event, $outage_config, $outage_socket);
	expect($outage['status'] === 'failed' && $outage['error_code'] === 'connection_failed')
		->toBeTrue('An unavailable receiver must return a bounded transient connection failure.');

	$invalid_tls = audit_syslog_test_config([
		'transport'   => 'tls',
		'port'        => '6514',
		'tls_ca_file' => '/does/not/exist',
	]);
	expect(!$invalid_tls['valid'] && in_array('tls_ca_file_invalid', $invalid_tls['errors'], true))
		->toBeTrue('An invalid TLS trust path must be rejected before a connection is attempted.');
})->group('integration');
