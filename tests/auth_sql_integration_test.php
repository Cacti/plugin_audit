#!/usr/bin/env php
<?php

/*
 * Runs the production authentication-ingestion SQL through Cacti's real
 * database layer. The CI fixture enables auditing before invoking this file.
 */

require dirname(__DIR__, 3) . '/include/cli_check.php';
require_once dirname(__DIR__) . '/setup.php';

if (!db_execute_prepared("SET SESSION sql_mode = CONCAT_WS(',', @@sql_mode, 'ANSI_QUOTES')")) {
	fwrite(STDERR, "Unable to enable ANSI_QUOTES for the authentication SQL integration test.\n");
	exit(1);
}

$time_type = db_fetch_cell_prepared(
	'SELECT DATA_TYPE
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE()
		AND TABLE_NAME = ?
		AND COLUMN_NAME = ?',
	['user_log', 'time']
);

if (strtolower((string) $time_type) !== 'timestamp') {
	fwrite(STDERR, "Cacti user_log.time must be TIMESTAMP for timezone-stable source identity.\n");
	exit(1);
}

if (!audit_user_log_identity_supported()) {
	fwrite(STDERR, "Cacti user_log primary key does not match the authentication identity contract.\n");
	exit(1);
}

if (!audit_setup_user_log_indexes()) {
	fwrite(STDERR, "Unable to create authentication indexes through the production schema helper.\n");
	exit(1);
}

audit_poll_user_log();

print "Authentication SQL integration test passed.\n";
