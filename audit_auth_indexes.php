#!/usr/bin/env php
<?php

require dirname(__DIR__, 2) . '/include/cli_check.php';
require_once __DIR__ . '/setup.php';

if (!audit_user_log_identity_supported()) {
	fwrite(STDERR, "Unsupported user_log primary key; authentication auditing remains disabled.\n");
	exit(1);
}

if (!audit_setup_user_log_indexes()) {
	fwrite(STDERR, "Unable to create the authentication audit indexes.\n");
	exit(1);
}

print "Authentication audit indexes are ready.\n";
