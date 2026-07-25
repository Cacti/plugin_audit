<?php

$controller = file_get_contents(dirname(__DIR__) . '/audit.php');
$functions  = file_get_contents(dirname(__DIR__) . '/audit_functions.php');
$javascript = file_get_contents(dirname(__DIR__) . '/js/functions.js');
$setup      = file_get_contents(dirname(__DIR__) . '/setup.php');

$required_controller_guards = array(
	"\$_SERVER['REQUEST_METHOD'] !== 'POST'",
	'audit_user_is_admin()',
	'csrf_check(false)',
	'html_escape($data',
	"__('Outcome Reason:', 'audit')",
	"header('Content-Type: text/csv; charset=UTF-8')",
	"fputcsv("
);

foreach ($required_controller_guards as $guard) {
	if (strpos($controller, $guard) === false) {
		fwrite(STDERR, 'Missing controller security guard: ' . $guard . PHP_EOL);
		exit(1);
	}
}

$required_schema_fragments = array(
	"'audit.php'        => __('Audit Log User'",
	"'audit_manage.php' => __('Audit Log Admin'",
	'audit_setup_realms(true)',
	'audit_setup_realms()',
	'audit_remove_deprecated_realms()',
	"auth_augment_roles(__('Audit Plugin', 'audit'), array('audit.php', 'audit_manage.php'))",
	'api_plugin_register_hook(\'audit\', \'replicate_out\'',
	'request_status',
	'ADD COLUMN IF NOT EXISTS external_status',
	'ADD COLUMN IF NOT EXISTS external_error',
	'SHOW CREATE TABLE $table',
	'audit_retry_external_logs()',
	'logout_pre_session_destroy',
	'event_uuid char(36)',
	'operation_outcome',
	'external_attempts'
);

foreach ($required_schema_fragments as $fragment) {
	if (strpos($setup, $fragment) === false) {
		fwrite(STDERR, 'Missing schema or replication requirement: ' . $fragment . PHP_EOL);
		exit(1);
	}
}

$required_verifier_fragments = array(
	'audit_operation_verifier_for_request',
	"'user_realm_permissions'",
	"'realm_permissions_verified'",
	"register_shutdown_function('audit_finalize_request', \$audit_id, \$started_at, \$verifier)"
);

foreach ($required_verifier_fragments as $fragment) {
	if (strpos($functions, $fragment) === false) {
		fwrite(STDERR, 'Missing operation verification requirement: ' . $fragment . PHP_EOL);
		exit(1);
	}
}

if (strpos($functions, "api_plugin_user_realm_auth('audit_manage.php')") === false) {
	fwrite(STDERR, 'Audit administrators must be authorized to purge.' . PHP_EOL);
	exit(1);
}

if (strpos($functions, "api_plugin_user_realm_auth('audit_purge.php')") !== false) {
	fwrite(STDERR, 'The deprecated delegated purge permission must not authorize purge.' . PHP_EOL);
	exit(1);
}

if (substr_count($controller, 'audit_user_is_admin()') < 2) {
	fwrite(STDERR, 'Purge authorization must protect both the action and its UI control.' . PHP_EOL);
	exit(1);
}

if (strpos($javascript, "loadPageNoHeader('audit.php?action=purge") !== false) {
	fwrite(STDERR, 'Purge must not use the legacy GET request path.' . PHP_EOL);
	exit(1);
}

if (strpos($javascript, "loadPageUsingPost('audit.php?action=purge") === false) {
	fwrite(STDERR, 'Purge must use the POST request path.' . PHP_EOL);
	exit(1);
}

print "Controller security checks passed.\n";
