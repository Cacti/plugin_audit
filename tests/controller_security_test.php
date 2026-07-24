<?php

$controller = file_get_contents(dirname(__DIR__) . '/audit.php');
$javascript = file_get_contents(dirname(__DIR__) . '/js/functions.js');

$required_controller_guards = array(
	"\$_SERVER['REQUEST_METHOD'] !== 'POST'",
	"api_plugin_user_realm_auth('audit_manage.php')",
	'csrf_check(false)',
	'html_escape($data',
	"header('Content-Type: text/csv; charset=UTF-8')",
	"fputcsv("
);

foreach ($required_controller_guards as $guard) {
	if (strpos($controller, $guard) === false) {
		fwrite(STDERR, 'Missing controller security guard: ' . $guard . PHP_EOL);
		exit(1);
	}
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
