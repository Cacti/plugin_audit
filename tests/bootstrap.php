<?php

if (!function_exists('get_client_addr')) {
    function get_client_addr(): string {
        return '127.0.0.1';
    }
}

if (!function_exists('isset_request_var')) {
    function isset_request_var(string $name): bool {
        return isset($_REQUEST[$name]);
    }
}

if (!function_exists('get_nfilter_request_var')) {
    function get_nfilter_request_var(string $name): string {
        return isset($_REQUEST[$name]) ? $_REQUEST[$name] : '';
    }
}

require_once __DIR__ . '/../audit_functions.php';
