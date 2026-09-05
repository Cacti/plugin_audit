<?php

/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
 */

/*
 * PHPStan stubs for the Cacti Audit Plugin.
 *
 * These stubs declare typed signatures for the Cacti core functions,
 * constants, and globals that the plugin calls. They let PHPStan
 * resolve and type-check the plugin without loading the full Cacti
 * framework (which is not present in the plugin repository).
 *
 * Signatures mirror the runtime behaviour documented in the Cacti
 * core source (develop branch). Where a Cacti function returns a
 * union (e.g. array|false), the union is preserved so level 8
 * narrowing is enforced at call sites.
 */

// ----- Cacti constants ------------------------------------------------

/** @var string */
const CACTI_VERSION = '1.2.x';

/** @var string */
const CACTI_PATH_BASE = '';

/** @var int */
const POLLER_ID = 1;

/** @var int */
const MAX_DISPLAY_PAGES = 5;

/** @var int */
const MESSAGE_LEVEL_ERROR = 3;

// ----- Cacti globals --------------------------------------------------

/** @var array<string,mixed> */
global $config;

/** @var string */
global $database_default;

/** @var string */
global $action;

/** @var array<int|string,mixed> */
global $utilities;

/** @var array<int|string,mixed> */
global $menu;

/** @var array<int|string,mixed> */
global $messages;

/** @var array<int|string,string> */
global $audit_retentions;

/** @var array<int|string,mixed> */
global $tabs;

/** @var array<string,mixed> */
global $settings;

/** @var array<int|string,int|string> */
global $item_rows;

// ----- Plugin / Hook API ---------------------------------------------

function api_plugin_register_hook(string $plugin, string $hook, string $function, string $file, int $install = 0): void {
}

function api_plugin_register_realm(string $plugin, array|string $file, array|string $display, int $install = 0): void {
}

function api_plugin_is_enabled(string $plugin): bool {
	return false;
}

function api_plugin_enable_hooks(string $plugin): void {
}

function api_plugin_replicate_config(): void {
}

function api_plugin_user_realm_auth(string $file = ''): bool {
	return false;
}

function auth_augment_roles(string $label, array $files): void {
}

// ----- Database -------------------------------------------------------

function db_execute(string $sql, bool $log = true, mixed $db_conn = false): bool {
	return false;
}

function db_execute_prepared(string $sql, array $params = [], bool $log = true, mixed $db_conn = false, bool $execute_prepared = true): bool {
	return false;
}

/**
 * @return array<int,array<string,mixed>>|false
 */
function db_fetch_assoc(string $sql, bool $log = true, mixed $db_conn = false): array|false {
	return false;
}

/**
 * @return array<int,array<string,mixed>>|false
 */
function db_fetch_assoc_prepared(string $sql, array $params = [], bool $log = true, mixed $db_conn = false): array|false {
	return false;
}

/**
 * @return array<string,mixed>|false
 */
function db_fetch_row(string $sql, bool $log = true, mixed $db_conn = false): array|false {
	return false;
}

/**
 * @return array<string,mixed>|false
 */
function db_fetch_row_prepared(string $sql, array $params = [], bool $log = true, mixed $db_conn = false): array|false {
	return false;
}

function db_fetch_cell(string $sql, string $col_name = '', bool $log = true, mixed $db_conn = false): mixed {
	return false;
}

function db_fetch_cell_prepared(string $sql, array $params = [], string $col_name = '', bool $log = true, mixed $db_conn = false): mixed {
	return false;
}

function db_fetch_insert_id(string $table = ''): int {
	return 0;
}

/** @phpstan-impure */
function db_affected_rows(mixed $db_conn = false): int {
	return 0;
}

function db_column_exists(string $table, string $column, bool $log = true, mixed $db_conn = false): bool {
	return false;
}

function db_table_exists(string $table, bool $log = true, mixed $db_conn = false): bool {
	return false;
}

/** @phpstan-impure */
function db_index_exists(string $table, string $index, bool $log = true, mixed $db_conn = false): bool {
	return false;
}

function db_add_index(string $table, string $type, string $name, mixed $definition, bool $log = true, mixed $db_conn = false): void {
}

// ----- Config / Options ---------------------------------------------

function read_config_option(string $name, bool $global = false): mixed {
	return false;
}

/** @phpstan-impure */
function set_config_option(string $name, string $value): bool {
	return false;
}

// ----- Localization --------------------------------------------------

/**
 * @param mixed ...$args sprintf arguments or domain
 */
function __(string $text, mixed ...$args): string {
	return $text;
}

/**
 * @param mixed ...$args sprintf arguments or domain
 */
function __esc(string $text, mixed ...$args): string {
	return $text;
}

// ----- Input Handling ------------------------------------------------

function get_request_var(string $name, mixed $default = '', string $filter = ''): mixed {
	return $default;
}

function get_filter_request_var(string $name, int $filter = FILTER_DEFAULT, array $options = []): mixed {
	return false;
}

function get_nfilter_request_var(string $name, mixed $default = '', string $filter = ''): mixed {
	return $default;
}

function isset_request_var(string $name): bool {
	return false;
}

function isempty_request_var(string $name): bool {
	return false;
}

function set_default_action(string $default = ''): void {
}

/**
 * @param array<string,mixed> $filters
 */
function validate_store_request_vars(array $filters, string $sess_prefix = ''): void {
}

function sanitize_search_string(mixed $string): string {
	return '';
}

function html_escape_request_var(string $name): string {
}

// ----- Logging / Misc ------------------------------------------------

/** @phpstan-impure */
function cacti_log(string $string, bool $output = false, string $environment = '', int $level = 1, bool $force = false): bool {
	return false;
}

function cacti_sizeof(mixed $array): int {
	return is_array($array) ? count($array) : 0;
}

function get_client_addr(): string {
	return '';
}

function get_username(int $user_id): string {
	return '';
}

function raise_message(string $id, string $message = '', int $level = 0): void {
}

function csrf_check(bool $force = false): bool {
	return false;
}

// ----- UI / HTML Helpers ---------------------------------------------

function top_header(): void {
}

function bottom_footer(): void {
}

function html_start_box(string $title, string $width, string $align = '', string $add = '', string $collapsible = '', string $url = ''): void {
}

function html_end_box(bool $trailing_br = true): void {
}

/**
 * @param array<int|string,mixed> ...$args
 */
function html_nav_bar(string $base_url, int $max_pages, int $current_page, int $rows_per_page, int $total_rows, int $pages_to_display, string $title, string $page_var = 'page', string $class = 'main'): string {
	return '';
}

/**
 * @param array<string,string|array<string,string>> $display_text
 */
function html_header_sort(array $display_text, string $sort_column, string $sort_direction, bool $last_column = false): void {
}

function html_escape(mixed $string): string {
	return '';
}

function form_alternate_row(string $id, bool $light = false): void {
}

function form_selectable_cell(string $text, int $id, string $class = '', string $title = ''): void {
}

function form_selectable_ecell(string $text, int $id, string $class = '', string $title = ''): void {
}

function form_end_row(): void {
}

function filter_value(string $text, string $filter): string {
	return '';
}

function get_order_string(): string {
	return '';
}

/**
 * @param array<int,array<string,mixed>>|false $array
 */
function array_rekey(array|false $array, string $key, string $key_value): array {
	return [];
}
