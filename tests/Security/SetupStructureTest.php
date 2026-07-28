<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

// Verify setup.php defines required plugin hooks and info function.

describe('audit setup.php structure', function () {
	$source = file_get_contents(realpath(__DIR__ . '/../../setup.php'));

	it('defines plugin_audit_install function', function () use ($source) {
		expect($source)->toContain('function plugin_audit_install');
	});

	it('defines plugin_audit_version function', function () use ($source) {
		expect($source)->toContain('function plugin_audit_version');
	});

	it('defines plugin_audit_uninstall function', function () use ($source) {
		expect($source)->toContain('function plugin_audit_uninstall');
	});

	it('reads plugin info from INFO file', function () use ($source) {
		expect($source)->toContain('parse_ini_file');
		expect($source)->toContain("'info'");
	});

	it('returns an array when plugin info is missing or malformed', function () use ($source) {
		expect($source)->toContain("\$info['info'] ?? null");
		expect($source)->toContain('is_array($plugin_info) ? $plugin_info : []');
	});

	it('INFO file defines name and version keys', function () {
		$info_file = realpath(__DIR__ . '/../../INFO');
		expect($info_file)->not->toBeFalse('INFO file must exist');

		$info = parse_ini_file($info_file, true);
		expect($info)->not->toBeFalse('INFO file must be valid INI');
		expect($info)->toHaveKey('info');
		expect($info['info'])->toHaveKey('name');
		expect($info['info'])->toHaveKey('version');
	});
});
