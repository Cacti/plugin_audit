<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Verify plugin source files use PHP 8.1+ syntax conventions.
 * The audit plugin targets PHP 8.1+ (matching Cacti develop).
 */

describe('PHP 8.1+ syntax in audit', function () {
	$files = [
		'audit.php',
		'audit_functions.php',
		'audit_syslog.php',
		'setup.php',
		'index.php',
	];

	beforeEach(function () use ($files) {
		foreach ($files as $relativeFile) {
			$path = realpath(__DIR__ . '/../../' . $relativeFile);
			expect($path)->not->toBeFalse("Required plugin file is missing: {$relativeFile}");
			expect(is_readable($path))->toBeTrue("Required plugin file is unreadable: {$relativeFile}");
		}
	});

	it('declares strict_types in every plugin file', function () use ($files) {
		foreach ($files as $relativeFile) {
			$path     = realpath(__DIR__ . '/../../' . $relativeFile);
			$contents = file_get_contents($path);
			expect($contents)->not->toBeFalse("Unable to read {$relativeFile}");

			expect(strpos($contents, 'declare(strict_types'))->not->toBeFalse(
				"{$relativeFile} must declare strict_types=1"
			);
		}
	});

	it('uses short array syntax', function () use ($files) {
		foreach ($files as $relativeFile) {
			$path     = realpath(__DIR__ . '/../../' . $relativeFile);
			$contents = file_get_contents($path);

			expect(preg_match('/\barray\s*\(/', $contents))->toBe(0,
				"{$relativeFile} still uses long array() syntax"
			);
		}
	});
});
