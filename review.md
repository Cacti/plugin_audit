# Audit Plugin Code Review

> Remediation update (branch `code_audit`): the implementation now addresses
> AUD-001 through AUD-010, adds focused security-helper coverage for AUD-011,
> and bumps the plugin schema/version to 1.3. The findings below describe the
> pre-remediation code that was reviewed and are retained as the audit record.
> Full browser/database integration coverage is still recommended before release.

## Executive summary

The plugin is small and readable, uses prepared statements for its primary insert and object lookups, and passes PHP syntax checks. However, it should not be released in its current form. The audit found two high-severity security defects, several confidentiality and audit-integrity weaknesses, broken remote-replication code, and no meaningful automated coverage for the sensitive paths.

The highest priorities are:

1. Escape every value rendered from `audit_log`.
2. Make purge a CSRF-protected POST operation with explicit authorization.
3. Replace the current credential redaction with recursive, allowlist-oriented collection, including CLI arguments.
4. Produce exports with a real CSV writer and neutralize spreadsheet formulas.
5. Define whether records represent attempts or successful changes and record that outcome accurately.

## Scope and methodology

Reviewed:

- `.github/copilot-instructions.md`
- `setup.php`
- `audit.php`
- `audit_functions.php`
- `js/functions.js`
- `INFO`, `README.md`, `CHANGELOG.md`
- `.github/workflows/plugin-ci-workflow.yml`
- localization build assets and repository layout

The review traced install/upgrade/uninstall, hook registration, GUI and CLI event capture, database writes and reads, record-detail rendering, filtering, export, purge, retention, external-file logging, and remote replication. Cacti core helpers in the adjacent Cacti checkout were consulted to verify authorization, CSRF, sorting, validation, and HTML helper behavior.

Validation performed:

```text
find . -name '*.php' -print0 | xargs -0 -n1 php -l
```

Result: every PHP file passed syntax validation.

No plugin unit or functional test suite is present. The CI workflow installs the plugin, checks syntax, runs the poller, and asserts that at least one CLI audit row exists; it does not exercise the web UI or any negative/security cases.

## Findings

### AUD-001 — High — Stored XSS in audit detail and list views

**Evidence**

- `audit.php:54-60` directly concatenates CLI record fields into HTML.
- `audit.php:77-81` directly concatenates page, username, IP address, date, and action into HTML.
- `audit.php:95-104` directly renders request field names and values.
- `audit.php:121-123` embeds JSON record data inside `<pre>` without HTML escaping.
- `audit.php:432-448` passes database values such as `user_agent`, username, page, IP, and action to `form_selectable_cell()`. Cacti's `form_selectable_cell()` does not escape its content; `form_selectable_ecell()` is the escaping variant.
- `audit_functions.php:131-158` stores attacker-influenced request data, and `audit_functions.php:167` stores the request's `User-Agent`.

**Impact**

An authenticated user who can cause an audited request can persist HTML or JavaScript in a request value or user-agent string. When an administrator with the audit realm views the list or hovers over the event, that content is inserted into the DOM. This can execute script in the administrator's Cacti session and may permit administrative account compromise.

**Recommendation**

- Escape all scalar values at the final HTML output boundary with `html_escape()`/`htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`.
- Recursively render arrays and objects as escaped text, never as markup.
- Use `form_selectable_ecell()` for plain database values. Keep `form_selectable_cell()` only where the plugin itself constructs trusted markup, and escape the interpolated action inside that markup.
- Return detail data as JSON and construct text nodes client-side, or keep the HTML endpoint but apply centralized contextual escaping.
- Add regression tests containing `<script>`, event-handler attributes, quotes, ampersands, and invalid UTF-8 in every stored field.

### AUD-002 — High — Any authorized viewer can purge the complete log through a CSRF-able GET

**Evidence**

- `js/functions.js:110-113` invokes `audit.php?action=purge` with GET.
- `audit.php:30-40` dispatches that GET directly to `audit_purge()`.
- `audit.php:140-148` unconditionally runs `TRUNCATE TABLE audit_log`.
- Cacti's global GET guard only blocks a limited set of action names (`save`, `update_data`, and `changepassword`); it does not protect this plugin's `purge` action.
- The plugin registers one realm for `audit.php` at `setup.php:39`. There is no separate manage/purge permission and no action-level authorization check.

**Impact**

A malicious site, link, image, or compromised page can cause a logged-in audit viewer's browser to erase the entire audit trail. Additionally, all users who may view the log can also destroy it. This undermines the central integrity property of an audit system.

**Recommendation**

- Change purge to POST and require a valid Cacti CSRF token.
- Add an explicit action-level authorization check and preferably a separate management realm.
- Require a confirmation page that states the scope and row count.
- Prefer a transactionally logged `DELETE` or archive workflow over `TRUNCATE`; record the purge in a separate, non-purged security log.
- Reject unsupported methods with HTTP 405 and unauthorized callers with HTTP 403.

### AUD-003 — High — Sensitive credentials are retained in web and CLI audit data

**Evidence**

- `audit_functions.php:131` copies all of `$_REQUEST`, not just known audit-safe fields.
- `audit_functions.php:136-140` removes only top-level keys whose names contain `pass` or `phrase`.
- Nested values are not inspected. Common secret-bearing names such as `token`, `secret`, `key`, `community`, `credential`, `auth`, and vendor-specific fields are retained.
- Depending on PHP `request_order`, `$_REQUEST` can include more than the POST body and is contrary to the repository instruction to use Cacti request helpers rather than superglobals.
- `audit_functions.php:249-266` stores the complete CLI command line. Cacti CLI tools and third-party scripts may accept passwords, tokens, SNMP communities, or database credentials as arguments.
- External logging duplicates the same data to a filesystem destination at `audit_functions.php:228-246`.

**Impact**

The audit table, exports, backups, replicated copies, and external log can become a credential repository. A viewer who legitimately needs activity metadata may receive secrets that grant substantially broader access. Retention increases the exposure window.

**Recommendation**

- Collect from `$_POST` through the Cacti request API, not `$_REQUEST`.
- Prefer a per-page allowlist of fields needed to explain the event. If a denylist remains as defense in depth, apply it recursively and include all secret categories.
- Replace secret values with a fixed marker so reviewers know a field was supplied but redacted.
- For CLI activity, store the executable and a safely parsed/redacted argument map. At minimum redact `--name=value`, `--name value`, short options known to contain secrets, and URI credentials.
- Document the data classification and secure the table, backups, export, external file permissions, and retention accordingly.
- Add tests for nested arrays, mixed case, CLI option forms, and each Cacti credential field.

### AUD-004 — Medium — CSV export is malformed and enables spreadsheet formula injection

**Evidence**

- `audit.php:177-200` concatenates comma-separated output manually without quoting or escaping fields.
- The existing `audit_csv_escape()` at `audit.php:205-209` is unused and would not produce standards-compliant CSV.
- Stored page, username, action, IP, user-agent, and POST values can contain commas, quotes, CR/LF, and leading spreadsheet formula characters.
- The response does not set a CSV content type or explicit character encoding.
- CLI records are not JSON, but `audit.php:182-184` assumes every `post` value decodes to an iterable object, leading to warnings and incomplete output.

**Impact**

Exports can have shifted columns or injected rows. Opening a crafted export in common spreadsheet software can evaluate cells beginning with `=`, `+`, `-`, or `@`, potentially causing data exfiltration or command execution in susceptible environments.

**Recommendation**

- Write rows with `fputcsv()` to `php://output`.
- Prefix formula-like cells with a single quote or apply a documented safe-cell policy.
- Normalize or preserve line breaks safely through CSV quoting.
- Send `Content-Type: text/csv; charset=UTF-8` and `X-Content-Type-Options: nosniff`.
- Handle GUI JSON and CLI text as separate formats and include `object_data` only by explicit design.
- Add round-trip CSV tests and formula-injection fixtures.

### AUD-005 — Medium — Records describe attempts as completed changes

**Evidence**

- Cacti invokes the `config_insert` hook from `include/global.php` during request bootstrap, before page-specific mutation logic completes.
- `audit_functions.php:126-212` inserts the audit row at hook time.
- `audit_functions.php:175` reads selected object data before the requested operation.
- Actions are inferred from request values at `audit_functions.php:142-147` and `177-200`; some mappings are inconsistent with the generic mapping. For example, `drp_action == 1` is globally labelled `delete`, then labelled `Create Device` for `automation_devices.php`.

**Impact**

Rejected, unauthorized, invalid, or failed requests can appear as successful changes. The captured object snapshot is generally pre-change data, but the schema and UI do not identify it as such. This can mislead incident response and root-cause analysis, which are the plugin's stated purposes.

**Recommendation**

- Explicitly define events as attempts, successes, or both.
- Capture a request/correlation ID at request start, then finalize the event after the mutation with outcome, error, and affected-row/object identifiers.
- Label snapshots as `before` and `after`.
- Centralize action mapping with page-specific enums and tests rather than mutating a shared global `$action`.
- Update README/UI language so the evidence semantics are unambiguous.

### AUD-006 — Medium — Remote replication dependency setup is broken and dead

**Evidence**

- `audit_check_dependencies()` is not registered as a hook in `plugin_audit_install()`.
- `setup.php:109` checks for unrelated table `alert_log`.
- `setup.php:110` queries misspelled table `autid_log`.
- `SHOW CREATE TABLE` is read with `db_fetch_cell()` and then blindly passed to `db_execute()` at `setup.php:112`, unlike the more defensive row handling in `audit_replicate_out()`.
- `$remote_poller_id` is read but unused.

**Impact**

The function cannot perform its intended setup. If wired in later without correction, it will inspect the wrong table and fail to obtain/create the audit table. This creates false confidence around replication readiness.

**Recommendation**

- Remove the dead function or register the correct dependency hook.
- Correct both table names and reuse one tested schema-replication helper.
- Verify behavior against supported Cacti remote-poller versions and add an integration assertion that the remote table exists with the expected schema.

### AUD-007 — Medium — Detail and export paths do not handle missing or malformed records

**Evidence**

- `audit.php:51` accesses `$data['action']` before checking whether the query returned a row.
- `audit.php:62-68` assumes `json_decode()` returned an iterable object.
- `audit.php:100-104` handles arrays and scalars but not nested objects.
- `audit.php:115-123` assumes decoded `object_data` has the expected iterable shape.
- `audit.php:182-190` repeats the JSON/iterability assumption during export.
- `json_encode()` return values are never checked in `audit_functions.php:121`, `158`, or `240`.

**Impact**

Invalid IDs, legacy rows, truncated/corrupt data, unsupported value types, or encoding failures cause warnings, incomplete responses, and lost audit content. If production error display is enabled, warnings may disclose paths or implementation details.

**Recommendation**

- Return 404 for an absent ID and a controlled error for malformed stored data.
- Use `json_decode($value, true, 512, JSON_THROW_ON_ERROR)` and `json_encode(..., JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE)` with exception handling.
- Implement a recursive renderer/serializer with depth and size limits.
- Store an encoding-error marker rather than silently writing `false`.

### AUD-008 — Medium — External file logging is not robust under concurrency or failure

**Evidence**

- `audit_functions.php:219-226` attempts to create the configured file even when external logging is disabled.
- `audit_functions.php:241-245` uses `fopen()`/`fwrite()` without `LOCK_EX`, does not verify a complete write, and ignores open/write failures.
- Database insert and file append are independent, with no delivery status or retry.
- File permissions are inherited from process umask and are not checked after creation.

**Impact**

Concurrent requests can interleave records. Disk-full, permission, rotation, or partial-write failures are silent, so operators may believe SIEM ingestion is complete when it is not. The file may be created with permissions broader than the audit data warrants.

**Recommendation**

- Do not touch the external destination unless external logging is enabled.
- Use an append API with exclusive locking and verify the byte count.
- Validate that the destination is a regular file, reject symlinks where appropriate, and enforce/document restrictive ownership and mode.
- Emit rate-limited operational errors and expose delivery health.
- Prefer syslog or a supported logging transport with rotation and delivery semantics.

### AUD-009 — Low — Retention scheduling can skip cleanup and uses fragile time arithmetic

**Evidence**

- `setup.php:149-163` stores only `date('d')`, the day number within a month, as the last-run marker.
- A gap of one or more months can make a new run on the same day number appear already completed.
- The cutoff is computed as `retention * 86400`, which does not match calendar days across daylight-saving transitions.
- The cleanup SQL is assembled as a string instead of using the repository's prepared-statement convention.

**Impact**

Expired audit data can be retained longer than configured, increasing storage and confidentiality exposure.

**Recommendation**

- Store a full UTC timestamp or ISO date.
- Compare elapsed time or calendar dates explicitly.
- Compute the cutoff with a UTC `DateTimeImmutable` interval and pass it via a prepared statement.
- Add tests for month boundaries, DST transitions, disabled/indefinite retention, and missed poller runs.

### AUD-010 — Low — Implementation diverges from repository conventions and contains UI defects

**Evidence**

- `process_request_vars()` at `audit.php:211` lacks the required `audit_` or `plugin_audit_` prefix.
- Direct superglobal access appears in `setup.php:70`, `203-220` and `audit_functions.php:131`, `159`, `167`, `248-266`, contrary to the Copilot instruction's input-handling rule.
- Several SQL statements containing values are assembled rather than prepared (`setup.php:86-95`, `audit.php:153-174`, and `347-380`). Current validation/quoting limits immediate injection risk in most of these paths, but the pattern is brittle and violates the stated convention.
- `audit.php:110` omits `.=` so the intended closing cells are never appended.
- `audit.php:117-123` closes the inner table and then emits `<tr>` elements outside it, producing invalid table structure.
- `audit.php:337` contains an extra closing `</tr>`.
- `audit.php:453` declares `colspan='5'` for a six-column table.
- JavaScript variables such as `strURL` and `id` are assigned without declarations (`js/functions.js:34`, `48`, `111`, `131`), leaking globals.

**Impact**

These issues increase collision risk inside Cacti's shared PHP namespace, make future security regressions more likely, and cause inconsistent DOM/layout behavior.

**Recommendation**

- Rename the helper to `audit_process_request_vars()`.
- Use the Cacti request API for request values and guard optional server variables.
- Convert value-bearing queries to prepared variants and build filter predicates plus parameter arrays centrally.
- Correct the HTML structure and JavaScript declarations, then validate rendered markup in browser tests.

### AUD-011 — Low — Test coverage is insufficient for an audit/security plugin

**Evidence**

- No unit, browser, or plugin-specific functional tests exist.
- `.github/workflows/plugin-ci-workflow.yml` checks only installability, PHP syntax, poller completion, and whether one CLI action creates at least one row.
- The workflow does not verify event accuracy, authorization, CSRF, escaping, redaction, export correctness, retention, external logging, upgrades, uninstall behavior, or replication.

**Impact**

The most important security and evidentiary properties can regress while CI remains green.

**Recommendation**

Add focused tests for:

- viewer versus manager authorization;
- purge method, CSRF, confirmation, and auditability;
- stored-XSS payloads in all rendered fields;
- recursive web and CLI secret redaction;
- successful, failed, and unauthorized change outcomes;
- valid/malformed GUI and CLI records;
- standards-compliant, formula-safe CSV;
- external-log concurrency and failure handling;
- retention boundaries;
- fresh install, upgrade from each supported schema, uninstall, and remote replication.

Run static analysis and style checks as well (for example PHPStan/Psalm at a practical level, PHPCS with Cacti rules, ESLint, and a dependency/security scanner where applicable).

## Positive observations

- Primary audit inserts use `db_execute_prepared()` (`audit_functions.php:210-212`, `264-266`).
- Page-specific object lookups use prepared queries.
- PHP object instantiation is disabled during `unserialize()` with `allowed_classes => false`.
- Password-like top-level fields and the CSRF token are intentionally removed, showing awareness of log sensitivity, though the implementation is incomplete.
- The table has useful indexes for the principal view filters and retention query.
- UI strings are generally localized with the `audit` text domain.
- The CI matrix covers PHP 8.1, 8.2, and 8.3 against a live Cacti/MySQL installation.

## Recommended remediation order

1. Fix AUD-001 and AUD-002 before the next release.
2. Address secret handling (AUD-003) and rotate any credentials that may already have been logged.
3. Fix export safety (AUD-004) and clarify/correct event semantics (AUD-005).
4. Repair or remove replication code (AUD-006), harden malformed-data handling (AUD-007), and make external delivery observable (AUD-008).
5. Correct retention and convention/UI issues (AUD-009 and AUD-010).
6. Build the security-focused regression suite in AUD-011 and make it a release gate.

## Release assessment

**Recommendation: block release.** Stored XSS in an administrator-facing audit viewer and CSRF-able destruction of the complete audit trail are release-blocking. Existing installations should also be treated as potentially containing sensitive credentials because both request bodies and CLI arguments are retained with incomplete redaction.
