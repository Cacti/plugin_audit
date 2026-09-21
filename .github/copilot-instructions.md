# GitHub Copilot Instructions

## Priority Guidelines

When generating code for this repository:

1. **Version Compatibility**: This is a Cacti plugin (`audit`, version 1.5) targeting Cacti 1.2.20+
2. **Context Files**: Prioritize patterns and standards defined in this file (`.github/copilot-instructions.md`)
3. **Codebase Patterns**: When context files don't provide specific guidance, scan the codebase for established patterns
4. **Architectural Consistency**: Maintain plugin-based architecture extending Cacti core
5. **Code Quality**: Prioritize security, maintainability, and compatibility in all generated code

## Technology Stack

### Core Technologies
- **PHP**: 8.1-8.3 (CI matrix)
- **Platform**: Cacti Plugin Architecture (Cacti 1.2.20+) — logs GUI and CLI activities to an audit trail
- **Database**: MySQL 8.0 (CI) / MariaDB, InnoDB engine

### Key Dependencies
- Cacti core framework (`api_plugin_*`, `db_*`, `get_request_var()`)
- `phpstan/` static analysis config; `js/` client-side helpers

## Project Structure

```
audit/                    # Repository root (install to plugins/audit/ in Cacti)
├── js/                     # Client-side helpers
├── locales/                  # Internationalization files
├── phpstan/                     # PHPStan configuration/baseline
├── tests/                          # Test suite
├── audit.php                         # Web UI for viewing/exporting/purging audit logs
├── audit_functions.php                 # audit_config_insert() (main logger), audit_process_page_data()
├── audit_syslog.php                      # Syslog delivery integration
├── INFO                                    # Plugin metadata (name, version, compat)
├── README.md
└── setup.php                                 # Plugin lifecycle (install/uninstall/upgrade) and hook registration
```

## Naming Conventions

### Function Names
ALL functions MUST use the `audit_` or `plugin_audit_` prefix to avoid namespace collisions with Cacti core: `plugin_audit_install()`, `audit_config_insert()`, `audit_process_page_data()`.

### Database Tables
Primary table: `audit_log` — columns include `page`, `user_id`, `action`, `ip_address`, `user_agent`, `event_time`, `post` (JSON), `object_data` (JSON), plus security columns `request_status`, `external_status`, `external_error`. A secondary `audit_syslog_delivery` table queues Syslog delivery.

## Code Style

### Indentation and Formatting
- **Tabs**: Use tabs (not spaces) for indentation throughout all PHP files.
- **Braces**: Opening brace on the same line for functions and control structures.
- **Spacing**: Space after control structure keywords (`if`, `foreach`, `while`).

### File Headers
ALL PHP files MUST include the standard GPL v2 license header used throughout this repository (see `setup.php`), crediting "The Cacti Group".

## Security Standards

### Input Handling — Critical
**NEVER** access `$_GET`/`$_POST` directly. Always use:
- `get_request_var('name')` — for basic input
- `get_filter_request_var('name')` — for validated/filtered input
- `get_nfilter_request_var('name')` — for non-filtered input
- `isset_request_var('name')` — to check existence

```php
switch (get_request_var('action')) {
case 'export':
	audit_export_rows();
	break;
```

`get_filter_request_var()` (and its `gfrv()` shorthand, where available) called with only the
`$name` argument (no regex/filter as the 2nd/3rd argument) already validates the value as numeric
and returns it as a **string** -- it does not return an int, and it halts execution if the request
value is not numeric. Because of this, do NOT cast its output to `(int)` when the result is only
used for string output (e.g. `print`/`echo`, string concatenation, embedding in HTML/JS); the cast
is redundant. Only cast when the value is genuinely used in an integer/numeric context (e.g.
arithmetic, strict `===` comparisons).

### Database Operations — Critical
**ALWAYS** use prepared statements, NEVER string concatenation:
- `db_execute_prepared($sql, $params)` — INSERT/UPDATE/DELETE
- `db_fetch_assoc_prepared($sql, $params)` — SELECT returning rows
- `db_fetch_row_prepared($sql, $params)` — single row
- `db_fetch_cell($sql)` — only for queries without user input

```php
db_execute_prepared('INSERT INTO audit_log (page, user_id, action, ip_address, user_agent, event_time, post, object_data)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
	array($page, $user_id, $action, $ip_address, $user_agent, $event_time, $post, $object_data));
```

### Sensitive Data Handling
`audit_config_insert()` sanitizes `$_POST` and **removes passwords** before logging — preserve this redaction behavior when touching the logging path; never let a new field capture raw credential values into `audit_log.post`.

## Database Operations

### Upgrades & Schema Changes
When adding DB columns, update `audit_check_upgrade()` in `setup.php`:

```php
db_execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS object_data LONGBLOB');
```
This runs on plugin version change detection.

## Internationalization

Wrap ALL user-facing strings in `__('String', 'audit')`. For plurals: `__('%d Months', 2, 'audit')`.

## Plugin Architecture

### Data Flow
1. Cacti triggers the `config_insert` hook on POST requests → `audit_config_insert()` executes.
2. The function validates the event via `audit_log_valid_event()`, sanitizes `$_POST`, and removes passwords.
3. If `selected_items` is present, `audit_process_page_data()` extracts object details from the DB.
4. The event is logged to `audit_log` (plus an optional external JSON file / Syslog delivery queue).

### Plugin Hooks
Hooks registered in `plugin_audit_install()`:
- `config_insert` — main logging trigger (fires on POST requests)
- `poller_bottom` — daily cleanup of old records based on retention setting
- `config_arrays` — inject menu items and configuration arrays
- `config_settings` — add the admin settings page
- `draw_navigation_text` — define breadcrumb navigation
- `replicate_out` — table replication for remote pollers
- `is_console_page`, `logout_pre_session_destroy` — session/console integration

### UI Structure
Use `top_header()` before and `bottom_footer()` after page content; use `html_start_box()` / `html_end_box()` for content sections; access Cacti config via `global $config;`.

## Testing

CI (`plugin-ci-workflow.yml`) tests against PHP 8.1-8.3, MySQL 8.0, plugin installed at `cacti/plugins/audit` (not `plugin_audit`). Test suite covers security columns, the syslog delivery queue table, and CLI-triggered audit entries.

## Localization Workflow

```bash
cd locales
./build_gettext.sh
```
Requires `xgettext` (GNU gettext). Regenerates `po/cacti.pot` from all `__()` calls, then compiles `.po` → `.mo` files.

## Best Practices

1. Never let raw request superglobals reach logging or query code — always go through the `get_*_request_var()` family.
2. Preserve password redaction in `audit_config_insert()`.
3. Use prepared statements exclusively for anything with variable input.
4. Wrap all user-facing strings with `__('text', 'audit')`.

## Common Pitfalls to Avoid

```php
// WRONG - direct superglobal access
$id = $_GET['id'];

// CORRECT
$id = get_filter_request_var('id');

// WRONG - string-concatenated SQL
db_execute("INSERT INTO audit_log (page) VALUES ('$page')");

// CORRECT
db_execute_prepared('INSERT INTO audit_log (page) VALUES (?)', array($page));
```

## Version Control

Document all changes in `CHANGELOG.md`; use descriptive commit messages referencing issue/PR numbers when applicable.

## CI & Dependency Baselines

- Do not commit a `composer.json` or `composer.lock` in this plugin's own repo root — the shared CI workflow installs Pest/dev dependencies into Cacti's own Composer-managed vendor tree (checked out alongside the plugin). Use Cacti's `composer.json`, not a plugin-local one.
- Do not add a plugin-local `.phpstan.neon`/`phpstan.neon` or `.php-cs-fixer.php`/`.php-cs-fixer.dist.php` — lint/static-analysis steps run against Cacti's own config from the Cacti core checkout, targeting this plugin's directory. Use the Cacti version, not a plugin-local config.
- Prefer Cacti's `cacti_count()`/`cacti_sizeof()` wrappers over the raw `count()`/`sizeof()` builtins in new or edited code.

## References

- [Cacti main repo](https://github.com/Cacti/cacti/tree/1.2.x)
- [Cacti Documentation](https://www.github.com/Cacti/documentation)
- `README.md` for feature descriptions
- `CHANGELOG.md` for version history
