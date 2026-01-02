# Cacti Audit Plugin AI Instructions

## Architecture Overview
This is a Cacti plugin that logs GUI and CLI activities to an audit trail. The plugin hooks into Cacti's event system to capture user actions.

**Core Components:**
- [`setup.php`](../setup.php): Plugin lifecycle (install/uninstall/upgrade) and hook registration via `api_plugin_register_hook()`
- [`audit.php`](../audit.php): Web UI for viewing/exporting/purging audit logs; handles actions via `switch(get_request_var('action'))`
- [`audit_functions.php`](../audit_functions.php): Core logging logic in `audit_config_insert()` and page-specific data extraction in `audit_process_page_data()`
- Database: Single `audit_log` table with columns: `page`, `user_id`, `action`, `ip_address`, `user_agent`, `event_time`, `post` (JSON), `object_data` (JSON)

**Data Flow:**
1. Cacti triggers `config_insert` hook on POST requests → `audit_config_insert()` executes
2. Function validates event via `audit_log_valid_event()`, sanitizes `$_POST`, removes passwords
3. If `selected_items` present, `audit_process_page_data()` extracts object details from DB
4. Event logged to `audit_log` table + optional external JSON file

## Critical Conventions

### Function Naming
ALL functions MUST use `audit_` or `plugin_audit_` prefix to avoid namespace collisions with Cacti core.

### Input Handling (Security Critical)
**NEVER** access `$_GET`/`$_POST` directly. Always use:
- `get_request_var('name')` - for basic input
- `get_filter_request_var('name')` - for validated/filtered input  
- `get_nfilter_request_var('name')` - for non-filtered input
- `isset_request_var('name')` - to check existence

Example from [`audit.php`](../audit.php#L30):
```php
switch(get_request_var('action')) {
case 'export':
    audit_export_rows();
    break;
```

### Database Operations (Security Critical)
**ALWAYS** use prepared statements, NEVER string concatenation:
- `db_execute_prepared($sql, $params)` - for INSERT/UPDATE/DELETE
- `db_fetch_assoc_prepared($sql, $params)` - for SELECT returning rows
- `db_fetch_row_prepared($sql, $params)` - for single row
- `db_fetch_cell($sql)` - only for queries without user input

Example from [`audit_functions.php`](../audit_functions.php#L210-L212):
```php
db_execute_prepared('INSERT INTO audit_log (page, user_id, action, ip_address, user_agent, event_time, post, object_data)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    array($page, $user_id, $action, $ip_address, $user_agent, $event_time, $post, $object_data));
```

### Localization
Wrap ALL user-facing strings in `__('String', 'audit')`. The second parameter `'audit'` is the text domain.

Example: `__('View Audit Log', 'audit')`

For plurals: `__('%d Months', 2, 'audit')`

### UI Structure
- Use `top_header()` before and `bottom_footer()` after page content
- Use `html_start_box()` / `html_end_box()` for content sections
- Access Cacti config: `global $config;`

## Developer Workflows

### Testing Integration
GitHub Actions runs tests against live Cacti install. See [`.github/workflows/plugin-ci-workflow.yml`](../.github/workflows/plugin-ci-workflow.yml):
- Tests against PHP 8.1, 8.2, 8.3
- Plugin must be in `cacti/plugins/audit` directory (NOT `plugin_audit`)
- MySQL 8.0 service with user `cactiuser:cactiuser`, database `cacti`

### Localization Workflow
```bash
cd locales
./build_gettext.sh
```
Requires `xgettext` (GNU gettext). Regenerates `po/cacti.pot` from all `__()` calls, then compiles `.po` → `.mo` files.

### Upgrades & Schema Changes
When adding DB columns, update `audit_check_upgrade()` in [`setup.php`](../setup.php#L69-L100):
```php
db_execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS object_data LONGBLOB');
```
This runs on plugin version change detection.

## Hook System
Hooks registered in `plugin_audit_install()`:
- `config_insert` - Main logging trigger (fires on POST requests)
- `poller_bottom` - Daily cleanup of old records based on retention setting
- `config_arrays` - Inject menu items and configuration arrays
- `config_settings` - Add admin settings page
- `draw_navigation_text` - Define breadcrumb navigation
- `replicate_out` - Table replication for remote pollers

## Key Files Reference
- [`setup.php`](../setup.php) - Hook registration, table schema, upgrade logic
- [`audit.php`](../audit.php) - UI controller with export/purge/getdata actions
- [`audit_functions.php`](../audit_functions.php) - `audit_config_insert()` (main logger), `audit_process_page_data()` (extract object details)
- [`locales/build_gettext.sh`](../locales/build_gettext.sh) - Translation builder
- [`.github/workflows/plugin-ci-workflow.yml`](../.github/workflows/plugin-ci-workflow.yml) - Integration tests
