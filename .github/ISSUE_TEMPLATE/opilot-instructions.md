# Cacti Audit Plugin Development Instructions

## Project Overview
This is a Cacti plugin designed to audit user activities, including configuration changes and CLI commands. It hooks into Cacti's core to capture `$_POST` data and logs it to the `audit_log` table.

## Architecture & Core Components
- **Plugin Entry (`setup.php`)**: Registers hooks, realms, and handles installation/upgrades.
- **Audit Logic (`audit_functions.php`)**: Contains `audit_process_page_data` which resolves object IDs to human-readable names for specific Cacti pages.
- **UI (`audit.php`)**: The main interface for viewing audit logs.
- **Database**: Uses the `audit_log` table. Schema updates are handled in `audit_check_upgrade()` within `setup.php`.

## Key Development Patterns

### 1. Extending Audit Coverage
To add detailed auditing for a new Cacti page (e.g., resolving an ID to a name), modify `audit_process_page_data` in `audit_functions.php`.

**Pattern:**
```php
case 'your_page.php':
    foreach ($selected_items as $item) {
        // Fetch descriptive data for the item ID
        $objects[] = db_fetch_assoc_prepared('SELECT name FROM your_table WHERE id = ?', array($item));
    }
    break;
```

### 2. Database Interaction
Always use Cacti's database wrapper functions. **Never** use raw PHP MySQL functions.
- `db_fetch_assoc_prepared($sql, $params)`: For fetching multiple rows.
- `db_fetch_row_prepared($sql, $params)`: For fetching a single row.
- `db_fetch_cell_prepared($sql, $params)`: For fetching a single value.
- `db_execute_prepared($sql, $params)`: For INSERT/UPDATE/DELETE.

### 3. Input Handling & Security
- Use `get_request_var('var_name')` or `get_filter_request_var('var_name')` to retrieve `$_GET`/`$_POST` data.
- Ensure all user-facing strings are localized using `__('String', 'audit')`.

### 4. Plugin Hooks
Hooks are registered in `plugin_audit_install()` in `setup.php`.
- `config_insert`: The primary hook used to capture data changes.
- `is_console_page`: Determines if the plugin page is part of the console.

### 5. SIEM / File Logging
The plugin supports writing audit logs to an external file (JSON format) for SIEM ingestion.
- **Configuration**: Controlled by `audit_log_external` (on/off) and `audit_log_external_path` settings in `setup.php`.
- **Implementation**: Logic resides in `audit_functions.php`. It writes JSON-encoded events to the specified file.
- **Permissions**: Ensure the web server user has write permissions to the target directory.

## Common Workflows

### Installation/Upgrade
- The plugin resides in `plugins/audit/`.
- Version changes in `INFO` trigger `audit_check_upgrade()` in `setup.php`.
- Always increment the version in `INFO` and `setup.php` when making schema changes.

### Localization
- Run `locales/build_gettext.sh` to regenerate `.pot` and `.mo` files after adding new translatable strings.
- Domain must always be `'audit'`.

## Clean as you Code & Refactoring Opportunities
When touching existing code, look for opportunities to improve quality:

1.  **N+1 Query Optimization**:
    - **Issue**: `audit_process_page_data` often loops through `$selected_items` and executes a SQL query for *each* item.
    - **Refactor**: Aggregate IDs and use `WHERE id IN (?, ?, ...)` to fetch all data in a single query.

2.  **Modern File Operations**:
    - **Issue**: Usage of `fopen`/`fwrite`/`fclose`.
    - **Refactor**: Use `file_put_contents()` with `FILE_APPEND` and `LOCK_EX` flags for atomic, cleaner file writing.

3.  **Switch Statement Complexity**:
    - **Issue**: `audit_process_page_data` contains a massive switch statement.
    - **Refactor**: Consider extracting case logic into separate handler functions or a map-based strategy to improve readability.

## Directory Structure
- `setup.php`: Plugin registration and hooks.
- `audit.php`: Main UI file.
- `audit_functions.php`: Helper functions and logic.
- `locales/`: Translation files.
- `INFO`: Plugin metadata (version, author, etc.).
