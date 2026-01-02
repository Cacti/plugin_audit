# ChangeLog

--- develop ---

* issue#38: Graph Template table does not exist
* issue: If the audit log does not exist or is not set, set it and create it
* issue: Audit assumes that all selected_items are numeric resulting in fatal error
* feature: Support for Cacti 1.3
* Refactor: Migrats JS functions to functions.js

--- 1.2 ---

* feature:#15: Capture record details when a device is deleted instead of just id
* feature:#16 Capture template details for a deleted template instead of just id
* feature:#17 Capture data of user or group that is deleted instead of just id
* issue:#18  correct classification of action to reflect either delete or Disable
* issue: #11: audit does not upgrade the audit_log table
* feature:#29 Rename Tab name from Misc to Audit
* feature:#25  Record additional Device info when deleted
* feature: Capture Actions on the automation_devices.php page
* feature: Allow logging of audit events to a file

--- 1.0 ---

* Initial Release

-----------------------------------------------
Copyright (c) 2004-2025 - The Cacti Group, Inc.
