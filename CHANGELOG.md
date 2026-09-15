# ChangeLog

--- 1.6 ---

* feature: Capture login failure, token, credentials-accepted, and authorization-denied events by polling the Cacti user_log table across all authentication methods
* feature: Ingest user_log every poller cycle with bounded high-water paging and retry-safe claim-first deduplication via audit_user_log_state
* feature: Apply the audit retention cutoff to every ingestion batch so historical rows are not replayed
* feature: Detect installation-wide failed-login volume anomalies every poller cycle with explicit global scope, source cardinality, and atomically throttled alerts
* performance: Add index-backed access paths for bounded user_log ingestion and failed-login aggregation
* feature: Capture authorization-denied events through Cacti's custom_denied hook without taking over the denied-page rendering, with referer paths and query strings redacted
* feature: Confirm session teardown through the logout_post_session_destroy hook, correlated with the existing pre-destroy logout event
* security: Record user_log result=1 as credentials_accepted with unknown outcome, not a confirmed login success
* security: Record ambiguous user_log result=3/user_id=0 and unsupported result codes as unknown rather than misclassifying them
* security: Restrict authentication auditing and brute-force detection settings to Audit Log Admin users and enforce authorization on save
* security: Make authentication auditing opt-in, seed upgrades at the current epoch, and preserve existing administrator choices
* security: Bound failed-row retries, reserve ingestion capacity for new rows, and recover interrupted finalization through deterministic event UUIDs
* security: Make marker cleanup replay-safe and rate-proportional, with terminal-loss evidence retained in the Cacti log when audit table writes fail
* security: Restrict the audit master switch, retention, and external file controls to Audit Log Admin users
* performance: Create and remove plugin-owned user_log indexes only when authentication auditing is enabled or disabled

* feature: Add standards-based remote Syslog delivery over UDP, TCP, and verified TLS
* feature: Add RFC 5424 headers with RFC 5424, CEF, or compact JSON message formats
* feature: Queue remote delivery in the poller with exponential backoff, dead-letter handling, health reporting, and audited admin actions
* security: Restrict Syslog settings, tests, and dead-letter retries to Audit Log Admin with validated destinations and CSRF-protected POST actions
* security: Preserve unfinished Syslog evidence during scheduled retention and manual purge
* issue: Capture expected Syslog connection and write warnings without leaking PHP notices into the Cacti poller log
* feature: Include redacted submitted, object, and detail data in CEF Syslog records
* feature: Verify user realm permission saves against the resulting database state
* security: Group Audit Log User and Audit Log Admin permissions under Audit Plugin
* feature: Add normalized compliance event identifiers, categories, actors, targets, outcomes, timing, and integrity metadata
* feature: Deliver finalized request outcomes to external log consumers
* feature: Audit audit-log views, searches, event detail access, exports, and purges
* feature: Capture Cacti 1.2.x logout and session-timeout events through the supported logout hook
* feature: Finalize captured CLI activity and make it available to external log delivery
* feature: Add selectable text or JSON formats for external audit logging
* feature: Rename outcome to request_status with started/completed/failed values
* feature: Track and retry failed external audit-log delivery
* security: Bound nested request depth, field counts, string sizes, and JSON parsing
* security: Escape stored audit data before rendering to prevent stored XSS
* security: Require an authorized, CSRF-protected POST to purge the audit log
* security: Recursively redact sensitive web and CLI values
* security: Generate standards-compliant, spreadsheet-safe CSV exports
* feature: Mark hook-time records explicitly as attempted actions
* feature: Finalize request outcomes and expose external-log delivery status
* issue: Harden external file logging, retention, malformed records, and replication
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
Copyright (c) 2004-2026 - The Cacti Group, Inc.
