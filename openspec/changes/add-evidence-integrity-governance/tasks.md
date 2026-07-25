## 1. Syslog Schema and Configuration

- [x] 1.1 Add an idempotent Syslog delivery-queue schema with event UUID, destination fingerprint, state, attempt schedule, bounded error, and timestamps
- [x] 1.2 Add a separate Remote Syslog settings group without changing the existing local-file settings
- [x] 1.3 Add validated settings for receiver, port, UDP/TCP/TLS transport, RFC 5424/CEF/JSON payload, facility, application name, node identity, timeout, UDP size limit, retry limits, and batch size
- [x] 1.4 Add TLS peer and hostname verification settings with optional CA and client-certificate paths, secure defaults, and secret-safe display and auditing
- [x] 1.5 Restrict Syslog configuration and test controls to Audit Log Admin and enforce POST plus CSRF validation for state-changing actions

## 2. Syslog Record Formatting

- [x] 2.1 Implement RFC 5424 PRI, UTC timestamp, hostname, application, process, message ID, structured-data escaping, and normalized field mapping
- [x] 2.2 Implement compact bounded JSON payload formatting with event UUID, correlation ID, actor, source, action, outcome, target, node, and poller identity
- [x] 2.3 Implement CEF payload mapping and escaping for normalized audit fields
- [x] 2.4 Implement RFC 6587 octet-count framing for TCP and TLS while keeping one complete record per UDP datagram
- [x] 2.5 Reject oversized UDP records without truncation or splitting and classify them as permanent delivery errors
- [x] 2.6 Add unit tests and fixtures for RFC 5424, JSON, CEF, escaping, framing, size limits, and stable event identity

## 3. Syslog Queue and Transports

- [x] 3.1 Enqueue one pending Syslog delivery row when an audit event is finalized and Syslog is enabled, without opening a network connection in the request
- [x] 3.2 Implement bounded UDP writes and record successful local socket acceptance as sent_unconfirmed
- [x] 3.3 Implement bounded TCP connection and complete framed writes with reusable connections within a poller batch
- [x] 3.4 Implement TLS connection and framed writes with peer and hostname verification enabled by default
- [x] 3.5 Process due queue rows from the Cacti poller in configurable bounded batches
- [x] 3.6 Implement exponential retry scheduling for transient failures and dead-letter transitions for permanent or exhausted failures
- [x] 3.7 Preserve event UUID and node identity across retries and prevent duplicate active queue rows for the same event and destination
- [x] 3.8 Add transport tests using local UDP, TCP, and TLS receivers, including timeouts, partial writes, certificate failure, receiver outage, and duplicate processing

## 4. Syslog Administration and Operations

- [x] 4.1 Add an audited Audit Log Admin test action that emits a clearly identified Syslog test record without exposing secrets
- [x] 4.2 Add queue-health reporting for state counts, oldest pending age, last attempt, last successful socket send, and last bounded error
- [x] 4.3 Add configurable health thresholds, persistent Audit UI warnings, and Cacti log transitions for unhealthy and recovered states
- [x] 4.4 Add an audited Audit Log Admin action to retry selected dead-letter rows
- [x] 4.5 Ensure retention and purge do not remove events with unfinished required Syslog delivery
- [x] 4.6 Document receiver setup, facility and format choices, UDP limitations, TCP/TLS recommendations, SIEM ingestion, and the sent_unconfirmed delivery semantics
- [x] 4.7 Run PHP compatibility, security, migration, and regression tests and verify existing local-file delivery remains unchanged

## 5. Evidence Integrity

- [ ] 5.1 Add idempotent schema for node sequence, previous-chain value, event HMAC, key identifier, and integrity checkpoints
- [ ] 5.2 Define and test a versioned canonical representation of immutable finalized audit fields
- [ ] 5.3 Implement serialized node-specific sequence allocation and HMAC-SHA-256 chain calculation during finalization
- [ ] 5.4 Add active and historical key identifiers with secure key-loading and rotation behavior that never stores keys in audit rows
- [ ] 5.5 Create periodic count- and time-based checkpoint records and enqueue them through the Syslog queue
- [ ] 5.6 Add integrity tests for mutation, deletion, sequence gaps, concurrent finalization, key rotation, and checkpoint comparison

## 6. Governance and Archival

- [ ] 6.1 Add retention-class schema and administration for age, required Syslog delivery, archive requirement, and purge eligibility
- [ ] 6.2 Assign a retention class to each event with a safe default and migration behavior for existing events
- [ ] 6.3 Add audited legal-hold placement and release with reason, actor, time, scope, and optional case identifier
- [ ] 6.4 Add archival generation with event ranges, counts, node ranges, terminal integrity values, policy identity, and authenticated manifests
- [ ] 6.5 Update scheduled retention and manual purge to enforce legal hold, delivery, archive, and checkpoint prerequisites and report protected counts
- [ ] 6.6 Add governance tests for held ranges, mixed protected selections, archive verification, retention classes, and uninstall cleanup

## 7. Investigation and Verification

- [ ] 7.1 Add indexed normalized fields needed for event type, outcome, category, target, correlation ID, node ID, and poller ID filters
- [ ] 7.2 Add bounded validated Audit Log User filters using safe parameterized queries for list and export
- [ ] 7.3 Add configurable coalescing for enumerated low-risk audit list and detail reads, preserving first time, last time, actor, target, session, and occurrence count
- [ ] 7.4 Exclude exports, purge, settings, delivery tests, dead-letter retries, verification, and all failures from coalescing
- [ ] 7.5 Add a read-only CLI verification report for hashes, chain continuity, checkpoints, queue state, and delivery completeness over a bounded range
- [ ] 7.6 Add an Audit Log Admin verification view with the same bounded checks and no evidence mutation
- [ ] 7.7 Add investigation and verification tests for combined filters, invalid input, coalescing boundaries, corruption, chain gaps, and incomplete delivery

## 8. Release Readiness

- [ ] 8.1 Review all new tables and settings for install, upgrade, replication, and complete uninstall behavior
- [ ] 8.2 Review permissions so Audit Log User remains read-only and all configuration, retry, legal-hold, purge, archive, and verification administration requires Audit Log Admin
- [ ] 8.3 Update plugin version metadata, changelog, administrator documentation, and upgrade notes
- [ ] 8.4 Run the full available test suite and perform a final security review of network destinations, TLS, error handling, secrets, CSRF, SQL, output encoding, and denial-of-service bounds
