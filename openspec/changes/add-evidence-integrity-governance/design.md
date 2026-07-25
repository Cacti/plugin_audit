## Context

The plugin currently stores every audit event in `audit_log` and can append a
finalized event to a local file. File delivery is attempted in the request
shutdown path and retried by `poller_bottom`, using status columns on the audit
row. This does not provide a remote trust boundary, retry scheduling, dead-letter
handling, or reliable health reporting.

The target Cacti branch is 1.2.x and the plugin must remain compatible with PHP
7.4. Cacti installations commonly integrate with SIEM products through a file
forwarder or Syslog. Supporting product-specific HTTP APIs would add credentials,
dependencies, and acknowledgement semantics that are not needed for the intended
deployment model.

## Goals / Non-Goals

**Goals:**

- Retain the existing local-file output.
- Add remote Syslog over UDP, TCP, and TLS.
- Support RFC 5424 records with CEF or JSON message payloads.
- Add stable node and poller identity and retain event UUIDs for receiver-side
  deduplication.
- Move remote transmission out of web request processing.
- Provide bounded exponential retry, dead-letter state, health visibility, and
  Audit Log Admin controls.
- Establish an integrity chain and verification report.
- Add governance and investigation capabilities without weakening undelivered
  evidence.

**Non-Goals:**

- Native Splunk HEC, Microsoft Sentinel API, or generic webhook adapters.
- Shipping or administering a SIEM receiver.
- Claiming that a successful Syslog send proves durable receiver storage.
- Guaranteeing immutability against a database or host administrator without an
  independently controlled receiver.
- Supporting RELP in the first implementation.

## Decisions

### Keep file and Syslog configuration independent

The existing file output remains an independent option. Remote Syslog has a
separate enable control and settings group rather than a generic provider
framework. This avoids unnecessary abstraction while allowing deployments to
use the file, Syslog, or both.

### Use a per-destination delivery table

Remote delivery state will be stored in a new table keyed by audit event and
destination type. The table will contain event UUID, destination, state,
attempts, next-attempt time, last attempt, completion time, last error, and a
destination fingerprint. This avoids overloading the existing file-delivery
columns and allows retention logic to protect evidence with unfinished remote
delivery.

Initial remote states are:

- `pending`: queued and never attempted.
- `retry`: a transient local connection or write failure occurred.
- `sent_unconfirmed`: the complete Syslog record was accepted by the local
  socket API, but the receiver did not provide durable acknowledgement.
- `dead_letter`: the maximum attempts were reached or a permanent formatting or
  configuration error prevents delivery.

No Syslog transport will be labelled `confirmed` or `delivered`, because standard
Syslog has no application-level durable acknowledgement.

### Queue remote delivery and process it from the poller

Finalizing an audit event creates a pending delivery row. The Cacti poller sends
due rows in bounded batches. Web and CLI requests do not open remote sockets.
This prevents receiver latency or failure from extending administrative
requests and provides one retry path.

### Use standard Syslog framing

UDP sends one record per datagram. TCP and TLS use RFC 6587 octet-counting
framing so embedded spaces and structured payloads do not create ambiguous
record boundaries.

Every record uses an RFC 5424 header containing:

- PRI derived from configured facility and event severity.
- UTC RFC 3339 timestamp.
- stable node identity as hostname.
- `cacti-audit` as application name.
- poller identifier as process ID when available.
- normalized event type as message ID.
- structured data containing event UUID, correlation ID, node ID, poller ID,
  outcome, target identifiers, and integrity metadata.

The message portion is selectable between CEF and compact JSON. An RFC 5424
message-only format is also available for receivers that prefer structured data
without a secondary envelope.

### Treat UDP explicitly as unconfirmed

A successful UDP socket write means only that the local operating system
accepted the datagram. The state becomes `sent_unconfirmed`; it is not retried.
Local socket failures are retried. Oversized UDP records are permanent errors
and move directly to dead-letter rather than being silently truncated or split.
TCP and TLS writes also become `sent_unconfirmed` after a complete framed write.

### Secure TLS by default

TLS defaults to port 6514, peer verification enabled, and hostname verification
enabled. Administrators may configure a CA file and optional client certificate
and key paths. Certificate and hostname verification cannot be disabled.

Receiver values are validated as a hostname or IP plus a numeric port. Control
characters, URI schemes, embedded credentials, and unbounded timeouts are
rejected. Test actions require Audit Log Admin, POST, and CSRF validation and
are themselves audited without recording secrets.

### Use bounded exponential retry

Transient failures use exponential backoff based on configurable base and
maximum delays, capped attempts, and bounded batch size. Permanent errors such
as invalid configuration, invalid TLS files, unsupported format, or UDP
oversize go directly to dead-letter. A manual Audit Log Admin retry resets
selected dead-letter rows to pending and records the action.

### Separate delivery health from individual events

The Audit UI will report pending, retry, sent-unconfirmed, and dead-letter
counts; oldest pending age; last attempt; last successful socket send; and last
error. The plugin logs state transitions into the Cacti log and displays an
administrator warning when configured thresholds are exceeded. Email or
third-party alert dispatch is outside the first Syslog slice.

### Chain finalized event content and support external checkpoints

Integrity records will cover all immutable audit content using HMAC-SHA-256 with
a separately configured key. A chain links each event to a previous chain value
within a node-specific sequence. Periodic checkpoint records are sent through
the same Syslog destination so an independently retained receiver can detect
later local rewriting or deletion.

Concurrent writers will not calculate chain state independently. A serialized
database operation will allocate the next node sequence and previous hash. Key
identifiers, not keys, are stored with events so rotation can be verified.

### Apply retention policy after delivery and legal-hold checks

Retention will not delete events with pending, retry, or dead-letter deliveries,
events under legal hold, or events whose required archive/checkpoint is
incomplete. Retention classes will be explicit rather than one global age.
Archival records contain counts, ranges, integrity roots, and policy identity.

### Add indexed investigation fields and coalesce self-access

Investigation filters operate on normalized indexed columns. Low-value audit
list/detail views may be coalesced within a bounded actor/session/time window,
but exports, purge attempts, configuration changes, integrity reports, delivery
tests, and failures are always recorded individually.

## Risks / Trade-offs

- **Syslog lacks durable acknowledgement** → Use `sent_unconfirmed`, retain UUIDs
  for receiver deduplication, and never describe a socket write as confirmed.
- **UDP loss or fragmentation** → Warn administrators, enforce a configurable
  message limit, reject oversized records, and recommend TCP/TLS.
- **TCP connection churn** → Process bounded batches and reuse a connection
  within one poller delivery cycle.
- **Receiver outage grows the queue** → Apply backoff, batch limits, health
  thresholds, and dead-letter visibility while protecting queued evidence from
  retention.
- **A compromised Cacti host can access the HMAC key** → External checkpoints
  make historical rewriting detectable, but cannot prevent future forgery after
  compromise; document this boundary.
- **Hash-chain serialization can add database contention** → Allocate sequence
  state in a short transaction and keep network I/O outside the transaction.
- **CEF cannot represent every nested field naturally** → Preserve normalized
  investigation fields in CEF and encode remaining bounded detail as an escaped
  extension; JSON remains available for full structured payloads.
- **Self-access coalescing can hide detail** → Limit coalescing to enumerated
  low-risk read events and retain actor, first/last time, and occurrence count.

## Migration Plan

1. Add schema for delivery queue, integrity sequence/key identifiers, governance
   metadata, and investigation indexes using idempotent migrations.
2. Leave existing file delivery enabled and unchanged.
3. Introduce Syslog settings disabled by default.
4. Allow Audit Log Admin to save and test configuration before enabling it.
5. Enabling Syslog affects newly finalized events; optional controlled backfill
   can enqueue a bounded historical range.
6. Rollback disables Syslog and stops queue processing without deleting queued
   state or audit evidence. Schema is retained until plugin uninstall.

## Resolved Defaults

- The first Syslog release includes optional mutual-TLS client certificate and
  key paths.
- The default maximum UDP record size is 8192 bytes.
- Integrity checkpoints will use configurable event-count and elapsed-time
  thresholds when that later task group is implemented.
