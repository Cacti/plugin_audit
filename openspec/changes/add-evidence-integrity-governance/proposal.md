## Why

The audit plugin currently writes to its database and an optional local file, so
audit evidence can be lost with the Cacti host and administrators have limited
visibility into delivery failures, integrity, retention, and investigations.
This change establishes remote evidence delivery and the governance controls
needed for a defensible audit trail.

## What Changes

- Add remote Syslog delivery settings alongside the existing local-file output.
- Support RFC 5424, CEF, and JSON syslog records over UDP, TCP, and TLS.
- Add stable node and poller identity to remotely delivered events.
- Track transport-specific delivery states without treating UDP transmission as
  proof of receiver acceptance.
- Add retry backoff, delivery-health reporting, dead-letter handling, and
  administrator alerts.
- Add signed records or an externally anchored integrity chain, plus a
  verification report.
- Add retention classes, legal hold, archival policies, and safeguards for
  undelivered evidence.
- Add investigation filters for event type, outcome, category, target, time,
  correlation identifier, and node.
- Coalesce repetitive low-value audit self-access events.
- Keep SIEM-specific configuration outside the plugin; Splunk, Microsoft
  Sentinel, and other systems can ingest the existing file or receive Syslog.

## Capabilities

### New Capabilities

- `remote-syslog-delivery`: Syslog settings, RFC 5424/CEF/JSON formatting,
  UDP/TCP/TLS transmission, delivery-state semantics, and node identity.
- `delivery-operations`: Retry scheduling, health status, dead-letter handling,
  administrative testing, and alerts for the Syslog delivery queue.
- `evidence-integrity`: Signed or chained event integrity, external anchoring,
  verification, and receiver deduplication identifiers.
- `audit-governance`: Retention classes, legal holds, archives, and protection
  of evidence that has not reached its required destination.
- `audit-investigation`: Structured filtering, self-access event coalescing, and
  integrity/delivery completeness reporting.

### Modified Capabilities

None. This repository does not yet contain baseline OpenSpec capability files.

## Impact

- Affects plugin settings, audit event schema, external-delivery functions,
  poller retry processing, administration screens, audit-list filtering, CLI
  reporting, documentation, and tests.
- Introduces outbound network connections controlled by Audit Log Admin and
  requires strict destination validation, TLS verification, bounded timeouts,
  secret redaction, and CSRF-protected test actions.
- Syslog delivery is the only remote transport. Integrity anchoring, governance,
  and investigation work remain separately reviewable tasks on the same feature
  branch.
