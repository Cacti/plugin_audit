## ADDED Requirements

### Requirement: Finalized audit events are authenticated
The plugin SHALL calculate an HMAC-SHA-256 value over a canonical representation
of every immutable finalized event field and SHALL record the key identifier
used without storing the key in the audit row.

#### Scenario: Protected content changes
- **WHEN** any protected event field is modified after finalization
- **THEN** integrity verification reports a mismatch

### Requirement: Integrity values form a node-specific chain
The plugin SHALL assign a monotonically increasing node sequence and SHALL bind
each finalized event to the preceding chain value for that node.

#### Scenario: Event is removed from the middle of a chain
- **WHEN** verification processes the remaining sequence
- **THEN** it reports the missing sequence or previous-value mismatch

#### Scenario: Concurrent events finalize
- **WHEN** multiple requests finalize concurrently on one node
- **THEN** sequence allocation produces one deterministic order without duplicate sequence numbers

### Requirement: Integrity checkpoints are delivered remotely
The plugin SHALL periodically create checkpoint records containing node ID,
sequence range, terminal chain value, key ID, and checkpoint time and SHALL
queue them for Syslog delivery.

#### Scenario: Local history is rewritten after checkpoint delivery
- **WHEN** a verifier compares local state with an independently retained checkpoint
- **THEN** it reports the inconsistent range

### Requirement: Key rotation preserves verification
The plugin SHALL support active and historical key identifiers so records remain
verifiable across key rotation.

#### Scenario: Administrator activates a new key
- **WHEN** a new integrity key becomes active
- **THEN** new events use its key ID while historical events retain their original key IDs

### Requirement: Receiver deduplication identity is stable
The plugin SHALL reuse an event UUID for all transmissions of the same event and
SHALL document UUID as the receiver deduplication key.

#### Scenario: Receiver receives a duplicate
- **WHEN** a retry produces another copy of an already observed event UUID
- **THEN** the receiver can identify it as the same logical event
