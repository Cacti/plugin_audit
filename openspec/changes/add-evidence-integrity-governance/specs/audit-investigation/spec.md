## ADDED Requirements

### Requirement: Investigators can filter normalized audit fields
Audit Log User SHALL be able to filter by event type, operation outcome,
category, target type and identifier, time range, correlation ID, node ID, and
poller ID in addition to existing filters.

#### Scenario: Multiple filters are applied
- **WHEN** an Audit Log User selects a time range, failure outcome, and node
- **THEN** the list and export contain only events satisfying every selected filter

### Requirement: Filter input is bounded and safely queried
The plugin MUST validate filter values, use prepared parameters, and bound time
range and result size where applicable.

#### Scenario: Invalid time or identifier filter is submitted
- **WHEN** a filter fails validation
- **THEN** the plugin rejects or normalizes it without constructing raw SQL

### Requirement: Low-value self-access events can be coalesced
The plugin SHALL coalesce only enumerated audit-list and detail-view events
within a bounded actor, session, event target, and time window.

#### Scenario: Repeated detail views occur in one window
- **WHEN** the same actor repeatedly views the same audit event within the configured window
- **THEN** one coalesced event records first time, last time, and occurrence count

#### Scenario: High-value audit action occurs
- **WHEN** a user exports, purges, changes settings, tests delivery, retries dead letters, or runs verification
- **THEN** the plugin records the action individually and does not coalesce it

### Requirement: Administrators can verify integrity and delivery completeness
The plugin SHALL provide a read-only CLI report and Audit Log Admin view that
verify event hashes, chain continuity, checkpoint coverage, queue state, and
delivery completeness for a bounded range.

#### Scenario: Verification finds no gaps
- **WHEN** all events and delivery records in the selected range are consistent
- **THEN** the report returns success with counts and terminal integrity values

#### Scenario: Verification finds corruption or delivery gaps
- **WHEN** a hash mismatch, sequence gap, missing checkpoint, or unfinished required delivery exists
- **THEN** the report returns failure, identifies the affected range, and does not modify evidence
