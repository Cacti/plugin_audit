## ADDED Requirements

### Requirement: Events have explicit retention classes
The plugin SHALL assign events to configurable retention classes with retention
age, remote-delivery requirement, archive requirement, and purge eligibility.

#### Scenario: Event reaches class retention age
- **WHEN** the event is not held and all class prerequisites are complete
- **THEN** retention may archive or delete it according to the class policy

### Requirement: Legal hold prevents deletion
Audit Log Admin SHALL be able to place and release legal holds with a reason,
actor, time, and optional case identifier.

#### Scenario: Retention processes a held event
- **WHEN** an event or covered range is under legal hold
- **THEN** retention and purge leave the event unchanged

#### Scenario: Administrator releases a hold
- **WHEN** an Audit Log Admin releases a hold
- **THEN** the release is audited and subsequent retention evaluates the event normally

### Requirement: Archives include integrity metadata
An archive SHALL include event count, event and time ranges, node ranges,
terminal integrity values, policy identity, creation time, and a manifest
authentication value.

#### Scenario: Archive verification succeeds
- **WHEN** an archive manifest and its events are unchanged
- **THEN** the verification command reports matching counts, ranges, and integrity values

### Requirement: Purge obeys governance restrictions
Purge MUST exclude legal-hold events and evidence with incomplete required
delivery or archival prerequisites.

#### Scenario: Purge selection contains protected evidence
- **WHEN** Audit Log Admin requests a purge covering protected and eligible events
- **THEN** only eligible events are deleted and the result reports protected and deleted counts
