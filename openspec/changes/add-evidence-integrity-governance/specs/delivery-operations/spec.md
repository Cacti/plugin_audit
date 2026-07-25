## ADDED Requirements

### Requirement: Remote events are queued outside request processing
The plugin SHALL create a pending delivery row for each finalized event when
remote Syslog is enabled and SHALL perform network transmission from poller
processing rather than the originating web or CLI request.

#### Scenario: Web request finalizes while receiver is unavailable
- **WHEN** an audited web request finishes and the Syslog receiver is unavailable
- **THEN** the request can complete while a pending delivery remains available for the poller

### Requirement: Transient failures use bounded backoff
The plugin SHALL schedule transient failures using exponential backoff with
configurable base delay, maximum delay, maximum attempts, and batch size.

#### Scenario: Connection attempt fails
- **WHEN** TCP or TLS connection establishment fails transiently
- **THEN** attempts increment, a bounded error is stored, and `next_attempt` is scheduled in the future

#### Scenario: Retry is not yet due
- **WHEN** the poller selects queued deliveries
- **THEN** it excludes retry rows whose `next_attempt` is in the future

### Requirement: Permanent and exhausted failures enter dead-letter
The plugin SHALL move permanent failures and rows that reach maximum attempts to
dead-letter state.

#### Scenario: Maximum attempts reached
- **WHEN** a transient failure occurs on the configured final attempt
- **THEN** the row becomes `dead_letter` and is no longer retried automatically

#### Scenario: Administrator retries dead-letter rows
- **WHEN** an Audit Log Admin performs a CSRF-valid manual retry
- **THEN** selected rows return to pending, their retry schedule is reset, and the action is audited

### Requirement: Delivery health is visible
The plugin SHALL show Audit Log Admin the queue counts by state, oldest pending
age, last attempt, last successful socket send, and last bounded error.

#### Scenario: Queue exceeds a health threshold
- **WHEN** pending age or dead-letter count exceeds configured thresholds
- **THEN** the Audit interface displays a persistent warning and the transition is written to the Cacti log

### Requirement: Retention protects unfinished delivery
The plugin MUST NOT delete an event that has pending, retry, or dead-letter
remote delivery state when remote delivery is required by its retention class.

#### Scenario: Retention encounters a failed delivery
- **WHEN** an event is older than its normal retention age but has dead-letter delivery
- **THEN** the event and its delivery metadata remain available
