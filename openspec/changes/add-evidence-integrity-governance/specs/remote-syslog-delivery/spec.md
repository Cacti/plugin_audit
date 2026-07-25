## ADDED Requirements

### Requirement: Administrators can configure remote Syslog
The plugin SHALL allow Audit Log Admin users to enable remote Syslog and
configure receiver hostname or IP, port, transport, payload format, facility,
application name, node identity, timeout, and message-size limit.

#### Scenario: Save valid Syslog configuration
- **WHEN** an Audit Log Admin submits a valid Syslog configuration
- **THEN** the plugin stores the configuration and excludes sensitive values from audit event payloads

#### Scenario: Reject invalid receiver configuration
- **WHEN** an administrator submits a receiver containing a URI scheme, control characters, embedded credentials, an invalid port, or an excessive timeout
- **THEN** the plugin rejects the configuration without attempting a network connection

### Requirement: Syslog supports UDP TCP and TLS transports
The plugin SHALL send Syslog using UDP, TCP, or TLS according to the configured
transport and SHALL default TLS to port 6514 with peer and hostname verification.

#### Scenario: UDP send succeeds locally
- **WHEN** the complete datagram is accepted by the local UDP socket
- **THEN** the delivery state becomes `sent_unconfirmed` and the plugin does not claim receiver acknowledgement

#### Scenario: TCP send succeeds locally
- **WHEN** a complete RFC 6587 framed record is written to the TCP socket
- **THEN** the delivery state becomes `sent_unconfirmed`

#### Scenario: TLS verification fails
- **WHEN** the receiver certificate cannot be verified under the configured TLS policy
- **THEN** the delivery attempt fails, records a bounded error, and becomes eligible for retry

### Requirement: Syslog records use standardized formats
The plugin SHALL emit an RFC 5424 header and SHALL support RFC 5424 structured
data, CEF, or compact JSON as the message payload.

#### Scenario: Format an RFC 5424 record
- **WHEN** a finalized audit event is formatted for Syslog
- **THEN** the record contains valid PRI, version, UTC timestamp, node identity, application name, poller identity, message ID, and escaped structured data

#### Scenario: Format a CEF record
- **WHEN** CEF is selected
- **THEN** event UUID, actor, source IP, action, outcome, target, severity, node, and correlation ID are mapped to escaped CEF fields

#### Scenario: Format a JSON record
- **WHEN** JSON is selected
- **THEN** the RFC 5424 message contains one compact JSON object with bounded normalized audit data

### Requirement: UDP records are bounded without silent truncation
The plugin MUST reject a UDP record that exceeds the configured maximum datagram
size and MUST NOT truncate or split an audit event silently.

#### Scenario: UDP record exceeds the maximum
- **WHEN** a formatted UDP record is larger than the configured maximum
- **THEN** the delivery enters dead-letter state with an `udp_message_too_large` error

### Requirement: Remote delivery includes stable identity
Every remote record SHALL include event UUID, correlation ID, stable node ID,
and poller ID when available.

#### Scenario: Receiver observes a retried event
- **WHEN** the same event is transmitted more than once after a local failure
- **THEN** every transmission uses the same event UUID and node identity

### Requirement: Syslog test actions are privileged and audited
Only Audit Log Admin SHALL be able to test the receiver, and test actions MUST
use POST and CSRF protection.

#### Scenario: Audit user attempts a delivery test
- **WHEN** a user without Audit Log Admin invokes the test action
- **THEN** the plugin returns HTTP 403 and sends no test record

#### Scenario: Administrator sends a test record
- **WHEN** an Audit Log Admin submits a CSRF-valid test request
- **THEN** the plugin sends a clearly identified test event and audits the test result without storing secrets
