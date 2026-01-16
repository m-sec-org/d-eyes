## ADDED Requirements

### Requirement: Default required_capabilities From Task Catalog
Server MUST ensure scheduler capability filtering can be applied consistently by defaulting `metadata.required_capabilities` during task creation when the client does not provide it (the key is absent), using the task type definition from the task catalog.

#### Scenario: Server injects default required_capabilities for catalog-known task types
- **GIVEN** a client calls `POST /api/v1/tasks` with `type` set and without `metadata.required_capabilities`
- **AND** the Server task catalog contains the task type and defines a non-empty `capabilities[]` list for that task type
- **WHEN** the Server accepts the create request
- **THEN** the persisted task metadata MUST include `required_capabilities` populated from the catalog task type `capabilities[]` (comma-separated, in catalog order)
- **AND** subsequent scheduling MUST only lease the task to Agents whose advertised capabilities satisfy `required_capabilities`

#### Scenario: Explicit required_capabilities is preserved
- **GIVEN** a client provides `metadata.required_capabilities` explicitly in `POST /api/v1/tasks`
- **WHEN** the Server stores the task
- **THEN** the Server MUST NOT overwrite the provided value (even if it is empty)

#### Scenario: Unknown task type does not force a default
- **GIVEN** a client creates a task with a task type that is not present in the task catalog
- **WHEN** the Server stores the task
- **THEN** the Server MUST NOT inject `required_capabilities` automatically

#### Scenario: Catalog-known task type without capabilities does not force a default
- **GIVEN** a client creates a task with a task type present in the task catalog
- **AND** the catalog task type defines an empty `capabilities[]` list
- **WHEN** the Server stores the task without `metadata.required_capabilities`
- **THEN** the Server MUST NOT inject `required_capabilities` automatically
