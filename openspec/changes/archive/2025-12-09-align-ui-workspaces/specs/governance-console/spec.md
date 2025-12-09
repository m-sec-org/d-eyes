## ADDED Requirements
### Requirement: Compliance Workspace Highlight & Affixed Gaps
The governance console SHALL let users select frameworks, highlight the active row, and display gap timelines + remediation forms in fixed-height cards with Affix/Flex layouts.

#### Scenario: Framework selection feedback
- **GIVEN** multiple frameworks (CIS, ISO, 等保等)
- **WHEN** the operator clicks a framework card
- **THEN** the row SHALL highlight with the tokenized accent color, load control item cards with descriptions/tags, and keep the remediation timeline affixed while the form scrolls independently.

#### Scenario: Remediation timeline constraints
- **GIVEN** a remediation form contains >8 input groups
- **WHEN** the user scrolls
- **THEN** the timeline column remains sticky with progress indicators, while the form column enforces fixed heights and remembers the last two remediation notes inline.

### Requirement: Playbook Builder JSON Guidance
Playbook authoring SHALL provide a CodeBlock component for JSON fields plus inline validation and sample hints on each Form.Item.

#### Scenario: JSON field preview
- **GIVEN** a playbook step requires JSON payload
- **WHEN** the user focuses the field
- **THEN** the CodeBlock shows syntax-highlighted sample JSON, validation errors surface below with AntD help text, and hovering “示例” links fills the form with sample payloads for quick iteration.

### Requirement: BAS Scenario Modals & Drag Sort
BAS workbench SHALL open approve/publish/run operations in modals that include summary metadata, remark fields, and drag-sortable step lists showing action/timeout tags.

#### Scenario: Modal submit with destroyOnHidden
- **GIVEN** a reviewer opens the “审批 BAS 场景” modal
- **WHEN** they submit or cancel
- **THEN** the modal uses `destroyOnHidden`, shows summary pills (步骤数量/状态), requires remarks when rejecting, and step lists remain draggable with badges indicating sandbox usage or timeout thresholds.
