## 1. API Design
- [x] 1.1 Draft `ThreatIntelProvider`, `SandboxController`, and `RuleEngineFactory` interfaces with default structs.
- [x] 1.2 Specify factory wiring for CLI + remote initializers.

## 2. Implementation
- [x] 2.1 Refactor `taskRequest.initThreatIntel` and related code to use the provider.
- [x] 2.2 Update BAS/sandbox consumers to operate via the controller abstraction.
- [x] 2.3 Introduce rule engine factory hooks in detect backend.

## 3. Testing
- [x] 3.1 Add unit tests using fake providers/controllers/factories to ensure injection works.

## 4. Documentation
- [x] 4.1 Update README/PLUGIN_GUIDE describing new core-service injection points.
