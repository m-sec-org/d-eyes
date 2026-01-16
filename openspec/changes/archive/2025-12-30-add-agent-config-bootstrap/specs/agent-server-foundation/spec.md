## ADDED Requirements

### Requirement: Default Config File Bootstrap
When the agent is launched without an explicit config path, it MUST ensure a default config file exists at the default location so operators can discover and customize settings.

#### Scenario: Create default config on first run
- **GIVEN** no `--config` flag is set and `D_EYES_CONFIG` is unset
- **AND** the resolved default config path does not exist (`$HOME/.d-eyes/config.yaml`, or `os.TempDir()/d-eyes/config.yaml` when home is unavailable)
- **WHEN** the agent initializes its global configuration
- **THEN** it MUST create the parent directory if missing
- **AND** it MUST write a `config.yaml` containing the built-in defaults (loading it produces the same effective config as in-memory defaults)
- **AND** it MUST create the file with restrictive permissions (POSIX: dir `0700`, file `0600`) and avoid partial files (atomic write or equivalent)

#### Scenario: Existing config is preserved
- **GIVEN** a config file already exists at the resolved path
- **WHEN** the agent starts
- **THEN** it MUST NOT overwrite the file and MUST load the existing content

#### Scenario: Help/version still bootstraps the default config
- **GIVEN** no `--config` flag is set and `D_EYES_CONFIG` is unset
- **AND** the resolved default config path does not exist
- **WHEN** an operator runs `d-eyes --help` or `d-eyes version`
- **THEN** the agent MUST create the default config file at the resolved path before exiting

#### Scenario: Unwritable default path does not block execution
- **GIVEN** the resolved default config path is not writable
- **WHEN** the agent starts
- **THEN** it MUST continue using in-memory defaults
- **AND** it MUST emit a warning unless running in quiet mode
