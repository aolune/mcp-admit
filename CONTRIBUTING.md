# Contributing to MCP Admit

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
```

On macOS or Linux, use the equivalent interpreter under `.venv/bin/python` or run the documented `uv` commands.

## Design rules

- Preserve static-first and no-exec-by-default behavior.
- Prefer deterministic, explainable rules over network services or model judgments.
- Treat a capability as an admission input, not proof that a server is malicious.
- Keep evidence precise and redact secret values.
- Use fail-closed defaults for policy and approval workflows.
- Scope findings to stable rule IDs and include a concrete remediation.

## Adding a rule

1. Add or update the deterministic detector.
2. Register rule metadata in `src/mcp_admit/rules/catalog.py`.
3. Add OWASP mapping where the existing family mapping is insufficient.
4. Add both a triggering fixture and a benign near-match when false positives are plausible.
5. Update `examples/fixture_matrix.yaml` and focused tests.
6. Verify JSON, Markdown, and SARIF output when the public finding contract changes.

## Required checks

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mcp_admit benchmark examples\fixture_matrix.yaml
.\.venv\Scripts\python.exe -m mcp_admit release-check
```

Tests must not make network requests or execute commands from scanned MCP configurations.
