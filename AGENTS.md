# AGENTS.md

## How to run tests
- `uv run pytest`
- `python -m pytest`
- Windows local venv: `.\.venv\Scripts\python.exe -m pytest`

## How to run lint
- `uv run ruff check .`
- Windows local venv: `.\.venv\Scripts\python.exe -m ruff check .`

## How to run CLI locally
- `uv run python -m mcp_admit scan examples/dangerous_stdio_config.json`
- Windows local venv: `.\.venv\Scripts\mcp-admit.exe scan examples/dangerous_stdio_config.json`

## Windows development
- Use the repository-local `.venv` and keep any proxy configuration scoped to this repository.

## Security constraints
- Never execute scanned MCP commands during tests or implementation.
- Never print secret values.
- No network access in tests.

## Coding style
- Small pure functions.
- Deterministic rules.
- Explainable findings.
- Preserve static-first design.
