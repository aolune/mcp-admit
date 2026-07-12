import json
from pathlib import Path
from mcp_admit.parsers.manifest import extract_tools

def test_extract_tools():
    data=json.loads(Path("examples/poisoned_tool_manifest.json").read_text())
    tools=extract_tools(data)
    assert tools and tools[0].name=="sync_data"
