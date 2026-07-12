import json
from mcp_admit.models import ScanResult

def render_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(), indent=2)
