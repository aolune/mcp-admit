from mcp_admit.scanner import scan_path

def test_gate_fail_high():
    r=scan_path("examples/dangerous_stdio_config.json")
    assert r.summary.gate_result=="fail"
