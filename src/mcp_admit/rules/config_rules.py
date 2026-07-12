from __future__ import annotations

import re
from urllib.parse import urlparse

from mcp_admit.models import Finding
from mcp_admit.redaction import redact_secret_value, redact_text

SHELL_LAUNCHERS = {"bash", "sh", "powershell", "pwsh", "cmd"}
SHELL_ARG_PATTERNS = [
    "curl",
    "wget",
    "nc ",
    "ncat",
    "base64",
    "eval",
    "rm -rf",
    "chmod",
    "ssh",
    "scp",
    "python -c",
    "node -e",
    "ruby -e",
    "perl -e",
]
PACKAGE_LAUNCHERS = {"npx", "uvx", "pipx", "bunx"}
PACKAGE_LAUNCHER_SUBCOMMANDS = {("pnpm", "dlx")}
CONTAINER_LAUNCHERS = {"docker", "podman"}
SECRET_NAMES = [
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN",
]
PRIVILEGED_CONTAINER_FLAGS = {
    "--privileged",
    "--pid=host",
    "--ipc=host",
    "--userns=host",
}
ELEVATED_CONTAINER_FLAG_PREFIXES = (
    "--cap-add",
    "--device",
)
SENSITIVE_HOST_MOUNT_MARKERS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/.ssh",
    "/.aws",
    "/.kube",
    "/:/",
    "source=/,",
    "src=/,",
    "source=/var/run/docker.sock",
    "src=/var/run/docker.sock",
)
CONTAINER_OPTIONS_WITH_VALUES = {
    "--add-host",
    "--entrypoint",
    "--env",
    "--mount",
    "--name",
    "--net",
    "--network",
    "--user",
    "--volume",
    "--workdir",
    "-e",
    "-u",
    "-v",
    "-w",
}
SECRET_VALUE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{12,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
]


def _finding(**kwargs) -> Finding:
    return Finding(**kwargs)


def _joined_command(command: str, args: list[object]) -> str:
    return " ".join([command, *(str(arg) for arg in args)]).strip()


def _package_is_pinned(package: str) -> bool:
    if not package or package.startswith("-"):
        return True
    if package.endswith("@latest"):
        return False
    if package.startswith("@"):
        return package.count("@") >= 2
    return "@" in package


def _first_package_arg(args: list[object]) -> str:
    for arg in args:
        value = str(arg)
        if value.startswith("-") or value == "dlx":
            continue
        return value
    return ""


def _is_package_launch(cmd_name: str, args: list[object]) -> bool:
    if cmd_name in PACKAGE_LAUNCHERS:
        return True
    first = str(args[0]).lower() if args else ""
    return (cmd_name, first) in PACKAGE_LAUNCHER_SUBCOMMANDS


def _downloads_script_to_shell(joined: str) -> bool:
    lowered = joined.lower()
    has_download = "curl " in lowered or "wget " in lowered
    has_shell_pipe = "| sh" in lowered or "| bash" in lowered or "bash <(" in lowered or "sh <(" in lowered
    return has_download and has_shell_pipe


def _is_private_host(host: str) -> bool:
    return (
        host in {"localhost", "169.254.169.254"}
        or host.startswith("127.")
        or re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", host) is not None
    )


def _is_suspicious_public_host(host: str) -> bool:
    markers = (
        "ngrok",
        "webhook.site",
        "requestbin",
        "pipedream",
        "localhost.run",
        "trycloudflare",
    )
    return any(marker in host for marker in markers)


def _server_location(path: str, name: str, suffix: str, server_path: str | None) -> str:
    base = server_path or f"{path}.mcpServers.{name}"
    return f"{base}.{suffix}"


def _is_container_launch(cmd_name: str, args: list[object], joined: str) -> bool:
    if cmd_name in CONTAINER_LAUNCHERS:
        return True
    lowered = joined.lower()
    return "docker run" in lowered or "podman run" in lowered


def _has_next_arg(args: list[str], index: int, expected: str) -> bool:
    return index + 1 < len(args) and args[index + 1].lower() == expected


def _uses_host_network(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        value = arg.lower()
        if value in {"--network=host", "--net=host"}:
            return True
        if value in {"--network", "--net"} and _has_next_arg(args, index, "host"):
            return True
    return False


def _uses_privileged_container_options(args: list[str]) -> bool:
    for arg in args:
        value = arg.lower()
        if value in PRIVILEGED_CONTAINER_FLAGS:
            return True
        if any(value == prefix or value.startswith(f"{prefix}=") for prefix in ELEVATED_CONTAINER_FLAG_PREFIXES):
            return True
    return False


def _mounts_sensitive_host_path(args: list[str]) -> bool:
    lowered_args = [arg.lower() for arg in args]
    mount_values = []
    for index, value in enumerate(lowered_args):
        if value in {"-v", "--volume", "--mount"} and index + 1 < len(lowered_args):
            mount_values.append(lowered_args[index + 1])
        elif value.startswith("--volume=") or value.startswith("--mount="):
            mount_values.append(value)

    return any(marker in mount for mount in mount_values for marker in SENSITIVE_HOST_MOUNT_MARKERS)


def _container_image_arg(args: list[str]) -> str:
    skip_next = False
    saw_run = False
    for arg in args:
        value = arg.lower()
        if skip_next:
            skip_next = False
            continue
        if value == "run":
            saw_run = True
            continue
        if not saw_run:
            continue
        if value in CONTAINER_OPTIONS_WITH_VALUES:
            skip_next = True
            continue
        if value.startswith("-"):
            continue
        return arg
    return ""


def _container_image_is_unpinned(image: str) -> bool:
    if not image:
        return False
    if "@sha256:" in image:
        return False
    image_name = image.rsplit("/", 1)[-1]
    if ":" not in image_name:
        return True
    return image_name.endswith(":latest")


def _scan_container_launch(
    findings: list[Finding],
    *,
    name: str,
    path: str,
    server_path: str | None,
    cmd_name: str,
    args: list[object],
    joined: str,
) -> None:
    arg_texts = [str(arg) for arg in args]
    if not _is_container_launch(cmd_name, args, joined):
        return

    if _uses_privileged_container_options(arg_texts):
        findings.append(
            _finding(
                id="MCPG-STDIO-004",
                title="privileged container launch",
                severity="critical",
                category="stdio",
                capability="container_escape",
                location=_server_location(path, name, "args", server_path),
                evidence=redact_text(joined),
                reason="Container launch grants privileged mode, host namespaces, devices, or elevated Linux capabilities.",
                recommendation="Remove privileged flags and run the MCP server with least-privilege container isolation.",
                risk_score=90,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
            )
        )

    if _mounts_sensitive_host_path(arg_texts):
        findings.append(
            _finding(
                id="MCPG-STDIO-005",
                title="sensitive host mount into container",
                severity="critical",
                category="stdio",
                capability="container_escape",
                location=_server_location(path, name, "args", server_path),
                evidence=redact_text(joined),
                reason="Container launch bind-mounts sensitive host paths such as Docker socket, root, SSH, cloud, or kube credentials.",
                recommendation="Avoid host-sensitive bind mounts; expose only narrow read-only paths after approval.",
                risk_score=90,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
            )
        )

    if _uses_host_network(arg_texts):
        findings.append(
            _finding(
                id="MCPG-STDIO-006",
                title="host network namespace in container launch",
                severity="high",
                category="stdio",
                capability="network_fetch",
                location=_server_location(path, name, "args", server_path),
                evidence=redact_text(joined),
                reason="Container launch uses the host network namespace, bypassing normal container network isolation.",
                recommendation="Use isolated container networking and explicitly approved egress instead of host networking.",
                risk_score=70,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.9,
            )
        )

    image = _container_image_arg(arg_texts)
    if _container_image_is_unpinned(image):
        findings.append(
            _finding(
                id="MCPG-STDIO-007",
                title="unpinned container image",
                severity="high",
                category="supply_chain",
                capability="supply_chain",
                location=_server_location(path, name, "args", server_path),
                evidence=redact_text(image),
                reason="Container launch uses an image without a stable tag or immutable digest.",
                recommendation="Pin container images by immutable digest or an approved version tag.",
                risk_score=70,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.85,
            )
        )


def scan_server(
    name: str,
    server: dict,
    path: str,
    server_path: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    cmd = str(server.get("command", ""))
    args = server.get("args", [])
    args = args if isinstance(args, list) else []
    env = server.get("env", {})
    transport = str(server.get("transport", ""))
    url = str(server.get("url", ""))
    joined = _joined_command(cmd, args)
    cmd_name = cmd.lower().split("\\")[-1].split("/")[-1]

    if cmd or transport == "stdio":
        findings.append(
            _finding(
                id="MCPG-STDIO-001",
                title="stdio command configured",
                severity="high",
                category="stdio",
                capability="code_exec",
                location=_server_location(path, name, "command", server_path),
                evidence=redact_text(joined or "stdio"),
                reason="Local stdio servers expand the execution boundary before tool metadata is trusted.",
                recommendation="Review before connecting; prefer pinned packages and a sandboxed execution profile.",
                risk_score=65,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.95,
            )
        )

    if _is_package_launch(cmd_name, args):
        package = _first_package_arg(args)
        if not _package_is_pinned(package):
            findings.append(
                _finding(
                    id="MCPG-STDIO-002",
                    title="unpinned package execution",
                    severity="high",
                    category="supply_chain",
                    capability="supply_chain",
                    location=_server_location(path, name, "args", server_path),
                    evidence=redact_text(joined),
                    reason="Package launcher command does not pin the MCP server package version or digest.",
                    recommendation="Pin package versions or digests before approving this server.",
                    risk_score=70,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.9,
                )
            )

    if _downloads_script_to_shell(joined):
        findings.append(
            _finding(
                id="MCPG-STDIO-008",
                title="downloaded script execution",
                severity="critical",
                category="supply_chain",
                capability="shell_exec",
                location=_server_location(path, name, "command", server_path),
                evidence=redact_text(joined),
                reason="Launch command downloads remote content and pipes it into a shell.",
                recommendation="Do not execute downloaded scripts; pin and review the server package or image instead.",
                risk_score=90,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
            )
        )

    if cmd_name in SHELL_LAUNCHERS or any(pattern in joined.lower() for pattern in SHELL_ARG_PATTERNS):
        findings.append(
            _finding(
                id="MCPG-STDIO-003",
                title="dangerous shell command",
                severity="critical",
                category="stdio",
                capability="shell_exec",
                location=_server_location(path, name, "command", server_path),
                evidence=redact_text(joined),
                reason="Shell or command-execution pattern detected in MCP server launch configuration.",
                recommendation="Deny by default, or require explicit approval plus a sandbox and command allowlist.",
                risk_score=90,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
            )
        )

    _scan_container_launch(
        findings,
        name=name,
        path=path,
        server_path=server_path,
        cmd_name=cmd_name,
        args=args,
        joined=joined,
    )

    for key, value in env.items() if isinstance(env, dict) else []:
        key_upper = str(key).upper()
        value_text = str(value)
        if any(secret_name in key_upper for secret_name in SECRET_NAMES):
            findings.append(
                _finding(
                    id="MCPG-SECRET-001",
                    title="secret-like environment variable configured",
                    severity="high",
                    category="secret",
                    capability="credential_access",
                    location=_server_location(path, name, f"env.{key}", server_path),
                    evidence=f"{key}={redact_secret_value(value_text)}",
                    reason="Secret-like environment variable is passed into the MCP server runtime.",
                    recommendation="Use scoped short-lived credentials and avoid passing broad secrets to tools.",
                    risk_score=75,
                    risk_level="L4",
                    policy_action="deny",
                    confidence=0.9,
                )
            )
        if any(pattern.search(value_text) for pattern in SECRET_VALUE_PATTERNS):
            findings.append(
                _finding(
                    id="MCPG-SECRET-002",
                    title="secret-like environment value configured",
                    severity="high",
                    category="secret",
                    capability="credential_access",
                    location=_server_location(path, name, f"env.{key}", server_path),
                    evidence=f"{key}={redact_secret_value(value_text)}",
                    reason="Environment value resembles a token, key, or signed credential.",
                    recommendation="Rotate exposed test secrets and inject scoped credentials at runtime only.",
                    risk_score=80,
                    risk_level="L4",
                    policy_action="deny",
                    confidence=0.9,
                )
            )

    if not url:
        return findings

    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme != "https":
        findings.append(
            _finding(
                id="MCPG-NET-001",
                title="non-https remote MCP url",
                severity="medium",
                category="supply_chain",
                capability="network_fetch",
                location=_server_location(path, name, "url", server_path),
                evidence=redact_text(url),
                reason="Remote MCP URL does not use HTTPS.",
                recommendation="Require HTTPS and certificate validation for remote MCP servers.",
                risk_score=35,
                risk_level="L2",
                policy_action="allow_with_constraints",
                confidence=0.9,
            )
        )

    host = (parsed.hostname or "").lower()
    if _is_private_host(host):
        findings.append(
            _finding(
                id="MCPG-NET-002",
                title="localhost/private/metadata MCP url",
                severity="high",
                category="supply_chain",
                capability="network_fetch",
                location=_server_location(path, name, "url", server_path),
                evidence=redact_text(url),
                reason="Remote MCP URL points to a local, private, or cloud metadata endpoint.",
                recommendation="Block private and metadata endpoints unless explicitly reviewed.",
                risk_score=80,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
            )
        )

    if _is_suspicious_public_host(host):
        findings.append(
            _finding(
                id="MCPG-NET-003",
                title="suspicious tunnel or webhook MCP url",
                severity="high",
                category="supply_chain",
                capability="network_fetch",
                location=_server_location(path, name, "url", server_path),
                evidence=redact_text(url),
                reason="Remote MCP URL uses a tunnel, request bin, or transient webhook-style host.",
                recommendation="Use a stable reviewed service endpoint with explicit ownership before approval.",
                risk_score=70,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.85,
            )
        )

    return findings
