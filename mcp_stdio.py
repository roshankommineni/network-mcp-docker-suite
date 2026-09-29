"""Run a server from the Network MCP Docker Suite over stdio, without Docker.

The upstream servers in this repo are written to run as long-lived HTTP services
inside containers: each one hardcodes ``mcp.run(transport="http", ...)`` in its
``__main__`` block and prints a banner to stdout on import. Neither is usable
from an MCP client that speaks stdio, and this host has no Docker.

This launcher adapts them instead of modifying them, so ``git pull`` stays clean:

* resolves configuration from the process environment, then ``.env``, then the
  OS credential store (Windows Credential Manager via ``keyring``),
* imports the server module with stdout redirected to stderr, so the banner
  cannot corrupt the JSON-RPC stream,
* runs the module's FastMCP instance over stdio.

Usage::

    python mcp_stdio.py ise
    python mcp_stdio.py catc
    python mcp_stdio.py catc --check
    python mcp_stdio.py ise --store-password

Secrets are never printed, and never written to this file or to .env by the
``--store-password`` helper; that helper puts them in the OS credential store.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import importlib.util
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

#: Service name used for entries in the OS credential store. Entries are keyed
#: by the environment variable they satisfy, e.g. ("network-mcp-suite",
#: "ISE_PASSWORD"). This mirrors the pattern used by the cisco-net-mcp server.
KEYRING_SERVICE = os.environ.get("NETWORK_MCP_KEYRING_SERVICE", "network-mcp-suite")


@dataclass(frozen=True)
class ServerSpec:
    """One server in the suite, and what it needs before it can be imported."""

    key: str
    directory: str
    module_file: str
    description: str
    #: Variables the module asserts on at import time. Missing ones abort early
    #: with guidance rather than an opaque ValueError from the module body.
    required: tuple[str, ...]
    #: Subset of ``required`` that holds a secret and may come from the keyring.
    secrets: tuple[str, ...] = ()
    #: Values applied only when the variable is not already set.
    defaults: dict[str, str] = field(default_factory=dict)

    @property
    def module_path(self) -> Path:
        return REPO_ROOT / self.directory / self.module_file

    @property
    def module_name(self) -> str:
        return self.module_file.removesuffix(".py")


# Only the servers that have been configured for this workspace are registered.
#
# ios-xe-mcp-server is deliberately NOT registered: it reaches Cisco device CLIs
# over SSH with netmiko, which this workspace routes exclusively through the
# cisco-net-mcp read-only server. Adding entries here for meraki, netbox,
# thousandeyes, splunk, prometheus, clickhouse or gitlab is a one-line change
# once credentials for those platforms exist.
SERVERS: dict[str, ServerSpec] = {
    "ise": ServerSpec(
        key="ise",
        directory="ise-mcp-server",
        module_file="ise_mcp_server.py",
        description="Cisco Identity Services Engine (ERS + MnT via the API Gateway)",
        required=("ISE_HOST", "ISE_USERNAME", "ISE_PASSWORD"),
        secrets=("ISE_PASSWORD",),
        defaults={"ISE_VERSION": "1.0", "ISE_REQUEST_TIMEOUT": "30"},
    ),
    "catc": ServerSpec(
        key="catc",
        directory="catc-mcp-server",
        module_file="catc_mcp_server.py",
        description="Cisco Catalyst Center (inventory, assurance, sites, compliance)",
        required=("CATC_URL", "CATC_USERNAME", "CATC_PASSWORD"),
        secrets=("CATC_PASSWORD",),
    ),
}

#: Values shipped in .env.example. Treated as absent so a half-edited .env
#: produces an actionable setup error instead of a puzzling 401 from the API.
PLACEHOLDERS = frozenset(
    {
        "ise.company.com",
        "ise-service-account",
        "SecurePassword123!",
        "https://catalyst-center.example.com",
        "your_catalyst_center_username",
        "your_catalyst_center_password",
    }
)


def log(message: str) -> None:
    """Write progress to stderr; stdout belongs to the JSON-RPC stream."""
    print(message, file=sys.stderr)


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a dotenv-style file into a mapping, ignoring comments and blanks."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        # Strip trailing inline comments, as used throughout .env.example.
        value = value.split(" #", 1)[0].split("\t#", 1)[0]
        values[key.strip()] = value.strip().strip("'\"")
    return values


def from_keyring(variable: str) -> str | None:
    """Look up a secret in the OS credential store, if keyring is available."""
    try:
        import keyring
    except ImportError:
        return None
    try:
        return keyring.get_password(KEYRING_SERVICE, variable)
    except Exception as exc:  # backend unavailable or locked
        log(f"  keyring lookup for {variable} failed: {type(exc).__name__}: {exc}")
        return None


def resolve_environment(spec: ServerSpec) -> tuple[dict[str, str], list[str]]:
    """Populate os.environ for the server. Returns (sources, missing).

    Precedence: existing process environment, then .env, then the credential
    store. The process environment wins so an MCP client's env block or a shell
    override is always authoritative.
    """
    sources: dict[str, str] = {}
    dotenv = parse_env_file(REPO_ROOT / ".env")

    candidates = list(spec.required) + [k for k in spec.defaults if k not in spec.required]
    for variable in candidates:
        current = os.environ.get(variable, "").strip()
        if current and current not in PLACEHOLDERS:
            sources[variable] = "environment"
            continue

        value = dotenv.get(variable, "").strip()
        if value and value not in PLACEHOLDERS:
            os.environ[variable] = value
            sources[variable] = ".env"
            continue

        if variable in spec.secrets:
            stored = from_keyring(variable)
            if stored:
                os.environ[variable] = stored
                sources[variable] = f"keyring:{KEYRING_SERVICE}"
                continue

        if variable in spec.defaults:
            os.environ[variable] = spec.defaults[variable]
            sources[variable] = "default"

    # Pass through the optional, non-required settings each server understands.
    for variable, value in dotenv.items():
        if variable.startswith(("ISE_", "CATC_")) and variable not in os.environ:
            if value and value not in PLACEHOLDERS:
                os.environ[variable] = value

    missing = [v for v in spec.required if not os.environ.get(v, "").strip()]
    return sources, missing


def describe(spec: ServerSpec, sources: dict[str, str], missing: list[str]) -> None:
    """Report where each setting came from, without revealing any secret."""
    log(f"{spec.key}: {spec.description}")
    for variable in spec.required + tuple(k for k in spec.defaults if k not in spec.required):
        origin = sources.get(variable, "unset")
        if variable in spec.secrets:
            shown = "***set***" if os.environ.get(variable) else "<missing>"
        else:
            shown = os.environ.get(variable) or "<missing>"
        log(f"  {variable} = {shown}  [{origin}]")
    if missing:
        log("")
        log(f"Missing required setting(s): {', '.join(missing)}")
        log("Provide them by either:")
        log(f"  - editing {REPO_ROOT / '.env'}, or")
        log(f"  - storing the password: python mcp_stdio.py {spec.key} --store-password")


def load_server_module(spec: ServerSpec):
    """Import the upstream server module with its banner kept off stdout."""
    module_path = spec.module_path
    if not module_path.is_file():
        raise FileNotFoundError(f"server module not found: {module_path}")

    # The module is written to be run from its own directory; make relative
    # lookups behave and keep its own dotenv loader from re-reading the root
    # .env (which would override the precedence resolved above).
    server_dir = str(module_path.parent)
    if server_dir not in sys.path:
        sys.path.insert(0, server_dir)
    os.chdir(server_dir)

    loader_spec = importlib.util.spec_from_file_location(spec.module_name, module_path)
    if loader_spec is None or loader_spec.loader is None:
        raise ImportError(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(loader_spec)
    sys.modules[spec.module_name] = module

    with contextlib.redirect_stdout(sys.stderr):
        loader_spec.loader.exec_module(module)
    return module


def store_password(spec: ServerSpec) -> int:
    """Prompt for each secret and save it in the OS credential store."""
    try:
        import keyring
    except ImportError:
        log("the 'keyring' package is not installed in this interpreter")
        return 1
    if not spec.secrets:
        log(f"{spec.key} has no secret settings")
        return 0
    for variable in spec.secrets:
        secret = getpass.getpass(f"Value for {variable} (input hidden): ")
        if not secret:
            log(f"skipped {variable} (empty input)")
            continue
        keyring.set_password(KEYRING_SERVICE, variable, secret)
        log(f"stored {variable} in credential store '{KEYRING_SERVICE}'")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a Network MCP Docker Suite server over stdio, without Docker.",
    )
    parser.add_argument("server", choices=sorted(SERVERS), help="which server to run")
    parser.add_argument(
        "--check",
        action="store_true",
        help="resolve and report configuration, import the module, then exit",
    )
    parser.add_argument(
        "--store-password",
        action="store_true",
        help="prompt for this server's secret(s) and save them in the OS credential store",
    )
    args = parser.parse_args(argv)
    spec = SERVERS[args.server]

    if args.store_password:
        return store_password(spec)

    sources, missing = resolve_environment(spec)
    if args.check or missing:
        describe(spec, sources, missing)
    if missing:
        return 1

    module = load_server_module(spec)
    server = getattr(module, "mcp", None)
    if server is None:
        log(f"{spec.module_name} does not expose a FastMCP instance named 'mcp'")
        return 1

    if args.check:
        import anyio

        tools = anyio.run(server.list_tools)
        names = sorted(getattr(tool, "name", str(tool)) for tool in tools)
        log("")
        log(f"import OK - {len(names)} tool(s) registered")
        for name in names:
            log(f"  {name}")
        return 0

    log(f"{spec.key}: serving {spec.description} over stdio")
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
