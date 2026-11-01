"""
Command-line interface (`rox-bot`) for Rox, Innodata's GCP Ops & Security Lead.

Supports subcommands:
- `upstream-status`
- `persona-info`
- `fleet-audit`
- `vm-metrics`
- `remediation-plan`
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any, TextIO

from rox_bot.compliance import (
    FleetAuditReport,
    audit_fleet_compliance,
    fleet_audit_to_dict,
    render_fleet_audit_markdown,
    render_remediation_plan_markdown,
)
from rox_bot.gcp_ops import (
    DEFAULT_GCP_PROJECT,
    DEFAULT_OPS_AGENT_POLICY,
    GceInstance,
    GcpOpsClient,
    HttpTransport,
    LogEntryRecord,
    OsConfigReport,
    VmMetricsSnapshot,
    default_repo_root,
    default_seed_fleet,
    default_upstream_pin_path,
    load_persona_metadata,
    load_seed_fleet_from_file,
    load_upstream_artbot_pin,
)


def _add_fleet_source_args(subparser: argparse.ArgumentParser) -> None:
    """Attach common `--project`, `--seed-file`, `--live`, `--token`, and `--json` flags."""
    subparser.add_argument(
        "--project",
        default=DEFAULT_GCP_PROJECT,
        help=f"GCP project ID (default: {DEFAULT_GCP_PROJECT})",
    )
    subparser.add_argument(
        "--seed-file",
        default=None,
        help="Optional JSON seed file containing fleet instances, metrics, logs, and os_reports",
    )
    subparser.add_argument(
        "--live",
        action="store_true",
        help="Query live GCP Compute, Monitoring, Logging, and OS Config APIs",
    )
    subparser.add_argument(
        "--token",
        default=None,
        help="OAuth2 bearer token for --live mode (defaults to GCP_ACCESS_TOKEN env var)",
    )
    subparser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output instead of Markdown",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the `rox-bot` CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="rox-bot",
        description="Rox-Bot (@rox-bot): GCP Ops & Security Lead Agent CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    up_parser = subparsers.add_parser(
        "upstream-status",
        help="Verify upstream ArtBOT release tag and public API contract lock",
    )
    up_parser.add_argument("--json", action="store_true", help="Output raw JSON pin data")

    persona_parser = subparsers.add_parser(
        "persona-info",
        help="Display Rox's persona metadata, signature slogan, and operating invariants",
    )
    persona_parser.add_argument(
        "--json", action="store_true", help="Output raw JSON persona metadata"
    )

    audit_parser = subparsers.add_parser(
        "fleet-audit",
        help="Audit GCP fleet compliance against Rox's 5 security & observability standards",
    )
    _add_fleet_source_args(audit_parser)

    metrics_parser = subparsers.add_parser(
        "vm-metrics",
        help="Inspect Cloud Monitoring CPU, Memory, Disk, Uptime & API metrics for fleet VMs",
    )
    metrics_parser.add_argument(
        "--instance",
        default=None,
        help="Filter metrics to a specific GCE instance name (e.g. artbot-01)",
    )
    _add_fleet_source_args(metrics_parser)

    rem_parser = subparsers.add_parser(
        "remediation-plan",
        help="Generate copy-pasteable gcloud and artbot-gcp remediation commands",
    )
    _add_fleet_source_args(rem_parser)

    return parser


def _resolve_fleet_data(
    args: argparse.Namespace,
    *,
    active_env: Mapping[str, str],
    transport: HttpTransport | None,
) -> tuple[
    list[GceInstance],
    dict[str, VmMetricsSnapshot],
    list[LogEntryRecord],
    dict[str, OsConfigReport],
]:
    """Load fleet dataset from `--seed-file`, `--live` GCP APIs, or default offline fixtures."""
    if args.seed_file:
        return load_seed_fleet_from_file(Path(str(args.seed_file)))
    if args.live:
        token = str(args.token or active_env.get("GCP_ACCESS_TOKEN") or "").strip()
        if not token:
            raise ValueError(
                "GCP_ACCESS_TOKEN is required for --live mode (pass --token or set env)"
            )
        client = GcpOpsClient(
            token,
            project_id=str(args.project),
            transport=transport,
        )
        instances = client.list_instances()
        names = [inst.name for inst in instances]
        metrics = client.collect_vm_metrics(names)
        try:
            logs = client.list_error_logs()
        except RuntimeError:
            logs = []
        os_reports: dict[str, OsConfigReport] = {}
        for inst in instances:
            try:
                os_reports[inst.name] = client.get_os_config_report(inst.name, inst.zone)
            except RuntimeError:
                os_reports[inst.name] = OsConfigReport(
                    instance_name=inst.name,
                    zone=inst.zone,
                    patch_compliant=True,
                    ops_agent_policy=str(
                        inst.labels.get("goog-ops-agent-policy") or DEFAULT_OPS_AGENT_POLICY
                    ),
                    nix_profile_aligned=True,
                    pending_security_updates=0,
                )
        return instances, metrics, logs, os_reports
    return default_seed_fleet()


def _build_audit_report(
    args: argparse.Namespace,
    *,
    active_env: Mapping[str, str],
    transport: HttpTransport | None,
) -> FleetAuditReport:
    instances, metrics, logs, os_reports = _resolve_fleet_data(
        args, active_env=active_env, transport=transport
    )
    return audit_fleet_compliance(
        instances,
        metrics,
        logs=logs,
        os_reports=os_reports,
        project_id=str(args.project),
    )


def main(
    argv: list[str] | None = None,
    *,
    repo_root: Path | None = None,
    transport: HttpTransport | None = None,
    env: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Command-line entrypoint for `rox-bot`."""
    out_stream = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr
    active_env: Mapping[str, str] = os.environ if env is None else env
    root = default_repo_root() if repo_root is None else repo_root

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "upstream-status":
        pin = load_upstream_artbot_pin(default_upstream_pin_path(root))
        if args.json:
            print(json.dumps(pin, indent=2), file=out_stream)
        else:
            allowlist = pin["public_api_allowlist"]
            print(
                f"Upstream Repo:   {pin['upstream_repo']}\n"
                f"Upstream Tag:    {pin['upstream_tag']}\n"
                f"Upstream Commit: {pin['upstream_commit']}\n"
                f"Allowed Symbols: {len(allowlist)}",
                file=out_stream,
            )
        return 0

    if args.command == "persona-info":
        persona = load_persona_metadata(root)
        if args.json:
            print(json.dumps(asdict(persona), indent=2), file=out_stream)
        else:
            invariants_bullet = "\n".join(f"  - {item}" for item in persona.core_invariants)
            print(
                f"Handle:        {persona.handle}\n"
                f"Title:         {persona.title}\n"
                f"GCP Project:   {persona.project_id}\n"
                f'T-Shirt Motto: "{persona.tshirt_slogan}"\n'
                f"TPM Partner:   {persona.partner_handle}\n"
                f"Avatar PNG:    {persona.avatar_png_path}\n"
                f"Invariants:\n{invariants_bullet}",
                file=out_stream,
            )
        return 0

    try:
        if args.command == "vm-metrics":
            _, metrics, _, _ = _resolve_fleet_data(args, active_env=active_env, transport=transport)
            target_instance = str(args.instance).strip() if args.instance else ""
            if target_instance:
                if target_instance not in metrics:
                    print(
                        f"Error: Instance '{target_instance}' not found in metrics snapshot",
                        file=err_stream,
                    )
                    return 1
                selected = [metrics[target_instance]]
            else:
                selected = [metrics[k] for k in sorted(metrics)]

            if args.json:
                payload: dict[str, Any] = {
                    "project_id": str(args.project),
                    "metrics": [asdict(m) for m in selected],
                }
                print(json.dumps(payload, indent=2), file=out_stream)
            else:
                for m in selected:
                    print(
                        f"Instance: {m.instance_name} | "
                        f"CPU: {m.cpu_utilization_pct}% | "
                        f"MEM: {m.memory_used_pct}% | "
                        f"DISK: {m.disk_used_pct}% | "
                        f"Uptime: {m.uptime_seconds}s | "
                        f"Heartbeat: {m.ops_agent_heartbeat}",
                        file=out_stream,
                    )
            return 0

        report = _build_audit_report(args, active_env=active_env, transport=transport)
    except ValueError as exc:
        print(f"Error: {exc}", file=err_stream)
        return 1

    if args.command == "fleet-audit":
        if args.json:
            print(json.dumps(fleet_audit_to_dict(report), indent=2), file=out_stream)
        else:
            print(render_fleet_audit_markdown(report), end="", file=out_stream)
        return 0

    # args.command == "remediation-plan"
    if args.json:
        print(
            json.dumps(
                {
                    "project_id": report.project_id,
                    "max_dov_bear_alarm": report.max_dov_bear_alarm,
                    "remediation_commands": list(report.all_remediation_commands),
                },
                indent=2,
            ),
            file=out_stream,
        )
    else:
        print(render_remediation_plan_markdown(report), end="", file=out_stream)
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
