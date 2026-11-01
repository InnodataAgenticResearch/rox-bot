"""
Rox's GCP Fleet Hygiene & Security Compliance Engine (`src/rox_bot/compliance.py`).

Evaluates every Compute Engine VM in `photography-otel-sandbox` against Rox's 6 standards:
1. Dedicated VM isolation (`1 bot = 1 VM`; no shared-kernel container multi-tenancy in production).
2. Required GCE labels (`customer`, `bot`, `contact`, `goog-ops-agent-policy=v2-template-1-7-0`).
3. Network tag hygiene (`customer-<slug>` required; no `allow-all-ingress`).
4. Ops Agent & Cloud Monitoring telemetry heartbeat active + OS Config/Nix profile alignment.
5. CPU (`<= 80%`), Memory (`<= 85%`), and Disk (`<= 85%`) saturation within SLO thresholds.
6. Nix `sd-switch` & Foundry `ProcessSupervisor` (`nix_sd_switch_and_process_supervision`).

Produces a `FleetAuditReport` with per-VM compliance scores (`0.0–100.0%`), remediation
`gcloud` / `artbot-gcp` commands, and cross-bot coordination alerts + `PeerBlackboardHandoff`
blocks for Dov (`@dov-bot`) mapped onto Dov's 0–5 🐻 Bear Alarm scale.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from artbot import (
    CUSTOMER_LABEL_KEY,
    FLEET_NODES_REGISTRY,
    PeerBlackboardHandoff,
    build_peer_blackboard_block,
    normalize_gcp_label_value,
    serialize_loop_data_block,
)

from rox_bot.gcp_ops import (
    DEFAULT_GCP_PROJECT,
    DEFAULT_OPS_AGENT_POLICY,
    REQUIRED_VM_LABELS,
    GceInstance,
    LogEntryRecord,
    OsConfigReport,
    VmMetricsSnapshot,
)

SLO_MAX_CPU_PCT = 80.0
SLO_MAX_MEMORY_PCT = 85.0
SLO_MAX_DISK_PCT = 85.0

FORBIDDEN_NETWORK_TAGS: frozenset[str] = frozenset(
    {"allow-all-ingress", "public-ssh-world", "open-all-ports"}
)

PILLAR_NAMES: tuple[str, ...] = (
    "1. Dedicated VM Isolation (1 Bot = 1 VM)",
    "2. Required GCE Metadata Labels",
    "3. Network Tag Hygiene",
    "4. Ops Agent & Telemetry Heartbeat",
    "5. Resource Saturation & Log Hygiene",
    "nix_sd_switch_and_process_supervision",
    "cross_customer_isolation",
)


@dataclass(frozen=True)
class ComplianceFinding:
    """Single security, hygiene, or saturation finding on a Compute Engine VM."""

    check_id: str
    pillar: str
    severity: str
    message: str
    remediation_command: str
    bear_alarm_level: int = 2

    @property
    def code(self) -> str:
        """Alias for `check_id`."""
        return self.check_id

    @property
    def rule_id(self) -> str:
        """Alias for `check_id`."""
        return self.check_id

    @property
    def description(self) -> str:
        """Alias for `message`."""
        return self.message


@dataclass(frozen=True)
class VmComplianceResult:
    """Compliance evaluation result for a single Compute Engine VM."""

    instance_name: str
    zone: str
    customer: str
    bot: str
    compliance_score: float
    passed_pillars: tuple[str, ...]
    findings: tuple[ComplianceFinding, ...]
    remediation_commands: tuple[str, ...]
    dov_bear_alarm_level: int
    dov_coordination_note: str


@dataclass(frozen=True)
class FleetAuditReport:
    """Fleet-wide compliance report across `photography-otel-sandbox`."""

    project_id: str
    fleet_score: float
    compliant_vm_count: int
    total_vm_count: int
    max_dov_bear_alarm: int
    vm_results: tuple[VmComplianceResult, ...]
    dov_alerts: tuple[str, ...]
    all_remediation_commands: tuple[str, ...]
    dov_handoff_message: str = ""


def _check_vm_isolation(
    instance: GceInstance,
    bot_to_vms: Mapping[str, list[str]],
    project_id: str,
) -> list[ComplianceFinding]:
    """Pillar 1: Dedicated VM isolation (`1 bot = 1 VM`; no shared-kernel multi-tenancy)."""
    findings: list[ComplianceFinding] = []
    image_lower = instance.boot_disk_image.lower()
    has_container_decl = "gce-container-declaration" in instance.metadata_items
    hosted_bots_raw = instance.metadata_items.get("hosted-bots", "")
    multi_bots = [b.strip() for b in hosted_bots_raw.split(",") if b.strip()]

    if has_container_decl or image_lower.startswith("cos-") or len(multi_bots) > 1:
        findings.append(
            ComplianceFinding(
                check_id="VM_ISOLATION_SHARED_KERNEL",
                pillar="1. Dedicated VM Isolation (1 Bot = 1 VM)",
                severity="CRITICAL",
                message=(
                    f"VM '{instance.name}' violates Rox's hardware virtualization boundary "
                    f"('CONTAINERS AREN\\'T SECURE IN PRODUCTION'): "
                    f"boot_disk='{instance.boot_disk_image}', "
                    f"container_declaration={has_container_decl}, "
                    f"hosted_bots={len(multi_bots) or 1}."
                ),
                remediation_command=(
                    f"artbot-gcp provision --project {project_id} --zone {instance.zone} "
                    f"--instance {instance.name} --image-family debian-12 --dedicated-vm"
                ),
            )
        )

    bot_name = instance.labels.get("bot", "").strip()
    if bot_name and len(bot_to_vms.get(bot_name, [])) > 1:
        shared_vms = ", ".join(sorted(bot_to_vms[bot_name]))
        findings.append(
            ComplianceFinding(
                check_id="VM_ISOLATION_DUPLICATE_BOT",
                pillar="1. Dedicated VM Isolation (1 Bot = 1 VM)",
                severity="HIGH",
                message=(
                    f"Bot '{bot_name}' is split or duplicated across multiple VMs ({shared_vms}); "
                    "enforce deterministic 1:1 bot-to-VM mapping."
                ),
                remediation_command=(
                    f"gcloud compute instances update {instance.name} "
                    f"--project={project_id} --zone={instance.zone} "
                    f"--update-labels=bot={instance.name}"
                ),
            )
        )
    return findings


def _check_gce_labels(
    instance: GceInstance,
    project_id: str,
) -> list[ComplianceFinding]:
    """Pillar 2: Required GCE labels (`customer`, `bot`, `contact`, `goog-ops-agent-policy`)."""
    findings: list[ComplianceFinding] = []
    missing_labels = [lbl for lbl in REQUIRED_VM_LABELS if not instance.labels.get(lbl, "").strip()]
    policy_val = instance.labels.get("goog-ops-agent-policy", "").strip()

    if missing_labels:
        customer_val = instance.labels.get(CUSTOMER_LABEL_KEY, "innodata") or "innodata"
        bot_val = instance.labels.get("bot", instance.name) or instance.name
        contact_val = instance.labels.get("contact", "rox") or "rox"
        findings.append(
            ComplianceFinding(
                check_id="GCE_LABELS_MISSING",
                pillar="2. Required GCE Metadata Labels",
                severity="HIGH",
                message=(
                    f"VM '{instance.name}' is missing required GCE labels: "
                    f"{', '.join(missing_labels)}."
                ),
                remediation_command=(
                    f"gcloud compute instances add-labels {instance.name} "
                    f"--project={project_id} --zone={instance.zone} "
                    f"--labels=customer={customer_val},bot={bot_val},"
                    f"contact={contact_val},goog-ops-agent-policy={DEFAULT_OPS_AGENT_POLICY}"
                ),
            )
        )
    elif policy_val != DEFAULT_OPS_AGENT_POLICY:
        findings.append(
            ComplianceFinding(
                check_id="GCE_LABELS_OPS_POLICY_DRIFT",
                pillar="2. Required GCE Metadata Labels",
                severity="MEDIUM",
                message=(
                    f"VM '{instance.name}' has goog-ops-agent-policy='{policy_val}' "
                    f"(expected '{DEFAULT_OPS_AGENT_POLICY}')."
                ),
                remediation_command=(
                    f"gcloud compute instances add-labels {instance.name} "
                    f"--project={project_id} --zone={instance.zone} "
                    f"--labels=goog-ops-agent-policy={DEFAULT_OPS_AGENT_POLICY}"
                ),
            )
        )
    return findings


def _check_network_tags(
    instance: GceInstance,
    project_id: str,
) -> list[ComplianceFinding]:
    """Pillar 3: Network tag hygiene (`customer-<slug>` present and no forbidden wide-open tags)."""
    findings: list[ComplianceFinding] = []
    customer_slug = normalize_gcp_label_value(instance.labels.get(CUSTOMER_LABEL_KEY) or "innodata")
    expected_tag = f"customer-{customer_slug}"

    if expected_tag not in instance.network_tags:
        findings.append(
            ComplianceFinding(
                check_id="NETWORK_TAG_CUSTOMER_MISSING",
                pillar="3. Network Tag Hygiene",
                severity="HIGH",
                message=(
                    f"VM '{instance.name}' is missing required network isolation tag "
                    f"'{expected_tag}' (current tags: {list(instance.network_tags)})."
                ),
                remediation_command=(
                    f"gcloud compute instances add-tags {instance.name} "
                    f"--project={project_id} --zone={instance.zone} --tags={expected_tag}"
                ),
            )
        )

    bad_tags = sorted(set(instance.network_tags).intersection(FORBIDDEN_NETWORK_TAGS))
    if bad_tags:
        findings.append(
            ComplianceFinding(
                check_id="NETWORK_TAG_FORBIDDEN_INGRESS",
                pillar="3. Network Tag Hygiene",
                severity="CRITICAL",
                message=(
                    f"VM '{instance.name}' carries forbidden wide-open network tag(s): "
                    f"{', '.join(bad_tags)}."
                ),
                remediation_command=(
                    f"gcloud compute instances remove-tags {instance.name} "
                    f"--project={project_id} --zone={instance.zone} --tags={','.join(bad_tags)}"
                ),
            )
        )
    return findings


def _check_telemetry_and_osconfig(
    instance: GceInstance,
    metric: VmMetricsSnapshot | None,
    os_report: OsConfigReport | None,
    project_id: str,
) -> list[ComplianceFinding]:
    """Pillar 4: Ops Agent & Cloud Monitoring telemetry heartbeat + OS Config / Nix alignment."""
    findings: list[ComplianceFinding] = []
    if instance.status != "RUNNING":
        findings.append(
            ComplianceFinding(
                check_id="VM_NOT_RUNNING",
                pillar="4. Ops Agent & Telemetry Heartbeat",
                severity="HIGH",
                message=(
                    f"VM '{instance.name}' is in status '{instance.status}' (expected RUNNING)."
                ),
                remediation_command=(
                    f"gcloud compute instances start {instance.name} "
                    f"--project={project_id} --zone={instance.zone}"
                ),
            )
        )

    if metric is None or not metric.ops_agent_heartbeat:
        findings.append(
            ComplianceFinding(
                check_id="OPS_AGENT_HEARTBEAT_MISSING",
                pillar="4. Ops Agent & Telemetry Heartbeat",
                severity="HIGH",
                message=(
                    f"VM '{instance.name}' is missing active Ops Agent telemetry heartbeat "
                    "in Cloud Monitoring (agent.googleapis.com/memory & disk metrics)."
                ),
                remediation_command=(
                    f"gcloud compute ssh {instance.name} --project={project_id} "
                    f"--zone={instance.zone} "
                    f"--command='sudo systemctl restart google-cloud-ops-agent'"
                ),
            )
        )

    if os_report is not None and (
        not os_report.patch_compliant or not os_report.nix_profile_aligned
    ):
        findings.append(
            ComplianceFinding(
                check_id="OSCONFIG_NIX_DRIFT",
                pillar="4. Ops Agent & Telemetry Heartbeat",
                severity="MEDIUM",
                message=(
                    f"VM '{instance.name}' has OS Config / Nix drift: "
                    f"patch_compliant={os_report.patch_compliant}, "
                    f"nix_profile_aligned={os_report.nix_profile_aligned}, "
                    f"pending_security_updates={os_report.pending_security_updates}."
                ),
                remediation_command=(
                    f"gcloud compute os-config patch-jobs execute "
                    f"--project={project_id} "
                    f"--instance-filter-names=zones/{instance.zone}/instances/{instance.name}"
                ),
            )
        )
    return findings


def _check_saturation_and_logs(
    instance: GceInstance,
    metric: VmMetricsSnapshot | None,
    instance_logs: Sequence[LogEntryRecord],
    project_id: str,
) -> list[ComplianceFinding]:
    """Pillar 5: CPU/Memory/Disk saturation within SLO thresholds and zero critical log spikes."""
    findings: list[ComplianceFinding] = []
    if metric is not None:
        saturated_parts: list[str] = []
        if metric.cpu_utilization_pct is not None and metric.cpu_utilization_pct > SLO_MAX_CPU_PCT:
            saturated_parts.append(
                f"CPU={metric.cpu_utilization_pct:.1f}% (>{SLO_MAX_CPU_PCT:.0f}%)"
            )
        if metric.memory_used_pct is not None and metric.memory_used_pct > SLO_MAX_MEMORY_PCT:
            saturated_parts.append(
                f"MEM={metric.memory_used_pct:.1f}% (>{SLO_MAX_MEMORY_PCT:.0f}%)"
            )
        if metric.disk_used_pct is not None and metric.disk_used_pct > SLO_MAX_DISK_PCT:
            saturated_parts.append(f"DISK={metric.disk_used_pct:.1f}% (>{SLO_MAX_DISK_PCT:.0f}%)")

        if saturated_parts:
            findings.append(
                ComplianceFinding(
                    check_id="RESOURCE_SLO_SATURATION",
                    pillar="5. Resource Saturation & Log Hygiene",
                    severity="HIGH",
                    message=(
                        f"VM '{instance.name}' exceeded resource saturation SLOs: "
                        f"{', '.join(saturated_parts)}."
                    ),
                    remediation_command=(
                        f"gcloud compute instances set-machine-type {instance.name} "
                        f"--project={project_id} --zone={instance.zone} "
                        "--machine-type=e2-standard-4"
                    ),
                )
            )

    if instance_logs:
        crit_count = sum(
            1 for entry in instance_logs if entry.severity in {"CRITICAL", "ALERT", "EMERGENCY"}
        )
        sev_label = "CRITICAL" if crit_count > 0 else "MEDIUM"
        findings.append(
            ComplianceFinding(
                check_id="CLOUD_LOGGING_ERROR_SPIKE",
                pillar="5. Resource Saturation & Log Hygiene",
                severity=sev_label,
                message=(
                    f"VM '{instance.name}' emitted {len(instance_logs)} error/auth log event(s) "
                    f"(latest: {instance_logs[0].unit} - '{instance_logs[0].message}')."
                ),
                remediation_command=(
                    f'gcloud logging read \'resource.type="gce_instance" AND '
                    f'labels."compute.googleapis.com/resource_name"="{instance.name}" '
                    f"AND severity>=ERROR' --project={project_id} --limit=20"
                ),
            )
        )
    return findings


def _check_nix_sd_switch_and_process_supervision(
    instance: GceInstance,
    expected_bridge_store_path: str = "",
    *,
    project_id: str = DEFAULT_GCP_PROJECT,
) -> list[ComplianceFinding]:
    """
    Pillar 6 (`nix_sd_switch_and_process_supervision`): Verify that a VM in
    `FLEET_NODES_REGISTRY` (or any bot VM) has a verified `sd-switch` bridge unit,
    Foundry `ProcessSupervisor` state, expected `/nix/store` bridge binary generation,
    and synchronized `~/.hermes/shared-skills`.
    """
    findings: list[ComplianceFinding] = []
    registry_spec = FLEET_NODES_REGISTRY.get(instance.name)
    bridge_unit = (
        str(registry_spec.get("bridge_unit", "artbot-teams-bridge.service"))
        if registry_spec is not None
        else f"{instance.labels.get('bot', instance.name)}-teams-bridge.service"
    )
    if not instance.sd_switch_healthy or not instance.process_supervisor_ok:
        findings.append(
            ComplianceFinding(
                check_id="NIX_SD_SWITCH_OR_SUPERVISOR_DRIFT",
                pillar="nix_sd_switch_and_process_supervision",
                severity="HIGH",
                message=(
                    f"VM '{instance.name}' (bridge_unit='{bridge_unit}', "
                    f"in_fleet_registry={registry_spec is not None}) has Nix sd-switch or "
                    f"Foundry ProcessSupervisor drift: "
                    f"sd_switch_healthy={instance.sd_switch_healthy}, "
                    f"process_supervisor_ok={instance.process_supervisor_ok}."
                ),
                remediation_command=(
                    f"artbot-gcp --project {project_id} deploy-fleet --bot {instance.name}"
                ),
            )
        )
    if (
        expected_bridge_store_path
        and instance.nix_bridge_store_path
        and instance.nix_bridge_store_path != expected_bridge_store_path
    ):
        findings.append(
            ComplianceFinding(
                check_id="NIX_STORE_GENERATION_DRIFT",
                pillar="nix_sd_switch_and_process_supervision",
                severity="WARNING",
                message=(
                    f"VM '{instance.name}' is running stale Nix bridge store path "
                    f"'{instance.nix_bridge_store_path}' (expected '{expected_bridge_store_path}')."
                ),
                remediation_command=(
                    f"artbot-gcp --project {project_id} deploy-fleet --bot {instance.name}"
                ),
                bear_alarm_level=2,
            )
        )
    if not instance.shared_skills_synced:
        findings.append(
            ComplianceFinding(
                check_id="SHARED_SKILLS_DRIFT",
                pillar="nix_sd_switch_and_process_supervision",
                severity="WARNING",
                message=(
                    f"VM '{instance.name}' is missing synchronized ~/.hermes/shared-skills "
                    "(shared_skills_synced=False)."
                ),
                remediation_command=(
                    f"artbot-gcp --project {project_id} deploy-fleet --bot {instance.name}"
                ),
                bear_alarm_level=2,
            )
        )
    return findings


def _check_cross_customer_isolation(
    instance: GceInstance,
    *,
    project_id: str = DEFAULT_GCP_PROJECT,
) -> list[ComplianceFinding]:
    """
    Pillar 7 (`cross_customer_isolation`): Verify zero cross-customer credential,
    `.env`, `qdrant.json`, or skill leakage across tenant boundaries.
    """
    findings: list[ComplianceFinding] = []
    if instance.cross_tenant_leak_detected:
        findings.append(
            ComplianceFinding(
                check_id="CROSS_CUSTOMER_ISOLATION_BREACH",
                pillar="cross_customer_isolation",
                severity="CRITICAL",
                message=(
                    instance.cross_tenant_leak_details
                    or "Cross-customer credential or tenant leakage detected"
                ),
                remediation_command=(
                    f"artbot-gcp --project {project_id} deploy-fleet --bot {instance.name}"
                ),
                bear_alarm_level=5,
            )
        )
    return findings


def _compute_dov_bear_alarm(
    instance_name: str,
    passed_count: int,
    findings: Sequence[ComplianceFinding],
) -> tuple[int, str]:
    """
    Map a VM's compliance findings onto Dov's (`@dov-bot`) 0–5 🐻 Bear Alarm scale.
    """
    if not findings:
        return (
            0,
            (
                f"@dov-bot [🐻 Bear Alarm 0/5 — All Clear]: VM '{instance_name}' "
                f"passed {len(PILLAR_NAMES)}/{len(PILLAR_NAMES)} Zero-Trust & Ops gates."
            ),
        )

    severities = {f.severity for f in findings}
    check_ids = {f.check_id for f in findings}

    if "CROSS_CUSTOMER_ISOLATION_BREACH" in check_ids or (
        "VM_ISOLATION_SHARED_KERNEL" in check_ids and len(findings) >= 3
    ):
        level = 5
    elif "CRITICAL" in severities:
        level = 4
    elif len(findings) >= 3:
        level = 3
    elif (
        "HIGH" in severities
        or "NIX_STORE_GENERATION_DRIFT" in check_ids
        or "SHARED_SKILLS_DRIFT" in check_ids
    ):
        level = 2
    else:
        level = 1

    summary_codes = ", ".join(f.check_id for f in findings)
    return (
        level,
        (
            f"@dov-bot [🐻 Bear Alarm {level}/5 — Action Required]: VM '{instance_name}' "
            f"triggered {len(findings)} finding(s) ({summary_codes})."
        ),
    )


def audit_instance_compliance(
    instance: GceInstance,
    metric: VmMetricsSnapshot | None = None,
    *,
    bot_to_vms: Mapping[str, list[str]] | None = None,
    logs: Sequence[LogEntryRecord] = (),
    os_report: OsConfigReport | None = None,
    project_id: str = DEFAULT_GCP_PROJECT,
    expected_bridge_store_path: str = "",
) -> VmComplianceResult:
    """Evaluate a single Compute Engine VM against Rox's 7 compliance pillars."""
    active_bot_to_vms: Mapping[str, list[str]] = bot_to_vms or {
        instance.labels.get("bot", "").strip(): [instance.name]
    }
    p1 = _check_vm_isolation(instance, active_bot_to_vms, project_id)
    p2 = _check_gce_labels(instance, project_id)
    p3 = _check_network_tags(instance, project_id)
    p4 = _check_telemetry_and_osconfig(instance, metric, os_report, project_id)
    p5 = _check_saturation_and_logs(instance, metric, logs, project_id)
    p6 = _check_nix_sd_switch_and_process_supervision(
        instance, expected_bridge_store_path, project_id=project_id
    )
    p7 = _check_cross_customer_isolation(instance, project_id=project_id)

    pillar_groups = [p1, p2, p3, p4, p5, p6, p7]
    passed_pillars = [PILLAR_NAMES[idx] for idx, grp in enumerate(pillar_groups) if not grp]
    vm_findings = [f for grp in pillar_groups for f in grp]
    score = round((len(passed_pillars) / float(len(PILLAR_NAMES))) * 100.0, 2)
    vm_remediations = list(dict.fromkeys(f.remediation_command for f in vm_findings))

    bear_level, bear_note = _compute_dov_bear_alarm(instance.name, len(passed_pillars), vm_findings)

    return VmComplianceResult(
        instance_name=instance.name,
        zone=instance.zone,
        customer=instance.labels.get(CUSTOMER_LABEL_KEY, "unassigned"),
        bot=instance.labels.get("bot", "unassigned"),
        compliance_score=score,
        passed_pillars=tuple(passed_pillars),
        findings=tuple(vm_findings),
        remediation_commands=tuple(vm_remediations),
        dov_bear_alarm_level=bear_level,
        dov_coordination_note=bear_note,
    )


def audit_fleet_compliance(
    instances: Sequence[GceInstance],
    metrics: Mapping[str, VmMetricsSnapshot],
    *,
    logs: Sequence[LogEntryRecord] = (),
    os_reports: Mapping[str, OsConfigReport] | None = None,
    project_id: str = DEFAULT_GCP_PROJECT,
    expected_bridge_store_path: str = "",
) -> FleetAuditReport:
    """
    Evaluate every Compute Engine VM in `instances` against Rox's 6 GCP Fleet Hygiene
    & Security Standards and produce a `FleetAuditReport`.
    """
    active_os_reports: Mapping[str, OsConfigReport] = {} if os_reports is None else os_reports

    bot_to_vms: dict[str, list[str]] = {}
    for inst in instances:
        bot_label = inst.labels.get("bot", "").strip()
        if bot_label:
            bot_to_vms.setdefault(bot_label, []).append(inst.name)

    logs_by_vm: dict[str, list[LogEntryRecord]] = {}
    for entry in logs:
        logs_by_vm.setdefault(entry.instance_name, []).append(entry)

    vm_results: list[VmComplianceResult] = []
    dov_alerts: list[str] = []

    for inst in sorted(instances, key=lambda i: i.name):
        res = audit_instance_compliance(
            inst,
            metrics.get(inst.name),
            bot_to_vms=bot_to_vms,
            logs=logs_by_vm.get(inst.name, []),
            os_report=active_os_reports.get(inst.name),
            project_id=project_id,
            expected_bridge_store_path=expected_bridge_store_path,
        )
        if res.dov_bear_alarm_level > 0:
            dov_alerts.append(res.dov_coordination_note)
        vm_results.append(res)

    all_remediations = list(
        dict.fromkeys(cmd for r in vm_results for cmd in r.remediation_commands)
    )

    total_vms = len(vm_results)
    compliant_vms = sum(1 for r in vm_results if r.compliance_score == 100.0)
    fleet_score = (
        round(sum(r.compliance_score for r in vm_results) / total_vms, 2)
        if total_vms > 0
        else 100.0
    )
    max_bear = max((r.dov_bear_alarm_level for r in vm_results), default=0)

    dov_handoff_message = ""
    if max_bear > 0:
        handoff = PeerBlackboardHandoff(
            handoff_id=f"rox-dov-{project_id}-bear-{max_bear}",
            source_agent="rox-bot",
            target_agent="dov-bot",
            status="action_required",
            task_summary=(
                f"GCP Fleet Audit on '{project_id}' triggered Bear Alarm {max_bear}/5 "
                f"({total_vms - compliant_vms}/{total_vms} non-compliant VMs)."
            ),
            context={
                "project_id": project_id,
                "fleet_score": fleet_score,
                "max_dov_bear_alarm": max_bear,
                "alerts": list(dov_alerts),
                "remediation_commands": list(all_remediations),
            },
            updated_at="2026-11-01T00:00:00Z",
        )
        dov_handoff_message = serialize_loop_data_block(build_peer_blackboard_block(handoff))

    return FleetAuditReport(
        project_id=project_id,
        fleet_score=fleet_score,
        compliant_vm_count=compliant_vms,
        total_vm_count=total_vms,
        max_dov_bear_alarm=max_bear,
        vm_results=tuple(vm_results),
        dov_alerts=tuple(dov_alerts),
        all_remediation_commands=tuple(all_remediations),
        dov_handoff_message=dov_handoff_message,
    )


def fleet_audit_to_dict(report: FleetAuditReport) -> dict[str, Any]:
    """Serialize a `FleetAuditReport` into a JSON-compatible dictionary."""
    return {
        "project_id": report.project_id,
        "fleet_score": report.fleet_score,
        "compliant_vm_count": report.compliant_vm_count,
        "total_vm_count": report.total_vm_count,
        "max_dov_bear_alarm": report.max_dov_bear_alarm,
        "dov_alerts": list(report.dov_alerts),
        "dov_handoff_message": report.dov_handoff_message,
        "all_remediation_commands": list(report.all_remediation_commands),
        "vm_results": [
            {
                "instance_name": r.instance_name,
                "zone": r.zone,
                "customer": r.customer,
                "bot": r.bot,
                "compliance_score": r.compliance_score,
                "passed_pillars": list(r.passed_pillars),
                "dov_bear_alarm_level": r.dov_bear_alarm_level,
                "dov_coordination_note": r.dov_coordination_note,
                "remediation_commands": list(r.remediation_commands),
                "findings": [
                    {
                        "check_id": f.check_id,
                        "pillar": f.pillar,
                        "severity": f.severity,
                        "message": f.message,
                        "remediation_command": f.remediation_command,
                    }
                    for f in r.findings
                ],
            }
            for r in report.vm_results
        ],
    }


def render_fleet_audit_markdown(report: FleetAuditReport) -> str:
    """Render a human- and agent-readable Markdown summary of a `FleetAuditReport`."""
    rule_line = (
        "> **Rox's Rule #1:** `\"CONTAINERS AREN'T SECURE IN PRODUCTION\"` "
        "— 1 Bot = 1 Dedicated Hardware-Virtualized GCE VM."
    )
    score_line = (
        f"- **Fleet Compliance Score:** `{report.fleet_score:.2f}%` "
        f"({report.compliant_vm_count}/{report.total_vm_count} VMs at 100%)"
    )
    lines: list[str] = [
        f"# Rox (`@rox-bot`) GCP Fleet Compliance Audit — `{report.project_id}`",
        "",
        rule_line,
        "",
        score_line,
        f"- **Max Dov (`@dov-bot`) Bear Alarm:** `{report.max_dov_bear_alarm}/5` 🐻",
        "",
        "## Per-VM Security & Observability Posture",
        "",
        "| Instance | Zone | Bot | Customer | Score | Bear Alarm | Status |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for vm in report.vm_results:
        status_str = (
            "COMPLIANT" if vm.compliance_score == 100.0 else f"{len(vm.findings)} FINDING(S)"
        )
        lines.append(
            f"| `{vm.instance_name}` | `{vm.zone}` | `{vm.bot}` | `{vm.customer}` "
            f"| `{vm.compliance_score:.1f}%` | `{vm.dov_bear_alarm_level}/5` 🐻 | {status_str} |"
        )

    lines.extend(["", "## Cross-Bot Escalations for Dov (`@dov-bot`)", ""])
    if report.dov_alerts:
        for alert in report.dov_alerts:
            lines.append(f"- {alert}")
        lines.extend(
            [
                "",
                "### Peer Blackboard Handoff (`peer.blackboard.v1`)",
                "",
                "```json",
                report.dov_handoff_message,
                "```",
            ]
        )
    else:
        lines.append("- `@dov-bot` [🐻 Bear Alarm 0/5]: Entire fleet is 100% compliant.")

    return "\n".join(lines) + "\n"


def render_remediation_plan_markdown(report: FleetAuditReport) -> str:
    """Render copy-pasteable `gcloud` and `artbot-gcp` remediation commands."""
    lines: list[str] = [
        f"# Rox (`@rox-bot`) Remediation Plan — `{report.project_id}`",
        "",
    ]
    if not report.all_remediation_commands:
        lines.append(
            "All VMs in `photography-otel-sandbox` are 100% compliant. "
            "Zero remediation actions required."
        )
        return "\n".join(lines) + "\n"

    for vm in report.vm_results:
        if not vm.findings:
            continue
        lines.append(
            f"## VM `{vm.instance_name}` (`{vm.zone}`) — "
            f"Score `{vm.compliance_score:.1f}%` "
            f"(Bear Alarm `{vm.dov_bear_alarm_level}/5` 🐻)"
        )
        lines.append("")
        for finding in vm.findings:
            lines.append(f"- **[{finding.severity}] `{finding.check_id}`:** {finding.message}")
            lines.append("  ```bash")
            lines.append(f"  {finding.remediation_command}")
            lines.append("  ```")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
