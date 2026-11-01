"""
GCP-Native Operations & Security Client (`GcpOpsClient`) for `photography-otel-sandbox`.

Wraps:
- Cloud Compute Engine API (`compute.googleapis.com`)
- Cloud Monitoring API (`monitoring.googleapis.com/v3`)
- Cloud Logging API (`logging.googleapis.com/v2/entries:list`)
- OS Config & VM Manager API (`osconfig.googleapis.com`)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

DEFAULT_GCP_PROJECT = "photography-otel-sandbox"
DEFAULT_OPS_AGENT_POLICY = "v2-template-1-7-0"

COMPUTE_BASE_URL = "https://compute.googleapis.com/compute/v1"
MONITORING_BASE_URL = "https://monitoring.googleapis.com/v3"
LOGGING_BASE_URL = "https://logging.googleapis.com/v2"
OSCONFIG_BASE_URL = "https://osconfig.googleapis.com/v1"

METRIC_CPU_UTILIZATION = "compute.googleapis.com/instance/cpu/utilization"
METRIC_UPTIME = "compute.googleapis.com/instance/uptime"
METRIC_MEMORY_PERCENT = "agent.googleapis.com/memory/percent_used"
METRIC_DISK_PERCENT = "agent.googleapis.com/disk/percent_used"
METRIC_API_REQUEST_COUNT = "serviceruntime.googleapis.com/api/request_count"

REQUIRED_VM_LABELS: tuple[str, ...] = (
    "customer",
    "bot",
    "contact",
    "goog-ops-agent-policy",
)


@dataclass(frozen=True)
class HttpResponse:
    """Minimal HTTP response object for deterministic testing and transports."""

    status_code: int
    body: str

    def json(self) -> dict[str, Any]:
        """Parse JSON response body into a dictionary."""
        parsed = json.loads(self.body)
        if not isinstance(parsed, dict):
            raise ValueError("Expected JSON object in HttpResponse body")
        return parsed


class HttpTransport(Protocol):
    """Protocol for injectable HTTP transports."""

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse: ...  # pragma: no cover - protocol stub

    def post_json(
        self,
        url: str,
        *,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse: ...  # pragma: no cover - protocol stub


class UrllibHttpTransport:
    """Standard-library urllib transport implementing `HttpTransport`."""

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse:  # pragma: no cover - network transport boundary
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return HttpResponse(
                    status_code=int(resp.status),
                    body=resp.read().decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status_code=int(exc.code),
                body=exc.read().decode("utf-8", errors="replace"),
            )

    def post_json(
        self,
        url: str,
        *,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse:  # pragma: no cover - network transport boundary
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return HttpResponse(
                    status_code=int(resp.status),
                    body=resp.read().decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status_code=int(exc.code),
                body=exc.read().decode("utf-8", errors="replace"),
            )


@dataclass(frozen=True)
class GceInstance:
    """Normalized Compute Engine VM instance record in `photography-otel-sandbox`."""

    name: str
    zone: str
    status: str
    machine_type: str
    boot_disk_image: str
    internal_ip: str
    external_ip: str
    labels: Mapping[str, str]
    network_tags: tuple[str, ...]
    service_account_email: str
    service_account_scopes: tuple[str, ...]
    metadata_items: Mapping[str, str]


@dataclass(frozen=True)
class VmMetricsSnapshot:
    """Native Cloud Monitoring metrics snapshot for a single Compute Engine VM."""

    instance_name: str
    cpu_utilization_pct: float | None
    memory_used_pct: float | None
    disk_used_pct: float | None
    uptime_seconds: float | None
    api_request_count: int
    ops_agent_heartbeat: bool


@dataclass(frozen=True)
class LogEntryRecord:
    """Structured Cloud Logging entry from systemd/journald or Ops Agent."""

    instance_name: str
    severity: str
    timestamp: str
    unit: str
    message: str


@dataclass(frozen=True)
class OsConfigReport:
    """OS Config & VM Manager compliance state for a single Compute Engine VM."""

    instance_name: str
    zone: str
    patch_compliant: bool
    ops_agent_policy: str
    nix_profile_aligned: bool
    pending_security_updates: int


@dataclass(frozen=True)
class RoxPersonaMetadata:
    """Metadata describing Rox (`@rox-bot`), GCP Ops & Security Lead."""

    handle: str
    title: str
    project_id: str
    tshirt_slogan: str
    partner_handle: str
    core_invariants: tuple[str, ...]
    avatar_svg_path: str
    avatar_png_path: str


def default_repo_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).resolve().parents[2]


def default_upstream_pin_path(repo_root: Path | None = None) -> Path:
    """Return the path to `UPSTREAM_ARTBOT.json`."""
    root = default_repo_root() if repo_root is None else repo_root
    return root / "UPSTREAM_ARTBOT.json"


def default_persona_path(repo_root: Path | None = None) -> Path:
    """Return the path to `config/PERSONA.md`."""
    root = default_repo_root() if repo_root is None else repo_root
    return root / "config" / "PERSONA.md"


def load_upstream_artbot_pin(path: Path | None = None) -> dict[str, Any]:
    """Load and validate `UPSTREAM_ARTBOT.json`."""
    pin_path = default_upstream_pin_path() if path is None else path
    raw = json.loads(pin_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("UPSTREAM_ARTBOT.json must contain a JSON object")
    for required_key in (
        "upstream_repo",
        "upstream_tag",
        "upstream_commit",
        "public_api_allowlist",
    ):
        if required_key not in raw or not raw[required_key]:
            raise ValueError(f"UPSTREAM_ARTBOT.json missing required field: {required_key}")
    return raw


def load_persona_metadata(repo_root: Path | None = None) -> RoxPersonaMetadata:
    """Load Rox's persona metadata and verify her signature slogan in `config/PERSONA.md`."""
    root = default_repo_root() if repo_root is None else repo_root
    persona_file = default_persona_path(root)
    text = persona_file.read_text(encoding="utf-8")
    slogan = "CONTAINERS AREN'T SECURE IN PRODUCTION"
    if slogan not in text:
        raise ValueError(f"config/PERSONA.md is missing required slogan: {slogan}")
    return RoxPersonaMetadata(
        handle="@rox-bot",
        title="GCP Ops & Security Lead",
        project_id=DEFAULT_GCP_PROJECT,
        tshirt_slogan=slogan,
        partner_handle="@dov-bot",
        core_invariants=(
            "1 bot = 1 dedicated hardware-virtualized GCE VM (no shared-kernel containers in prod)",
            "Mandatory labels: customer, bot, contact, goog-ops-agent-policy=v2-template-1-7-0",
            "Network tag isolation: customer-<slug> required on every bot VM",
            "Active Cloud Monitoring & Ops Agent telemetry heartbeat within SLOs",
            "Deterministic Nix profile alignment & @dov-bot 0-5 Bear Alarm coordination",
        ),
        avatar_svg_path="assets/rox_avatar.svg",
        avatar_png_path="assets/rox_avatar.png",
    )


def _short_resource_name(url_or_name: str, default: str = "unknown") -> str:
    """Extract the trailing segment of a GCP resource URI."""
    cleaned = url_or_name.strip().rstrip("/")
    if not cleaned:
        return default
    return cleaned.rpartition("/")[2]


def parse_gce_instance(raw: Mapping[str, Any], fallback_zone: str = "us-central1-a") -> GceInstance:
    """Normalize a raw Compute Engine instance dictionary into a `GceInstance`."""
    name = str(raw.get("name") or "").strip()
    if not name:
        raise ValueError("Compute Engine instance record is missing 'name'")

    zone_raw = str(raw.get("zone") or fallback_zone)
    zone = _short_resource_name(zone_raw, default=fallback_zone)
    status = str(raw.get("status") or "UNKNOWN").strip().upper()
    machine_type = _short_resource_name(
        str(raw.get("machineType") or "e2-medium"), default="e2-medium"
    )

    disks = raw.get("disks")
    boot_disk_image = "debian-12"
    if isinstance(disks, list) and disks:
        first_disk = disks[0]
        if isinstance(first_disk, Mapping):
            licenses = first_disk.get("licenses")
            init_params = first_disk.get("initializeParams")
            if isinstance(init_params, Mapping) and init_params.get("sourceImage"):
                boot_disk_image = _short_resource_name(str(init_params["sourceImage"]))
            elif isinstance(licenses, list) and licenses:
                boot_disk_image = _short_resource_name(str(licenses[0]))

    internal_ip = ""
    external_ip = ""
    nics = raw.get("networkInterfaces")
    if isinstance(nics, list) and nics:
        first_nic = nics[0]
        if isinstance(first_nic, Mapping):
            internal_ip = str(first_nic.get("networkIP") or "")
            access_configs = first_nic.get("accessConfigs")
            if isinstance(access_configs, list) and access_configs:
                first_ac = access_configs[0]
                if isinstance(first_ac, Mapping):
                    external_ip = str(first_ac.get("natIP") or "")

    raw_labels = raw.get("labels")
    labels: dict[str, str] = {}
    if isinstance(raw_labels, Mapping):
        for k, v in raw_labels.items():
            labels[str(k)] = str(v)

    tags_obj = raw.get("tags")
    network_tags: list[str] = []
    if isinstance(tags_obj, Mapping):
        items = tags_obj.get("items")
        if isinstance(items, list):
            network_tags = [str(tag) for tag in items if str(tag).strip()]

    sa_email = ""
    sa_scopes: list[str] = []
    service_accounts = raw.get("serviceAccounts")
    if isinstance(service_accounts, list) and service_accounts:
        first_sa = service_accounts[0]
        if isinstance(first_sa, Mapping):
            sa_email = str(first_sa.get("email") or "")
            scopes_raw = first_sa.get("scopes")
            if isinstance(scopes_raw, list):
                sa_scopes = [_short_resource_name(str(s)) for s in scopes_raw if str(s).strip()]

    metadata_items: dict[str, str] = {}
    meta_obj = raw.get("metadata")
    if isinstance(meta_obj, Mapping):
        items_list = meta_obj.get("items")
        if isinstance(items_list, list):
            for entry in items_list:
                if isinstance(entry, Mapping) and entry.get("key"):
                    metadata_items[str(entry["key"])] = str(entry.get("value") or "")

    return GceInstance(
        name=name,
        zone=zone,
        status=status,
        machine_type=machine_type,
        boot_disk_image=boot_disk_image,
        internal_ip=internal_ip,
        external_ip=external_ip,
        labels=labels,
        network_tags=tuple(network_tags),
        service_account_email=sa_email,
        service_account_scopes=tuple(sa_scopes),
        metadata_items=metadata_items,
    )


class GcpOpsClient:
    """
    Pure dependency-injected client for GCP Compute Engine, Cloud Monitoring,
    Cloud Logging, and OS Config APIs in `photography-otel-sandbox`.
    """

    def __init__(
        self,
        access_token: str,
        *,
        project_id: str = DEFAULT_GCP_PROJECT,
        transport: HttpTransport | None = None,
        timeout: float = 20.0,
    ) -> None:
        cleaned_token = access_token.strip()
        if not cleaned_token:
            raise ValueError("access_token must be a non-empty OAuth2 bearer token")
        self.access_token = cleaned_token
        self.project_id = project_id.strip() or DEFAULT_GCP_PROJECT
        self.transport: HttpTransport = UrllibHttpTransport() if transport is None else transport
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def list_instances(self) -> list[GceInstance]:
        """
        List all Compute Engine instances across all zones in `self.project_id`
        via `compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances`.
        """
        url = f"{COMPUTE_BASE_URL}/projects/{self.project_id}/aggregated/instances"
        resp = self.transport.get(url, headers=self._headers(), timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Compute Engine aggregated instances API failed with HTTP {resp.status_code}"
            )
        payload = resp.json()
        items = payload.get("items")
        instances: list[GceInstance] = []
        if isinstance(items, Mapping):
            for scope_key, scoped_val in sorted(items.items()):
                fallback_zone = _short_resource_name(str(scope_key), default="us-central1-a")
                if isinstance(scoped_val, Mapping):
                    raw_list = scoped_val.get("instances")
                    if isinstance(raw_list, list):
                        for raw_inst in raw_list:
                            if isinstance(raw_inst, Mapping):
                                instances.append(
                                    parse_gce_instance(raw_inst, fallback_zone=fallback_zone)
                                )
        return sorted(instances, key=lambda inst: inst.name)

    def query_time_series(
        self,
        metric_type: str,
        *,
        minutes: int = 15,
    ) -> dict[str, float]:
        """
        Query Cloud Monitoring `timeSeries` (`monitoring.googleapis.com/v3`) for `metric_type`
        and return the latest point value keyed by `instance_name` (or `instance_id` / `service`).
        """
        filter_expr = f'metric.type = "{metric_type}"'
        params = urllib.parse.urlencode(
            {
                "filter": filter_expr,
                "pageSize": str(min(max(minutes * 10, 50), 500)),
            }
        )
        url = f"{MONITORING_BASE_URL}/projects/{self.project_id}/timeSeries?{params}"
        resp = self.transport.get(url, headers=self._headers(), timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Cloud Monitoring timeSeries API failed for {metric_type} "
                f"with HTTP {resp.status_code}"
            )
        payload = resp.json()
        series_list = payload.get("timeSeries")
        results: dict[str, float] = {}
        if isinstance(series_list, list):
            for series in series_list:
                if not isinstance(series, Mapping):
                    continue
                metric_labels = (
                    series.get("metric", {}).get("labels", {})
                    if isinstance(series.get("metric"), Mapping)
                    else {}
                )
                resource_labels = (
                    series.get("resource", {}).get("labels", {})
                    if isinstance(series.get("resource"), Mapping)
                    else {}
                )
                key = str(
                    metric_labels.get("instance_name")
                    or resource_labels.get("instance_name")
                    or resource_labels.get("instance_id")
                    or resource_labels.get("service")
                    or "project-total"
                )
                points = series.get("points")
                if isinstance(points, list) and points:
                    first_pt = points[0]
                    if isinstance(first_pt, Mapping):
                        val_obj = first_pt.get("value")
                        if isinstance(val_obj, Mapping):
                            if "doubleValue" in val_obj:
                                results[key] = float(val_obj["doubleValue"])
                            elif "int64Value" in val_obj:
                                results[key] = float(val_obj["int64Value"])
        return results

    def collect_vm_metrics(
        self,
        instance_names: Sequence[str],
    ) -> dict[str, VmMetricsSnapshot]:
        """
        Query CPU, uptime, memory, disk, and API request count metrics from Cloud Monitoring
        and assemble a `VmMetricsSnapshot` per instance.
        """
        cpu_map = self.query_time_series(METRIC_CPU_UTILIZATION)
        uptime_map = self.query_time_series(METRIC_UPTIME)
        mem_map = self.query_time_series(METRIC_MEMORY_PERCENT)
        disk_map = self.query_time_series(METRIC_DISK_PERCENT)
        api_map = self.query_time_series(METRIC_API_REQUEST_COUNT)

        snapshots: dict[str, VmMetricsSnapshot] = {}
        for name in instance_names:
            raw_cpu = cpu_map.get(name)
            # GCE cpu/utilization is either 0.0-1.0 fraction or 0-100 percentage
            cpu_pct: float | None = None
            if raw_cpu is not None:
                cpu_pct = round(raw_cpu * 100.0 if raw_cpu <= 1.0 else raw_cpu, 2)
            mem_pct = round(mem_map[name], 2) if name in mem_map else None
            disk_pct = round(disk_map[name], 2) if name in disk_map else None
            uptime_sec = round(uptime_map[name], 1) if name in uptime_map else None
            req_count = int(api_map.get(name, api_map.get("project-total", 0.0)))
            heartbeat = (
                cpu_pct is not None
                and mem_pct is not None
                and disk_pct is not None
                and (uptime_sec is not None and uptime_sec > 0.0)
            )
            snapshots[name] = VmMetricsSnapshot(
                instance_name=name,
                cpu_utilization_pct=cpu_pct,
                memory_used_pct=mem_pct,
                disk_used_pct=disk_pct,
                uptime_seconds=uptime_sec,
                api_request_count=req_count,
                ops_agent_heartbeat=heartbeat,
            )
        return snapshots

    def list_error_logs(
        self,
        *,
        page_size: int = 50,
    ) -> list[LogEntryRecord]:
        """
        Query Cloud Logging (`logging.googleapis.com/v2/entries:list`) for systemd/journald
        and Ops Agent warnings/errors across the fleet.
        """
        url = f"{LOGGING_BASE_URL}/entries:list"
        payload: dict[str, Any] = {
            "resourceNames": [f"projects/{self.project_id}"],
            "filter": (
                'resource.type="gce_instance" AND '
                '(severity>=ERROR OR jsonPayload.MESSAGE:"auth" OR jsonPayload.MESSAGE:"restart")'
            ),
            "orderBy": "timestamp desc",
            "pageSize": page_size,
        }
        resp = self.transport.post_json(
            url,
            payload=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Cloud Logging entries:list API failed with HTTP {resp.status_code}"
            )
        body = resp.json()
        raw_entries = body.get("entries")
        records: list[LogEntryRecord] = []
        if isinstance(raw_entries, list):
            for entry in raw_entries:
                if not isinstance(entry, Mapping):
                    continue
                raw_labels = entry.get("labels")
                labels: Mapping[str, Any] = raw_labels if isinstance(raw_labels, Mapping) else {}
                raw_res = entry.get("resource")
                res_obj: Mapping[str, Any] = raw_res if isinstance(raw_res, Mapping) else {}
                raw_res_labels = res_obj.get("labels")
                res_labels: Mapping[str, Any] = (
                    raw_res_labels if isinstance(raw_res_labels, Mapping) else {}
                )
                inst_name = str(
                    labels.get("compute.googleapis.com/resource_name")
                    or res_labels.get("instance_name")
                    or res_labels.get("instance_id")
                    or "unknown-vm"
                )
                severity = str(entry.get("severity") or "ERROR").upper()
                timestamp = str(entry.get("timestamp") or "")
                raw_jp = entry.get("jsonPayload")
                json_payload: Mapping[str, Any] = raw_jp if isinstance(raw_jp, Mapping) else {}
                unit = str(
                    json_payload.get("_SYSTEMD_UNIT")
                    or json_payload.get("unit")
                    or "google-cloud-ops-agent.service"
                )
                message = str(
                    json_payload.get("MESSAGE")
                    or json_payload.get("message")
                    or entry.get("textPayload")
                    or ""
                )
                records.append(
                    LogEntryRecord(
                        instance_name=inst_name,
                        severity=severity,
                        timestamp=timestamp,
                        unit=unit,
                        message=message,
                    )
                )
        return records

    def get_os_config_report(
        self,
        instance_name: str,
        zone: str = "us-central1-a",
    ) -> OsConfigReport:
        """
        Query OS Config & VM Manager (`osconfig.googleapis.com`) inventory/compliance
        for `(instance_name, zone)`.
        """
        url = (
            f"{OSCONFIG_BASE_URL}/projects/{self.project_id}"
            f"/locations/{zone}/instances/{instance_name}/inventory"
        )
        resp = self.transport.get(url, headers=self._headers(), timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(
                f"OS Config inventory API failed for {instance_name} with HTTP {resp.status_code}"
            )
        data = resp.json()
        raw_os_info = data.get("osInfo")
        os_info: Mapping[str, Any] = raw_os_info if isinstance(raw_os_info, Mapping) else {}
        patch_compliant = bool(data.get("patchCompliant", True))
        ops_policy = str(data.get("opsAgentPolicy") or DEFAULT_OPS_AGENT_POLICY)
        nix_aligned = bool(
            data.get("nixProfileAligned", True)
            and str(os_info.get("kernelRelease") or "6.6").strip() != ""
        )
        pending_updates = int(data.get("pendingSecurityUpdates", 0))
        return OsConfigReport(
            instance_name=instance_name,
            zone=zone,
            patch_compliant=patch_compliant,
            ops_agent_policy=ops_policy,
            nix_profile_aligned=nix_aligned,
            pending_security_updates=pending_updates,
        )


def default_seed_fleet() -> tuple[
    list[GceInstance],
    dict[str, VmMetricsSnapshot],
    list[LogEntryRecord],
    dict[str, OsConfigReport],
]:
    """
    Return a deterministic, representative `photography-otel-sandbox` fleet dataset
    for offline CLI execution and compliance verification.
    """
    instances: list[GceInstance] = [
        GceInstance(
            name="artbot-01",
            zone="us-central1-a",
            status="RUNNING",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12-bookworm-v20261015",
            internal_ip="10.128.0.11",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "artbot",
                "contact": "drosen",
                "goog-ops-agent-policy": "v2-template-1-7-0",
            },
            network_tags=("customer-innodata",),
            service_account_email="artbot-sa@photography-otel-sandbox.iam.gserviceaccount.com",
            service_account_scopes=("logging.write", "monitoring.write"),
            metadata_items={"enable-osconfig": "TRUE", "nix-profile": "makor-env-dannyrosen"},
        ),
        GceInstance(
            name="rox-bot-01",
            zone="us-central1-a",
            status="RUNNING",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12-bookworm-v20261015",
            internal_ip="10.128.0.12",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "rox-bot",
                "contact": "rox",
                "goog-ops-agent-policy": "v2-template-1-7-0",
            },
            network_tags=("customer-innodata",),
            service_account_email="rox-bot-sa@photography-otel-sandbox.iam.gserviceaccount.com",
            service_account_scopes=("compute.readonly", "monitoring.read", "logging.read"),
            metadata_items={"enable-osconfig": "TRUE", "nix-profile": "rox-bot-env"},
        ),
        GceInstance(
            name="dov-bot-01",
            zone="us-central1-a",
            status="RUNNING",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12-bookworm-v20261015",
            internal_ip="10.128.0.13",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "dov-bot",
                "contact": "drosen",
                "goog-ops-agent-policy": "v2-template-1-7-0",
            },
            network_tags=("customer-innodata",),
            service_account_email="dov-bot-sa@photography-otel-sandbox.iam.gserviceaccount.com",
            service_account_scopes=("logging.write", "monitoring.write"),
            metadata_items={"enable-osconfig": "TRUE", "nix-profile": "dov-bot-env"},
        ),
        GceInstance(
            name="legacy-container-pod-vm",
            zone="us-central1-b",
            status="RUNNING",
            machine_type="e2-medium",
            boot_disk_image="cos-stable-113-18244-151-14",
            internal_ip="10.128.0.99",
            external_ip="34.122.10.99",
            labels={
                "customer": "acme",
                "bot": "multi-bot-pack",
            },
            network_tags=("allow-all-ingress",),
            service_account_email="default-compute@developer.gserviceaccount.com",
            service_account_scopes=("cloud-platform",),
            metadata_items={
                "gce-container-declaration": "spec:\n  containers:\n  - image: nginx:latest",
                "hosted-bots": "bot-a,bot-b",
            },
        ),
    ]

    metrics: dict[str, VmMetricsSnapshot] = {
        "artbot-01": VmMetricsSnapshot(
            instance_name="artbot-01",
            cpu_utilization_pct=24.5,
            memory_used_pct=48.2,
            disk_used_pct=41.0,
            uptime_seconds=604800.0,
            api_request_count=1280,
            ops_agent_heartbeat=True,
        ),
        "rox-bot-01": VmMetricsSnapshot(
            instance_name="rox-bot-01",
            cpu_utilization_pct=19.8,
            memory_used_pct=42.0,
            disk_used_pct=36.5,
            uptime_seconds=604800.0,
            api_request_count=940,
            ops_agent_heartbeat=True,
        ),
        "dov-bot-01": VmMetricsSnapshot(
            instance_name="dov-bot-01",
            cpu_utilization_pct=22.1,
            memory_used_pct=45.6,
            disk_used_pct=39.2,
            uptime_seconds=604800.0,
            api_request_count=1120,
            ops_agent_heartbeat=True,
        ),
        "legacy-container-pod-vm": VmMetricsSnapshot(
            instance_name="legacy-container-pod-vm",
            cpu_utilization_pct=91.4,
            memory_used_pct=93.5,
            disk_used_pct=89.0,
            uptime_seconds=3600.0,
            api_request_count=4500,
            ops_agent_heartbeat=False,
        ),
    }

    logs: list[LogEntryRecord] = [
        LogEntryRecord(
            instance_name="legacy-container-pod-vm",
            severity="CRITICAL",
            timestamp="2026-11-01T02:15:00Z",
            unit="docker.service",
            message=(
                "Shared-kernel container namespace escalation attempt blocked; service restart loop"
            ),
        ),
    ]

    os_reports: dict[str, OsConfigReport] = {
        "artbot-01": OsConfigReport(
            instance_name="artbot-01",
            zone="us-central1-a",
            patch_compliant=True,
            ops_agent_policy="v2-template-1-7-0",
            nix_profile_aligned=True,
            pending_security_updates=0,
        ),
        "rox-bot-01": OsConfigReport(
            instance_name="rox-bot-01",
            zone="us-central1-a",
            patch_compliant=True,
            ops_agent_policy="v2-template-1-7-0",
            nix_profile_aligned=True,
            pending_security_updates=0,
        ),
        "dov-bot-01": OsConfigReport(
            instance_name="dov-bot-01",
            zone="us-central1-a",
            patch_compliant=True,
            ops_agent_policy="v2-template-1-7-0",
            nix_profile_aligned=True,
            pending_security_updates=0,
        ),
        "legacy-container-pod-vm": OsConfigReport(
            instance_name="legacy-container-pod-vm",
            zone="us-central1-b",
            patch_compliant=False,
            ops_agent_policy="unassigned",
            nix_profile_aligned=False,
            pending_security_updates=7,
        ),
    }
    return instances, metrics, logs, os_reports


def load_seed_fleet_from_file(
    seed_file: Path,
) -> tuple[
    list[GceInstance],
    dict[str, VmMetricsSnapshot],
    list[LogEntryRecord],
    dict[str, OsConfigReport],
]:
    """Load fleet instances, metrics, logs, and OS Config reports from a JSON seed file."""
    raw = json.loads(seed_file.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("Seed file must contain a top-level JSON object")

    raw_instances = raw.get("instances", [])
    instances = [parse_gce_instance(item) for item in raw_instances if isinstance(item, Mapping)]

    metrics: dict[str, VmMetricsSnapshot] = {}
    raw_metrics = raw.get("metrics", {})
    if isinstance(raw_metrics, Mapping):
        for name, m_val in raw_metrics.items():
            if isinstance(m_val, Mapping):
                metrics[str(name)] = VmMetricsSnapshot(
                    instance_name=str(name),
                    cpu_utilization_pct=(
                        float(m_val["cpu_utilization_pct"])
                        if m_val.get("cpu_utilization_pct") is not None
                        else None
                    ),
                    memory_used_pct=(
                        float(m_val["memory_used_pct"])
                        if m_val.get("memory_used_pct") is not None
                        else None
                    ),
                    disk_used_pct=(
                        float(m_val["disk_used_pct"])
                        if m_val.get("disk_used_pct") is not None
                        else None
                    ),
                    uptime_seconds=(
                        float(m_val["uptime_seconds"])
                        if m_val.get("uptime_seconds") is not None
                        else None
                    ),
                    api_request_count=int(m_val.get("api_request_count", 0)),
                    ops_agent_heartbeat=bool(m_val.get("ops_agent_heartbeat", True)),
                )

    logs: list[LogEntryRecord] = []
    raw_logs = raw.get("logs", [])
    if isinstance(raw_logs, list):
        for entry in raw_logs:
            if isinstance(entry, Mapping):
                logs.append(
                    LogEntryRecord(
                        instance_name=str(entry.get("instance_name") or "unknown-vm"),
                        severity=str(entry.get("severity") or "ERROR"),
                        timestamp=str(entry.get("timestamp") or ""),
                        unit=str(entry.get("unit") or "systemd"),
                        message=str(entry.get("message") or ""),
                    )
                )

    os_reports: dict[str, OsConfigReport] = {}
    raw_os = raw.get("os_reports", {})
    if isinstance(raw_os, Mapping):
        for name, os_val in raw_os.items():
            if isinstance(os_val, Mapping):
                os_reports[str(name)] = OsConfigReport(
                    instance_name=str(name),
                    zone=str(os_val.get("zone") or "us-central1-a"),
                    patch_compliant=bool(os_val.get("patch_compliant", True)),
                    ops_agent_policy=str(
                        os_val.get("ops_agent_policy") or DEFAULT_OPS_AGENT_POLICY
                    ),
                    nix_profile_aligned=bool(os_val.get("nix_profile_aligned", True)),
                    pending_security_updates=int(os_val.get("pending_security_updates", 0)),
                )

    return instances, metrics, logs, os_reports
