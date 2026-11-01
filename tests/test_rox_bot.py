"""
Deterministic unit test suite for `rox_bot` achieving 100% line and branch coverage.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

import rox_bot
from rox_bot.cli import main
from rox_bot.compliance import (
    PILLAR_NAMES,
    audit_fleet_compliance,
    audit_instance_compliance,
    fleet_audit_to_dict,
    render_fleet_audit_markdown,
    render_remediation_plan_markdown,
)
from rox_bot.gcp_ops import (
    DEFAULT_GCP_PROJECT,
    GceInstance,
    GceInstanceInfo,
    GcpOpsClient,
    HttpResponse,
    LogEntryRecord,
    VmMetricsSnapshot,
    default_persona_path,
    default_repo_root,
    default_seed_fleet,
    default_upstream_pin_path,
    load_persona_metadata,
    load_seed_fleet_from_file,
    load_upstream_artbot_pin,
    parse_gce_instance,
)
from tests.fakes import FakeHttpTransport


def test_package_exports_and_persona_and_upstream_pin(tmp_path: Path) -> None:
    assert rox_bot.__version__ == "0.1.0"
    assert GceInstanceInfo is GceInstance
    assert "nix_sd_switch_and_process_supervision" in PILLAR_NAMES
    assert len(PILLAR_NAMES) == 6
    root = default_repo_root()
    assert default_upstream_pin_path().name == "UPSTREAM_ARTBOT.json"
    assert default_persona_path().name == "PERSONA.md"

    pin = load_upstream_artbot_pin()
    assert pin["upstream_tag"] == "v0.2.0-artbot"
    assert pin["upstream_commit"] == "6c63513a9f92887aa13ddd7f562e82eb32e87873"
    for sym in (
        "CUSTOMER_LABEL_KEY",
        "FLEET_NODES_REGISTRY",
        "PEER_AGENT_ROSTER",
        "PeerBlackboardHandoff",
        "build_peer_blackboard_block",
        "normalize_gcp_label_value",
    ):
        assert sym in pin["public_api_allowlist"]

    persona = load_persona_metadata()
    assert persona.handle == "@rox-bot"
    assert persona.tshirt_slogan == "CONTAINERS AREN'T SECURE IN PRODUCTION"
    assert persona.partner_handle == "@dov-bot"
    assert (root / persona.avatar_svg_path).is_file()
    assert (root / persona.avatar_png_path).is_file()

    # Invalid UPSTREAM_ARTBOT.json not a dict
    bad_json_list = tmp_path / "list_pin.json"
    bad_json_list.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON object"):
        load_upstream_artbot_pin(bad_json_list)

    # Missing required field in UPSTREAM_ARTBOT.json
    bad_json_missing = tmp_path / "missing_pin.json"
    bad_json_missing.write_text(json.dumps({"upstream_repo": "only-one"}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field"):
        load_upstream_artbot_pin(bad_json_missing)

    # Missing slogan in PERSONA.md
    bad_root = tmp_path / "bad_repo"
    (bad_root / "config").mkdir(parents=True)
    (bad_root / "config" / "PERSONA.md").write_text("# No slogan here\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required slogan"):
        load_persona_metadata(bad_root)


def test_http_response_and_fake_transport_defaults() -> None:
    resp = HttpResponse(status_code=200, body='{"ok": true}')
    assert resp.json() == {"ok": True}

    fake = FakeHttpTransport()
    # Default fallback when queue is empty
    default_get = fake.get("https://example.com", headers={}, timeout=5.0)
    assert default_get.status_code == 200
    assert default_get.json() == {}

    default_post = fake.post_json("https://example.com", payload={"a": 1}, headers={}, timeout=5.0)
    assert default_post.status_code == 200
    assert default_post.json() == {}

    default_patch = fake.patch_json(
        "https://example.com", payload={"a": 1}, headers={}, timeout=5.0
    )
    assert default_patch.status_code == 200
    assert default_patch.json() == {}


def test_parse_gce_instance_variations() -> None:
    with pytest.raises(ValueError, match="missing 'name'"):
        parse_gce_instance({})

    # Minimal instance with empty zone, licenses fallback, and non-list/non-mapping fields
    minimal = parse_gce_instance(
        {
            "name": "vm-minimal",
            "zone": "   ",
            "machineType": "",
            "disks": [{"licenses": ["projects/debian-cloud/global/licenses/debian-12"]}],
            "networkInterfaces": [{}],
            "labels": "not-a-dict",
            "tags": "not-a-dict",
            "serviceAccounts": ["not-a-dict"],
            "metadata": "not-a-dict",
        },
        fallback_zone="us-east1-b",
    )
    assert minimal.name == "vm-minimal"
    assert minimal.zone == "us-east1-b"
    assert minimal.machine_type == "e2-medium"
    assert minimal.boot_disk_image == "debian-12"
    assert minimal.internal_ip == ""
    assert minimal.external_ip == ""
    assert minimal.labels == {}
    assert minimal.network_tags == ()
    assert minimal.service_account_email == ""
    assert minimal.service_account_scopes == ()
    assert minimal.metadata_items == {}
    assert minimal.sd_switch_healthy is True
    assert minimal.process_supervisor_ok is True

    # Instance with non-mapping disk/nic and non-list accessConfigs/tags/scopes/metadata
    edge = parse_gce_instance(
        {
            "name": "vm-edge",
            "disks": ["not-a-mapping"],
            "networkInterfaces": ["not-a-mapping"],
            "tags": {"items": "not-a-list"},
            "serviceAccounts": [{"email": "sa@example.com", "scopes": "not-a-list"}],
            "metadata": {"items": ["not-a-mapping", {"key": "", "value": "skip"}]},
            "sd_switch_healthy": False,
            "process_supervisor_ok": False,
        }
    )
    assert edge.boot_disk_image == "debian-12"
    assert edge.service_account_email == "sa@example.com"
    assert edge.service_account_scopes == ()
    assert edge.metadata_items == {}
    assert edge.sd_switch_healthy is False
    assert edge.process_supervisor_ok is False

    # Instance with empty disks/licenses, non-list metadata.items, and accessConfigs non-mapping
    edge2 = parse_gce_instance(
        {
            "name": "vm-edge-2",
            "disks": [{"licenses": []}],
            "networkInterfaces": [{"networkIP": "10.0.0.2", "accessConfigs": ["not-a-mapping"]}],
            "metadata": {"items": "not-a-list"},
        }
    )
    assert edge2.boot_disk_image == "debian-12"
    assert edge2.internal_ip == "10.0.0.2"
    assert edge2.external_ip == ""

    # Full instance with sourceImage, natIP, labels, tags, scopes, metadata
    full = parse_gce_instance(
        {
            "name": "artbot-01",
            "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
            "status": "running",
            "machineType": "zones/us-central1-a/machineTypes/e2-standard-4",
            "disks": [
                {
                    "initializeParams": {
                        "sourceImage": "projects/debian-cloud/global/images/debian-12-bookworm"
                    }
                }
            ],
            "networkInterfaces": [
                {
                    "networkIP": "10.128.0.10",
                    "accessConfigs": [{"natIP": "35.192.0.10"}],
                }
            ],
            "labels": {"customer": "innodata", "bot": "artbot"},
            "tags": {"items": ["customer-innodata", ""]},
            "serviceAccounts": [
                {
                    "email": "bot@p.iam.gserviceaccount.com",
                    "scopes": [
                        "https://www.googleapis.com/auth/logging.write",
                        "   ",
                    ],
                }
            ],
            "metadata": {
                "items": [
                    {"key": "enable-osconfig", "value": "TRUE"},
                ]
            },
        }
    )
    assert full.zone == "us-central1-a"
    assert full.status == "RUNNING"
    assert full.machine_type == "e2-standard-4"
    assert full.boot_disk_image == "debian-12-bookworm"
    assert full.internal_ip == "10.128.0.10"
    assert full.external_ip == "35.192.0.10"
    assert full.labels == {"customer": "innodata", "bot": "artbot"}
    assert full.network_tags == ("customer-innodata",)
    assert full.service_account_scopes == ("logging.write",)
    assert full.metadata_items == {"enable-osconfig": "TRUE"}


def test_gcp_ops_client_methods_and_error_branches() -> None:
    with pytest.raises(ValueError, match="access_token must be a non-empty"):
        GcpOpsClient("   ")

    # Default transport initialization
    default_client = GcpOpsClient("tok-123", project_id="  ")
    assert default_client.project_id == DEFAULT_GCP_PROJECT

    fake = FakeHttpTransport()
    client = GcpOpsClient("tok-secret", project_id="photography-otel-sandbox", transport=fake)

    # 1. list_instances success + non-mapping/empty scopes
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "items": {
                    "zones/us-central1-a": {
                        "instances": [
                            {"id": "10001", "name": "vm-b", "status": "RUNNING"},
                            "not-a-mapping",
                        ]
                    },
                    "zones/us-central1-b": {"warning": "no instances"},
                    "zones/us-central1-c": "not-a-mapping",
                }
            }
        ),
    )
    instances = client.list_instances()
    assert [i.name for i in instances] == ["vm-b"]

    # list_instances when items is not a mapping
    fake.queue_get_response(200, json.dumps({"items": []}))
    assert client.list_instances() == []

    # list_instances HTTP error
    fake.queue_get_response(403, '{"error": "forbidden"}')
    with pytest.raises(RuntimeError, match="Compute Engine aggregated instances API failed"):
        client.list_instances()

    # 2. query_time_series & collect_vm_metrics
    # CPU response (fraction <= 1.0 and percentage > 1.0, plus edge cases)
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "timeSeries": [
                    "not-a-mapping",
                    {
                        "metric": {"labels": {"instance_name": "vm-1"}},
                        "points": [{"value": {"doubleValue": 0.42}}],
                    },
                    {
                        "metric": "not-a-mapping",
                        "resource": {"labels": {"instance_name": "vm-2"}},
                        "points": [{"value": {"doubleValue": 55.0}}],
                    },
                    {
                        "resource": "not-a-mapping",
                        "points": [],
                    },
                    {
                        "resource": {"labels": {"instance_id": "vm-3"}},
                        "points": ["not-a-mapping"],
                    },
                    {
                        "resource": {"labels": {"instance_id": "vm-4"}},
                        "points": [{"value": "not-a-mapping"}],
                    },
                    {
                        "resource": {"labels": {"instance_id": "vm-5"}},
                        "points": [{"value": {"stringValue": "ignored"}}],
                    },
                ]
            }
        ),
    )
    # Uptime response (int64Value)
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "timeSeries": [
                    {
                        "metric": {"labels": {"instance_name": "vm-1"}},
                        "points": [{"value": {"int64Value": "86400"}}],
                    }
                ]
            }
        ),
    )
    # Memory response
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "timeSeries": [
                    {
                        "metric": {"labels": {"instance_name": "vm-1"}},
                        "points": [{"value": {"doubleValue": 61.25}}],
                    }
                ]
            }
        ),
    )
    # Disk response
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "timeSeries": [
                    {
                        "metric": {"labels": {"instance_name": "vm-1"}},
                        "points": [{"value": {"doubleValue": 40.0}}],
                    }
                ]
            }
        ),
    )
    # API request count response (non-list timeSeries)
    fake.queue_get_response(200, json.dumps({"timeSeries": None}))

    snapshots = client.collect_vm_metrics(["vm-1", "vm-2", "vm-no-metrics"])
    assert snapshots["vm-1"].cpu_utilization_pct == 42.0
    assert snapshots["vm-1"].uptime_seconds == 86400.0
    assert snapshots["vm-1"].memory_used_pct == 61.25
    assert snapshots["vm-1"].disk_used_pct == 40.0
    assert snapshots["vm-1"].ops_agent_heartbeat is True
    assert snapshots["vm-2"].cpu_utilization_pct == 55.0
    assert snapshots["vm-2"].ops_agent_heartbeat is False
    assert snapshots["vm-no-metrics"].cpu_utilization_pct is None
    assert snapshots["vm-no-metrics"].ops_agent_heartbeat is False

    # query_time_series HTTP error
    fake.queue_get_response(500, '{"error": "internal"}')
    with pytest.raises(RuntimeError, match="Cloud Monitoring timeSeries API failed"):
        client.query_time_series("compute.googleapis.com/instance/cpu/utilization")

    # 3. list_error_logs
    fake.queue_post_response(
        200,
        json.dumps(
            {
                "entries": [
                    "not-a-mapping",
                    {
                        "labels": {"compute.googleapis.com/resource_name": "vm-1"},
                        "severity": "error",
                        "timestamp": "2026-11-01T00:00:00Z",
                        "jsonPayload": {
                            "_SYSTEMD_UNIT": "sshd.service",
                            "MESSAGE": "Failed password for invalid user",
                        },
                    },
                    {
                        "labels": "not-a-mapping",
                        "resource": "not-a-mapping",
                        "jsonPayload": "not-a-mapping",
                        "textPayload": "Plain text error",
                    },
                ]
            }
        ),
    )
    logs = client.list_error_logs()
    assert len(logs) == 2
    assert logs[0].instance_name == "vm-1"
    assert logs[0].unit == "sshd.service"
    assert logs[1].instance_name == "unknown-vm"
    assert logs[1].message == "Plain text error"

    # list_error_logs when entries is None
    fake.queue_post_response(200, json.dumps({"entries": None}))
    assert client.list_error_logs() == []

    # list_error_logs HTTP error
    fake.queue_post_response(401, '{"error": "unauthenticated"}')
    with pytest.raises(RuntimeError, match="Cloud Logging entries:list API failed"):
        client.list_error_logs()

    # 4. get_os_config_report
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "osInfo": {"kernelRelease": "6.6.52"},
                "patchCompliant": True,
                "opsAgentPolicy": "v2-template-1-7-0",
                "nixProfileAligned": True,
                "pendingSecurityUpdates": 0,
            }
        ),
    )
    os_rep = client.get_os_config_report("vm-1", "us-central1-a")
    assert os_rep.patch_compliant is True
    assert os_rep.nix_profile_aligned is True

    # get_os_config_report when osInfo is not a mapping
    fake.queue_get_response(200, json.dumps({"osInfo": "invalid"}))
    os_rep2 = client.get_os_config_report("vm-2", "us-central1-a")
    assert os_rep2.patch_compliant is True

    # get_os_config_report HTTP error
    fake.queue_get_response(404, '{"error": "not found"}')
    with pytest.raises(RuntimeError, match="OS Config inventory API failed"):
        client.get_os_config_report("vm-1", "us-central1-a")


def test_compliance_audit_all_branches_and_bear_alarm_levels() -> None:
    # 1. Seed fleet audit (covers Bear Alarm 0 and Bear Alarm 5)
    instances, metrics, logs, os_reports = default_seed_fleet()
    report = audit_fleet_compliance(instances, metrics, logs=logs, os_reports=os_reports)
    assert report.total_vm_count == 4
    assert report.compliant_vm_count == 3
    assert report.max_dov_bear_alarm == 5
    assert "peer.blackboard.v1" in report.dov_handoff_message
    handoff_json = json.loads(report.dov_handoff_message)
    assert handoff_json["owner_agent"] == "rox-bot"
    assert handoff_json["payload"]["source_agent"] == "rox-bot"
    assert handoff_json["payload"]["target_agent"] == "dov-bot"
    by_name = {r.instance_name: r for r in report.vm_results}
    assert by_name["artbot-01"].dov_bear_alarm_level == 0
    assert len(by_name["artbot-01"].passed_pillars) == 6
    assert by_name["legacy-container-pod-vm"].dov_bear_alarm_level == 5

    # Verify Markdown and dict serialization
    audit_md = render_fleet_audit_markdown(report)
    assert "CONTAINERS AREN'T SECURE IN PRODUCTION" in audit_md
    assert "legacy-container-pod-vm" in audit_md
    assert "peer.blackboard.v1" in audit_md
    rem_md = render_remediation_plan_markdown(report)
    assert "artbot-gcp provision" in rem_md
    report_dict = fleet_audit_to_dict(report)
    assert report_dict["max_dov_bear_alarm"] == 5
    assert "peer.blackboard.v1" in report_dict["dov_handoff_message"]

    # 2. Test Bear Alarm levels 1, 2, 3, 4, Pillar 6 drift on FLEET_NODES_REGISTRY node,
    # and duplicate bot / policy drift / stopped VM branches
    custom_instances = [
        # Bear Alarm 1 (single MEDIUM finding: goog-ops-agent-policy drift)
        GceInstance(
            name="vm-bear-1",
            zone="us-central1-a",
            status="RUNNING",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12",
            internal_ip="10.0.0.1",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "bot-1",
                "contact": "rox",
                "goog-ops-agent-policy": "old-v1-policy",
            },
            network_tags=("customer-innodata",),
            service_account_email="sa@p.iam.gserviceaccount.com",
            service_account_scopes=("logging.write",),
            metadata_items={},
        ),
        # Bear Alarm 2 (single HIGH finding: duplicate bot shared with vm-bear-3)
        GceInstance(
            name="vm-bear-2",
            zone="us-central1-a",
            status="RUNNING",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12",
            internal_ip="10.0.0.2",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "shared-bot",
                "contact": "rox",
                "goog-ops-agent-policy": "v2-template-1-7-0",
            },
            network_tags=("customer-innodata",),
            service_account_email="sa@p.iam.gserviceaccount.com",
            service_account_scopes=("logging.write",),
            metadata_items={},
        ),
        # Bear Alarm 3 (multiple HIGH/MEDIUM findings without CRITICAL)
        GceInstance(
            name="vm-bear-3",
            zone="us-central1-a",
            status="TERMINATED",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12",
            internal_ip="10.0.0.3",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "shared-bot",
                "contact": "rox",
                "goog-ops-agent-policy": "v2-template-1-7-0",
            },
            network_tags=("customer-innodata",),
            service_account_email="sa@p.iam.gserviceaccount.com",
            service_account_scopes=("logging.write",),
            metadata_items={},
        ),
        # Bear Alarm 4 (CRITICAL finding from forbidden network tag, <3 total findings)
        GceInstance(
            name="vm-bear-4",
            zone="us-central1-a",
            status="RUNNING",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12",
            internal_ip="10.0.0.4",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "",
                "contact": "rox",
                "goog-ops-agent-policy": "v2-template-1-7-0",
            },
            network_tags=("customer-innodata", "open-all-ports"),
            service_account_email="sa@p.iam.gserviceaccount.com",
            service_account_scopes=("logging.write",),
            metadata_items={},
        ),
        # Pillar 6 failure on FLEET_NODES_REGISTRY node `rox-ops-bot`
        GceInstance(
            name="rox-ops-bot",
            zone="me-west1-c",
            status="RUNNING",
            machine_type="e2-standard-4",
            boot_disk_image="debian-12",
            internal_ip="10.0.0.5",
            external_ip="",
            labels={
                "customer": "innodata",
                "bot": "rox-ops-bot",
                "contact": "rox",
                "goog-ops-agent-policy": "v2-template-1-7-0",
            },
            network_tags=("customer-innodata",),
            service_account_email="sa@p.iam.gserviceaccount.com",
            service_account_scopes=("logging.write",),
            metadata_items={},
            sd_switch_healthy=False,
            process_supervisor_ok=False,
        ),
    ]
    custom_metrics = {
        "vm-bear-1": VmMetricsSnapshot(
            instance_name="vm-bear-1",
            cpu_utilization_pct=15.0,
            memory_used_pct=30.0,
            disk_used_pct=25.0,
            uptime_seconds=1000.0,
            api_request_count=10,
            ops_agent_heartbeat=True,
        ),
        "vm-bear-2": VmMetricsSnapshot(
            instance_name="vm-bear-2",
            cpu_utilization_pct=15.0,
            memory_used_pct=30.0,
            disk_used_pct=25.0,
            uptime_seconds=1000.0,
            api_request_count=10,
            ops_agent_heartbeat=True,
        ),
        "vm-bear-4": VmMetricsSnapshot(
            instance_name="vm-bear-4",
            cpu_utilization_pct=15.0,
            memory_used_pct=30.0,
            disk_used_pct=25.0,
            uptime_seconds=1000.0,
            api_request_count=10,
            ops_agent_heartbeat=True,
        ),
        "rox-ops-bot": VmMetricsSnapshot(
            instance_name="rox-ops-bot",
            cpu_utilization_pct=15.0,
            memory_used_pct=30.0,
            disk_used_pct=25.0,
            uptime_seconds=1000.0,
            api_request_count=10,
            ops_agent_heartbeat=True,
        ),
    }
    # Include a non-CRITICAL log entry on vm-bear-3 and duplicate remediation check
    custom_logs = [
        LogEntryRecord(
            instance_name="vm-bear-3",
            severity="ERROR",
            timestamp="2026-11-01T00:00:00Z",
            unit="systemd",
            message="Service restart warning",
        )
    ]
    custom_report = audit_fleet_compliance(
        custom_instances,
        custom_metrics,
        logs=custom_logs,
        os_reports=None,
    )
    c_by_name = {r.instance_name: r for r in custom_report.vm_results}
    assert c_by_name["vm-bear-1"].dov_bear_alarm_level == 1
    assert c_by_name["vm-bear-2"].dov_bear_alarm_level == 2
    assert c_by_name["vm-bear-3"].dov_bear_alarm_level == 3
    assert c_by_name["vm-bear-4"].dov_bear_alarm_level == 4
    assert c_by_name["rox-ops-bot"].dov_bear_alarm_level == 2
    assert c_by_name["rox-ops-bot"].remediation_commands == (
        "artbot-gcp --project photography-otel-sandbox deploy-fleet --bot rox-ops-bot",
    )

    # 2b. Test NIX_STORE_GENERATION_DRIFT (matching and mismatched expected_bridge_store_path)
    expected_store = "/nix/store/pzb8758pnipisza0s48f2gppzpyqh2zx-artbot-0.1.0/bin/artbot-bridge"
    stale_store = "/nix/store/2q2xapqxrrchhj4k68989q1c9bdhq03v-artbot-0.1.0/bin/artbot-bridge"
    aligned_vm = GceInstance(
        name="avi-bot",
        zone="me-west1-c",
        status="RUNNING",
        machine_type="e2-standard-4",
        boot_disk_image="debian-12",
        internal_ip="10.0.0.11",
        external_ip="",
        labels={
            "customer": "innodata",
            "bot": "avi-bot",
            "contact": "rox",
            "goog-ops-agent-policy": "v2-template-1-7-0",
        },
        network_tags=("customer-innodata",),
        service_account_email="sa@p.iam.gserviceaccount.com",
        service_account_scopes=("logging.write",),
        metadata_items={},
        nix_bridge_store_path=expected_store,
    )
    stale_vm = GceInstance(
        name="bijal-bot",
        zone="me-west1-c",
        status="RUNNING",
        machine_type="e2-standard-4",
        boot_disk_image="debian-12",
        internal_ip="10.0.0.12",
        external_ip="",
        labels={
            "customer": "innodata",
            "bot": "bijal-bot",
            "contact": "rox",
            "goog-ops-agent-policy": "v2-template-1-7-0",
        },
        network_tags=("customer-innodata",),
        service_account_email="sa@p.iam.gserviceaccount.com",
        service_account_scopes=("logging.write",),
        metadata_items={},
        nix_bridge_store_path=stale_store,
    )
    skew_metrics = {
        "avi-bot": VmMetricsSnapshot(
            instance_name="avi-bot",
            cpu_utilization_pct=15.0,
            memory_used_pct=30.0,
            disk_used_pct=25.0,
            uptime_seconds=1000.0,
            api_request_count=10,
            ops_agent_heartbeat=True,
        ),
        "bijal-bot": VmMetricsSnapshot(
            instance_name="bijal-bot",
            cpu_utilization_pct=15.0,
            memory_used_pct=30.0,
            disk_used_pct=25.0,
            uptime_seconds=1000.0,
            api_request_count=10,
            ops_agent_heartbeat=True,
        ),
    }
    aligned_res = audit_instance_compliance(
        aligned_vm,
        skew_metrics["avi-bot"],
        expected_bridge_store_path=expected_store,
    )
    assert aligned_res.compliance_score == 100.0
    assert aligned_res.dov_bear_alarm_level == 0
    assert aligned_res.findings == ()

    skew_report = audit_fleet_compliance(
        [aligned_vm, stale_vm],
        skew_metrics,
        expected_bridge_store_path=expected_store,
    )
    skew_by_name = {r.instance_name: r for r in skew_report.vm_results}
    assert skew_by_name["avi-bot"].dov_bear_alarm_level == 0
    stale_res = skew_by_name["bijal-bot"]
    assert stale_res.dov_bear_alarm_level == 2
    assert len(stale_res.findings) == 1
    drift_finding = stale_res.findings[0]
    assert drift_finding.check_id == "NIX_STORE_GENERATION_DRIFT"
    assert drift_finding.rule_id == "NIX_STORE_GENERATION_DRIFT"
    assert drift_finding.pillar == "nix_sd_switch_and_process_supervision"
    assert drift_finding.severity == "WARNING"
    assert drift_finding.bear_alarm_level == 2
    assert drift_finding.description == (
        f"VM 'bijal-bot' is running stale Nix bridge store path "
        f"'{stale_store}' (expected '{expected_store}')."
    )
    assert drift_finding.remediation_command == (
        "artbot-gcp --project photography-otel-sandbox deploy-fleet --bot bijal-bot"
    )

    # 3. Empty fleet report (100% compliant, zero alerts, zero remediation commands)
    empty_report = audit_fleet_compliance([], {})
    assert empty_report.fleet_score == 100.0
    assert empty_report.max_dov_bear_alarm == 0
    assert empty_report.dov_handoff_message == ""
    assert "Entire fleet is 100% compliant" in render_fleet_audit_markdown(empty_report)
    assert "Zero remediation actions required" in render_remediation_plan_markdown(empty_report)


def test_load_seed_fleet_from_file_and_cli_commands(tmp_path: Path) -> None:
    # Invalid seed file (not a JSON object)
    bad_seed = tmp_path / "bad_seed.json"
    bad_seed.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a top-level JSON object"):
        load_seed_fleet_from_file(bad_seed)

    # Valid seed file with non-mapping entries mixed in to exercise all branches
    seed_file = tmp_path / "seed.json"
    seed_payload: dict[str, Any] = {
        "instances": [
            "skip-non-mapping",
            {
                "name": "artbot-01",
                "zone": "us-central1-a",
                "status": "RUNNING",
                "labels": {
                    "customer": "innodata",
                    "bot": "artbot",
                    "contact": "drosen",
                    "goog-ops-agent-policy": "v2-template-1-7-0",
                },
                "tags": {"items": ["customer-innodata"]},
            },
        ],
        "metrics": {
            "artbot-01": {
                "cpu_utilization_pct": 21.0,
                "memory_used_pct": 40.0,
                "disk_used_pct": 30.0,
                "uptime_seconds": 3600.0,
                "api_request_count": 50,
                "ops_agent_heartbeat": True,
            },
            "skip-me": "not-a-mapping",
        },
        "logs": [
            "skip-non-mapping",
            {
                "instance_name": "artbot-01",
                "severity": "ERROR",
                "timestamp": "2026-11-01T00:00:00Z",
                "unit": "test.service",
                "message": "test log",
            },
        ],
        "os_reports": {
            "artbot-01": {
                "zone": "us-central1-a",
                "patch_compliant": True,
                "ops_agent_policy": "v2-template-1-7-0",
                "nix_profile_aligned": True,
                "pending_security_updates": 0,
            },
            "skip-os": "not-a-mapping",
        },
    }
    seed_file.write_text(json.dumps(seed_payload), encoding="utf-8")
    s_inst, s_met, s_logs, s_os = load_seed_fleet_from_file(seed_file)
    assert len(s_inst) == 1
    assert "artbot-01" in s_met
    assert len(s_logs) == 1
    assert "artbot-01" in s_os

    # Also test seed file where metrics/logs/os_reports are not mappings/lists
    minimal_seed = tmp_path / "min_seed.json"
    minimal_seed.write_text(
        json.dumps(
            {
                "instances": [],
                "metrics": "not-a-mapping",
                "logs": "not-a-list",
                "os_reports": "not-a-mapping",
            }
        ),
        encoding="utf-8",
    )
    m_inst, m_met, m_logs, m_os = load_seed_fleet_from_file(minimal_seed)
    assert (m_inst, m_met, m_logs, m_os) == ([], {}, [], {})

    # CLI: upstream-status (text and JSON)
    out = io.StringIO()
    assert main(["upstream-status"], stdout=out) == 0
    assert "v0.2.0-artbot" in out.getvalue()

    out = io.StringIO()
    assert main(["upstream-status", "--json"], stdout=out) == 0
    assert json.loads(out.getvalue())["upstream_tag"] == "v0.2.0-artbot"

    # CLI: persona-info (text and JSON)
    out = io.StringIO()
    assert main(["persona-info"], stdout=out) == 0
    assert "CONTAINERS AREN'T SECURE IN PRODUCTION" in out.getvalue()

    out = io.StringIO()
    assert main(["persona-info", "--json"], stdout=out) == 0
    assert json.loads(out.getvalue())["handle"] == "@rox-bot"

    # CLI: fleet-audit (default offline, --json, and --seed-file)
    out = io.StringIO()
    assert main(["fleet-audit"], stdout=out) == 0
    assert "Rox (`@rox-bot`) GCP Fleet Compliance Audit" in out.getvalue()

    out = io.StringIO()
    assert main(["fleet-audit", "--seed-file", str(seed_file), "--json"], stdout=out) == 0
    assert json.loads(out.getvalue())["total_vm_count"] == 1

    # CLI: vm-metrics (all, specific instance, --json, and missing instance error)
    out = io.StringIO()
    assert main(["vm-metrics"], stdout=out) == 0
    assert "Instance: artbot-01" in out.getvalue()

    out = io.StringIO()
    assert main(["vm-metrics", "--instance", "artbot-01", "--json"], stdout=out) == 0
    assert len(json.loads(out.getvalue())["metrics"]) == 1

    err = io.StringIO()
    assert main(["vm-metrics", "--instance", "nonexistent-vm"], stderr=err) == 1
    assert "not found in metrics snapshot" in err.getvalue()

    # CLI: remediation-plan (text and --json)
    out = io.StringIO()
    assert main(["remediation-plan"], stdout=out) == 0
    assert "Remediation Plan" in out.getvalue()

    out = io.StringIO()
    assert main(["remediation-plan", "--json"], stdout=out) == 0
    assert "remediation_commands" in json.loads(out.getvalue())

    # CLI: --live mode missing token error
    err = io.StringIO()
    assert main(["fleet-audit", "--live"], env={}, stderr=err) == 1
    assert "GCP_ACCESS_TOKEN is required" in err.getvalue()

    # CLI: --live mode success with FakeHttpTransport
    fake = FakeHttpTransport()
    # 1. list_instances
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "items": {
                    "zones/us-central1-a": {
                        "instances": [
                            {
                                "name": "artbot-01",
                                "status": "RUNNING",
                                "labels": {
                                    "customer": "innodata",
                                    "bot": "artbot",
                                    "contact": "drosen",
                                    "goog-ops-agent-policy": "v2-template-1-7-0",
                                },
                                "tags": {"items": ["customer-innodata"]},
                            }
                        ]
                    }
                }
            }
        ),
    )
    # 2-6. 5 monitoring timeSeries calls
    for val in (0.20, 7200.0, 45.0, 35.0, 100.0):
        fake.queue_get_response(
            200,
            json.dumps(
                {
                    "timeSeries": [
                        {
                            "metric": {"labels": {"instance_name": "artbot-01"}},
                            "points": [{"value": {"doubleValue": val}}],
                        }
                    ]
                }
            ),
        )
    # 7. logging entries:list
    fake.queue_post_response(200, json.dumps({"entries": []}))
    # 8. OS Config inventory
    fake.queue_get_response(
        200,
        json.dumps(
            {
                "patchCompliant": True,
                "opsAgentPolicy": "v2-template-1-7-0",
                "nixProfileAligned": True,
                "pendingSecurityUpdates": 0,
            }
        ),
    )
    out = io.StringIO()
    rc = main(
        ["fleet-audit", "--live", "--token", "fake-token", "--json"],
        transport=fake,
        stdout=out,
    )
    assert rc == 0
    live_data = json.loads(out.getvalue())
    assert live_data["fleet_score"] == 100.0
    assert live_data["max_dov_bear_alarm"] == 0

    # CLI: --live mode when logging and osconfig return 403 (fallback branch)
    fake_fb = FakeHttpTransport()
    fake_fb.queue_get_response(
        200,
        json.dumps(
            {
                "items": {
                    "zones/us-central1-a": {
                        "instances": [
                            {
                                "id": "999",
                                "name": "artbot-01",
                                "status": "RUNNING",
                                "labels": {
                                    "customer": "innodata",
                                    "bot": "artbot",
                                    "contact": "drosen",
                                    "goog-ops-agent-policy": "v2-template-1-7-0",
                                },
                                "tags": {"items": ["customer-innodata"]},
                            }
                        ]
                    }
                }
            }
        ),
    )
    for val in (0.20, 7200.0, 45.0, 35.0, 100.0):
        fake_fb.queue_get_response(
            200,
            json.dumps(
                {
                    "timeSeries": [
                        {
                            "resource": {"labels": {"instance_id": "999"}},
                            "points": [{"value": {"doubleValue": val}}],
                        }
                    ]
                }
            ),
        )
    fake_fb.queue_post_response(403, '{"error": "forbidden"}')
    fake_fb.queue_get_response(403, '{"error": "forbidden"}')
    out_fb = io.StringIO()
    assert (
        main(
            ["fleet-audit", "--live", "--token", "fake-token", "--json"],
            transport=fake_fb,
            stdout=out_fb,
        )
        == 0
    )
    assert json.loads(out_fb.getvalue())["fleet_score"] == 100.0
