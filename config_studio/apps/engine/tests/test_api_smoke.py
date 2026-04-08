import base64
import io
import zipfile
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)
HEADERS = {"x-api-key": "dev-engine-key"}


def make_zip_base64(files: dict[str, bytes | str]) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_requires_api_key():
    response = client.post("/api/analyze", json={"config_text": "hostname r1"})
    assert response.status_code == 401


def test_analyze_basic_config():
    response = client.post(
        "/api/analyze",
        headers=HEADERS,
        json={
            "config_text": """hostname r1
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
!
ip http server
line vty 0 4
 transport input telnet
!""",
            "quick_pass": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "complete"
    assert "findings" in body
    assert body["vendor"]["vendor"] in ["cisco_ios", "cisco_iosxe", "unknown"]
    assert body["report"]["body"]["ordered_change_script"]["generated"] is True
    assert "configure terminal" in body["report"]["body"]["ordered_change_script"]["apply_script"]


def test_report_render_requires_api_key():
    response = client.post(
        "/api/report/render",
        params={"format": "html"},
        json={"config_text": "hostname r1"},
    )
    assert response.status_code == 401


def test_report_render_html_and_pdf():
    payload = {
        "config_text": """hostname r1
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
!
ip http server
line vty 0 4
 transport input telnet
!""",
        "quick_pass": False,
        "engineer_name": "Chandler",
    }

    html_response = client.post(
        "/api/report/render",
        params={"format": "html"},
        headers=HEADERS,
        json=payload,
    )
    assert html_response.status_code == 200
    assert "Optimesh Config Studio Pre-Flight Report" in html_response.text
    assert "Ordered change script" in html_response.text

    pdf_response = client.post(
        "/api/report/render",
        params={"format": "pdf"},
        headers=HEADERS,
        json=payload,
    )
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"].startswith("application/pdf")
    assert pdf_response.content.startswith(b"%PDF")


def test_compare_requires_api_key():
    response = client.post(
        "/api/compare",
        json={"running_config": "hostname r1", "startup_config": "hostname r1"},
    )
    assert response.status_code == 401


def test_compare_detects_lost_on_reload():
    response = client.post(
        "/api/compare",
        headers=HEADERS,
        json={
            "running_config": "hostname r1\ninterface Loopback0\n ip address 1.1.1.1 255.255.255.255",
            "startup_config": "hostname r1",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["lost_on_reload"]) >= 1


def test_correlate_requires_api_key():
    response = client.post(
        "/api/correlate",
        json={"configs": [{"config_text": "hostname r1"}, {"config_text": "hostname r2"}]},
    )
    assert response.status_code == 401


def test_correlate_detects_cross_device_mismatches():
    response = client.post(
        "/api/correlate",
        headers=HEADERS,
        json={
            "configs": [
                {
                    "config_text": """hostname EDGE-A
interface GigabitEthernet0/0
 description TO-EDGE-B
 ip address 10.0.0.1 255.255.255.252
 mtu 1500
!
router ospf 1
 network 10.0.0.0 0.0.0.3 area 0
!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
!"""
                },
                {
                    "config_text": """hostname EDGE-B
interface GigabitEthernet0/0
 description TO-EDGE-A
 ip address 10.0.0.2 255.255.255.252
 mtu 9216
!
router ospf 1
 network 10.0.0.0 0.0.0.3 area 1
!
router bgp 65002
 neighbor 192.0.2.1 remote-as 65001
!"""
                },
            ]
        },
    )
    assert response.status_code == 200
    body = response.json()
    titles = [finding["title"] for finding in body["findings"]]
    assert "Cross-device OSPF area mismatch" in titles
    assert "Cross-device MTU mismatch" in titles
    assert "Cross-device BGP peer mismatch" in titles
    assert body["summary"]["total"] >= 3
    assert len(body["inferred_links"]) >= 1


def test_batch_review_returns_archive_intake_summary_for_skipped_entries():
    response = client.post(
        "/api/batch-review",
        headers=HEADERS,
        json={
            "zip_filename": "mixed-batch.zip",
            "zip_base64": make_zip_base64(
                {
                    "configs/router1.cfg": "hostname r1\nip http server\n",
                    "configs/router2.cfg": "hostname r2\nline vty 0 4\n transport input telnet\n",
                    "notes/readme.md": "deployment checklist",
                    "configs/empty.cfg": "   \n",
                }
            ),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["review_count"] == 2
    assert body["archive_summary"]["zip_filename"] == "mixed-batch.zip"
    assert body["archive_summary"]["archive_member_count"] == 4
    assert body["archive_summary"]["readable_config_count"] == 2
    assert body["archive_summary"]["skipped_non_config_count"] == 1
    assert body["archive_summary"]["skipped_empty_count"] == 1
    skipped = {entry["filename"]: entry["reason"] for entry in body["archive_summary"]["skipped_entries"]}
    assert skipped["notes/readme.md"] == "text file does not look like a network config"
    assert skipped["configs/empty.cfg"] == "empty text file"
    assert body["cross_config"] is not None


def test_batch_review_rejects_config_larger_than_2mb():
    response = client.post(
        "/api/batch-review",
        headers=HEADERS,
        json={
            "zip_filename": "oversized.zip",
            "zip_base64": make_zip_base64({"router.cfg": "a" * (2 * 1024 * 1024 + 1)}),
        },
    )

    assert response.status_code == 400
    assert "2 MB per-file batch review limit" in response.json()["detail"]


def test_batch_review_allows_sidecar_heavy_zip_when_readable_config_count_is_small():
    files = {
        **{f"notes/readme-{idx}.md": "deployment checklist" for idx in range(260)},
        "configs/router1.cfg": "hostname r1\nip http server\n",
        "configs/router2.cfg": "hostname r2\nline vty 0 4\n transport input telnet\n",
    }
    response = client.post(
        "/api/batch-review",
        headers=HEADERS,
        json={
            "zip_filename": "sidecar-heavy.zip",
            "zip_base64": make_zip_base64(files),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["review_count"] == 2
    assert body["archive_summary"]["archive_member_count"] == 262
    assert body["archive_summary"]["readable_config_count"] == 2
    assert body["archive_summary"]["skipped_non_config_count"] == 260



def test_batch_review_rejects_zip_with_more_than_50_readable_configs():
    files = {f"configs/device-{idx}.cfg": f"hostname r{idx}\n" for idx in range(51)}
    response = client.post(
        "/api/batch-review",
        headers=HEADERS,
        json={
            "zip_filename": "too-many-configs.zip",
            "zip_base64": make_zip_base64(files),
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Batch review supports up to 50 readable config files per ZIP upload."



def test_batch_review_rejects_zip_with_too_many_total_members():
    files = {f"notes/readme-{idx}.md": "deployment checklist" for idx in range(1001)}
    response = client.post(
        "/api/batch-review",
        headers=HEADERS,
        json={
            "zip_filename": "too-many-members.zip",
            "zip_base64": make_zip_base64(files),
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "ZIP archive contains too many total entries. Limit is 1000 files per upload."


def test_batch_review_rejects_zip_payload_over_raw_upload_limit():
    oversized_archive = base64.b64encode(b"0" * (25 * 1024 * 1024 + 1)).decode("ascii")
    response = client.post(
        "/api/batch-review",
        headers=HEADERS,
        json={
            "zip_filename": "oversized-raw.zip",
            "zip_base64": oversized_archive,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "ZIP archive is too large. Limit is 25 MB per upload."


def test_pipeline_review_requires_api_key():
    response = client.post(
        "/api/pipeline/review",
        json={"config_text": "hostname r1"},
    )
    assert response.status_code == 401


def test_pipeline_review_blocks_on_critical_findings():
    response = client.post(
        "/api/pipeline/review",
        headers=HEADERS,
        json={
            "config_text": """hostname r1
enable password lab123
ip http server
line vty 0 4
 transport input telnet
!""",
            "fail_on_severity": "critical",
            "include_review": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["gate_status"] == "block"
    assert body["should_block"] is True
    assert body["blocking_findings_count"] >= 1
    assert any(finding["severity"] == "critical" for finding in body["blocking_findings"])
    assert body["review"] is None


def test_pipeline_review_can_gate_on_warning_threshold_and_attempt_webhook():
    captured = {}

    def fake_send(url, payload, headers):
        captured["url"] = url
        captured["payload"] = payload
        captured["headers"] = headers
        return {
            "attempted": True,
            "delivered": True,
            "status_code": 200,
            "detail": "Webhook delivered.",
        }

    with patch("app.api.routes._send_review_webhook", side_effect=fake_send) as send_webhook:
        response = client.post(
            "/api/pipeline/review",
            headers=HEADERS,
            json={
                "config_text": """hostname r1
ip http server
line vty 0 4
 transport input telnet
!""",
                "fail_on_severity": "warning",
                "webhook_url": "https://example.test/hooks/config-review",
                "webhook_headers": {"X-Pipeline-Token": "abc123"},
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["gate_status"] == "block"
    assert body["webhook"]["attempted"] is True
    send_webhook.assert_called_once()
    assert captured["url"] == "https://example.test/hooks/config-review"
    assert captured["headers"] == {"X-Pipeline-Token": "abc123"}
    assert captured["payload"]["event"] == "config_review.completed"
    assert captured["payload"]["gate"]["status"] == "block"
    assert captured["payload"]["gate"]["should_block"] is True
    assert captured["payload"]["gate"]["fail_on_severity"] == "warning"
    assert captured["payload"]["gate"]["blocking_findings_count"] == body["blocking_findings_count"]
    assert captured["payload"]["summary"]["hostname"] == body["summary"]["hostname"]
    assert len(captured["payload"]["blocking_findings"]) == body["blocking_findings_count"]
    assert captured["payload"]["review"]["review_id"] == body["review"]["review_id"]


def test_pipeline_review_respects_max_blocking_findings_threshold():
    response = client.post(
        "/api/pipeline/review",
        headers=HEADERS,
        json={
            "config_text": """hostname r1
ip http server
!""",
            "fail_on_severity": "warning",
            "max_blocking_findings": 3,
            "include_review": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["blocking_findings_count"] == 2
    assert body["max_blocking_findings"] == 3
    assert body["should_block"] is False
    assert body["gate_status"] == "pass"
    assert body["review"] is None


def test_pipeline_review_rejects_invalid_webhook_url():
    response = client.post(
        "/api/pipeline/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "webhook_url": "ftp://example.test/not-allowed",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "webhook_url must be a valid http(s) URL."


def test_export_review_requires_api_key():
    response = client.post(
        "/api/export/review",
        json={
            "config_text": "hostname r1",
            "target": "jira",
            "auth": {"auth_type": "bearer", "token": "secret"},
            "jira": {"base_url": "https://example.atlassian.net", "issue_key": "NET-123"},
        },
    )
    assert response.status_code == 401


def test_export_review_to_jira_attaches_artifacts_and_posts_comment():
    with patch("app.api.routes._http_request_multipart", return_value={
        "attempted": True,
        "delivered": True,
        "status_code": 200,
        "detail": "uploaded",
    }) as upload, patch("app.api.routes._http_request_json", return_value={
        "attempted": True,
        "delivered": True,
        "status_code": 201,
        "detail": "commented",
    }) as post_json:
        response = client.post(
            "/api/export/review",
            headers=HEADERS,
            json={
                "config_text": "hostname r1\nip http server\nline vty 0 4\n transport input telnet",
                "engineer_name": "Chandler",
                "target": "jira",
                "auth": {"auth_type": "bearer", "token": "jira-token"},
                "jira": {"base_url": "https://example.atlassian.net", "issue_key": "NET-123"},
                "include_pdf": True,
                "include_json": True,
                "include_html": False,
                "export_comment": "Attach to the maintenance ticket.",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "jira"
    assert body["destination"]["issue_key"] == "NET-123"
    assert len(body["attachments"]) == 2
    assert body["comment"]["attempted"] is True
    assert body["comment_components"][0]["component"] == "jira_comment"
    assert upload.call_count == 2
    post_json.assert_called_once()


def test_export_review_to_servicenow_attaches_artifacts_and_updates_record():
    with patch("app.api.routes._http_request_multipart", return_value={
        "attempted": True,
        "delivered": True,
        "status_code": 201,
        "detail": "uploaded",
    }) as upload, patch("app.api.routes._http_request_json", return_value={
        "attempted": True,
        "delivered": True,
        "status_code": 200,
        "detail": "updated",
    }) as patch_json:
        response = client.post(
            "/api/export/review",
            headers=HEADERS,
            json={
                "config_text": "hostname r1\nip http server",
                "target": "servicenow",
                "auth": {"auth_type": "basic", "username": "api-user", "password": "api-pass"},
                "service_now": {
                    "instance_url": "https://example.service-now.com",
                    "table_name": "change_request",
                    "record_sys_id": "abcd1234"
                },
                "include_pdf": True,
                "include_json": False,
                "include_html": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "servicenow"
    assert body["destination"]["record_sys_id"] == "abcd1234"
    assert len(body["attachments"]) == 1
    assert body["comment"]["attempted"] is True
    assert body["comment_components"][0]["component"] == "work_notes"
    upload.assert_called_once()
    patch_json.assert_called_once()


def test_query_requires_api_key():
    response = client.post(
        "/api/query",
        json={"config_text": "hostname r1", "question": "What is the hostname?"},
    )
    assert response.status_code == 401


def test_query_fallback_returns_answer():
    response = client.post(
        "/api/query",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nrouter bgp 65001\n neighbor 10.0.0.2 remote-as 65002",
            "question": "What BGP neighbors are configured?",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert "answer" in body
    assert isinstance(body["line_references"], list)


def test_multi_query_requires_api_key():
    response = client.post(
        "/api/query/multi",
        json={
            "configs": [
                {"config_text": "hostname r1"},
                {"config_text": "hostname r2"},
            ],
            "question": "Which devices have OSPF?",
        },
    )
    assert response.status_code == 401


def test_multi_query_fallback_returns_matches_across_devices():
    response = client.post(
        "/api/query/multi",
        headers=HEADERS,
        json={
            "configs": [
                {
                    "config_text": "hostname EDGE-A\nrouter ospf 1\n network 10.0.0.0 0.0.0.3 area 0\ninterface Loopback0\n ip address 1.1.1.1 255.255.255.255"
                },
                {
                    "config_text": "hostname EDGE-B\nrouter bgp 65002\n neighbor 192.0.2.1 remote-as 65001"
                },
            ],
            "question": "Which devices have OSPF area 0 configured?",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert "answer" in body
    assert isinstance(body["matches"], list)
    assert len(body["matches"]) == 1
    assert body["matches"][0]["hostname"] == "EDGE-A"
    assert 2 in body["matches"][0]["line_references"]


def test_multi_query_preserves_hostname_when_vendor_is_manually_overridden():
    response = client.post(
        "/api/query/multi",
        headers=HEADERS,
        json={
            "configs": [
                {
                    "config_text": "hostname EDGE-A\nrouter ospf 1\n network 10.0.0.0 0.0.0.3 area 0",
                    "vendor": "cisco_ios"
                },
                {
                    "config_text": "hostname EDGE-B\nrouter bgp 65002\n neighbor 192.0.2.1 remote-as 65001",
                    "vendor": "cisco_ios"
                },
            ],
            "question": "Which devices have OSPF area 0 configured?",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["matches"]) == 1
    assert body["matches"][0]["hostname"] == "EDGE-A"


def test_export_review_rejects_invalid_jira_url():
    response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "jira",
            "auth": {"auth_type": "bearer", "token": "jira-token"},
            "jira": {"base_url": "not-a-url", "issue_key": "NET-123"},
        },
    )

    assert response.status_code == 400
    assert "jira.base_url" in response.json()["detail"]


def test_export_review_to_webhook_posts_summary_and_embedded_artifacts():
    captured = {}

    def fake_send(url, payload, headers):
        captured["url"] = url
        captured["payload"] = payload
        captured["headers"] = headers
        return {
            "attempted": True,
            "delivered": True,
            "status_code": 202,
            "detail": "accepted",
        }

    with patch("app.api.routes._send_review_webhook", side_effect=fake_send) as send_webhook:
        response = client.post(
            "/api/export/review",
            headers=HEADERS,
            json={
                "config_text": "hostname r1\nip http server\nline vty 0 4\n transport input telnet",
                "target": "webhook",
                "webhook": {
                    "url": "https://itsm.example.test/hooks/change-record",
                    "headers": {"X-ITSM-Key": "abc123"},
                    "include_review_payload": True,
                    "embed_artifacts": True,
                },
                "include_pdf": False,
                "include_json": True,
                "include_html": True,
                "export_comment": "Push into alternate ITSM.",
                "metadata": {"change_id": "CHG-42"},
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "webhook"
    assert body["destination"]["url"] == "https://itsm.example.test/hooks/change-record"
    assert len(body["attachments"]) == 2
    assert body["delivery"]["attempted"] is True
    assert body["comment"]["attempted"] is False
    send_webhook.assert_called_once()
    assert captured["url"] == "https://itsm.example.test/hooks/change-record"
    assert captured["headers"] == {"X-ITSM-Key": "abc123"}
    assert captured["payload"]["metadata"]["change_id"] == "CHG-42"
    assert captured["payload"]["review"]["report"]["body"]["executive_summary"]["pass_fail_label"] in ["PASS", "FAIL"]
    assert all("data_base64" in artifact for artifact in captured["payload"]["artifacts"])


def test_export_review_to_webhook_rejects_invalid_url():
    response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "webhook",
            "webhook": {"url": "ftp://example.test/bad"},
        },
    )

    assert response.status_code == 400
    assert "webhook.url" in response.json()["detail"]


def test_export_review_surfaces_partial_jira_delivery_failures():
    with patch("app.api.routes._http_request_multipart", side_effect=[
        {
            "attempted": True,
            "delivered": True,
            "status_code": 200,
            "detail": "uploaded json",
        },
        {
            "attempted": True,
            "delivered": False,
            "status_code": 502,
            "detail": "attachment gateway failure",
        },
    ]) as upload, patch("app.api.routes._http_request_json", return_value={
        "attempted": True,
        "delivered": False,
        "status_code": 500,
        "detail": "jira comment failed",
    }) as post_json:
        response = client.post(
            "/api/export/review",
            headers=HEADERS,
            json={
                "config_text": "hostname r1\nip http server\nline vty 0 4\n transport input telnet",
                "target": "jira",
                "auth": {"auth_type": "bearer", "token": "jira-token"},
                "jira": {"base_url": "https://example.atlassian.net", "issue_key": "NET-123"},
                "include_pdf": True,
                "include_json": True,
                "include_html": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["export_status"] == "partial_failure"
    assert body["summary"]["has_failures"] is True
    assert body["summary"]["attachments_attempted"] == 2
    assert body["summary"]["attachments_delivered"] == 1
    assert body["summary"]["attachments_failed"] == 1
    assert body["summary"]["comment_attempted"] is True
    assert body["summary"]["comment_delivered"] is False
    assert not body["attachments"][1]["delivered"]
    assert body["attachments"][1]["detail"] == "attachment gateway failure"
    upload.assert_called()
    post_json.assert_called_once()


def test_export_review_surfaces_failed_webhook_delivery():
    with patch("app.api.routes._send_review_webhook", return_value={
        "attempted": True,
        "delivered": False,
        "status_code": 503,
        "detail": "upstream unavailable",
    }) as send_webhook:
        response = client.post(
            "/api/export/review",
            headers=HEADERS,
            json={
                "config_text": "hostname r1\nip http server",
                "target": "webhook",
                "webhook": {
                    "url": "https://itsm.example.test/hooks/change-record",
                    "include_review_payload": False,
                    "embed_artifacts": False,
                },
                "include_pdf": False,
                "include_json": True,
                "include_html": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["export_status"] == "failed"
    assert body["summary"]["has_failures"] is True
    assert body["summary"]["attachments_attempted"] == 1
    assert body["summary"]["attachments_delivered"] == 1
    assert body["summary"]["delivery_attempted"] is True
    assert body["summary"]["delivery_delivered"] is False
    assert body["delivery"]["status_code"] == 503
    assert body["delivery"]["detail"] == "upstream unavailable"
    send_webhook.assert_called_once()


def test_export_review_surfaces_partial_servicenow_record_updates():
    with patch("app.api.routes._http_request_multipart", return_value={
        "attempted": True,
        "delivered": True,
        "status_code": 201,
        "detail": "uploaded",
    }) as upload, patch("app.api.routes._http_request_json", side_effect=[
        {
            "attempted": True,
            "delivered": True,
            "status_code": 200,
            "detail": "updated work notes",
        },
        {
            "attempted": True,
            "delivered": False,
            "status_code": 403,
            "detail": "field write denied",
        },
    ]) as patch_json:
        response = client.post(
            "/api/export/review",
            headers=HEADERS,
            json={
                "config_text": "hostname r1\nip http server",
                "target": "servicenow",
                "auth": {"auth_type": "basic", "username": "api-user", "password": "api-pass"},
                "service_now": {
                    "instance_url": "https://example.service-now.com",
                    "table_name": "change_request",
                    "record_sys_id": "abcd1234",
                    "update_work_notes": True,
                    "update_short_description": True
                },
                "include_pdf": True,
                "include_json": False,
                "include_html": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["export_status"] == "partial_failure"
    assert body["summary"]["has_failures"] is True
    assert body["summary"]["attachments_attempted"] == 1
    assert body["summary"]["attachments_delivered"] == 1
    assert body["summary"]["comment_attempted"] is True
    assert body["summary"]["comment_delivered"] is False
    assert body["summary"]["comment_components_attempted"] == 2
    assert body["summary"]["comment_components_delivered"] == 1
    assert body["summary"]["comment_components_failed"] == 1
    assert body["comment"]["detail"] == "Failed ServiceNow record updates: short_description"
    assert body["failed_components"] == ["servicenow:short_description"]
    components = {component["component"]: component for component in body["comment_components"]}
    assert components["work_notes"]["delivered"] is True
    assert components["short_description"]["delivered"] is False
    assert components["short_description"]["status_code"] == 403
    upload.assert_called_once()
    assert patch_json.call_count == 2


def test_export_review_surfaces_partial_servicenow_attachment_failures():
    with patch("app.api.routes._http_request_multipart", side_effect=[
        {
            "attempted": True,
            "delivered": False,
            "status_code": 502,
            "detail": "attachment gateway failure",
        },
        {
            "attempted": True,
            "delivered": True,
            "status_code": 201,
            "detail": "uploaded pdf",
        },
    ]) as upload, patch("app.api.routes._http_request_json", return_value={
        "attempted": True,
        "delivered": True,
        "status_code": 200,
        "detail": "updated work notes",
    }) as patch_json:
        response = client.post(
            "/api/export/review",
            headers=HEADERS,
            json={
                "config_text": "hostname r1\nip http server",
                "target": "servicenow",
                "auth": {"auth_type": "basic", "username": "api-user", "password": "api-pass"},
                "service_now": {
                    "instance_url": "https://example.service-now.com",
                    "table_name": "change_request",
                    "record_sys_id": "abcd1234",
                    "update_work_notes": True,
                    "update_short_description": False
                },
                "include_pdf": True,
                "include_json": True,
                "include_html": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["export_status"] == "partial_failure"
    assert body["summary"]["has_failures"] is True
    assert body["summary"]["attachments_attempted"] == 2
    assert body["summary"]["attachments_delivered"] == 1
    assert body["summary"]["attachments_failed"] == 1
    assert body["summary"]["comment_attempted"] is True
    assert body["summary"]["comment_delivered"] is True
    assert not body["attachments"][0]["delivered"]
    assert body["attachments"][0]["detail"] == "attachment gateway failure"
    assert body["failed_components"] == [f"attachment:{body['attachments'][0]['filename']}"]
    upload.assert_called()
    patch_json.assert_called_once()


def test_export_review_to_jira_requires_auth():
    response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "jira",
            "jira": {"base_url": "https://example.atlassian.net", "issue_key": "NET-123"},
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "auth is required for Jira export."


def test_export_review_to_jira_rejects_noop_request():
    response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "jira",
            "auth": {"auth_type": "bearer", "token": "jira-token"},
            "jira": {
                "base_url": "https://example.atlassian.net",
                "issue_key": "NET-123",
                "add_comment": False,
            },
            "include_pdf": False,
            "include_json": False,
            "include_html": False,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Jira export must attach at least one artifact or add a comment."


def test_export_review_to_servicenow_rejects_noop_request():
    response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "servicenow",
            "auth": {"auth_type": "bearer", "token": "sn-token"},
            "service_now": {
                "instance_url": "https://example.service-now.com",
                "record_sys_id": "abcd1234",
                "update_work_notes": False,
                "update_short_description": False,
            },
            "include_pdf": False,
            "include_json": False,
            "include_html": False,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "ServiceNow export must attach at least one artifact or update work notes/short description."


def test_export_review_to_servicenow_rejects_basic_auth_without_password():
    response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "servicenow",
            "auth": {"auth_type": "basic", "username": "api-user"},
            "service_now": {
                "instance_url": "https://example.service-now.com",
                "record_sys_id": "abcd1234"
            },
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Basic auth requires username and password."


def test_export_review_to_servicenow_rejects_invalid_instance_url():
    response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "servicenow",
            "auth": {"auth_type": "bearer", "token": "sn-token"},
            "service_now": {
                "instance_url": "not-a-url",
                "record_sys_id": "abcd1234"
            },
        },
    )

    assert response.status_code == 400
    assert "service_now.instance_url" in response.json()["detail"]


def test_export_review_rejects_blank_destination_identifiers():
    jira_response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "jira",
            "auth": {"auth_type": "bearer", "token": "jira-token"},
            "jira": {"base_url": "https://example.atlassian.net", "issue_key": "   "},
        },
    )

    assert jira_response.status_code == 422
    assert jira_response.json()["detail"][0]["loc"][-1] == "issue_key"

    servicenow_response = client.post(
        "/api/export/review",
        headers=HEADERS,
        json={
            "config_text": "hostname r1\nip http server",
            "target": "servicenow",
            "auth": {"auth_type": "bearer", "token": "sn-token"},
            "service_now": {
                "instance_url": "https://example.service-now.com",
                "record_sys_id": "   "
            },
        },
    )

    assert servicenow_response.status_code == 422
    assert servicenow_response.json()["detail"][0]["loc"][-1] == "record_sys_id"
