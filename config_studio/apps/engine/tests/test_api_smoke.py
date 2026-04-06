from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)
HEADERS = {"x-api-key": "dev-engine-key"}


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
