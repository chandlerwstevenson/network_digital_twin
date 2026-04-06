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
