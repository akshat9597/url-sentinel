from ingestion.access_logs import parse_access_logs


def test_nginx_combined_log_is_parsed():
    line = '192.0.2.25 - - [28/Aug/2026:11:00:00 +0530] "GET /search?q=hello HTTP/1.1" 200 128 "-" "ByteForce-Test/1.0"'
    events, errors = parse_access_logs(line, "nginx", "portal.example.test", "198.51.100.10")
    assert not errors
    assert events[0]["src_ip"] == "192.0.2.25"
    assert events[0]["host"] == "portal.example.test"
    assert events[0]["uri"] == "/search?q=hello"
    assert events[0]["status_code"] == 200


def test_json_lines_log_is_parsed():
    line = '{"time_iso8601":"2026-08-28T11:00:00+05:30","remote_addr":"203.0.113.8","request_method":"GET","host":"shop.example.test","request_uri":"/products?id=7","status":404}'
    events, errors = parse_access_logs(line, "json")
    assert not errors
    assert events[0]["src_ip"] == "203.0.113.8"
    assert events[0]["status_code"] == 404


def test_malformed_log_returns_friendly_error():
    events, errors = parse_access_logs("this is not an access log")
    assert events == []
    assert "Line 1" in errors[0]

