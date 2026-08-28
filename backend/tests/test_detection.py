from detection.normalizer import normalize_url
from detection.rule_engine import analyze


def detected(url):
    return analyze(normalize_url(url))


def test_normal_url_is_benign():
    assert detected("https://portal.example.test/search?q=hello")["attack_type"] == "BENIGN"


def test_sql_like_url():
    assert detected("https://portal.example.test/search?q=%27+OR+%271%27%3D%271")["attack_type"] == "SQL_INJECTION"


def test_xss_like_url():
    assert detected("https://portal.example.test/?q=%3Cscript%3Ealert(1)%3C/script%3E")["attack_type"] == "XSS"


def test_directory_traversal_url():
    assert detected("https://files.example.test/download?f=../../../../etc/passwd")["attack_type"] in {"DIRECTORY_TRAVERSAL", "LFI"}


def test_ssrf_private_ip():
    result = detected("https://gateway.example.test/preview?url=http://10.0.0.8/admin")
    assert result["attack_type"] == "SSRF"
    assert any("private" in item.lower() for item in result["evidence"])


def test_duplicate_conflicting_parameters():
    result = detected("https://accounts.example.test/profile?role=user&role=admin")
    assert result["attack_type"] == "HTTP_PARAMETER_POLLUTION"


def test_invalid_url_does_not_crash():
    value = normalize_url("http://[broken")
    assert value["original"] == "http://[broken"
    assert value["parse_error"]


def test_loopback_is_private_ssrf_target():
    assert detected("https://gateway.example.test/?target=http://127.0.0.1/")["attack_type"] == "SSRF"
