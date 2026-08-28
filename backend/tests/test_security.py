from security import create_token, decode_token, hash_password, redact_url, verify_password
from api.authentication import LoginRequest


def test_sensitive_query_values_are_redacted():
    result = redact_url("https://portal.example.test/login?username=alex&password=secret&token=abc")
    assert "alex" in result
    assert "secret" not in result
    assert "abc" not in result
    assert result.count("%5BREDACTED%5D") == 2


def test_password_hash_can_be_verified():
    encoded = hash_password("a-safe-test-password")
    assert verify_password("a-safe-test-password", encoded)
    assert not verify_password("incorrect", encoded)


def test_signed_session_rejects_tampering_and_expiry():
    token = create_token("analyst@example.test", "ANALYST", "test-secret")
    assert decode_token(token, "test-secret")["sub"] == "analyst@example.test"
    assert decode_token(token + "x", "test-secret") is None
    expired = create_token("analyst@example.test", "ANALYST", "test-secret", expires_seconds=-1)
    assert decode_token(expired, "test-secret") is None


def test_reserved_local_admin_email_is_allowed():
    request = LoginRequest(email="admin@byteforce.local", password="safe-test-password")
    assert request.email == "admin@byteforce.local"
