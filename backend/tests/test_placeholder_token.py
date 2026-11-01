from app import auth


def test_example_placeholder_token_never_authenticates(monkeypatch):
    ph = "CHANGE_ME_generate_with_openssl_rand_hex_32"
    monkeypatch.setenv("QYRIX_ADMIN_TOKEN", ph)
    assert auth._match(ph, "QYRIX_ADMIN_TOKEN") is False


def test_real_length_token_still_authenticates(monkeypatch):
    monkeypatch.setenv("QYRIX_ADMIN_TOKEN", "a" * 40)
    assert auth._match("a" * 40, "QYRIX_ADMIN_TOKEN") is True
