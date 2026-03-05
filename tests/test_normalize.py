from whitelistchecker.normalize import normalize_key


def test_normalize_fragment_and_spaces():
    assert normalize_key("vless://example#frag extra") == "vless://example"
    assert normalize_key("vmess://example   ") == "vmess://example"
