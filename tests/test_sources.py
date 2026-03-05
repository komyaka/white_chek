from whitelistchecker.sources import load_source_urls, extract_proxy_lines
import tempfile


def test_load_source_urls():
    content = """
# comment
http://a.com http://b.com

https://c.com
"""
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(content)
        f.flush()
        path = f.name
    urls = load_source_urls(path)
    assert urls == ["http://a.com", "http://b.com", "https://c.com"]


def test_extract_proxy_lines():
    text = """
random
vless://a
vmess://b  
hysteria2://c#tag
"""
    lines = extract_proxy_lines(text)
    assert lines == ["vless://a", "vmess://b", "hysteria2://c#tag"]
