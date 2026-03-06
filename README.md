# Standalone Whitelist Checker

A Python 3.11+ tool that collects proxy configs from multiple sources,
deduplicates them, checks connectivity through real engines (Xray / Hysteria),
optionally runs a speedtest, and writes five standardised output files.

---

## Quick Start

```bash
# Install
pip install -e .

# Copy and edit configuration
cp .env.example .env

# Create a links file with one source URL per line
echo "https://raw.githubusercontent.com/example/proxies/main/list.txt" > links.txt

# Run (egress off, speedtest off — safest for first run)
whitelist-checker \
  --links-file links.txt \
  --output-dir configs \
  --egress-mode off \
  --no-speedtest

# Run stub smoke-test (no real engines, no internet required for checks)
whitelist-checker \
  --links-file links.txt \
  --output-dir configs \
  --engine-mode stub \
  --egress-mode off \
  --no-speedtest
```

After a successful run you will find **exactly 5 files** in `configs/`:

```
configs/white-list_available
configs/white-list_available(top100)
configs/white-list_available_st
configs/white-list_available_st(top100)
configs/white-list_available_source_stats.txt
```

---

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--links-file` | `links.txt` | File containing source URLs (one or more per line, `#` comments ok) |
| `--output-dir` | `configs` | Directory for output files |
| `--output-file` | `white-list_available` | Base name for output files |
| `--egress-mode` | `off` | Egress restriction: `off`, `iptables`, `linux-netns` |
| `--cidr-whitelist-url` | (github raw) | URL to fetch CIDR list for egress |
| `--cidr-whitelist-file` | — | Local file for CIDRs (takes priority over URL) |
| `--engine-mode` | `real` | `real` (spawn Xray/Hysteria) or `stub` (all keys pass) |
| `--xray-path` | auto-discover | Path to `xray` binary |
| `--hysteria-path` | auto-discover | Path to `hysteria` binary |
| `--speedtest` / `--no-speedtest` | enabled | Run speedtest pipeline |
| `--recheck-previous` / `--no-recheck-previous` | enabled | Merge previous whitelist into input |
| `--use-notworkers` / `--no-use-notworkers` | enabled | Exclude/append notworkers |
| `--threads` | `200` | Max parallel workers |
| `--base-port` | `20000` | First SOCKS port to allocate |
| `--mode` | `merge` | `merge` (all sources) or `single` |

All flags can also be set via environment variables — see `.env.example`.

---

## Egress Modes

| Mode | Behaviour |
|---|---|
| `off` | No network restriction (default) |
| `iptables` | Sets `OUTPUT` policy to `DROP`; allows lo, ESTABLISHED/RELATED, DNS to 8.8.8.8/8.8.4.4/1.1.1.1, and each CIDR. Rules are rolled back on exit. Fatal if apply fails. |
| `linux-netns` | Creates a network namespace with a veth pair (10.200.0.0/24), applies MASQUERADE via host iptables, and applies the same OUTPUT rules inside the netns. Cleans up on exit. Fatal on failure. |

> **Note:** `iptables` and `linux-netns` modes require root. Always rolled back even on crash.

---

## Outputs

| File | Description |
|---|---|
| `white-list_available` | Working proxies sorted by latency (ascending) |
| `white-list_available(top100)` | Top 100 fastest from above |
| `white-list_available_st` | After speedtest filtering (or copy of available when speedtest disabled) |
| `white-list_available_st(top100)` | Top 100 from speedtest output |
| `white-list_available_source_stats.txt` | `# working_count TAB source_url` sorted by count ASC then URL ASC; multi-credit (a working key counts for every source that contained it) |

Set `KEEP_ONLY_WHITELIST_FILES=true` (default) to remove all other files from the output directory after a successful run.

---

## Smoke Test (real sources, egress off, speedtest off)

```bash
# 1. Create a minimal links file
cat > /tmp/smoke_links.txt << 'EOF'
# Add one or two real proxy list URLs here
https://raw.githubusercontent.com/example/list/main/proxies.txt
EOF

# 2. Run
whitelist-checker \
  --links-file /tmp/smoke_links.txt \
  --output-dir /tmp/smoke_out \
  --egress-mode off \
  --no-speedtest

# 3. Verify exactly 5 files
ls /tmp/smoke_out/
# Expected:
#   white-list_available
#   white-list_available(top100)
#   white-list_available_st
#   white-list_available_st(top100)
#   white-list_available_source_stats.txt
```

---

## Integration Test (stub, offline, no binaries needed)

```bash
# Run the full offline stub integration tests
python -m pytest tests/test_integration_stub.py -v

# Run all tests
python -m pytest tests/ -v
```

The integration tests:
- Mock all HTTP source fetches (no internet)
- Use `ENGINE_MODE=stub` (no Xray/Hysteria binaries needed)
- Verify exactly 5 output files are produced
- Verify source stats file format and multi-credit counting
- Verify notworkers exclusion and append behaviour
- Verify `_st` files are produced when speedtest is disabled

---

## Engine Binaries

Xray is used for `vless://`, `vmess://`, `trojan://`, `ss://` protocols.  
Hysteria is used for `hysteria://`, `hysteria2://`, `hy2://` protocols.

Binaries are auto-discovered from `$PATH`. Override with `XRAY_PATH` / `HYSTERIA_PATH` or `--xray-path` / `--hysteria-path`.

---

## Dependencies

```
httpx[socks]>=0.27.0
pydantic>=2.6.0
rich>=13.7.0
pyyaml>=6.0.1
```

Install with:
```bash
pip install -e .
```
