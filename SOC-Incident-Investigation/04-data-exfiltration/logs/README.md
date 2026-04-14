# Lab sample files — Data exfiltration (04)

These **small synthetic files** are for **offline CLI practice**. They match the narrative in [`../README.md`](../README.md). Full **Mordor / Security-Datasets** exports are larger and more realistic.

## Files

| File | Used in |
|------|---------|
| `network_connections.csv` | Large outbound transfers (`awk` on column 9) |
| `file_events.txt` | Zip staging |
| `process_creation.txt` | Directory discovery (`dir` / `Get-ChildItem`) |
| `netstat_dump.txt` | External connections on port 443 |
| `known_good_domains.txt` | `grep -v` baseline (placeholder) |
| `auth.log` | Session open for `contractor1` |

## Run queries against these samples (WSL / Linux)

From **`04-data-exfiltration/`**:

```bash
export L="$(pwd)/logs"
```

**Step 1 — large transfers**

```bash
awk -F',' '$9 > 50000 {print $1, $3, $5, $9}' "$L/network_connections.csv" | sort -k4 -rn | head -20
```

**Step 2 — staging**

```bash
grep -E "\.zip|\.rar|\.7z|\.tar" "$L/file_events.txt" | grep -i "create\|write" | awk '{print $1, $2, $5}'
```

**Step 3 — discovery**

```bash
grep -iE "dir |Get-ChildItem|tree " "$L/process_creation.txt" | head -10
```

**Step 4 — netstat (simplified)**

```bash
grep -E "ESTABLISHED.*:443" "$L/netstat_dump.txt" | grep -v -f "$L/known_good_domains.txt" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

If `grep -v -f` fails on an empty file, use:

```bash
grep -E "ESTABLISHED.*:443" "$L/netstat_dump.txt" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

**Step 5 — user session**

```bash
grep "host-42" "$L/auth.log" | tail -20
```

For the full command list and documented outputs, see [`../queries.md`](../queries.md).
