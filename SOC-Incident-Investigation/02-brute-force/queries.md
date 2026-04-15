# Investigation Queries — Brute Force

**Dataset (reference):** Mordor / Security-Datasets — https://github.com/OTRF/Security-Datasets  
**Lab sample (repo):** [`logs/sample-auth.log`](./logs/sample-auth.log) — synthetic OpenSSH-style lines for offline practice  
**Tools:** Linux CLI (`grep`, `awk`, `sort`, `uniq`) — use **WSL**, Git Bash, or a VM if you are on Windows  

---

## Path setup

Use the sample file in this folder, or a live system log:

```bash
export AUTH_LOG="$(pwd)/logs/sample-auth.log"
# On Linux with local evidence:
# export AUTH_LOG="/var/log/auth.log"
```

All commands below use `"$AUTH_LOG"`.

---

## WSL, BusyBox, and grep -P

Some WSL images ship **BusyBox** `grep`, which **does not** support **`-P`** (Perl-style regex). You will see `grep: unrecognized option: P`.

| Approach | What to do |
|----------|------------|
| **GNU grep** | Use **Ubuntu** on WSL (`wsl -d Ubuntu`) or install GNU grep (`apt install grep` on Debian/Ubuntu). Then the `grep -oP` commands below work as written. |
| **Portable IP counts** | Use **awk** on standard OpenSSH lines — the source IP is **three fields before the end** (`$(NF-3)` = IP between `from` and `port`). |
| **Prompt character** | Do not paste the shell **`$`** when copying commands; it is not part of the command. |

**Portable substitute for Steps 2–3 (per-IP failure counts):**

```bash
grep "Failed password" "$AUTH_LOG" | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
```

**Portable substitute for Step 5 (username histogram):** GNU `grep -oP` is easiest; on BusyBox, run the same queries under **GNU grep**, or use:

```bash
grep "Failed password" "$AUTH_LOG" | awk '
  /invalid user/ { for (i = 1; i <= NF; i++) if ($i == "user") { print $(i+1); next } }
  { for (i = 1; i <= NF; i++) if ($i == "for" && $(i+1) != "invalid") { print $(i+1); next } }
' | sort | uniq -c | sort -rn
```

---

## Step 1 — List failed login attempts

**Goal:** See raw authentication failures (noise vs pattern).

```bash
grep "Failed password" "$AUTH_LOG"
```

**Example output (truncated; sample has 23 lines):**

```
Apr 10 08:14:03 srv-sshd sshd[3842]: Failed password for admin from 203.0.113.15 port 44120 ssh2
Apr 10 08:14:05 srv-sshd sshd[3843]: Failed password for root from 203.0.113.15 port 44120 ssh2
Apr 10 08:14:07 srv-sshd sshd[3844]: Failed password for user1 from 203.0.113.15 port 44120 ssh2
Apr 10 08:14:10 srv-sshd sshd[3845]: Failed password for admin from 203.0.113.15 port 44122 ssh2
Apr 10 08:14:12 srv-sshd sshd[3846]: Failed password for root from 203.0.113.15 port 44122 ssh2
Apr 10 08:14:15 srv-sshd sshd[3847]: Failed password for invalid user guest from 203.0.113.15 port 44124 ssh2
Apr 10 08:14:18 srv-sshd sshd[3848]: Failed password for admin from 203.0.113.15 port 44126 ssh2
Apr 10 08:14:21 srv-sshd sshd[3849]: Failed password for user1 from 203.0.113.15 port 44126 ssh2
Apr 10 08:14:24 srv-sshd sshd[3850]: Failed password for root from 203.0.113.15 port 44128 ssh2
Apr 10 08:14:27 srv-sshd sshd[3851]: Failed password for admin from 203.0.113.15 port 44128 ssh2
Apr 10 08:14:30 srv-sshd sshd[3852]: Failed password for user1 from 203.0.113.15 port 44130 ssh2
Apr 10 08:14:33 srv-sshd sshd[3853]: Failed password for root from 203.0.113.15 port 44130 ssh2
```

**Finding:** Repeated failures against **admin**, **root**, and **user1**; one **invalid user** probe (**guest**). Same source IP appears on every line in this window.

---

## Step 2 — Count failed attempts per source IP

**Goal:** Rank external hosts by failure volume (who is the brute-force candidate).

**GNU grep:**

```bash
grep "Failed password" "$AUTH_LOG" | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn
```

**Portable (BusyBox / no `-P`):**

```bash
grep "Failed password" "$AUTH_LOG" | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
```

**Example output (lab sample):**

```
     20 203.0.113.15
      3 198.51.100.3
```

**Finding:** **203.0.113.15** accounts for most failures — primary attacker candidate. **198.51.100.3** is secondary noise (investigate or baseline).

---

## Step 3 — Confirm the attacker IP

**Goal:** Tie the loudest IP to the attack narrative (blocklist / enrichment input).

**GNU grep:**

```bash
grep "Failed password" "$AUTH_LOG" | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -5
```

**Portable:**

```bash
grep "Failed password" "$AUTH_LOG" | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -5
```

**Example output:**

```
     20 203.0.113.15
      3 198.51.100.3
```

**Finding:** **203.0.113.15** is the **attacker IP** for this incident (DOCUMENTATION prefix **203[.]0[.]113[.]15** when publishing).

---

## Step 4 — Detect successful login (same service, same day)

**Goal:** Find **Accepted** lines after the failure burst — indicates valid credentials.

```bash
grep -E "Accepted (password|publickey)" "$AUTH_LOG"
```

**Example output:**

```
Apr 10 08:15:52 srv-sshd sshd[3901]: Accepted password for user1 from 203.0.113.15 port 44140 ssh2
```

**Finding:** Password authentication **succeeded** for **user1** from the **same** IP that generated the failures — classic **brute-then-success** sequence.

---

## Step 5 — Identify compromised account and targeted names

**Goal:** Confirm which account authenticated, and which names were guessed.

```bash
grep "Accepted" "$AUTH_LOG" | grep "user1"
```

**GNU grep:**

```bash
grep "Failed password" "$AUTH_LOG" | grep -oP 'Failed password for\s+(?:invalid user\s+)?\K\S+' | sort | uniq -c | sort -rn
```

**Portable:** use the **`awk`** username histogram in the **WSL, BusyBox, and grep -P** section above.

**Example output (accepted):**

```
Apr 10 08:15:52 srv-sshd sshd[3901]: Accepted password for user1 from 203.0.113.15 port 44140 ssh2
```

**Example output (targets, lab sample):**

```
      8 admin
      7 root
      7 user1
      1 guest
```

**Finding:** **user1** is the **compromised** account (successful password). **admin**, **root**, and **user1** were heavily targeted; **guest** appeared as an invalid-user probe.

---

## Step 6 — Optional: failure → success timeline for one IP

**Goal:** Single view of **Failed** and **Accepted** from **203.0.113.15**.

```bash
grep "203.0.113.15" "$AUTH_LOG" | grep -E "Failed password|Accepted"
```

**Finding:** Validates ordering: many **Failed password** lines, then **Accepted password** for **user1**.

---

## Step 7 — IOC handoff to SOAR

**Goal:** Copy the external brute-force IP into enrichment (see [`ioc-enrichment.md`](./ioc-enrichment.md)).

```bash
echo "203.0.113.15"
```

Defang for written reports: `203[.]0[.]113[.]15`.

---

*Mordor exports may produce higher failure counts (e.g. hundreds per IP); the workflow is identical.*
