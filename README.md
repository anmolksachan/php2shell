# PHP2Shell — CVE-2026-109618 / CVE-2026-109619

Pre-auth RCE research lab for PHP's `session.upload_progress` heap chain.  
**GitHub:** https://github.com/anmolksachan/php2shell  
**Blog:** [PHP2Shell: CVE-2026-109618 Pre-Auth RCE, I Tested It Locally and Here’s How It Works](https://anmolksachan.medium.com/php2shell-cve-2026-109618-pre-auth-rce-i-tested-it-locally-and-heres-how-it-works-0a50d01fa552)

> Authorized testing only. All testing was done against local Docker containers on 127.0.0.1.

---

## Folder Structure

```
php2shell/
├── README.md              ← you are here
├── blog.md                ← full technical writeup + Medium/GitHub publishing guide
├── php2shell-lab.zip      ← everything bundled as a zip (for GitHub release)
├── scripts/               ← run these in order
│   ├── setup.sh           ← Step 1: clone toolkit, bootstrap exploit, start Docker labs
│   ├── run_exploit.sh     ← Step 2: run the exploit against PHP 8.5.11
│   ├── run_interactive.sh ← Step 3 (optional): interactive REPL
│   ├── test_all_labs.sh   ← test all 7 containers at once
│   └── cleanup.sh         ← stop and remove all Docker containers
└── toolkit/               ← devploit/php2shell (auto-cloned by setup.sh)
    ├── tools/             ← dispatcher, labs manager, calibration tools
    ├── profiles/          ← per-build offset profiles (JSON)
    ├── lab/               ← Docker lab configs + proof output
    └── vendor/            ← 9bie upstream exploit (fetched by bootstrap)
```

---

## Quick Start (do these in order)

```bash
# 1. Start here
cd scripts/
chmod +x *.sh

# 2. Setup: clones toolkit, bootstraps upstream exploit, starts 7 Docker labs
./setup.sh

# 3. Run the exploit against PHP 8.5.11 (verified RCE)
./run_exploit.sh

# 4. Run a custom command
./run_exploit.sh http://127.0.0.1:8106/index.php p2s-lab-8511 "id; uname -a"

# 5. Interactive REPL (one exploit chain per command you type)
./run_interactive.sh

# 6. Test all 7 labs at once
./test_all_labs.sh

# 7. Clean up when done
./cleanup.sh
```

---

## Lab Containers (started by setup.sh)

| Port | PHP Version | Container Name | RCE Confirmed |
|------|------------|----------------|---------------|
| :8100 | 7.4.33 | p2s-lab-7433 | No |
| :8101 | 8.0.30 | p2s-lab-8030 | No |
| :8102 | 8.1.34 | p2s-lab-8134 | No |
| :8103 | 8.2.34 | p2s-lab-8234 | No |
| :8104 | 8.3.35 | p2s-lab-8335 | No |
| :8105 | 8.4.26 | p2s-lab-8426 | **Yes** |
| :8106 | 8.5.11 | p2s-lab-8511 | **Yes** |

---

## CVE Summary

| Field | Value |
|-------|-------|
| CVEs | CVE-2026-109618, CVE-2026-109619 |
| Affected | PHP 8.4.x ≤ 8.4.26, PHP 8.5.x ≤ 8.5.11 + Apache mod_php prefork |
| Fixed in | PHP 8.4.27, PHP 8.5.12 (released 2026-10-21) |
| Auth required | None |
| Attack vector | Network (HTTP only) |
| Impact | RCE as www-data |

---

## Credits

- **Toolkit:** [devploit/php2shell](https://github.com/devploit/php2shell)
- **Upstream exploit:** [9bie](https://github.com/9bie/php2shell-bypass-aslr-exp)
- **CVE discovery:** Wiz Research
- **This lab:** [@anmolksachan](https://github.com/anmolksachan)
