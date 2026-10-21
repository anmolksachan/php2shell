# CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell") — Notes

Honest status tracking, not hype. Compiled Oct 21, 2026. Verify dates/links yourself before relying on this for anything important.

## What's confirmed

- Two critical, pre-auth RCE vulnerabilities in **PHP core** (not a plugin/CMS):
  - **CVE-2026-109618** — RCE via out-of-memory corruption
  - **CVE-2026-109619** — RCE via stale global state left over between requests
- **CVSS v4.0 9.2**, both.
- **Discovered by Wiz Research** (Sagi Tzadik, Shir Tamari, Nir Ohfeld, Tomer Schwartz), working with the PHP Foundation. Coverage independently corroborated by Sansec, Cloudflare, Huntress, Imperva, SOCRadar.
- **Official patch released** by PHP, Oct 21, 2026 14:00 UTC. Fixed in **8.5.12, 8.4.27, 8.3.36, 8.2.35**.
- PHP's own advisory: *"a demonstrated exploit where an unauthenticated request can trigger the attack before any application code runs."* Highest risk on **mod_php**; PHP-FPM, php-cgi, FrankenPHP, LiteSpeed also affected.
- Wiz demonstrated working pre-auth RCE chains against current **WordPress, Drupal, and Joomla** container images, calling them "representative" targets — the bug is in PHP itself, so exposure isn't limited to those three.
- PHP ≤8.1 is EOL — only minimal source backports exist. That's an upgrade problem, not a patch problem.

## What's NOT confirmed (as of this writing)

- **No independently-verified, fully weaponized public exploit.** The one repo claiming full exploitation (`ikow/php2shell-poc`) only had one piece — session fixation — check out against a real, open php-src PR; the actual UAF/RCE chain was self-reported, unreproduced by anyone else.
- A later, more credible lab repo from a named researcher (`dinosn/php-cve-2026-10961x-lab-poc`, Nicolas Krassas) demonstrates the vulnerability classes are real and reproducible **under lab conditions**, but explicitly states it is **not** a portable, remote, blind exploit — one chain needs debugger calibration, the other needs local `/proc` access on the target host, and php-fpm was found unaffected by one of the two chains on the tested image.
- **No confirmed in-the-wild exploitation.** No fraudulent/malicious use found in Certificate Transparency or elsewhere as of this writing.
- The "70% of the internet" framing floating around is PHP's general market-share figure, not something specifically measured for this advisory.

## Nuclei template

[`CVE-2026-109618-109619-php2shell.yaml`](./CVE-2026-109618-109619-php2shell.yaml) — **version detection only, no exploitation.**

- Checks the `X-Powered-By: PHP/x.y.z` response header against the patched branches.
- Deliberately does **not** attempt to trigger the vulnerability — there is no safe, reliable, remote exploitation trigger to encode as of this writing, and a nuclei template is built for mass automated scanning, which is the wrong place to carry an unproven exploit even if one existed.
- **Tested locally** against a real PHP 8.3.6 instance (flagged, correctly) and a simulated PHP 8.3.36 banner (not flagged, correctly). Not tested against a live/production target.
- Known blind spot: many production stacks hide or strip `X-Powered-By`. A clean scan is **not** proof of patching — confirm via `php -v` / package manager wherever you can.

```
nuclei -u <target> -t CVE-2026-109618-109619-php2shell.yaml
```

## Sources

- [PHP official advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w](https://github.com/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618)
- [GHSA-6wmf-4rv5-p3rp](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619)
- [Wiz Research write-up](https://www.wiz.io/blog/php2shell-php-rce) / [php2shell.com](https://php2shell.com)
- [Sansec technical analysis](https://sansec.io/research/php2shell)

## Disclaimer

For defensive/inventory use only. Don't run anything exploit-shaped against systems you don't own or aren't authorized to test. Re-verify version numbers and claims above against the primary sources before acting on them — this situation was moving fast and some of it (especially the unofficial PoC repos) was unverified at the time it was written.
