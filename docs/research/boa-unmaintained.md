# Boa web server: discontinued, unpatched (CVE-2009-4496 and others)

*Researched: 2026-10-24. Researcher: Claude (first end-to-end run of the `add-checker` workflow). Checker: `boa-unmaintained` (data-only advisory, `any_version`).*

## Summary
Boa is a small web server that was discontinued in 2005 and is still embedded in many IoT firmwares and
SDKs. It has known vulnerabilities and nothing upstream will fix them. A device whose `Server` header says
`Boa` (with or without a version) is running an unmaintained server. The checker reports that as a
lifecycle/exposure finding; it does **not** claim any specific exploit works against the device.

## Sources
| # | Source | Kind | Date read | Established |
| - | ------ | ---- | --------- | ----------- |
| 1 | Microsoft Security blog, 2022-11-22, "Vulnerable SDK components lead to supply chain risks in IoT and OT environments" (full page fetched) | vendor research | 2026-10-24 | Boa discontinued since 2005; still used by many IoT vendors/SDKs; "firmware updates and downstream patches do not address its known vulnerabilities"; CVE-2009-4496 is the Boa-specific CVE it names; the RealTek SDK CVEs (CVE-2021-35395, CVE-2022-27255) are separate; no Boa version numbers or banner string given |
| 2 | Web-search results for CVE-2017-9833 (Ubuntu CVE tracker, Debian tracker, cvefeed, Exploit-DB 42290): search snippets only | distro trackers / press | 2026-10-24 | CVE-2017-9833 (Boa 0.94.14rc21, `wapopen` CGI, `FILECAMERA` traversal) is disputed: Debian "NOT-FOR-US", vulnerable CGI belongs to a vendor, not Boa |

Could not be reached: security-tracker.debian.org (DNS blocked here). Items 2 rest on search snippets and are unverified.

## Affected and fixed versions
| Branch | Affected | First fixed | Source | Notes |
| ------ | -------- | ----------- | ------ | ----- |
| all (0.9x, incl. 0.94.13, 0.94.14rc21) | all | none | 1 | Discontinued 2005; vendors may ship private forks, which a banner cannot distinguish |

## Conflicts between sources
* **CVE-2017-9833**: NVD-derived text says "Boa 0.94.14rc21"; Debian/Ubuntu say disputed and not a Boa flaw.
  Decision: do not cite it. A scanner that reported it would mislabel devices.
* Press coverage describes Boa as having "many vulnerabilities"; only CVE-2009-4496 is named in the one primary
  source read. Decision: cite that one CVE, say "known vulnerabilities" without enumerating more.

## What a remote scanner can observe
`Server: Boa/0.94.14rc21` (or `Boa/0.94.13`, or just `Boa`) in HTTP response headers. Many Boa builds
print the banner; some vendors remove it, in which case this checker is silent (no signal, no guess).

## Detection decision
Data-only advisory, `product = "boa"`, `any_version = true`, `from = "0.0"` (never fixed). Reported with
**Likely** confidence: the banner is authoritative about *what server software is running* and no fix exists
upstream; it is **not** evidence that a specific CVE is exploitable. A distribution-style banner would drop
it to **Possible** (not expected for Boa). Passive only: the engine already reads `GET /`.
Deliberately not done: probing for `wapopen` or any CGI, any traversal request, any exploit.

## Open questions
* Verify CVE-2009-4496's description and affected versions against the NVD record and the Debian tracker.
* Confirm whether any maintained fork (e.g. vendor-private) announces a distinct banner we could exempt.
* Once verified, set `verified = true` in `data/advisories.toml`.
