# Threat-intelligence feeds: licensing position and API keys

ShadowStrike Phantom can pull from public threat-intelligence feeds. Every feed that needs an
API key is licensed for non-commercial use on its free tier, so the product never ships a key.
Each installation supplies its own. This document records that position so that no build ever
bakes a key in.

## What each feed's free tier allows

| Feed | Key name in `feeds.credentials` | Free-tier terms |
|---|---|---|
| abuse.ch (MalwareBazaar, ThreatFox, URLhaus) | `ABUSECH_AUTH_KEY` | abuse.ch Terms of Use, effective 2025-11-04. Section 3.1 limits free access to not-for-profit purposes. Section 4 says commercial use may need a paid subscription, managed by Spamhaus, now the primary licensee of the abuse.ch datasets. |
| AlienVault OTX | `OTX_API_KEY` | The OTX EULA makes OTX free to end users for non-commercial use. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | VirusTotal's Public vs Premium API page says the Public API "must not be used in commercial products or services". It is also capped at 500 requests a day and 4 a minute. |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | The free tier is meant for individuals, at 1,000 checks a day. That is far too few for an endpoint product. |

These terms belong to the providers and can change. Check the current text before relying on
this table for a commercial deployment.

## How the product meets them

- **Every installation supplies its own keys.** `FeedCredentials`
  (`src/PhantomCore/ThreatIntel/FeedCredentials.*`) reads `NAME=VALUE` lines from
  `<DataDirectory>\feeds.credentials`. A missing file is a normal state: the feeds that need a
  key stay disabled and the key-free ones still run.
- **The key file must be protected.** If the data directory is not hardened, `FeedCredentials`
  refuses the file, because any unprivileged process could rewrite it and put its own value
  into our outbound requests. The installer limits the directory to SYSTEM and Administrators
  (`packaging/installer/ContentComponent.wxs`). The service sets the same ACL again on first
  run.
- **Keys are never logged.** Diagnostics name a key and give its length, which is enough to
  tell "absent" from "present but wrong".
- **No key ships in the package or the repository.**
  - The installer payload has no credentials file.
  - `.gitignore` excludes `*.credentials`.
  - `tests/kernel_contracts/test_feed_keys_user_supplied.py` fails the build if a credentials
    file is tracked, a package references one, or a key value is assigned in any tracked file.
- **Feed data stays on the endpoint that pulled it.** It is used for that endpoint's own
  detection and is never proxied or passed on.

## What this means for shipped detection content

Because of these terms, the malware-hash section of the shipped signature database holds only
EICAR test hashes. Hash content comes from the user's own feeds through the updater. Shipping
redistributable hash content needs a source whose licence allows it. That work is tracked
separately and is not done by putting a key into the build.
