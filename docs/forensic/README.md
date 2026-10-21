# Forensic analysis (public edition)

[Zoraxy-Forensic-Network-Analysis-Oct2026-rev1.7-PUBLIC.docx](Zoraxy-Forensic-Network-Analysis-Oct2026-rev1.7-PUBLIC.docx) is a
six-month review of what a small home-lab reverse proxy sees when it is published to the internet: April to 18 October 2026, behind
Cloudflare's free plan, with this plugin enforcing in seconds. It was written to be useful to other administrators.

## What is in it

- Traffic and refusals month by month, and refusals per day by Zoraxy layer.
- The cloud-hosted scanning campaign in detail: the behaviour, the paths it hunts for, the spoofed crawler names, and a table of
  bursts with the layer that stopped each one.
- Cloudflare's alternate-port sweeps, with proxied versus refused counts.
- The defence layers and what each did, example Cloudflare rules you can reuse (including the alternate-port block and the one-line list
  rule), and the plugin's detection design.
- Lessons, and a checklist to reproduce the set-up.

## What was left out, on purpose

Internal addresses and layout, management interfaces, the operator's own devices, certificate and credential detail, which services
have which access controls, the exact contents of the operator's Cloudflare rules, and any weakness that was still open at the time.
It was written fresh from the facts rather than edited from the internal version, and an automated check over the final text looks
for forbidden patterns (private ranges, internal names, credential words). The scanner addresses in it are labelled as short-lived
indicators, because cloud addresses are reused.

## Related

- [scripts/](../../scripts/) is the weekly report script that produced the figures.
- [REPORT-GUIDE.md](REPORT-GUIDE.md) says how to read the report correctly, including when an AI writes the analysis.
- The post that ties it together: <https://www.braedach.com/zoraxy-reverse-proxy-2/>.
