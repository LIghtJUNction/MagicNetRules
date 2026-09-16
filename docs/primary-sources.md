# Primary text feeds

The registry is `config/text-sources.json`; the output inventory remains
`config/rulesets.json`. New inputs are merged into existing policy or service
sets. This expansion adds nine inputs from four repositories and **zero SRS
output names**. It does not consolidate the pre-existing 115 output names.

| Primary repository | Input | Existing output |
| --- | --- | --- |
| felixonmars/dnsmasq-china-list | accelerated-domains.china.conf | magicnet-cn-domain |
| gaoyifan/china-operator-ip | china.txt, china6.txt | magicnet-cn-ip |
| blackmatrix7/ios_rule_script | WeChat | magicnet-cn-domain, service-wechat |
| blackmatrix7/ios_rule_script | Google, GoogleFCM | service-google |
| blackmatrix7/ios_rule_script | GitHub | magicnet-dev, service-github |
| blackmatrix7/ios_rule_script | OpenAI | magicnet-ai, service-openai |
| hagezi/dns-blocklists | wildcard/light-onlydomains.txt | magicnet-adblock |

Upstream homepage, branch, path, license document and entry bounds are explicit
in the registry. Some of these primary feeds also contribute indirectly to the
existing aggregates: an added feed is not necessarily new unique coverage.
The builder deduplicates within each output; different routing policies remain
separate. Do not load every service and its aggregate just because it exists.

## Conversion boundaries

`clash-domain` deliberately imports only DOMAIN, DOMAIN-SUFFIX and
DOMAIN-KEYWORD. It is not a full Clash converter. IP-CIDR, IP-CIDR6, IP-ASN and
PROCESS-NAME may be omitted only where explicitly listed for that feed. Each
omission is counted by type in `upstream-manifest.json`. Unknown operators,
logical rules and extra domain qualifiers fail the build rather than silently
changing their meaning. This avoids turning an ASN or no-resolve rule into a
broad unconditional route. The original list remains in the source archive.

The dnsmasq adapter imports domain suffixes, not the upstream DNS server choice.
DNS acceleration is not proof of route geography. Whole-TLD suffixes are therefore
limited to the explicitly reviewed `cn` and `xn--fiqs8s` (.中国). The feed's broad
`top`, `wang`, `xn--55qx5d` and `xn--io0a7i` entries are explicitly omitted and
counted in `omitted_tlds`, while separately listed domains under them are kept.
Any new unreviewed whole-TLD entry fails validation rather than expanding direct
routing without review.
IPv4/IPv6 sources are validated separately and reject private/default routes and
noncanonical prefixes. HaGeZi's plain domain feed is deliberately imported as
exact names: this conservative integration does not invent wildcard blocking
for unlisted children and is not equivalent to the complete HaGeZi wildcard or
AdGuard syntax. Existing selectable HaGeZi binary variants are unchanged.

Google FCM is general push infrastructure, not a Play download rule. It is
therefore added to service-google, not service-google-play or domestic direct
sets. Source expansion alone does not prove that Play login/download or phone
push works; route priority, DNS and real-device testing are still required.

## Update and publication

The existing six-hour scheduled release workflow fetches these inputs at build
time. Each Git branch is resolved once to a commit, then content and license
files are downloaded by immutable commit URL. Sources have byte limits,
nonempty/cardinality checks and strict parsers. Domestic-domain and added adblock
feeds also reject matches against selected critical Google endpoints. These
sentinels are regression checks, not a complete false-positive detector.

A bad or unavailable mandatory input fails the entire snapshot: never publish a
partial update or silently reuse an old source. Existing snapshot replacement,
SRS compilation, reproducibility checks and release checksum verification still
apply. No sources, generated files, licenses fetched at build time or dist files
are committed. Output remains on Releases, not on a data branch.

## Audit and licenses

`magicnet-rules-sources.tar.gz` includes original text bytes, converted JSON,
upstream license texts, the registry, fetcher, converter and builder. The
provenance manifest records immutable URLs, SHA-256, entry counts, duplicates,
explicit omissions and license-file hashes. Runtime SRS files remain separate
from these audit materials. Redistribute the accompanying source/license bundle
with derived rules; the repository's MIT license does not relicense third-party
rule data. The registry records the upstream license version without assuming
an unexpressed “or later” grant.

Large aggressive threat lists and blanket VPN/DoH blocking lists are not added
by default. More upstream names do not establish better coverage, lower memory
or lower latency. Review the actual output diff and test device behavior before
making those claims.
