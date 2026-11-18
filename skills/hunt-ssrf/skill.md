# HUNT-SSRF v4.0

**Research-driven SSRF assessment methodology for modern web, cloud-native, and agentic systems**

- **Version:** 4.0
- **Updated:** 2026-11-18
- **Supersedes:** `hunt-ssrf v3`
- **Primary use:** authorized security assessment, source review, and secure engineering
- **Core weakness:** CWE-918 — Server-Side Request Forgery (SSRF)

---

## 0. Mission and operating contract

Find and explain server-side request-forgery weaknesses by tracing how untrusted data influences outbound network activity. Focus on trust-boundary failures that can be reproduced in an owner-controlled environment and fixed systematically.

This methodology covers classic web fetchers, background workers, document and media processors, cloud-native services, LLM inference endpoints, RAG pipelines, AI agents, and MCP servers.

Assessment boundaries:

1. Work only on assets, accounts, tenants, and components explicitly included in the engagement.
2. Use a researcher-controlled callback service or a program-provided interaction service for outbound-request attribution.
3. Use local fixtures or owner-provided staging endpoints to test restricted-destination policy. Do not use production internal services, metadata services, or customer data as test targets.
4. Do not retrieve, retain, or reproduce live credentials, tokens, private keys, environment variables, or private customer content. A synthetic marker is sufficient to test response propagation.
5. Stop when the minimum evidence for the finding is established. Preserve request IDs and logs, not sensitive response bodies.

These constraints are part of a repeatable test design: they make evidence attributable, reproducible, and safe to share with the asset owner.

---

## 1. The central invariant

> **The destination approved by policy must be the destination the network connector actually reaches.**

A string check is not enough. A hostname check is not enough. A DNS lookup performed before the HTTP request is not enough. A model instruction is not a network control.

The invariant must hold across:

- URL parsing and canonicalization;
- hostname resolution and all A/AAAA answers;
- the actual socket or transport connection;
- connection reuse and pooling;
- proxies, tunnels, service meshes, and fallback routes;
- redirects, retries, and alternate transports;
- browser subresources and document-renderer fetches;
- queued jobs and scheduled execution;
- every AI-agent, MCP, plugin, and workflow tool that can cause network access.

A secure design enforces the decision as close as possible to connection creation and records the peer actually reached.

---

## 2. Model the whole request path

Represent each candidate feature as a data-flow graph:

```text
untrusted input
  -> transformations / storage / model context
  -> URL parser and canonicalization
  -> destination policy
  -> resolver
  -> proxy / transport / connector
  -> redirect / retry / connection reuse
  -> response consumer
```

For agentic systems, extend it:

```text
untrusted page, file, email, or RAG chunk
  -> model context
  -> tool selection and arguments
  -> tool adapter
  -> guarded transport
  -> network
  -> tool result / screenshot / document / model summary
```

For every edge, record:

| Stage | Questions to answer |
|---|---|
| Input | Which field influences the destination? Is it user-supplied, stored, imported, generated, or derived from retrieved content? |
| Transformation | Is it decoded, normalized, concatenated, templated, path-joined, converted, or rewritten by an SDK? |
| Parser | Which parser interprets scheme, authority, host, port, path, user-info, and fragment? Does another parser later reinterpret it? |
| Policy | Is there an allowlist, destination policy, egress rule, tenant rule, or only a UI/model instruction? |
| Resolver | Which resolver is used? Are both address families considered? What happens on partial failure? |
| Connector | Does the connector use the exact address that policy approved? Can a custom dispatcher or proxy resolve again? |
| Redirects | Are redirects automatic? Is each hop independently authorized? |
| Response | Are body, headers, status, timing, screenshot, PDF, or model-generated summaries exposed? |
| Execution | Is the fetch immediate, queued, retried, scheduled, delegated, or run under another service identity? |

Do not mark an edge as secure merely because a helper exists. Trace the value into the actual network call.

---

## 3. Discover fetch surfaces

Search for product behavior, not only parameters named `url`.

### 3.1 Classic web and application surfaces

- Link previews, URL unfurling, social cards, and metadata extraction.
- Avatar, image, video, audio, document, and archive imports.
- Screenshot, PDF, office-document, and HTML rendering services.
- Webhook registration, verification, testing, and delivery.
- Feed readers, crawlers, importers, and URL-based file upload.
- OAuth, OpenID Connect, SAML, and remote JWKS discovery.
- API testers, OpenAPI importers, integration builders, and workflow HTTP nodes.
- Remote CSS, SVG, XML, font, and image references.
- Server-side browser navigation and page rendering.

### 3.2 Cloud-native and platform surfaces

- Serverless and edge functions that fetch caller-controlled destinations.
- Kubernetes controllers, operators, admission components, and service-call features.
- Storage and backup integrations that retrieve remote endpoints.
- Service-mesh egress gateways, forward proxies, and internal fetch services.
- Workload identity and metadata protection boundaries.
- Build systems, CI runners, package importers, and repository automation.

### 3.3 AI, agent, and MCP surfaces

- MCP server discovery, remote connection setup, and tool enumeration.
- Tools named `fetch`, `fetch_url`, `browse`, `navigate`, `call_api`, `http_request`, or similar.
- Browser tools that expose navigation, screenshots, page evaluation, or downloads.
- Document loaders, webpage-to-Markdown converters, and RAG ingestion connectors.
- Vision/audio/video endpoints that accept remote media references.
- Search connectors with configurable provider URLs or base URLs.
- OpenAPI/action importers and plugins that generate network-capable tools.
- Code-execution tools where scripts can access network libraries.
- Background agent jobs that continue after the initiating request ends.

### 3.4 Source-review indicators

Look for:

- HTTP clients receiving values from request parameters, stored records, GraphQL input, or agent arguments.
- URL parsing and IP classification helpers, especially custom `is_public_ip`, `is_global_ip`, or `is_private_ip` functions.
- Redirect-following defaults and retry middleware.
- DNS lookups separated from connection creation.
- Proxy environment variables and custom transport, dispatcher, or dialer configuration.
- Multiple HTTP libraries in the same repository.
- SDKs that perform hidden fetches internally.
- Sandboxes that expose `requests`, `fetch`, sockets, or browser networking.
- Queue consumers, scheduled jobs, dead-letter reprocessing, and webhook delivery workers.
- MCP tool schemas accepting arbitrary URL, host, endpoint, or base-URL strings.
- LLM media loaders that dereference `image_url`, `audio_url`, `video_url`, or document references.

Useful search terms include:

```text
fetch, request, httpClient, axios, requests, httpx, aiohttp, urllib,
urlparse, urljoin, resolve, lookup, dial, connect, redirect, proxy,
webhook, preview, crawler, browser, navigate, load_image, image_url,
fetch_url, baseURL, callback, serverUrl, MCP, tool, document_loader
```

### 3.5 Sink inventory

Create one row for each distinct outbound sink. Do not collapse several fetchers into one entry just because they share a UI form.

| Field | Record |
|---|---|
| Feature | Exact route, workflow, tool, or user-visible feature |
| Input | Parameter, JSON property, GraphQL field, stored value, or model-generated argument |
| Trigger | Immediate request, import, queue job, scheduled event, agent tool call, or retry |
| Sink | Library, browser, worker, proxy, MCP server, SDK, or custom transport |
| Policy | Validation component and decision point |
| Resolution | Resolver, A/AAAA handling, and connection-pinning behavior |
| Redirects | Disabled, manual, automatic, or unknown |
| Response | None, metadata, body, file, screenshot, PDF, or model summary |
| Identity | Anonymous user, tenant, service account, worker role, or agent identity |
| Evidence | Request ID, callback ID, trace, tool invocation, and egress log |
| Confidence | Confirmed, probable, unverified, or disproved |

---

## 4. Reconstruct the control path

For each sink, trace the complete path from the initial input to the socket or managed transport.

1. Identify the original input and every transformation.
2. Identify the parser actually used by the validator.
3. Identify the parser actually used by the HTTP client, browser, SDK, or proxy.
4. Identify the exact destination policy and the address data it consumes.
5. Determine whether policy and connection use the same resolution result.
6. Identify every redirect, retry, proxy, connection pool, and fallback path.
7. Identify the process, tenant, and service identity that performs the fetch.
8. Identify which parts of the upstream response can reach the requester or another tool.
9. Check whether every alternate code path uses the same mandatory transport.

The highest-value review question is: **where is the last security decision before the network connection is made, and can any later component change the destination?**

---

## 5. URL parsing and canonicalization

Parser disagreement is a recurring root cause because validators and transports may implement different URL standards or permissive parsing rules.

### 5.1 Review dimensions

Check whether the validator and sink agree on:

- scheme and scheme case;
- authority boundaries;
- username/password (userinfo) handling;
- hostname and trailing-dot normalization;
- port parsing and default ports;
- IPv4 and IPv6 literal parsing;
- percent-encoding and decoding order;
- Unicode and IDNA conversion;
- backslash treatment;
- empty, malformed, or partially parsed authorities;
- fragment handling;
- path normalization and path-joining semantics;
- protocol-relative references;
- absolute URLs unexpectedly accepted in a relative-path field.

String-prefix checks are not origin checks. A check such as `startsWith(trustedOrigin)` does not prove that two URLs have the same scheme, host, and port. Compare structured, normalized components.

### 5.2 Preferred validation design

- Parse once into a structured URL object using a well-maintained parser.
- Reject malformed, ambiguous, unsupported, or opaque URL forms.
- Permit only the schemes the feature genuinely needs.
- Compare a normalized origin tuple: scheme, hostname, and effective port.
- Use an exact hostname allowlist where feasible; do not use substring or suffix checks without label-boundary semantics.
- Normalize IDNA and trailing-dot behavior consistently.
- Keep path validation separate from origin validation.
- Ensure the transport consumes the same normalized destination representation that policy approved.
- Do not parse with one library and silently reinterpret the original string with another.

### 5.3 Differential test harness

In a local test harness, feed the same benign corpus to the validator and the actual transport parser. Compare their structured outputs, not just accept/reject booleans.

Record:

```text
raw input
validator parser output
transport parser output
normalized scheme / host / port / path
policy decision
actual connector destination in the fixture
```

Any difference that changes the effective origin or network destination is a failed invariant and should become a regression test.

---

## 6. Address classification and IPv6 correctness

Do not rely on a single convenience property such as `is_global` as the complete SSRF policy.

### 6.1 Classification model

Build policy from the current IANA IPv4 and IPv6 Special-Purpose Address Registries, the application’s explicit allowlist, and the actual network architecture. Treat these as separate questions:

1. Is the address syntactically valid?
2. Is it special-purpose or non-global according to current registries?
3. Is it reachable from this workload due to local routes, NAT, tunnels, or proxies?
4. Does the product’s policy permit this class of destination?

An address being technically routable in some environments does not mean it should be reachable by a user-controlled fetch feature.

### 6.2 Address families and representations to cover

The local regression corpus should include the relevant categories:

- IPv4 loopback, private-use, link-local, unspecified, multicast, reserved, and shared address space.
- IPv6 loopback, unspecified, unique-local, link-local, multicast, and deprecated site-local space.
- IPv4-mapped IPv6 forms.
- IPv4-embedded transition or translation forms, including NAT64 and 6to4.
- Teredo and other transition mechanisms where supported by the platform.
- IPv4-translated and implementation-specific IPv6 forms.
- Mixed A and AAAA responses.
- Addresses whose classification differs by runtime/library version.

Relevant standards and registries include RFC 6890, RFC 6052, RFC 8215, RFC 3879, and the IANA IPv4/IPv6 special-purpose registries.

### 6.3 Policy requirements

- Parse addresses with a standards-aware IP library.
- Normalize IPv4-embedded IPv6 forms before policy comparison where the address format embeds an IPv4 destination.
- Explicitly account for deprecated or unusual ranges rather than assuming the language runtime classifies every range according to the application’s policy.
- Evaluate the complete DNS answer set. A mixed public/non-public answer must not be treated as safe merely because one answer is public.
- Fail closed on malformed addresses, partial resolution failure, or unknown address forms.
- Keep the policy corpus versioned and update it when IANA or platform behavior changes.
- Test both address families independently in an isolated harness.

### 6.4 Important implementation lesson

The November 2026 MCP fetch advisory involving `fec0::/10` is a useful reminder that classifier correctness is version- and policy-dependent. The advisory describes a low-severity classification gap, while also noting that default hosts commonly have no route to that deprecated site-local range. Do not convert a classifier finding into a claim of proven internal access without independent reachability evidence.

---

## 7. DNS resolution, rebinding, and connection pinning

The critical failure pattern is a time-of-check/time-of-use gap: the application checks one DNS result, then the HTTP stack resolves the hostname again when it connects.

### 7.1 Secure connection model

- Resolve the hostname through the intended resolver.
- Collect and classify all relevant A and AAAA answers.
- Apply policy to the complete result set.
- Connect only to an approved address from that validated set.
- Bind the approved address to the connector/dial operation rather than performing a separate preflight lookup and then making an ordinary hostname-based request.
- Preserve the original hostname for HTTP `Host`, TLS SNI, and certificate verification.
- Ensure retries, alternate addresses, connection pools, and custom transports cannot silently trigger a fresh unvalidated resolution.
- Record the selected address and actual peer address in test telemetry.

### 7.2 Questions for code review

- Does the HTTP client resolve the hostname again after the policy check?
- Does a custom dispatcher, agent, proxy, or SDK override the transport that was pinned?
- Does the library prefer IPv6 after an IPv4-only check, or vice versa?
- Can connection pooling reuse a socket created under another destination decision?
- Does a retry or fallback use a different resolver or connector?
- Is the peer address observable and checked against the approved set?

### 7.3 Safe validation

Use a controlled DNS fixture and a mock or local connector. Simulate a change in answers between the policy decision and the attempted connection. Assert that the connector can use only the approved address and that any changed or unapproved answer is rejected. Do not use a live third-party network or a production internal destination to test rebinding.

---

## 8. Redirects, retries, and path changes

Every redirect is a new destination decision.

### 8.1 Review

- Automatic redirect behavior in the client and SDK.
- Relative and absolute `Location` handling.
- Scheme, host, port, and origin changes.
- Redirects across HTTP and HTTPS.
- Redirects that change request method or body semantics.
- Credential, cookie, and authorization-header forwarding across origins.
- Hop limits and loops.
- Retries and fallback transports that skip the original policy layer.
- Redirects inside browser tools, document loaders, MCP tools, and agent adapters.

### 8.2 Secure behavior

- Disable automatic redirects when the feature does not require them.
- When redirects are required, handle them manually.
- Parse, resolve, classify, and authorize every `Location` before following it.
- Apply the same DNS and connection-pinning policy to each hop.
- Enforce a small hop limit and a total request budget.
- Strip credentials and sensitive headers when origin changes, according to the application’s authentication design.
- Do not allow an alternate retry path to bypass the guarded transport.

### 8.3 Verified case patterns

- CodeWhale / DeepSeek TUI CVE-2026-45310: the initial URL was checked, but the HTTP client followed redirects without repeating the restricted-destination policy. The advisory identifies 0.8.22 as the fixed release.
- LangChain Community CVE-2026-27795: a redirect path bypassed the earlier `RecursiveUrlLoader` destination protections; the advisory identifies 1.1.18 as the patched release.

These cases show why initial-URL validation is not equivalent to end-to-end destination enforcement.

---

## 9. Proxies, tunnels, and egress layers

The application may validate one destination while a proxy, service mesh, or custom transport connects to another.

Review:

- HTTP CONNECT and forward-proxy behavior.
- SOCKS local-vs-remote DNS resolution.
- Environment-derived proxy configuration.
- Proxy-side resolution and destination ACLs.
- Service-mesh egress gateways.
- Custom Node `http.Agent` and `undici` dispatcher behavior.
- Custom Go `RoundTripper` and dialer behavior.
- Rust connector and resolver hooks.
- Proxy bypass rules and direct fallback.
- Connection pooling across proxy routes.
- HTTP/2 and HTTP/3 connection reuse where origin coalescing or transport routing can affect policy.

The policy must be enforced at the actual egress point as well as in application code. A proxy error must not trigger a less restricted direct connection. Collect logs from the final egress enforcement point in the authorized test environment.

---

## 10. Browser, PDF, SVG, and document-rendering fetches

A renderer can make many requests after the initial URL has been accepted.

Inventory:

- Main-frame navigation.
- Images, stylesheets, fonts, scripts, iframes, media, and CSS imports.
- SVG external references and XML resource resolution.
- PDF and office-document conversion.
- Downloads, service workers, speculative connections, and client-side navigation.
- Browser automation tools that expose navigation, screenshot, evaluation, or download operations.
- Subresources requested by embedded documents and templates.

Defensive requirements:

- Apply egress policy to every browser-originated request, not only the top-level navigation.
- Run renderers in isolated workers without sensitive internal network access.
- Disable unnecessary protocols and external resource loading.
- Bound execution time, request count, response size, and recursion depth.
- Avoid passing raw screenshots or rendered documents containing internal content to a requester or downstream model.
- Keep browser navigation, screenshot, and evaluation privileges separate where possible.

A top-level URL check does not prove that subresource requests are safe.

---

## 11. Second-order and asynchronous SSRF

A URL may be stored now and fetched later by a different worker or service identity.

Review:

- Stored avatar and attachment URLs.
- Import and thumbnail queues.
- Webhook delivery and verification jobs.
- Scheduled reports, crawlers, and reprocessing pipelines.
- Retry and dead-letter queues.
- Background agent jobs and deferred tool calls.
- Tenant or permission changes between submission and execution.

Requirements:

- Re-evaluate destination policy when the fetch actually runs.
- Record the worker identity, tenant, job ID, and egress decision.
- Ensure queue consumers use the same guarded transport as synchronous endpoints.
- Expire or revalidate stored URLs when policy or ownership changes.
- Bound retry count and job lifetime.
- Do not assume validation at submission remains valid at execution time.

For safe proof, use a harmless controlled callback and correlate it with the job ID and worker logs.

---

## 12. Non-HTTP protocols and parser side effects

Some libraries and document processors support schemes or resource handlers beyond ordinary HTTP(S).

Review the protocol surface of the actual dependency stack, including:

- file and local-resource handlers;
- FTP and legacy handlers;
- XML external entities and external document references;
- archive and media library URL handlers;
- custom SDK schemes;
- browser custom protocols and embedded-resource handlers.

Design rules:

- Allow only the protocols required by the feature.
- Reject unknown schemes before dispatch.
- Disable external-entity resolution and remote resource loading by default.
- Separate filesystem access from network access.
- Run parsers and converters without ambient access to sensitive files or networks.
- Test scheme handling in a local, isolated fixture.

Do not treat a URL validator for HTTP(S) as a complete control over every protocol a downstream library may support.

---

## 13. AI agents, MCP, and indirect prompt injection

Agentic applications create a confused-deputy risk: a model may select a network-capable tool and construct its arguments using untrusted content. The model is not the authorization boundary.

### 13.1 Map the full chain

```text
untrusted content
  -> model context
  -> tool selection
  -> tool arguments
  -> tool adapter
  -> mandatory guarded transport
  -> network
  -> response consumer or next tool
```

### 13.2 Tool inventory

| Tool class | Review focus |
|---|---|
| Direct fetch | Arbitrary URL or host reaches an HTTP client |
| Browser navigation | Main-frame and subresource policy; screenshot/evaluation permissions |
| Document ingestion | Parser and loader make hidden secondary requests |
| Search connector | Provider URL, base URL, crawler, or result enrichment fetch |
| Workflow HTTP node | Stored destinations and delayed worker execution |
| MCP discovery | Metadata and remote configuration may influence later connections |
| Code execution | Network-capable modules, sockets, or browser APIs exposed to scripts |
| LLM media loader | User-controlled media references are fetched by inference infrastructure |

### 13.3 Distinct trust boundaries

- Direct user prompt vs. indirect instructions embedded in a page, file, email, or RAG chunk.
- UI validation vs. tool-adapter validation.
- Tool-adapter validation vs. underlying HTTP-client behavior.
- One tool's output becoming another tool's URL or destination argument.
- Connection-time policy vs. redirect handling inside the tool's client.
- User identity vs. privileged service identity.
- Synchronous session vs. background agent job.

### 13.4 Assessment method

- Inventory every tool that can cause network access, including tools not named `fetch`.
- Review tool schemas for URL, host, endpoint, callback, media URL, and base-URL arguments.
- Trace model-generated arguments into the adapter and network client.
- Confirm that the adapter cannot bypass the centrally enforced destination policy.
- Review tool chaining and response handling for privilege amplification.
- Verify invocation logs, trace IDs, tenant, service identity, and egress records. Do not rely on model text claiming a tool was used.
- Use a harmless prompt-injection canary that requests a call only to a researcher-controlled endpoint. Do not ask an agent to access private services or secrets.
- Confirm that the model cannot grant itself permissions the user does not possess.

### 13.5 MCP-specific checks

- Is the MCP server authenticated where the deployment requires authentication?
- Are remote server metadata and endpoint changes treated as untrusted configuration?
- Are tools constrained by the same egress policy as the parent application?
- Can a tool follow redirects or perform hidden secondary fetches?
- Does an MCP client expose network, filesystem, or browser capabilities to untrusted servers?
- Are server discovery and connection tests subject to the same destination controls as normal tool calls?
- Is tool output treated as untrusted before it is used as a new tool argument?

### 13.6 Important recent lesson

A November 11, 2026 MCP `mcp-server-fetch` advisory documents an IPv6 site-local classification gap in a destination guard. The advisory explicitly rates practical reachability as low on default hosts and does not establish a general metadata-service compromise. Treat it as a classifier regression example, not proof that every installation is exploitable.

---

## 14. LLM inference, media loading, and RAG

An inference API may fetch media or documents before the model processes them. This creates an SSRF sink even when the application does not expose a conventional fetch tool.

Review:

- Vision-language `image_url` inputs.
- Audio and video URL inputs.
- Remote PDF and document references.
- `load_image`, `load_audio`, `load_video`, and document-loader helpers.
- Embedding pipelines that fetch remote pages before chunking.
- Search connectors and web crawlers used during retrieval.
- Tool-generated URLs passed into inference or document-processing services.

Controls:

- Treat all remote media references as untrusted destinations.
- Apply scheme, address, DNS, connection, redirect, and egress policy in the media-fetch service.
- Keep model inference credentials separate from media-fetch privileges.
- Bound download size, content type, decompression, and processing time.
- Do not return raw upstream responses or internal documents through model summaries.
- Use local fixtures to test media fetching and response propagation.

**Verified case:** LMDeploy CVE-2026-33626 affected the vision-language image-loading path; the NVD record identifies 0.12.3 as the fixed version. This illustrates why media loaders belong in the sink inventory.

---

## 15. API schemas, GraphQL, and integrations

A schema can reveal hidden fetch behavior even when the UI does not expose a URL field.

Review:

- GraphQL mutations and input objects containing URL-like fields.
- Remote asset import operations.
- Webhook, callback, and notification destinations.
- OpenAPI/action importers.
- Integration builders and configurable base URLs.
- API gateways that derive a destination from headers or tenant configuration.
- Fields that accept a host separately from path, scheme, or port.

Trace each field to its actual outbound sink. Validate the destination at execution time and apply the same policy to imported, stored, and user-supplied configurations.

---

## 16. Cloud, containers, and workload identity

The most important cloud question is not simply whether a fetcher can contact a metadata service. It is which network boundaries and identities the fetcher can reach, and whether those privileges exceed the initiating user's permissions.

Review defensively:

| Environment | Review focus |
|---|---|
| AWS EC2 | IMDS configuration, IMDSv2 enforcement, hop limit, role permissions, and workload egress policy |
| AWS ECS / Fargate | Task-role scope and container metadata boundaries |
| AWS Lambda | Execution-role scope, environment-secret handling, file/protocol handlers, and outbound controls; do not assume EC2-style IMDS applies |
| Google Cloud | Metadata protections, service-account/workload identity scope, and Cloud Run egress controls |
| Azure | Managed-identity permissions and metadata protections |
| Kubernetes | Pod egress, service-account privileges, controller/operator permissions, admission and webhook trust boundaries |
| Serverless / edge | Runtime identity, environment access, network policy, and SDK-specific URL handling |
| Service mesh | Egress gateway policy, workload identity, proxy bypass, and route consistency |

Use cloud configuration evidence, policy review, synthetic fixtures, and owner-supplied logs. Do not fetch live metadata or retrieve credentials as proof.

---

## 17. Language and transport review matrix

The main question is whether the validator, resolver, proxy, and connector agree on the destination.

| Ecosystem | Components to review | Frequent review concern |
|---|---|---|
| JavaScript / TypeScript | WHATWG `URL`, `fetch`, Node HTTP clients, `undici`, agents and dispatchers | Different parser/dispatcher paths; redirects and custom dispatcher behavior |
| Python | `urllib.parse`, `requests`, `httpx`, `aiohttp`, `urllib3`, `ipaddress`, socket resolution | Parser differences; DNS re-resolution; library-specific address classification |
| Go | `net/url`, `net/http`, `net.Dialer`, `RoundTripper`, resolver configuration | Custom dialers and redirect policy |
| Java | `URI`, `URL`, `HttpClient`, Apache HttpComponents | Parser and normalization differences; proxy configuration |
| .NET | `System.Uri`, `HttpClient`, `SocketsHttpHandler` | Handler-level connection and proxy behavior |
| Rust | `url`, `reqwest`, `hyper`, resolver and connector configuration | Redirect policy and IPv6 classification/normalization |
| PHP | `parse_url`, cURL, stream wrappers, framework clients | Scheme handlers and wrapper defaults |
| Ruby | `URI`, `Net::HTTP`, Faraday, Addressable | Parser behavior and adapter-specific transport behavior |

Do not assume that two APIs in the same language share parsing or transport semantics. Inspect the exact version and configuration in use.

---

## 18. Controlled validation playbook

Use the following workflow in an isolated lab, a dedicated test tenant, or owner-approved staging. The fixtures must be under the tester's or asset owner's control.

### Phase 0 — Engagement setup

- Record in-scope hostnames, applications, tools, accounts, and tenants.
- Record prohibited test classes and rate limits from the engagement rules.
- Choose the controlled callback service and local fixture environment.
- Define the request ID format and the stop condition.
- Identify who can provide staging logs and confirm egress events.

### Phase 1 — Surface mapping

- Enumerate URL-taking features and hidden import/render workflows.
- Enumerate MCP, agent, RAG, media-loading, and workflow tools.
- Inspect API schemas, GraphQL input types, MCP schemas, and frontend request construction.
- Search source for outbound clients, URL parsers, resolvers, and security wrappers.
- Build the sink inventory.

### Phase 2 — Data-flow reconstruction

For each sink:

- Trace the input to the connector.
- Record every parser and transformation.
- Identify validation and authorization decisions.
- Identify DNS, redirect, proxy, retry, and pooling behavior.
- Identify response exposure and asynchronous execution.
- Record the runtime identity and tenant.

### Phase 3 — Harmless attribution

- Verify the controlled callback service independently.
- Generate one unique, unpredictable identifier per candidate sink.
- Submit one candidate at a time.
- Correlate callback timestamp, request ID, account, tenant, and application logs.
- For agentic paths, correlate the tool invocation ID and model trace with egress logs.
- Run a negative control.
- Repeat only when necessary to rule out unrelated background traffic.

### Phase 4 — Policy regression tests in a lab

Build a local matrix that covers:

| Test family | Fixture | Expected secure result |
|---|---|---|
| URL syntax | Valid, malformed, ambiguous, and unsupported test URLs | Reject ambiguity and unsupported schemes |
| Parser parity | Same corpus through validator and transport parser | Normalized destination must match |
| Origin checks | Same-origin and different-origin fixtures | Compare structured origins, not string prefixes |
| Address policy | Synthetic IPv4 and IPv6 classification corpus | Every prohibited class rejected |
| Mixed DNS answers | Controlled A/AAAA fixtures | No unapproved address can be selected |
| DNS change | Controlled resolver changes answer between phases | Connector remains pinned or request is denied |
| Redirects | Local redirect server with several controlled hops | Every hop gets a new policy decision |
| Proxy | Local test proxy and direct-connection fallback simulation | No unguarded route is selected |
| Retry | Mock connector returns retryable errors | Retry cannot bypass policy |
| Browser resources | Local HTML page with controlled subresources | Every subresource is subject to egress policy |
| Document parsing | Local SVG/XML/PDF fixtures | No uncontrolled remote resource loads |
| Async worker | Local queue and worker | Policy is rechecked at execution time |
| Agent tool | Test agent invokes a controlled callback tool | Tool identity and egress event are correlated |
| Tool chaining | Controlled tool output passed to a second mock tool | Each invocation is independently authorized |
| Media loader | Local image/audio/document fixture | Loader uses the guarded fetch service |

Do not turn this matrix into live internal-network probing. The goal is to prove that the implementation enforces its policy, not to enumerate private services.

### Phase 5 — Impact assessment

Answer only what the evidence supports:

- Can the input influence a server-side request?
- Is the request attributable to the tested sink?
- Does the connection pass through the intended policy layer?
- Is a policy decision incorrect in the controlled fixture?
- Does any harmless fixture response reach the caller or a downstream tool?
- Is the behavior cross-tenant or executed under a more privileged service identity?
- Is the observed impact only an outbound request, or is response content exposed?

Do not infer secret access, internal compromise, or code execution from a callback alone.

### Phase 6 — Report and regression

- Provide the smallest reproducible request using the controlled canary.
- Include request ID, timestamp, callback event, and relevant logs.
- Include the exact sink and source-to-sink trace.
- State the observed impact and the impact not tested.
- Identify the broken invariant and systemic remediation.
- Add a regression test for the root cause.

---

## 19. Evidence and confidence model

| Evidence level | Observation | What it proves |
|---|---|---|
| E0 — Reflection | Submitted value appears in output | Input reflection only |
| E1 — DNS | Unique controlled hostname is resolved | A resolver or intermediary handled the hostname; HTTP fetch is not proven |
| E2 — HTTP callback | Controlled endpoint receives an attributable request | An HTTP-capable component made an outbound request |
| E3 — Synthetic response | A harmless marker from a controlled response reaches the caller | Response propagation is established |
| E4 — Policy failure in fixture | Local/owner-controlled restricted fixture is reached despite policy | Destination enforcement failed in the tested environment |
| E5 — Boundary/identity effect | Owner-approved synthetic evidence shows a cross-tenant or privilege boundary failure | The specific authorization boundary is affected |

Evidence that is insufficient by itself:

- URL reflection or a validator accepting a string.
- A response code change without independent attribution.
- A request taking longer than expected.
- A model claiming that it fetched a URL.
- A tool error interpreted as proof of success.
- A DNS event that cannot be tied to the tested input.
- A callback generated by the researcher's own browser or proxy.
- A callback without a unique test identifier or tenant correlation.

A DNS-only result is not equivalent to an HTTP fetch. An HTTP callback is not equivalent to response disclosure. Response disclosure is not automatically equivalent to credential compromise.

---

## 20. Severity and reportability

Severity depends on exploit preconditions, attacker privileges, destination policy, reachable trust boundary, response exposure, service identity, tenant separation, and realistic impact.

| Evidence | Suggested interpretation |
|---|---|
| Reflection only | Not SSRF |
| DNS-only interaction | Resolver interaction; investigate attribution |
| Controlled HTTP callback | Confirmed outbound request; impact remains unproven |
| Controlled response marker returned | Read-capable fetch behavior demonstrated against the controlled endpoint |
| Controlled policy failure | Destination policy is ineffective in the tested fixture |
| Cross-tenant synthetic result | Authorization boundary issue; assess affected roles and tenants |
| Live sensitive material appears unexpectedly | Stop, do not retain or use it, and notify the owner through the approved channel |

Do not assign a critical severity merely because an internal destination is theoretically reachable. Do not downgrade a cross-tenant or privileged-service issue solely because it is blind. Explain preconditions and evidence separately.

---

## 21. Remediation architecture

A robust outbound-fetch service should:

1. Accept structured destinations or narrowly defined resource identifiers where practical, rather than arbitrary URL strings.
2. Permit only required schemes, ports, and hosts.
3. Parse and canonicalize once using a well-maintained parser.
4. Reject ambiguous or malformed inputs.
5. Compare origins structurally; never rely on string-prefix checks.
6. Resolve the complete relevant address set.
7. Classify addresses against a current, versioned policy based on IANA registries and deployment needs.
8. Normalize embedded IPv4 representations before comparison.
9. Pin the approved address at the actual dial/connect layer.
10. Preserve correct hostname semantics for HTTP Host and TLS certificate verification.
11. Revalidate every redirect, retry destination, and fallback route.
12. Apply equivalent policy to proxies, tunnels, service meshes, and browser requests.
13. Disable unused protocols and automatic redirects.
14. Bound connection time, total duration, response bytes, redirects, and concurrency.
15. Isolate document renderers and browser workers from sensitive internal networks.
16. Run fetch workers with least-privilege identities.
17. Recheck policy when background jobs execute.
18. Avoid returning raw upstream bodies or headers unless explicitly required.
19. Log the policy decision, normalized destination, resolved address, selected peer, redirect hop, request ID, tenant, and tool identity without logging secrets.
20. Make the guarded transport mandatory for application modules, plugins, MCP tools, and agent adapters.
21. Add static or architectural checks that prevent direct unguarded HTTP clients from being introduced.
22. Add regression tests for every parser, DNS, redirect, proxy, and identity failure that has been fixed.

### Architecture tests that should always pass

- Every outbound request goes through the approved transport.
- The transport connects only to an address approved by the destination policy.
- The connected peer matches the approved address set.
- All A and AAAA results are handled consistently.
- IPv4-embedded IPv6 representations receive explicit policy treatment.
- Redirect targets are independently authorized.
- DNS, parsing, and policy failures fail closed.
- Proxy routes and direct routes enforce equivalent policy.
- Browser subresources and document renderers cannot bypass egress policy.
- Background workers re-evaluate destinations at execution time.
- Model-generated URLs receive the same validation as user-submitted URLs.
- Every MCP and agent tool uses the same mandatory network boundary.
- A new network sink cannot be introduced without a corresponding policy test.

---

## 22. Report template

```markdown
# SSRF in [feature / tool] through [input field]

## Summary
[Describe the user-controlled or model-generated input, the server-side fetch,
and the policy boundary that failed.]

## Affected asset
- Host / application:
- Endpoint / feature / tool:
- Account role:
- Tenant:
- Runtime / worker / agent identity:
- Environment:

## Root cause
- Input source:
- Fetch sink and library:
- Parser / canonicalization path:
- Destination policy:
- DNS and connection behavior:
- Redirect / retry / proxy behavior:
- Response behavior:

## Reproduction
1. State the minimum authorized setup.
2. Submit the controlled canary with a unique identifier.
3. Show the matching callback and application/egress event.
4. Include request ID and timestamp.
5. Include the negative control.

## Observed impact
[State only what was directly demonstrated.]

## Security implications
[Explain the trust boundary and realistic preconditions without claiming
unverified data access or compromise.]

## Remediation
[Describe the shared control that prevents this failure across all sinks.]

## Limitations
[List destinations, protocols, roles, tools, and impact paths not tested.]
```

---

## 23. Verified research notes (checked 2026-11-18)

The cases below are examples of root-cause patterns, not a payload collection. Always reopen the vendor advisory before using affected/fixed-version information in a live assessment.

| Reference | Root-cause lesson | Source |
|---|---|---|
| **CVE-2026-45310 — CodeWhale / DeepSeek TUI** | Initial destination validation did not cover automatic redirect targets. The NVD record identifies 0.8.22 as fixed. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-45310) · [GitHub advisory](https://github.com/Hmbown/CodeWhale/security/advisories/GHSA-96ff-gc8g-wpvg) |
| **CVE-2026-33626 — LMDeploy** | Vision-language image loading accepted remote URLs without adequate destination validation. The NVD record identifies 0.12.3 as fixed. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-33626) |
| **CVE-2026-50168 — Angular platform-server** | WHATWG URL validation and the lenient Domino parser disagreed, creating an allowlist bypass in server-side rendering. | [GitHub advisory](https://github.com/advisories/GHSA-xrxm-cp7j-8xf6) · [Tenable summary](https://www.tenable.com/cve/CVE-2026-50168) |
| **CVE-2026-26019 — LangChain Community** | Same-origin enforcement used string-prefix comparison and did not adequately classify private/reserved destinations. | [GitHub advisory](https://github.com/advisories/GHSA-gf3v-fwqg-4vh7) · [GitLab advisory](https://advisories.gitlab.com/npm/%40langchain/community/CVE-2026-26019/) |
| **CVE-2026-27795 — LangChain Community** | Redirect following bypassed the earlier `RecursiveUrlLoader` protection; advisory identifies 1.1.18 as patched. | [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-27795) · [GitHub advisory](https://github.com/advisories/GHSA-mphv-75cg-56wg) |
| **CVE-2026-48737 — pyLoad-ng** | A generic global-address classification missed IPv6 transition-address cases. The advisory notes reachability depends on NAT64/6to4 routing and lists no patched version at publication. | [GitHub advisory](https://github.com/advisories/GHSA-m5x5-28jr-gpjj) |
| **CVE-2026-57126 — PraisonAI** | Literal-host checks did not resolve hostnames before fetch operations, leaving DNS destination validation incomplete. Verify affected/fixed release details against the vendor record. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-57126) |
| **GHSA-3rxj-6jhw-qfv7 — MCP `mcp-server-fetch`** | Published 2026-11-11; an IPv6 site-local classification gap in the fetch guard. No CVE was assigned in the advisory, and practical reachability is explicitly limited on default hosts. | [GitHub advisory](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-3rxj-6jhw-qfv7) · [2026-11-11 release notes](https://github.com/modelcontextprotocol/servers/releases) |
| **CVE-2025-64709 — Typebot** | Custom-header handling in a webhook fetch flow affected the IMDSv2 protection boundary. This is a reminder to review request-method and header capabilities as well as destination checks. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-64709) |

### Research hygiene notes

- The uploaded v3 reference shelf contained entries whose identifiers or descriptions were not substantiated during this update. They were not copied forward as confirmed facts.
- In particular, do not reuse the original `CVE-2026-2020` or `CVE-2026-61430` labels without locating a primary advisory that supports the exact product and root cause.
- The original Angular entry conflated a real parser-differential issue with an incorrect CVE identifier. The verified parser-differential case is **CVE-2026-50168**.
- Broad prevalence percentages about MCP servers were omitted because the underlying sampling method and representativeness were not established from a primary source.
- CVE publication, advisory update, affected-version, and fixed-version data can differ between the CNA, NVD, and vendor release. Prefer the vendor advisory for remediation and record any discrepancy.

---

## 24. Reference shelf

### Prevention and standards

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry)
- [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry)
- [RFC 6890 — Special-Purpose IP Address Registries](https://www.rfc-editor.org/rfc/rfc6890)
- [RFC 6052 — IPv6 Addressing of IPv4/IPv6 Translators](https://www.rfc-editor.org/rfc/rfc6052)
- [RFC 8215 — Local-Use IPv4/IPv6 Translation Prefix](https://www.rfc-editor.org/rfc/rfc8215)
- [RFC 3879 — Deprecating Site Local Addresses](https://www.rfc-editor.org/rfc/rfc3879)
- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [RFC 3986 — URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)

### Vulnerability advisories

- [CVE-2026-45310 — CodeWhale redirect handling](https://nvd.nist.gov/vuln/detail/CVE-2026-45310)
- [CVE-2026-33626 — LMDeploy media loading](https://nvd.nist.gov/vuln/detail/CVE-2026-33626)
- [CVE-2026-50168 — Angular parser differential](https://github.com/advisories/GHSA-xrxm-cp7j-8xf6)
- [CVE-2026-26019 — LangChain URL-origin validation](https://github.com/advisories/GHSA-gf3v-fwqg-4vh7)
- [CVE-2026-27795 — LangChain redirect handling](https://github.com/advisories/GHSA-mphv-75cg-56wg)
- [CVE-2026-48737 — pyLoad IPv6 transition classification](https://github.com/advisories/GHSA-m5x5-28jr-gpjj)
- [CVE-2026-57126 — PraisonAI hostname validation](https://nvd.nist.gov/vuln/detail/CVE-2026-57126)
- [GHSA-3rxj-6jhw-qfv7 — MCP fetch IPv6 site-local classification](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-3rxj-6jhw-qfv7)
- [CVE-2025-64709 — Typebot webhook/IMDSv2 boundary](https://nvd.nist.gov/vuln/detail/CVE-2025-64709)

---

## 25. Final decision rule

A high-quality SSRF finding must answer these questions with evidence:

1. **Control:** Which exact input controls the outbound request?
2. **Attribution:** What proves that this input caused the observed request?
3. **Sink:** Which process, library, tool, worker, or proxy performed it?
4. **Boundary:** Which destination or authorization boundary was affected in the controlled environment?
5. **Exposure:** What response or effect was actually observable?
6. **Consistency:** Did parser, policy, resolver, proxy, and connector agree on the same destination?
7. **Execution:** Did redirects, retries, background jobs, browsers, or agent tools receive the same policy?
8. **Identity:** Which user, tenant, and service identity performed the operation?
9. **Fix:** What shared control prevents recurrence across every network-capable code path?

If an answer is unknown, mark it unknown. Do not replace missing evidence with assumptions, payload folklore, a model's narration, or an exaggerated impact claim.
