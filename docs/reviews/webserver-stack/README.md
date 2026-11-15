# Web server stack changes

The console and hosted-site defaults now bound HTTP work without rejecting
Jetty's internal asynchronous tasks. Origin checks reject opaque and ambiguous
values, wildcard console listeners retain hostname checks, and the HTTPS site
template works with Jetty 12's server TLS factory.

The source changes are in `apps/jetty`, `apps/routerconsole`, and
`installer/resources/eepsite`. Ant, Gradle and the Debian companion profile now
use Jetty 12.0.41. Debian builds and runtime packages require
`libjetty12-java >= 12.0.41`.

The [12.0.41 release](https://github.com/jetty/jetty.project/releases/tag/jetty-12.0.41)
includes fixes newer than the previous 12.0.28/12.0.32 pins. Upstream's
[security advisories](https://jetty.org/security.html) include HTTP request
smuggling fixes affecting those older releases. The complete bundle and the
Debian EE8 companion bundle carry SHA-256 sidecars and artifact manifests with
upstream Maven URLs. The jars came from the existing local Gradle cache; its
content hashes were checked before copying. Normal Ant builds verify the
sidecars. Explicit archive imports now require an upstream SHA-256 digest.

| Default | Console | Hosted site |
| --- | --- | --- |
| Concurrent application requests | 12 | 12 |
| Requests waiting for admission | 96 | 64 |
| Maximum admission wait | 5 seconds | 10 seconds |
| Open network connections, across listeners | 128 | 256 |
| Connection idle timeout | 90 seconds | 120 seconds |
| Acceptor / selector threads per listener | 1 / 1 | 1 / 1 |
| Reserved worker threads | 1 | 1 |

Excess requests wait in Jetty's `QoSHandler` without holding a worker thread.
Full queues and expired waits return HTTP 503. Connection limits pause acceptance
until a connection closes. Limits apply across clients rather than per source IP,
since inbound I2P clients share a loopback address. Worker task queues remain
unbounded, and worker thread counts remain bounded. The console explicitly
budgets connector and reserved threads; hosted sites have 20 maximum workers
and four minimum workers by default.

This follows Jetty's guidance on [worker queues](https://jetty.org/docs/jetty/12/programming-guide/arch/threads.html)
and [asynchronous request admission](https://javadoc.jetty.org/jetty-12/org/eclipse/jetty/server/handler/QoSHandler.html).
The hosted-site HTTPS template uses `SslContextFactory.Server`, retains Jetty's
maintained cipher exclusions, permits TLS 1.2 and 1.3, and installs
`SecureRequestCustomizer` so applications receive the secure request state and
SNI checks. Both console listeners suppress the server version and powered-by
headers.

Origin validation in both the core and servlet APIs compares parsed scheme,
hostname and effective port without DNS resolution. For methods other than
GET, HEAD, OPTIONS and TRACE, it rejects `Origin: null`, multiple origins,
credentials, paths, queries, fragments, malformed values and different origins.
Requests without Origin remain compatible with existing command-line clients;
application authentication and CSRF tokens remain necessary. This is consistent
with [OWASP's origin verification guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#using-standard-headers-to-verify-origin).

## Configuration and compatibility

Accessing a wildcard-bound console through a DNS name now requires listing
that name in `routerconsole.allowedHosts`, for example:

```properties
routerconsole.allowedHosts=router.example,router.lan
```

Restart the console after changing this setting. Localhost, numeric IPv4/IPv6
addresses and explicitly allowed hostnames remain supported. Hostname matching
is case-insensitive. An empty hostname set no longer allows arbitrary names.
Browsers sending opaque origins on writes receive 403 and must use the console
origin directly.

Hosted-site values can be set in a `.properties` file passed to `JettyStart`
before the XML configuration files:

```properties
jetty.threads.max=20
jetty.threads.min=4
jetty.threads.idleTimeout=60000
jetty.connectionLimit=256
jetty.qos.maxRequestCount=12
jetty.qos.maxSuspendedRequestCount=64
jetty.qos.maxSuspendMillis=10000
jetty.http.idleTimeout=120000
jetty.ssl.idleTimeout=120000
```

Increase worker and admission limits together for busy sites, leaving workers
for connectors, reserved execution and I/O completion. Keep a finite waiting
queue and positive admission timeout. The HTTPS template still requires a site
certificate and the matching keystore paths/passwords. Older TLS clients must
support TLS 1.2 or newer.

These edits update source code and shipped templates. Existing installations
need rebuilt Java artifacts and equivalent changes to their own site XML files;
their live configuration and services were not changed by this work.

## Validation

Run the regression with a JDK providing Java 17 compilation and `keytool`, plus
the existing local build jars:

```sh
python3 tests/scripts/check_webserver_stack.py
python3 tests/scripts/check_performance_web.py
```

The local regression passes 233 checks against Jetty 12.0.41. It exercises both Origin APIs with HTTP,
HTTPS request state, default ports and IPv6; console host restrictions and
redirects; ambiguous authorities, request framing and malformed chunk extensions;
a 148-task worker burst;
global connection accounting; asynchronous request saturation, queue overflow,
callback failure, timeout cleanup, recovery and restart. It also loads the
shipped site, gzip and static context configurations to check page delivery,
headers, caching, HEAD, ranges, compression, disabled directory listings and
error responses through the request limiter. The TLS factory starts with a
temporary test certificate, and selected protocols and cipher suites are checked.

The same regression against the saved original sources fails 37 expectations
before reaching the new admission tests. Those are regression expectations, not
37 separate vulnerabilities. All 183 production Java sources in the Jetty and
console modules also compile with `--release 17`. The existing performance/web
regression passes its combined checks. The Jetty Ant jar build passes. Both
dependency profiles pass the checksum gate, while an intentionally altered jar
fails it. Debian source packaging retains the EE8 companion bundle; bundled
Ubuntu source packaging retains the full bundle.

Generated evidence is under `tests/results/webserver-stack/`, including
`validation.json`, `original.json`, `module-compilation.json`, `jetty-build.json`
and `dependency-integrity.json`. A review patch
is provided as [changes.patch](changes.patch).

HTTP runs through Jetty's in-memory connector. Connection accounting uses
synthetic selectable channels. TLS context startup is tested, but live TCP load,
TLS handshakes, browser interaction, a full distribution build and live I2P
throughput are outside these checks. The controlled overload timings are not
claims about live network speed.

## Additional server facilities

`WebServerPolicy` composes global request rate limits, request body limits,
default privacy headers, graceful draining and Jetty response statistics.
Defaults are 64 requests/second with a 128-request burst, a 128 MiB request body
limit and a five-second graceful stop. `jetty.requestsPerSecond`,
`jetty.requestBurst`, `jetty.maxRequestBytes` and `jetty.stopTimeout` configure the
hosted site. Console rate settings are `routerconsole.requestsPerSecond` and
`routerconsole.requestBurst`. Console shutdown returns immediately and performs
draining and cleanup on a dedicated thread. Body read rates are bounded at
16 bytes/second for the site and 128 bytes/second for the console.

Access logging uses a bounded background writer and batched flushes. Full log
queues drop records rather than stopping HTTP workers; dropped records are
observable. Shutdown drains accepted records. URI credentials are omitted and
untrusted fields cannot inject log records. Metadata lookups for
`X-I2P-Location` run in a bounded, coalesced background worker, with a cache per
local endpoint. A first response can omit that optional header while a lookup
is pending. Generated locations no longer expose backend listener ports.

## Optional HTTP/3 over QUIC

The optional adapter uses Jetty's HTTP/3 and native Quiche implementation.
Jetty 12 labels this transport experimental, so it is disabled by default.
It provides direct UDP access; ordinary I2P HTTP streaming tunnels do not carry
QUIC. Existing HTTP/TLS listeners remain available.

Resolve the matching optional runtime with
`./gradlew :apps:jetty:copyHttp3Runtime` and install its jars alongside the I2P
runtime. The dependency graph includes JNA and native Quiche. A separate Maven
fixture under `tests/fixtures/webserver-stack/http3/` resolves server and client
dependencies for acceptance testing.

For a hosted site, append `eepsite/jetty-http3.xml` after its `jetty.xml` and
`jetty-ssl.xml`. Configure `jetty.quic.host`, `jetty.quic.port` and
`jetty.quic.pemDirectory` in a preceding properties file. Console HTTP/3 is
enabled with `routerconsole.http3.enable=true` alongside a configured TLS
listener, using the same numeric UDP port. PEM exports require a verified
owner-only directory and symbolic-link targets are rejected. Optional modules
must match the active Jetty version.

HTTP/3 shares the application protections. Stream counts, receive windows,
header sizes, blocked QPACK streams, idle timeouts and session counts are
bounded. `Alt-Svc` advertises only a running secure direct service and is
suppressed for I2P hostnames and tunnel-identifying headers. The adapter does
not register UDP as an I2P streaming tunnel target.

Local TCP and UDP binds are denied by the execution sandbox. The companion
`webserver-stack.yml` workflow and `check_webserver_live.py` perform live
TCP/TLS/QUIC checks and run fresh packaged console/site instances on a hosted
runner. Live validation is still pending; it must complete before publication.
