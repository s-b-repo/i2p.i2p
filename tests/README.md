# Tests and security checks

Keep test programs, fixtures, runners and generated evidence under `tests/`.

- `regression/`: standalone Java regressions supplied with individual fixes.
- `scripts/`: existing project checks and the NTCP key-log check.
- `audit/`: security scanner, GitHub Actions worker tooling and their unit tests.
- `native/`: sanitizer harnesses for production C functions and JNI failure paths.
- `fixtures/runtime-review/`: saved original inputs for before/after runtime checks.
- `results/`: ignored generated reports, logs and temporary test output.

Run the audit tooling tests with:

```sh
python3 -m unittest discover -s tests/audit -p 'test_*.py'
python3 tests/audit/workflow_definitions.py --check
python3 tests/audit/audit.py security --output tests/results/security
python3 tests/audit/pattern_scan.py --output tests/results/patterns/report.json
python3 tests/audit/audit.py regression --output tests/results/regression
```

Run the tunnel bandwidth, fragment bounds, access-filter capacity and native C
checks with:

```sh
python3 tests/scripts/check_runtime_candidates.py
```

This requires a JDK supporting `--release 17`, GCC, GMP development headers and
JNI headers. MinGW enables optional Windows cross-compilation. The runner checks
that saved original sources fail and current fixes pass, then writes
`tests/results/runtime-review/report.json`. Read the
[runtime review](../docs/reviews/runtime-validation.md) for results and limits.

The regex scan covers Java/C production source and writes path/line/rule matches
under `results/patterns/`. Review its matches with the guidance in
[audit/PATTERNS.md](audit/PATTERNS.md); counts are review candidates and require
caller/control-flow checks before treating them as defects.

See [the worker documentation](audit/README.md) for prerequisites, other commands
and coverage limits. GitHub requires workflow entry points under
`.github/workflows/`; those entry points call the tooling here.

Run the I2PSnark bencode decoder regressions with:

```sh
python3 tests/scripts/check_i2psnark_bdecode.py
```

This requires a JDK supporting `--release 8` and an existing
`core/java/build/i2p.jar`. It checks truncated containers, overflowing string
lengths, integer length limits, dictionary validation and nesting limits, plus
valid streamed values and the hash of the original torrent info bytes. Each
group runs in a separate JVM with a heap limit and timeout. Use `--case` to run
one group, or `--source-root` to exercise another copy of the decoder sources.

Run the I2PSnark discovery and connection lifecycle checks with:

```sh
python3 tests/scripts/check_i2psnark_discovery.py
```

This requires a JDK supporting `--release 17` and the local core, streaming,
systray, desktopgui and Jetty build jars. It compiles all I2PSnark Java sources
and exercises real KRPC messages through an in-memory I2P session. Checks cover
parallel destination resolution, iterative referrals, early replies, announce
tokens, deadlines, cancellation, bounded queues, saved DHT nodes, private
torrents, restart generations and pending connection limits. No network sockets
are opened; timing checks measure controlled discovery behavior, not live swarm
download throughput. Discovered destinations remain in Snark's DHT routing table;
they do not identify the host router or supply a RouterInfo for the router netDb.

Run the local app integration checks with:

```sh
python3 tests/scripts/check_i2psnark_integrations.py
```

These require the same build jars, console build classes, the bundled Tomcat JSP compiler and Ant
(`ANT_HOME` may point to its installation). The runner compiles Snark, the console
link helper and the torrents JSP. It checks console-to-Snark URL handoffs through
the shared request filter, escaped prefilled forms, completion notification
paths, notification-service failures, application lifecycle state, delayed or
replaced update services, registration rollback and shutdown races. App services
are controlled test doubles: no desktop notifications are sent, downloads added,
updates installed or network connections opened.

Tunnel restart and default-page checks use the existing local build jars, the
i2ptunnel helper jar, and preserved source snapshots:

```sh
python3 tests/scripts/check_performance_web.py
python3 tests/scripts/check_default_pages.py
```

The first command compiles the original, isolated and combined Java changes with
`--release 17`. It tests controlled tunnel start ordering and cancellation,
console response delays, real in-memory Jetty HTTP responses and CSP nonces.
It opens no network sockets. The second checks all shipped HTML pages' passive
resource policies, language links and resource counts. Add `--previews` with
WeasyPrint installed to generate static PDF previews; those do not replace
browser testing. See the [performance and web review](../docs/reviews/performance-web/README.md)
for evidence and limits.

Run the web server stack security and asynchronous overload checks with:

```sh
python3 tests/scripts/check_webserver_stack.py
```

This uses existing local build jars, a JDK supporting `--release 17`, and
`keytool` for a temporary test certificate. It checks Origin validation, console
hosts, HTTP framing, worker queue saturation, bounded asynchronous admission,
connection accounting, failure/timeout recovery, restart, static file delivery
and TLS configuration. It opens no network sockets. See the
[web server stack review](../docs/reviews/webserver-stack/README.md) for settings,
compatibility changes and validation limits.

Run the SusiMail security checks with existing local build jars, a JDK supporting
`--release 17`, Python 3 and Node.js:

```sh
python3 tests/scripts/check_mail_security.py
```

This compiles all SusiMail production Java sources, checks SMTP/POP3 command
bytes and diagnostics, MIME downloads and ZIP entry names, HTTP cache/CSP
headers, CSRF checks and session ID rotation. JavaScript scenarios check parent
frame resizing without executing scripts inside messages. Jetty uses an
in-memory connector; no mail servers or network sockets are needed. Results go
under `tests/results/mail-security/current/`. See the
[mail security review](../docs/reviews/mail-security.md) for results and limits.
