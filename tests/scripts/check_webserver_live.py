#!/usr/bin/env python3
"""Real loopback HTTP/TLS/QUIC and isolated packaged-router acceptance checks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def invoke(command, cwd, timeout=120):
    before = time.monotonic()
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout)
        return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                "duration_seconds": round(time.monotonic() - before, 3)}
    except subprocess.TimeoutExpired as failure:
        def text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        return {"exit_code": None, "error": "timeout", "stdout": text(failure.stdout), "stderr": text(failure.stderr)}


def available_port():
    with socket.socket() as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        return endpoint.getsockname()[1]


def get(url, headers=None, data=None):
    # Trust only the temporary self-signed fixture in this local acceptance run.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    try:
        response = opener.open(urllib.request.Request(url, headers=headers or {}, data=data), timeout=5)
    except urllib.error.HTTPError as failure:
        response = failure
    with response:
        return response.status, dict(response.headers), response.read(512 * 1024)


def passed_java(result):
    match = re.search(r"^LIVE_WEB_SERVER_CHECKS=(\d+); FAILURES=(\d+)$", result.get("stdout", ""), re.M)
    return result["exit_code"] == 0 and match is not None and int(match[2]) == 0


def router_run(work, classpath, certificate, package, optional):
    install, state = work / "install", work / "state"
    install.mkdir()
    state.mkdir(mode=0o700)
    with zipfile.ZipFile(package) as archive:
        for name in archive.namelist():
            if not (install / name).resolve().is_relative_to(install):
                raise RuntimeError("Unexpected package path")
        archive.extractall(install)
    for jar in optional.glob("*.jar"):
        shutil.copy2(jar, install / "lib" / jar.name)
    shutil.copytree(ROOT / "installer/resources/eepsite", state / "eepsite")
    shutil.copy2(ROOT / "installer/resources/eepsite-jetty9.3/jetty-gzip.xml", state / "eepsite/jetty-gzip.xml")
    (state / "keystore").mkdir(mode=0o700)
    shutil.copy2(certificate, state / "keystore/console.ks")
    shutil.copy2(certificate, state / "eepsite/etc/keystore.ks")
    ports = []
    while len(ports) < 4:
        port = available_port()
        if port not in ports:
            ports.append(port)
    console, console_tls, site, site_tls = ports
    for name, replacements in {
        "jetty.xml": {"<Set name=\"port\">7658</Set>": f"<Set name=\"port\">{site}</Set>"},
        "jetty-ssl.xml": {"<Set name=\"port\">7668</Set>": f"<Set name=\"port\">{site_tls}</Set>",
                          "<Set name=\"securePort\">7668</Set>": f"<Set name=\"securePort\">{site_tls}</Set>"},
    }.items():
        path = state / "eepsite" / name
        text = path.read_text()
        for old, new in replacements.items():
            if old not in text:
                raise RuntimeError("Template port setting changed: " + name)
            text = text.replace(old, new)
        path.write_text(text)
    (state / "eepsite/live.properties").write_text(f"jetty.quic.port={site_tls}\n")
    (state / "router.config").write_text("\n".join([
        "router.reseedDisable=true", "i2np.udp.enable=false", "i2np.ntcp.enable=false", "time.disabled=true",
        "routerconsole.browser=none", "router.updatePolicy=notify", "router.enablePlugins=false",
        "i2np.upnp.enable=false", "routerconsole.newsRefreshFrequency=0",
        "routerconsole.http3.enable=true", "routerconsole.keystorePassword=changeit", "routerconsole.keyPassword=myKeyPassword",
        "routerconsole.lang=en", "router.sharePercentage=0", "i2cp.disableInterface=true",
    ]) + "\n")
    (state / "clients.config").write_text("\n".join([
        "clientApp.0.main=net.i2p.router.web.RouterConsoleRunner", "clientApp.0.startOnLoad=true", "clientApp.0.delay=0",
        f"clientApp.0.args={console} 127.0.0.1 -s {console_tls} 127.0.0.1 {install / 'webapps'}",
        "clientApp.1.main=net.i2p.jetty.JettyStart", "clientApp.1.startOnLoad=true", "clientApp.1.delay=0",
        "clientApp.1.args=eepsite/live.properties eepsite/jetty.xml eepsite/jetty-ssl.xml eepsite/jetty-http3.xml eepsite/jetty-gzip.xml",
    ]) + "\n")
    (state / "webapps.config").write_text("\n".join([
        "webapps.routerconsole.startOnLoad=true", "webapps.i2ptunnel.startOnLoad=true", "webapps.i2psnark.startOnLoad=false",
        "webapps.susidns.startOnLoad=false", "webapps.susimail.startOnLoad=false", "webapps.imagegen.startOnLoad=false",
    ]) + "\n")
    output = work / "router.log"
    command = ["java", "-Xmx384m", "-XX:-UsePerfData", "-Djava.awt.headless=true", "-Djbigi.enable=false",
               "-DI2P_DISABLE_OUTPUT_OVERRIDE=true", "-Di2p.dir.base=" + str(install), "-Di2p.dir.config=" + str(state),
               "-Di2p.dir.temp=" + str(state / "tmp"), "-cp", str(install / "lib/*"), "net.i2p.router.RouterLaunch"]
    checks = []
    def check(ok, label):
        checks.append({"check": label, "passed": bool(ok)})
    with output.open("w") as log:
        process = subprocess.Popen(command, cwd=state, stdout=log, stderr=subprocess.STDOUT)
        native = None
        try:
            base = f"http://localhost:{console}"
            deadline = time.monotonic() + 120
            ready = False
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    ready = get(base + "/")[0] == 200 and get(f"http://localhost:{site}/help/")[0] == 200
                    if ready:
                        break
                except OSError:
                    pass
                time.sleep(0.25)
            check(ready, "packaged router console and hosted site start")
            if ready:
                status, headers, body = get(base + "/")
                check(status == 200 and b"I2P" in body, "real packaged console page")
                check(headers.get("X-Content-Type-Options") == "nosniff" and headers.get("Referrer-Policy") == "no-referrer",
                      "packaged console security headers")
                check("Server" not in headers, "packaged console hides server version")
                check(get(base + "/", {"Host": "evil.example"})[0] == 403, "packaged console denies untrusted hosts")
                check(get(base + "/", {"Origin": "https://evil.example"}, b"x=1")[0] == 403,
                      "packaged console denies cross-origin write")
                check(get(base + "/", {"Origin": "null"}, b"x=1")[0] == 403, "packaged console denies opaque-origin write")
                check(get(base + "/i2ptunnel/")[0] == 200, "packaged tunnel manager is reachable")
                check(get(f"https://localhost:{console_tls}/")[0] == 200, "packaged console HTTPS works")
                check(get(f"https://localhost:{site_tls}/help/")[0] == 200, "packaged site HTTPS works")
                code, headers, body = get(f"http://localhost:{site}/help/lib/")
                check(code == 403, "packaged hosted site blocks directory listing")
                native = invoke(["java", "-Xmx256m", "-XX:-UsePerfData", "-Djbigi.enable=false", "-cp", classpath,
                                 "net.i2p.jetty.LiveWebServerRegression", "--probe", f"https://127.0.0.1:{console_tls}/",
                                 f"https://127.0.0.1:{site_tls}/help/"], work, 45)
                check(passed_java(native), "real packaged console and site serve QUIC with origin protection")
        except Exception as failure:
            check(False, "router acceptance exception: " + type(failure).__name__ + ": " + str(failure))
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return {"passed": all(item["passed"] for item in checks), "checks": checks, "quic_probe": native,
            "process_exit_code": process.returncode, "stdout": output.read_text(errors="replace")[-40000:],
            "limits": ["Fresh isolated identity; peer transports, reseeding, NTP and automatic update installation disabled.",
                       "This exercises real loopback HTTP/TLS/UDP, not live I2P tunnel throughput."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http3-jars", type=Path, default=ROOT / "tests/results/webserver-stack/http3-jars")
    parser.add_argument("--package", type=Path, help="Also run the isolated packaged router and its hosted site")
    parser.add_argument("--output", type=Path, default=ROOT / "tests/results/webserver-stack/live.json")
    args = parser.parse_args()
    native_jars = sorted(args.http3_jars.resolve().glob("*.jar"))
    if not native_jars:
        raise SystemExit("Resolve the optional HTTP/3 runtime first; see the companion Maven fixture")
    jars = native_jars + sorted((ROOT / "build").glob("*.jar")) + [ROOT / "installer/lib/wrapper/all/wrapper.jar"]
    dependencies = os.pathsep.join(map(str, jars))
    report = {"passed": False, "dependencies": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in jars}}
    with tempfile.TemporaryDirectory(prefix="i2p-webserver-live-") as temporary:
        work = Path(temporary)
        classes = work / "classes"
        classes.mkdir()
        sources = sorted((ROOT / "apps/jetty/java/src").rglob("*.java"))
        sources += [ROOT / "apps/routerconsole/java/src/net/i2p/router/web/HostCheckHandler.java",
                    ROOT / "tests/regression/LiveWebServerRegression.java"]
        report["compilation"] = invoke(["javac", "--release", "17", "-encoding", "UTF-8", "-cp", dependencies,
                                        "-d", str(classes), *map(str, sources)], ROOT)
        optional_sources = sorted((ROOT / "apps/jetty/java/http3-src").rglob("*.java"))
        if report["compilation"]["exit_code"] == 0:
            report["secure_adapter_compilation"] = invoke(
                ["javac", "--release", "17", "-encoding", "UTF-8", "-cp", os.pathsep.join([str(classes), dependencies]),
                 "-d", str(classes), *map(str, optional_sources)], ROOT)
            if report["secure_adapter_compilation"]["exit_code"] == 0:
                adapter = args.http3_jars.resolve() / "jetty-http3-i2p.jar"
                with zipfile.ZipFile(adapter, "w", compression=zipfile.ZIP_DEFLATED) as jar:
                    jar.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Version: 12.0.41\n\n")
                    jar.write(ROOT / "licenses/LICENSE-Apache2.0.txt", "META-INF/LICENSE.txt")
                    jar.write(ROOT / "licenses/LICENSE-Jetty.txt", "META-INF/NOTICE-Jetty.txt")
                    for item in sorted((classes / "net/i2p/jetty/http3").rglob("*.class")):
                        jar.write(item, str(item.relative_to(classes)))
                report["dependencies"][str(adapter)] = hashlib.sha256(adapter.read_bytes()).hexdigest()
        certificate = work / "server.ks"
        report["certificate"] = invoke(["keytool", "-genkeypair", "-keystore", str(certificate), "-storetype", "JKS",
                                         "-storepass", "changeit", "-keypass", "myKeyPassword", "-alias", "regression",
                                         "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1,ip:::1",
                                         "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "1", "-noprompt"], work)
        if (report["compilation"]["exit_code"] == 0 and report["certificate"]["exit_code"] == 0 and
            report.get("secure_adapter_compilation", {}).get("exit_code") == 0):
            classpath = os.pathsep.join([str(classes), dependencies])
            report["protocols"] = invoke(["java", "-Xmx256m", "-XX:-UsePerfData", "-Djbigi.enable=false", "-cp", classpath,
                                           "net.i2p.jetty.LiveWebServerRegression", str(certificate)], work, 90)
            report["passed"] = passed_java(report["protocols"])
            if args.package:
                report["router"] = router_run(work, classpath, certificate, args.package.resolve(), args.http3_jars.resolve())
                report["passed"] = report["passed"] and report["router"]["passed"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("LIVE_WEB_SERVER_PASSED=" + str(report["passed"]))
    if not report["passed"]:
        for name in ("compilation", "secure_adapter_compilation", "certificate", "protocols", "router"):
            if name in report:
                print(name, report[name])
    print("Report:", args.output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
