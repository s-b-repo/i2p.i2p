#!/usr/bin/env python3
"""Offline HTTP, asynchronous overload and lifecycle checks for I2P's web stack."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
SOURCES = [
    "apps/jetty/java/src/net/i2p/servlet/util/ServletUtil.java",
    "apps/routerconsole/java/src/net/i2p/router/web/HostCheckHandler.java",
    "apps/routerconsole/java/src/net/i2p/router/web/RouterConsoleRunner.java",
]
CONFIGS = ["installer/resources/eepsite/jetty.xml", "installer/resources/eepsite/jetty-ssl.xml"]


def invoke(command, directory, timeout=120):
    before = time.monotonic()
    try:
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=timeout)
        return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                "duration_seconds": round(time.monotonic() - before, 3)}
    except subprocess.TimeoutExpired as error:
        def decode(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        return {"exit_code": None, "error": "timeout", "stdout": decode(error.stdout),
                "stderr": decode(error.stderr), "duration_seconds": timeout}


def run(source):
    bundle = ROOT / "apps/jetty/jetty-home-12.0.41"
    manifest = json.loads((bundle / "artifacts.json").read_text())
    jars = []
    for artifact in manifest["artifacts"]:
        jar = bundle / artifact["path"]
        if hashlib.sha256(jar.read_bytes()).hexdigest() != artifact["sha256"]:
            raise RuntimeError("Bundled dependency checksum mismatch: " + str(jar))
        jars.append(jar)
    # Load the pinned Jetty set before the existing I2P and Tomcat build jars.
    jars += sorted((ROOT / "build").glob("*.jar"))
    jars.append(ROOT / "installer/lib/wrapper/all/wrapper.jar")
    if not (ROOT / "build/i2p.jar").is_file() or any(not p.is_file() for p in jars):
        raise RuntimeError("Build the repository jars before running this check")
    dependencies = os.pathsep.join(map(str, jars))
    fixture = ROOT / "tests/regression/WebServerStackRegression.java"
    support = [p for p in sorted((ROOT / "apps/jetty/java/src").rglob("*.java"))
               if str(p.relative_to(ROOT)) not in SOURCES]
    report = {
        "passed": False,
        "source_root": str(source),
        "java": invoke(["java", "-version"], ROOT),
        "source_sha256": {p: hashlib.sha256((source / p).read_bytes()).hexdigest() for p in SOURCES + CONFIGS},
        "dependency_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in jars},
        "limits": [
            "LocalConnector exercises real HTTP parsing and handlers without opening network sockets.",
            "Connection cap accounting uses synthetic selectable channels, not a live TCP load test.",
            "TLS XML is configured but no certificate handshake is performed.",
            "Controlled saturation is not a measurement of live I2P throughput or browser latency.",
            "Compilation targets Java 17 against existing local dependency jars, not a full distribution build.",
        ],
    }
    with tempfile.TemporaryDirectory(prefix="i2p-webserver-stack-") as temporary:
        directory = Path(temporary)
        classes = directory / "classes"
        classes.mkdir()
        report["compilation"] = invoke(
            ["javac", "--release", "17", "-encoding", "UTF-8", "-cp", dependencies,
             "-d", str(classes), *[str(source / p) for p in SOURCES],
             *map(str, support), str(fixture), str(ROOT / "tests/regression/AsyncWebServerRegression.java")], ROOT)
        if report["compilation"]["exit_code"] != 0:
            return report
        key_directory = directory / "eepsite/etc"
        key_directory.mkdir(parents=True)
        report["test_certificate"] = invoke(
            ["keytool", "-genkeypair", "-keystore", "eepsite/etc/keystore.ks", "-storetype", "JKS",
             "-storepass", "changeit", "-keypass", "myKeyPassword", "-alias", "regression",
             "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1,ip:::1",
             "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "1", "-noprompt"], directory)
        if report["test_certificate"]["exit_code"] != 0:
            return report
        report["runtime"] = invoke(
            ["java", "-Xmx256m", "-XX:-UsePerfData", "-Djbigi.enable=false", "-Djbigi.dontLog=true",
             "-DI2P_DISABLE_OUTPUT_OVERRIDE=true", "-cp", os.pathsep.join([str(classes), dependencies]),
             "net.i2p.router.web.WebServerStackRegression", str(source), str(ROOT)], directory, 90)
        match = re.search(r"^WEB_SERVER_STACK_CHECKS=(\d+); FAILURES=(\d+)$", report["runtime"]["stdout"], re.M)
        if match:
            report["checks"], report["failures"] = map(int, match.groups())
            report["passed"] = report["runtime"]["exit_code"] == 0 and report["failures"] == 0
        if report["passed"] and source == ROOT:
            report["asynchronous"] = invoke(
                ["java", "-Xmx256m", "-XX:-UsePerfData", "-Djbigi.enable=false", "-Djbigi.dontLog=true",
                 "-DI2P_DISABLE_OUTPUT_OVERRIDE=true", "-cp", os.pathsep.join([str(classes), dependencies]),
                 "net.i2p.jetty.AsyncWebServerRegression"], directory, 90)
            match = re.search(r"^ASYNC_WEB_SERVER_CHECKS=(\d+); FAILURES=(\d+)$", report["asynchronous"]["stdout"], re.M)
            report["passed"] = (report["asynchronous"]["exit_code"] == 0 and match is not None and int(match[2]) == 0)
            if match:
                report["checks"] += int(match[1])
                report["failures"] += int(match[2])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "tests/results/webserver-stack/validation.json")
    args = parser.parse_args()
    report = run(args.source_root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("WEB_SERVER_STACK_PASSED=" + str(report["passed"]))
    if "checks" in report:
        print("CHECKS=" + str(report["checks"]) + "; FAILURES=" + str(report["failures"]))
    if not report["passed"]:
        for step in ("compilation", "test_certificate", "runtime", "asynchronous"):
            if step in report:
                print(report[step]["stdout"])
                print(report[step]["stderr"])
    print("Report:", args.output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
