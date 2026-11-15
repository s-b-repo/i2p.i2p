#!/usr/bin/env python3
"""Offline before/after checks for tunnel restarts and default web protections."""

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
BASELINE = ROOT / "tests/fixtures/performance-web/baseline"
CASES = {
    "tunnel_restart": {
        "sources": ["apps/i2ptunnel/java/src/net/i2p/i2ptunnel/TunnelController.java",
                    "apps/i2ptunnel/java/src/net/i2p/i2ptunnel/TunnelControllerGroup.java",
                    "apps/i2ptunnel/java/src/net/i2p/i2ptunnel/web/IndexBean.java"],
        "fixture": "TunnelRestartRegression",
        "main": "net.i2p.i2ptunnel.TunnelRestartRegression",
    },
    "default_web_security": {
        "sources": ["apps/jetty/java/src/net/i2p/servlet/I2PDefaultServlet.java",
                    "apps/routerconsole/java/src/net/i2p/router/web/CSSHelper.java"],
        "fixture": "DefaultWebSecurityRegression",
        "main": "net.i2p.servlet.DefaultWebSecurityRegression",
    },
}


def invoke(command, directory, timeout=120):
    before = time.monotonic()
    try:
        result = subprocess.run(command, cwd=directory, text=True, capture_output=True, timeout=timeout)
        return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                "duration_seconds": round(time.monotonic() - before, 3)}
    except subprocess.TimeoutExpired as error:
        def decode(data):
            return data.decode(errors="replace") if isinstance(data, bytes) else data or ""
        return {"exit_code": None, "error": "timeout", "stdout": decode(error.stdout),
                "stderr": decode(error.stderr), "duration_seconds": timeout}


def compile_sources(sources, classes, classpath):
    classes.mkdir()
    return invoke(["javac", "--release", "17", "-encoding", "UTF-8", "-cp", classpath,
                   "-d", str(classes), *map(str, sources)], ROOT)


def exercise(case, classpath, directory, source):
    directory.mkdir()
    result = invoke(["java", "-Xmx256m", "-Djbigi.enable=false", "-Djbigi.dontLog=true",
                     "-DI2P_DISABLE_OUTPUT_OVERRIDE=true", "-cp", classpath, case["main"], str(source)], directory, 45)
    match = re.search(r"^[A-Z_]+_CHECKS=(\d+); FAILURES=(\d+)$", result.get("stdout", ""), re.M)
    result["checks"] = int(match[1]) if match else None
    result["failures"] = int(match[2]) if match else None
    result["passed"] = result["exit_code"] == 0 and result["failures"] == 0
    return result


def run():
    jars = sorted((ROOT / "build").glob("*.jar"))
    jars += sorted((ROOT / "apps/jetty/jetty-home-12.0.41/lib").glob("*.jar"))
    jars.append(ROOT / "apps/i2ptunnel/java/build/temp-beans.jar")
    if any(not jar.is_file() for jar in jars) or not (ROOT / "build/i2p.jar").is_file():
        raise RuntimeError("Build the repository jars and i2ptunnel helpers before running these checks")
    dependencies = os.pathsep.join(map(str, jars))
    sources = [path for case in CASES.values() for path in case["sources"]]
    fixtures = [ROOT / "tests/regression" / (case["fixture"] + ".java") for case in CASES.values()]
    report = {
        "passed": False,
        "java": invoke(["java", "-version"], ROOT),
        "source_sha256": {path: {"original": hashlib.sha256((BASELINE / path).read_bytes()).hexdigest(),
                                  "current": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()} for path in sources},
        "dependency_sha256": {str(jar.relative_to(ROOT)): hashlib.sha256(jar.read_bytes()).hexdigest() for jar in jars},
        "original": {}, "isolated": {}, "combined": {},
        "limits": ["Controlled tunnel connection work does not measure live tunnel throughput or build success rates.",
                   "The restart request still performs stop/session cleanup synchronously before background starts.",
                   "Jetty LocalConnector checks HTTP without opening network sockets.",
                   "Compilation targets Java 17 using existing local build jars; this is not a full project build."],
    }
    with tempfile.TemporaryDirectory(prefix="i2p-performance-web-") as temporary:
        work = Path(temporary)
        original = work / "original-classes"
        report["original_compilation"] = compile_sources([BASELINE / path for path in sources] + fixtures, original, dependencies)
        if report["original_compilation"]["exit_code"] != 0:
            return report
        original_cp = os.pathsep.join([str(original), dependencies])
        for key, case in CASES.items():
            report["original"][key] = exercise(case, original_cp, work / ("original-" + key), BASELINE)
            print("original", key, "failures:", report["original"][key]["failures"], flush=True)
            isolated = work / ("isolated-classes-" + key)
            compilation = compile_sources([ROOT / path for path in case["sources"]] + [ROOT / "tests/regression" / (case["fixture"] + ".java")], isolated, original_cp)
            outcome = {"compilation": compilation, "passed": False}
            if compilation["exit_code"] == 0:
                outcome.update(exercise(case, os.pathsep.join([str(isolated), original_cp]), work / ("isolated-" + key), ROOT))
            report["isolated"][key] = outcome
            print("isolated", key, "passed:", outcome["passed"], flush=True)
        combined = work / "combined-classes"
        report["combined_compilation"] = compile_sources([ROOT / path for path in sources] + fixtures, combined, dependencies)
        if report["combined_compilation"]["exit_code"] == 0:
            for key, case in CASES.items():
                report["combined"][key] = exercise(case, os.pathsep.join([str(combined), dependencies]), work / ("combined-" + key), ROOT)
                print("combined", key, "passed:", report["combined"][key]["passed"], flush=True)
        report["passed"] = (all(r["exit_code"] == 1 and (r["failures"] or 0) > 0 for r in report["original"].values())
                            and all(r["passed"] for r in report["isolated"].values())
                            and len(report["combined"]) == len(CASES)
                            and all(r["passed"] for r in report["combined"].values()))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "tests/results/performance-web/validation.json")
    args = parser.parse_args()
    report = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("PERFORMANCE_WEB_PASSED=" + str(report["passed"]))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
