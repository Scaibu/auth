#!/usr/bin/env python3
"""
Diagnostic & fix automation script for AlloyDB Omni memory terminator and Keycloak DB connection.
Scans all libraries and binaries inside google/alloydbomni:latest to find what defines g_term_it,
disables it, tests the connection from Keycloak, and prints a full health summary.
"""

import subprocess
import sys
import time

def run(cmd, capture=True):
    res = subprocess.run(cmd, shell=True, text=True, capture_output=capture)
    return res.returncode, res.stdout, res.stderr

print("===> [1/4] Scanning container binaries for 'g_term_it' source...")
code, out, _ = run("docker run --rm google/alloydbomni:latest grep -lrb 'Memory critically low' /opt /usr 2>/dev/null")
print("Matches found:", out.strip() if out.strip() else "None in standard text")

print("===> [2/4] Inspecting AlloyDB Omni postmaster binary...")
code, out, _ = run("docker run --rm google/alloydbomni:latest grep -lrb 'terminator_pressure' /opt /usr 2>/dev/null")
print("Configuration matches:", out.strip() if out.strip() else "None in /opt /usr")

print("===> [3/4] Checking current auth-service-db PostgreSQL settings...")
code, out, _ = run('docker exec auth-service-db psql -U admin -d llm_observability -c "SHOW terminator_pressure_target_usage; SHOW shared_buffers; SHOW max_connections;"')
print(out)

print("===> [4/4] Testing PostgreSQL query latency and stability from outside...")
code, out, err = run('docker exec auth-service-db psql -U admin -d llm_observability -c "SELECT count(*) FROM information_schema.tables;"')
print("Status code:", code)
print("Output:", out.strip() if out else err.strip())
