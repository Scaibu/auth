#!/usr/bin/env python3
"""
Deep inspection of AlloyDB Omni /usr/lib/postgresql/16/bin/postgres for terminator settings and thresholds.
"""

import subprocess

cmd = "docker run --rm google/alloydbomni:latest cat /usr/lib/postgresql/16/bin/postgres"
data = subprocess.check_output(cmd, shell=True)

keywords = [b"g_term_it", b"terminator", b"Memory critically low", b"terminator_pressure"]
for kw in keywords:
    print(f"Keyword '{kw.decode()}':", data.count(kw), "occurrences")

# Find strings surrounding "Memory critically low"
idx = data.find(b"Memory critically low")
if idx != -1:
    surrounding = data[max(0, idx - 200): idx + 300]
    # Filter printable
    printable = "".join(chr(b) if 32 <= b < 127 else " " for b in surrounding)
    print("Context around 'Memory critically low':")
    print(printable)

# Find all GUC variable names starting with terminator or pressure
import re
guc_vars = re.findall(rb"[a-zA-Z0-9_]*terminator[a-zA-Z0-9_]*", data)
print("Unique terminator tokens:", set(v.decode() for v in guc_vars))
