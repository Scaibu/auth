#!/usr/bin/env bash
# ==============================================================================
# AUTH SERVICE DATABASE MIGRATION RUNNER
# Applies AlloyDB (PostgreSQL) DDL migrations for @observability/auth
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo "RUNNING AUTH DATABASE MIGRATIONS"
echo "================================================================================"

cd "${PACKAGE_ROOT}"
npx tsx database/migrate.ts

echo "================================================================================"
echo "AUTH DATABASE MIGRATIONS COMPLETED"
echo "================================================================================"
