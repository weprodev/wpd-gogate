---
description: Review git diff vs main/develop for code smells against wpd-gogate architecture and Go best practices
argument-hint: "[target-branch]"
allowed-tools: Bash(git:*), Read, Grep, Glob
---

# /smell — Pre-PR Quality Review

Structured review of **your changes** against this repository’s architecture, security rules, and Go best practices.
Applies to the core library (`*.go`), migrations (`migrations/`), seeds (`seeds/`), and local testing configurations.

Run before opening a PR — after local lint/test, before or alongside `make audit`.

**Default base branch:** `main` · override: `/smell develop`

**Authoritative sources:** `gate.go`, `model_ref.go`, `role_ref.go`, `middleware.go`

---

## Step 1 — Ingest diff

!`bash -c '
BASE="$1"
if [ -z "$BASE" ]; then
  BASE="main"
  git rev-parse "$BASE" >/dev/null 2>&1 || BASE="origin/main"
  git rev-parse "$BASE" >/dev/null 2>&1 || BASE="develop"
fi
if ! git rev-parse "$BASE" >/dev/null 2>&1; then
  echo "ERROR: base $BASE not found. Pass: /smell <branch>"
  exit 1
fi
echo "===== BASE: $BASE ====="
echo
echo "----- Stat (committed vs $BASE) -----"
git diff --stat "$BASE"...HEAD || true
echo
echo "----- Stat (working tree) -----"
git diff --stat HEAD || true
echo
echo "===== Committed diff (vs $BASE, -U10) ====="
git diff -U10 "$BASE"...HEAD || true
echo
echo "===== Working-tree diff (-U10) ====="
git diff -U10 HEAD || true
' -- "$ARGUMENTS"`

---

## Step 2 — Classify change

State one category with a one-sentence reason:

`feature` · `refactor` · `bugfix` · `test` · `docs` · `config` · `mixed`

---

## Step 3 — Apply review lens

Pick the primary lens and justify in one sentence:

- **Concurrency & Thread Safety** — Mutex usage, map access, race conditions
- **SQL Efficiency** — Single-query verification, proper index utilization, N+1 query avoidance
- **Clean Code** — Framework-agnostic design, fluent chain safety, error handling
- **Security & Integrity** — Null team scoping, SQL injection, cache consistency

Review **only what changed**. Do not demand unrelated refactors.

### Core Review Checklist

| Area | Violation |
| ---- | --------- |
| **Concurrency & Cache** | Modifying policies without acquiring the write lock; reading the cache registry without a read lock; race conditions. |
| **Framework Agnosticism**| Importing `github.com/labstack/echo/v4` or other HTTP frameworks outside `middleware.go`. |
| **SQL & Database** | Splitting checks into multiple DB queries when `UNION ALL` can check both role and direct permissions at once; string concatenation in queries (always use placeholders). |
| **Null Scoping** | Comparing nullable `team_id` with simple `=` instead of `IS NOT DISTINCT FROM` or matching `NULL` values incorrectly. |
| **Fluent Chain Safety** | Returning nil references or builder states that panic when methods are chained (e.g. `gate.Model(...)`, `gate.Role(...)`). |
| **Cache Updates** | Assigning/revoking roles or permissions in the database without updating the in-memory cache synchronously. |
| **Error Handling** | Ignoring errors in query executions, transactions, or policy loading; swallowing errors without a logger or wrapped return. |
| **Migrations & Seeds** | `.up.sql` without a matching `.down.sql`; hardcoded UUIDs in seed scripts instead of dynamic generation. |

Verify using the package commands:

```bash
make lint
make race
```

---

## Step 4 — Record findings

One finding per issue. Use a catalog ID, the smallest relevant excerpt, and one sentence each for **why** and **fix**.

Do not invent issues. If the diff is clean, say so.

### Project catalog (prefer these)

| ID | Meaning |
| -- | ------- |
| **GGT.THREAD-UNSAFE** | Concurrent read/write on map, missing mutex lock, or race condition |
| **GGT.UNOPTIMIZED-DB** | Multiple database round-trips for a check, N+1 queries, or unindexed checks |
| **GGT.NULL-TEAM-ID** | Incorrect check for nullable `team_id` columns (e.g. missing `IS NOT DISTINCT FROM`) |
| **GGT.FRAMEWORK-LEAK** | Echo or Web framework dependencies leaking into framework-agnostic core package files |
| **GGT.CACHE-DESYNC** | Database mutated but cache registry not kept in sync |
| **GGT.FLUENT-PANIC** | Method chaining logic containing nil pointer hazards or state issues |
| **GGT.MIGRATION-HYGIENE**| Migration sequencing issues, missing down files, or hardcoded seed IDs |
| **CC.DUPLICATION** | Significant duplicated code blocks that could be extracted |
| **GO.ERR-IGNORED** | Error return value discarded or ignored |
| **GO.ERR-NO-WRAP** | Error returned from DB or system without context or `%w` wrapping |
| **GO.CONTEXT-OMIT** | Database/network operations missing context propagation |

---

## Step 5 — Report

Severity: **BLOCKER** · **HIGH** · **MEDIUM** · **LOW** · **NIT**

**BLOCKER** and **HIGH** must be fixed before merge.

```markdown
# Smell Report

**Base:** `<branch>`
**Classification:** `<category>`
**Lens:** `<primary lens>`

## Summary
- Files changed: N
- Findings: N (BLOCKER: n, HIGH: n, …)
- Top risk: …

## Findings

### [SEVERITY] `ID` — `path:line`
**Why:** …
**Fix:** …

## Synthesis
One paragraph on overall code quality, library API cleanliness, and merge readiness.
```

If no issues: **"No findings on this diff — ready for `make audit`."**

---

## Gate

Part of **`docs/agents/verification.md`** (or package verification workflow).

1. Fix compile/lint failures on touched paths first.
2. Complete this smell report; fix **BLOCKER** and **HIGH**.
3. Run **`make audit`** from repo root.
4. Repeat if the diff changes materially.
