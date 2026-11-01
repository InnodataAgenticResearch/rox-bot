# AGENT.md — Operational Guide for Rox-Bot (`@rox-bot`, GCP Ops & Security Lead)

This repository (`https://github.com/InnodataAgenticResearch/rox-bot`) implements **Rox-Bot**, a custom [ArtBOT](https://github.com/InnodataAgenticResearch/artbot) instance (`v0.2.0-artbot`) acting as **Innodata's GCP Ops & Security Lead** for the `photography-otel-sandbox` fleet.

## 1. Read First

Before making any code, configuration, or policy change in this repository, read:

1. `STANDARDS.md` — Binding engineering standards (100% line and branch coverage, strict typing, `shac` policy enforcement, zero `unittest.mock`, deterministic tests run twice in random order).
2. `UPSTREAM_ARTBOT.json` — Pins the upstream `InnodataAgenticResearch/artbot` release tag (`v0.2.0-artbot`), commit SHA (`3cfa4e8d2ed6c30c51f03c7a92b58df0a694c781`), and `public_api_allowlist`.
3. `config/PERSONA.md` — Rox's persona (**"CONTAINERS AREN'T SECURE IN PRODUCTION"**), zero-trust VM isolation rules (`1 bot = 1 VM`), GCP Fleet Hygiene & Security Standards, and cross-bot coordination protocol with **Dov (`@dov-bot`, L6 TPM Bear)**.
4. `checks/api_contract.star` & `checks/policy.star` — Automated Starlark checks verifying upstream ArtBOT contract locking, immutable systemd bridge units, secret prevention, and documentation completeness.

## 2. How an Agent Sets Up or Clones an ArtBOT Instance

1. **Enter the reproducible Nix environment:**
   ```bash
   nix develop
   ```
2. **Verify the upstream ArtBOT pin and Rox persona metadata:**
   ```bash
   PYTHONPATH=src:../artbot/src python3 -m rox_bot.cli upstream-status
   PYTHONPATH=src:../artbot/src python3 -m rox_bot.cli persona-info
   ```
3. **Configure local runtime credentials outside the repository** (`~/.hermes/profiles/rox-bot/.env`, `chmod 600`) using `config/env.example` as a template:
   - `GCP_PROJECT_ID="photography-otel-sandbox"`
   - `GCP_ACCESS_TOKEN="<oauth2-bearer-token>"` (or fetched dynamically from the GCE metadata server when running `--live` on a GCP VM)
   - `TEAMS_WEBHOOK_URL="https://<tenant>.<region>.environment.api.powerplatform.com/..."`
4. **Run a fleet compliance audit or remediation plan:**
   ```bash
   # Deterministic offline audit using representative fleet fixtures:
   PYTHONPATH=src:../artbot/src python3 -m rox_bot.cli fleet-audit

   # Live GCP API query against photography-otel-sandbox:
   PYTHONPATH=src:../artbot/src python3 -m rox_bot.cli fleet-audit --live --project photography-otel-sandbox
   ```

## 3. Interaction & Behavioral Invariants

1. **Mention-Only Channel Discipline:** When bridged to Microsoft Teams, `@rox-bot` only responds when explicitly mentioned in unquoted text and replies strictly in-thread (`replyToId` + `messageId`).
2. **Upstream ArtBOT Public Contract Lock:** Never import private submodules (`from artbot.<submodule> import ...`) or underscore-prefixed symbols from `artbot`. Only symbols listed in `UPSTREAM_ARTBOT.json` (`public_api_allowlist`) are permitted.
3. **Pure Dependency Injection:** `GcpOpsClient` (`src/rox_bot/gcp_ops.py`) uses `HttpTransport` from `artbot` so all Compute Engine, Cloud Monitoring, Cloud Logging, and OS Config API interactions are 100% deterministically testable offline via `tests/fakes.py` (`FakeHttpTransport`).
4. **Cross-Bot Escalation to Dov (`@dov-bot`):** Every `FleetAuditReport` maps VM compliance and saturation anomalies onto **Dov's 0–5 🐻 Bear Alarm Scale** and emits a serialized `PeerBlackboardHandoff` block (`schema="peer.blackboard.v1"`) when `max_dov_bear_alarm > 0`.

## 4. Engineering Standards (`STANDARDS.md`)

- **100% Line & Branch Coverage:** Enforced via `pytest -p randomly --cov=rox_bot --cov-branch --cov-report=term-missing --cov-fail-under=100`.
- **Zero `unittest.mock`:** Enforced by `no_unittest_mock_in_tests` in `checks/policy.star`. Use `FakeHttpTransport` in `tests/fakes.py`.
- **Strict Typing & Formatting:** `ruff format --check .`, `ruff check .`, and `mypy --strict src tests` must pass with zero warnings or errors.
- **No Secrets in Git:** Never commit `.env`, `.pem`, `.key`, OAuth bearer tokens, or live tenant Power Platform webhook URLs.

## 5. Verification (`just check`)

Before committing or pushing any change, run `just check` inside the Nix dev shell:

```bash
nix develop -c just check
```

This executes in strict sequence:
1. `ruff format --check .`
2. `ruff check .`
3. `mypy --strict src tests`
4. `shac test`
5. `shac check --all`
6. `pytest` (run 1, randomized)
7. `pytest` (run 2, randomized)
