#!/usr/bin/env python
"""
Fortify SSC audit history -> ArmorCode finding tags.

Reads fortify-armorcode-app-mappings.json (same directory as this script) and, for each
enabled mapping, fetches Fortify issues (paginated, limit=200, embed=auditHistory),
maps Fortify issue id -> ArmorCode finding via toolId, and plans/applies tags:

  DeloitteSSC_<attributeName>: <newValue>

Environment (required — ask your lead for token values):
  FORTIFY_TOKEN        Fortify API token (value only, no "FortifyToken" prefix)
  ARMORCODE_API_KEY    ArmorCode API bearer token (value only, no "Bearer" prefix)
  FORTIFY_BASE_URL     optional, default TennCare SSC URL
  ARMORCODE_BASE_URL   optional, default https://app.armorcode.com

Examples (use python or python3 — whichever works on your server):
  python sync_fortify_audit_tags.py
  python sync_fortify_audit_tags.py --apply-tags
  python sync_fortify_audit_tags.py --only MATS-DAST --apply-tags
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

FORTIFY_PAGE_LIMIT = 200
TAG_PREFIX = "DeloitteSSC_"
DEFAULT_MAPPINGS_FILE = "fortify-armorcode-app-mappings.json"
SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def fortify_token() -> str:
    token = os.environ.get("FORTIFY_TOKEN", "").strip()
    if not token:
        sys.exit(
            "FORTIFY_TOKEN is not set. Ask your lead for the Fortify API token, then run:\n"
            "  export FORTIFY_TOKEN='your-token-here'"
        )
    return token


def armorcode_api_key() -> str:
    key = os.environ.get("ARMORCODE_API_KEY", "").strip()
    if not key:
        sys.exit(
            "ARMORCODE_API_KEY is not set. Ask your lead for the ArmorCode API token, then run:\n"
            "  export ARMORCODE_API_KEY='your-token-here'"
        )
    return key


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class HttpClient:
    def __init__(
        self,
        base_url: str,
        headers: dict[str, str],
        *,
        delay_s: float = 0.05,
        verify_ssl: bool = True,
        timeout: int = 120,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Accept": "application/json", **headers}
        self.delay_s = delay_s
        self.timeout = timeout
        self._ssl_ctx = None if verify_ssl else ssl._create_unverified_context()

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        json_body: bool = True,
    ) -> tuple[int, Any]:
        path = path if path.startswith("/") else f"/{path}"
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None}
            )
        headers = dict(self.headers)
        data: bytes | None = None
        if body is not None:
            headers.setdefault("Content-Type", "application/json")
            data = json.dumps(body).encode() if json_body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self._ssl_ctx
            ) as resp:
                status = resp.getcode()
                raw = resp.read().decode()
                parsed = json.loads(raw) if raw else {}
                return status, parsed
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"{method} {url} -> HTTP {exc.code}: {detail[:1200]}"
            ) from exc
        finally:
            if self.delay_s:
                time.sleep(self.delay_s)


class FortifyClient(HttpClient):
    def __init__(self, **kwargs: Any):
        base = os.environ.get(
            "FORTIFY_BASE_URL",
            "https://ssc.shd.tenncare.tn.gov:8443/ssc/api/v1",
        ).rstrip("/")
        super().__init__(
            base,
            {"Authorization": f"FortifyToken {fortify_token()}"},
            **kwargs,
        )

    def iter_issues(self, project_version_id: int) -> Iterator[dict[str, Any]]:
        start = 0
        while True:
            status, payload = self.request(
                "GET",
                f"/projectVersions/{project_version_id}/issues",
                query={
                    "start": start,
                    "limit": FORTIFY_PAGE_LIMIT,
                    "embed": "auditHistory",
                },
            )
            if status != 200:
                raise RuntimeError(f"Fortify issues returned HTTP {status}")
            batch = payload.get("data") or []
            if not batch:
                break
            for issue in batch:
                yield issue

            links = payload.get("links") or {}
            next_link = links.get("next") or {}
            href = next_link.get("href") if isinstance(next_link, dict) else None
            if href and "start=" in href:
                parsed = urllib.parse.urlparse(href)
                qs = urllib.parse.parse_qs(parsed.query)
                next_start = qs.get("start", [None])[0]
                if next_start is not None and int(next_start) != start:
                    start = int(next_start)
                    continue
            total = payload.get("count")
            start += len(batch)
            if len(batch) < FORTIFY_PAGE_LIMIT:
                break
            if total is not None and start >= int(total):
                break


class ArmorCodeClient(HttpClient):
    def __init__(self, **kwargs: Any):
        base = os.environ.get("ARMORCODE_BASE_URL", "https://app.armorcode.com").rstrip(
            "/"
        )
        super().__init__(
            base,
            {"Authorization": f"Bearer {armorcode_api_key()}"},
            **kwargs,
        )

    def iter_findings(
        self,
        filters: dict[str, list[Any]],
        *,
        page_size: int = 500,
        ignore_mitigated: bool = False,
    ) -> Iterator[dict[str, Any]]:
        after_key: int | None = None
        while True:
            query: dict[str, str] = {"size": str(page_size)}
            if after_key is not None and after_key != -1:
                query["afterKey"] = str(after_key)
            body = {
                "filters": filters,
                "maxSize": page_size,
                "ignoreMitigated": ignore_mitigated,
            }
            _, payload = self.request("POST", "/api/findings", query=query, body=body)
            block = payload.get("data") or {}
            findings = block.get("findings") or []
            for finding in findings:
                yield finding
            after_key = block.get("afterKey")
            if after_key in (-1, None) or not findings:
                break

    def bulk_update_tags(self, entries: list[dict[str, Any]]) -> str:
        status, payload = self.request(
            "POST", "/api/v2/findings/tags/bulk", body={"entries": entries}
        )
        if status not in (200, 202):
            raise RuntimeError(f"Bulk tag submit HTTP {status}: {payload}")
        data = payload.get("data") or payload
        job_id = (
            data.get("jobId")
            or data.get("referenceId")
            or payload.get("jobId")
            or payload.get("referenceId")
        )
        if not job_id:
            raise RuntimeError(f"No job id in bulk tag response: {payload}")
        return str(job_id)

    def poll_job(self, job_id: str, *, timeout_s: int = 600) -> dict[str, Any]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            _, payload = self.request("GET", f"/api/v2/jobs/{job_id}")
            data = payload.get("data") or payload
            status = (data.get("status") or "").upper()
            if status in ("COMPLETED", "SUCCESS"):
                return data
            if status in ("FAILED", "ERROR"):
                raise RuntimeError(f"Bulk tag job failed: {data}")
            time.sleep(5)
        raise RuntimeError(f"Bulk tag job {job_id} timed out after {timeout_s}s")


# ---------------------------------------------------------------------------
# Mappings file
# ---------------------------------------------------------------------------


@dataclass
class AppMapping:
    name: str
    fortify_project_version_id: int
    armorcode_product_id: int
    armorcode_sub_product_id: int | None
    enabled: bool = True

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> AppMapping:
        def pick(*keys: str) -> Any:
            for k in keys:
                if k in raw and raw[k] is not None:
                    return raw[k]
            return None

        name = str(pick("name") or raw.get("label") or "unnamed")
        enabled = raw.get("enabled", True)
        if isinstance(enabled, str):
            enabled = enabled.lower() not in ("false", "0", "no")

        fvid = pick("fortifyProjectVersionId", "fortify_project_version_id")
        pid = pick("armorcodeProductId", "armorcode_product_id")
        spid = pick("armorcodeSubProductId", "armorcode_sub_product_id")

        if pid is None:
            raise ValueError(f"Mapping {name!r} requires armorcodeProductId")
        if enabled and fvid is None:
            raise ValueError(
                f"Mapping {name!r} requires fortifyProjectVersionId when enabled"
            )
        return AppMapping(
            name=name,
            fortify_project_version_id=int(fvid) if fvid is not None else 0,
            armorcode_product_id=int(pid),
            armorcode_sub_product_id=int(spid) if spid is not None else None,
            enabled=bool(enabled),
        )


def load_mappings(path: Path) -> list[AppMapping]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("mappings") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ValueError(f"{path}: expected 'mappings' array")
    out: list[AppMapping] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path}: mappings[{i}] must be an object")
        out.append(AppMapping.from_dict(row))
    return out


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


@dataclass
class IssueSyncRow:
    mapping_name: str
    fortify_issue_id: int
    issue_name: str
    tags: list[str] = field(default_factory=list)
    armorcode_finding_id: int | None = None
    armorcode_status: str | None = None
    skip_reason: str | None = None


def audit_history(issue: dict[str, Any]) -> list[dict[str, Any]]:
    embed = issue.get("_embed") or {}
    return list(embed.get("auditHistory") or [])


def tags_from_issue(issue: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    tags: list[str] = []
    for row in audit_history(issue):
        attr = (row.get("attributeName") or "").strip()
        val = (row.get("newValue") or "").strip()
        if not attr or not val:
            continue
        literal = f"{TAG_PREFIX}{attr}: {val}"
        if literal not in seen:
            seen.add(literal)
            tags.append(literal)
    return tags


def build_tool_index(
    ac: ArmorCodeClient,
    mapping: AppMapping,
    *,
    ignore_mitigated: bool,
) -> dict[str, dict[str, Any]]:
    filters: dict[str, list[Any]] = {
        "source": ["Fortify"],
        "product": [mapping.armorcode_product_id],
    }
    if mapping.armorcode_sub_product_id is not None:
        filters["subProduct"] = [mapping.armorcode_sub_product_id]

    index: dict[str, dict[str, Any]] = {}
    total = 0
    for finding in ac.iter_findings(filters, ignore_mitigated=ignore_mitigated):
        total += 1
        tool_id = finding.get("toolId")
        if tool_id is None:
            continue
        key = str(tool_id).strip()
        if key not in index:
            index[key] = finding
    print(
        f"  ArmorCode index [{mapping.name}]: {len(index)} toolIds "
        f"from {total} findings",
        file=sys.stderr,
    )
    return index


def process_mapping(
    mapping: AppMapping,
    *,
    fortify: FortifyClient,
    ac: ArmorCodeClient,
    ignore_mitigated: bool,
) -> list[IssueSyncRow]:
    rows: list[IssueSyncRow] = []
    examined = 0
    for issue in fortify.iter_issues(mapping.fortify_project_version_id):
        examined += 1
        tags = tags_from_issue(issue)
        rows.append(
            IssueSyncRow(
                mapping_name=mapping.name,
                fortify_issue_id=int(issue["id"]),
                issue_name=str(issue.get("issueName") or ""),
                tags=tags,
            )
        )
        if examined % 200 == 0:
            print(f"  Fortify [{mapping.name}]: {examined} issues...", file=sys.stderr)
    print(
        f"  Fortify [{mapping.name}]: {examined} issues, "
        f"{sum(1 for r in rows if r.tags)} with tags",
        file=sys.stderr,
    )

    tool_index = build_tool_index(ac, mapping, ignore_mitigated=ignore_mitigated)
    for row in rows:
        ac_finding = tool_index.get(str(row.fortify_issue_id))
        if not ac_finding:
            row.skip_reason = "no_armorcode_finding_for_toolId"
            continue
        row.armorcode_finding_id = int(ac_finding["id"])
        row.armorcode_status = ac_finding.get("status")
        if not row.tags:
            row.skip_reason = "no_audit_tags"
    return rows


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def row_to_dict(row: IssueSyncRow) -> dict[str, Any]:
    return {
        "mapping": row.mapping_name,
        "fortifyIssueId": row.fortify_issue_id,
        "issueName": row.issue_name,
        "tags": row.tags,
        "armorcodeFindingId": row.armorcode_finding_id,
        "armorcodeStatus": row.armorcode_status,
        "skipReason": row.skip_reason,
    }


def write_summary_csv(path: Path, rows: list[IssueSyncRow]) -> None:
    fields = [
        "mapping",
        "fortifyIssueId",
        "armorcodeFindingId",
        "tagCount",
        "tags",
        "skipReason",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(
                {
                    "mapping": row.mapping_name,
                    "fortifyIssueId": row.fortify_issue_id,
                    "armorcodeFindingId": row.armorcode_finding_id or "",
                    "tagCount": len(row.tags),
                    "tags": " | ".join(row.tags),
                    "skipReason": row.skip_reason or "",
                }
            )


def apply_bulk_tags(
    ac: ArmorCodeClient,
    rows: list[IssueSyncRow],
    *,
    chunk_size: int = 500,
    job_log: list[str],
) -> None:
    entries: list[dict[str, Any]] = []
    for row in rows:
        if not row.armorcode_finding_id or not row.tags or row.skip_reason:
            continue
        entries.append(
            {"findingId": row.armorcode_finding_id, "tags": row.tags}
        )
    if not entries:
        print("  No tag entries to apply.", file=sys.stderr)
        return

    for i in range(0, len(entries), chunk_size):
        chunk = entries[i : i + chunk_size]
        job_id = ac.bulk_update_tags(chunk)
        print(f"  Submitted bulk job {job_id} ({len(chunk)} findings)...", file=sys.stderr)
        result = ac.poll_job(job_id)
        line = f"jobId={job_id} status={result.get('status')} findings={len(chunk)}"
        job_log.append(line)
        print(f"  {line}", file=sys.stderr)


def sanitize_dir_name(name: str) -> str:
    return re.sub(r"[^\w\-.]+", "_", name).strip("_") or "mapping"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync Fortify auditHistory tags to ArmorCode via mappings JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--mappings-file",
        default=str(SCRIPT_DIR / DEFAULT_MAPPINGS_FILE),
        help=f"Path to mappings JSON (default: ./{DEFAULT_MAPPINGS_FILE})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(SCRIPT_DIR / "output"),
        help="Output root directory",
    )
    parser.add_argument(
        "--only",
        action="append",
        metavar="NAME",
        help="Run only mapping(s) with this name (repeatable)",
    )
    parser.add_argument(
        "--apply-tags",
        action="store_true",
        help="Push tags to ArmorCode (default: dry-run, files only)",
    )
    parser.add_argument(
        "--ignore-mitigated",
        action="store_true",
        help="Exclude mitigated findings from ArmorCode index",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable Fortify TLS verify")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between HTTP calls")
    args = parser.parse_args()

    mappings_path = Path(args.mappings_file)
    if not mappings_path.is_file():
        sys.exit(f"Mappings file not found: {mappings_path}")

    all_mappings = load_mappings(mappings_path)
    only = {n.strip() for n in (args.only or []) if n.strip()}
    selected: list[AppMapping] = []
    for m in all_mappings:
        if only and m.name not in only:
            continue
        if not m.enabled:
            print(f"Skipping disabled mapping: {m.name}", file=sys.stderr)
            continue
        selected.append(m)

    if not selected:
        sys.exit("No enabled mappings to run. Edit fortify-armorcode-app-mappings.json.")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(args.output_dir) / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    fortify = FortifyClient(verify_ssl=not args.insecure, delay_s=args.delay)
    ac = ArmorCodeClient(delay_s=args.delay)

    run_manifest: dict[str, Any] = {
        "startedAt": ts,
        "mappingsFile": str(mappings_path.resolve()),
        "applyTags": args.apply_tags,
        "mappings": [],
    }
    job_log: list[str] = []
    all_rows: list[IssueSyncRow] = []

    for mapping in selected:
        print(f"\n=== {mapping.name} ===", file=sys.stderr)
        print(
            f"  Fortify version {mapping.fortify_project_version_id} -> "
            f"ArmorCode product {mapping.armorcode_product_id}"
            + (
                f" / sub-product {mapping.armorcode_sub_product_id}"
                if mapping.armorcode_sub_product_id
                else ""
            ),
            file=sys.stderr,
        )
        mdir = run_dir / sanitize_dir_name(mapping.name)
        mdir.mkdir(parents=True, exist_ok=True)

        try:
            rows = process_mapping(
                mapping,
                fortify=fortify,
                ac=ac,
                ignore_mitigated=args.ignore_mitigated,
            )
        except Exception as exc:
            print(f"  FAILED: {exc}", file=sys.stderr)
            run_manifest["mappings"].append(
                {"name": mapping.name, "error": str(exc)}
            )
            continue

        all_rows.extend(rows)
        mapped = [r for r in rows if r.armorcode_finding_id and r.tags]
        unmapped = [r for r in rows if r.skip_reason == "no_armorcode_finding_for_toolId"]
        no_tags = [r for r in rows if r.skip_reason == "no_audit_tags"]

        write_jsonl(mdir / "fortify_issues_scanned.jsonl", [row_to_dict(r) for r in rows])
        write_jsonl(
            mdir / "tags_planned.jsonl",
            [row_to_dict(r) for r in mapped],
        )
        write_jsonl(mdir / "unmapped.jsonl", [row_to_dict(r) for r in unmapped])
        write_summary_csv(mdir / "summary.csv", rows)

        m_manifest = {
            "name": mapping.name,
            "fortifyProjectVersionId": mapping.fortify_project_version_id,
            "armorcodeProductId": mapping.armorcode_product_id,
            "armorcodeSubProductId": mapping.armorcode_sub_product_id,
            "fortifyIssues": len(rows),
            "withTags": sum(1 for r in rows if r.tags),
            "mapped": len(mapped),
            "unmapped": len(unmapped),
            "noAuditTags": len(no_tags),
        }
        (mdir / "manifest.json").write_text(
            json.dumps(m_manifest, indent=2), encoding="utf-8"
        )
        run_manifest["mappings"].append(m_manifest)

        if args.apply_tags and mapped:
            apply_bulk_tags(ac, mapped, job_log=job_log)

    (run_dir / "manifest.json").write_text(
        json.dumps(run_manifest, indent=2), encoding="utf-8"
    )
    if job_log:
        (run_dir / "bulk_job_log.txt").write_text("\n".join(job_log) + "\n", encoding="utf-8")

    print(f"\nDone. Output: {run_dir}", file=sys.stderr)
    print(f"  Total issue rows: {len(all_rows)}", file=sys.stderr)
    if not args.apply_tags:
        print("  Dry run — re-run with --apply-tags to push to ArmorCode.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
