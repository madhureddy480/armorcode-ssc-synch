#!/usr/bin/env python3
"""
DEPRECATED for Fortify-direct workflows — use sync_fortify_report_introduced.py instead.

Find ArmorCode findings whose Fortify audit trail includes a comment like
"Changed Report Introduced To ..." (ArmorCode comments API path).

OpenAPI notes:
  - GET /user/findings/{id} does NOT return Fortify tool comments.
  - POST /api/findings with fetchComments:true returns ArmorCode collaboration
    comments only (not Fortify SSC audit messages).
  - Fortify comments are exposed via (undocumented in openapi.json but works
    with API bearer token on app.armorcode.com):

    GET /user/tools/generic/FORTIFY/comments
        ?findingId={armorcodeFindingId}
        &id={fortifyVulnId}
        &productId={productId}
        &subProductId={subProductId}
        &environment={envName}

Usage:
  export ARMORCODE_API_KEY='your-bearer-token'
  python3 find_fortify_report_comments.py --product-id 772747
  python3 find_fortify_report_comments.py --finding-id 8520461759  # single finding
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator

BASE_URL = os.environ.get("ARMORCODE_BASE_URL", "https://app.armorcode.com")
DEFAULT_SEARCH = "Changed Report Introduced To"
DEFAULT_TAG_KEY = "changedReport"


def load_api_key() -> str:
    key = os.environ.get("ARMORCODE_API_KEY", "").strip()
    if key:
        return key
    key_file = os.path.join(os.path.dirname(__file__), "apikey.txt")
    if os.path.isfile(key_file):
        with open(key_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "Bearer " in line:
                    return line.split("Bearer ", 1)[1].strip().strip("'\"")
    sys.exit("Set ARMORCODE_API_KEY or put 'Bearer <token>' in apikey.txt")


class ArmorCodeClient:
    def __init__(self, api_key: str, base_url: str = BASE_URL, delay_s: float = 0.05):
        self.base_url = base_url.rstrip("/")
        self.delay_s = delay_s
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int = 120,
    ) -> Any:
        url = self.base_url + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()
            raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {detail[:500]}") from exc
        finally:
            if self.delay_s:
                time.sleep(self.delay_s)

    def get_finding(self, finding_id: int) -> dict[str, Any]:
        return self._request("GET", f"/user/findings/{finding_id}")

    def iter_findings(
        self,
        filters: dict[str, list[Any]],
        *,
        page_size: int = 500,
        ignore_mitigated: bool = False,
    ) -> Iterator[dict[str, Any]]:
        after_key: int | None = None
        while True:
            query = urllib.parse.urlencode({"size": page_size})
            if after_key is not None and after_key != -1:
                query += "&" + urllib.parse.urlencode({"afterKey": after_key})
            body = {
                "filters": filters,
                "maxSize": page_size,
                "ignoreMitigated": ignore_mitigated,
            }
            payload = self._request("POST", f"/api/findings?{query}", body)
            block = payload.get("data") or {}
            for finding in block.get("findings") or []:
                yield finding
            after_key = block.get("afterKey")
            if after_key in (-1, None) or not block.get("findings"):
                break

    def get_fortify_comments(
        self,
        *,
        finding_id: int,
        fortify_vuln_id: str,
        product_id: int,
        sub_product_id: int,
        environment: str,
    ) -> list[dict[str, Any]]:
        params = urllib.parse.urlencode(
            {
                "findingId": finding_id,
                "id": fortify_vuln_id,
                "productId": product_id,
                "subProductId": sub_product_id,
                "environment": environment,
            }
        )
        payload = self._request(
            "GET",
            f"/user/tools/generic/FORTIFY/comments?{params}",
            timeout=180,
        )
        if isinstance(payload, dict) and "content" in payload:
            return payload.get("content") or []
        if isinstance(payload, list):
            return payload
        return []

    def update_finding_tags(self, finding_ids: list[int], finding_tags: list[str], notes: str = "") -> Any:
        body: dict[str, Any] = {
            "findingIds": [str(fid) for fid in finding_ids],
            "findingTags": finding_tags,
        }
        if notes:
            body["notes"] = notes
        return self._request("PUT", "/user/findings/findingTags", body, timeout=180)


def fortify_params_from_finding(finding: dict[str, Any]) -> dict[str, Any] | None:
    tool = (finding.get("toolName") or "").lower()
    if tool != "fortify":
        return None
    product = finding.get("product") or {}
    sub = finding.get("subProduct") or {}
    env = finding.get("envName") or finding.get("environment")
    vuln_id = finding.get("toolId")
    if not all([finding.get("id"), vuln_id, product.get("id"), sub.get("id"), env]):
        return None
    return {
        "finding_id": int(finding["id"]),
        "fortify_vuln_id": str(vuln_id),
        "product_id": int(product["id"]),
        "sub_product_id": int(sub["id"]),
        "environment": str(env),
    }


def message_matches(message: str, needle: str) -> bool:
    return needle.lower() in (message or "").lower()


def extract_changed_report_value(message: str) -> str:
    m = re.search(r"Changed Report Introduced To\s*'([^']+)'", message, flags=re.IGNORECASE)
    if m:
        return f"Changed Report Introduced To '{m.group(1)}'"
    # Fallback to whole message if quote style is different.
    return message.strip()


def scan_finding(
    client: ArmorCodeClient,
    finding: dict[str, Any],
    needle: str,
) -> list[dict[str, Any]]:
    params = fortify_params_from_finding(finding)
    if not params:
        return []
    comments = client.get_fortify_comments(**params)
    hits = []
    for comment in comments:
        msg = comment.get("message") or ""
        if message_matches(msg, needle):
            changed_report = extract_changed_report_value(msg)
            hits.append(
                {
                    "findingId": params["finding_id"],
                    "title": finding.get("title"),
                    "status": finding.get("status"),
                    "severity": finding.get("severity"),
                    "message": msg,
                    "changedReport": changed_report,
                    "createdBy": comment.get("createdBy"),
                    "createdAt": comment.get("createdAt"),
                }
            )
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--search",
        default=DEFAULT_SEARCH,
        help=f"Substring to match in Fortify comment message (default: {DEFAULT_SEARCH!r})",
    )
    parser.add_argument("--product-id", type=int, help="ArmorCode product id filter")
    parser.add_argument("--sub-product-id", type=int, help="ArmorCode sub-product id filter")
    parser.add_argument("--finding-id", type=int, help="Scan only one finding (fast check)")
    parser.add_argument("--max-findings", type=int, default=0, help="Stop after N findings (0=all)")
    parser.add_argument("--ignore-mitigated", action="store_true", help="Skip mitigated in list API")
    parser.add_argument("--output", default="fortify_report_comment_hits.jsonl")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between API calls (seconds)")
    parser.add_argument("--apply-tags", action="store_true", help="Apply tags to matching findings")
    parser.add_argument("--tag-key", default=DEFAULT_TAG_KEY, help=f"Tag key to write (default: {DEFAULT_TAG_KEY})")
    parser.add_argument(
        "--notes",
        default="Automated sync from Fortify comments: Changed Report Introduced To",
        help="Optional notes sent with the tag update request",
    )
    args = parser.parse_args()

    client = ArmorCodeClient(load_api_key(), delay_s=args.delay)
    filters: dict[str, list[Any]] = {"toolSource": ["Fortify"]}
    if args.product_id:
        filters["product"] = [args.product_id]
    if args.sub_product_id:
        filters["subProduct"] = [args.sub_product_id]

    matches: list[dict[str, Any]] = []
    examined = 0

    if args.finding_id:
        finding = client.get_finding(args.finding_id)
        findings_iter = [finding]
    else:
        findings_iter = client.iter_findings(
            filters,
            ignore_mitigated=args.ignore_mitigated,
        )

    with open(args.output, "w", encoding="utf-8") as out:
        for finding in findings_iter:
            examined += 1
            hits = scan_finding(client, finding, args.search)
            for hit in hits:
                matches.append(hit)
                out.write(json.dumps(hit) + "\n")
                print(
                    f"MATCH findingId={hit['findingId']} status={hit.get('status')} "
                    f"message={hit['message'][:80]!r}..."
                )
            if examined % 50 == 0:
                print(f"... scanned {examined} findings, {len(matches)} matches so far", file=sys.stderr)
            if args.max_findings and examined >= args.max_findings:
                break

    # Group matching findings by extracted value, so each batch applies one homogeneous tag.
    grouped: dict[str, list[int]] = {}
    for m in matches:
        tag_value = m.get("changedReport") or m.get("message") or ""
        tag_literal = f"{args.tag_key}: {tag_value}"
        grouped.setdefault(tag_literal, []).append(int(m["findingId"]))

    if args.apply_tags and grouped:
        print(f"\nApplying tags to {sum(len(v) for v in grouped.values())} findings...")
        for tag_literal, finding_ids in grouped.items():
            # Keep requests moderate in size.
            chunk_size = 200
            for i in range(0, len(finding_ids), chunk_size):
                chunk = finding_ids[i : i + chunk_size]
                client.update_finding_tags(chunk, [tag_literal], notes=args.notes)
                print(f"  updated {len(chunk)} findings with tag {tag_literal!r}")
    elif grouped:
        print("\nDry run (no updates). Use --apply-tags to push tags:")
        for tag_literal, finding_ids in grouped.items():
            print(f"  would apply {tag_literal!r} to {len(finding_ids)} findings")

    print(f"\nDone. Examined {examined} findings, {len(matches)} matches written to {args.output}")


if __name__ == "__main__":
    main()
