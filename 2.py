#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IAM policy scope analyzer — from scratch (clean indentation, no emoji).

Default behavior:
- Customer-managed only (Scope="Local")
- Only attached policies
- Excludes policies used solely as permissions boundaries
- Flags:
  * Full admin: Allow + Action "*" or "*:*" + Resource "*"
  * Service-wide admin on all resources: e.g., "s3:*" on "*"
- Reports where each managed policy is attached (users/groups/roles)
- Optional: include inline identity policies (users, roles, groups)

Outputs:
- JSON report (detailed)
- CSV report (managed summary)
"""

import argparse
import csv
import json
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union, Set

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError


JsonDict = Dict[str, Any]


# ---------------------------
# Helpers
# ---------------------------

def _ensure_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _decode_policy_document(maybe_encoded: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Accept dict JSON or (possibly URL-encoded) JSON string; return dict.
    """
    if isinstance(maybe_encoded, dict):
        return maybe_encoded

    s = (maybe_encoded or "").strip()
    if not s:
        return {}

    # Try raw JSON first
    try:
        return json.loads(s)
    except Exception:
        pass

    # Fallback: URL-decoded JSON
    try:
        decoded = urllib.parse.unquote(s)
        return json.loads(decoded)
    except Exception as e:
        raise ValueError("Unable to parse policy document: %s" % e) from e


def _extract_service_prefix(action: str) -> Optional[str]:
    """
    If action is like 'service:*', return 'service' (lowercased). Else None.
    """
    if not isinstance(action, str):
        return None
    a = action.lower()
    if a == "*" or a == "*:*":
        return None
    if a.endswith(":*") and ":" in a:
        return a.split(":", 1)[0]
    return None


def analyze_policy_document(doc: Dict[str, Any]) -> Tuple[bool, List[str], bool, List[str]]:
    """
    Analyze a policy document and return:
      - full_admin: bool
      - service_wide_on_all_resources: List[str] of services with 'service:*' on Resource "*"
      - broad_by_notaction: bool  (Allow + NotAction + Resource "*")
      - notaction_services: List[str]  (best-effort service tokens inside NotAction)
    Notes:
      - If Resource is omitted, treat as "*".
      - We ignore NotAction for "full admin" calculation, but surface it separately.
    """
    stmts = _ensure_list(doc.get("Statement"))
    full_admin = False
    svc_wide: Set[str] = set()
    broad_notaction = False
    notaction_svcs: Set[str] = set()

    for st in stmts:
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        actions = [a for a in _ensure_list(st.get("Action")) if isinstance(a, str)]
        not_actions = [a for a in _ensure_list(st.get("NotAction")) if isinstance(a, str)]

        # Treat missing Resource as "*"
        if "Resource" in st:
            resources = [r for r in _ensure_list(st.get("Resource")) if isinstance(r, str)]
        else:
            resources = ["*"]

        resource_all = any(r == "*" for r in resources)

        # Full admin: Action wildcard + Resource "*"
        if resource_all and any(a in ("*", "*:*") for a in actions):
            full_admin = True

        # Service-wide: e.g., "s3:*" with Resource "*"
        if resource_all:
            for a in actions:
                svc = _extract_service_prefix(a)
                if svc:
                    svc_wide.add(svc)

        # Broad by NotAction (Allow + NotAction + Resource "*")
        if resource_all and not_actions:
            broad_notaction = True
            for a in not_actions:
                svc = _extract_service_prefix(a)
                if svc:
                    notaction_svcs.add(svc)

    return full_admin, sorted(svc_wide), broad_notaction, sorted(notaction_svcs)


def paginate(client, op_name: str, result_key: str, **kwargs):
    paginator = client.get_paginator(op_name)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def list_entities_for_policy(iam, policy_arn: str) -> Tuple[List[str], List[str], List[str]]:
    users: List[str] = []
    groups: List[str] = []
    roles: List[str] = []

    paginator = iam.get_paginator("list_entities_for_policy")
    for page in paginator.paginate(PolicyArn=policy_arn):
        users.extend([u.get("UserName") for u in page.get("PolicyUsers", []) if "UserName" in u])
        groups.extend([g.get("GroupName") for g in page.get("PolicyGroups", []) if "GroupName" in g])
        roles.extend([r.get("RoleName") for r in page.get("PolicyRoles", []) if "RoleName" in r])

    return users, groups, roles


def get_policy_default_doc(iam, arn: str, version_id: str) -> Dict[str, Any]:
    resp = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
    raw = resp["PolicyVersion"]["Document"]
    return _decode_policy_document(raw)


# ---------------------------
# Scanners
# ---------------------------

def scan_managed_policies(
    iam,
    include_aws_managed: bool,
    include_unattached: bool,
    include_boundaries: bool,
) -> List[Dict[str, Any]]:
    """
    Scan managed policies based on filters; analyze and return structured results.
    - Scope: Local (default) or All if include_aws_managed
    - OnlyAttached: True unless include_unattached
    - We do NOT set PolicyUsageFilter to avoid suppressing unattached.
      Instead, if include_unattached and not include_boundaries, we skip
      policies where AttachmentCount==0 and PermissionsBoundaryUsageCount>0
      (i.e., used solely as permissions boundaries).
    """
    list_kwargs = {
        "Scope": "All" if include_aws_managed else "Local",
        "OnlyAttached": not include_unattached,
    }

    results: List[Dict[str, Any]] = []

    for pol in paginate(iam, "list_policies", "Policies", **list_kwargs):
        arn = pol["Arn"]
        name = pol["PolicyName"]
        default_version_id = pol.get("DefaultVersionId")
        attachment_count = pol.get("AttachmentCount", 0)
        pb_count = pol.get("PermissionsBoundaryUsageCount", 0)
        is_attachable = pol.get("IsAttachable", True)

        if include_unattached and not include_boundaries:
            if attachment_count == 0 and pb_count > 0:
                # skip boundary-only policies when requesting unattached set
                continue

        analysis_error: Optional[str] = None

        # Fetch policy document
        try:
            doc = get_policy_default_doc(iam, arn, default_version_id)
        except (ClientError, BotoCoreError, ValueError) as e:
            doc = {}
            analysis_error = "get_policy_version error: %s" % e

        fa, svc_wide, broad_na, na_svcs = analyze_policy_document(doc) if doc else (False, [], False, [])

        # Attachment details
        try:
            users, groups, roles = list_entities_for_policy(iam, arn)
        except (ClientError, BotoCoreError) as e:
            users, groups, roles = [], [], []
            msg = "list_entities_for_policy error: %s" % e
            analysis_error = ("%s | %s" % (analysis_error, msg)) if analysis_error else msg

        results.append({
            "Type": "Managed",
            "PolicyArn": arn,
            "PolicyName": name,
            "DefaultVersionId": default_version_id,
            "AttachmentCount": attachment_count,
            "PermissionsBoundaryUsageCount": pb_count,
            "IsAttachable": is_attachable,
            "FullAdmin": fa,
            "ServiceWideOnAllResources": svc_wide,
            "BroadByNotActionOnAllResources": broad_na,
            "NotActionServices": na_svcs,
            "AttachedUsers": users,
            "AttachedGroups": groups,
            "AttachedRoles": roles,
            "AnalysisError": analysis_error,
        })

    return results


def scan_inline_policies(iam) -> List[Dict[str, Any]]:
    """
    Scan inline identity policies (users, roles, groups).
    Return only those flagged as broad (full admin or service-wide or broad by NotAction).
    """
    flagged: List[Dict[str, Any]] = []

    # Users
    for u in paginate(iam, "list_users", "Users"):
        uname = u["UserName"]
        for pn in paginate(iam, "list_user_policies", "PolicyNames", UserName=uname):
            try:
                up = iam.get_user_policy(UserName=uname, PolicyName=pn)
                doc = _decode_policy_document(up["PolicyDocument"])
                fa, svc_wide, broad_na, na_svcs = analyze_policy_document(doc)
                if fa or svc_wide or broad_na:
                    flagged.append({
                        "Type": "Inline",
                        "IdentityType": "User",
                        "IdentityName": uname,
                        "PolicyName": pn,
                        "FullAdmin": fa,
                        "ServiceWideOnAllResources": svc_wide,
                        "BroadByNotActionOnAllResources": broad_na,
                        "NotActionServices": na_svcs,
                        "AnalysisError": None,
                    })
            except Exception as e:
                flagged.append({
                    "Type": "Inline",
                    "IdentityType": "User",
                    "IdentityName": uname,
                    "PolicyName": pn,
                    "FullAdmin": False,
                    "ServiceWideOnAllResources": [],
                    "BroadByNotActionOnAllResources": False,
                    "NotActionServices": [],
                    "AnalysisError": "get_user_policy error: %s" % e,
                })

    # Roles
    for r in paginate(iam, "list_roles", "Roles"):
        rname = r["RoleName"]
        for pn in paginate(iam, "list_role_policies", "PolicyNames", RoleName=rname):
            try:
                rp = iam.get_role_policy(RoleName=rname, PolicyName=pn)
                doc = _decode_policy_document(rp["PolicyDocument"])
                fa, svc_wide, broad_na, na_svcs = analyze_policy_document(doc)
                if fa or svc_wide or broad_na:
                    flagged.append({
                        "Type": "Inline",
                        "IdentityType": "Role",
                        "IdentityName": rname,
                        "PolicyName": pn,
                        "FullAdmin": fa,
                        "ServiceWideOnAllResources": svc_wide,
                        "BroadByNotActionOnAllResources": broad_na,
                        "NotActionServices": na_svcs,
                        "AnalysisError": None,
                    })
            except Exception as e:
                flagged.append({
                    "Type": "Inline",
                    "IdentityType": "Role",
                    "IdentityName": rname,
                    "PolicyName": pn,
                    "FullAdmin": False,
                    "ServiceWideOnAllResources": [],
                    "BroadByNotActionOnAllResources": False,
                    "NotActionServices": [],
                    "AnalysisError": "get_role_policy error: %s" % e,
                })

    # Groups
    for g in paginate(iam, "list_groups", "Groups"):
        gname = g["GroupName"]
        for pn in paginate(iam, "list_group_policies", "PolicyNames", GroupName=gname):
            try:
                gp = iam.get_group_policy(GroupName=gname, PolicyName=pn)
                doc = _decode_policy_document(gp["PolicyDocument"])
                fa, svc_wide, broad_na, na_svcs = analyze_policy_document(doc)
                if fa or svc_wide or broad_na:
                    flagged.append({
                        "Type": "Inline",
                        "IdentityType": "Group",
                        "IdentityName": gname,
                        "PolicyName": pn,
                        "FullAdmin": fa,
                        "ServiceWideOnAllResources": svc_wide,
                        "BroadByNotActionOnAllResources": broad_na,
                        "NotActionServices": na_svcs,
                        "AnalysisError": None,
                    })
            except Exception as e:
                flagged.append({
                    "Type": "Inline",
                    "IdentityType": "Group",
                    "IdentityName": gname,
                    "PolicyName": pn,
                    "FullAdmin": False,
                    "ServiceWideOnAllResources": [],
                    "BroadByNotActionOnAllResources": False,
                    "NotActionServices": [],
                    "AnalysisError": "get_group_policy error: %s" % e,
                })

    return flagged


# ---------------------------
# Output
# ---------------------------

def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)


def write_csv_managed(path: str, records: List[Dict[str, Any]]) -> None:
    headers = [
        "PolicyType",
        "PolicyArn",
        "PolicyName",
        "DefaultVersionId",
        "AttachmentCount",
        "PermissionsBoundaryUsageCount",
        "FullAdmin",
        "ServiceWideOnAllResources",
        "BroadByNotActionOnAllResources",
        "NotActionServices",
        "AttachedUsers",
        "AttachedGroups",
        "AttachedRoles",
        "AnalysisError",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in records:
            w.writerow([
                r.get("Type", "Managed"),
                r.get("PolicyArn"),
                r.get("PolicyName"),
                r.get("DefaultVersionId"),
                r.get("AttachmentCount"),
                r.get("PermissionsBoundaryUsageCount", 0),
                r.get("FullAdmin"),
                ";".join(r.get("ServiceWideOnAllResources", [])),
                r.get("BroadByNotActionOnAllResources", False),
                ";".join(r.get("NotActionServices", [])),
                ";".join(r.get("AttachedUsers", [])),
                ";".join(r.get("AttachedGroups", [])),
                ";".join(r.get("AttachedRoles", [])),
                r.get("AnalysisError") or "",
            ])


def write_csv_inline(path: str, records: List[Dict[str, Any]]) -> None:
    headers = [
        "PolicyType",
        "IdentityType",
        "IdentityName",
        "PolicyName",
        "FullAdmin",
        "ServiceWideOnAllResources",
        "BroadByNotActionOnAllResources",
        "NotActionServices",
        "AnalysisError",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in records:
            w.writerow([
                r.get("Type", "Inline"),
                r.get("IdentityType"),
                r.get("IdentityName"),
                r.get("PolicyName"),
                r.get("FullAdmin"),
                ";".join(r.get("ServiceWideOnAllResources", [])),
                r.get("BroadByNotActionOnAllResources", False),
                ";".join(r.get("NotActionServices", [])),
                r.get("AnalysisError") or "",
            ])


# ---------------------------
# CLI
# ---------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze IAM policies for overly broad access."
    )
    parser.add_argument("--profile", help="AWS profile name (optional)")
    parser.add_argument("--region", help="AWS region for client (IAM is global; optional)", default=None)

    parser.add_argument("--include-aws-managed", action="store_true",
                        help="Include AWS-managed policies in addition to customer-managed")
    parser.add_argument("--include-unattached", action="store_true",
                        help="Include unattached managed policies")
    parser.add_argument("--include-boundaries", action="store_true",
                        help="Include policies used as permissions boundaries")

    parser.add_argument("--include-inline", action="store_true",
                        help="Scan inline identity policies (users/roles/groups)")

    parser.add_argument("--out-json", default="iam_policy_scope.json", help="Output JSON file")
    parser.add_argument("--out-csv", default="iam_policy_scope.csv", help="Output CSV for managed policies")
    parser.add_argument("--out-inline-csv", default="iam_inline_scope.csv",
                        help="Output CSV for flagged inline policies (only if --include-inline)")

    args = parser.parse_args()

    session_kwargs: Dict[str, Any] = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)

    config = Config(retries={"max_attempts": 10, "mode": "standard"})
    iam = session.client("iam", region_name=args.region, config=config)

    started = time.time()

    managed = scan_managed_policies(
        iam=iam,
        include_aws_managed=args.include_aws_managed,
        include_unattached=args.include_unattached,
        include_boundaries=args.include_boundaries,
    )

    inline_flagged: List[Dict[str, Any]] = []
    if args.include_inline:
        inline_flagged = scan_inline_policies(iam)

    payload = {
        "ManagedPolicies": managed,
        "InlinePoliciesFlagged": inline_flagged,
        "Summary": {
            "ManagedPoliciesTotal": len(managed),
            "ManagedFullAdmin": sum(1 for r in managed if r.get("FullAdmin")),
            "ManagedServiceWideHits": sum(1 for r in managed if r.get("ServiceWideOnAllResources")),
            "ManagedBroadByNotAction": sum(1 for r in managed if r.get("BroadByNotActionOnAllResources")),
            "InlineFlaggedTotal": len(inline_flagged),
            "GeneratedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    write_json(args.out_json, payload)
    write_csv_managed(args.out_csv, managed)
    if args.include_inline:
        write_csv_inline(args.out_inline_csv, inline_flagged)

    elapsed = time.time() - started
    print("Done in %.1fs" % elapsed)
    print("- JSON:", args.out_json)
    print("- CSV (managed):", args.out_csv)
    if args.include_inline:
        print("- CSV (inline flagged):", args.out_inline_csv)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
