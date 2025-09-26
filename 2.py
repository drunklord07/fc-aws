#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IAM policy scope analyzer (clean, from scratch).

Default:
- Customer-managed only (Scope="Local")
- Only attached policies
- Excludes policies used solely as permissions boundaries when including unattached (unless opted in)
Flags reported:
- Full admin (Allow + Action "*" or "*:*" + Resource "*")
- Service-wide admin on all resources (e.g., "s3:*" on "*")
- Broad via NotAction on all resources (Allow + NotAction + Resource "*")

Outputs:
- JSON: detailed results + summary
- CSV: managed policies summary
- CSV (inline): flagged inline policies (only with --include-inline)
"""

import argparse
import csv
import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union, Set

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

JsonDict = Dict[str, Any]


# ---------- Helpers ----------

def ensure_list(x: Any) -> List[Any]:
    return [] if x is None else (x if isinstance(x, list) else [x])


def decode_policy_document(maybe_encoded: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(maybe_encoded, dict):
        return maybe_encoded
    s = (maybe_encoded or "").strip()
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        pass
    try:
        return json.loads(urllib.parse.unquote(s))
    except Exception as e:
        raise ValueError("Unable to parse policy document: %s" % e)


def extract_service_prefix(action: str) -> Optional[str]:
    if not isinstance(action, str):
        return None
    a = action.lower()
    if a in ("*", "*:*"):
        return None
    if a.endswith(":*") and ":" in a:
        return a.split(":", 1)[0]
    return None


def analyze_policy_document(doc: Dict[str, Any]) -> Tuple[bool, List[str], bool, List[str]]:
    """
    Returns:
      full_admin, service_wide_services, broad_by_notaction, notaction_services
    """
    stmts = ensure_list(doc.get("Statement"))
    full_admin = False
    svc_wide: Set[str] = set()
    broad_na = False
    na_svcs: Set[str] = set()

    for st in stmts:
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        actions = [a for a in ensure_list(st.get("Action")) if isinstance(a, str)]
        not_actions = [a for a in ensure_list(st.get("NotAction")) if isinstance(a, str)]

        # Treat missing Resource as "*"
        res_list = ensure_list(st.get("Resource")) if "Resource" in st else ["*"]
        resource_all = any(r == "*" for r in res_list)

        if resource_all and any(a in ("*", "*:*") for a in actions):
            full_admin = True

        if resource_all:
            for a in actions:
                svc = extract_service_prefix(a)
                if svc:
                    svc_wide.add(svc)

        if resource_all and not_actions:
            broad_na = True
            for a in not_actions:
                svc = extract_service_prefix(a)
                if svc:
                    na_svcs.add(svc)

    return full_admin, sorted(svc_wide), broad_na, sorted(na_svcs)


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
    return decode_policy_document(resp["PolicyVersion"]["Document"])


# ---------- Scanners ----------

def scan_managed_policies(
    iam,
    include_aws_managed: bool,
    include_unattached: bool,
    include_boundaries: bool,
) -> List[Dict[str, Any]]:
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

        # Skip boundary-only policies when including unattached, unless opted in.
        if include_unattached and not include_boundaries:
            if attachment_count == 0 and pb_count > 0:
                continue

        analysis_error: Optional[str] = None
        try:
            doc = get_policy_default_doc(iam, arn, default_version_id)
        except (ClientError, BotoCoreError, ValueError) as e:
            doc = {}
            analysis_error = "get_policy_version error: %s" % e

        fa, svc_wide, broad_na, na_svcs = analyze_policy_document(doc) if doc else (False, [], False, [])

        try:
            users, groups, roles = list_entities_for_policy(iam, arn)
        except (ClientError, BotoCoreError) as e:
            users, groups, roles = [], [], []
            msg = "list_entities_for_policy error: %s" % e
            analysis_error = (analysis_error + " | " + msg) if analysis_error else msg

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
    flagged: List[Dict[str, Any]] = []

    # Users
    for u in paginate(iam, "list_users", "Users"):
        uname = u["UserName"]
        for pn in paginate(iam, "list_user_policies", "PolicyNames", UserName=uname):
            try:
                up = iam.get_user_policy(UserName=uname, PolicyName=pn)
                doc = decode_policy_document(up["PolicyDocument"])
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
                doc = decode_policy_document(rp["PolicyDocument"])
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
                doc = decode_policy_document(gp["PolicyDocument"])
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


# ---------- Output ----------

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


# ---------- CLI ----------

def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze IAM policies for overly broad access.")
    parser.add_argument("--profile", help="AWS profile name (optional)")
    parser.add_argument("--region", help="AWS region for client (IAM is global; optional)", default=None)
    parser.add_argument("--include-aws-managed", action="store_true", help="Include AWS-managed policies")
    parser.add_argument("--include-unattached", action="store_true", help="Include unattached managed policies")
    parser.add_argument("--include-boundaries", action="store_true", help="Include boundary-only policies")
    parser.add_argument("--include-inline", action="store_true", help="Scan inline identity policies")
    parser.add_argument("--out-json", default="iam_policy_scope.json", help="Output JSON path")
    parser.add_argument("--out-csv", default="iam_policy_scope.csv", help="Output CSV (managed) path")
    parser.add_argument("--out-inline-csv", default="iam_inline_scope.csv",
                        help="Output CSV (inline flagged) path")
    args = parser.parse_args()

    session_kwargs: Dict[str, Any] = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)

    config = Config(retries={"max_attempts": 10, "mode": "standard"})
    iam = session.client("iam", region_name=args.region, config=config)

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

    print("Done.")
    print("- JSON:", args.out_json)
    print("- CSV (managed):", args.out_csv)
    if args.include_inline:
        print("- CSV (inline flagged):", args.out_inline_csv)


if __name__ == "__main__":
    main()
