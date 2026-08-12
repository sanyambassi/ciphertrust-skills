"""Transparent Encryption (CTE) checks."""
from __future__ import annotations

from cm_client import CmClient

from ..context import ReportCtx
from ..util import safe_get

def check_cte(ctx: ReportCtx, client: CmClient) -> None:
    clients, cerr = safe_get(client, "/v1/transparent-encryption/clients/?limit=100")
    policies, perr = safe_get(client, "/v1/transparent-encryption/policies/?limit=100")
    if cerr:
        ctx.section("cte_clients", "WARN", {"error": str(cerr)}, cerr.status)
        return
    resources = (clients or {}).get("resources") or []
    disconnected = []
    unregistered = []
    gp_bad = []
    for cl in resources:
        if not isinstance(cl, dict):
            continue
        health = str(cl.get("client_health_status") or "").upper()
        comm = bool(cl.get("communication_enabled"))
        row = {
            "name": cl.get("name"),
            "client_health_status": cl.get("client_health_status"),
            "communication_enabled": comm,
        }
        if health == "UNREGISTERED":
            unregistered.append(row)
            ctx.add(
                "cte",
                "cte_client_unregistered",
                "INFO",
                f"CTE client '{cl.get('name')}' is UNREGISTERED.",
            )
        elif health and health != "HEALTHY":
            # NOT CONNECTED / other — WARN only when communication is expected
            if comm:
                disconnected.append(row)
                ctx.add(
                    "cte",
                    "cte_client_disconnected",
                    "WARNING",
                    f"CTE client '{cl.get('name')}' health is '{cl.get('client_health_status')}' "
                    f"(communication enabled).",
                )
            else:
                unregistered.append(row)
                ctx.add(
                    "cte",
                    "cte_client_offline",
                    "INFO",
                    f"CTE client '{cl.get('name')}' health is '{cl.get('client_health_status')}' "
                    f"(communication disabled).",
                )
        cid = cl.get("id")
        if not cid:
            continue
        gp, gerr = safe_get(client, f"/v1/transparent-encryption/clients/{cid}/guardpoints/?limit=100")
        if gerr:
            continue
        for g in (gp or {}).get("resources") or []:
            st = str(g.get("guard_point_state") or g.get("state") or "")
            if st and st.upper() not in ("ACTIVE",):
                gp_bad.append(
                    {
                        "client": cl.get("name"),
                        "guard_path": g.get("guard_path"),
                        "guard_point_state": st,
                    }
                )
                sev = "WARNING" if st.upper() in ("DISABLED", "ERROR", "FAILED") else "INFO"
                ctx.add(
                    "cte",
                    "cte_guardpoint_not_active",
                    sev,
                    f"CTE GuardPoint on '{cl.get('name')}' path '{g.get('guard_path')}' is '{st}'.",
                )
    ctx.section(
        "cte_clients",
        "WARN" if (disconnected or any(g.get("guard_point_state", "").upper() in ("DISABLED", "ERROR", "FAILED") for g in gp_bad)) else "PASS",
        {
            "total": (clients or {}).get("total", len(resources)),
            "disconnected": disconnected[:20],
            "unregistered_or_offline": unregistered[:20],
            "guardpoints_not_active": gp_bad[:20],
        },
        200,
    )

    if perr:
        ctx.section("cte_policies", "WARN", {"error": str(perr)}, perr.status)
    else:
        learn = []
        for p in (policies or {}).get("resources") or []:
            if isinstance(p, dict) and p.get("never_deny") is True:
                learn.append(p.get("name"))
                ctx.add(
                    "cte",
                    "cte_policy_learn_mode",
                    "WARNING",
                    f"CTE policy '{p.get('name')}' has Learn Mode enabled (never_deny=true).",
                )
        ctx.section(
            "cte_policies",
            "WARN" if learn else "PASS",
            {
                "total": (policies or {}).get("total"),
                "learn_mode_policies": learn,
            },
            200,
        )
