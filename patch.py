import copy
from typing import Any, Dict, List

from fastapi import HTTPException

import state as _state
from utils import get_agent, history_event, now_iso


def apply_patch_actions(agent_id: str, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    agent = get_agent(agent_id)
    before = copy.deepcopy(agent)
    changes = []

    for action in actions:
        name = action.get("action")

        if name == "set_temperature":
            old = agent["temperature"]
            agent["temperature"] = float(action.get("value", old))
            changes.append({"field": "temperature", "old": old, "new": agent["temperature"]})

        elif name == "set_security_control":
            control = action.get("control")
            if control in agent["security_controls"]:
                old = agent["security_controls"][control]
                agent["security_controls"][control] = bool(action.get("value", old))
                changes.append({
                    "field": f"security_controls.{control}",
                    "old": old,
                    "new": agent["security_controls"][control],
                })

        elif name == "set_policy":
            policy = action.get("policy")
            if policy in agent["policies"]:
                old = agent["policies"][policy]
                agent["policies"][policy] = bool(action.get("value", old))
                changes.append({
                    "field": f"policies.{policy}",
                    "old": old,
                    "new": agent["policies"][policy],
                })

        elif name == "append_system_prompt":
            addition = str(action.get("value", "")).strip()
            if addition:
                old = agent["system_prompt"]
                old_version = agent["version"]
                agent["system_prompt"] = old + " " + addition
                agent["version"] += 1
                changes.append({"field": "system_prompt", "old": old, "new": agent["system_prompt"]})
                changes.append({"field": "version", "old": old_version, "new": agent["version"]})

        elif name == "remove_permission":
            permission = action.get("permission")
            if permission in agent["permissions"]:
                old = agent["permissions"][permission]
                agent["permissions"][permission] = False
                changes.append({"field": f"permissions.{permission}", "old": old, "new": False})

        elif name == "remove_tool":
            tool = action.get("tool")
            if tool in agent["allowed_tools"]:
                old = copy.deepcopy(agent["allowed_tools"])
                agent["allowed_tools"] = [t for t in agent["allowed_tools"] if t != tool]
                changes.append({"field": "allowed_tools", "old": old, "new": agent["allowed_tools"]})

        elif name == "set_quarantine":
            old = agent["quarantined"]
            agent["quarantined"] = bool(action.get("value", old))
            changes.append({"field": "quarantined", "old": old, "new": agent["quarantined"]})

    patch_record = {
        "timestamp": now_iso(),
        "before": before,
        "after": copy.deepcopy(agent),
        "changes": changes,
    }
    agent["patch_history"].append(patch_record)
    history_event("patch_applied", agent_id, patch_record)
    return patch_record


def rollback_last_patch(agent_id: str) -> Dict[str, Any]:
    agent = get_agent(agent_id)
    if not agent["patch_history"]:
        raise HTTPException(status_code=404, detail="Aucun patch à annuler")

    last = agent["patch_history"][-1]
    restored = copy.deepcopy(last["before"])

    restored["patch_history"] = agent["patch_history"][:-1]
    restored["scan_history"] = agent["scan_history"]
    restored["rollback_history"] = agent["rollback_history"]
    restored["alerts"] = agent["alerts"]
    restored["patch_notes"] = agent["patch_notes"]

    rollback_record = {
        "timestamp": now_iso(),
        "rolled_back_to_version": restored["version"],
        "rolled_back_from_version": agent["version"],
    }
    restored["rollback_history"].append(rollback_record)

    _state.state["agents"][agent_id] = restored
    history_event("rollback", agent_id, rollback_record)
    return rollback_record
