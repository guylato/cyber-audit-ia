import concurrent.futures
from typing import Any, Dict, List

from config import MAX_PENTEST_WORKERS
from utils import create_alert, get_agent, history_event, new_id, now_iso
from agents import run_agent, run_agent_multiturn, run_custom_agent, run_custom_agent_multiturn
from pentest import (
    canary_test_cases,
    dynamic_test_cases,
    hallucination_test_cases,
    multi_turn_test_cases,
    security_test_cases,
)
from heuristics import config_findings, heuristic_findings_from_multiturn, heuristic_findings_from_output
from scoring import aggregate_risk, score_dimensions


def _run_test_case(agent_id: str, case: Dict[str, Any]) -> Dict[str, Any]:
    result = run_agent(agent_id, case["user_input"])
    agent = get_agent(agent_id)
    findings = heuristic_findings_from_output(agent, case, result)
    return {"test_case": case, "result": result, "findings": findings}


def perform_audit(agent_id: str, include_dynamic: bool = True) -> Dict[str, Any]:
    agent = get_agent(agent_id)
    test_cases = security_test_cases(agent)

    if include_dynamic:
        dyn = dynamic_test_cases(agent)
        test_cases.extend(dyn)
        print(f"[DEBUG] audit {agent_id}: {len(test_cases)} tests ({len(dyn)} dynamiques)")

    execution_results = []
    findings = []

    if agent["quarantined"]:
        for case in test_cases:
            execution_results.append({
                "test_case": case,
                "result": {"success": False, "error_type": "QUARANTINED"},
                "findings": [],
            })
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PENTEST_WORKERS) as executor:
            futures = {executor.submit(_run_test_case, agent_id, case): case for case in test_cases}
            for future in concurrent.futures.as_completed(futures):
                try:
                    outcome = future.result()
                    execution_results.append(outcome)
                    findings.extend(outcome["findings"])
                except Exception as e:
                    case = futures[future]
                    print(f"[WARN] Test case {case.get('id')} failed: {e}")

    findings.extend(config_findings(agent))
    risk = aggregate_risk(findings)

    if risk["label"] == "critical":
        create_alert(agent_id, "critical", "Risque critique détecté", "Le score global de risque a atteint un niveau critique.")

    slim_results = [
        {
            "test_case": {k: r["test_case"][k] for k in ["id", "category", "severity"] if k in r["test_case"]},
            "success": r["result"].get("success"),
            "error_type": r["result"].get("error_type"),
            "findings_count": len(r.get("findings", [])),
        }
        for r in execution_results
    ]

    audit = {
        "audit_id": new_id("audit"),
        "timestamp": now_iso(),
        "agent_id": agent_id,
        "findings": findings,
        "risk": risk,
        "tests_executed": slim_results,
        "tests_count": len(test_cases),
        "status": "clean" if not findings else "vulnerable",
    }

    agent["scan_history"].append({
        "audit_id": audit["audit_id"],
        "timestamp": audit["timestamp"],
        "risk": risk,
        "mode": "standard",
    })
    history_event("audit", agent_id, {
        "audit_id": audit["audit_id"],
        "risk": risk,
        "findings_count": len(findings),
    })
    return audit


def perform_advanced_audit(
    agent_id: str,
    include_dynamic: bool = True,
    include_multiturn: bool = True,
    include_canary: bool = True,
    include_tool_abuse: bool = True,
    include_hallucination: bool = True,
    repetitions: int = 2,
) -> Dict[str, Any]:
    agent = get_agent(agent_id)

    findings = []
    execution_results = []
    all_cases = list(security_test_cases(agent))

    if include_dynamic:
        all_cases.extend(dynamic_test_cases(agent))
    if include_canary:
        all_cases.extend(canary_test_cases(agent))
    if include_hallucination:
        all_cases.extend(hallucination_test_cases(agent))

    for case in all_cases:
        for repetition in range(repetitions):
            try:
                result = run_agent(agent_id, case["user_input"])
                case_findings = heuristic_findings_from_output(agent, case, result)
                findings.extend(case_findings)
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": repetition + 1,
                    "success": result.get("success"),
                    "error_type": result.get("error_type"),
                    "findings_count": len(case_findings),
                })
            except Exception as e:
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": repetition + 1,
                    "success": False,
                    "error_type": str(e),
                    "findings_count": 0,
                })

    if include_multiturn:
        for case in multi_turn_test_cases(agent):
            try:
                result = run_agent_multiturn(agent_id, case["conversation"])
                case_findings = heuristic_findings_from_multiturn(agent, case, result)
                findings.extend(case_findings)
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": 1,
                    "success": result.get("success"),
                    "error_type": None if result.get("success") else "MULTITURN_FAILURE",
                    "findings_count": len(case_findings),
                })
            except Exception as e:
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": 1,
                    "success": False,
                    "error_type": str(e),
                    "findings_count": 0,
                })

    findings.extend(config_findings(agent))
    risk = aggregate_risk(findings)
    dimension_scores = score_dimensions(findings)

    if risk["label"] == "critical":
        create_alert(agent_id, "critical", "Risque critique détecté", "L'audit avancé a détecté un niveau de risque critique.")

    audit = {
        "audit_id": new_id("advanced-audit"),
        "timestamp": now_iso(),
        "agent_id": agent_id,
        "mode": "advanced",
        "findings": findings,
        "risk": risk,
        "dimension_scores": dimension_scores,
        "tests_executed": execution_results,
        "tests_count": len(execution_results),
        "status": "clean" if not findings else "vulnerable",
    }

    agent["scan_history"].append({
        "audit_id": audit["audit_id"],
        "timestamp": audit["timestamp"],
        "risk": risk,
        "mode": "advanced",
    })
    history_event("advanced_audit", agent_id, {
        "audit_id": audit["audit_id"],
        "risk": risk,
        "findings_count": len(findings),
        "dimension_scores": dimension_scores,
    })
    return audit


def perform_advanced_audit_on_custom_agent(
    agent: Dict[str, Any],
    scenario_agent_id: str,
    include_dynamic: bool = True,
    include_multiturn: bool = True,
    include_canary: bool = True,
    include_tool_abuse: bool = True,
    include_hallucination: bool = True,
    repetitions: int = 2,
) -> Dict[str, Any]:
    findings = []
    execution_results = []
    all_cases = list(security_test_cases(agent))

    if include_dynamic:
        all_cases.extend(dynamic_test_cases(agent))
    if include_canary:
        all_cases.extend(canary_test_cases(agent))
    if include_hallucination:
        all_cases.extend(hallucination_test_cases(agent))

    for case in all_cases:
        for repetition in range(repetitions):
            try:
                result = run_custom_agent(agent, case["user_input"])
                case_findings = heuristic_findings_from_output(agent, case, result)
                findings.extend(case_findings)
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": repetition + 1,
                    "success": result.get("success"),
                    "error_type": result.get("error_type"),
                    "findings_count": len(case_findings),
                })
            except Exception as e:
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": repetition + 1,
                    "success": False,
                    "error_type": str(e),
                    "findings_count": 0,
                })

    if include_multiturn:
        for case in multi_turn_test_cases(agent):
            try:
                result = run_custom_agent_multiturn(agent, case["conversation"])
                case_findings = heuristic_findings_from_multiturn(agent, case, result)
                findings.extend(case_findings)
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": 1,
                    "success": result.get("success"),
                    "error_type": None if result.get("success") else "MULTITURN_FAILURE",
                    "findings_count": len(case_findings),
                })
            except Exception as e:
                execution_results.append({
                    "case_id": case["id"],
                    "category": case["category"],
                    "repetition": 1,
                    "success": False,
                    "error_type": str(e),
                    "findings_count": 0,
                })

    findings.extend(config_findings(agent))
    risk = aggregate_risk(findings)
    dimension_scores = score_dimensions(findings)

    return {
        "audit_id": new_id("scenario-audit"),
        "timestamp": now_iso(),
        "scenario_agent_id": scenario_agent_id,
        "audited_model": agent["model"],
        "findings": findings,
        "risk": risk,
        "dimension_scores": dimension_scores,
        "tests_executed": execution_results,
        "tests_count": len(execution_results),
        "status": "clean" if not findings else "vulnerable",
    }
