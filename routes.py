from typing import Any, Dict

from fastapi import APIRouter, HTTPException

import state as _state
from config import AVAILABLE_MODELS, DEFAULT_AGENT_MODEL, DEFAULT_AUDITOR_MODEL, TIMEOUT_SECONDS
from models import (
    AdvancedAuditRequest,
    AgentRunRequest,
    AuditRequest,
    BenchmarkRequest,
    CrossAuditRequest,
    PatchRequest,
    ScenarioAuditRequest,
)
from utils import get_agent, llm
from agents import build_temporary_agent_from_scenario, run_agent
from audit import perform_advanced_audit, perform_advanced_audit_on_custom_agent, perform_audit
from supervisor import supervisor_propose_patch
from patch import apply_patch_actions, rollback_last_patch
from remediation import benchmark_models, benchmark_models_advanced, remediation_loop, validate_patch
from reports import generate_patch_note, generate_txt_report

router = APIRouter()


@router.get("/")
def root() -> Dict[str, Any]:
    return {
        "message": "Cyber AI Supervisor v3.2 prêt",
        "agents": list(_state.state["agents"].keys()),
        "model_agent": DEFAULT_AGENT_MODEL,
        "model_supervisor": DEFAULT_AUDITOR_MODEL,
        "available_models": AVAILABLE_MODELS,
        "timeout_seconds": TIMEOUT_SECONDS,
        "features": [
            "cvss_like_scoring",
            "parallel_pentest",
            "dynamic_pentest",
            "advanced_behavioral_audit",
            "multi_turn_attack_simulation",
            "canary_secret_detection",
            "hallucinated_action_detection",
            "dimension_scoring",
            "remediation_loop",
            "benchmark_models",
            "advanced_benchmark",
            "cross_audit",
            "scenario_audit",
            "alerts",
            "quarantine",
            "professional_report",
        ],
    }


@router.get("/health")
def health() -> Dict[str, Any]:
    try:
        reply = llm("Réponds uniquement OK", DEFAULT_AGENT_MODEL, temperature=0.0)
        return {"status": "ok", "ollama": True, "model_reply": reply}
    except HTTPException as e:
        return {"status": "degraded", "ollama": False, "error": e.detail}


@router.get("/models")
def get_models() -> Dict[str, Any]:
    return {"models": AVAILABLE_MODELS}


@router.get("/agents")
def list_agents() -> Dict[str, Any]:
    agents_summary = {
        agent_id: {k: v for k, v in agent.items() if k not in ["scan_history", "patch_history", "rollback_history"]}
        for agent_id, agent in _state.state["agents"].items()
    }
    return {"agents": agents_summary}


@router.post("/agents/run")
def api_run_agent(payload: AgentRunRequest) -> Dict[str, Any]:
    return run_agent(payload.agent_id, payload.user_input)


@router.post("/audit")
def api_audit(payload: AuditRequest) -> Dict[str, Any]:
    return perform_audit(payload.agent_id)


@router.post("/audit/advanced")
def api_advanced_audit(payload: AdvancedAuditRequest) -> Dict[str, Any]:
    return perform_advanced_audit(
        agent_id=payload.agent_id,
        include_dynamic=payload.include_dynamic,
        include_multiturn=payload.include_multiturn,
        include_canary=payload.include_canary,
        include_tool_abuse=payload.include_tool_abuse,
        include_hallucination=payload.include_hallucination,
        repetitions=payload.repetitions,
    )


@router.post("/cross-audit")
def api_cross_audit(payload: CrossAuditRequest) -> Dict[str, Any]:
    if payload.auditor_model not in AVAILABLE_MODELS:
        raise HTTPException(status_code=400, detail=f"Modèle auditeur inconnu: {payload.auditor_model}")

    agent = get_agent(payload.agent_id)
    original_supervisor = _state.SUPERVISOR_MODEL

    try:
        _state.SUPERVISOR_MODEL = payload.auditor_model
        result = perform_advanced_audit(
            agent_id=payload.agent_id,
            include_dynamic=payload.include_dynamic,
            include_multiturn=True,
            include_canary=True,
            include_tool_abuse=True,
            include_hallucination=True,
            repetitions=payload.repetitions,
        )
        result["auditor_model"] = payload.auditor_model
        result["audited_model"] = agent["model"]
        return result
    finally:
        _state.SUPERVISOR_MODEL = original_supervisor


@router.post("/scenario-audit")
def api_scenario_audit(payload: ScenarioAuditRequest) -> Dict[str, Any]:
    if payload.auditor_model not in AVAILABLE_MODELS:
        raise HTTPException(status_code=400, detail=f"Modèle auditeur inconnu: {payload.auditor_model}")

    temp_agent = build_temporary_agent_from_scenario(payload.scenario_agent_id, payload.audited_model)
    original_supervisor = _state.SUPERVISOR_MODEL

    try:
        _state.SUPERVISOR_MODEL = payload.auditor_model
        result = perform_advanced_audit_on_custom_agent(
            agent=temp_agent,
            scenario_agent_id=payload.scenario_agent_id,
            include_dynamic=payload.include_dynamic,
            include_multiturn=payload.include_multiturn,
            include_canary=payload.include_canary,
            include_tool_abuse=payload.include_tool_abuse,
            include_hallucination=payload.include_hallucination,
            repetitions=payload.repetitions,
        )
        result["auditor_model"] = payload.auditor_model
        result["audited_model"] = payload.audited_model
        result["scenario_agent_id"] = payload.scenario_agent_id
        return result
    finally:
        _state.SUPERVISOR_MODEL = original_supervisor


@router.post("/patch")
def api_patch(payload: PatchRequest) -> Dict[str, Any]:
    audit = perform_advanced_audit(payload.agent_id)
    agent = get_agent(payload.agent_id)
    proposal = supervisor_propose_patch(agent, audit["findings"], audit["risk"])

    if not payload.auto_apply:
        return {"message": "Patch proposé mais non appliqué", "audit": audit, "proposal": proposal}

    patch_record = apply_patch_actions(payload.agent_id, proposal.get("recommended_actions", []))

    if not payload.auto_validate:
        return {
            "message": "Patch appliqué sans validation",
            "audit": audit,
            "proposal": proposal,
            "patch_record": patch_record,
        }

    validation = validate_patch(payload.agent_id)
    patch_note = generate_patch_note(payload.agent_id, audit, proposal, patch_record, validation)
    rollback = None

    if not validation["validated"]:
        rollback = rollback_last_patch(payload.agent_id)

    report_text = None
    try:
        report_text = generate_txt_report(payload.agent_id, audit, patch_note)
    except Exception as e:
        report_text = f"Erreur génération rapport: {str(e)}"

    return {
        "message": "Cycle cyber terminé",
        "rapport": report_text,
        "audit": audit,
        "proposal": proposal,
        "patch_record": patch_record,
        "validation": validation,
        "patch_note": patch_note,
        "rollback": rollback,
        "final_agent_state": {
            k: v for k, v in get_agent(payload.agent_id).items()
            if k not in ["scan_history", "patch_history"]
        },
    }


@router.post("/rollback/{agent_id}")
def api_rollback(agent_id: str) -> Dict[str, Any]:
    return rollback_last_patch(agent_id)


@router.get("/patch-notes/{agent_id}")
def api_patch_notes(agent_id: str) -> Dict[str, Any]:
    agent = get_agent(agent_id)
    return {"agent_id": agent_id, "patch_notes": agent["patch_notes"]}


@router.get("/history")
def api_history() -> Dict[str, Any]:
    return {"history": _state.state["global_history"]}


@router.get("/alerts/{agent_id}")
def api_alerts(agent_id: str) -> Dict[str, Any]:
    return {"agent_id": agent_id, "alerts": get_agent(agent_id)["alerts"]}


@router.post("/pentest/{agent_id}")
def api_pentest(agent_id: str) -> Dict[str, Any]:
    audit = perform_advanced_audit(
        agent_id,
        include_dynamic=True,
        include_multiturn=True,
        include_canary=True,
        include_tool_abuse=True,
        include_hallucination=True,
        repetitions=2,
    )
    return {
        "message": "Pentest IA exécuté",
        "agent_id": agent_id,
        "risk": audit["risk"],
        "dimension_scores": audit["dimension_scores"],
        "findings": audit["findings"],
        "tests_count": audit["tests_count"],
    }


@router.post("/benchmark")
def api_benchmark(payload: BenchmarkRequest) -> Dict[str, Any]:
    return benchmark_models(payload.agent_id, payload.models)


@router.post("/benchmark/advanced")
def api_benchmark_advanced(payload: BenchmarkRequest) -> Dict[str, Any]:
    return benchmark_models_advanced(payload.agent_id, payload.models)


@router.post("/remediate/{agent_id}")
def api_remediate(agent_id: str) -> Dict[str, Any]:
    print(f"[INFO] Début remediation pour {agent_id}")
    result = remediation_loop(agent_id)
    print(f"[INFO] Fin remediation pour {agent_id}")
    return {"message": "Boucle de remédiation terminée", **result}


@router.get("/dashboard/summary")
def dashboard_summary() -> Dict[str, Any]:
    summary = []
    for agent_id, agent in _state.state["agents"].items():
        last_scan = agent["scan_history"][-1] if agent["scan_history"] else None
        summary.append({
            "agent_id": agent_id,
            "role": agent["role"],
            "version": agent["version"],
            "quarantined": agent["quarantined"],
            "model": agent["model"],
            "risk": last_scan["risk"] if last_scan else {"score": None, "label": "unknown"},
            "patch_notes_count": len(agent["patch_notes"]),
            "alerts_count": len(agent["alerts"]),
            "scans_count": len(agent["scan_history"]),
        })
    return {"summary": summary}


@router.post("/demo/full-cycle/{agent_id}")
def demo_full_cycle(agent_id: str) -> Dict[str, Any]:
    print(f"[INFO] Début full cycle pour {agent_id}")

    get_agent(agent_id)

    audit_before = perform_advanced_audit(
        agent_id,
        include_dynamic=True,
        include_multiturn=True,
        include_canary=True,
        include_tool_abuse=True,
        include_hallucination=True,
        repetitions=2,
    )

    result = remediation_loop(agent_id)

    report_text = None
    try:
        final_patch_note = result.get("final_patch_note")
        if final_patch_note:
            report_text = generate_txt_report(agent_id, audit_before, final_patch_note)
        else:
            report_text = "Aucun rapport généré."
    except Exception as e:
        report_text = f"Erreur génération rapport: {str(e)}"

    print(f"[INFO] Fin full cycle pour {agent_id}")

    return {
        "message": "Démo complète terminée",
        "rapport": report_text,
        "audit_before": audit_before,
        **result,
    }
