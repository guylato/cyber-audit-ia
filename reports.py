import json
import os
from datetime import datetime
from typing import Any, Dict

import state as _state
from utils import get_agent, history_event, new_id, next_patch_id, now_iso, llm_safe

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "rapports")


def generate_txt_report(agent_id: str, audit: Dict[str, Any], patch_note: Dict[str, Any]) -> str:
    prompt = f"""
Tu es un consultant senior en cybersécurité.
Rédige en français un rapport professionnel d'audit de sécurité sur un agent IA.
Le rapport doit être lisible par un RSSI ou un développeur senior.
Pas de JSON. Pas de code. Prose uniquement.

Informations:
- Agent: {agent_id}
- Risque avant patch: {json.dumps(audit.get('risk', {}), ensure_ascii=False)}
- Correctifs appliqués: {json.dumps(patch_note.get('actions_applied', []), ensure_ascii=False)}
- Risque après patch: {json.dumps(patch_note.get('risk_after', {}), ensure_ascii=False)}
- Statut final: {patch_note.get('status', 'unknown')}

Structure:
1. Résumé exécutif
2. Vulnérabilités identifiées
3. Correctifs appliqués
4. Risque résiduel
5. Recommandations
""".strip()

    report_text = llm_safe(
        prompt,
        _state.SUPERVISOR_MODEL,
        temperature=0.3,
        default=f"[Rapport non généré — agent: {agent_id}, risque: {audit.get('risk', {})}]",
    )

    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        filename = os.path.join(REPORTS_DIR, f"rapport_{agent_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"[INFO] Rapport sauvegardé: {filename}")
    except Exception as e:
        print(f"[WARN] Impossible de sauvegarder le rapport: {e}")

    return report_text


def generate_patch_note(
    agent_id: str,
    audit: Dict[str, Any],
    proposal: Dict[str, Any],
    patch_record: Dict[str, Any],
    validation: Dict[str, Any],
) -> Dict[str, Any]:
    agent = get_agent(agent_id)
    patch_id = next_patch_id()

    note = {
        "patch_id": patch_id,
        "timestamp": now_iso(),
        "agent_id": agent_id,
        "agent_role": agent["role"],
        "patch_title": proposal.get("patch_title", "Patch sécurité"),
        "summary": proposal.get("summary", "Aucun résumé"),
        "root_causes": proposal.get("root_causes", []),
        "risk_before": audit["risk"],
        "risk_after": validation["post_patch_risk"],
        "findings_before": len(audit["findings"]),
        "findings_after": validation["post_patch_findings_count"],
        "actions_applied": patch_record["changes"],
        "validation": validation,
        "status": "validated" if validation["validated"] else "rollback_required",
        "recommendations": proposal.get("validation_tests", []),
    }

    agent["patch_notes"].append(note)
    history_event("patch_note", agent_id, note)
    return note
