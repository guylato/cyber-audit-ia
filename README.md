Module Superviseur — cyber-audit-ia

Rôle

Le superviseur est le composant final du pipeline d'audit. Il intervient une fois qu'un agent IA a été testé (pentest statique, dynamique, multi-tours, canary) et que les findings de sécurité ont été collectés. Son rôle est d'analyser ces findings et de proposer un correctif concret, sans intervention humaine, sous forme de patch de configuration appliqué à l'agent audité.

Fonctionnement


Entrée : le superviseur reçoit l'agent audité (rôle, prompt système, permissions, security_controls, policies, allowed_tools, statut de quarantaine), la liste des findings détectés (limités aux 12 premiers pour rester dans un contexte raisonnable), et un score de risque global calculé en amont.
Prompt structuré : ces informations sont injectées dans un prompt qui contraint le modèle superviseur à répondre exclusivement en JSON valide, sans texte libre autour.
Sortie attendue : un objet JSON contenant :

summary : résumé de l'analyse
root_causes : causes racines identifiées
recommended_actions : liste d'actions correctives concrètes (ex. set_temperature, set_security_control, set_policy, append_system_prompt, remove_permission, remove_tool, set_quarantine)
patch_title : titre du correctif proposé
validation_tests : tests à rejouer pour valider le correctif
residual_risk : niveau de risque résiduel estimé (low / medium / high / critical)



Robustesse : si le modèle superviseur ne renvoie pas un JSON exploitable, un patch de sécurité par défaut est appliqué automatiquement (durcissement de la température, activation des garde-fous anti-injection et de filtrage de sortie, politique de non-fuite de données, renforcement du prompt système). Cela garantit qu'un échec de parsing ne bloque jamais le pipeline de remédiation.


Principe de conception


Actions minimales et ciblées : le superviseur est explicitement contraint à proposer des correctifs proportionnés au risque plutôt que des changements larges.
Escalade vers la quarantaine : en cas de risque critique, la mise en quarantaine de l'agent est une action recommandée en priorité.
Traçabilité : chaque patch proposé est associé à des tests de validation précis, permettant de vérifier que le correctif adresse bien les findings d'origine avant remédiation complète (jusqu'à 3 itérations, voir MAX_REMEDIATION_ITERATIONS).


Positionnement dans le pipeline global

Agent audité → Pentest (statique/dynamique/multi-tours/canary)
            → Findings heuristiques + scoring de risque
            → Superviseur (analyse + patch proposé)
            → Application du patch (remediation.py)
            → Re-test de validation

Ce module illustre une approche de type "blue team automatisée" : détection, analyse de cause racine, et remédiation, appliquée non pas à une infrastructure classique mais à des agents IA eux-mêmes.
