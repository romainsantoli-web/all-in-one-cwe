# 🗺️ Roadmap & Évolutions SOTA — Security All-in-One CWE

**Dernière mise à jour :** 1er avril 2026

## ✅ 7 entrées SOTA reclassifiées (outils déjà présents → "étendre" au lieu de "intégrer")

| Priorité | Outil concerné                  | Action proposée                              | Bénéfice attendu                          | Effort estimé |
|----------|---------------------------------|----------------------------------------------|-------------------------------------------|---------------|
| P0       | **Checkov**                     | Ajout de policies custom                     | Meilleure couverture IaC                  | ~10 h        |
| P1       | **Shodan CLI**                  | Ajout du monitoring continu                  | Veille active sur la cible                | ~7 h         |
| P1       | **Graphw00f**                   | Intégration InQL + graphql-cop               | Audit GraphQL plus profond                | ~10 h        |
| P1       | **TruffleHog + Gitleaks**       | Patterns custom + règles métier              | Détection secrets plus fine               | ~4 h         |
| P2       | **Dalfox**                      | Ajout du mode DalScan headless               | Meilleure détection XSS DOM               | ~4 h         |
| P2       | **CRLFuzz + Smuggler**          | Chaîne automatisée                           | Flux CRLF + HTTP Request Smuggling        | ~7 h         |
| P2       | **Arjun**                       | Ajout de ParamSpider                         | Découverte de paramètres plus exhaustive  | ~2 h         |

**Total quick wins** : **~44 heures**

## 📊 Récapitulatif mis à jour
- 7 entrées SOTA reclassifiées comme extensions  
- Estimation globale réduite : **~750-950 heures** au total  
- Dont **~190 heures de quick wins** identifiés et prioritaires  
- SEC-M6 corrigé : Semgrep / Gitleaks / TruffleHog maintenant pleinement intégrés dans le CI/CD

→ Le projet reste focalisé sur la simplicité (`make run`) tout en continuant d'étendre la suite de façon intelligente.

---
