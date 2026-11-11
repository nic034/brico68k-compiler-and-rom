# Guide de développement — périmètre ROM / émulateur / BricoBanc

## Répartition des responsabilités

**La ROM Brico68k est développée exclusivement par le mainteneur du projet (Nicolas).**
Les contributions automatisées et travaux de l'assistant portent **uniquement sur l'émulateur Neo Geo / Motorola 68000, son banc de validation, et le projet BricoBanc**.

| Domaine | Responsabilité | Règle pour les contributions automatisées |
| --- | --- | --- |
| ROM Brico68k (code 68000, tests de diagnostic, binaires et versions) | Nicolas | Lecture comme référence uniquement ; aucune modification ou publication |
| Compilateur de ROM Brico68k | Nicolas | Aucune modification ni publication automatique |
| `Brico68k_Emulator.py`, `emulator/` | Développement émulateur | Corrections et tests possibles après validation |
| Données et scripts de banc (`bench/`, tests d'émulation) | Développement émulateur | Évolutions possibles sans toucher au contenu de la ROM |
| BricoBanc (`nic034/bricobanc`) | Développement banc | Interface, Pico, MAME et tests dans son dépôt dédié |
| `brico16bits/` (patch firmware) | Hors périmètre automatique | Ne pas modifier ; consulter comme référence si nécessaire |

**Chemins exclus des commits d'émulateur :** `rom/`, `source/`, `Brico68k_Compiler.py`, `brico16bits/`. Un utilisateur peut bien sûr continuer à faire évoluer ces composants lui-même. Les scripts/tests de l'émulateur peuvent charger les ROM qu'il fournit, sans modifier les fichiers d'entrée.

## Organisation des travaux

1. Repartir du dernier commit de `main` avant chaque lot et relever son SHA.
2. Analyser le comportement existant ; identifier précisément les fichiers et les risques.
3. Ajouter des tests reproductibles avant la correction lorsqu'un défaut est confirmé.
4. Modifier uniquement l'émulateur ou l'outillage de validation ; préserver les entrées ROM.
5. Exécuter les tests Python, les validations MAME réellement disponibles et les contrôles de non-régression ; comparer sorties et empreintes `gfx` / `pixels` lorsque pertinentes.
6. Mesurer les timings lorsqu'un environnement capable de les mesurer est disponible. Distinguer temps émulé, cycles de CPU et mesures sur matériel réel.
7. Pousser une correction validée avec un message de commit explicite, de préférence sur une branche et en PR pour les modifications à risque. Ne jamais écraser des travaux concurrents.

Ne **pas** déclarer une émulation de firmware RP2040 complète ou une validation électrique sur Neo Geo à partir de mocks, de captures SRAM ou de tests isolés.

## Critères de validation

- **Tests logiciels** : préciser les commandes exécutées, le nombre de tests réussis/échoués/ignorés, les versions des outils et les fichiers testés.
- **Émulation intégrée** : vérifier le lancement, le dialogue hôte, les commandes, les états et les sorties réellement observées avec MAME et/ou le moteur Pico concerné ; signaler toute substitution.
- **Non-régression** : conserver le contrôle des inventaires de scénarios et commandes, des résultats de diagnostic et des empreintes graphiques.
- **Timings matériels** : une vérification de timings sur le vrai matériel nécessite des mesures physiques ; le cycle accounting d'un émulateur ne suffit pas.
- **Traçabilité** : inclure SHA de départ, fichiers modifiés, résultats des tests, limites, liens de commits et PR.

Si la validation est impossible, documenter le blocage et laisser le correctif isolé ; ne jamais modifier la ROM pour faire passer des tests.

## Relations entre projets

- Dépôt présent : [Brico68k Compiler and ROM](https://github.com/nic034/brico68k-compiler-and-rom) — ROM maintenue par Nicolas ; émulateur et outils de test partagés.
- Dépôt de développement du banc : [BricoBanc](https://github.com/nic034/bricobanc) — émulation RP2040, intégration MAME, interface et validation.

Ce guide définit le **périmètre de travail** ; il n'atteste pas que l'émulation RP2040 ou l'intégration MAME/UF2 de bout en bout sont achevées.
