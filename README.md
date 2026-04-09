# 🛡 PhishGuard — Détecteur de Phishing Statique

> Outil open-source d'analyse statique d'emails et d'URLs pour détecter les tentatives de phishing.

---

## Sommaire

- [Aperçu](#aperçu)
- [Fonctionnement](#fonctionnement)
- [Architecture du projet](#architecture-du-projet)
- [Moteur de détection](#moteur-de-détection)
- [Score de risque](#score-de-risque)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Tests](#tests)
- [Choix techniques](#choix-techniques)
- [Roadmap](#roadmap)

---

## Aperçu

PhishGuard permet à n'importe quel utilisateur de **coller un email suspect** ou **entrer une URL** et d'obtenir instantanément :

- Un **score de risque de 0 à 100**
- Un **verdict clair** (Sûr / Suspect / Phishing !)
- La **liste détaillée des indicateurs** détectés, classés par sévérité
- Un **résumé par catégorie** (URL, Langage, Expéditeur, En-têtes)
- Des **recommandations concrètes** adaptées au niveau de risque

---

## Fonctionnement

### Flux général

```
Utilisateur saisit un email ou une URL
             │
             ▼
    ┌─────────────────┐
    │   ui.js         │  ← Récupère le texte et appelle PhishDetector.analyze()
    └────────┬────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────┐
    │                    detector.js                      │
    │                                                     │
    │  ┌──────────────┐  ┌──────────────┐                │
    │  │ analyserURLs │  │analyserLangage│                │
    │  └──────┬───────┘  └──────┬───────┘                │
    │         │                 │                         │
    │  ┌──────────────┐  ┌──────────────┐                │
    │  │analyserExpéd.│  │analyserEnTêtes│               │
    │  └──────┬───────┘  └──────┬───────┘                │
    │         │                 │                         │
    │         └────────┬────────┘                         │
    │                  ▼                                  │
    │       Agrégation des scores et indicateurs          │
    │                  ▼                                  │
    │    Normalisation du score (0–100, plafonné)         │
    │                  ▼                                  │
    │    Calcul du niveau : safe / warning / danger       │
    └──────────────────┬──────────────────────────────────┘
                       │
                       ▼
    ┌─────────────────────────────┐
    │  ui.js — Rendu des résultats│
    │  - Cercle SVG animé         │
    │  - Barre de risque          │
    │  - Liste des indicateurs    │
    │  - Grille des catégories    │
    │  - Recommandations          │
    └─────────────────────────────┘
```

---

## Architecture du projet

```
phishing-detector/
│
├── index.html          ← Structure HTML de l'interface
├── style.css           ← Design complet (thème terminal sombre)
├── detector.js         ← Moteur de détection (logique métier)
├── ui.js               ← Gestion du DOM et du rendu
│
├── tests/
│   ├── index.html      ← Runner de tests dans le navigateur
│   └── tests.js        ← Suite de tests unitaires (37 tests)
│
└── docs/
    ├── ARCHITECTURE.md                    ← Documentation technique
    └── PhishGuard_Carnet_de_Tests.pdf     ← Carnet de tests complet
```

### Séparation des responsabilités

```
┌──────────────────────────────────────────────────┐
│                   index.html                     │
│  Structure sémantique HTML, zones accessibles    │
└────────────────┬─────────────────────────────────┘
                 │ inclut
    ┌────────────▼─────────────┐
    │        style.css         │
    │  Présentation visuelle   │
    │  Variables CSS, animations│
    └──────────────────────────┘

    ┌────────────────────────────────────────────┐
    │              detector.js                   │
    │  Module IIFE isolé : PhishDetector         │
    │  ├── Listes statiques (données)            │
    │  ├── Expressions régulières                │
    │  ├── 4 analyseurs spécialisés              │
    │  └── API publique : .analyze(texte, mode)  │
    └────────────────────────────────────────────┘

    ┌────────────────────────────────────────────┐
    │                  ui.js                     │
    │  Module IIFE isolé : interface uniquement  │
    │  ├── Gestion des onglets                   │
    │  ├── Écouteurs d'événements                │
    │  ├── Rendu DOM des résultats               │
    │  └── Animations SVG et CSS                 │
    └────────────────────────────────────────────┘
```

---

## Moteur de détection

Le fichier `detector.js` est organisé en **4 sections** clairement délimitées :

### Section 1 — Listes statiques

| Liste | Description | Source |
|-------|-------------|--------|
| `DOMAINES_PHISHING` | Set de domaines frauduleux connus | PhishTank, OpenPhish, APWG |
| `MARQUES_USURPEES` | Marques fréquemment imitées (PayPal, Amazon…) | Études APWG |
| `TLD_RISQUE` | Extensions de domaine à risque (.xyz, .tk…) | Rapport Spamhaus |

### Section 2 — Expressions régulières

12 regex compilées une seule fois pour la performance :

```
REGEX.url               → Extraction des URLs dans un texte
REGEX.ipDansUrl         → IP directe dans une URL (http://1.2.3.4/...)
REGEX.arobaseUrl        → "@" dans l'URL pour masquer le domaine
REGEX.urlRaccourcie     → Services bit.ly, tinyurl, etc.
REGEX.encodageUrl       → Séquences %XX d'obfuscation
REGEX.multiTiretDomaine → paypal-secure-login-update.com
REGEX.leetspeak         → paypa1, amaz0n
REGEX.urlLongue         → URLs > 80 caractères
REGEX.email             → Extraction des adresses email
REGEX.piecesJointes     → Extensions dangereuses (.exe, .zip, .docm…)
REGEX.rappelTel         → Numéro + demande d'appel urgent
REGEX.hrefTrompeur      → Lien HTML avec texte ≠ href
```

### Section 3 — Les 4 analyseurs spécialisés

```
analyserURLs(texte)
  ├── IP directe, "@", raccourcisseur, longueur
  ├── Encodage, liste noire, TLD, marque usurpée
  └── Leetspeak, HTTP sans S

analyserLangage(texte)
  ├── Mots-clés d'urgence (critique & warning)
  ├── Demandes de données sensibles (carte, PIN, IBAN…)
  ├── Pièces jointes dangereuses
  └── Demande de rappel téléphonique urgent

analyserExpediteur(texte)
  ├── Imitations de marques dans les domaines
  ├── TLD à risque pour les expéditeurs
  └── Reply-To ≠ From (technique de détournement)

analyserEnTetes(texte)
  ├── SPF : fail → +20
  ├── DKIM : none/fail → +15
  ├── DMARC : fail → +15
  └── X-Mailer suspect → +10
```

### Section 4 — Score final

```
score_brut  = somme(scores de tous les analyseurs)
score_final = min(score_brut, 100)

niveauRisque :
  0  ≤ score < 34  → "safe"    (vert)
  34 ≤ score < 67  → "warning" (jaune)
  67 ≤ score ≤ 100 → "danger"  (rouge)
```

---

## Score de risque

| Indicateur | Type | Points |
|------------|------|--------|
| Domaine en liste noire | Critique | +50 |
| "@" dans URL | Critique | +25 |
| IP directe dans URL | Critique | +30 |
| Marque usurpée dans sous-domaine | Critique | +20 |
| Expéditeur imite une marque | Critique | +25 |
| Reply-To ≠ From | Critique | +20 |
| SPF fail | Critique | +20 |
| Données sensibles demandées | Critique | +15–40 |
| Pièce jointe dangereuse | Critique | +20 |
| DKIM fail | Warning | +15 |
| DMARC fail | Warning | +15 |
| URL raccourcie | Warning | +15 |
| TLD à risque | Warning | +8–10 |
| HTTP sans S | Warning | +8 |
| URL > 80 caractères | Warning | +10 |
| Leetspeak dans domaine | Warning | +10 |

---

## Installation

```bash
git clone https://github.com/AnaisUIMM/Phishguard.git
cd Phishguard
python3 -m http.server 8080
# → http://localhost:8080
```

---

## Utilisation

### Analyser un email

1. Ouvrez PhishGuard dans votre navigateur
2. Collez l'intégralité de l'email dans la zone de texte
3. Cliquez sur **Analyser** (ou `Ctrl+Entrée`)

> Inclure les en-têtes techniques (From, Reply-To, Authentication-Results) améliore la précision.

### Analyser une URL

1. Cliquez sur l'onglet **URL**
2. Entrez l'URL suspecte et appuyez sur `Entrée`

> ⚠ N'ouvrez jamais l'URL dans votre navigateur avant de l'avoir analysée.

### Lire les résultats

```
┌────────────────────────────────────────────┐
│  ┌──────┐  🚨 Phishing !                  │
│  │  87  │  Très forte probabilité de       │
│  │ /100 │  tentative de phishing.          │
│  └──────┘                                  │
│  [Safe ─────────────────────────●─] Danger │
│                                            │
│  INDICATEURS DÉTECTÉS                      │
│  │ CRITIQUE  IP directe dans URL  +30  │   │
│  │ CRITIQUE  Données sensibles     +25  │   │
│  │ SUSPECT   URL raccourcie        +15  │   │
│                                            │
│  RECOMMANDATIONS                           │
│  › Ne cliquez sur aucun lien              │
│  › Signalez à signal-spam.fr              │
└────────────────────────────────────────────┘
```

---

## Tests

```bash
# Dans le navigateur (serveur actif)
http://localhost:8080/tests/index.html

# En ligne de commande
node tests/tests.js
```

**Résultat : 37/37 tests passés ✅**

| Suite | Tests |
|-------|-------|
| Score global — emails légitimes | 3 |
| Score global — emails de phishing | 4 |
| Détection URL (6 suites) | 9 |
| Langage (3 suites) | 7 |
| Expéditeur (2 suites) | 2 |
| En-têtes SPF/DKIM/DMARC | 4 |
| Structure du résultat | 4 |
| Cas limites | 3 |

---

## Choix techniques

**JavaScript vanilla** — zéro dépendance, portable, analyse instantanée.

**Pattern IIFE** — encapsulation complète, seule `analyze()` est exposée.

**Analyseurs séparés** — fonctions pures, testables et extensibles indépendamment.

**Protection XSS** — tout contenu injecté via `innerHTML` passe par `escapeHTML()`.

---

## Roadmap

- [ ] Import de fichier `.eml`
- [ ] Base de données mise à jour via GitHub Actions
- [ ] Extension navigateur Chrome/Firefox
- [ ] Analyse de QR codes
- [ ] Localisation EN/FR

---

## Ressources

- [PhishTank](https://www.phishtank.com/) — base de données de phishing
- [signal-spam.fr](https://www.signal-spam.fr/) — signalement de spam en France
- [APWG eCrime Reports](https://apwg.org/resources/apwg-reports/) — rapports sur le phishing
