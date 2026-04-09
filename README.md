# 🛡 PhishGuard — Détecteur de Phishing Statique

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-00ff87?style=flat-square"/>
  <img src="https://img.shields.io/badge/langage-JavaScript%20pur-f7df1e?style=flat-square"/>
  <img src="https://img.shields.io/badge/API-aucune-00c96a?style=flat-square"/>
  <img src="https://img.shields.io/badge/IA-aucune-00c96a?style=flat-square"/>
  <img src="https://img.shields.io/badge/données%20transmises-zéro-00c96a?style=flat-square"/>
  <img src="https://img.shields.io/badge/licence-MIT-blue?style=flat-square"/>
</p>

> Outil open-source d'analyse statique d'emails et d'URLs pour détecter les tentatives de phishing.  
> **100 % local — aucune IA — aucune API — aucune donnée transmise.**

---

## Sommaire

- [Aperçu](#aperçu)
- [Fonctionnement](#fonctionnement)
- [Architecture du projet](#architecture-du-projet)
- [Moteur de détection](#moteur-de-détection)
- [Score de risque](#score-de-risque)
- [Indicateurs analysés](#indicateurs-analysés)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Tests](#tests)
- [Structure des fichiers](#structure-des-fichiers)
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

L'analyse s'effectue entièrement dans le navigateur. Aucune donnée ne quitte l'appareil de l'utilisateur.

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
    │                  ▼                                  │
    │    Génération des recommandations                   │
    └──────────────────┬──────────────────────────────────┘
                       │
                       ▼
             Objet AnalyseResult
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
│   └── tests.js        ← Suite de tests unitaires (~40 tests)
│
└── docs/
    ├── ARCHITECTURE.md ← Documentation technique détaillée
    └── TESTS.md        ← Résultats et méthodologie de tests
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

Le fichier `detector.js` est organisé en **5 sections** clairement délimitées :

### Section 1 — Listes statiques

Trois ensembles de données de référence :

| Liste | Description | Source |
|-------|-------------|--------|
| `DOMAINES_PHISHING` | Set de domaines frauduleux connus | PhishTank, OpenPhish, APWG |
| `MARQUES_USURPEES` | Marques fréquemment imitées (PayPal, Amazon…) | Études APWG |
| `TLD_RISQUE` | Extensions de domaine à risque (.xyz, .tk…) | Rapport Spamhaus |

### Section 2 — Expressions régulières

12 regex compilées une seule fois pour la performance :

```
REGEX.url             → Extraction des URLs dans un texte
REGEX.ipDansUrl       → IP directe dans une URL (http://1.2.3.4/...)
REGEX.arobaseUrl      → "@" dans l'URL pour masquer le domaine
REGEX.urlRaccourcie   → Services bit.ly, tinyurl, etc.
REGEX.encodageUrl     → Séquences %XX d'obfuscation
REGEX.multiTiretDomaine → paypal-secure-login-update.com
REGEX.leetspeak       → paypa1, amaz0n
REGEX.urlLongue       → URLs > 80 caractères
REGEX.email           → Extraction des adresses email
REGEX.piecesJointes   → Extensions dangereuses (.exe, .zip, .docm…)
REGEX.rappelTel       → Numéro + demande d'appel urgent
REGEX.hrefTrompeur    → Lien HTML avec texte ≠ href
```

### Section 3 — Les 4 analyseurs spécialisés

Chaque analyseur est une **fonction pure** qui retourne `{ score, indicateurs[] }` :

```
analyserURLs(texte)
  ├── Vérifie chaque URL trouvée dans le texte
  ├── Tests : IP directe, "@", raccourcisseur, longueur,
  │           encodage, liste noire, TLD, marque usurpée,
  │           leetspeak, HTTP sans S
  └── Score partiel : jusqu'à ~100 pts

analyserLangage(texte)
  ├── Recherche des mots-clés d'urgence (critique & warning)
  ├── Demandes de données sensibles (carte, PIN, IBAN…)
  ├── Pièces jointes dangereuses
  └── Demande de rappel téléphonique urgent

analyserExpediteur(texte)
  ├── Extraction des adresses email du texte
  ├── Détection des imitations de marques dans les domaines
  ├── TLD à risque pour les expéditeurs
  └── Reply-To ≠ From (technique de détournement)

analyserEnTetes(texte)
  ├── SPF : fail → +20, pass → indicateur positif
  ├── DKIM : none/fail → +15
  ├── DMARC : fail → +15
  ├── Received from IP directe → +10
  └── X-Mailer suspect (PHPMailer, mass mailer) → +10
```

### Section 4 — Agrégation et score final

```
score_brut = somme(scores de tous les analyseurs)
score_final = min(score_brut, 100)          ← plafonnement

niveauRisque :
  0  ≤ score < 34  → "safe"    (vert)
  34 ≤ score < 67  → "warning" (jaune)
  67 ≤ score ≤ 100 → "danger"  (rouge)
```

---

## Score de risque

### Tableau des points par indicateur

| Indicateur | Type | Points |
|------------|------|--------|
| Domaine en liste noire | Critique | +50 |
| IP directe dans URL | Critique | +30 |
| Langage d'urgence critique | Critique | +10–30 |
| Données sensibles demandées | Critique | +15–40 |
| Marque usurpée dans sous-domaine | Critique | +20 |
| Reply-To ≠ From | Critique | +20 |
| Pièce jointe dangereuse | Critique | +20 |
| SPF fail | Critique | +20 |
| "@" dans URL | Critique | +25 |
| Expéditeur imite une marque | Critique | +25 |
| DKIM fail | Warning | +15 |
| DMARC fail | Warning | +15 |
| URL raccourcie | Warning | +15 |
| Rappel téléphonique urgent | Warning | +15 |
| Marque dans chemin d'URL | Warning | +12 |
| Obfuscation URL (>5 %XX) | Warning | +12 |
| TLD à risque | Warning | +8 |
| Domaine à multiples tirets | Warning | +8 |
| HTTP sans S | Warning | +8 |
| Leetspeak dans domaine | Warning | +10 |
| URL > 80 caractères | Warning | +10 |
| TLD expéditeur à risque | Warning | +10 |

---

## Indicateurs analysés

### Catégorie URL

Toute URL détectée dans le texte est soumise à une série de vérifications :

```
URL extraite
    │
    ├─► IP directe ?          → critique (+30)
    ├─► "@" présent ?         → critique (+25)
    ├─► Dans liste noire ?    → critique (+50)
    ├─► Marque dans sous-dom? → critique (+20)
    │
    ├─► URL raccourcie ?      → warning (+15)
    ├─► > 80 caractères ?     → warning (+10)
    ├─► > 5 séquences %XX ?   → warning (+12)
    ├─► TLD à risque ?        → warning (+8)
    ├─► Multiples tirets ?    → warning (+8)
    ├─► Leetspeak ?           → warning (+10)
    └─► HTTP sans S ?         → warning (+8)
```

### Catégorie Langage

Analyse du texte pour identifier les techniques de manipulation psychologique :

```
Texte en minuscules
    │
    ├─► Mots-clés urgence critique :
    │   "compte suspendu", "dans les 24 heures",
    │   "action requise immédiatement"…      → critique (+10/mot, max +30)
    │
    ├─► Mots-clés incitatifs :
    │   "cliquez ici", "mise à jour requise"… → warning (+5/mot, max +20)
    │
    ├─► Données sensibles demandées :
    │   "carte bancaire", "code PIN", "IBAN"… → critique (+15/mot, max +40)
    │
    ├─► Extension dangereuse : .exe, .zip…    → critique (+20)
    └─► Numéro + demande d'appel urgent       → warning (+15)
```

---

## Installation

Aucune dépendance, aucun serveur requis. Trois options :

### Option 1 — Ouverture directe (la plus simple)

```bash
# Cloner le dépôt
git clone https://github.com/votre-username/phishguard.git
cd phishguard

# Ouvrir directement dans le navigateur
open index.html          # macOS
xdg-open index.html      # Linux
start index.html         # Windows
```

### Option 2 — Serveur local (recommandé)

```bash
# Python 3
python -m http.server 8080
# → http://localhost:8080

# Node.js (avec npx)
npx serve .
# → http://localhost:3000
```

### Option 3 — Via GitHub Pages

Forkez le dépôt, activez GitHub Pages dans les paramètres du dépôt → branche `main`, dossier racine.

---

## Utilisation

### Analyser un email

1. Ouvrez PhishGuard dans votre navigateur
2. L'onglet **Email / Texte** est actif par défaut
3. Copiez l'intégralité de l'email (en-têtes inclus si disponibles)
4. Collez-le dans la zone de texte
5. Cliquez sur **Analyser** (ou `Ctrl+Entrée`)

> **Astuce :** Inclure les en-têtes techniques (From, Reply-To, Authentication-Results) améliore significativement la précision de l'analyse.

### Analyser une URL

1. Cliquez sur l'onglet **URL**
2. Entrez l'URL suspecte dans le champ
3. Appuyez sur `Entrée` ou cliquez sur **Analyser**

> ⚠ **Important :** N'ouvrez jamais l'URL dans votre navigateur avant de l'avoir analysée.

### Lire les résultats

```
┌────────────────────────────────────────────┐
│           RÉSULTATS D'ANALYSE              │
│                                            │
│  ┌──────┐  🚨 Phishing !                  │
│  │  87  │  Très forte probabilité de       │
│  │ /100 │  tentative de phishing.          │
│  └──────┘                                  │
│                                            │
│  [Safe ─────────────────────────●─] Danger │
│                                            │
│  INDICATEURS DÉTECTÉS                      │
│  ┌─────────────────────────────────────┐   │
│  │ CRITIQUE  IP directe dans URL  +30  │   │
│  │ CRITIQUE  Données sensibles     +25  │   │
│  │ SUSPECT   URL raccourcie        +15  │   │
│  └─────────────────────────────────────┘   │
│                                            │
│  RECOMMANDATIONS                           │
│  › Ne cliquez sur aucun lien              │
│  › Signalez à signal-spam.fr              │
└────────────────────────────────────────────┘
```

---

## Tests

### Lancer les tests dans le navigateur

```bash
# Ouvrir la page de tests
open tests/index.html
```

### Lancer les tests en Node.js

```bash
# Depuis la racine du projet
node tests/tests.js
```

### Résultats attendus

```
📦 Score global — emails légitimes
  ✅ Email légitime simple doit avoir un score < 34
  ✅ Email newsletter légitime doit avoir un score < 20
  ✅ Niveau de risque d'un email légitime est "safe"

📦 Score global — emails de phishing
  ✅ Email phishing critique doit avoir un score ≥ 67
  ✅ Email phishing critique → niveau "danger"
  ✅ Email phishing modéré doit avoir un score ≥ 34
  ✅ Score maximal plafonné à 100

[... 40 tests au total ...]

══════════════════════════════════════════════════
📊 RAPPORT DE TESTS : 40/40 réussis
✅ Tous les tests sont passés !
══════════════════════════════════════════════════
```

### Couverture des tests

| Suite | Tests | Couverture |
|-------|-------|------------|
| Score global — emails légitimes | 3 | Faux positifs |
| Score global — emails de phishing | 4 | Détection correcte |
| Détection URL — IP directe | 2 | REGEX.ipDansUrl |
| Détection URL — liste noire | 2 | DOMAINES_PHISHING |
| Détection URL — arobase | 1 | REGEX.arobaseUrl |
| Détection URL — raccourcisseur | 1 | REGEX.urlRaccourcie |
| Détection URL — TLD à risque | 1 | TLD_RISQUE |
| Détection URL — URL longue | 1 | REGEX.urlLongue |
| Détection URL — URL légitime | 2 | Faux positifs URL |
| Langage — urgence | 2 | MOTS_CLES_URGENCE |
| Langage — données sensibles | 3 | MOTS_CLES_DONNEES_SENSIBLES |
| Langage — pièces jointes | 2 | REGEX.piecesJointes |
| Expéditeur — imitation | 1 | analyserExpediteur |
| Expéditeur — Reply-To | 1 | Détection Reply-To |
| En-têtes — SPF/DKIM/DMARC | 4 | analyserEnTetes |
| Structure du résultat | 4 | Contrat de l'API |
| Cas limites | 3 | Entrées vides/minimales |

---

## Structure des fichiers

### `detector.js` — Moteur de détection

```
PhishDetector (IIFE)
│
├── SECTION 1 — Listes statiques
│   ├── DOMAINES_PHISHING (Set)
│   ├── MARQUES_USURPEES (Array)
│   └── TLD_RISQUE (Array)
│
├── SECTION 2 — Expressions régulières (REGEX)
│
├── SECTION 3 — Analyseurs spécialisés
│   ├── analyserURLs(texte) → { score, indicateurs }
│   ├── analyserLangage(texte) → { score, indicateurs }
│   ├── analyserExpediteur(texte) → { score, indicateurs }
│   └── analyserEnTetes(texte) → { score, indicateurs }
│
├── SECTION 4 — Agrégation
│   ├── construireCategories(indicateurs) → CategorieResult[]
│   └── genererRecommandations(score, indicateurs) → string[]
│
└── SECTION 5 — API publique
    └── analyze(texte, mode) → AnalyseResult
```

### `ui.js` — Interface utilisateur

```
(IIFE)
│
├── SECTION 1 — Références DOM
├── SECTION 2 — État interne (modeActif)
├── SECTION 3 — Gestion des onglets
├── SECTION 4 — Lecture du texte saisi
├── SECTION 5 — Fonctions de rendu
│   ├── afficherBlocsResultats()
│   ├── réinitialiserAffichage()
│   ├── animerScoreCercle(score)
│   ├── animerBarreRisque(score)
│   ├── appliquerCouleurRisque(niveau)
│   ├── renderIndicateurs(indicateurs)
│   ├── renderCategories(categories)
│   └── renderRecommandations(recommandations)
├── SECTION 6 — Flux d'analyse principal
│   └── lancerAnalyse()
├── SECTION 7 — Utilitaires
│   └── escapeHTML(str)  ← Protection anti-XSS
└── SECTION 8 — Écouteurs d'événements
```

---

## Choix techniques

### Pourquoi JavaScript pur (vanilla) ?

- **Zéro dépendance** : pas de `npm install`, pas de risque de supply chain attack
- **Portable** : un seul fichier HTML suffit pour distribuer l'outil
- **Transparence** : le code est directement lisible dans les DevTools du navigateur
- **Performance** : analyse instantanée, pas de requête réseau

### Pourquoi le pattern IIFE ?

```javascript
const PhishDetector = (() => {
  // Code privé...
  return { analyze }; // Seule l'API publique est exposée
})();
```

Le pattern IIFE (Immediately Invoked Function Expression) permet :
- **Encapsulation** : les variables internes ne polluent pas le scope global
- **Module pattern** : seule la méthode `analyze()` est accessible depuis l'extérieur
- **Testabilité** : l'API publique est un contrat clair et stable

### Pourquoi des analyseurs séparés ?

Chaque analyseur est une **fonction pure** (entrée → sortie, sans effet de bord) :
- Facile à tester de manière unitaire
- Facile à étendre (ajouter un analyseur ne touche pas les autres)
- Facile à déboguer (isolation des responsabilités)

### Protection XSS

Tout contenu utilisateur injecté dans le DOM via `innerHTML` est préalablement passé par `escapeHTML()` qui neutralise les 5 caractères HTML sensibles (`&`, `<`, `>`, `"`, `'`).

---

## Roadmap

- [ ] Analyse des liens HTML (href ≠ texte affiché)
- [ ] Import de fichier `.eml`
- [ ] Export du rapport en PDF
- [ ] Base de données de domaines mise à jour automatiquement (GitHub Actions)
- [ ] Extension navigateur Chrome/Firefox
- [ ] Analyse de QR codes (image → URL → analyse)
- [ ] Mode sombre / clair
- [ ] Localisation EN/FR

---

## Licence

MIT — Voir [LICENSE](LICENSE) pour les détails.

---

## Ressources

- [PhishTank](https://www.phishtank.com/) — base de données de phishing
- [signal-spam.fr](https://www.signal-spam.fr/) — signalement de spam en France
- [APWG eCrime Reports](https://apwg.org/resources/apwg-reports/) — rapports sur le phishing
- [Google Safe Browsing](https://safebrowsing.google.com/) — pour aller plus loin

---

<p align="center">
  Fait avec rigueur · Aucune donnée transmise · <a href="https://github.com/votre-username/phishguard">GitHub</a>
</p>
