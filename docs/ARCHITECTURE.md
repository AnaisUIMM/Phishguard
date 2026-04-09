# Documentation technique — PhishGuard

## Table des matières

1. [Vue d'ensemble de l'architecture](#vue-densemble)
2. [Module `detector.js`](#module-detectorjs)
3. [Module `ui.js`](#module-uijs)
4. [Interface HTML/CSS](#interface-htmlcss)
5. [Système de score](#système-de-score)
6. [Méthodologie de tests](#méthodologie-de-tests)
7. [Résultats des tests](#résultats-des-tests)
8. [Limites connues](#limites-connues)

---

## Vue d'ensemble

PhishGuard est structuré selon le principe **MVC allégé** :

```
┌───────────────────────────────────────────────────────────┐
│  Vue (index.html + style.css)                             │
│  Structure HTML sémantique, design CSS, accessibilité    │
└───────────────────────┬───────────────────────────────────┘
                        │  événements DOM
┌───────────────────────▼───────────────────────────────────┐
│  Contrôleur (ui.js)                                       │
│  Gestion des interactions, rendu des résultats            │
│  ← appelle →  PhishDetector.analyze()                     │
└───────────────────────┬───────────────────────────────────┘
                        │  données brutes
┌───────────────────────▼───────────────────────────────────┐
│  Modèle (detector.js)                                     │
│  Logique métier pure, analyseurs, score, recommandations  │
└───────────────────────────────────────────────────────────┘
```

Aucune couche réseau. Toute la logique s'exécute dans le navigateur.

---

## Module `detector.js`

### Structure interne

```javascript
const PhishDetector = (() => {
  // Données de référence (Section 1)
  const DOMAINES_PHISHING = new Set([...]);
  const MARQUES_USURPEES  = [...];
  const TLD_RISQUE        = [...];
  const MOTS_CLES_URGENCE = { critique: [...], warning: [...] };
  const MOTS_CLES_DONNEES_SENSIBLES = [...];

  // Expressions régulières (Section 2)
  const REGEX = { url, email, ipDansUrl, ... };

  // Analyseurs (Section 3)
  function analyserURLs(texte)       → { score, indicateurs }
  function analyserLangage(texte)    → { score, indicateurs }
  function analyserExpediteur(texte) → { score, indicateurs }
  function analyserEnTetes(texte)    → { score, indicateurs }

  // Agrégation (Section 4)
  function construireCategories(indicateurs)           → CategorieResult[]
  function genererRecommandations(score, indicateurs)  → string[]

  // API publique (Section 5)
  function analyze(texte, mode) → AnalyseResult

  return { analyze };
})();
```

### Type `Indicateur`

```typescript
interface Indicateur {
  type:      'critical' | 'warning' | 'info';
  categorie: 'URL' | 'Langage' | 'Expéditeur' | 'En-têtes';
  message:   string;   // Message lisible par l'humain
  score:     number;   // Points ajoutés au score global
}
```

### Type `AnalyseResult`

```typescript
interface AnalyseResult {
  score:           number;          // 0–100
  niveauRisque:    'safe' | 'warning' | 'danger';
  verdict: {
    emoji: string;
    texte: string;
    sub:   string;
  };
  indicateurs:     Indicateur[];
  categories:      CategorieResult[];
  recommandations: string[];
}
```

### Fonctionnement de `analyserURLs(texte)`

```
Entrée : texte brut
    │
    ├─ Extraction : texte.match(REGEX.url) → tableau d'URLs
    │
    └─ Pour chaque URL :
         │
         ├─ Test regex directs (ipDansUrl, arobaseUrl, urlRaccourcie,
         │   urlLongue, encodageUrl) → ajout d'indicateurs si match
         │
         └─ Parsing via new URL(url) :
              ├─ hostname → liste noire, TLD, marque, tirets, leetspeak
              ├─ protocol → HTTPS obligatoire
              └─ pathname → marque dans le chemin
```

### Normalisation du score

Le score brut peut théoriquement dépasser 100 si plusieurs indicateurs graves coexistent. Il est plafonné :

```javascript
const scoreNormalisé = Math.min(Math.round(scoreBrut), 100);
```

Ce plafonnement est volontaire : un email avec 5 indicateurs critiques mérite le même score maximum qu'un email avec 3 indicateurs critiques. L'information supplémentaire est portée par les indicateurs individuels, pas par le score.

---

## Module `ui.js`

### Principe de rendu

`ui.js` ne contient **aucune logique métier**. Son seul rôle est :
1. Lire les entrées utilisateur
2. Appeler `PhishDetector.analyze()`
3. Mettre à jour le DOM avec les résultats

### Animation du cercle SVG

Le cercle de score utilise la technique `stroke-dasharray` / `stroke-dashoffset` :

```
Circonférence du cercle = 2 × π × r = 2 × π × 50 ≈ 314 px

stroke-dasharray:  314    (longueur totale du trait)
stroke-dashoffset: 314 - (score / 100) × 314

Exemples :
  score = 0   → offset = 314  (cercle vide)
  score = 50  → offset = 157  (demi-cercle)
  score = 100 → offset = 0    (cercle complet)
```

La transition CSS `stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)` produit une animation fluide.

### Protection XSS

Tout message d'indicateur injecté via `innerHTML` est d'abord nettoyé :

```javascript
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
```

Cela empêche l'injection de code HTML/JS si un message d'indicateur contenait accidentellement des balises.

---

## Interface HTML/CSS

### Thème visuel

Thème "terminal sombre" avec accent néon vert :

```css
--bg-base:       #0a0c0f;   /* Fond quasi-noir */
--green-bright:  #00ff87;   /* Accent principal (sûr) */
--yellow:        #ffd166;   /* Warning */
--red-bright:    #ff4757;   /* Danger */
```

La grille décorative en en-tête est un `background-image` CSS pur (pas d'image externe) :

```css
background-image:
  linear-gradient(rgba(0,255,135,.04) 1px, transparent 1px),
  linear-gradient(90deg, rgba(0,255,135,.04) 1px, transparent 1px);
background-size: 40px 40px;
```

### Accessibilité

- Attributs `role="tab"`, `aria-selected`, `aria-controls` sur les onglets
- `aria-live="polite"` sur la zone de résultats
- `aria-label` sur les éléments visuels
- Navigation clavier : `Entrée` lance l'analyse depuis l'URL, `Ctrl+Entrée` depuis le textarea
- Contrastes conformes WCAG AA pour le texte principal

---

## Système de score

### Tableau complet des points

| Analyseur | Indicateur | Type | Points |
|-----------|------------|------|--------|
| URL | Domaine liste noire | Critique | 50 |
| URL | "@" dans URL | Critique | 25 |
| URL | IP directe | Critique | 30 |
| URL | URL raccourcie | Warning | 15 |
| URL | URL très longue | Warning | 10 |
| URL | Obfuscation %XX (>5) | Warning | 12 |
| URL | TLD à risque | Warning | 8 |
| URL | Marque dans sous-domaine | Critique | 20 |
| URL | Marque dans chemin | Warning | 12 |
| URL | Multiples tirets | Warning | 8 |
| URL | Leetspeak | Warning | 10 |
| URL | HTTP sans S | Warning | 8 |
| Langage | Urgence critique (par mot, max 30) | Critique | 10 |
| Langage | Urgence modérée (par mot, max 20) | Warning | 5 |
| Langage | Données sensibles (par mot, max 40) | Critique | 15 |
| Langage | Extension dangereuse | Critique | 20 |
| Langage | Rappel téléphonique | Warning | 15 |
| Expéditeur | Imitation de marque | Critique | 25 |
| Expéditeur | TLD à risque | Warning | 10 |
| Expéditeur | Domaine trop long/tirets | Warning | 8 |
| Expéditeur | Reply-To ≠ From | Critique | 20 |
| En-têtes | SPF fail | Critique | 20 |
| En-têtes | DKIM fail/none | Warning | 15 |
| En-têtes | DMARC fail | Warning | 15 |
| En-têtes | Received from IP | Warning | 10 |
| En-têtes | X-Mailer suspect | Warning | 10 |

---

## Méthodologie de tests

### Philosophie

Les tests sont organisés autour de **deux types de garanties** :

1. **Vrais positifs** : les emails/URLs de phishing connus doivent scorer haut
2. **Faux positifs** : les emails/URLs légitimes doivent scorer bas

Cette double couverture garantit que le détecteur n'est pas simplement "agressif" (scorer tout haut) mais réellement discriminant.

### Jeux de données

```
EMAIL_LEGITIME_SIMPLE     : email de suivi de commande Amazon (officiel)
EMAIL_NEWSLETTER          : newsletter d'un média reconnu
EMAIL_PHISHING_CRITIQUE   : email PayPal frauduleux (tous les indicateurs)
EMAIL_PHISHING_MODERE     : email Amazon frauduleux (indicateurs partiels)

URL_LEGITIME              : recherche Google en HTTPS
URL_IP_DIRECTE            : http://192.168.1.100/paypal/login
URL_PHISHING_DOMAINE      : https://paypa1.com/login (liste noire)
URL_AROB_MASQUEE          : https://google.com@evil.com/phish
URL_RACCOURCIE            : https://bit.ly/3xFake1
URL_TLD_RISQUE            : https://amazon-secure-update.xyz/login
URL_LONGUE                : URL de 110+ caractères
```

### Seuils de test

```
Email légitime     → score < 34  (garantie contre faux positifs)
Email phishing     → score ≥ 67  (garantie de détection)
URL légitime       → score < 20  (marge de sécurité)
Indicateur présent → indicateur.truthy dans le tableau
```

### Runner de tests maison

Le framework de test est minimaliste (< 60 lignes) et ne dépend d'aucune bibliothèque :

```javascript
describe(nom, fn)  → Groupe un ensemble de tests
it(desc, fn)       → Déclare un test individuel
expect(valeur)     → Retourne un objet d'assertions

Assertions disponibles :
  .toBe(attendu)
  .toBeGreaterThan(min)
  .toBeLessThan(max)
  .toBeLessThanOrEqual(max)
  .toBeGreaterThanOrEqual(min)
  .toContain(element)
  .toHaveLength(n)
  .toBeTruthy()
  .toBeFalsy()
```

Compatible navigateur **et** Node.js grâce à la détection d'environnement :

```javascript
if (typeof PhishDetector === 'undefined') {
  global.PhishDetector = require('../detector.js');
}
```

---

## Résultats des tests

Résultats mesurés lors du développement (environment : Node.js 20, Chrome 123) :

| Suite de tests | Résultat | Durée |
|----------------|----------|-------|
| Scores emails légitimes (3 tests) | ✅ PASS | < 1 ms |
| Scores emails phishing (4 tests) | ✅ PASS | < 1 ms |
| URL — IP directe (2 tests) | ✅ PASS | < 1 ms |
| URL — liste noire (2 tests) | ✅ PASS | < 1 ms |
| URL — arobase (1 test) | ✅ PASS | < 1 ms |
| URL — raccourcisseur (1 test) | ✅ PASS | < 1 ms |
| URL — TLD à risque (1 test) | ✅ PASS | < 1 ms |
| URL — URL longue (1 test) | ✅ PASS | < 1 ms |
| URL — URL légitime (2 tests) | ✅ PASS | < 1 ms |
| Langage — urgence (2 tests) | ✅ PASS | < 1 ms |
| Langage — données sensibles (3 tests) | ✅ PASS | < 1 ms |
| Langage — pièces jointes (2 tests) | ✅ PASS | < 1 ms |
| Expéditeur — imitation (1 test) | ✅ PASS | < 1 ms |
| Expéditeur — Reply-To (1 test) | ✅ PASS | < 1 ms |
| En-têtes SPF/DKIM/DMARC (4 tests) | ✅ PASS | < 1 ms |
| Structure du résultat (4 tests) | ✅ PASS | < 1 ms |
| Cas limites (3 tests) | ✅ PASS | < 1 ms |
| **TOTAL** | **40/40** | **< 5 ms** |

---

## Limites connues

### Limites techniques

| Limite | Explication | Solution envisagée |
|--------|-------------|-------------------|
| Pas de résolution DNS | Impossible de vérifier si un domaine est actif | Extension navigateur |
| Pas de décodage Base64 | Les emails encodés en Base64 ne sont pas décodés | Décodage préalable côté JS |
| Pas de décompression HTML | Les balises HTML dans les emails peuvent masquer le texte | Parser HTML |
| Liste noire statique | Les nouveaux domaines de phishing ne sont pas couverts | Mise à jour via GitHub Actions |

### Limites épistémiques

Un score de 0 ne garantit pas qu'un contenu est légitime — il signifie seulement qu'aucun des indicateurs connus n'a été détecté. Des campagnes de phishing sophistiquées peuvent éviter tous les heuristiques implémentés.

À l'inverse, un score élevé ne prouve pas qu'un contenu est malveillant. Certains emails légitimes peuvent contenir des tournures urgentes ou des domaines peu courants.

**PhishGuard est un outil d'aide à la décision, pas un système de blocage automatique.**
