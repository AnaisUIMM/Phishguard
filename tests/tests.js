/**
 * PhishGuard — Suite de tests
 * ============================
 * Fichier : tests/tests.js
 * Description : Tests unitaires du moteur de détection PhishDetector.
 *               Framework maison minimaliste (pas de dépendance externe).
 *               À exécuter dans le navigateur via tests/index.html
 *               ou en Node.js avec : node tests/tests.js
 */

/* ==========================================================
   MICRO-FRAMEWORK DE TEST
   API : describe(nom, fn), it(nom, fn), expect(valeur)
========================================================== */

const résultatsTests = [];
let suiteCourante = '';

function describe(nom, fn) {
  suiteCourante = nom;
  console.group(`\n📦 ${nom}`);
  fn();
  console.groupEnd();
}

function it(description, fn) {
  try {
    fn();
    résultatsTests.push({ suite: suiteCourante, description, statut: 'PASS' });
    console.log(`  ✅ ${description}`);
  } catch (err) {
    résultatsTests.push({ suite: suiteCourante, description, statut: 'FAIL', erreur: err.message });
    console.error(`  ❌ ${description}\n     → ${err.message}`);
  }
}

function expect(valeur) {
  return {
    toBe(attendu) {
      if (valeur !== attendu) {
        throw new Error(`Attendu: ${JSON.stringify(attendu)}, Obtenu: ${JSON.stringify(valeur)}`);
      }
    },
    toBeGreaterThan(min) {
      if (valeur <= min) {
        throw new Error(`Attendu > ${min}, Obtenu: ${valeur}`);
      }
    },
    toBeLessThan(max) {
      if (valeur >= max) {
        throw new Error(`Attendu < ${max}, Obtenu: ${valeur}`);
      }
    },
    toBeLessThanOrEqual(max) {
      if (valeur > max) {
        throw new Error(`Attendu ≤ ${max}, Obtenu: ${valeur}`);
      }
    },
    toBeGreaterThanOrEqual(min) {
      if (valeur < min) {
        throw new Error(`Attendu ≥ ${min}, Obtenu: ${valeur}`);
      }
    },
    toContain(element) {
      if (!valeur.includes(element)) {
        throw new Error(`Attendu que la liste contienne "${element}"`);
      }
    },
    toHaveLength(longueur) {
      if (valeur.length !== longueur) {
        throw new Error(`Longueur attendue: ${longueur}, Obtenu: ${valeur.length}`);
      }
    },
    toBeTruthy() {
      if (!valeur) throw new Error(`Attendu truthy, Obtenu: ${valeur}`);
    },
    toBeFalsy() {
      if (valeur) throw new Error(`Attendu falsy, Obtenu: ${valeur}`);
    },
  };
}

/* ==========================================================
   CHARGEMENT DU MODULE (environnements Node.js / navigateur)
========================================================== */

// En Node.js, on charge le fichier via require
if (typeof PhishDetector === 'undefined') {
  try {
    // Node.js
    global.PhishDetector = require('../detector.js');
  } catch {
    console.error('Impossible de charger detector.js. Assurez-vous d\'être dans le dossier tests/.');
    process.exit(1);
  }
}

/* ==========================================================
   JEUX DE DONNÉES DE TEST
========================================================== */

// ── Emails légitimes (scores attendus bas) ─────────────────

const EMAIL_LEGITIME_SIMPLE = `
From: support@amazon.com
To: client@gmail.com
Subject: Votre commande a bien été expédiée

Bonjour,
Votre commande #123-456-789 a été expédiée.
Suivez-la sur : https://www.amazon.com/gp/your-account/order-history

Cordialement,
L'équipe Amazon
`;

const EMAIL_NEWSLETTER = `
From: newsletter@lemonde.fr
Subject: Les titres du jour

Bonjour,
Retrouvez nos articles sur https://www.lemonde.fr/

— La rédaction
`;

// ── Emails de phishing évidents ────────────────────────────

const EMAIL_PHISHING_CRITIQUE = `
From: noreply@paypa1-secure.xyz
Reply-To: hacker@evil.ru
Subject: URGENT - Votre compte PayPal a été suspendu

Votre compte a été suspendu en raison d'une activité suspecte.
Vérifiez immédiatement vos informations dans les 24 heures sinon
votre compte sera fermé définitivement.

Entrez votre numéro de carte bancaire et votre code PIN ici :
http://192.168.1.1/paypal-secure-login-verify.php

Cordialement,
L'équipe PayPal
`;

const EMAIL_PHISHING_MODERE = `
From: info@amazon-security.net
Subject: Mise à jour requise

Cher client,
Veuillez mettre à jour vos informations pour continuer.
Cliquez ici : https://amazon-security.net/update

Merci,
Amazon
`;

// ── URLs de test ───────────────────────────────────────────

const URL_LEGITIME   = 'https://www.google.com/search?q=test';
const URL_IP_DIRECTE = 'http://192.168.1.100/paypal/login';
const URL_PHISHING_DOMAINE = 'https://paypa1.com/login';
const URL_AROB_MASQUEE     = 'https://google.com@evil.com/phish';
const URL_RACCOURCIE       = 'https://bit.ly/3xFake1';
const URL_TLD_RISQUE       = 'https://amazon-secure-update.xyz/login';
const URL_LONGUE           = 'https://legitime.com/' + 'a'.repeat(100);

/* ==========================================================
   SUITE 1 — SCORES GLOBAUX
========================================================== */

describe('Score global — emails légitimes', () => {

  it('Email légitime simple doit avoir un score < 34', () => {
    const r = PhishDetector.analyze(EMAIL_LEGITIME_SIMPLE, 'email');
    expect(r.score).toBeLessThan(34);
  });

  it('Email newsletter légitime doit avoir un score < 20', () => {
    const r = PhishDetector.analyze(EMAIL_NEWSLETTER, 'email');
    expect(r.score).toBeLessThan(20);
  });

  it('Niveau de risque d\'un email légitime est "safe"', () => {
    const r = PhishDetector.analyze(EMAIL_LEGITIME_SIMPLE, 'email');
    expect(r.niveauRisque).toBe('safe');
  });

});

describe('Score global — emails de phishing', () => {

  it('Email phishing critique doit avoir un score ≥ 67', () => {
    const r = PhishDetector.analyze(EMAIL_PHISHING_CRITIQUE, 'email');
    expect(r.score).toBeGreaterThanOrEqual(67);
  });

  it('Email phishing critique → niveau "danger"', () => {
    const r = PhishDetector.analyze(EMAIL_PHISHING_CRITIQUE, 'email');
    expect(r.niveauRisque).toBe('danger');
  });

  it('Email phishing modéré doit avoir un score ≥ 34', () => {
    const r = PhishDetector.analyze(EMAIL_PHISHING_MODERE, 'email');
    expect(r.score).toBeGreaterThanOrEqual(34);
  });

  it('Score maximal plafonné à 100', () => {
    const r = PhishDetector.analyze(EMAIL_PHISHING_CRITIQUE, 'email');
    expect(r.score).toBeLessThanOrEqual(100);
  });

});

/* ==========================================================
   SUITE 2 — DÉTECTION D'URLs
========================================================== */

describe('Détection URL — IP directe', () => {

  it('URL avec IP directe doit déclencher un indicateur critique', () => {
    const r = PhishDetector.analyze(URL_IP_DIRECTE, 'url');
    const ind = r.indicateurs.find(i => i.message.includes('adresse IP directe'));
    expect(ind).toBeTruthy();
  });

  it('URL avec IP directe → score > 25', () => {
    const r = PhishDetector.analyze(URL_IP_DIRECTE, 'url');
    expect(r.score).toBeGreaterThan(25);
  });

});

describe('Détection URL — domaine liste noire', () => {

  it('paypa1.com dans la liste noire → indicateur critique', () => {
    const r = PhishDetector.analyze(URL_PHISHING_DOMAINE, 'url');
    const ind = r.indicateurs.find(i => i.message.includes('liste noire'));
    expect(ind).toBeTruthy();
  });

  it('paypa1.com → score ≥ 50', () => {
    const r = PhishDetector.analyze(URL_PHISHING_DOMAINE, 'url');
    expect(r.score).toBeGreaterThanOrEqual(50);
  });

});

describe('Détection URL — arobase dans URL', () => {

  it('URL avec "@" pour masquer le vrai domaine → indicateur critique', () => {
    const r = PhishDetector.analyze(URL_AROB_MASQUEE, 'url');
    const ind = r.indicateurs.find(i => i.message.includes('@'));
    expect(ind).toBeTruthy();
  });

});

describe('Détection URL — raccourcisseur', () => {

  it('URL bit.ly → indicateur warning', () => {
    const r = PhishDetector.analyze(URL_RACCOURCIE, 'url');
    const ind = r.indicateurs.find(i => i.message.includes('raccourcie'));
    expect(ind).toBeTruthy();
  });

});

describe('Détection URL — TLD à risque', () => {

  it('Domaine en .xyz → indicateur TLD à risque', () => {
    const r = PhishDetector.analyze(URL_TLD_RISQUE, 'url');
    const ind = r.indicateurs.find(i => i.message.includes('.xyz'));
    expect(ind).toBeTruthy();
  });

});

describe('Détection URL — URL très longue', () => {

  it('URL > 80 caractères → indicateur warning', () => {
    const r = PhishDetector.analyze(URL_LONGUE, 'url');
    const ind = r.indicateurs.find(i => i.message.includes('longue'));
    expect(ind).toBeTruthy();
  });

});

describe('Détection URL — URL légitime Google', () => {

  it('URL Google légitime → score < 20', () => {
    const r = PhishDetector.analyze(URL_LEGITIME, 'url');
    expect(r.score).toBeLessThan(20);
  });

  it('URL Google légitime → niveau safe', () => {
    const r = PhishDetector.analyze(URL_LEGITIME, 'url');
    expect(r.niveauRisque).toBe('safe');
  });

});

/* ==========================================================
   SUITE 3 — DÉTECTION DU LANGAGE
========================================================== */

describe('Détection du langage — urgence', () => {

  it('"Votre compte sera fermé" → indicateur critique', () => {
    const r = PhishDetector.analyze('Votre compte sera fermé dans les 24 heures.', 'email');
    const ind = r.indicateurs.find(i => i.type === 'critical' && i.categorie === 'Langage');
    expect(ind).toBeTruthy();
  });

  it('"Cliquez ici" → indicateur warning', () => {
    const r = PhishDetector.analyze('Cliquez ici pour mettre à jour.', 'email');
    const ind = r.indicateurs.find(i => i.categorie === 'Langage' && i.type === 'warning');
    expect(ind).toBeTruthy();
  });

});

describe('Détection du langage — données sensibles', () => {

  it('Demande de numéro de carte bancaire → indicateur critique', () => {
    const r = PhishDetector.analyze('Entrez votre numéro de carte bancaire pour vérifier.', 'email');
    const ind = r.indicateurs.find(i => i.message.includes('sensibles'));
    expect(ind).toBeTruthy();
  });

  it('Demande de mot de passe → indicateur critique', () => {
    const r = PhishDetector.analyze('Réinitialisez votre mot de passe ici.', 'email');
    const ind = r.indicateurs.find(i => i.message.includes('sensibles'));
    expect(ind).toBeTruthy();
  });

  it('Demande de code PIN → score élevé', () => {
    const r = PhishDetector.analyze('Entrez votre code PIN et votre IBAN.', 'email');
    expect(r.score).toBeGreaterThan(20);
  });

});

describe('Détection du langage — pièces jointes dangereuses', () => {

  it('Mention de fichier .exe → indicateur critique', () => {
    const r = PhishDetector.analyze('Ouvrez le fichier facture.exe ci-joint.', 'email');
    const ind = r.indicateurs.find(i => i.message.includes('.exe'));
    expect(ind).toBeTruthy();
  });

  it('Mention de fichier .docm → indicateur critique', () => {
    const r = PhishDetector.analyze('Votre document.docm est prêt.', 'email');
    const ind = r.indicateurs.find(i => i.type === 'critical' && i.categorie === 'Langage');
    expect(ind).toBeTruthy();
  });

});

/* ==========================================================
   SUITE 4 — ANALYSE DE L'EXPÉDITEUR
========================================================== */

describe('Analyse expéditeur — imitation de marque', () => {

  it('Expéditeur paypal@paypa1-secure.xyz → indicateur critique', () => {
    const r = PhishDetector.analyze('From: paypal@paypa1-secure.xyz', 'email');
    const ind = r.indicateurs.find(i => i.type === 'critical' && i.categorie === 'Expéditeur');
    expect(ind).toBeTruthy();
  });

});

describe('Analyse expéditeur — Reply-To différent', () => {

  it('From et Reply-To sur domaines différents → indicateur critique', () => {
    const texte = `From: support@amazon.com\nReply-To: attacker@evil.xyz\nSujet: Test`;
    const r = PhishDetector.analyze(texte, 'email');
    const ind = r.indicateurs.find(i => i.message.includes('Reply-To'));
    expect(ind).toBeTruthy();
  });

});

/* ==========================================================
   SUITE 5 — ANALYSE DES EN-TÊTES
========================================================== */

describe('Analyse en-têtes — SPF/DKIM/DMARC', () => {

  it('SPF fail → indicateur critique', () => {
    const r = PhishDetector.analyze('Authentication-Results: spf=fail', 'email');
    const ind = r.indicateurs.find(i => i.message.includes('SPF'));
    expect(ind).toBeTruthy();
  });

  it('DKIM none → indicateur warning', () => {
    const r = PhishDetector.analyze('Authentication-Results: dkim=none', 'email');
    const ind = r.indicateurs.find(i => i.message.includes('DKIM'));
    expect(ind).toBeTruthy();
  });

  it('SPF pass → indicateur info (non critique)', () => {
    const r = PhishDetector.analyze('Authentication-Results: spf=pass dkim=pass', 'email');
    const ind = r.indicateurs.find(i => i.message.includes('SPF valide'));
    expect(ind).toBeTruthy();
  });

  it('DMARC fail → indicateur warning', () => {
    const r = PhishDetector.analyze('Authentication-Results: dmarc=fail', 'email');
    const ind = r.indicateurs.find(i => i.message.includes('DMARC'));
    expect(ind).toBeTruthy();
  });

});

/* ==========================================================
   SUITE 6 — STRUCTURE DES RÉSULTATS
========================================================== */

describe('Structure du résultat', () => {

  it('Le résultat contient score, niveauRisque, verdict, indicateurs, categories, recommandations', () => {
    const r = PhishDetector.analyze('Test', 'email');
    expect(typeof r.score).toBe('number');
    expect(typeof r.niveauRisque).toBe('string');
    expect(typeof r.verdict).toBe('object');
    expect(Array.isArray(r.indicateurs)).toBe(true);
    expect(Array.isArray(r.categories)).toBe(true);
    expect(Array.isArray(r.recommandations)).toBe(true);
  });

  it('niveauRisque est "safe", "warning" ou "danger"', () => {
    const niveaux = ['safe', 'warning', 'danger'];
    const r = PhishDetector.analyze('Test', 'email');
    expect(niveaux).toContain(r.niveauRisque);
  });

  it('Le verdict contient emoji, texte et sub', () => {
    const r = PhishDetector.analyze('Test', 'email');
    expect(typeof r.verdict.emoji).toBe('string');
    expect(typeof r.verdict.texte).toBe('string');
    expect(typeof r.verdict.sub).toBe('string');
  });

  it('Les recommandations ne sont jamais vides', () => {
    const r = PhishDetector.analyze('Test', 'email');
    expect(r.recommandations.length).toBeGreaterThan(0);
  });

});

describe('Cas limites — entrées vides ou minimales', () => {

  it('Texte vide → score = 0', () => {
    const r = PhishDetector.analyze('', 'email');
    expect(r.score).toBe(0);
  });

  it('URL vide → score = 0', () => {
    const r = PhishDetector.analyze('', 'url');
    expect(r.score).toBe(0);
  });

  it('Texte sans indicateur → niveau safe', () => {
    const r = PhishDetector.analyze('Bonjour, comment allez-vous ?', 'email');
    expect(r.niveauRisque).toBe('safe');
  });

});

/* ==========================================================
   RAPPORT FINAL
========================================================== */

const total   = résultatsTests.length;
const réussis = résultatsTests.filter(t => t.statut === 'PASS').length;
const échoués = total - réussis;

console.log('\n' + '═'.repeat(50));
console.log(`📊 RAPPORT DE TESTS : ${réussis}/${total} réussis`);
if (échoués > 0) {
  console.log(`\n❌ Tests échoués :`);
  résultatsTests.filter(t => t.statut === 'FAIL').forEach(t => {
    console.log(`  • [${t.suite}] ${t.description}`);
    console.log(`    → ${t.erreur}`);
  });
} else {
  console.log('✅ Tous les tests sont passés !');
}
console.log('═'.repeat(50));

// Export pour Node.js
if (typeof module !== 'undefined') {
  module.exports = { résultatsTests, réussis, total };
}
