/**
 * PhishGuard — Moteur de détection de phishing
 * =============================================
 * Fichier : detector.js
 * Description : Analyse statique d'emails et d'URLs à l'aide de
 *               règles heuristiques, expressions régulières et
 *               listes noires statiques. Aucune IA, aucune API.
 *
 * Architecture : module objet unique `PhishDetector` exposant
 *                une méthode publique `analyze(texte, mode)`.
 */

const PhishDetector = (() => {

  /* ==========================================================
     SECTION 1 — LISTES STATIQUES
     Données de référence : domaines frauduleux connus,
     marques souvent usurpées, TLD à risque, etc.
  ========================================================== */

  /**
   * Domaines connus pour le phishing.
   * Source : compilées manuellement à partir de rapports publics
   * (PhishTank, OpenPhish, APWG).
   */
  const DOMAINES_PHISHING = new Set([
    'paypa1.com', 'paypa-l.com', 'pay-pal.com', 'paypalsecure.net',
    'secure-paypal.com', 'paypal-update.com',
    'amazon-security.net', 'amaz0n.com', 'amazon-alert.com',
    'apple-id-support.com', 'appleid-locked.com', 'apple-account.net',
    'microsoft-support.net', 'microsoftsecurity.com',
    'google-security-alert.com', 'gmail-verify.com',
    'facebook-security.com', 'fb-login-secure.com',
    'netflix-billing.net', 'netflix-update.com',
    'dhl-tracking-parcel.com', 'dhl-express.info',
    'fedex-delivery.net', 'ups-tracking.info',
    'impots-gouv.fr.secure-login.com',
    'caf-allocation.com', 'ameli-remboursement.com',
    'credit-agricole-secure.com', 'bnp-secure-login.com',
  ]);

  /**
   * Marques fréquemment usurpées dans les campagnes de phishing.
   * Leur présence dans un domaine différent de l'officiel est suspecte.
   */
  const MARQUES_USURPEES = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'impots', 'caf', 'ameli', 'sécurité sociale', 'pole emploi',
    'credit agricole', 'bnp', 'societe generale', 'lcl', 'caisse epargne',
    'sfr', 'orange', 'free', 'bouygues',
    'dhl', 'fedex', 'ups', 'laposte', 'colissimo',
  ];

  /**
   * Extensions de domaine (TLD) fréquemment associées au phishing.
   * Ces TLD ne sont pas malveillants en soi, mais leur présence
   * associée à d'autres indicateurs augmente le score.
   */
  const TLD_RISQUE = [
    '.xyz', '.top', '.club', '.online', '.site', '.info', '.biz',
    '.tk', '.ml', '.ga', '.cf', '.gq',  // TLD gratuits Freenom
    '.ru', '.cn', '.pw', '.cc', '.su',
  ];

  /**
   * Mots-clés à connotation urgente ou manipulatrice.
   * Classés par niveau : critique (score élevé) et warning (score modéré).
   */
  const MOTS_CLES_URGENCE = {
    critique: [
      'compte suspendu', 'compte bloqué', 'accès refusé',
      'activité suspecte', 'connexion inhabituelle',
      'vérifiez immédiatement', 'action requise immédiatement',
      'votre compte sera fermé', 'dans les 24 heures',
      'dans les 48 heures', 'urgent', 'immédiatement',
      'suspended account', 'account blocked', 'verify now',
      'immediate action required', 'your account will be closed',
    ],
    warning: [
      'cliquez ici', 'cliquer ici', 'mise à jour requise',
      'mettre à jour vos informations', 'confirmer votre identité',
      'vérifier votre compte', 'réinitialiser votre mot de passe',
      'click here', 'update your information', 'verify your account',
      'reset your password', 'confirm your identity',
      'félicitations', 'vous avez gagné', 'gagnant', 'prize', 'winner',
    ],
  };

  /**
   * Mots-clés liés aux informations sensibles demandées.
   * Aucun service légitime ne demande ces données par email.
   */
  const MOTS_CLES_DONNEES_SENSIBLES = [
    'numéro de carte', 'carte bancaire', 'carte de crédit', 'cvv', 'cvc',
    'code secret', 'code pin', 'mot de passe', 'password',
    'numéro de sécurité sociale', 'numéro de sécu',
    'rib', 'iban', 'bic', 'coordonnées bancaires',
    'credit card', 'card number', 'social security', 'bank account',
  ];

  /* ==========================================================
     SECTION 2 — EXPRESSIONS RÉGULIÈRES
     Patterns de détection compilés une seule fois.
  ========================================================== */

  const REGEX = {
    /** URL complète dans un texte */
    url: /https?:\/\/[^\s"'<>]+/gi,

    /** Adresse email */
    email: /[\w.+-]+@[\w-]+\.[\w.]+/gi,

    /** IP dans une URL (très suspect) */
    ipDansUrl: /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i,

    /** Sous-domaine trompeur : marque dans le sous-domaine, domaine différent */
    sousDomaineMarque: /https?:\/\/([\w-]+\.)*([a-z]+)\.([\w-]+)\.([\w.]+)/i,

    /** Encodage de caractères dans URL (obfuscation) */
    encodageUrl: /%[0-9a-fA-F]{2}/g,

    /** Redirection via service de raccourcissement */
    urlRaccourcie: /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.to|is\.gd|rb\.gy|cutt\.ly|buff\.ly)\/\S+/i,

    /** Présence de "@" dans une URL (astuce pour masquer le vrai domaine) */
    arobaseUrl: /https?:\/\/[^@]+@/i,

    /** HTML href différent du texte affiché */
    hrefTrompeur: /href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi,

    /** Répétition de traits d'union (ex : paypal-secure-login-update.com) */
    multiTiretDomaine: /[\w]+-[\w]+-[\w]+-[\w]+\.[a-z]+/i,

    /** Chiffres remplaçant des lettres (paypa1, amaz0n) */
    leetspeak: /[a-z](0|1|3|4|5)[a-z]/i,

    /** Longueur excessive d'URL */
    urlLongue: /https?:\/\/\S{80,}/i,

    /** Attachement suspect dans le texte */
    piecesJointes: /\.(exe|zip|rar|js|vbs|bat|cmd|ps1|docm|xlsm|iso|img)\b/i,

    /** Demande de rappel téléphonique d'urgence */
    rappelTel: /(appelez|appeler|call).*(\+?\d[\d\s\-().]{7,})/i,
  };

  /* ==========================================================
     SECTION 3 — ANALYSEURS SPÉCIALISÉS
     Fonctions pures retournant { score, indicateurs[] }
  ========================================================== */

  /**
   * Analyse les URLs présentes dans le texte.
   * @param {string} texte — contenu brut (email ou URL isolée)
   * @returns {{ score: number, indicateurs: Indicateur[] }}
   */
  function analyserURLs(texte) {
    const indicateurs = [];
    let score = 0;

    // Extraction de toutes les URLs du texte
    const urls = texte.match(REGEX.url) || [];

    urls.forEach(url => {
      let urlLower = url.toLowerCase();

      // ── Adresse IP dans l'URL ──────────────────────────────
      if (REGEX.ipDansUrl.test(url)) {
        score += 30;
        indicateurs.push({
          type: 'critical',
          categorie: 'URL',
          message: `URL utilisant une adresse IP directe : ${url.substring(0, 60)}`,
          score: 30,
        });
      }

      // ── "@" dans l'URL ─────────────────────────────────────
      if (REGEX.arobaseUrl.test(url)) {
        score += 25;
        indicateurs.push({
          type: 'critical',
          categorie: 'URL',
          message: `Symbole "@" dans l'URL (technique de masquage de domaine)`,
          score: 25,
        });
      }

      // ── URL raccourcie ─────────────────────────────────────
      if (REGEX.urlRaccourcie.test(url)) {
        score += 15;
        indicateurs.push({
          type: 'warning',
          categorie: 'URL',
          message: `URL raccourcie détectée (destination réelle masquée) : ${url.substring(0, 50)}`,
          score: 15,
        });
      }

      // ── URL très longue ────────────────────────────────────
      if (REGEX.urlLongue.test(url)) {
        score += 10;
        indicateurs.push({
          type: 'warning',
          categorie: 'URL',
          message: `URL anormalement longue (${url.length} caractères)`,
          score: 10,
        });
      }

      // ── Encodage suspect ───────────────────────────────────
      const encodages = url.match(REGEX.encodageUrl) || [];
      if (encodages.length > 5) {
        score += 12;
        indicateurs.push({
          type: 'warning',
          categorie: 'URL',
          message: `Forte obfuscation par encodage URL (${encodages.length} séquences %XX)`,
          score: 12,
        });
      }

      // ── Domaine connu comme phishing ───────────────────────
      try {
        const parsed = new URL(url);
        const domaine = parsed.hostname.toLowerCase();

        if (DOMAINES_PHISHING.has(domaine)) {
          score += 50;
          indicateurs.push({
            type: 'critical',
            categorie: 'URL',
            message: `Domaine présent dans la liste noire : ${domaine}`,
            score: 50,
          });
        }

        // ── TLD à risque ───────────────────────────────────
        const tldMatch = TLD_RISQUE.find(t => domaine.endsWith(t));
        if (tldMatch) {
          score += 8;
          indicateurs.push({
            type: 'warning',
            categorie: 'URL',
            message: `Extension de domaine à risque : ${tldMatch}`,
            score: 8,
          });
        }

        // ── Marque usurpée dans le sous-domaine ───────────
        const parties = domaine.split('.');
        const sousDomainesStr = parties.slice(0, -2).join('.');
        MARQUES_USURPEES.forEach(marque => {
          if (sousDomainesStr.includes(marque)) {
            score += 20;
            indicateurs.push({
              type: 'critical',
              categorie: 'URL',
              message: `Marque "${marque}" usurpée dans le sous-domaine : ${domaine}`,
              score: 20,
            });
          }
        });

        // ── Marque usurpée dans le chemin ─────────────────
        const chemin = parsed.pathname.toLowerCase();
        MARQUES_USURPEES.forEach(marque => {
          if (chemin.includes(marque) && !domaine.includes(marque)) {
            score += 12;
            indicateurs.push({
              type: 'warning',
              categorie: 'URL',
              message: `Marque "${marque}" dans le chemin de l'URL (possible imitation)`,
              score: 12,
            });
          }
        });

        // ── Multiples traits d'union dans le domaine ──────
        if (REGEX.multiTiretDomaine.test(domaine)) {
          score += 8;
          indicateurs.push({
            type: 'warning',
            categorie: 'URL',
            message: `Domaine avec multiples tirets (structure atypique) : ${domaine}`,
            score: 8,
          });
        }

        // ── Leetspeak dans le domaine ──────────────────────
        if (REGEX.leetspeak.test(domaine)) {
          score += 10;
          indicateurs.push({
            type: 'warning',
            categorie: 'URL',
            message: `Substitution de caractères dans le domaine (ex: 0→o, 1→l) : ${domaine}`,
            score: 10,
          });
        }

        // ── Absence de HTTPS ──────────────────────────────
        if (!url.startsWith('https://')) {
          score += 8;
          indicateurs.push({
            type: 'warning',
            categorie: 'URL',
            message: `URL non sécurisée (HTTP sans S)`,
            score: 8,
          });
        }

      } catch {
        // URL malformée → suspect
        score += 5;
        indicateurs.push({
          type: 'warning',
          categorie: 'URL',
          message: `URL malformée ou illisible`,
          score: 5,
        });
      }
    });

    return { score, indicateurs };
  }

  /**
   * Analyse le langage utilisé dans le texte (urgence, manipulation).
   * @param {string} texte
   * @returns {{ score: number, indicateurs: Indicateur[] }}
   */
  function analyserLangage(texte) {
    const indicateurs = [];
    let score = 0;
    const texteMin = texte.toLowerCase();

    // ── Mots-clés d'urgence critique ────────────────────────
    const trouvésCritique = MOTS_CLES_URGENCE.critique.filter(
      mot => texteMin.includes(mot)
    );
    if (trouvésCritique.length > 0) {
      const pts = Math.min(trouvésCritique.length * 10, 30);
      score += pts;
      indicateurs.push({
        type: 'critical',
        categorie: 'Langage',
        message: `Langage d'urgence critique détecté : "${trouvésCritique.slice(0, 3).join('", "')}"`,
        score: pts,
      });
    }

    // ── Mots-clés d'urgence modérée ─────────────────────────
    const trouvésWarning = MOTS_CLES_URGENCE.warning.filter(
      mot => texteMin.includes(mot)
    );
    if (trouvésWarning.length > 0) {
      const pts = Math.min(trouvésWarning.length * 5, 20);
      score += pts;
      indicateurs.push({
        type: 'warning',
        categorie: 'Langage',
        message: `Termes incitatifs suspects : "${trouvésWarning.slice(0, 3).join('", "')}"`,
        score: pts,
      });
    }

    // ── Demande de données sensibles ────────────────────────
    const donnéesDemandées = MOTS_CLES_DONNEES_SENSIBLES.filter(
      mot => texteMin.includes(mot)
    );
    if (donnéesDemandées.length > 0) {
      const pts = Math.min(donnéesDemandées.length * 15, 40);
      score += pts;
      indicateurs.push({
        type: 'critical',
        categorie: 'Langage',
        message: `Demande de données sensibles : "${donnéesDemandées.slice(0, 3).join('", "')}"`,
        score: pts,
      });
    }

    // ── Pièces jointes dangereuses ──────────────────────────
    const pieceMatch = texte.match(REGEX.piecesJointes);
    if (pieceMatch) {
      score += 20;
      indicateurs.push({
        type: 'critical',
        categorie: 'Langage',
        message: `Extension de fichier dangereuse mentionnée : ${pieceMatch[0]}`,
        score: 20,
      });
    }

    // ── Rappel téléphonique d'urgence ───────────────────────
    if (REGEX.rappelTel.test(texte)) {
      score += 15;
      indicateurs.push({
        type: 'warning',
        categorie: 'Langage',
        message: `Numéro de téléphone avec demande d'appel urgent détecté`,
        score: 15,
      });
    }

    return { score, indicateurs };
  }

  /**
   * Analyse l'expéditeur d'un email (adresse From, Reply-To).
   * @param {string} texte
   * @returns {{ score: number, indicateurs: Indicateur[] }}
   */
  function analyserExpediteur(texte) {
    const indicateurs = [];
    let score = 0;
    const texteMin = texte.toLowerCase();

    // Extraction des adresses email dans le texte
    const emails = texte.match(REGEX.email) || [];

    emails.forEach(email => {
      const [, domaine] = email.split('@');
      if (!domaine) return;
      const domaineMin = domaine.toLowerCase();

      // ── Domaine d'expéditeur avec marque usurpée ──────────
      // On vérifie également les variantes leetspeak (paypa1 pour paypal)
      const domaineNormalisé = domaineMin
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/3/g, 'e')
        .replace(/4/g, 'a')
        .replace(/5/g, 's');

      MARQUES_USURPEES.forEach(marque => {
        // Test sur le domaine original ET sur la version normalisée (anti-leetspeak)
        const correspondance = domaineMin.includes(marque) || domaineNormalisé.includes(marque);
        if (correspondance) {
          // Vérifier si c'est le vrai domaine ou une imitation
          const domainesOfficiels = {
            'paypal': 'paypal.com',
            'amazon': 'amazon.com',
            'apple': 'apple.com',
            'microsoft': 'microsoft.com',
            'google': 'google.com',
          };
          const officiel = domainesOfficiels[marque];
          // Si domaine officiel connu : signaler si différent
          // Si pas de domaine officiel référencé : signaler si TLD suspect ou sous-domaine
          const estOfficiel = officiel && (domaineMin === officiel || domaineMin.endsWith('.' + officiel));
          if (!estOfficiel) {
            score += 25;
            indicateurs.push({
              type: 'critical',
              categorie: 'Expéditeur',
              message: `Expéditeur imite "${marque}" depuis un domaine non officiel : ${domaineMin}`,
              score: 25,
            });
          }
        }
      });

      // ── TLD à risque pour l'expéditeur ────────────────────
      const tldExp = TLD_RISQUE.find(t => domaineMin.endsWith(t));
      if (tldExp) {
        score += 10;
        indicateurs.push({
          type: 'warning',
          categorie: 'Expéditeur',
          message: `Domaine d'expéditeur avec TLD à risque : ${domaineMin}`,
          score: 10,
        });
      }

      // ── Domaine d'expéditeur très long ou à tirets ────────
      if (domaineMin.length > 30 || (domaineMin.match(/-/g) || []).length > 3) {
        score += 8;
        indicateurs.push({
          type: 'warning',
          categorie: 'Expéditeur',
          message: `Domaine d'expéditeur suspect (trop long ou trop de tirets) : ${domaineMin}`,
          score: 8,
        });
      }
    });

    // ── Reply-To différent du From ───────────────────────────
    const fromMatch  = texteMin.match(/^from:\s*.*<?([\w.+-]+@[\w.-]+)>?/m);
    const replyMatch = texteMin.match(/^reply-to:\s*.*<?([\w.+-]+@[\w.-]+)>?/m);
    if (fromMatch && replyMatch) {
      const fromDom  = fromMatch[1].split('@')[1]  || '';
      const replyDom = replyMatch[1].split('@')[1] || '';
      if (fromDom !== replyDom) {
        score += 20;
        indicateurs.push({
          type: 'critical',
          categorie: 'Expéditeur',
          message: `Reply-To différent du From (${fromDom} ≠ ${replyDom}) — technique de détournement`,
          score: 20,
        });
      }
    }

    return { score, indicateurs };
  }

  /**
   * Analyse les en-têtes techniques d'un email (SPF, DKIM, DMARC).
   * @param {string} texte
   * @returns {{ score: number, indicateurs: Indicateur[] }}
   */
  function analyserEnTetes(texte) {
    const indicateurs = [];
    let score = 0;
    const texteMin = texte.toLowerCase();

    // ── SPF fail ─────────────────────────────────────────────
    if (/spf[=:\s]*(fail|softfail)/i.test(texte)) {
      score += 20;
      indicateurs.push({
        type: 'critical',
        categorie: 'En-têtes',
        message: `SPF en échec (l'expéditeur n'est pas autorisé à envoyer pour ce domaine)`,
        score: 20,
      });
    } else if (/spf[=:\s]*pass/i.test(texte)) {
      indicateurs.push({
        type: 'info',
        categorie: 'En-têtes',
        message: `SPF valide (domaine d'envoi autorisé)`,
        score: 0,
      });
    }

    // ── DKIM fail ────────────────────────────────────────────
    if (/dkim[=:\s]*(fail|none)/i.test(texte)) {
      score += 15;
      indicateurs.push({
        type: 'warning',
        categorie: 'En-têtes',
        message: `DKIM absent ou en échec (signature cryptographique manquante)`,
        score: 15,
      });
    } else if (/dkim[=:\s]*pass/i.test(texte)) {
      indicateurs.push({
        type: 'info',
        categorie: 'En-têtes',
        message: `DKIM valide (signature cryptographique correcte)`,
        score: 0,
      });
    }

    // ── DMARC fail ───────────────────────────────────────────
    if (/dmarc[=:\s]*(fail|none)/i.test(texte)) {
      score += 15;
      indicateurs.push({
        type: 'warning',
        categorie: 'En-têtes',
        message: `DMARC absent ou en échec (politique d'authentification non satisfaite)`,
        score: 15,
      });
    }

    // ── Received from suspect ────────────────────────────────
    if (/^received:\s*from\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/im.test(texte)) {
      score += 10;
      indicateurs.push({
        type: 'warning',
        categorie: 'En-têtes',
        message: `En-tête "Received" provenant d'une IP directe (serveur non nommé)`,
        score: 10,
      });
    }

    // ── X-Mailer suspect ─────────────────────────────────────
    if (/x-mailer:\s*(phpmailer|sendmail|mass mailer|bulkmailer)/i.test(texte)) {
      score += 10;
      indicateurs.push({
        type: 'warning',
        categorie: 'En-têtes',
        message: `X-Mailer suspect détecté (outil d'envoi en masse)`,
        score: 10,
      });
    }

    return { score, indicateurs };
  }

  /* ==========================================================
     SECTION 4 — AGRÉGATION ET SCORE FINAL
  ========================================================== */

  /**
   * Construit les résultats par catégorie à partir des indicateurs.
   * @param {Indicateur[]} tousIndicateurs
   * @returns {CategorieResult[]}
   */
  function construireCategories(tousIndicateurs) {
    const map = {};
    tousIndicateurs.forEach(ind => {
      if (!map[ind.categorie]) {
        map[ind.categorie] = { nom: ind.categorie, score: 0, count: 0 };
      }
      map[ind.categorie].score += ind.score;
      map[ind.categorie].count++;
    });
    return Object.values(map);
  }

  /**
   * Génère les recommandations selon le niveau de risque et les indicateurs.
   * @param {number} score
   * @param {Indicateur[]} indicateurs
   * @returns {string[]}
   */
  function genererRecommandations(score, indicateurs) {
    const recos = [];

    if (score >= 67) {
      recos.push('Ne cliquez sur aucun lien ni pièce jointe de ce message.');
      recos.push('Signalez ce message à votre service informatique ou à signal-spam.fr.');
      recos.push('Supprimez immédiatement ce message sans y répondre.');
      recos.push('Si vous avez déjà cliqué, changez vos mots de passe concernés immédiatement.');
    } else if (score >= 34) {
      recos.push('Vérifiez l\'expéditeur directement via le site officiel (ne répondez pas à l\'email).');
      recos.push('En cas de doute, contactez l\'organisation par téléphone (numéro officiel).');
      recos.push('Ne saisissez pas d\'informations personnelles avant vérification.');
    } else {
      recos.push('Ce contenu semble sûr, mais restez vigilant.');
      recos.push('Vérifiez toujours l\'URL dans la barre de navigation avant de saisir des données.');
    }

    // Recommandations spécifiques selon indicateurs
    const aIPDansUrl = indicateurs.some(i => i.message.includes('adresse IP directe'));
    if (aIPDansUrl) {
      recos.push('Une URL avec IP directe ne provient jamais d\'une entreprise légitime.');
    }

    const aDonnéesSensibles = indicateurs.some(i => i.categorie === 'Langage' && i.message.includes('sensibles'));
    if (aDonnéesSensibles) {
      recos.push('Aucun service légitime ne vous demandera votre mot de passe ou numéro de carte par email.');
    }

    const aSpfFail = indicateurs.some(i => i.message.includes('SPF en échec'));
    if (aSpfFail) {
      recos.push('L\'échec SPF indique que cet email ne vient pas du serveur officiel du domaine affiché.');
    }

    return recos;
  }

  /* ==========================================================
     SECTION 5 — API PUBLIQUE
  ========================================================== */

  /**
   * Analyse un texte (email ou URL) et retourne un rapport complet.
   *
   * @param {string} texte — contenu brut à analyser
   * @param {'email'|'url'} mode — type d'analyse à effectuer
   * @returns {AnalyseResult}
   */
  function analyze(texte, mode = 'email') {
    // Pour le mode URL, on enveloppe dans un texte analysable
    const contenu = mode === 'url' ? `URL: ${texte.trim()}` : texte;

    // Exécution de tous les analyseurs
    const resultURL      = analyserURLs(contenu);
    const resultLangage  = analyserLangage(contenu);
    const resultExp      = (mode === 'email') ? analyserExpediteur(contenu) : { score: 0, indicateurs: [] };
    const resultEnTetes  = (mode === 'email') ? analyserEnTetes(contenu)    : { score: 0, indicateurs: [] };

    // Agrégation des indicateurs
    const tousIndicateurs = [
      ...resultURL.indicateurs,
      ...resultLangage.indicateurs,
      ...resultExp.indicateurs,
      ...resultEnTetes.indicateurs,
    ];

    // Calcul du score brut
    const scoreBrut = (
      resultURL.score +
      resultLangage.score +
      resultExp.score +
      resultEnTetes.score
    );

    // Normalisation sur 100 (plafonnement)
    const scoreNormalisé = Math.min(Math.round(scoreBrut), 100);

    // Niveau de risque
    let niveauRisque;
    if (scoreNormalisé < 34)      niveauRisque = 'safe';
    else if (scoreNormalisé < 67) niveauRisque = 'warning';
    else                          niveauRisque = 'danger';

    // Verdict textuel
    const verdicts = {
      safe:    { emoji: '✅', texte: 'Contenu sûr',   sub: 'Aucun indicateur majeur de phishing détecté.' },
      warning: { emoji: '⚠️',  texte: 'Suspect',       sub: 'Des indicateurs suspects ont été détectés. Vérifiez avant de cliquer.' },
      danger:  { emoji: '🚨', texte: 'Phishing !',    sub: 'Très forte probabilité de tentative de phishing. Ne cliquez pas !' },
    };

    // Catégories
    const categories = construireCategories(tousIndicateurs);

    // Recommandations
    const recommandations = genererRecommandations(scoreNormalisé, tousIndicateurs);

    return {
      score:          scoreNormalisé,
      niveauRisque,
      verdict:        verdicts[niveauRisque],
      indicateurs:    tousIndicateurs,
      categories,
      recommandations,
    };
  }

  // Exposition de l'API publique
  return { analyze };

})();

// Export pour Node.js (tests unitaires)
if (typeof module !== 'undefined') {
  module.exports = PhishDetector;
}
