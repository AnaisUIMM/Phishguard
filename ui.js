/**
 * PhishGuard — Interface utilisateur
 * ====================================
 * Fichier : ui.js
 * Description : Gestion du DOM, des interactions utilisateur
 *               et du rendu des résultats d'analyse.
 *               Aucune logique métier ici — uniquement la vue.
 *
 * Dépend de : detector.js (doit être chargé avant)
 */

(() => {
  'use strict';

  /* ==========================================================
     SECTION 1 — RÉFÉRENCES DOM
  ========================================================== */

  // Onglets
  const tabs       = document.querySelectorAll('.tab');
  const tabPanels  = document.querySelectorAll('.tab-content');

  // Entrées
  const inputEmail = document.getElementById('input-email');
  const inputUrl   = document.getElementById('input-url');

  // Boutons
  const btnAnalyze = document.getElementById('btn-analyze');
  const btnClear   = document.getElementById('btn-clear');

  // Résultats
  const placeholder     = document.getElementById('results-placeholder');
  const scoreBlock      = document.getElementById('score-block');
  const indicatorsBlock = document.getElementById('indicators-block');
  const categoriesBlock = document.getElementById('categories-block');
  const recoBlock       = document.getElementById('reco-block');

  // Composants du score
  const scoreCircle  = document.getElementById('score-circle');
  const scoreNumber  = document.getElementById('score-number');
  const scoreArc     = document.getElementById('score-arc');
  const riskBarFill  = document.getElementById('risk-bar-fill');
  const riskBarCursor= document.getElementById('risk-bar-cursor');
  const verdictEmoji = document.getElementById('verdict-emoji');
  const verdictText  = document.getElementById('verdict-text');
  const verdictSub   = document.getElementById('verdict-sub');

  // Listes
  const indicatorsList  = document.getElementById('indicators-list');
  const categoriesGrid  = document.getElementById('categories-grid');
  const recoList        = document.getElementById('reco-list');

  /* ==========================================================
     SECTION 2 — ÉTAT INTERNE
  ========================================================== */

  /** Mode actif : 'email' ou 'url' */
  let modeActif = 'email';

  /* ==========================================================
     SECTION 3 — GESTION DES ONGLETS
  ========================================================== */

  /**
   * Active l'onglet correspondant au mode sélectionné.
   * @param {string} mode — 'email' ou 'url'
   */
  function activerOnglet(mode) {
    modeActif = mode;

    tabs.forEach(tab => {
      const estActif = tab.dataset.tab === mode;
      tab.classList.toggle('active', estActif);
      tab.setAttribute('aria-selected', estActif ? 'true' : 'false');
    });

    tabPanels.forEach(panel => {
      const estActif = panel.id === `tab-${mode}`;
      panel.classList.toggle('active', estActif);
      if (estActif) {
        panel.removeAttribute('hidden');
      } else {
        panel.setAttribute('hidden', '');
      }
    });
  }

  // Écouteurs d'onglets
  tabs.forEach(tab => {
    tab.addEventListener('click', () => activerOnglet(tab.dataset.tab));
  });

  /* ==========================================================
     SECTION 4 — RÉCUPÉRATION DU TEXTE SAISI
  ========================================================== */

  /**
   * Retourne le texte saisi dans l'onglet actif.
   * @returns {string}
   */
  function getTexte() {
    return modeActif === 'url'
      ? inputUrl.value.trim()
      : inputEmail.value.trim();
  }

  /* ==========================================================
     SECTION 5 — RENDU DES RÉSULTATS
  ========================================================== */

  /**
   * Masque le placeholder et affiche les blocs de résultats.
   */
  function afficherBlocsResultats() {
    placeholder.classList.add('hidden');
    scoreBlock.classList.remove('hidden');
    indicatorsBlock.classList.remove('hidden');
    categoriesBlock.classList.remove('hidden');
    recoBlock.classList.remove('hidden');
  }

  /**
   * Réinitialise l'affichage pour un nouvel état vierge.
   */
  function réinitialiserAffichage() {
    placeholder.classList.remove('hidden');
    scoreBlock.classList.add('hidden');
    indicatorsBlock.classList.add('hidden');
    categoriesBlock.classList.add('hidden');
    recoBlock.classList.add('hidden');

    // Réinitialiser les classes de risque
    scoreBlock.classList.remove('risk-safe', 'risk-warn', 'risk-danger');
    scoreCircle.classList.remove('risk-safe', 'risk-warn', 'risk-danger');

    // Réinitialiser les listes
    indicatorsList.innerHTML  = '';
    categoriesGrid.innerHTML  = '';
    recoList.innerHTML        = '';
  }

  /**
   * Anime le cercle de score SVG.
   * Circonférence = 2πr = 2 × π × 50 ≈ 314
   * @param {number} score — valeur entre 0 et 100
   */
  function animerScoreCercle(score) {
    const circonference = 314;
    const offset = circonference - (score / 100) * circonference;

    // Légère temporisation pour déclencher l'animation CSS
    requestAnimationFrame(() => {
      scoreArc.style.strokeDashoffset = offset;
    });
  }

  /**
   * Anime la barre de risque horizontale.
   * @param {number} score
   */
  function animerBarreRisque(score) {
    requestAnimationFrame(() => {
      riskBarFill.style.width  = `${score}%`;
      riskBarCursor.style.left = `${score}%`;
    });
  }

  /**
   * Applique les couleurs selon le niveau de risque.
   * @param {'safe'|'warning'|'danger'} niveau
   */
  function appliquerCouleurRisque(niveau) {
    const classeMap = { safe: 'risk-safe', warning: 'risk-warn', danger: 'risk-danger' };
    const classe = classeMap[niveau];

    scoreBlock.classList.remove('risk-safe', 'risk-warn', 'risk-danger');
    scoreBlock.classList.add(classe);

    // Couleur de la barre
    const couleursMap = {
      safe:    'var(--green-bright)',
      warning: 'var(--yellow)',
      danger:  'var(--red-bright)',
    };
    riskBarFill.style.background = couleursMap[niveau];
    riskBarCursor.style.borderColor = couleursMap[niveau];
  }

  /**
   * Construit et injecte la liste des indicateurs dans le DOM.
   * @param {Indicateur[]} indicateurs
   */
  function renderIndicateurs(indicateurs) {
    indicatorsList.innerHTML = '';

    if (indicateurs.length === 0) {
      const li = document.createElement('li');
      li.className = 'indicator-item info';
      li.innerHTML = `
        <span class="indicator-badge">INFO</span>
        <span>Aucun indicateur de phishing détecté.</span>
      `;
      indicatorsList.appendChild(li);
      return;
    }

    // Tri : critiques en premier, puis warnings, puis infos
    const ordre = { critical: 0, warning: 1, info: 2 };
    const triés = [...indicateurs].sort(
      (a, b) => ordre[a.type] - ordre[b.type]
    );

    triés.forEach(ind => {
      const li = document.createElement('li');
      li.className = `indicator-item ${ind.type}`;

      const badge = { critical: 'CRITIQUE', warning: 'SUSPECT', info: 'INFO' }[ind.type];
      const scoreHtml = ind.score > 0
        ? `<span class="indicator-score">+${ind.score}</span>`
        : '';

      li.innerHTML = `
        <span class="indicator-badge">${badge}</span>
        <span class="indicator-message">${escapeHTML(ind.message)}</span>
        ${scoreHtml}
      `;
      indicatorsList.appendChild(li);
    });
  }

  /**
   * Construit et injecte la grille des catégories.
   * @param {CategorieResult[]} categories
   */
  function renderCategories(categories) {
    categoriesGrid.innerHTML = '';

    if (categories.length === 0) {
      categoriesGrid.innerHTML = '<p style="color:var(--text-muted);font-size:.78rem">Aucune catégorie analysée.</p>';
      return;
    }

    // Score max pour normaliser les barres
    const scoreMax = Math.max(...categories.map(c => c.score), 1);

    categories.forEach(cat => {
      const pct  = Math.min((cat.score / scoreMax) * 100, 100);
      const couleur = cat.score === 0
        ? 'var(--green-mid)'
        : cat.score < 20
          ? 'var(--yellow)'
          : 'var(--red-bright)';

      const div = document.createElement('div');
      div.className = 'category-card';
      div.innerHTML = `
        <span class="cat-name">${escapeHTML(cat.nom)}</span>
        <div class="cat-score-row">
          <span class="cat-value" style="color:${couleur}">${cat.score} pts</span>
          <div class="cat-bar">
            <div class="cat-bar-fill" style="width:${pct}%;background:${couleur}"></div>
          </div>
        </div>
        <span style="font-size:.65rem;color:var(--text-muted)">${cat.count} indicateur${cat.count > 1 ? 's' : ''}</span>
      `;
      categoriesGrid.appendChild(div);
    });
  }

  /**
   * Construit et injecte la liste des recommandations.
   * @param {string[]} recommandations
   */
  function renderRecommandations(recommandations) {
    recoList.innerHTML = '';
    recommandations.forEach(reco => {
      const li = document.createElement('li');
      li.className = 'reco-item';
      li.textContent = reco;
      recoList.appendChild(li);
    });
  }

  /* ==========================================================
     SECTION 6 — FLUX D'ANALYSE PRINCIPAL
  ========================================================== */

  /**
   * Lance l'analyse et met à jour l'interface.
   */
  function lancerAnalyse() {
    const texte = getTexte();

    // Validation : texte vide
    if (!texte) {
      // Secousse visuelle sur le champ actif
      const champ = modeActif === 'url' ? inputUrl : inputEmail;
      champ.style.borderColor = 'var(--red-bright)';
      setTimeout(() => { champ.style.borderColor = ''; }, 1200);
      return;
    }

    // Réinitialisation visuelle
    réinitialiserAffichage();

    // ── Analyse ──────────────────────────────────────────────
    const résultat = PhishDetector.analyze(texte, modeActif);

    // ── Affichage ────────────────────────────────────────────
    afficherBlocsResultats();

    // Score et cercle
    scoreNumber.textContent = résultat.score;
    animerScoreCercle(résultat.score);
    animerBarreRisque(résultat.score);
    appliquerCouleurRisque(résultat.niveauRisque);

    // Verdict
    verdictEmoji.textContent = résultat.verdict.emoji;
    verdictText.textContent  = résultat.verdict.texte;
    verdictSub.textContent   = résultat.verdict.sub;

    // Indicateurs, catégories, recommandations
    renderIndicateurs(résultat.indicateurs);
    renderCategories(résultat.categories);
    renderRecommandations(résultat.recommandations);
  }

  /* ==========================================================
     SECTION 7 — UTILITAIRES
  ========================================================== */

  /**
   * Échappe les caractères HTML pour éviter les injections XSS
   * lors de l'insertion dans le DOM via innerHTML.
   * @param {string} str
   * @returns {string}
   */
  function escapeHTML(str) {
    return String(str)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#x27;');
  }

  /* ==========================================================
     SECTION 8 — ÉCOUTEURS D'ÉVÉNEMENTS
  ========================================================== */

  // Bouton Analyser
  btnAnalyze.addEventListener('click', lancerAnalyse);

  // Analyse au clavier : Entrée dans le champ URL
  inputUrl.addEventListener('keydown', e => {
    if (e.key === 'Enter') lancerAnalyse();
  });

  // Ctrl+Entrée dans le textarea email
  inputEmail.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.ctrlKey) lancerAnalyse();
  });

  // Bouton Effacer
  btnClear.addEventListener('click', () => {
    inputEmail.value = '';
    inputUrl.value   = '';
    réinitialiserAffichage();
  });

  // Retrait de la bordure rouge sur saisie
  inputEmail.addEventListener('input', () => {
    inputEmail.style.borderColor = '';
  });
  inputUrl.addEventListener('input', () => {
    inputUrl.style.borderColor = '';
  });

})();
