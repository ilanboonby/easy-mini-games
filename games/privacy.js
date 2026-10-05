"use strict";
/* Le Registre Anonyme : pseudonymisation, réidentification, k-anonymat, l-diversité,
   attaque par différenciation, confidentialité différentielle. Toutes les données sont fictives
   et générées de façon déterministe ; tous les calculs (jointure, groupes, bruit de Laplace) sont réels. */
(function () {
  const F = () => f();

  /* ============ Données fictives (déterministes) ============ */
  const rngf = seed => () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const CPS = ["44000", "44010", "44015", "44100", "44110", "44115", "44120", "44200", "44210", "44300", "44310", "44315", "44400", "44410"];
  const FF = ["Léa", "Camille", "Inès", "Manon", "Chloé", "Jade", "Louise", "Emma", "Zoé", "Nina", "Anaïs", "Sarah", "Clara", "Lucie", "Éva", "Margaux", "Juliette", "Océane", "Agathe", "Mathilde"];
  const FM = ["Hugo", "Lucas", "Nathan", "Louis", "Jules", "Ethan", "Arthur", "Maël", "Théo", "Paul", "Victor", "Antoine", "Gabriel", "Raphaël", "Samuel", "Étienne", "Maxime", "Baptiste", "Romain", "Simon"];
  const LNAMES = ["Martin", "Bernard", "Dubois", "Thomas", "Robert", "Richard", "Petit", "Durand", "Leroy", "Moreau", "Simon", "Laurent", "Lefèvre", "Michel", "Garcia", "David", "Bertrand", "Roux", "Vincent", "Fournier", "Morel", "Girard", "André", "Mercier", "Dupont", "Lambert", "Bonnet", "François", "Martinez", "Legrand", "Garnier", "Faure", "Rousseau", "Blanc", "Guérin", "Muller", "Henry", "Roussel", "Nicolas", "Perrin"];
  const REF_YEAR = 2026, LAST_DAY = 60, NPAT = 600, ALICE = 17, BOB = 600;
  const DIS = { grippe: "grippe", fracture: "fracture", asthme: "asthme", diabete: "diabète", hypertension: "hypertension", depression: "dépression", prostate: "cancer prostate", sein: "cancer sein" };
  const p2 = n => String(n).padStart(2, "0");
  const dim = (y, m) => [31, (y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];

  function build() {
    const R = rngf(443), pick = a => a[Math.floor(R() * a.length)];
    const P = [];
    for (let i = 1; i <= NPAT; i++) {
      const sexe = R() < 0.52 ? "F" : "M";
      const age = Math.min(94, Math.floor(Math.pow(R(), 0.85) * 95));
      const y = REF_YEAR - age, m = 1 + Math.floor(R() * 12), d = 1 + Math.floor(R() * dim(y, m));
      const w = { grippe: 14, fracture: 8 + (age > 65 ? 8 : 0), asthme: age < 40 ? 14 : 5, "diabète": age > 45 ? 12 : 2, hypertension: age > 50 ? 16 : 2, "dépression": age >= 18 ? 10 : 1, "cancer prostate": sexe === "M" && age >= 55 ? 10 : 0, "cancer sein": sexe === "F" && age >= 45 ? 9 : 0 };
      let tot = 0; for (const k in w) tot += w[k];
      let r = R() * tot, mal = "grippe"; for (const k in w) { if (r < w[k]) { mal = k; break; } r -= w[k]; }
      const cp = CPS[Math.min(CPS.length - 1, Math.floor(Math.pow(R(), 1.1) * CPS.length))];
      const nom = (sexe === "F" ? pick(FF) : pick(FM)) + " " + pick(LNAMES);
      let duree = 2 + Math.floor(-Math.log(1 - R()) * 6);
      if (i % 40 === 0) duree = 90 + Math.floor(R() * 110);
      const secuTail = "44" + (100 + Math.floor(R() * 900)) + (100 + Math.floor(R() * 900)) + p2(Math.floor(R() * 97));
      P.push({
        id: i, nom, secuTail, cp, naissance: `${y}-${p2(m)}-${p2(d)}`, sexe, maladie: mal, duree, jour: 1 + Math.floor(R() * (LAST_DAY - 1)),
        adresse: (1 + Math.floor(R() * 90)) + " " + pick(["rue du Port", "quai des Écluses", "impasse du Phare", "rue des Mouettes", "avenue du Large"]),
        profession: pick(["enseignant", "infirmier", "boulanger", "comptable", "retraité", "étudiant", "artisan", "cadre"]),
        employeur: pick(["Mairie", "Chantiers Navals", "Lycée Ada", "Banque du Port", "Marché Central", "sans emploi"]),
      });
    }
    // Des groupes réalistes, pour que les limites du k-anonymat soient observables : une cohorte de
    // patients âgés d'un même secteur (même diagnostic) et une cohorte à deux diagnostics seulement.
    const setYear = (r, y) => { const [, m, d] = r.naissance.split("-"); r.naissance = `${y}-${m}-${p2(Math.min(+d, dim(y, +m)))}`; };
    const inA = i => i >= 101 && i <= 108, inB = i => i >= 201 && i <= 210;
    P.forEach(r => {
      if (inA(r.id) || inB(r.id)) return;
      const y = +r.naissance.slice(0, 4);
      if (y <= 1939) setYear(r, y + 20 + (r.id % 9));
      else if (r.sexe === "F" && r.cp.startsWith("443") && y >= 1940 && y <= 1949) setYear(r, y + 10);
    });
    P.forEach(r => {
      const i = r.id;
      if (inA(i)) { r.sexe = "M"; r.cp = i % 2 ? "44400" : "44410"; setYear(r, 1936 + (i % 4)); r.maladie = "cancer prostate"; }
      if (inB(i)) { r.sexe = "F"; r.cp = ["44300", "44310", "44315"][i % 3]; setYear(r, i <= 205 ? 1940 + (i % 5) : 1945 + (i % 5)); r.maladie = i % 2 ? "diabète" : "hypertension"; }
    });
    // Deux personnes du récit
    Object.assign(P[ALICE - 1], { nom: "Alice Martel", sexe: "F", naissance: "1984-09-02", cp: "44115", maladie: "asthme", jour: 12 });
    Object.assign(P[BOB - 1], { nom: "Bob Lemaire", sexe: "M", naissance: "1971-03-14", cp: "44310", maladie: "dépression", jour: LAST_DAY });
    P.forEach(r => { r.secu = (r.sexe === "F" ? 2 : 1) + r.naissance.slice(2, 4) + r.naissance.slice(5, 7) + r.secuTail; r.pseudo = sha256("cle-secrete-hopital:" + r.secu).slice(0, 6); });
    // Liste électorale fictive : 80 % des adultes de la table + des habitants qui ne sont pas patients
    const V = [];
    P.forEach(r => { if (+r.naissance.slice(0, 4) <= REF_YEAR - 18 && (R() < 0.8 || r.id === ALICE || r.id === BOB)) V.push({ id: r.id, nom: r.nom, cp: r.cp, naissance: r.naissance, sexe: r.sexe }); });
    for (let j = 0; j < 260; j++) {
      const sexe = R() < 0.5 ? "F" : "M", y = REF_YEAR - 18 - Math.floor(Math.pow(R(), 0.9) * 72), m = 1 + Math.floor(R() * 12), d = 1 + Math.floor(R() * dim(y, m));
      V.push({ id: 1000 + j, nom: (sexe === "F" ? pick(FF) : pick(FM)) + " " + pick(LNAMES), cp: CPS[Math.min(CPS.length - 1, Math.floor(Math.pow(R(), 1.1) * CPS.length))], naissance: `${y}-${p2(m)}-${p2(d)}`, sexe });
    }
    V.sort((a, b) => a.nom.localeCompare(b.nom, "fr") || a.id - b.id);
    return { P, V };
  }
  const { P: BASE, V: VOTERS } = build();

  /* ============ Généralisation, groupes, mesures ============ */
  const MODES = ["date", "mois", "annee", "5", "10", "20"];
  const MODE_TXT = { date: "date exacte", mois: "mois", annee: "année", 5: "tranches de 5 ans", 10: "tranches de 10 ans", 20: "tranches de 20 ans" };
  const gCp = (cp, d) => d >= 5 ? cp : cp.slice(0, d) + "*".repeat(5 - d);
  const gNais = (date, m) => {
    if (m === "date") return date;
    if (m === "mois") return date.slice(0, 7);
    if (m === "annee") return date.slice(0, 4);
    const w = +m, lo = Math.floor(+date.slice(0, 4) / w) * w; return `${lo}-${lo + w - 1}`;
  };
  const keyOf = (r, cfg) => gCp(r.cp, cfg.cp) + "|" + gNais(r.naissance, cfg.nais) + "|" + r.sexe;
  const groupsOf = (rows, cfg) => { const m = new Map(); rows.forEach(r => { const k = keyOf(r, cfg); if (!m.has(k)) m.set(k, []); m.get(k).push(r); }); return m; };
  const nbMal = a => new Set(a.map(z => z.maladie)).size;
  const defCfg = () => ({ cp: 5, nais: "date", supk: 0, divl: 0, cols: { nom: true, secu: true, adresse: true, profession: true, employeur: true } });
  const allRows = () => BASE.filter(r => !F().erased.includes(r.id));
  function pubWith(cfg) {
    let rows = allRows();
    const total = rows.length;
    if (cfg.supk > 1) { const g = groupsOf(rows, cfg); rows = rows.filter(r => g.get(keyOf(r, cfg)).length >= cfg.supk); }
    if (cfg.divl > 1) { const g = groupsOf(rows, cfg); rows = rows.filter(r => nbMal(g.get(keyOf(r, cfg))) >= cfg.divl); }
    const g = groupsOf(rows, cfg), gs = [...g.values()];
    const k = gs.length ? Math.min(...gs.map(a => a.length)) : 0;
    const l = gs.length ? Math.min(...gs.map(nbMal)) : 0;
    const loss = ((5 - cfg.cp) / 5 + MODES.indexOf(cfg.nais) / 5) / 2;
    const util = (1 - loss) * (total ? rows.length / total : 0);
    return { rows, g, k, l, total, loss, prec: 1 - loss, util };
  }
  const pub = () => pubWith(F().cfg);
  const MIN_UTIL = 0.30, K_TARGET = 5, L_TARGET = 3;
  const DIRECTION = () => ({ cp: 3, nais: "5", supk: 5, divl: 0, cols: {} });

  function joinCalc(cfg) {
    const p = pubWith(cfg), vc = new Map();
    VOTERS.forEach(v => { const k = keyOf(v, cfg); if (!vc.has(k)) vc.set(k, []); vc.get(k).push(v); });
    const links = [];
    p.rows.forEach(r => { const k = keyOf(r, cfg), vs = vc.get(k); if (p.g.get(k).length === 1 && vs && vs.length === 1) links.push({ r, v: vs[0] }); });
    return { p, links, ok: links.filter(l => l.v.id === l.r.id) };
  }
  const ATTR = {
    sexe: { txt: "sexe", fn: (r, cfg) => r.sexe },
    cp: { txt: "code postal", fn: (r, cfg) => gCp(r.cp, cfg.cp) },
    annee: { txt: "année de naissance", fn: (r, cfg) => r.naissance.slice(0, 4) },
    naissance: { txt: "naissance", fn: (r, cfg) => gNais(r.naissance, cfg.nais) },
  };
  function uniqShare(rows, names, cfg) {
    const m = new Map(); rows.forEach(r => { const k = names.map(n => ATTR[n].fn(r, cfg)).join("|"); m.set(k, (m.get(k) || 0) + 1); });
    let u = 0; m.forEach(n => { if (n === 1) u++; });
    return rows.length ? u / rows.length : 0;
  }

  /* ============ Bruit de Laplace et requêtes ============ */
  const lapl = (b, R) => { const u = R() - 0.5; return -b * Math.sign(u) * Math.log(Math.max(1e-12, 1 - 2 * Math.abs(u))); };
  const atkAcc = eps => { const b = 1 / eps; return 1 - 0.25 * (2 + 0.5 / b) * Math.exp(-0.5 / b); }; // exactitude de Mallory : écart de 2 comptages bruités
  const boundAcc = e => Math.exp(e) / (1 + Math.exp(e));
  const pct = v => (Math.round(v * 1000) / 10).toString().replace(".", ",") + " %";
  const fx = (v, d) => (Math.round(v * Math.pow(10, d)) / Math.pow(10, d)).toString().replace(".", ",").replace("-", "−");
  const BUDGET0 = 2;

  /* ============ Carnet ============ */
  const notes = {
    pseudo: ["Pseudonymisation", "Remplacer le nom et le numéro de sécu par un pseudonyme (ou les retirer) est de la pseudonymisation : le jeu reste une donnée personnelle au sens du RGPD, car la personne reste retrouvable par recoupement ou grâce à la table de correspondance. L'anonymisation exige que la réidentification soit impossible par des moyens raisonnables : c'est un résultat à démontrer, pas une étape de nettoyage."],
    reid: ["Réidentification par jointure", "Un jeu « sans nom » peut être croisé avec une source publique (liste électorale, réseaux sociaux, annuaire) sur des colonnes communes. Quand la combinaison est unique des deux côtés, on retrouve le nom, et donc la maladie. Aucune astuce technique n'est nécessaire : une simple jointure suffit."],
    cas: ["Cas réels", "Dossiers médicaux : en 1997, la chercheuse Latanya Sweeney a retrouvé le dossier hospitalier d'un gouverneur du Massachusetts en croisant des données de santé « anonymisées » avec une liste électorale. Classements de films : en 2008, des chercheurs ont montré que le jeu de notes publié pour le Netflix Prize permettait de retrouver certains abonnés en le comparant à des avis publics sur un autre site."],
    quasi: ["Quasi-identifiants", "Une colonne seule est rarement un identifiant ; leur combinaison l'est. Code postal, date de naissance et sexe suffisent à rendre la plupart des lignes uniques. Plus on combine d'attributs, plus la part de lignes uniques grimpe vite : la population unique est la matière première de la réidentification."],
    kanon: ["k-anonymat", "Un jeu est k-anonyme si chaque combinaison de quasi-identifiants est partagée par au moins k lignes : on se fond dans une foule d'au moins k personnes. On y arrive par généralisation (code postal tronqué, âge en tranches) et par suppression des lignes rares. Chaque généralisation coûte en précision : c'est un compromis, pas une case à cocher."],
    homog: ["Homogénéité et l-diversité", "Le k-anonymat protège l'identité de la ligne, pas la valeur sensible. Si les k membres d'un groupe ont la même maladie, savoir qu'on est dans le groupe suffit (attaque par homogénéité) ; avec un peu de connaissance préalable (« il n'est pas diabétique »), un groupe à deux valeurs se réduit à une seule. La l-diversité exige au moins l valeurs sensibles distinctes par groupe : mieux, mais encore imparfait si une valeur domine le groupe."],
    diff: ["Attaque par différenciation", "Chaque statistique agrégée semble inoffensive. Mais deux statistiques qui ne diffèrent que par une personne (avant/après son arrivée, avec/sans elle) livrent, par soustraction, la valeur d'un individu. Masquer les petits effectifs ne protège pas : les deux comptages, eux, sont grands."],
    dp: ["Confidentialité différentielle", "On ajoute à chaque réponse un bruit aléatoire (loi de Laplace, d'échelle sensibilité/ε). La sensibilité est ce qu'une seule personne peut changer au résultat (1 pour un comptage ; la borne d'écrêtage pour une somme). Plus ε est petit, plus la protection est forte et plus la réponse est floue. Le budget de confidentialité s'additionne à chaque requête : une fois épuisé, on se tait. Le bruit est dosé par un calcul, pas par un « à peu près »."],
    min: ["Minimisation, conservation et droits", "On ne collecte que ce que la finalité exige (minimisation), on fixe une durée de conservation avant de collecter, on informe les personnes et on respecte leurs droits : accès, rectification, effacement, opposition, limitation (RGPD). Une donnée réellement anonyme sort du champ du RGPD ; une donnée pseudonymisée y reste. Le consentement n'est qu'une des bases légales possibles, la recherche d'intérêt public en est une autre."],
  };

  /* ============ Entités et lieux ============ */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, qui supervise ce test d'anonymisation." },
    morel: { npc: true, names: ["morel", "docteure morel", "docteur morel", "docteure", "chercheuse"], label: "la Docteure Morel", desc: () => "La Docteure Morel, responsable du département d'information médicale : elle veut publier les dossiers pour la recherche, sans mettre ses patients en danger." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", vis: () => S.room === "mairie", desc: () => "Mallory, assise devant la liste électorale. Pour cet audit autorisé, elle joue le rôle de l'attaquante." },
    delegue: { npc: true, names: ["delegue", "octave", "dpo"], label: "Octave, délégué à la protection des données", vis: () => S.room === "guichet", desc: () => "Octave, délégué à la protection des données de l'hôpital. Il tient le registre des traitements." },
    alice: { npc: true, names: ["alice", "alice martel", "patiente"], label: "Alice, patiente", vis: () => S.room === "guichet", desc: () => "Alice Martel, patiente du service de pneumologie, un formulaire à la main : elle veut exercer ses droits." },
    dossier: { names: ["dossier", "dossiers", "base", "source", "table source", "archives"], label: "la table des dossiers", vis: () => S.room === "archives",
      desc: () => { F().sawSrc = true; return srcText(); } },
    liste: { names: ["liste", "liste electorale", "electeurs", "registre electoral"], label: "la liste électorale", vis: () => S.room === "mairie",
      desc: () => { F().sawList = true; return `La liste électorale de Port-443 : ${VOTERS.length} personnes, publique, consultable en mairie. Colonnes : nom, code postal, date de naissance, sexe. Un extrait :\n` + VOTERS.slice(60, 66).map(v => `${v.nom} · ${v.cp} · ${v.naissance} · ${v.sexe}`).join("\n") + "\n\n`joindre` : croise la table de l'hôpital (dans son état actuel) avec cette liste."; } },
    tableau: { names: ["tableau", "table publiee", "version", "jeu", "jeu de donnees", "publication"], label: "le jeu de données à publier", vis: () => S.room === "atelier",
      desc: () => { F().sawTab = true; return pubText(); } },
    bord: { names: ["tableau de bord", "bord", "statistiques", "stats", "ecran"], label: "le tableau de bord statistique", vis: () => S.room === "stats",
      desc: () => `Le tableau de bord que l'hôpital veut ouvrir aux chercheurs : il répond à des requêtes de comptage et de somme, mis à jour chaque jour (aujourd'hui : jour ${LAST_DAY}). Règle actuelle : « aucun résultat inférieur à 5 n'est affiché ».\n` +
        "Requêtes : `compter ‹maladie› [jour ‹n›] [cp ‹code›]` · `somme ‹maladie›`\nMaladies : grippe, fracture, asthme, diabète, hypertension, dépression, prostate, sein." + (F().dp ? `\nMode confidentialité différentielle : ACTIVÉ (ε = ${F().eps === null ? "à choisir" : fx(F().eps, 3)} par requête, budget restant ${fx(F().budget, 3)} sur ${BUDGET0}).` : "\nMode confidentialité différentielle : désactivé (`activer bruit`).") },
    registre: { names: ["registre", "registre des traitements", "traitement", "formulaire", "fiche"], label: "le registre des traitements", vis: () => S.room === "guichet",
      desc: () => `Le registre des traitements du projet. Finalité : « étudier la durée de séjour selon le diagnostic, l'âge et la zone géographique ». Colonnes collectées aujourd'hui :\n${colsText()}\n\`retirer ‹colonne›\` pour minimiser · \`conservation ‹années›\` pour fixer la durée de conservation.` },
  };

  const rooms = {
    hall: { name: "Le hall de l'hôpital de Port-443", short: "Hall", alias: ["hall", "accueil"], ents: ["ada", "morel"], exits: { nord: "archives", est: "mairie", ouest: "atelier", sud: "stats" },
      desc: () => "Un hall clair, des chariots, des panneaux « Respectez la confidentialité ». Au nord, les archives. À l'est, la mairie voisine et sa liste électorale. À l'ouest, l'atelier d'anonymisation. Au sud, le cabinet des statistiques." },
    archives: { name: "Les archives médicales", short: "Archives", alias: ["archives", "archive"], ents: ["dossier"], exits: { sud: "hall" },
      desc: () => "Des classeurs, un terminal. La table des dossiers de l'hôpital y est conservée : nom, numéro de sécu, adresse, profession, employeur, code postal, date de naissance, sexe, diagnostic, durée de séjour." },
    mairie: { name: "La mairie : consultation publique", short: "Mairie", alias: ["mairie", "liste"], ents: ["liste", "mallory"], exits: { ouest: "hall" },
      desc: () => "Le bureau où n'importe qui peut consulter la liste électorale. Mallory a posé son carnet sur la table : elle est là pour l'audit, avec l'autorisation de la Guilde." },
    atelier: { name: "L'atelier d'anonymisation", short: "Atelier", alias: ["atelier", "anonymisation", "labo"], ents: ["tableau"], exits: { est: "hall" },
      desc: () => "Un poste de travail où l'on prépare la version publiable du jeu de données. On y mesure, on généralise, on supprime, et on y lance les attaques de test. `aide` rappelle les commandes." },
    stats: { name: "Le cabinet des statistiques", short: "Statistiques", alias: ["stats", "statistiques", "cabinet"], ents: ["bord"], exits: { nord: "hall", est: "guichet" },
      desc: () => "Un écran affiche le tableau de bord que les chercheurs interrogeront. À l'est, le guichet des droits des patients." },
    guichet: { name: "Le guichet des droits", short: "Guichet", alias: ["guichet", "droits"], ents: ["registre", "delegue", "alice"], exits: { ouest: "stats" },
      desc: () => "Un comptoir discret, des affiches sur les droits des patients, et le registre des traitements de l'hôpital." },
  };

  /* ============ Affichages ============ */
  const COLS = ["nom", "secu", "adresse", "profession", "employeur"];
  const NEEDED = { cp: "le code postal", naissance: "la date de naissance", sexe: "le sexe", maladie: "le diagnostic", duree: "la durée de séjour" };
  function colsText() {
    const c = F().cfg.cols;
    return COLS.map(n => `  · ${n}${c[n] ? "" : " (retirée)"}`).join("\n") + "\n  · cp, naissance, sexe, maladie, durée de séjour (nécessaires à la finalité)";
  }
  function rowLine(r, cfg, ident) {
    const mal = r.maladie;
    return (ident ? ident + " " : "") + `${gCp(r.cp, cfg.cp)} ${gNais(r.naissance, cfg.nais)} ${r.sexe} ${mal}`;
  }
  function srcText() {
    const x = F(), c = x.cfg.cols, rows = allRows().slice(0, 7);
    const heads = COLS.filter(n => c[n]).concat(["cp", "naissance", "sexe", "maladie", "durée"]);
    return `La table des dossiers : ${allRows().length} patients. Colonnes : ${heads.join(", ")}. Un extrait :\n` +
      rows.map(r => `${c.nom ? r.nom + " · " : ""}${c.secu ? r.secu + " · " : ""}${r.cp} · ${r.naissance} · ${r.sexe} · ${r.maladie}`).join("\n") +
      `\n\nObservation : le numéro de sécu contient déjà le sexe, l'année et le mois de naissance. \`retirer ‹colonne›\` retire une colonne de la version à publier.`;
  }
  function pubText() {
    const x = F(), cfg = x.cfg, c = cfg.cols, p = pub();
    const ident = c.nom || c.secu;
    const lines = p.rows.slice(0, 7).map(r => rowLine(r, cfg, ident ? (c.nom ? r.nom : "") + (c.secu ? " " + r.secu : "") + " ·" : "P-" + r.pseudo + " ·"));
    return `Version à publier (${p.rows.length} lignes sur ${p.total}). Quasi-identifiants : code postal ${cfg.cp} chiffres, naissance en ${MODE_TXT[cfg.nais]}` + (cfg.supk > 1 ? `, groupes de moins de ${cfg.supk} supprimés` : "") + (cfg.divl > 1 ? `, groupes à moins de ${cfg.divl} diagnostics supprimés` : "") + `.\n` + lines.join("\n") + "\n…\n`mesurer` pour les chiffres, `groupes` pour les groupes.";
  }

  /* ============ Étapes ============ */
  const minDone = () => { const c = F().cfg.cols; return !c.adresse && !c.profession && !c.employeur; };
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.pseudo) return "pseudo";
    if (!x.j1) return "join";
    if (!x.malTalk) return "mal";
    if (!(x.uni[1] && x.uni[2] && x.uni[3])) return "uni";
    if (!x.kOK) return "kanon";
    if (!x.rejoin) return "rejoin";
    if (!x.hom) return "hom";
    if (!x.know) return "know";
    if (!x.divOK) return "div";
    if (!(x.h2 && x.k2)) return "recheck";
    if (!x.diff) return "diff";
    if (!x.dp) return "dp";
    if (x.eps === null) return "eps";
    if (!x.dpAtk) return "dpatk";
    if (!x.sumDP && !x.budgetOut) return "sens";
    if (!x.budgetOut) return "budget";
    if (!x.trade) return "trade";
    if (!minDone()) return "min";
    if (!x.keep) return "keep";
    if (!(x.accAcc && x.accEff)) return "droits";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada attend dans le hall.", "`parler ada`"],
    pseudo: () => ["Va aux archives (au nord) : la table des dossiers contient des colonnes qui désignent directement les gens. Retire-les.", "`aller nord`, `examiner dossier`, `retirer nom`, `retirer secu`."],
    join: () => ["La mairie, à l'est du hall, publie une liste électorale. Vois si l'on peut croiser les deux tables.", "`aller sud`, `aller est`, `examiner liste`, `joindre`."],
    mal: () => ["Mallory, dans la même pièce, connaît des précédents réels.", "`parler mallory`"],
    uni: () => ["À l'atelier (ouest du hall), mesure la part de lignes uniques selon le nombre d'attributs : 1, puis 2, puis 3.", "`aller ouest`, `unicite sexe`, `unicite cp sexe`, `unicite cp sexe naissance`."],
    kanon: () => ["Généralise (code postal tronqué, naissance en tranches) et supprime les petits groupes jusqu'à k ≥ 5, sans détruire l'utilité (au moins " + pct(MIN_UTIL) + "). Vérifie avec `mesurer`.", "Par exemple `generaliser cp 3`, `generaliser naissance 10`, `supprimer 5`, puis `mesurer`. `groupes` montre la répartition ; essaie d'autres réglages."],
    rejoin: () => ["Retourne à la mairie et rejoue la jointure sur ta nouvelle version.", "`aller est` (depuis le hall), `joindre`."],
    hom: () => ["Le k-anonymat protège-t-il la valeur sensible ? À l'atelier, lance l'attaque par homogénéité.", "`attaquer homogeneite`"],
    know: () => ["Mallory sait une chose sur sa cible. Lance l'attaque par connaissance préalable.", "`attaquer connaissance`"],
    div: () => ["Exige plus de diversité des diagnostics dans chaque groupe, au moins 3, sans passer sous le seuil d'utilité.", "`diversifier 3` (ajuste la généralisation si l'utilité s'effondre ; `mesurer`)."],
    recheck: () => ["Rejoue les deux attaques sur la nouvelle version.", "`attaquer homogeneite` puis `attaquer connaissance`."],
    diff: () => ["Au cabinet des statistiques (sud du hall), compare l'état du tableau de bord avant et après l'arrivée du dernier patient (jour 60). Choisis une maladie fréquente, par exemple la dépression.", "`aller sud`, `compter depression jour 59`, `compter depression jour 60`."],
    dp: () => ["Le bon remède n'est pas de cacher les petits chiffres, mais de bruiter toutes les réponses.", "`activer bruit`"],
    eps: () => ["Choisis le paramètre ε, la quantité de confidentialité dépensée à chaque requête. Plus il est petit, plus on protège.", "`epsilon 0.5`"],
    dpatk: () => ["Rejoue exactement la même attaque par différenciation, mais avec le bruit.", F().eps !== null && F().budget < F().eps - 1e-9 ? "Ton budget est épuisé : `aller nord`, `parler morel` pour en obtenir un nouveau, puis `epsilon 0.5`." : "`compter depression jour 59` puis `compter depression jour 60` (avec ε ≤ 1)."],
    sens: () => ["Les sommes ont une autre sensibilité que les comptages. Interroge une somme de durées de séjour : le bruit sera bien plus gros.", "`somme depression` (la borne d'écrêtage est modifiable : `borne 10`)."],
    budget: () => ["Chaque requête consomme du budget. Continue d'interroger jusqu'à ce que le tableau de bord refuse de répondre.", "`budget` pour voir le solde, puis `compter grippe` jusqu'à épuisement."],
    trade: () => ["Regarde le compromis entre utilité et vie privée pour plusieurs valeurs de ε.", "`compromis`"],
    min: () => ["Au guichet des droits (à l'est du cabinet), examine le registre : des colonnes n'ont aucun rapport avec la finalité de la recherche.", "`aller est`, `examiner registre`, `retirer adresse`, `retirer profession`, `retirer employeur`."],
    keep: () => ["Fixe une durée de conservation proportionnée : le projet dure 3 ans, publication et archivage compris 2 ans de plus.", "`conservation 5` (entre 3 et 5 ans)."],
    droits: () => ["Alice demande l'accès à son dossier et l'effacement de ses données.", "`parler alice`, `accorder acces`, `accorder effacement`."],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ============ Dialogues ============ */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "L'hôpital de Port-443 veut publier ses dossiers pour la recherche. La Docteure Morel affirme qu'ils seront « anonymisés » : on retire les noms, on garde la médecine. Ton rôle : vérifier cette promesse comme le ferait un attaquant, puis améliorer le jeu de données. Audit autorisé, données entièrement fictives.");
          say("Maître Ada", "Commence aux archives, au nord. Tu y verras ce qu'il y a dans la table.");
          out("`aller nord` puis `examiner dossier`.", "sys");
        } else if (x.end) say("Maître Ada", "L'hôpital a adopté tes réglages. Un registre anonyme, ça se démontre, et ça se défend longtemps.");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas fini. `indice` si tu bloques.");
        break;
      case "morel":
        if (!x.pseudo) say("Docteure Morel", "J'ai déjà fait retirer les noms, il me semble ? Allez voir aux archives : je veux savoir si c'est suffisant.");
        else if (!x.kOK) say("Docteure Morel", "Mes chercheurs ont besoin de l'âge, de la zone géographique et du diagnostic. Si vous les abîmez trop, mon étude ne vaut plus rien : je n'accepte pas une version dont l'utilité tombe sous " + pct(MIN_UTIL) + " (voyez `mesurer`).");
        else if (!x.divOK) say("Docteure Morel", "Ma version est « 5-anonyme » et j'en suis fière. Faites-moi mentir si vous pouvez : attaquez-la.");
        else if (x.dp && !x.dpAtk && x.eps !== null && x.budget < x.eps - 1e-9) { x.budget = BUDGET0; say("Docteure Morel", "Le comité d'éthique vous accorde, exceptionnellement et pour l'exercice, un nouveau budget de " + BUDGET0 + ". Choisissez un ε plus petit : à ε = 0.5, vous aurez de quoi mener l'attaque."); }
        else if (!x.diff) say("Docteure Morel", "Parfait pour le jeu de données. Mais mes chercheurs veulent aussi un tableau de bord de statistiques, au sud. Regardez s'il est sûr.");
        else say("Docteure Morel", "Je ne pensais pas que des chiffres globaux pouvaient trahir un patient. Poursuivez.");
        break;
      case "mallory":
        if (!x.j1) say("Mallory", "Je n'ai qu'une liste électorale et un peu de patience. Montre-moi ce que tu as comme table de l'hôpital et on croise.");
        else {
          if (!x.malTalk) { x.malTalk = true; note("cas"); }
          say("Mallory", "Ça s'est déjà fait en vrai. En 1997, une chercheuse a retrouvé le dossier médical d'un gouverneur dans des données hospitalières « anonymisées », en les croisant avec une liste électorale. En 2008, le jeu de notes de films publié pour un concours a été rapproché d'avis publics sur un autre site pour retrouver des abonnés. Pas de magie : des colonnes communes.");
          say("Mallory", "Conclusion : ce n'est pas le nom qui identifie, c'est la combinaison. Mesure ça à l'atelier.");
        }
        break;
      case "delegue":
        if (!minDone()) say("Octave", "La finalité, c'est la durée de séjour selon le diagnostic, l'âge et la zone. Une adresse ? Une profession ? Un employeur ? Si on n'en a pas besoin, on ne les garde pas : c'est la minimisation. `retirer ‹colonne›`.");
        else if (!x.keep) say("Octave", "Combien de temps garde-t-on les données de recherche ? « Toujours » n'est pas une réponse : il faut une durée liée à la finalité, fixée avant de collecter. `conservation ‹années›`.");
        else say("Octave", "Les droits : accès, rectification, effacement, opposition, limitation. Alice est devant toi : à toi de jouer.");
        break;
      case "alice":
        if (!(x.accAcc && x.accEff)) {
          say("Alice", "Bonjour. J'ai appris que mes données servent à de la recherche. Je veux voir ce que vous avez sur moi, et je veux que vous les retiriez de la base.");
          out("`accorder acces` · `accorder effacement`", "sys");
        } else say("Alice", "Merci d'avoir répondu clairement.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ============ Verbes : table, anonymisation ============ */
  const toks = c => norm(c.rawArg || "").split(" ").filter(Boolean);
  function retirer(c) {
    const x = F(), cfg = x.cfg, t = toks(c);
    if (!["archives", "atelier", "guichet"].includes(S.room)) { out("On retire une colonne depuis les archives, l'atelier ou le guichet.", "sys"); return; }
    if (!t.length) { out("Retirer quelle colonne ? `retirer nom`, `retirer secu`, `retirer adresse`…", "err"); return; }
    const map = { nom: "nom", noms: "nom", secu: "secu", numero: "secu", nir: "secu", securite: "secu", adresse: "adresse", adresses: "adresse", profession: "profession", metier: "profession", employeur: "employeur" };
    const found = [...new Set(t.map(w => map[w]).filter(Boolean))];
    const needed = t.find(w => ({ cp: 1, postal: 1, naissance: 1, age: 1, sexe: 1, maladie: 1, diagnostic: 1, duree: 1, sejour: 1 })[w]);
    if (!found.length) {
      if (needed) out("Cette colonne est nécessaire à la finalité de la recherche (durée de séjour selon le diagnostic, l'âge et la zone) : on la garde, mais on peut la généraliser (`generaliser`).", "sys");
      else out("Je ne connais pas cette colonne. Colonnes retirables : nom, secu, adresse, profession, employeur.", "err");
      return;
    }
    found.forEach(n => {
      if (!cfg.cols[n]) { out(`La colonne « ${n} » est déjà retirée.`, "sys"); return; }
      cfg.cols[n] = false; out(`Colonne « ${n} » retirée de la version à publier.`, "ok");
    });
    if (!cfg.cols.nom && !cfg.cols.secu && !x.pseudo) {
      x.pseudo = true; note("pseudo");
      out("Il ne reste plus ni nom ni numéro de sécu : chaque ligne porte un pseudonyme, par exemple « P-" + BASE[0].pseudo + " » (empreinte SHA-256 tronquée du numéro, calculée avec une clé secrète conservée par l'hôpital). Les chercheurs ne peuvent pas remonter au nom, mais l'hôpital le peut : c'est de la pseudonymisation.", "ok");
      say("Docteure Morel", "Voilà : plus de noms, plus de numéros. C'est anonyme, non ?");
      out("Pour en juger comme le ferait un attaquant, regarde ce qu'on trouve à la mairie (est du hall).", "sys");
    }
    if (minDone() && S.room === "guichet") say("Octave", "Bien : plus rien de superflu. Reste la durée de conservation.");
  }

  function generaliser(c) {
    const x = F(), cfg = x.cfg, t = toks(c);
    if (S.room !== "atelier") { out("La généralisation se règle à l'atelier (ouest du hall).", "sys"); return; }
    const attr = t.find(w => /^(cp|code|postal|naissance|age|date)$/.test(w));
    if (!attr) { out("Généraliser quoi ? `generaliser cp 3` (chiffres conservés, de 0 à 5) ou `generaliser naissance 10` (date, mois, annee, 5, 10 ou 20).", "err"); return; }
    const val = t.find((w, i) => i > t.indexOf(attr) && (/^\d+$/.test(w) || /^(date|mois|annee|an|exacte)$/.test(w)));
    if (/^(cp|code|postal)$/.test(attr)) {
      const d = val === undefined ? NaN : +val;
      if (!(d >= 0 && d <= 5) || !/^\d$/.test(val)) { out("Combien de chiffres du code postal garder ? De 0 à 5 : `generaliser cp 3`.", "err"); return; }
      cfg.cp = d; out(`Code postal : ${d} chiffre${d > 1 ? "s" : ""} conservé${d > 1 ? "s" : ""} (${gCp("44310", d)}). Il y a maintenant ${new Set(allRows().map(r => gCp(r.cp, d))).size} valeur(s) distincte(s).`, "ok");
    } else {
      let m = val === "an" ? "annee" : val === "exacte" ? "date" : val;
      if (!MODES.includes(m)) { out("Quelle granularité ? `generaliser naissance date`, `mois`, `annee`, `5`, `10` ou `20` (tranches de 5, 10, 20 ans).", "err"); return; }
      cfg.nais = m; out(`Naissance : ${MODE_TXT[m]} (par exemple ${gNais("1971-03-14", m)}).`, "ok");
    }
    const p = pub();
    out(`Groupes : ${p.g.size} · k actuel = ${p.k} · utilité ${pct(p.util)}. (\`mesurer\` pour le détail)`, "sys");
    if (!x.shownTr) { x.shownTr = true; fig("tranches"); }
  }

  function supprimer(c) {
    const x = F(), cfg = x.cfg, t = toks(c);
    if (S.room !== "atelier") { out("La suppression se règle à l'atelier (ouest du hall).", "sys"); return; }
    const k = +(t.find(w => /^\d+$/.test(w)) || NaN);
    if (!(k >= 0 && k <= 50)) { out("Supprimer les groupes de moins de combien de lignes ? `supprimer 5`. (`supprimer 0` annule.)", "err"); return; }
    cfg.supk = k < 2 ? 0 : k;
    const p = pub();
    if (cfg.supk) out(`Les groupes de moins de ${k} lignes sont supprimés : il reste ${p.rows.length} lignes sur ${p.total} (${p.total - p.rows.length} supprimées).`, "ok");
    else out("Aucune suppression.", "ok");
    out(`k actuel = ${p.k} · utilité ${pct(p.util)}.`, "sys");
    if (cfg.supk && p.rows.length < p.total * 0.6) out("Attention : plus du tiers du jeu a disparu. Les chercheurs perdent aussi la queue de la distribution (les cas rares, souvent les plus intéressants). Généraliser un peu plus avant de supprimer coûte parfois moins cher.", "err");
  }

  function mesurer() {
    const x = F(), cfg = x.cfg;
    if (S.room !== "atelier") { out("Les mesures se font à l'atelier (ouest du hall).", "sys"); return; }
    const p = pub(), uniq = p.rows.length ? [...p.g.values()].filter(a => a.length === 1).length / p.rows.length : 0;
    code([
      `lignes conservées : ${p.rows.length} / ${p.total}`,
      `groupes (cp × naissance × sexe) : ${p.g.size}`,
      `k (plus petit groupe) : ${p.k}`,
      `lignes uniques : ${pct(uniq)}`,
      `l (diagnostics distincts mini) : ${p.l}`,
      `précision conservée : ${pct(p.prec)}`,
      `   cp ${cfg.cp} chiffres · naissance ${MODE_TXT[cfg.nais]}`,
      `utilité globale : ${pct(p.util)}  (minimum ${pct(MIN_UTIL)})`,
    ].join("\n"));
    out("Précision = 1 moins la perte moyenne de finesse (code postal : chiffres perdus sur 5 ; naissance : niveau de généralisation sur 5). Utilité = précision × part des lignes conservées. Indice simplifié du jeu.", "sys");
    if (p.k >= K_TARGET && p.util >= MIN_UTIL) {
      if (!x.kOK) {
        x.kOK = true; note("kanon"); fig("tranches");
        say("Docteure Morel", "5-anonyme et encore utilisable : c'est une version que je peux défendre. Mais ce n'est pas encore une preuve de sécurité.");
        out("Rejoue la jointure à la mairie pour voir ce qu'elle donne maintenant.", "sys");
      } else out("Objectif k ≥ 5 atteint avec une utilité acceptable.", "ok");
    } else if (p.k >= K_TARGET) out(`k ≥ ${K_TARGET}, mais l'utilité (${pct(p.util)}) est sous ${pct(MIN_UTIL)} : trop de perte pour la recherche. Cherche un autre compromis (généraliser moins, supprimer plus, ou l'inverse).`, "err");
    else out(`k = ${p.k} : il reste des groupes de moins de ${K_TARGET} lignes. Généralise ou supprime.`, "err");
  }

  function groupes() {
    if (S.room !== "atelier") { out("Les groupes se consultent à l'atelier (ouest du hall).", "sys"); return; }
    const p = pub(), arr = [...p.g.entries()].map(([k, a]) => ({ k, n: a.length, d: nbMal(a), a })).sort((a, b) => a.n - b.n || a.k.localeCompare(b.k));
    if (!arr.length) { out("Aucun groupe : la version est vide.", "err"); return; }
    out(`Les 6 plus petits groupes sur ${arr.length} (clé : code postal | naissance | sexe) :`, "sys");
    code(arr.slice(0, 6).map(g => {
      const cnt = {}; g.a.forEach(r => cnt[r.maladie] = (cnt[r.maladie] || 0) + 1);
      return `${g.k.replace(/\|/g, " ")} : ${g.n} ligne${g.n > 1 ? "s" : ""}, ${g.d} diagnostic${g.d > 1 ? "s" : ""}\n   ${Object.entries(cnt).map(([m, n]) => `${m} ×${n}`).join(", ")}`;
    }).join("\n"));
  }

  function unicite(c) {
    const x = F(), t = toks(c);
    if (S.room !== "atelier" && S.room !== "mairie") { out("Cette mesure se fait à l'atelier (ouest du hall).", "sys"); return; }
    const names = [...new Set(t.map(w => /^(cp|code|postal)$/.test(w) ? "cp" : /^sexe$/.test(w) ? "sexe" : /^(annee|an)$/.test(w) ? "annee" : /^(naissance|date|age)$/.test(w) ? "naissance" : null).filter(Boolean))];
    if (!names.length) { out("Quels attributs croiser ? `unicite sexe`, `unicite cp sexe`, `unicite cp sexe naissance` (aussi : annee).", "err"); return; }
    const p = pub(), u = uniqShare(p.rows, names, x.cfg);
    out(`Part de lignes uniques (un seul patient avec cette combinaison) sur ${names.map(n => ATTR[n].txt).join(" + ")} : **${pct(u)}** (${names.length} attribut${names.length > 1 ? "s" : ""}).`, u > 0.5 ? "err" : "ok");
    x.uni[Math.min(3, names.length)] = true;
    if (names.length === 3 && !x.shownUni) { x.shownUni = true; }
    if (x.uni[1] && x.uni[2] && x.uni[3] && !x.noteQ) { x.noteQ = true; note("quasi"); fig("unique"); out("Plus on combine d'attributs, plus on devient unique : voilà pourquoi code postal, naissance et sexe sont des quasi-identifiants.", "ok"); }
    else if (names.length < 3 && !(x.uni[1] && x.uni[2] && x.uni[3])) out("Essaie aussi avec 1, 2 puis 3 attributs.", "sys");
  }

  function joindre() {
    const x = F(), cfg = x.cfg;
    if (S.room !== "mairie") { out("La liste électorale est à la mairie (est du hall).", "sys"); return; }
    if (cfg.cols.nom || cfg.cols.secu) {
      out("La table contient encore " + (cfg.cols.nom && cfg.cols.secu ? "les noms et les numéros de sécu" : cfg.cols.nom ? "les noms" : "les numéros de sécu") + " : inutile de croiser quoi que ce soit, tout le monde est déjà identifié. Retire d'abord ces colonnes aux archives (`retirer nom`, `retirer secu`).", "err");
      return;
    }
    const j = joinCalc(cfg), n = j.p.rows.length;
    out(`Jointure sur (code postal, naissance, sexe) entre ${n} lignes de l'hôpital et ${VOTERS.length} électeurs.`, "sys");
    out(`Lignes retrouvées de façon unique : **${j.links.length}** sur ${n} (${pct(n ? j.links.length / n : 0)}), dont ${j.ok.length} avec le bon nom.`, j.links.length ? "err" : "ok");
    if (j.links.length) {
      out("Quelques personnes retrouvées :", "sys");
      code(j.links.slice(0, 5).map(l => `${l.v.nom} → ${l.r.maladie}`).join("\n"));
      if (j.links.length > 5) out(`… et ${j.links.length - 5} autres.`, "sys");
    } else if (j.p.k >= 1) out(`Aucune ligne n'est seule dans son groupe (k = ${j.p.k}) : la jointure ne désigne plus personne en particulier. Elle laisse seulement un ensemble de ${j.p.k} candidats ou plus.`, "ok");
    if (!x.kOK) {
      if (!x.j1) { x.j1 = true; note("reid"); fig("join"); say("Mallory", "Le nom est parti, mais la date de naissance, le code postal et le sexe sont restés. Et la mairie me les donne avec le nom en face. Pas besoin de pirater quoi que ce soit.");
        out("Mallory attend près de toi : `parler mallory`.", "sys"); }
    } else if (!x.rejoin) { x.rejoin = true; out("Cette fois, personne n'est retrouvé de façon unique : le k-anonymat a bloqué la réidentification par jointure. Mais il reste d'autres attaques.", "ok"); }
  }

  /* ============ Attaques sur le k-anonymat ============ */
  function homogene(p) {
    const gs = [...p.g.entries()].filter(([k, a]) => a.length >= 3 && nbMal(a) === 1).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
    const vc = new Map(); VOTERS.forEach(v => { const k = keyOf(v, p.cfg); if (!vc.has(k)) vc.set(k, []); vc.get(k).push(v); });
    for (const [k, a] of gs) { const v = (vc.get(k) || []).find(v => a.some(r => r.id === v.id)); if (v) return { k, a, v }; }
    return null;
  }
  function attaquer(c) {
    const x = F(), t = toks(c);
    if (S.room !== "atelier") { out("Les attaques de test se lancent à l'atelier (ouest du hall).", "sys"); return; }
    const kind = /^homog/.test(t[0] || "") ? "hom" : /^(conn|prealable|savoir|fond|diab)/.test(t[0] || "") ? "know" : null;
    if (!kind) { out("Quelle attaque ? `attaquer homogeneite` ou `attaquer connaissance`.", "err"); return; }
    let cfg = x.cfg, p = pub(), preset = false;
    if (!x.kOK) { out("Pas encore : ta version n'est pas encore 5-anonyme avec une utilité acceptable. Commence par le k-anonymat (`mesurer`).", "sys"); return; }
    const after = !!x.divOK;
    p.cfg = cfg;
    const test = pp => kind === "hom" ? homogene(pp) : know(pp);
    let r = test(p);
    if ((!r || (kind === "know" && !r.certain)) && !after) {
      cfg = DIRECTION(); p = pubWith(cfg); p.cfg = cfg; preset = true; r = test(p);
    }
    if (preset) out(`Sur ta version, ${kind === "hom" ? "aucun groupe n'est homogène" : "aucune déduction certaine n'est possible"} : bravo, mais ce n'est pas le cas partout. La direction, elle, voulait publier une version « 5-anonyme » plus simple : code postal sur 3 chiffres, naissance en tranches de 5 ans, groupes de moins de 5 supprimés (${p.rows.length} lignes). Mallory l'attaque :`, "sys");
    else out(`Mallory attaque ${after ? "ta version diversifiée" : "la version 5-anonyme"} (${p.rows.length} lignes, k = ${p.k}, l = ${p.l}).`, "sys");
    if (kind === "hom") {
      if (!r) {
        out("Aucun groupe d'au moins 3 lignes n'a un diagnostic unique : l'homogénéité ne livre rien ici.", "ok");
        if (after) { x.h2 = true; checkRecheck(); } return;
      }
      const m = r.a[0].maladie;
      out(`Mallory sait que **${r.v.nom}** (${r.v.cp}, né${r.v.sexe === "F" ? "e" : ""} le ${r.v.naissance}) a été hospitalisé${r.v.sexe === "F" ? "e" : ""}. Son groupe : ${r.a.length} lignes (${r.k.replace(/\|/g, " · ")}), toutes avec le même diagnostic.`, "sys");
      out(`Elle ne sait pas laquelle des ${r.a.length} lignes est la sienne. Elle n'en a pas besoin : **${r.v.nom} a : ${m}.** Sa vie privée est brisée sans qu'on ait identifié la ligne.`, "err");
      if (!x.hom) { x.hom = true; fig("tranches"); say("Docteure Morel", "Mais… c'est bien 5-anonyme ! Personne ne peut savoir quelle ligne est la sienne !"); say("Mallory", "Pas besoin : elles disent toutes la même chose."); }
    } else {
      if (!r) { out("Aucun groupe exploitable pour cette attaque.", "ok"); if (after) { x.k2 = true; checkRecheck(); } return; }
      const cnt = {}; r.a.forEach(z => cnt[z.maladie] = (cnt[z.maladie] || 0) + 1);
      out(`Mallory sait que **${r.v.nom}** est dans la table (${r.v.cp}, né${r.v.sexe === "F" ? "e" : ""} le ${r.v.naissance}), et, par un collègue, ${r.v.sexe === "F" ? "qu'elle" : "qu'il"} n'a jamais été diabétique. Son groupe : ${r.a.length} lignes, diagnostics : ${Object.entries(cnt).map(([m, n]) => `${m} ×${n}`).join(", ")}.`, "sys");
      const rest = Object.entries(cnt).filter(([m]) => m !== "diabète"), tot = rest.reduce((s, [, n]) => s + n, 0);
      if (rest.length === 1) {
        out(`Si l'on exclut « diabète », il ne reste que **${rest[0][0]}**. Certitude : ${r.v.nom} a ${rest[0][0]}.`, "err");
        if (!x.know) { x.know = true; }
      } else {
        out(`Après exclusion de « diabète », il reste ${rest.length} possibilités : ${rest.map(([m, n]) => `${m} ${pct(n / tot)}`).join(", ")}. Pas de certitude : Mallory ne peut que parier, avec ${pct(Math.max(...rest.map(([, n]) => n / tot)))} de chances au mieux.`, "ok");
        if (after) { x.k2 = true; checkRecheck(); }
      }
    }
    if (x.hom && x.know && !x.noteH) { x.noteH = true; note("homog"); out("Le k-anonymat protège l'identité de la ligne, pas la valeur sensible. Remède : la l-diversité (`diversifier 3`).", "ok"); }
  }
  // déduction par connaissance préalable : groupe contenant du diabète, avec le moins de diagnostics distincts
  function know(p) {
    const gs = [...p.g.entries()].filter(([k, a]) => a.some(r => r.maladie === "diabète") && nbMal(a) >= 2).sort((a, b) => nbMal(a[1]) - nbMal(b[1]) || a[1].length - b[1].length || a[0].localeCompare(b[0]));
    const vc = new Map(); VOTERS.forEach(v => { const k = keyOf(v, p.cfg); if (!vc.has(k)) vc.set(k, []); vc.get(k).push(v); });
    for (const [k, a] of gs) {
      const v = (vc.get(k) || []).find(v => { const r = a.find(r => r.id === v.id); return r && r.maladie !== "diabète"; });
      if (v) return { k, a, v, certain: nbMal(a) === 2 };
    }
    return null;
  }
  function checkRecheck() {
    const x = F();
    if (x.h2 && x.k2 && !x.recheckSaid) {
      x.recheckSaid = true;
      out("Les deux attaques ne livrent plus de certitude : chaque groupe contient au moins " + L_TARGET + " diagnostics distincts.", "ok");
      out("Limite : si un diagnostic domine fortement un groupe, Mallory peut encore parier juste avec une bonne probabilité (attaque par asymétrie). La l-diversité réduit le risque, elle ne l'annule pas.", "sys");
      say("Docteure Morel", "Bien. Ce jeu est publiable. Mais mon tableau de bord, lui, répond à des requêtes en direct : voyez au sud.");
    }
  }
  function diversifier(c) {
    const x = F(), cfg = x.cfg, t = toks(c);
    if (S.room !== "atelier") { out("La diversité se règle à l'atelier (ouest du hall).", "sys"); return; }
    if (!x.hom || !x.know) { out("Il faut d'abord comprendre le problème : lance les attaques de l'étape précédente (`attaquer homogeneite`, `attaquer connaissance`).", "sys"); return; }
    const l = +(t.find(w => /^\d+$/.test(w)) || NaN);
    if (!(l >= 0 && l <= 8)) { out("Combien de diagnostics distincts exiger par groupe ? `diversifier 3`. (`diversifier 0` annule.)", "err"); return; }
    cfg.divl = l < 2 ? 0 : l;
    const p = pub();
    if (cfg.divl) out(`Les groupes ayant moins de ${l} diagnostics distincts sont supprimés : il reste ${p.rows.length} lignes sur ${p.total}. l = ${p.l}, k = ${p.k}, utilité ${pct(p.util)}.`, "ok");
    else out("Aucune exigence de diversité.", "ok");
    if (p.k >= K_TARGET && p.l >= L_TARGET && p.util >= MIN_UTIL) {
      if (!x.divOK) { x.divOK = true; out("Version 5-anonyme et 3-diverse, avec une utilité acceptable. Il faut maintenant vérifier qu'elle résiste : rejoue les deux attaques.", "ok"); }
    } else if (p.util < MIN_UTIL) out(`Utilité ${pct(p.util)} : sous ${pct(MIN_UTIL)}. Généralise davantage (des groupes plus gros sont plus divers) plutôt que de supprimer trop de lignes.`, "err");
    else if (p.l < L_TARGET) out(`l = ${p.l} : il faut au moins ${L_TARGET}.`, "err");
    else if (p.k < K_TARGET) out(`k = ${p.k} : repasse sous ${K_TARGET}. Vérifie avec \`mesurer\`.`, "err");
  }

  /* ============ Statistiques, différenciation, confidentialité différentielle ============ */
  const MALMAP = { grippe: "grippe", fracture: "fracture", asthme: "asthme", diabete: "diabète", hypertension: "hypertension", depression: "dépression", prostate: "cancer prostate", sein: "cancer sein" };
  function parseQ(c) {
    const t = toks(c), q = { mal: null, jour: LAST_DAY, cp: null };
    for (let i = 0; i < t.length; i++) {
      if (MALMAP[t[i]]) q.mal = MALMAP[t[i]];
      else if (t[i] === "jour" && /^\d+$/.test(t[i + 1] || "")) q.jour = +t[++i];
      else if ((t[i] === "cp" || t[i] === "code") && /^\d{5}$/.test(t[i + 1] || "")) q.cp = t[++i];
    }
    return q;
  }
  const sel = q => allRows().filter(r => r.maladie === q.mal && r.jour <= q.jour && (!q.cp || r.cp === q.cp));
  function budgetCheck(cost) {
    const x = F();
    if (x.eps === null) { out("Choisis d'abord ε : `epsilon 0.5`.", "err"); return false; }
    if (x.budget < cost - 1e-9) {
      out(`Budget épuisé : il reste ${fx(x.budget, 3)}, cette requête coûte ${fx(cost, 3)}. Le tableau de bord refuse de répondre.`, "err");
      if (!x.budgetOut) { x.budgetOut = true; note("dp"); out("Voilà le budget de confidentialité : chaque réponse en consomme une part, et la somme est plafonnée. Sans plafond, un attaquant répéterait la même question, moyennerait les bruits et retrouverait la vraie valeur (l'erreur diminue comme 1/√n).", "ok"); }
      else out("Seule issue : attendre une nouvelle période autorisée par le comité d'éthique, ou renoncer à de nouvelles requêtes. `parler morel` si tu es bloqué avant l'attaque.", "sys");
      return false;
    }
    return true;
  }
  function noisy(exact, b) { const x = F(); const R = rngf(4430 + 7919 * (++x.qn)); return exact + lapl(b, R); }
  function compter(c) {
    const x = F();
    if (S.room !== "stats") { out("Le tableau de bord est au cabinet des statistiques (sud du hall).", "sys"); return; }
    const q = parseQ(c);
    if (!q.mal) { out("Quelle maladie ? `compter depression`, `compter grippe jour 59`… (grippe, fracture, asthme, diabète, hypertension, dépression, prostate, sein)", "err"); return; }
    if (q.jour < 1 || q.jour > LAST_DAY) { out(`Le tableau de bord couvre les jours 1 à ${LAST_DAY}.`, "err"); return; }
    const exact = sel(q).length, lab = `${q.mal}${q.cp ? ", cp " + q.cp : ""}, patients admis jusqu'au jour ${q.jour}`;
    if (x.dp) {
      if (!budgetCheck(x.eps)) return;
      x.budget = Math.round((x.budget - x.eps) * 1000) / 1000;
      const b = 1 / x.eps, v = noisy(exact, b);
      out(`Réponse bruitée : ${lab} → **${fx(v, 1)}** (bruit de Laplace d'échelle 1/ε = ${fx(b, 2)} ; budget restant ${fx(x.budget, 3)}).`, "ok");
      x.qdp.push({ key: q.mal + "|" + (q.cp || ""), jour: q.jour, v, eps: x.eps });
      diffDetect(q, true);
      return;
    }
    if (exact < 5) { out(`Résultat masqué : moins de 5 patients (règle de petits effectifs).`, "sys"); return; }
    out(`${lab} → **${exact}**.`, "ok");
    x.qx.push({ key: q.mal + "|" + (q.cp || ""), jour: q.jour, n: exact });
    diffDetect(q, false);
  }
  function diffDetect(q, dp) {
    const x = F(), key = q.mal + "|" + (q.cp || ""), list = dp ? x.qdp : x.qx, cur = list[list.length - 1];
    for (const prev of list.slice(0, -1)) {
      if (prev.key !== key || prev.jour === cur.jour) continue;
      const lo = Math.min(prev.jour, cur.jour), hi = Math.max(prev.jour, cur.jour);
      const between = allRows().filter(r => r.jour > lo && r.jour <= hi && (!q.cp || r.cp === q.cp));
      const a = prev.jour < cur.jour ? prev : cur, bb = prev.jour < cur.jour ? cur : prev;
      if (!dp) {
        const d = bb.n - a.n;
        if (between.length === 1) {
          const w = between[0];
          out(`Mallory soustrait : ${bb.n} (jour ${bb.jour}) − ${a.n} (jour ${a.jour}) = ${d}. La seule personne admise entre ces deux états est **${w.nom}**, que Mallory a vue arriver. Écart ${d} : ${w.nom} ${d === 1 ? "A" : "n'a PAS"} ${q.mal}.`, "err");
          out("La règle « pas de petits effectifs » n'a rien empêché : aucun des deux résultats n'est petit.", "err");
          if (!x.diff) { x.diff = true; note("diff"); fig("diff"); say("Docteure Morel", "Deux statistiques anodines, et voilà un patient mis à nu… Il faut une autre protection."); }
        } else if (between.length > 1 && !x.sawMix) { x.sawMix = true; out(`L'écart (${d}) mélange ${between.length} personnes admises entre les jours ${lo + 1} et ${hi} : l'attaque est moins précise. Resserre l'intervalle (jour ${LAST_DAY - 1} contre jour ${LAST_DAY}).`, "sys"); }
        return;
      }
      if (between.length === 1) {
        const w = between[0], D = bb.v - a.v, truth = allRows().find(r => r.id === w.id).maladie === q.mal, e = Math.max(prev.eps, cur.eps), tot = prev.eps + cur.eps;
        const pairKey = lo + "-" + hi + "-" + key + "-" + x.qn;
        if (x.pairs.includes(pairKey)) continue; x.pairs.push(pairKey);
        out(`Mallory soustrait : ${fx(bb.v, 1)} − ${fx(a.v, 1)} = ${fx(D, 1)}. Elle cherche à savoir si ${w.nom} (seul${w.sexe === "F" ? "e" : ""} admis${w.sexe === "F" ? "e" : ""} ${lo + 1 === hi ? "le jour " + hi : "entre les jours " + (lo + 1) + " et " + hi}) a ${q.mal}. Si l'écart dépasse 0,5, elle répondra « oui ».`, "sys");
        out(`Son pari : « ${D > 0.5 ? "oui" : "non"} » : c'est ${(D > 0.5) === truth ? "juste" : "faux"} cette fois, mais avec ε = ${fx(e, 3)} par requête son taux de réussite moyen n'est que de ${pct(atkAcc(e))} (pile ou face = 50 %). Garantie théorique pour ${fx(tot, 3)} de budget dépensé : au plus ${pct(boundAcc(tot))}.`, e <= 1 ? "ok" : "err");
        if (e <= 1) { if (!x.dpAtk) { x.dpAtk = true; note("dp"); fig("laplace"); say("Docteure Morel", "Elle en est réduite à parier. Et ce n'est pas du flou : c'est un calcul."); } }
        else out("ε est encore trop généreux : le bruit est faible et l'attaque réussit presque à tous les coups. Baisse ε (`epsilon 0.5`).", "err");
        return;
      }
    }
  }
  function somme(c) {
    const x = F();
    if (S.room !== "stats") { out("Le tableau de bord est au cabinet des statistiques (sud du hall).", "sys"); return; }
    const q = parseQ(c);
    if (!q.mal) { out("Somme des durées de séjour pour quelle maladie ? `somme depression`", "err"); return; }
    const B = x.borne, rows = sel(q), exact = rows.reduce((s, r) => s + Math.min(r.duree, B), 0), raw = rows.reduce((s, r) => s + r.duree, 0);
    if (!x.dp) { out(`Somme des durées de séjour (écrêtées à ${B} jours) pour ${q.mal} : **${exact}** jours (non écrêtée : ${raw}). Écrêter limite l'influence d'un seul patient à ${B} jours : c'est la sensibilité de cette requête.`, "ok"); return; }
    if (!budgetCheck(x.eps)) return;
    x.budget = Math.round((x.budget - x.eps) * 1000) / 1000;
    const b = B / x.eps, v = noisy(exact, b);
    out(`Somme bruitée (durées écrêtées à ${B} j) pour ${q.mal} → **${fx(v, 1)}** jours. Sensibilité = borne = ${B}, donc bruit d'échelle ${B}/${fx(x.eps, 3)} = ${fx(b, 1)}. (Valeur exacte cachée : ${exact} ; budget restant ${fx(x.budget, 3)}.)`, "ok");
    out(`Un comptage a une sensibilité de 1 ; ici, une personne peut changer la somme de ${B} jours. À ε égal, le bruit est ${B} fois plus gros. Une borne plus basse réduit le bruit, mais écrête davantage les longs séjours (\`borne ‹jours›\`).`, "sys");
    if (!x.sumDP) { x.sumDP = true; }
  }
  function borne(c) {
    const x = F(), v = +(toks(c).find(w => /^\d+$/.test(w)) || NaN);
    if (!(v >= 1 && v <= 200)) { out("Quelle borne d'écrêtage, en jours ? `borne 30` (de 1 à 200).", "err"); return; }
    x.borne = v; out(`Borne d'écrêtage : ${v} jours. La sensibilité des sommes devient ${v}.`, "ok");
  }
  function activer(c) {
    const x = F(), t = toks(c);
    if (/^(bruit|dp|confidentialite|differentielle|laplace)/.test(t[0] || "")) {
      if (S.room !== "stats") { out("Le mode bruité se règle au cabinet des statistiques (sud du hall).", "sys"); return; }
      if (!x.diff) { say("Docteure Morel", "Pourquoi bruiter ? Voyons d'abord si les statistiques actuelles sont vulnérables : essayez de comparer deux états du tableau de bord."); return; }
      if (x.dp) { out("Déjà activé.", "sys"); return; }
      x.dp = true;
      out(`Mode confidentialité différentielle activé. Chaque réponse reçoit un bruit de Laplace d'échelle sensibilité/ε, tiré d'un générateur reproductible. Chaque requête dépense ε du budget total (${BUDGET0}).`, "ok");
      out("Choisis ε : `epsilon ‹valeur›` (ex. 0.5). Plus il est petit, plus la protection est forte et plus la réponse est floue.", "sys");
    } else out("Activer quoi ? `activer bruit`.", "err");
  }
  function epsilon(c) {
    const x = F(), raw = (c.rawArg || "").replace(",", ".").match(/[\d.]+/);
    if (S.room !== "stats") { out("ε se règle au cabinet des statistiques (sud du hall).", "sys"); return; }
    if (!x.dp) { out("Active d'abord le mode bruité : `activer bruit`.", "sys"); return; }
    const v = raw ? parseFloat(raw[0]) : NaN;
    if (!(v >= 0.01 && v <= 100)) { out("ε doit être compris entre 0,01 et 100 : `epsilon 0.5`.", "err"); return; }
    x.eps = v;
    out(`ε = ${fx(v, 3)} par requête : bruit d'échelle 1/ε = ${fx(1 / v, 2)} pour un comptage. Avec un budget de ${BUDGET0}, tu disposes d'environ ${Math.floor(BUDGET0 / v + 1e-9)} requête(s).`, "ok");
    if (v > 1) out("C'est plutôt généreux : peu de bruit, peu de protection. Voyons ce que Mallory en tire.", "sys");
    if (!x.shownLap) { x.shownLap = true; fig("laplace"); }
  }
  function budget() {
    const x = F();
    if (!x.dp) { out("Aucun budget tant que le mode bruité n'est pas activé : `activer bruit`.", "sys"); return; }
    out(`Budget de confidentialité : ${fx(x.budget, 3)} restant sur ${BUDGET0}. ε par requête : ${x.eps === null ? "non choisi" : fx(x.eps, 3)}.`, "sys");
  }
  function compromis() {
    const x = F();
    if (S.room !== "stats") { out("Le compromis se calcule au cabinet des statistiques (sud du hall).", "sys"); return; }
    if (!x.dp) { out("Active d'abord le mode bruité pour parler de ε : `activer bruit`.", "sys"); return; }
    const ref = sel({ mal: "dépression", jour: LAST_DAY }).length;
    const eps = [0.05, 0.1, 0.5, 1, 2, 5];
    out(`Compromis pour un comptage (par exemple « dépression » : ${ref} patients) et pour l'attaque de différenciation de Mallory :`, "sys");
    code("ε      erreur  erreur   attaque\n       typique relative réussie\n" + eps.map(e => `${String(e).padEnd(6)} ${("±" + fx(1 / e, 1)).padEnd(7)} ${pct(1 / e / ref).padEnd(8)} ${pct(atkAcc(e))}`).join("\n"));
    out("Erreur typique = erreur absolue moyenne = 1/ε. Attaque réussie : exactitude de Mallory sur deux requêtes (50 % = hasard). Garantie : avec une dépense totale de 2ε, elle ne dépasse jamais e^(2ε)/(1+e^(2ε)).", "sys");
    out("Les deux courbes vont en sens inverse : ce qui protège (un grand bruit) abîme l'utilité (réponses floues), et inversement. Il n'existe pas de bon ε universel, seulement un choix de société, expliqué et assumé. Plus la population est grande, plus l'erreur relative baisse : le bruit absolu ne dépend pas de la taille.", "sys");
    if (!x.trade) { x.trade = true; fig("laplace"); }
  }

  /* ============ Minimisation, conservation, droits ============ */
  function conservation(c) {
    const x = F(), v = +(toks(c).find(w => /^\d+$/.test(w)) || NaN), t = toks(c);
    if (S.room !== "guichet") { out("La durée de conservation se fixe au guichet des droits (est du cabinet).", "sys"); return; }
    if (!minDone()) { say("Octave", "Commençons par la minimisation : retire d'abord les colonnes sans rapport avec la finalité."); return; }
    if (t.some(w => /^(toujours|indefiniment|illimite|jamais)/.test(w))) { say("Octave", "« Toujours » n'est pas une durée : c'est l'absence de décision. On garde le temps nécessaire à la finalité, pas plus."); return; }
    if (!(v >= 0)) { out("Combien d'années ? `conservation 5`", "err"); return; }
    if (v < 3) say("Octave", `${v} an${v > 1 ? "s" : ""} ? Le projet dure 3 ans : il faut pouvoir publier et justifier les résultats. Trop court.`);
    else if (v > 5) say("Octave", `${v} ans ? Rien dans la finalité ne justifie de garder au-delà de 3 ans de projet et 2 ans d'archivage de vérification. Au-delà, on supprime ou on anonymise vraiment.`);
    else { x.keep = true; out(`Durée de conservation fixée à ${v} ans, avec suppression automatique à l'échéance, inscrite au registre.`, "ok"); say("Octave", "Voilà une durée liée à la finalité, décidée avant de collecter. Passons aux droits : Alice t'attend."); }
  }
  function accorder(c) {
    const x = F(), t = toks(c);
    if (S.room !== "guichet") { out("Les demandes se traitent au guichet des droits.", "sys"); return; }
    if (!minDone() || !x.keep) { say("Octave", "Termine d'abord la minimisation et la durée de conservation du projet."); return; }
    const a = t.find(w => /^(acces|effacement|efface|oubli)/.test(w));
    if (!a) { out("Accorder quoi ? `accorder acces` ou `accorder effacement`.", "err"); return; }
    const al = BASE[ALICE - 1];
    if (/^acces/.test(a)) {
      x.accAcc = true;
      out("Droit d'accès : Alice reçoit une copie de ce que l'hôpital détient sur elle, et la finalité du traitement :", "ok");
      code(`${al.nom} · ${al.naissance} · ${al.cp} · ${al.sexe}\ndiagnostic : ${al.maladie} · séjour ${al.duree} j\nfinalité : recherche sur la durée de séjour\nconservation : 5 ans`);
      say("Alice", "Je vois ce que vous avez. Maintenant, je voudrais que vous le retiriez de la base de recherche.");
    } else {
      if (!x.erased.includes(ALICE)) x.erased.push(ALICE);
      x.accEff = true;
      out(`Droit à l'effacement : la ligne d'Alice est retirée de la base (il reste ${allRows().length} patients). Si elle figurait dans une version réellement anonymisée et déjà diffusée, on ne pourrait pas la retrouver : c'est précisément parce qu'elle ne se rattache plus à personne que le RGPD ne s'applique plus. Dans une version seulement pseudonymisée, on retrouve et on efface.`, "ok");
      out("(Nuance : l'effacement connaît des exceptions, par exemple pour la recherche d'intérêt public quand l'effacement la compromettrait gravement ; l'opposition et l'information restent dues.)", "sys");
      say("Alice", "Merci d'avoir pris ma demande au sérieux.");
    }
    if (x.accAcc && x.accEff) { note("min"); out("Ada t'attend dans le hall pour l'épilogue : `parler ada`.", "sys"); }
  }

  /* ============ Fin ============ */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Le jeu de données publié est 5-anonyme et 3-diverse, le tableau de bord est bruité et plafonné par un budget, les colonnes inutiles sont parties, la conservation est bornée et Alice a eu réponse. Le tout n'est pas une garantie absolue : c'est un risque mesuré, réduit, documenté, et réévalué à chaque nouvelle publication.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Retirer les noms = pseudonymisation.** Le jeu reste une donnée personnelle (RGPD) : la personne est retrouvable par recoupement ou via la table de correspondance. L'anonymisation exige que la réidentification soit impossible par des moyens raisonnables, et il faut le démontrer.");
    out("**La liste électorale = une source auxiliaire publique.** La réidentification est une jointure sur des quasi-identifiants (code postal, date de naissance, sexe). C'est exactement le principe des cas réels cités : dossiers hospitaliers rapprochés d'une liste électorale (1997), notes de films rapprochées d'avis publics (2008).");
    out("**Les lignes uniques et le k-anonymat.** La part de lignes uniques grimpe avec le nombre d'attributs. Le k-anonymat impose des groupes d'au moins k lignes identiques sur les quasi-identifiants, par généralisation (tronquer, mettre en tranches) et suppression. Chaque effort coûte de la précision.");
    out("**Homogénéité et l-diversité.** Un groupe où tout le monde a la même maladie trahit chacun de ses membres sans qu'on trouve sa ligne ; une connaissance préalable réduit un groupe à peu de valeurs possibles. La l-diversité exige plusieurs valeurs sensibles par groupe ; la t-proximité va plus loin sur leur répartition.");
    out("**Différenciation et confidentialité différentielle.** Deux agrégats qui diffèrent d'une personne la révèlent. La confidentialité différentielle borne cette fuite de façon mathématique : bruit de Laplace d'échelle sensibilité/ε, budget qui s'additionne (composition), écrêtage pour borner la sensibilité des sommes.");
    out("**Minimisation, conservation, droits.** Ne collecter que le nécessaire, fixer une durée, informer, et honorer accès, rectification, effacement, opposition et limitation. La base légale n'est pas forcément le consentement.");
    out("**Les simplifications du jeu.** (1) Les tables comptent quelques centaines de lignes inventées ; les vraies ont des millions de lignes et bien plus de colonnes, ce qui rend la réidentification plus facile, pas moins. (2) L'indice d'utilité est une métrique jouet ; en pratique on mesure l'erreur sur les analyses réellement visées. (3) La liste électorale ici est complète à 80 % ; l'attaquant réel dispose d'autres sources, et chaque source de plus aide. (4) La confidentialité différentielle simulée est « centrale » (un serveur de confiance bruite les réponses) ; la version locale bruite côté utilisateur. Les compositions sont ici simplement additives, alors que des théorèmes plus fins existent. (5) Le RGPD, ici résumé, comporte des exceptions et des régimes particuliers (données de santé, recherche) à examiner avec un juriste.");
    out("Rappel utile : **retirer les noms ne rend pas un jeu anonyme : on mesure l'unicité, on généralise, on teste les attaques, et pour les statistiques on borne mathématiquement la fuite.**", "ok");
  }

  /* ============ Schémas ============ */
  const figs = {
    join: () => {
      const b = BASE[BOB - 1];
      return {
        cap: "Une jointure sur trois colonnes communes suffit : le nom vient de la liste publique, la maladie de l'hôpital.",
        svg: SVG(250, "Jointure entre jeu pseudonymisé et liste électorale",
          T(104, 18, "Hôpital (pseudonymisé)", "f-b") + R(8, 28, 192, 74, "f-priv") +
          T(18, 48, "P-" + b.pseudo + " · " + b.maladie, "f-s", "start") + T(18, 68, b.cp + " · " + b.naissance + " · " + b.sexe, "ft-bad f-s", "start") + T(18, 90, "(+ " + (NPAT - 1) + " autres lignes)", "f-s", "start") +
          T(316, 18, "Liste électorale (publique)", "f-b") + R(220, 28, 192, 74, "f-pub") +
          T(230, 48, b.nom, "f-s", "start") + T(230, 68, b.cp + " · " + b.naissance + " · " + b.sexe, "ft-bad f-s", "start") + T(230, 90, "(+ " + (VOTERS.length - 1) + " autres)", "f-s", "start") +
          AR(200, 65, 220, 65, "f-bad", true) + T(210, 124, "jointure sur code postal + naissance + sexe", "ft-bad f-s") +
          AR(210, 132, 210, 160, "f-bad") + R(60, 160, 300, 46, "f-bad") + T(210, 182, b.nom + " → " + b.maladie, "f-b ft-bad") + T(210, 198, "nom + maladie : vie privée perdue", "f-s") +
          T(210, 234, "aucun mot de passe ni piratage : des données publiques", "f-s"))
      };
    },
    unique: () => {
      const x = F(), p = pub(), cfg = x.cfg;
      const sets = [[["sexe"], "sexe"], [["sexe", "cp"], "+ code postal"], [["sexe", "cp", "annee"], "+ année de naiss."], [["sexe", "cp", "naissance"], "+ naissance (publiée)"]];
      let body = T(8, 18, `Lignes uniques de la table publiée (${p.rows.length} lignes)`, "f-b", "start");
      sets.forEach(([nm, lab], i) => {
        const u = uniqShare(p.rows, nm, cfg), y = 36 + i * 44, w = Math.round(210 * u), col = u > 0.5 ? "var(--bad)" : u > 0.1 ? "var(--you)" : "var(--ok)";
        body += T(8, y + 14, lab, "f-s", "start") + R(150, y, 210, 20) + (w > 0 ? `<rect x="150" y="${y}" width="${w}" height="20" rx="4" fill="${col}" opacity=".7"/>` : "") + T(368, y + 15, pct(u), "f-b", "start") +
          T(8, y + 30, nm.length + " attribut" + (nm.length > 1 ? "s" : ""), "f-s", "start");
      });
      body += T(210, 222, `code postal : ${cfg.cp} chiffres · naissance : ${MODE_TXT[cfg.nais]}`, "f-s");
      return { cap: "Part de lignes uniques selon le nombre de quasi-identifiants. Plus on combine d'attributs, plus on devient unique. Le schéma se met à jour quand tu généralises.", svg: SVG(236, "Population unique selon les attributs", body) };
    },
    tranches: () => {
      const x = F(), p = pub(), cfg = x.cfg;
      const cls = [["1", n => n === 1], ["2-4", n => n >= 2 && n <= 4], ["5-9", n => n >= 5 && n <= 9], ["10-19", n => n >= 10 && n <= 19], ["20+", n => n >= 20]];
      const sizes = [...p.g.values()].map(a => a.length);
      const rowsIn = cls.map(([, f2]) => sizes.filter(f2).reduce((s, n) => s + n, 0));
      const mx = Math.max(1, ...rowsIn);
      let body = T(8, 18, `Lignes selon la taille de leur groupe (k = ${p.k})`, "f-b", "start");
      cls.forEach(([lab], i) => {
        const bx = 60 + i * 70, h = Math.round(110 * rowsIn[i] / mx), risk = i < 2;
        body += `<rect x="${bx}" y="${150 - h}" width="48" height="${h}" rx="4" fill="${risk ? "var(--bad)" : "var(--ok)"}" opacity=".7"/>` + T(bx + 24, 144 - h, String(rowsIn[i]), "f-s") + T(bx + 24, 166, lab, "f-s");
      });
      body += LN(189, 28, 189, 150, "f-dash") + T(210, 182, "à gauche du trait (k < 5) : lignes en danger", "ft-bad f-s") +
        T(210, 204, `code postal ${cfg.cp} chiffres · naissance ${MODE_TXT[cfg.nais]}`, "f-s") + T(210, 222, `utilité ${pct(p.util)} · ${p.rows.length}/${p.total} lignes`, "f-b");
      return { cap: "Taille des groupes d'équivalence selon la généralisation choisie. En généralisant, les lignes passent à droite du seuil, mais la précision baisse.", svg: SVG(236, "Généralisation en tranches", body) };
    },
    diff: () => {
      const x = F(), q = (x.qx || []).filter(r => r.key.startsWith("dépression")), a = q.find(r => r.jour === LAST_DAY - 1), bq = q.find(r => r.jour === LAST_DAY), bob = BASE[BOB - 1];
      const na = a ? a.n : 0, nb = bq ? bq.n : 0;
      return {
        cap: "Deux statistiques qui diffèrent d'une seule personne : la soustraction révèle sa valeur, même si aucun des deux chiffres n'est « petit ».",
        svg: SVG(230, "Attaque par différenciation",
          R(8, 24, 190, 60) + T(103, 44, "Requête A (jour " + (LAST_DAY - 1) + ")", "f-b") + T(103, 62, "dépression", "f-s") + T(103, 78, String(na), "f-b ft-pub") +
          R(222, 24, 190, 60) + T(317, 44, "Requête B (jour " + LAST_DAY + ")", "f-b") + T(317, 62, "dépression", "f-s") + T(317, 78, String(nb), "f-b ft-pub") +
          T(210, 112, "B − A = " + (nb - na), "f-b ft-bad") + AR(103, 86, 160, 120, "f-bad") + AR(317, 86, 260, 120, "f-bad") +
          R(60, 128, 300, 54, "f-bad") + T(210, 150, "Seul admis le jour " + LAST_DAY + " : " + bob.nom, "f-s") + T(210, 172, (nb - na === 1 ? "il a donc ce diagnostic" : "écart : " + (nb - na)), "f-b ft-bad") +
          T(210, 208, "les petits effectifs masqués ne protègent pas ici", "f-s"))
      };
    },
    laplace: () => {
      const x = F(), e = x.eps === null ? 1 : x.eps, b = 1 / e;
      // densité de Laplace(0, b), normalisée à 100 px au sommet ; en rouge : l'écart que l'on veut cacher (1 personne)
      const X0 = 20, X1 = 400, YB = 140, sx = (X1 - X0) / 16, cx = X0 + 8 * sx;
      let path = "";
      for (let i = 0; i <= 160; i++) {
        const u = -8 + i / 10, py = YB - 100 * Math.exp(-Math.abs(u) / b);
        path += (i ? "L" : "M") + (X0 + (u + 8) * sx).toFixed(1) + "," + py.toFixed(1);
      }
      return {
        cap: "Bruit de Laplace ajouté à un comptage (sensibilité 1) selon ε. Les traits rouges marquent l'écart d'une personne, ce qu'on veut cacher. ε petit : courbe large, l'écart se noie. ε grand : courbe très pointue, l'écart reste visible.",
        svg: SVG(236, "Bruit de Laplace selon epsilon",
          T(8, 18, `ε = ${fx(e, 3)} · échelle b = 1/ε = ${fx(b, 2)}`, "f-b", "start") +
          LN(X0, YB, X1, YB) + LN(cx - sx, 34, cx - sx, YB, "f-bad f-dash") + LN(cx + sx, 34, cx + sx, YB, "f-bad f-dash") +
          `<path d="${path}" fill="none" stroke="var(--you)" stroke-width="2"/>` +
          T(cx, 158, "0", "f-s") + T(cx + 4 * sx, 158, "+4", "f-s") + T(cx - 4 * sx, 158, "−4", "f-s") + T(cx + sx, 30, "1 personne", "ft-bad f-s") +
          T(210, 178, "erreur ajoutée à la vraie valeur", "f-s") +
          T(210, 200, `erreur typique ± ${fx(b, 2)} · attaquant (2 requêtes) : ${pct(atkAcc(e))}`, "f-s") +
          T(210, 220, `borne théorique : ${pct(boundAcc(2 * e))} (50 % = hasard)`, "f-s"))
      };
    },
  };

  GAMES.privacy = {
    id: "privacy", order: 28, title: "Le Registre Anonyme", pageTitle: "Privacy Quest", subtitle: "aventure textuelle · vie privée et anonymisation",
    blurb: "Teste l'« anonymisation » du jeu de données de l'hôpital en le recoupant, puis protège-le avec k-anonymat et bruit calibré.",
    concept: "Vie privée : réidentification, k-anonymat, confidentialité différentielle",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      x.cfg = defCfg(); x.erased = []; x.uni = {}; x.qx = []; x.qdp = []; x.pairs = []; x.qn = 0; x.eps = null; x.budget = BUDGET0; x.borne = 30;
    },
    refig(name) { fig(name); },
    figAlias: { join: ["jointure", "reidentification", "croisement"], unique: ["unicite", "population", "attributs"], tranches: ["generalisation", "groupes", "k", "kanonymat"], diff: ["differenciation", "soustraction", "agregats"], laplace: ["bruit", "epsilon", "dp", "confidentialite"] },
    help: "Spécifiques : `retirer ‹colonne›` · `joindre` · `unicite ‹attributs›` · `generaliser ‹cp|naissance› ‹valeur›` · `supprimer ‹k›` · `mesurer` · `groupes` · `attaquer ‹homogeneite|connaissance›` · `diversifier ‹l›` · `compter ‹maladie› [jour ‹n›]` · `somme ‹maladie›` · `activer bruit` · `epsilon ‹valeur›` · `borne ‹jours›` · `budget` · `compromis` · `conservation ‹années›` · `accorder ‹acces|effacement›`",
    verbs: {
      retirer: { words: ["retirer", "enlever", "ecarter"], run: retirer },
      generaliser: { words: ["generaliser", "grouper", "tronquer"], run: generaliser },
      supprimer: { words: ["supprimer", "purger"], run: supprimer },
      mesurer: { words: ["mesurer", "evaluer", "mesures"], run: mesurer },
      groupes: { words: ["groupes", "classes"], run: groupes },
      unicite: { words: ["unicite", "unique", "uniques"], run: unicite },
      joindre: { words: ["joindre", "croiser", "relier", "apparier", "jointure"], run: joindre },
      attaquer: { words: ["attaquer", "tester", "tenter"], run: attaquer },
      diversifier: { words: ["diversifier", "diversite", "ldiversite"], run: diversifier },
      compter: { words: ["compter", "combien", "requete"], run: compter },
      somme: { words: ["somme", "totaliser", "additionner"], run: somme },
      activer: { words: ["activer", "bruiter"], run: activer },
      epsilon: { words: ["epsilon", "eps"], run: epsilon },
      borne: { words: ["borne", "ecreter", "plafonner"], run: borne },
      budget: { words: ["budget", "solde"], run: budget },
      compromis: { words: ["compromis", "arbitrage", "utilite"], run: compromis },
      conservation: { words: ["conservation", "conserver", "garder"], run: conservation },
      accorder: { words: ["accorder", "honorer", "autoriser"], run: accorder },
    },
    intro() {
      out("Le Registre Anonyme", "title");
      out("L'hôpital de Port-443 veut publier son registre de patients pour la recherche médicale. La Docteure Morel l'assure : « on a retiré les noms, c'est anonyme ». Maître Ada te demande de vérifier cette promesse comme le ferait un attaquant, puis d'améliorer le jeu de données. Audit autorisé ; les patients, les listes et les chiffres sont fictifs, mais les calculs sont réels.", "");
    },
  };
})();
