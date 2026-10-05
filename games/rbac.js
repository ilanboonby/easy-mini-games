"use strict";
/* Le Registre des Clés : RBAC, moindre privilège, séparation des tâches, dérive des privilèges,
   escalade simulée, accès juste-à-temps, aperçu d'ABAC. Le moteur de droits est réel : tout est calculé. */
(function () {
  const F = () => f();
  const STOP = new Set(["le", "la", "les", "l", "un", "une", "des", "du", "de", "d", "mon", "ma", "mes", "ce", "cette", "ces", "en", "et", "a", "au", "aux", "sur", "pour", "dans", "vers", "par"]);
  const tk = s => norm(s || "").split(" ").filter(t => t && !STOP.has(t));

  const ACTS = { lire: "lire", ecrire: "écrire", approuver: "approuver", administrer: "administrer" };
  const RSHORT = { registre: "registre", virements: "virements", journaux: "journaux", sauvegardes: "sauvegardes", prod: "prod" };
  const RES = Object.keys(RSHORT);
  const AMAP = new Map([["lire", "lire"], ["consulter", "lire"], ["voir", "lire"], ["ecrire", "ecrire"], ["saisir", "ecrire"], ["modifier", "ecrire"], ["approuver", "approuver"], ["valider", "approuver"], ["administrer", "administrer"], ["admin", "administrer"]]);
  const actOf = t => AMAP.get(t) || null;
  const resOf = t => /^(registre|registres|compte|comptes)$/.test(t) ? "registre" : /^(virement|virements|virer)$/.test(t) ? "virements" : /^(journal|journaux|logs?)$/.test(t) ? "journaux" : /^(sauvegarde|sauvegardes|backup|backups)$/.test(t) ? "sauvegardes" : /^(prod|production|serveur|serveurs)$/.test(t) ? "prod" : null;
  const pp = k => { const [a, r] = k.split(":"); return ACTS[a] + " " + RSHORT[r]; };

  const PERS = {
    camille: { n: "Camille", job: "comptable", svc: "finance", login: 1 },
    zoe: { n: "Zoé", job: "comptable", svc: "finance", login: 1 },
    theo: { n: "Théo", job: "comptable", svc: "finance", login: 0 },
    hugo: { n: "Hugo", job: "responsable", svc: "finance", login: 1 },
    lea: { n: "Léa", job: "sysadmin", svc: "informatique", login: 0 },
    paul: { n: "Paul", job: "auditeur", svc: "audit", login: 2 },
    noor: { n: "Noor", job: "dev", svc: "informatique", login: 1 },
    sam: { n: "Sam", job: "stagiaire", svc: "informatique", login: 1 },
    yann: { n: "Yann", job: "parti", svc: "externe", login: 214 },
    ines: { n: "Inès", job: "parti", svc: "informatique", login: 131 },
  };
  const hasP = t => Object.prototype.hasOwnProperty.call(PERS, t);
  const JOBL = { comptable: "comptable", responsable: "responsable des virements", sysadmin: "administratrice système", auditeur: "auditeur", dev: "développeuse", stagiaire: "stagiaire", parti: "parti·e, compte jamais fermé" };
  const NEEDS = {
    comptable: ["lire:registre", "lire:virements", "ecrire:virements"],
    responsable: ["lire:virements", "approuver:virements"],
    sysadmin: ["administrer:prod", "administrer:sauvegardes", "lire:journaux"],
    auditeur: ["lire:registre", "lire:virements", "lire:journaux"],
    dev: ["ecrire:prod", "lire:journaux"],
    stagiaire: ["lire:registre"],
    parti: [],
  };
  const pn = p => PERS[p].n;
  const jobOf = p => F().job[p] || PERS[p].job;
  const svcOf = p => F().svc[p] || PERS[p].svc;
  const needsOf = p => { const x = F(); let n = (NEEDS[jobOf(p)] || []).slice(); if (x.jitMode && p === "lea") n = n.filter(k => k !== "administrer:prod"); return n; };
  const fmtT = m => { const t = 540 + m; return String(Math.floor(t / 60) % 24).padStart(2, "0") + ":" + String(t % 60).padStart(2, "0"); };
  const ada = t => say("Maître Ada", t);

  /* ---------- le moteur de droits ---------- */
  function permsOf(p, standing) {
    const x = F(), m = new Map();
    const add = (k, s) => { if (!m.has(k)) m.set(k, []); m.get(k).push(s); };
    (x.assign[p] || []).forEach(r => (x.roles[r] || []).forEach(k => add(k, "rôle " + r)));
    (x.direct[p] || []).forEach(k => add(k, "droit direct"));
    if (!standing && x.jit[p] && x.jit[p].exp > x.clock) add(x.jit[p].perm, "accès temporaire");
    return m;
  }
  function check(p, a, r) {
    const x = F();
    if (x.disabled[p]) return { ok: false, dis: true };
    const m = permsOf(p), k = a + ":" + r;
    return m.has(k) ? { ok: true, by: m.get(k) } : { ok: false };
  }
  const viol = p => { const m = permsOf(p); return F().rules.filter(([a, b]) => m.has(a) && m.has(b)); };
  const active = () => F().people.filter(p => !F().disabled[p]);
  const anyViol = () => active().flatMap(p => viol(p).map(r => [p, r]));
  const vkey = v => v[0] + "|" + v[1].join("|");
  function guarded(mutate) {
    const x = F(), before = new Set(anyViol().map(vkey));
    const snap = JSON.stringify([x.roles, x.assign]);
    mutate();
    const bad = anyViol().filter(v => !before.has(vkey(v)));
    if (bad.length) { const s = JSON.parse(snap); x.roles = s[0]; x.assign = s[1]; }
    return bad;
  }
  const sodRule = () => F().rules.some(r => r.includes("ecrire:virements") && r.includes("approuver:virements"));
  const roleFor = p => (F().assign[p] || [])[0];
  const roleGiving = (p, k) => (F().assign[p] || []).find(r => (F().roles[r] || []).includes(k));
  const members = r => Object.keys(F().assign).filter(p => F().assign[p].includes(r) && F().people.includes(p));
  function problems(p) {
    const x = F(), st = permsOf(p, true), need = needsOf(p);
    return { miss: need.filter(k => !permsOf(p).has(k)), extra: [...st.keys()].filter(k => !need.includes(k)), viol: viol(p), dorm: PERS[p].login > 90 && !x.disabled[p] };
  }
  const issuesOf = pr => pr.miss.length + pr.extra.length + pr.viol.length + (pr.dorm ? 1 : 0);
  const allIssues = () => active().reduce((n, p) => n + issuesOf(problems(p)), 0);
  const vulnerable = t => ["ecrire:registre", "lire:sauvegardes", "administrer:prod"].some(k => permsOf(t).has(k));
  const leaStanding = () => permsOf("lea", true).has("administrer:prod");

  const notes = {
    authn: ["Authentification et autorisation", "L'authentification répond à « qui es-tu ? » (mot de passe, clé, facteur supplémentaire). L'autorisation répond à « qu'as-tu le droit de faire ? ». Un attaquant qui vole un mot de passe réussit l'authentification : tout ce qui reste pour le limiter, c'est l'autorisation."],
    roles: ["Les rôles (RBAC)", "Plutôt que d'accorder des droits personne par personne, on regroupe les permissions en rôles qui correspondent à des métiers (comptable, auditeur…), puis on affecte les personnes aux rôles. Arrivée, départ, changement de poste : on modifie une affectation, pas vingt droits. C'est le modèle RBAC (Role-Based Access Control)."],
    refus: ["Le refus par défaut", "Une demande n'est acceptée que si une règle l'accorde explicitement. Tout le reste est refusé. Un oubli produit alors un refus (visible, vite corrigé) plutôt qu'un accès ouvert (invisible, découvert par l'attaquant)."],
    moindre: ["Le moindre privilège", "Chacun reçoit exactement les permissions nécessaires à son travail, ni plus ni moins. Cela se vérifie : on compare ce qui est accordé à ce qui est nécessaire. Chaque permission en trop agrandit le « rayon d'impact » d'un compte compromis ou d'une erreur."],
    sod: ["La séparation des tâches", "Certaines actions ne doivent pas être possibles par une seule personne : saisir ET approuver un virement, par exemple (principe des quatre yeux, « maker-checker »). On l'exprime par des règles de conflit entre permissions : aucun rôle, ni cumul de rôles, ne doit les réunir chez la même personne."],
    derive: ["La dérive des privilèges", "Au fil des changements de poste, on ajoute des rôles sans retirer les anciens : les droits s'accumulent (privilege creep). Parade : des revues périodiques d'accès (recertification) et un processus « arrivée, mutation, départ » qui retire autant qu'il ajoute."],
    dormants: ["Les comptes dormants", "Un compte inutilisé (ancien prestataire, stage terminé) reste une porte ouverte, sans personne pour remarquer une connexion inhabituelle. On désactive les comptes inactifs, puis on les supprime après une durée de conservation définie."],
    jit: ["L'accès juste-à-temps", "Un droit d'administration permanent est une cible permanente. En « juste-à-temps » (JIT), il est demandé pour une tâche, approuvé par un tiers, limité à une courte durée, journalisé, puis il disparaît tout seul. Le compte de tous les jours n'est plus administrateur."],
    abac: ["ABAC : les droits selon des attributs", "Dans l'ABAC (Attribute-Based Access Control), la décision dépend d'attributs : de la personne (service), de la ressource (sensibilité) et du contexte (heure, lieu, appareil). Il complète le RBAC : le rôle dit ce qui est possible, les attributs disent dans quelles conditions. Attention à la complexité des politiques."],
  };

  /* ---------- lieux et entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle t'a confié l'audit des droits d'accès de Port-443 : tout se passe sur des données fictives, avec l'accord de la Guilde." },
    sam: { npc: true, names: ["sam", "stagiaire"], label: "Sam, le stagiaire", desc: () => "Sam, stagiaire en informatique, qui range des câbles à l'accueil entre deux demandes. Son compte lui permet de lire le registre des comptes, et c'est en principe tout." },
    camille: { npc: true, names: ["camille", "comptable"], label: "Camille, la comptable", desc: () => "Camille, comptable, qui saisit les virements de la Guilde du matin au soir." },
    hugo: { npc: true, names: ["hugo", "responsable"], label: "Hugo, le responsable des virements", desc: () => "Hugo, responsable financier : il approuve les virements saisis par la comptabilité." },
    lea: { npc: true, names: ["lea", "administratrice", "sysadmin"], label: "Léa, l'administratrice système", desc: () => "Léa, administratrice système : elle s'occupe du serveur de production et des sauvegardes." },
    paul: { npc: true, names: ["paul", "auditeur"], label: "Paul, l'auditeur", desc: () => "Paul, auditeur interne. Il lit tout ce qu'il contrôle et ne modifie rien : c'est sa force." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", vis: () => F().ph >= 6, desc: () => "Mallory, l'attaquante, qui joue ici le rôle d'un adversaire pour l'exercice autorisé : elle ne fait que ce que les droits du compte volé lui permettent." },
    registre: { names: ["registre", "grand registre", "registre des cles", "console"], label: "le Registre des Clés", onExamine() { F().sawReg = true; },
      desc: () => "Le Registre des Clés : un meuble à tiroirs et une console. Il consigne les personnes, les rôles, les permissions, et décide de chaque demande d'accès.\n`droits` : qui peut quoi · `roles` : les rôles · `besoins` : les fiches de poste · `controler` : conformité\n`creer role ‹nom›` · `accorder ‹rôle› ‹action› ‹ressources›` · `affecter ‹personne› ‹rôle›` · `retirer …` · `supprimer ‹rôle›`\n`tester ‹personne› ‹action› ‹ressource›` : le moteur décide et explique.\nActions : lire, ecrire, approuver, administrer. Ressources : registre, virements, journaux, sauvegardes, prod." },
    fiches: { names: ["fiches", "fiche", "besoins", "fiches de poste"], label: "les fiches de poste", onExamine() { needsTable(); },
      desc: () => "Les fiches de poste : ce dont chaque métier a réellement besoin pour travailler (`besoins`)." },
    console: { names: ["console de virements", "virements", "console virement"], label: "la console de virements", vis: () => S.room === "finances",
      desc: () => F().ph < 4 ? "La console de virements : une personne saisit, une autre approuve. Elle ne sera utile que plus tard." : "La console de virements (simulée). `virement ‹qui saisit› ‹qui approuve›` lance un virement et le moteur vérifie les droits de chacun.", },
    politique: { names: ["panneau", "politique", "panneau abac"], label: "le panneau des politiques contextuelles", vis: () => S.room === "finances",
      desc: () => F().ph < 8 ? "Un panneau recouvert d'un drap. Maître Ada le dévoilera plus tard." : "Politique de virement : écrire des virements est permis à la personne dont le rôle l'accorde ET dont le service est « finance » ET entre 8 h et 19 h ET depuis le bureau.\n`abac ‹personne› ‹heure› ‹lieu›` (lieu : bureau, domicile, etranger)." },
    journal: { names: ["journal", "journaux", "grand livre"], label: "le grand livre des journaux", vis: () => S.room === "audit",
      desc: () => "Le grand livre : chaque décision du Registre y est consignée (qui, quoi, résultat). L'audit consiste surtout à le relire." },
    poste: { names: ["poste", "console d exercice", "exercice"], label: "le poste d'exercice", vis: () => S.room === "serveurs",
      desc: () => F().ph < 6 ? "Un poste de test éteint. Il servira plus tard." : "Le poste d'exercice : `lancer exercice ‹personne›` rejoue ce que ferait Mallory avec le mot de passe volé de cette personne, en appliquant les vrais droits configurés." },
  };

  const rooms = {
    hall: { name: "Le hall de la Guilde", short: "Hall", alias: ["hall", "guilde", "accueil"], ents: ["ada", "sam"], exits: { nord: "registre", est: "finances", ouest: "serveurs", sud: "audit" },
      desc: () => "Le grand hall de la Guilde de Port-443. Au nord, le bureau du Registre des Clés. À l'est, les finances. À l'ouest, la salle des serveurs. Au sud, le bureau de l'audit." },
    registre: { name: "Le bureau du Registre des Clés", short: "Registre", alias: ["registre", "bureau registre"], ents: ["registre", "fiches"], exits: { sud: "hall" },
      desc: () => "Un bureau étroit, tapissé de tiroirs étiquetés. Le Registre des Clés y trône : tout droit d'accès de la Guilde y est consigné et chaque demande y est jugée." },
    finances: { name: "Le service des finances", short: "Finances", alias: ["finances", "finance"], ents: ["camille", "hugo", "console", "politique"], exits: { ouest: "hall" },
      desc: () => "Des piles de factures, deux écrans et une console de virements. Ici, de l'argent bouge." },
    serveurs: { name: "La salle des serveurs", short: "Serveurs", alias: ["serveurs", "salle des serveurs", "serveur"], ents: ["lea", "poste", "mallory"], exits: { est: "hall" },
      desc: () => "Des baies ronronnantes, un air froid. C'est ici que vivent la production et les sauvegardes." },
    audit: { name: "Le bureau de l'audit", short: "Audit", alias: ["audit"], ents: ["paul", "journal"], exits: { nord: "hall" },
      desc: () => "Un bureau sobre, des classeurs alignés au cordeau. Paul y relit les journaux et vérifie que les droits correspondent aux besoins." },
  };

  /* ---------- objectifs et indices ---------- */
  const hasRoleBased = (p, k) => [...permsOf(p).entries()].some(([kk, s]) => kk === k && s.some(t => t.startsWith("rôle")));
  const p1ok = () => ["camille", "zoe"].every(p => !(F().direct[p] || []).length && NEEDS.comptable.every(k => permsOf(p, true).has(k)));
  const objective = () => {
    const x = F();
    switch (x.ph) {
      case 0: return "quest";
      case 1: {
        if (!x.sawDroits) return "droits";
        if (!x.denied) return "tester0";
        const full = Object.keys(x.roles).find(r => NEEDS.comptable.every(k => x.roles[r].includes(k)));
        if (!full) return Object.keys(x.roles).length ? "perm1" : "mk1";
        if (!["camille", "zoe"].every(p => NEEDS.comptable.every(k => hasRoleBased(p, k)))) return "aff1";
        return "purge1";
      }
      case 2: return "onboard";
      case 3: return allIssues() ? "lp" : "lpcheck";
      case 4:
        if (!x.fraudSeen && !x.rules.length) return "fraud";
        if (!sodRule()) return "rule";
        if (anyViol().length) return "fixhugo";
        return "vok";
      case 5: return !x.audited ? "see5" : allIssues() ? "fix5" : "audit5";
      case 6: return !x.exoSeen && vulnerable("sam") ? "exo1" : vulnerable("sam") ? "fix6" : "exo2";
      case 7:
        if (leaStanding()) return "standing";
        if (!x.jitReq) return "jitreq";
        if (!x.jitGranted) return "jitval";
        if (!x.jitExpired) return "wait7";
        return "exoLea";
      case 8: return "abac";
      default: return x.end ? "fin" : "end";
    }
  };
  const hints = {
    quest: () => ["Maître Ada t'attend dans le hall.", "`parler ada`"],
    droits: () => ["Commence par regarder l'état des droits à la console du Registre.", "`aller nord` puis `droits` (et `droits camille` pour le détail)."],
    tester0: () => ["Pose deux questions au moteur : une demande légitime, et une qui ne devrait pas passer.", "`tester camille lire journaux` puis `tester sam lire registre`."],
    mk1: () => ["Au lieu d'accorder des droits personne par personne, crée un rôle pour le métier de comptable.", "`creer role comptable`"],
    perm1: () => ["Donne au rôle les trois permissions qu'utilisent Camille et Zoé : lire le registre, lire et écrire les virements.", "`accorder comptable lire registre virements` puis `accorder comptable ecrire virements` (remplace « comptable » par le nom de ton rôle)."],
    aff1: () => ["Affecte maintenant Camille et Zoé au rôle.", "`affecter camille comptable` et `affecter zoe comptable`."],
    purge1: () => ["Il reste des droits directs : sans les retirer, le rôle ne sert à rien.", "`retirer droits camille` et `retirer droits zoe`, puis vérifie : `tester camille ecrire virements`."],
    onboard: () => ["Théo, nouveau comptable, commence aujourd'hui. Une seule commande suffit.", "`affecter theo comptable` (avec le nom de ton rôle)."],
    lp: () => ["`controler` montre, pour chaque personne, ce qui manque et ce qui est en trop ; `besoins` donne les fiches de poste. Le vieux rôle fourre-tout est le coupable.", "`supprimer employe`, puis pour chaque métier : `creer role auditeur`, `accorder auditeur lire registre virements journaux`, `affecter paul auditeur`. Même méthode : responsable (Hugo : lire et approuver virements), sysadmin (Léa : administrer prod sauvegardes, lire journaux), dev (Noor : ecrire prod, lire journaux), stagiaire (Sam : lire registre). Une action par commande `accorder`."],
    lpcheck: () => ["Tout semble en ordre : lance le contrôle officiel.", "`controler`"],
    fraud: () => ["Dans l'exercice, Mallory tient le mot de passe de Hugo. Va aux finances et vois ce que Hugo peut faire seul sur la console de virements.", "`aller sud` ou `aller nord` jusqu'au hall, `aller est`, puis `virement hugo hugo`."],
    rule: () => ["Déclare une règle de séparation : personne ne doit pouvoir à la fois saisir et approuver un virement.", "`interdire ecrire virements avec approuver virements`"],
    fixhugo: () => {
      const v = anyViol()[0], p = v ? v[0] : "hugo", r = v ? roleGiving(p, "ecrire:virements") || roleGiving(p, v[1][0]) || roleFor(p) : "comptable";
      return ["Le moteur signale un cumul interdit. `droits " + p + "` montre d'où vient chaque permission : retire à la personne le rôle qu'elle n'aurait jamais dû avoir.", "`retirer " + p + " " + r + "`"];
    },
    vok: () => ["Vérifie que le processus légitime fonctionne : une personne saisit, une autre approuve (console des finances).", "`virement camille hugo`"],
    see5: () => ["Six mois ont passé. Va au bureau de l'audit (sud du hall) et lance la revue des droits.", "`auditer`"],
    fix5: () => {
      const x = F(), zr = roleGiving("zoe", "ecrire:virements") || "comptable";
      return ["La revue signale des écarts : un cumul de rôles après un changement de poste et des comptes dormants. Corrige-les, puis relance la revue.", "`retirer zoe " + zr + "`, `desactiver yann`, `desactiver ines`, puis `auditer`."];
    },
    audit5: () => ["Relance la revue pour la valider.", "`auditer` (au bureau de l'audit)."],
    exo1: () => ["Un poste d'exercice, dans la salle des serveurs (ouest du hall), rejoue ce que ferait Mallory avec le mot de passe volé de Sam.", "`aller ouest` (depuis le hall) puis `lancer exercice`."],
    fix6: () => ["L'exercice a montré la chaîne : quelles permissions de Sam la rendent possible ? `droits sam` et `roles` montrent d'où elles viennent. Un stagiaire n'a pas besoin de ça.", "`retirer sam support` (ou `retirer support ecrire registre` et `retirer support lire sauvegardes`)."],
    exo2: () => ["Rejoue l'exercice : la chaîne doit être coupée.", "`lancer exercice` (salle des serveurs)."],
    standing: () => {
      const r = roleGiving("lea", "administrer:prod") || "sysadmin";
      return ["Même une administratrice de confiance est une cible : un droit d'administration permanent est un risque permanent. Retire-le du rôle, on l'accordera à la demande.", "`retirer " + r + " administrer prod`"];
    },
    jitreq: () => ["Léa doit intervenir sur la production : elle en fait la demande, pour une durée limitée.", "`demander lea administrer prod 30`"],
    jitval: () => ["Tu es l'approbateur, une autre personne que la demandeuse. Valide la demande puis vérifie ce que le moteur répond.", "`valider demande`, puis `tester lea administrer prod`."],
    wait7: () => ["Laisse le temps passer : le droit doit disparaître sans que personne ne le révoque.", "`attendre 30` puis `tester lea administrer prod`."],
    exoLea: () => ["Rejoue l'exercice sur le compte de Léa, hors fenêtre d'accès.", "`lancer exercice lea` (salle des serveurs)."],
    abac: () => ["Dernier aperçu : les droits selon des attributs. Aux finances, le panneau évalue le service, l'heure et le lieu. Essaie un cas normal et des cas anormaux.", "`abac camille 14 bureau`, `abac camille 23 domicile`, `abac paul 14 bureau` (salle des finances)."],
    end: () => ["Rends compte à Maître Ada.", "`parler ada` (dans le hall)."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- affichages ---------- */
  function needsTable() {
    const x = F();
    out("Fiches de poste : le besoin légitime de chaque métier.", "sys");
    code(x.people.filter(p => !x.disabled[p]).map(p => `${pn(p).padEnd(8)}${(JOBL[jobOf(p)] || "").slice(0, 24).padEnd(25)}${needsOf(p).map(pp).join(", ") || "rien"}`).join("\n"));
  }
  function showDroits(c) {
    const x = F(), t = tk(c.rawArg), p = t.find(hasP);
    x.sawDroits = true;
    if (p && x.people.includes(p)) {
      const m = permsOf(p), v = viol(p);
      out(`Droits de ${pn(p)} (${JOBL[jobOf(p)]})${x.disabled[p] ? " : COMPTE DÉSACTIVÉ" : ""}`, "title");
      code(m.size ? [...m.entries()].map(([k, s]) => `${pp(k).padEnd(24)}← ${s.join(" + ")}`).join("\n") : "(aucune permission)");
      v.forEach(([a, b]) => out(`Attention : cumul interdit par la règle « ${pp(a)} ⟂ ${pp(b)} ».`, "err"));
      return;
    }
    out("Qui peut quoi, aujourd'hui", "title");
    code(x.people.map(q => { const d = (x.direct[q] || []).length; return `${pn(q).padEnd(8)}${((x.assign[q] || []).join(",") || "-").padEnd(18)}${d ? d + " droit(s) direct(s)" : ""}${x.disabled[q] ? "désactivé" : ""}`; }).join("\n"));
    if (!x.people.some(q => (x.direct[q] || []).length)) out("Plus aucun droit direct : tout passe par les rôles.", "sys");
    fig("matrice");
  }
  function showRoles() {
    const x = F(), rs = Object.keys(x.roles);
    if (!rs.length) { out("Aucun rôle pour l'instant. `creer role ‹nom›`", "sys"); return; }
    out("Les rôles", "title");
    code(rs.map(r => `${r} : ${x.roles[r].map(pp).join(", ") || "(vide)"}\n    membres : ${members(r).join(", ") || "personne"}`).join("\n"));
  }

  /* ---------- progression ---------- */
  function adv(n) {
    const x = F(); x.ph = n;
    if (n === 2) {
      x.people.push("theo");
      note("roles"); fig("matrice");
      ada("Voilà ce que valent les rôles : changer le métier d'un groupe, c'est changer UNE ligne. Et justement, Théo, un nouveau comptable, arrive ce matin. Avec des droits accordés au cas par cas, il aurait fallu recopier la liste de Camille en espérant n'oublier ni ajouter rien de trop.");
      out("Affecte-lui le bon rôle : `affecter theo ‹rôle›`", "sys");
    } else if (n === 3) {
      x.roles.employe = ["lire:registre", "lire:virements", "lire:journaux", "lire:sauvegardes", "lire:prod"];
      ["hugo", "lea", "paul", "noor", "sam"].forEach(p => x.assign[p] = ["employe"]);
      note("refus");
      ada("Une seule commande pour Théo : il est opérationnel. Voyons les autres : les comptes de Hugo, Léa, Paul, Noor et Sam n'avaient RIEN au départ. Refus par défaut : `tester hugo lire virements` t'aurait répondu non. Mais j'ai trouvé dans le Registre un vieux rôle « employe » que quelqu'un a affecté à ces cinq personnes pour « que tout marche ».");
      out("Ton chantier : le moindre privilège. Ce que fait chaque métier est dans `besoins` ; `controler` vérifie automatiquement, personne par personne, ce qui manque et ce qui est en trop.", "sys");
    } else if (n === 4) {
      note("moindre");
      const r = roleGiving("camille", "ecrire:virements") || Object.keys(x.roles).find(k => x.roles[k].includes("ecrire:virements"));
      x.assign.hugo = (x.assign.hugo || []).concat(r);
      ada(`Conforme, personne n'a plus que son besoin. Mais attends : voilà ce que les contrôles ne voient pas. Pendant les vacances de Camille, on a affecté à Hugo le rôle « ${r} » pour la remplacer, et plus personne n'y a repensé. Dans l'exercice autorisé de cette semaine, Mallory tient le mot de passe de Hugo.`);
      out("Va aux finances (est du hall) et observe ce que Hugo peut faire tout seul : `virement hugo hugo`.", "sys");
    } else if (n === 5) {
      note("sod"); fig("separation");
      x.rules.push(["ecrire:virements", "lire:journaux"]);
      x.job.zoe = "auditeur"; x.svc.zoe = "audit";
      x.assign.zoe = (x.assign.zoe || []).concat(roleFor("paul"));
      x.assign.yann = [roleFor("noor")]; x.assign.ines = [roleFor("sam")];
      x.people.push("yann", "ines");
      ada("Quatre yeux : la séparation des tâches tient. Six mois plus tard (le temps passe vite dans la Guilde) : Zoé a rejoint l'audit interne. Le jour de sa mutation, on lui a donné le rôle d'auditeur, mais personne n'a retiré l'ancien. La conformité impose aussi une règle d'indépendance : qui lit les journaux d'audit ne doit pas pouvoir écrire dans les virements qu'il contrôle. De plus, Yann (prestataire) et Inès (stage d'été) sont partis, et leurs comptes sont toujours là.");
      out("Va au bureau de l'audit (sud du hall) : `auditer`.", "sys");
    } else if (n === 6) {
      note("derive");
      x.roles.support = ["ecrire:registre", "lire:sauvegardes", "lire:journaux"];
      x.assign.sam = (x.assign.sam || []).concat("support");
      ada("La revue est propre. Mais le Registre continue de vivre. Cette semaine, pour dépanner le help desk, quelqu'un a donné à Sam le rôle « support » (réinitialiser des comptes, restaurer des fichiers depuis les sauvegardes, consulter les journaux) : il est stagiaire, il ne fait pas de mal. Vraiment ? Mallory a hameçonné son mot de passe, dans un exercice autorisé.");
      out("Va à la salle des serveurs (ouest du hall) : le poste d'exercice rejouera la suite avec les vrais droits : `lancer exercice`.", "sys");
    } else if (n === 7) {
      x.jitMode = true;
      ada("La chaîne est coupée : Sam n'est plus un levier. Reste un risque plus gros : Léa détient en permanence un droit d'administration sur la production. Si son compte tombe, tout tombe. La Guilde veut passer à l'accès juste-à-temps : l'administration ne s'accorde plus qu'à la demande, pour une durée courte, sur approbation.");
      out("Commence par retirer le droit permanent du rôle de Léa.", "sys");
    } else if (n === 8) {
      note("jit"); fig("temporaire");
      ada("Le privilège le plus dangereux est devenu éphémère. Dernier chapitre, plus court : un aperçu de ce que l'on peut ajouter au RBAC. Le panneau des politiques, aux finances, est dévoilé.");
      out("Aux finances : `abac ‹personne› ‹heure› ‹lieu›`, par exemple `abac camille 14 bureau`.", "sys");
    } else if (n === 9) {
      note("abac"); fig("abac");
      ada("Voilà. Rends-moi compte quand tu veux.");
      out("Retourne voir Maître Ada dans le hall : `parler ada`.", "sys");
    }
  }
  function progress() {
    const x = F();
    if (x.ph === 1 && p1ok()) adv(2);
    if (x.ph === 2 && NEEDS.comptable.every(k => permsOf("theo").has(k))) adv(3);
    if (x.ph === 4 && sodRule() && !anyViol().length && x.vOK) adv(5);
    if (x.ph === 7 && !leaStanding() && x.jitGranted && x.jitExpired && x.exoLea) adv(8);
    if (x.ph === 8 && x.abac && x.abac.ok && x.abac.service && x.abac.ctx) adv(9);
  }

  /* ---------- commandes de configuration ---------- */
  function mkRole(c) {
    const x = F(), t = tk(c.rawArg); if (t[0] === "role" || t[0] === "roles") t.shift();
    if (!t.length) { out("`creer role ‹nom›` (un seul mot, par exemple creer role comptable).", "err"); return; }
    if (t.length > 1) { out("Un nom de rôle tient en un seul mot (ex. `creer role comptable`).", "err"); return; }
    const n = t[0];
    if (!/^[a-z0-9]+$/.test(n) || hasP(n) || ["droits", "direct", "directs", "role", "roles", "demande"].includes(n)) { out("Nom de rôle invalide ou réservé. Choisis un nom de métier, ex. `creer role comptable`.", "err"); return; }
    if (x.roles[n]) { out(`Le rôle « ${n} » existe déjà (\`roles\` pour le voir).`, "sys"); return; }
    x.roles[n] = [];
    out(`Rôle « ${n} » créé, encore vide : il n'autorise rien. Ajoute-lui des permissions : \`accorder ${n} ‹action› ‹ressource›\``, "ok");
  }
  function grant(c) {
    const x = F(), t = tk(c.rawArg); if (t[0] === "role") t.shift();
    if (t.length < 3) { out("`accorder ‹rôle› ‹action› ‹ressource(s)›` (ex. accorder comptable lire registre virements).", "err"); return; }
    const r = t[0];
    if (!x.roles[r]) { out(`Il n'y a pas de rôle « ${r} ». \`creer role ${r}\` d'abord (ou \`roles\` pour la liste).`, "err"); return; }
    const a = t.slice(1).map(actOf).find(Boolean);
    if (!a) { out("Quelle action ? lire, ecrire, approuver ou administrer.", "err"); return; }
    const rs = [...new Set(t.slice(1).map(resOf).filter(Boolean))];
    if (!rs.length) { out("Quelle ressource ? registre, virements, journaux, sauvegardes ou prod.", "err"); return; }
    const ks = rs.map(q => a + ":" + q), fresh = ks.filter(k => !x.roles[r].includes(k));
    if (!fresh.length) { out("Ces permissions sont déjà dans le rôle.", "sys"); return; }
    const bad = guarded(() => fresh.forEach(k => x.roles[r].push(k)));
    if (bad.length) { const [p, rule] = bad[0]; out(`Refusé par une règle de séparation : « ${pp(rule[0])} ⟂ ${pp(rule[1])} ». Avec cette permission, ${pn(p)} cumulerait les deux. Rien n'a été modifié.`, "err"); return; }
    out(`Le rôle « ${r} » autorise maintenant : ${fresh.map(pp).join(", ")}. Membres concernés : ${members(r).map(pn).join(", ") || "personne pour l'instant"}.`, "ok");
    progress();
  }
  function assign(c) {
    const x = F(), t = tk(c.rawArg), p = t.find(hasP), r = t.find(q => !hasP(q));
    if (!p || !x.people.includes(p)) { out("Qui ? `affecter ‹personne› ‹rôle›` (ex. affecter camille comptable). Personnes : " + x.people.join(", ") + ".", "err"); return; }
    if (!r || !x.roles[r]) { out(`Ce rôle n'existe pas${r ? " : « " + r + " »" : ""}. \`roles\` pour la liste.`, "err"); return; }
    if ((x.assign[p] || []).includes(r)) { out(`${pn(p)} a déjà le rôle « ${r} ».`, "sys"); return; }
    const bad = guarded(() => { x.assign[p] = (x.assign[p] || []).concat(r); });
    if (bad.length) { const rule = bad[0][1]; out(`Refusé par la règle de séparation « ${pp(rule[0])} ⟂ ${pp(rule[1])} » : avec « ${r} », ${pn(p)} cumulerait ces deux permissions. Rien n'a été modifié.`, "err"); if (!x.guardSeen) { x.guardSeen = true; out("C'est tout l'intérêt d'une règle : le moteur empêche l'erreur AVANT qu'elle ne se produise, y compris celle d'un administrateur pressé.", "sys"); } return; }
    out(`${pn(p)} a maintenant le rôle « ${r} ».${x.disabled[p] ? " (Son compte est désactivé : aucun effet tant qu'il l'est.)" : ""}`, "ok");
    progress();
  }
  function revoke(c) {
    const x = F(), t = tk(c.rawArg);
    if (!t.length) { out("`retirer ‹personne› ‹rôle›` · `retirer ‹rôle› ‹action› ‹ressource›` · `retirer droits ‹personne›`", "err"); return; }
    if (["droit", "droits", "directs"].includes(t[0])) {
      const p = t.find(hasP);
      if (!p || !x.people.includes(p)) { out("Les droits directs de qui ? `retirer droits camille`", "err"); return; }
      const d = x.direct[p] || [];
      if (!d.length) { out(`${pn(p)} n'a aucun droit direct.`, "sys"); return; }
      x.direct[p] = [];
      out(`Droits directs de ${pn(p)} retirés (${d.map(pp).join(", ")}). Désormais, seuls ses rôles comptent.`, "ok");
      progress(); return;
    }
    if (hasP(t[0])) {
      const p = t[0], r = t[1];
      if (!x.people.includes(p)) { out("Cette personne n'existe pas (encore).", "err"); return; }
      if (!r || !(x.assign[p] || []).includes(r)) { out(`${pn(p)} n'a pas ce rôle${r ? " (« " + r + " »)" : ""}. Rôles de ${pn(p)} : ${(x.assign[p] || []).join(", ") || "aucun"}.`, "err"); return; }
      x.assign[p] = x.assign[p].filter(q => q !== r);
      out(`Le rôle « ${r} » est retiré à ${pn(p)}.`, "ok");
      progress(); return;
    }
    const r = t[0];
    if (!x.roles[r]) { out(`Rien à retirer sous « ${t[0]} » : ni personne, ni rôle. \`roles\` pour la liste.`, "err"); return; }
    const a = t.slice(1).map(actOf).find(Boolean), rs = [...new Set(t.slice(1).map(resOf).filter(Boolean))];
    if (!a || !rs.length) { out("`retirer ‹rôle› ‹action› ‹ressource›` (ex. retirer support ecrire registre)", "err"); return; }
    const ks = rs.map(q => a + ":" + q).filter(k => x.roles[r].includes(k));
    if (!ks.length) { out(`Le rôle « ${r} » n'accordait pas cela.`, "sys"); return; }
    x.roles[r] = x.roles[r].filter(k => !ks.includes(k));
    out(`Le rôle « ${r} » n'autorise plus : ${ks.map(pp).join(", ")}. Cela touche : ${members(r).map(pn).join(", ") || "personne"}.`, "ok");
    progress();
  }
  function delRole(c) {
    const x = F(), t = tk(c.rawArg); if (t[0] === "role") t.shift();
    const r = t[0];
    if (!r || !x.roles[r]) { out("Quel rôle supprimer ? `supprimer ‹rôle›` (`roles` pour la liste).", "err"); return; }
    const m = members(r);
    delete x.roles[r];
    Object.keys(x.assign).forEach(p => x.assign[p] = x.assign[p].filter(q => q !== r));
    out(`Rôle « ${r} » supprimé, et retiré à : ${m.map(pn).join(", ") || "personne"}. Ces personnes n'ont plus ces permissions.`, "ok");
    progress();
  }
  function ruleCmd(c) {
    const x = F(), parts = norm(c.rawArg).split(" avec ");
    const parse = s => { const t = tk(s); const a = t.map(actOf).find(Boolean), r = t.map(resOf).find(Boolean); return a && r ? a + ":" + r : null; };
    const A = parts.length === 2 ? parse(parts[0]) : null, B = parts.length === 2 ? parse(parts[1]) : null;
    if (!A || !B) { out("`interdire ‹action› ‹ressource› avec ‹action› ‹ressource›` : par exemple interdire ecrire virements avec approuver virements.", "err"); return; }
    if (A === B) { out("Une règle de conflit oppose deux permissions différentes.", "err"); return; }
    if (x.rules.some(r => r.includes(A) && r.includes(B))) { out("Cette règle existe déjà.", "sys"); return; }
    x.rules.push([A, B]);
    out(`Règle enregistrée : nul ne peut détenir à la fois « ${pp(A)} » et « ${pp(B)} », par un seul rôle comme par un cumul de rôles.`, "ok");
    const v = anyViol().filter(q => q[1].includes(A) && q[1].includes(B));
    if (v.length) out(`Le moteur détecte des cumuls existants : ${v.map(q => pn(q[0])).join(", ")}. À corriger (\`droits ${v[0][0]}\` montre l'origine).`, "err");
    else out("Aucun cumul existant. Le moteur refusera tout futur cumul.", "sys");
    progress();
  }
  function disable(c) {
    const x = F(), p = tk(c.rawArg).find(hasP);
    if (!p || !x.people.includes(p)) { out("Quel compte ? `desactiver yann`", "err"); return; }
    if (x.disabled[p]) { out("Déjà désactivé.", "sys"); return; }
    if (PERS[p].login <= 90 && !(x.ph >= 5 && jobOf(p) === "parti")) { out(`${pn(p)} s'est connecté·e il y a ${PERS[p].login} jour(s) : ce compte est actif, on ne le désactive pas.`, "err"); return; }
    x.disabled[p] = true;
    out(`Compte de ${pn(p)} désactivé : plus aucune authentification ne donnera de droits (${PERS[p].login} jours sans connexion). Le compte est conservé pour la traçabilité, avant suppression selon la politique de rétention.`, "ok");
    note("dormants"); progress();
  }

  /* ---------- tester ---------- */
  function testCmd(c) {
    const x = F(), t = tk(c.rawArg), p = t.find(hasP);
    if (!p || !x.people.includes(p)) { out("`tester ‹personne› ‹action› ‹ressource›` (ex. tester camille lire registre). Personnes : " + x.people.join(", ") + ".", "err"); return; }
    const rest = t.filter(q => q !== p), a = rest.map(actOf).find(Boolean), r = rest.map(resOf).find(Boolean);
    if (!a || !r) { out("Il faut une action (lire, ecrire, approuver, administrer) et une ressource (registre, virements, journaux, sauvegardes, prod).", "err"); return; }
    const res = check(p, a, r), k = a + ":" + r;
    out(`Demande : ${pn(p)} veut ${ACTS[a]} ${RSHORT[r]} (${fmtT(x.clock)}).`, "sys");
    if (res.ok) {
      out(`AUTORISÉ : accordé par ${res.by.join(" ; ")}.`, "ok");
      if (res.by.includes("accès temporaire")) out(`Cet accès est temporaire : il expire à ${fmtT(x.jit[p].exp)}.`, "sys");
      if (!(needsOf(p).includes(k))) out(`Remarque : ce n'est pas dans le besoin du poste de ${pn(p)} (${JOBL[jobOf(p)]}). Une permission en trop : à examiner.`, "sys");
    } else {
      x.denied = true;
      if (res.dis) out(`REFUSÉ : le compte de ${pn(p)} est désactivé.`, "err");
      else {
        const roles = x.assign[p] || [];
        out(`REFUSÉ : ${roles.length ? `aucun des rôles de ${pn(p)} (${roles.join(", ")}) ne contient « ${pp(k)} »` : `${pn(p)} n'a aucun rôle`}. Refus par défaut : ce qui n'est pas explicitement accordé est interdit.`, "err");
      }
      note("refus");
    }
  }

  /* ---------- contrôle et audit ---------- */
  function report(audit) {
    const x = F(), lines = [];
    let n = 0;
    active().forEach(p => {
      const pr = problems(p), parts = [];
      if (pr.miss.length) parts.push("MANQUE " + pr.miss.map(pp).join(", "));
      if (pr.extra.length) parts.push("EN TROP " + pr.extra.map(pp).join(", "));
      pr.viol.forEach(([a, b]) => parts.push(`CUMUL INTERDIT (${pp(a)} ⟂ ${pp(b)})`));
      if (pr.dorm) parts.push(`DORMANT (${PERS[p].login} j sans connexion)`);
      const ok = !parts.length; n += parts.length;
      lines.push(`${ok ? "OK " : "XX "}${pn(p).padEnd(7)}${(JOBL[jobOf(p)] || "").slice(0, 16).padEnd(17)}${x.ph >= 5 ? ("j-" + PERS[p].login).padEnd(6) : ""}${ok ? "conforme" : parts.join(" ; ")}`);
    });
    code(lines.join("\n"));
    return n;
  }
  function controlCmd() {
    const x = F();
    out("Contrôle de conformité : droits accordés comparés au besoin du poste.", "sys");
    const n = report(false);
    if (n) out(`${n} écart(s). « MANQUE » : un besoin légitime est bloqué. « EN TROP » : une permission que le poste n'exige pas.`, "err");
    else out("Aucun écart : chacun a exactement ce dont il a besoin.", "ok");
    if (x.ph === 3 && !n) adv(4); else if (x.ph === 3) { /* continuer */ }
    progress();
  }
  function auditCmd() {
    const x = F();
    if (S.room !== "audit") { out("La revue des droits se fait au bureau de l'audit (sud du hall).", "sys"); return; }
    if (x.ph < 5) { out("Paul : « Pas de revue à faire pour l'instant : tu viens juste de reconfigurer les droits. »", "sys"); return; }
    say("Paul", "Je compare, pour chaque compte, les droits accordés au besoin du poste actuel, les règles de conflit et la dernière connexion.");
    const n = report(true);
    x.audited = true;
    if (n) out(`${n} écart(s) relevé(s). Dernière colonne : « j-N » = jours depuis la dernière connexion.`, "err");
    else out("Revue propre : droits conformes, aucun cumul, aucun compte dormant actif.", "ok");
    if (x.ph === 5 && !n) adv(6);
  }

  /* ---------- virements ---------- */
  function pay(c) {
    const x = F();
    if (S.room !== "finances") { out("La console de virements est au service des finances (est du hall).", "sys"); return; }
    if (x.ph < 4) { out("La console est verrouillée pour l'instant.", "sys"); return; }
    const ps = tk(c.rawArg).filter(q => hasP(q) && x.people.includes(q));
    if (ps.length < 2) { out("`virement ‹qui saisit› ‹qui approuve›` (ex. virement camille hugo). La même personne deux fois est permis comme test.", "err"); return; }
    const s = ps[0], a = ps[1], same = s === a;
    const evil = same && s === "hugo";
    out(evil ? "Exercice autorisé : Mallory, avec le mot de passe de Hugo, tente un virement de 48 000 € vers le compte MAL-0443." : "Virement de 1 250 € à la Boulangerie du Port.", "sys");
    const cs = check(s, "ecrire", "virements");
    if (!cs.ok) { out(`Étape 1, saisie par ${pn(s)} : REFUSÉ${cs.dis ? " (compte désactivé)" : " (pas la permission d'écrire des virements)"}.`, "err"); return; }
    out(`Étape 1, saisie par ${pn(s)} : autorisé (${cs.by.join(" ; ")}).`, "ok");
    if (same && sodRule()) { out(`Étape 2, approbation par ${pn(a)} : REFUSÉ. La règle de séparation interdit de saisir ET d'approuver : il faut une autre personne (quatre yeux).`, "err"); return; }
    const ca = check(a, "approuver", "virements");
    if (!ca.ok) { out(`Étape 2, approbation par ${pn(a)} : REFUSÉ${ca.dis ? " (compte désactivé)" : " (pas la permission d'approuver des virements)"}.`, "err"); return; }
    out(`Étape 2, approbation par ${pn(a)} : autorisé (${ca.by.join(" ; ")}).`, "ok");
    if (evil) {
      x.fraudSeen = true;
      out("Le virement de 48 000 € est EXÉCUTÉ. Aucun regard tiers : l'argent est parti et le journal indique « approuvé par Hugo ».", "err");
      out("Chacune des deux permissions était légitime prise seule. C'est leur CUMUL, chez une seule personne, qui est dangereux. Impossible à voir en testant les permissions une par une.", "sys");
      fig("separation");
    } else {
      out(`Virement exécuté : saisi par ${pn(s)}, approuvé par ${pn(a)}.`, "ok");
      if (sodRule() && !anyViol().length) x.vOK = true;
    }
    progress();
  }

  /* ---------- exercice d'attaque simulé ---------- */
  function exo(c) {
    const x = F();
    if (x.ph < 6) { out("Le poste d'exercice n'est pas encore configuré.", "sys"); return; }
    if (S.room !== "serveurs") { out("Le poste d'exercice est dans la salle des serveurs (ouest du hall).", "sys"); return; }
    const t = tk(c.rawArg).find(q => hasP(q) && x.people.includes(q)) || (x.ph >= 7 ? "lea" : "sam");
    out(`Exercice autorisé, données fictives : Mallory a hameçonné le mot de passe de ${pn(t)} et se connecte avec.`, "title");
    out("Étape 1, authentification : mot de passe correct, le système croit parler à " + pn(t) + ". L'authentification est réussie. Reste l'autorisation : que peut faire ce compte ?", "sys");
    const T = (a, r) => check(t, a, r);
    let esc = false, lat = false, admin = false;
    const rg = T("lire", "registre");
    out(rg.ok ? "Étape 2, reconnaissance, lire registre : AUTORISÉ. Mallory dresse la liste des comptes et repère que Léa est l'administratrice." : "Étape 2, reconnaissance, lire registre : REFUSÉ.", rg.ok ? "err" : "ok");
    const jr = T("lire", "journaux");
    if (jr.ok) out("Lire journaux : AUTORISÉ. Elle apprend les horaires de connexion de Léa et voit qu'on ne surveille pas grand-chose.", "err");
    const wr = T("ecrire", "registre");
    if (wr.ok) { esc = true; out("Étape 3, escalade verticale, écrire registre : AUTORISÉ. Mallory s'affecte elle-même le rôle d'administration dans le Registre. Qui peut modifier les droits peut se donner tous les droits.", "err"); }
    else out("Étape 3, escalade verticale, écrire registre : REFUSÉ. Impossible de modifier ses propres droits (refus par défaut).", "ok");
    const sv = T("lire", "sauvegardes");
    if (sv.ok) { lat = true; out("Étape 4, mouvement latéral, lire sauvegardes : AUTORISÉ. Une ancienne copie contient le jeton d'administration de Léa : Mallory prend son identité, sans toucher à Sam.", "err"); }
    else out("Étape 4, mouvement latéral, lire sauvegardes : REFUSÉ. Aucune copie de secrets à récupérer.", "ok");
    const ad = T("administrer", "prod");
    if (ad.ok) { admin = true; out(`Étape 5, administrer prod : AUTORISÉ par ${ad.by.join(" ; ")}. Le compte détient déjà les clés de la production.`, "err"); }
    const reached = esc || lat || admin;
    const nb = permsOf(t).size;
    if (reached) {
      out(`Bilan : COMPROMISSION TOTALE. Mallory administre la production et peut tout lire, modifier et supprimer, sauvegardes comprises. Rayon d'impact initial : ${nb} permission(s) sur le compte de ${pn(t)}.`, "err");
      if (t === "sam") x.exoSeen = true;
      if (t === "lea" && x.jit.lea && x.jit.lea.exp > x.clock) out("(C'est une fenêtre d'accès temporaire ouverte : l'exposition est limitée à sa durée, mais elle existe. D'où l'intérêt de durées courtes.)", "sys");
    } else {
      out(`Bilan : l'attaque s'arrête là. Rayon d'impact : ${nb} permission(s) sur le compte de ${pn(t)}${rg.ok ? " (de la lecture seule)" : ""}. Un compte compromis ne vaut que ce que ses droits permettent.`, "ok");
      if (t === "sam" && x.ph === 6) { fig("escalade"); adv(7); return; }
      if (t === "lea" && x.ph === 7 && !leaStanding()) { x.exoLea = true; }
    }
    fig("escalade");
    progress();
  }

  /* ---------- accès juste-à-temps ---------- */
  function request(c) {
    const x = F();
    if (!x.jitMode) { out("Pas de procédure de demande pour l'instant.", "sys"); return; }
    const t = tk(c.rawArg), p = t.find(hasP), a = t.map(actOf).find(Boolean), r = t.map(resOf).find(Boolean), mn = t.find(q => /^\d+$/.test(q));
    if (!p || !a || !r || !mn) { out("`demander ‹personne› ‹action› ‹ressource› ‹minutes›` (ex. demander lea administrer prod 30).", "err"); return; }
    if (p !== "lea" || a !== "administrer" || r !== "prod") { out("Seule l'administration de la production est accessible à la demande, et seulement à son administratrice (Léa). Le reste relève du rôle ordinaire.", "err"); return; }
    if (leaStanding()) { out("Léa a déjà ce droit en permanence : il n'y a rien à demander. Retire d'abord le droit permanent.", "err"); return; }
    const m = +mn;
    if (m < 1 || m > 60) { out("Durée refusée : de 1 à 60 minutes (une courte durée, c'est le principe).", "err"); return; }
    x.req = { p, k: "administrer:prod", m }; x.jitReq = true;
    out(`Demande enregistrée : Léa veut « administrer prod » pendant ${m} min (motif : mise à jour du serveur). Elle ne peut pas se l'accorder elle-même : un tiers doit approuver. C'est toi : \`valider demande\`.`, "ok");
  }
  function validate() {
    const x = F();
    if (!x.req) { out("Aucune demande en attente. `demander lea administrer prod 30`", "sys"); return; }
    const q = x.req; x.req = null;
    x.jit[q.p] = { perm: q.k, exp: x.clock + q.m }; x.jitGranted = true;
    out(`Demande approuvée par toi (${fmtT(x.clock)}). Léa reçoit « administrer prod » jusqu'à ${fmtT(x.clock + q.m)}. L'octroi, l'approbateur et la durée sont journalisés.`, "ok");
    note("jit"); fig("temporaire"); progress();
  }
  function waitCmd(c) {
    const x = F(), n = +(tk(c.rawArg).find(q => /^\d+$/.test(q)) || 0);
    if (!n || n > 600) { out("`attendre ‹minutes›` (ex. attendre 30).", "err"); return; }
    const before = x.clock; x.clock += n;
    out(`Le temps passe : il est ${fmtT(x.clock)}.`, "sys");
    Object.keys(x.jit).forEach(p => { const j = x.jit[p]; if (j.exp > before && j.exp <= x.clock) { x.jitExpired = true; out(`L'accès temporaire de ${pn(p)} (${pp(j.perm)}) a expiré à ${fmtT(j.exp)}. Personne n'a eu à le révoquer : il disparaît tout seul, même si l'on oublie.`, "ok"); } });
    progress();
  }
  const timeCmd = () => out(`Il est ${fmtT(F().clock)}.`, "sys");

  /* ---------- aperçu ABAC ---------- */
  function abacCmd(c) {
    const x = F();
    if (x.ph < 8) { out("Le panneau des politiques n'est pas encore dévoilé.", "sys"); return; }
    if (S.room !== "finances") { out("Le panneau est aux finances (est du hall).", "sys"); return; }
    const t = tk(c.rawArg), p = t.find(hasP), h = t.find(q => /^\d+$/.test(q)), lt = t.find(q => /^(bureau|siege|domicile|maison|home|etranger|exterieur)$/.test(q));
    if (!p || !x.people.includes(p) || h === undefined || !lt || +h > 23) { out("`abac ‹personne› ‹heure 0-23› ‹lieu›` (lieu : bureau, domicile, etranger). Ex. abac camille 14 bureau", "err"); return; }
    const place = /^(bureau|siege)$/.test(lt) ? "bureau" : /^(domicile|maison|home)$/.test(lt) ? "domicile" : "étranger";
    const rb = check(p, "ecrire", "virements"), sv = svcOf(p) === "finance", hr = +h >= 8 && +h < 19, pl = place === "bureau";
    out(`Demande : ${pn(p)} veut écrire des virements à ${h} h, depuis « ${place} ».`, "sys");
    code([
      `${rb.ok ? "OUI" : "NON"}  rôle accordant « écrire virements »`,
      `${sv ? "OUI" : "NON"}  service = finance        (service : ${svcOf(p)})`,
      `${hr ? "OUI" : "NON"}  heure entre 8 h et 19 h  (heure : ${h} h)`,
      `${pl ? "OUI" : "NON"}  lieu = bureau            (lieu : ${place})`,
    ].join("\n"));
    const ok = rb.ok && sv && hr && pl;
    x.abac = x.abac || {};
    if (ok) { x.abac.ok = true; out("AUTORISÉ : le rôle l'accorde ET tous les attributs conviennent.", "ok"); }
    else {
      const why = [!rb.ok && "pas de rôle qui l'accorde", !sv && "mauvais service", !hr && "hors des heures de travail", !pl && "lieu non autorisé"].filter(Boolean);
      out("REFUSÉ : " + why.join(", ") + ".", "err");
      if (!sv) x.abac.service = true;
      if (!hr || !pl) x.abac.ctx = true;
    }
    x.abacLast = `${pn(p)} · ${h} h · ${place} : ${ok ? "autorisé" : "refusé"}`;
    fig("abac", x.abacLast);
    progress();
  }

  /* ---------- dialogues ---------- */
  function brief() {
    const x = F();
    switch (x.ph) {
      case 1: return "Premier chantier : Camille et Zoé, nos deux comptables, ont des droits accordés un à un, au cas par cas. Crée un rôle pour leur métier, donne-lui leurs permissions, affecte-les, puis retire leurs droits directs.";
      case 2: return "Théo attend : affecte-lui le rôle de comptable.";
      case 3: return "Le vieux rôle « employe » donne tout à tout le monde. Remplace-le par un rôle par métier, avec ce dont chacun a besoin (`besoins`), et valide avec `controler`.";
      case 4: return "Hugo et la séparation des tâches : va aux finances, vois ce qu'il peut faire seul, puis déclare la règle et corrige.";
      case 5: return "La revue des droits t'attend au bureau de l'audit : `auditer`.";
      case 6: return "L'exercice de la salle des serveurs te dira ce que Mallory peut faire avec le compte de Sam. Puis coupe la chaîne.";
      case 7: return "Enlève le droit d'administration permanent de Léa et mets en place l'accès à la demande.";
      case 8: return "Il reste l'aperçu ABAC, aux finances : `abac ‹personne› ‹heure› ‹lieu›`.";
      default: return "";
    }
  }
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (x.ph === 0) {
          x.ph = 1; note("authn");
          ada("Bienvenue à la Guilde de Port-443. Notre administration accorde les droits d'accès depuis dix ans : « donne-lui ça, il en a besoin ». Personne ne sait plus qui peut quoi, ni pourquoi. Ton rôle : mener un audit autorisé des droits, sur des données fictives, et bâtir un modèle sain. Un compte n'est pas qu'un mot de passe : le mot de passe prouve QUI tu es (authentification) ; ce qu'on t'autorise à faire, c'est l'autorisation. Aujourd'hui, c'est elle qui nous protège quand un mot de passe fuite.");
          out("Rends-toi au bureau du Registre des Clés (`aller nord`), regarde l'état des droits (`droits`) et interroge le moteur (`tester ‹personne› ‹action› ‹ressource›`).", "sys");
        } else if (x.end) ada("La Guilde tient désormais ses clés. Merci !");
        else if (x.ph === 9) ending();
        else { ada(brief()); out("`indice` si tu bloques.", "sys"); }
        break;
      case "sam":
        if (x.ph >= 6 && vulnerable("sam")) say("Sam", "Le help desk m'a donné un rôle « support » : c'est cool, je peux réinitialiser des comptes et restaurer des sauvegardes. Je n'y connais pas grand-chose, mais ça m'a l'air d'être beaucoup de pouvoir.");
        else if (x.ph >= 6) say("Sam", "Je ne fais que lire le registre des comptes. Ça me va : moins je peux, moins je risque de casser quelque chose, ou de me faire voler quelque chose.");
        else say("Sam", "Je suis le stagiaire. Pour l'instant, je ne peux rien faire du tout : on m'a dit que c'est normal, c'est « refus par défaut ».");
        break;
      case "camille":
        if (x.ph <= 1) say("Camille", "Je saisis les virements. Mes droits ont été ajoutés au fil des ans ; je crois que j'ai même accès aux journaux, que je n'ai jamais ouverts.");
        else if (x.ph < 4) say("Camille", "Je saisis, Hugo approuve : c'est comme ça que ça doit marcher. Et pour Théo, ça s'est fait en une ligne.");
        else say("Camille", "Mes virements doivent être approuvés par quelqu'un d'autre. Ça m'a toujours rassurée : si je me trompe, quelqu'un le voit.");
        break;
      case "hugo":
        if (x.ph === 4 && !sodRule()) say("Hugo", "En l'absence de Camille, j'ai aussi saisi les virements. Pratique, non ? Personne ne m'a dit que c'était un problème.");
        else if (x.ph >= 4) say("Hugo", "Je n'approuve que ce que les autres ont saisi. Je ne peux plus me faire confiance à moi-même, et c'est justement l'idée.");
        else say("Hugo", "J'approuve les virements. Parlons de ça plus tard.");
        break;
      case "lea":
        if (x.ph >= 7 && !x.jitGranted) say("Léa", "Plus de droit permanent ? Il faudra que je demande à chaque fois. Un peu pénible, mais si mon compte est pris, ça ne donnera plus accès à la production à n'importe quelle heure.");
        else if (x.ph >= 7) say("Léa", "Je demande, on m'approuve, ça expire. Je préfère : il m'arrivait d'oublier que j'étais connectée en administratrice.");
        else say("Léa", "Je garde la production et les sauvegardes. Mon compte d'administratrice, je l'utilise pour tout, même pour lire mes mails. Je sais, je sais.");
        break;
      case "paul":
        if (x.ph >= 5) say("Paul", "Je ne fais que lire. La revue des droits (`auditer`), c'est la recertification : on compare ce qui est accordé à ce qui est nécessaire, régulièrement.");
        else say("Paul", "L'audit, c'est surtout regarder les droits de tout le monde et se demander : est-ce que c'est encore nécessaire ?");
        break;
      case "mallory":
        say("Mallory", "Je n'ai pas besoin de casser quoi que ce soit : il me suffit d'un compte avec trop de droits. Dans cet exercice, je suis sage : j'obéis aux autorisations. Elles sont mon seul obstacle.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    ada("La Guilde a des rôles, des règles de conflit, des revues de droits, aucun compte fantôme et aucun administrateur permanent. Tu as vu que le mot de passe volé de Sam n'aurait donné qu'un peu de lecture, et celui de Léa rien du tout hors fenêtre. Voilà la vraie force d'un modèle de droits : il rend les incidents petits.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le Registre des Clés = le système de gestion des identités et des accès (IAM) et son moteur de politique.** Il stocke qui a quels rôles et décide de chaque demande : c'est le point de décision (PDP) ; chaque porte qui l'interroge est un point d'application (PEP). Le « tester » du jeu est exactement une décision d'autorisation, avec ses explications.");
    out("**Mot de passe contre autorisation.** Mallory réussit toujours l'authentification, parce que le mot de passe est volé : il n'y a rien à casser. Ce qui change l'issue, c'est ce que le compte a le droit de faire. D'où l'intérêt de combiner authentification forte (MFA) ET autorisation étroite.");
    out("**Les rôles = le RBAC.** Les permissions (action sur ressource) vont aux rôles, les personnes aux rôles. Un nouvel arrivant se traite par une affectation. Un rôle se conçoit par métier, pas par personne.");
    out("**Le refus par défaut.** Le moteur ne dit oui que si une permission l'accorde. C'est la base de tout système d'accès sûr.");
    out("**Le moindre privilège et la vérification des besoins.** Le contrôle compare l'accordé au nécessaire : « manque » (le travail est bloqué) et « en trop » (le risque grossit). En entreprise, ce rapprochement se fait par des revues d'accès régulières.");
    out("**Hugo seul à la console = un manquement à la séparation des tâches.** Les contrôles « maker-checker » imposent que deux personnes interviennent sur une opération sensible. Ici, c'est une règle statique (appliquée à l'attribution des droits) ; dans la vraie vie, on ajoute aussi des règles dynamiques (la même personne ne peut pas approuver ce qu'elle a saisi, vérifié à l'exécution).");
    out("**Zoé, Yann et Inès = la dérive des privilèges et les comptes dormants.** Au changement de poste, on ajoute sans retirer ; au départ, on oublie de fermer. Parades : un processus arrivée-mutation-départ et des revues périodiques. Un compte dormant est une porte ouverte sans surveillance.");
    out("**L'exercice sur Sam = l'escalade de privilèges et le mouvement latéral.** « Écrire registre » signifie modifier des droits : c'est une permission d'administration déguisée (escalade verticale). Les sauvegardes contiennent souvent des secrets : les lire permet de prendre l'identité d'un autre compte (mouvement latéral). Le moindre privilège limite le « rayon d'impact ».");
    out("**L'accès juste-à-temps = la gestion des accès privilégiés (PAM).** Le droit est demandé, approuvé par un tiers, limité à quelques minutes, journalisé, puis expire seul. Les comptes d'administration permanents deviennent l'exception (un compte « de secours » est gardé hors ligne, pour les pannes).");
    out("**Le panneau des politiques = ABAC.** La décision tient compte d'attributs de la personne, de la ressource et du contexte (heure, lieu, appareil). Il complète le RBAC (ici, le rôle ne suffit plus). L'inconvénient : des politiques plus complexes à écrire, à tester et à expliquer.");
    out("**Les simplifications du jeu.** (1) Quatre actions et cinq ressources seulement ; en vrai, des centaines de permissions, souvent fines (par objet, par champ). (2) Pas de hiérarchie de rôles, pas de groupes, pas de règle de refus explicite, pas d'héritage ; « administrer » n'inclut pas « lire » ici, alors que souvent oui. (3) Les besoins sont donnés par une fiche exacte ; en vrai, on les négocie avec les métiers. (4) L'exercice est un scénario fixe : une vraie attaque mêle de nombreuses techniques, et les contrôles réels incluent la détection (alertes, journaux) et le MFA, que le jeu n'aborde pas. (5) L'approbation JIT est résumée en une commande ; en vrai, elle passe par un outil de gestion des accès privilégiés avec motif, ticket et enregistrement de session. (6) L'ABAC est réduit à une seule politique.");
    out("Rappel utile : **on accorde des droits à des rôles, jamais à des personnes ; chacun n'a que ce dont il a besoin, quand il en a besoin ; et une seule personne ne doit jamais pouvoir faire seule ce qui est dangereux.**", "ok");
  }

  /* ---------- schémas ---------- */
  const LET = { lire: "L", ecrire: "E", approuver: "A", administrer: "D" };
  const figs = {
    matrice: () => {
      const x = F(), ppl = x.people, heads = ["registre", "virem.", "journaux", "sauveg.", "prod"], cx0 = 128, cw = 57;
      const h = 40 + ppl.length * 22 + 30;
      let s = heads.map((t, i) => T(cx0 + i * cw + cw / 2, 20, t, "f-s f-b")).join("");
      ppl.forEach((p, ri) => {
        const y = 30 + ri * 22, m = permsOf(p), need = needsOf(p), off = x.disabled[p];
        s += T(6, y + 14, pn(p) + (off ? " (désact.)" : ""), "f-s" + (off ? "" : " f-b"), "start");
        RES.forEach((r, ci) => {
          const acts = ["lire", "ecrire", "approuver", "administrer"].filter(a => m.has(a + ":" + r));
          const excess = !off && acts.some(a => !need.includes(a + ":" + r));
          const cls = off ? "" : excess ? "f-bad" : acts.length ? "f-ok" : "";
          s += R(cx0 + ci * cw + 2, y, cw - 4, 19, cls) + (acts.length ? T(cx0 + ci * cw + cw / 2, y + 14, acts.map(a => LET[a]).join(" "), "f-s" + (excess ? " ft-bad" : off ? "" : " ft-ok")) : "");
        });
      });
      s += T(8, h - 8, "L lire · E écrire · A approuver · D administrer · rouge : en trop", "f-s", "start");
      return { cap: "Matrice personnes × ressources, calculée à partir des rôles actuels. Vert : conforme au besoin du poste. Rouge : permission au-delà du besoin (ou compte qui ne devrait plus rien avoir).", svg: SVG(h, "Matrice des droits", s) };
    },
    escalade: () => {
      const A = permsOf("sam").has("ecrire:registre"), B = permsOf("sam").has("lire:sauvegardes"), any = A || B || permsOf("sam").has("administrer:prod");
      const bx = (x0, op, t1, t2o, t2c) => R(x0, 112, 196, 48, op ? "f-bad" : "f-ok") + T(x0 + 98, 132, t1, "f-b") + T(x0 + 98, 150, op ? t2o : t2c, "f-s " + (op ? "ft-bad" : "ft-ok"));
      return {
        cap: any ? "L'exercice sur le compte de Sam : une permission en trop (écrire le registre, lire les sauvegardes) suffit à transformer un stagiaire en administrateur."
          : "Même chaîne, après correction : les deux voies sont refusées. Le compte de Sam ne vaut plus que ses droits de lecture.",
        svg: SVG(270, "Chaîne d'escalade",
          R(60, 6, 300, 28, "f-bad") + T(210, 25, "mot de passe de Sam volé", "f-b") + AR(210, 34, 210, 52) +
          R(60, 52, 300, 28) + T(210, 71, "connexion réussie (authentifiée)", "f-s") + AR(150, 80, 108, 110) + AR(270, 80, 312, 110) +
          bx(8, A, "écrire registre", "s'ajoute « admin »", "refusé : bloqué") + bx(216, B, "lire sauvegardes", "jeton de Léa : latéral", "refusé : bloqué") +
          T(106, 176, "escalade verticale", "f-s") + T(314, 176, "mouvement latéral", "f-s") +
          AR(106, 160, 150, 192, A ? "f-bad" : "f-dash") + AR(314, 160, 270, 192, B ? "f-bad" : "f-dash") +
          R(60, 192, 300, 44, any ? "f-bad" : "f-ok") + T(210, 212, "administrer prod", "f-b") + T(210, 228, any ? "TOTAL : tout est compromis" : "hors d'atteinte", "f-s " + (any ? "ft-bad" : "ft-ok")) +
          T(210, 258, "Sam n'avait besoin que de « lire registre ».", "f-s"))
      };
    },
    separation: ok => ({
      cap: "Sans séparation, une seule personne saisit et approuve : un compte volé suffit. Avec séparation, deux personnes distinctes interviennent, et une règle de conflit interdit de cumuler les deux permissions.",
      svg: SVG(230, "Séparation des tâches",
        T(8, 16, "Sans séparation", "f-b", "start") +
        R(8, 24, 130, 42, "f-bad") + T(73, 42, "Hugo", "f-b") + T(73, 58, "saisit + approuve", "f-s") + AR(138, 45, 176, 45, "f-bad") +
        R(176, 24, 236, 42, "f-bad") + T(294, 42, "virement 48 000 € → MAL-0443", "f-s") + T(294, 58, "aucun regard tiers", "f-s ft-bad") +
        T(8, 98, "Avec séparation (quatre yeux)", "f-b", "start") +
        R(8, 106, 112, 42, "f-ok") + T(64, 124, "Camille", "f-b") + T(64, 140, "saisit (écrire)", "f-s") + AR(120, 127, 150, 127, "f-ok") +
        R(150, 106, 112, 42, "f-ok") + T(206, 124, "Hugo", "f-b") + T(206, 140, "approuve", "f-s") + AR(262, 127, 292, 127, "f-ok") +
        R(292, 106, 120, 42, "f-ok") + T(352, 131, "exécuté", "f-s") +
        R(8, 168, 404, 52, ok ? "f-ok" : "f-bad") + T(210, 188, "règle : écrire virements ⟂ approuver virements", "f-b") +
        T(210, 208, ok ? "appliquée : plus personne ne cumule" : "à déclarer, ou cumul encore présent", "f-s " + (ok ? "ft-ok" : "ft-bad")))
    }),
    temporaire: standing => {
      const X = hh => 20 + hh * (380 / 24);
      return {
        cap: "Un droit permanent expose le compte 24 h sur 24. En juste-à-temps, il n'existe que pendant de courtes fenêtres approuvées. Un compte compromis à 22 h n'obtient alors rien.",
        svg: SVG(200, "Accès temporaire",
          T(8, 16, "Droit d'administration permanent", "f-b", "start") +
          `<rect x="${X(0)}" y="24" width="380" height="14" rx="3" fill="var(--bad)"/>` +
          T(8, 62, "Accès à la demande (juste-à-temps)", "f-b", "start") +
          `<rect x="${X(0)}" y="70" width="380" height="14" rx="3" fill="none" stroke="var(--line)"/>` +
          `<rect x="${X(9)}" y="70" width="10" height="14" rx="2" fill="var(--ok)"/><rect x="${X(14)}" y="70" width="7" height="14" rx="2" fill="var(--ok)"/>` +
          T(X(9) + 5, 100, "9 h", "f-s") + T(X(14) + 3, 100, "14 h", "f-s") +
          LN(X(22), 108, X(22), 20, "f-bad f-dash") + T(X(22) - 4, 122, "22 h : compte volé", "f-s ft-bad", "end") +
          T(8, 150, standing ? "Aujourd'hui : droit permanent encore en place." : "Aujourd'hui : plus de droit permanent.", "f-s " + (standing ? "ft-bad" : "ft-ok"), "start") +
          T(8, 172, "Permanent : accès total à 22 h.  Juste-à-temps : rien.", "f-s", "start") +
          T(8, 190, "Fenêtre : demande, approbation par un tiers, durée courte, journal.", "f-s", "start"))
      };
    },
    abac: last => ({
      cap: "RBAC : le rôle dit ce qui est possible. ABAC : des attributs (personne, ressource, contexte) disent dans quelles conditions. Ici, les deux doivent être satisfaits.",
      svg: SVG(250, "ABAC",
        R(8, 8, 128, 62, "f-pub") + T(72, 26, "personne", "f-b ft-pub") + T(72, 44, "service", "f-s") + T(72, 60, "poste, rôle", "f-s") +
        R(146, 8, 128, 62, "f-pub") + T(210, 26, "ressource", "f-b ft-pub") + T(210, 44, "virements", "f-s") + T(210, 60, "sensibilité haute", "f-s") +
        R(284, 8, 128, 62, "f-pub") + T(348, 26, "contexte", "f-b ft-pub") + T(348, 44, "heure", "f-s") + T(348, 60, "lieu", "f-s") +
        AR(72, 70, 150, 100) + AR(210, 70, 210, 100) + AR(348, 70, 270, 100) +
        R(60, 100, 300, 54, "f-priv") + T(210, 120, "politique", "f-b ft-priv") + T(210, 138, "rôle OK ET finance ET 8-19 h ET bureau", "f-s") +
        AR(150, 154, 106, 180) + AR(270, 154, 314, 180) +
        R(8, 180, 196, 30, "f-ok") + T(106, 200, "autorisé", "f-b ft-ok") + R(216, 180, 196, 30, "f-bad") + T(314, 200, "refusé", "f-b ft-bad") +
        T(210, 236, last ? "Dernier test : " + last : "Dernier test : aucun", "f-s"))
    }),
  };

  GAMES.rbac = {
    id: "rbac", order: 13, title: "Le Registre des Clés", pageTitle: "RBAC Quest", subtitle: "aventure textuelle · RBAC et moindre privilège",
    blurb: "Construis un modèle de droits qui tourne pour de vrai : rôles, moindre privilège, séparation des tâches, escalade et accès temporaire.",
    concept: "RBAC, moindre privilège, séparation des tâches",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      x.ph = 0; x.roles = {}; x.assign = {}; x.rules = []; x.disabled = {}; x.jit = {}; x.clock = 0; x.job = {}; x.svc = {};
      x.people = ["camille", "zoe", "hugo", "lea", "paul", "noor", "sam"];
      x.direct = { camille: ["lire:registre", "ecrire:virements", "lire:virements", "lire:journaux"], zoe: ["lire:registre", "lire:virements", "ecrire:virements"] };
    },
    refig(name) {
      const x = F();
      fig(name, name === "separation" ? (sodRule() && !anyViol().length) : name === "temporaire" ? leaStanding() : name === "abac" ? x.abacLast : undefined);
    },
    figAlias: { matrice: ["droits", "matrix", "rbac", "roles"], escalade: ["attaque", "exercice", "mallory", "chaine"], separation: ["taches", "tâches", "quatre", "yeux", "sod"], temporaire: ["jit", "juste", "temps", "admin"], abac: ["attributs", "contexte", "politique"] },
    help: "Moteur de droits : `droits [‹personne›]` · `roles` · `besoins` · `creer role ‹nom›` · `accorder ‹rôle› ‹action› ‹ressources›` · `affecter ‹personne› ‹rôle›` · `retirer ‹personne› ‹rôle›` / `retirer ‹rôle› ‹action› ‹ressource›` / `retirer droits ‹personne›` · `supprimer ‹rôle›` · `tester ‹personne› ‹action› ‹ressource›` · `controler` · `interdire ‹a› avec ‹b›` · `virement ‹saisit› ‹approuve›` · `auditer` · `desactiver ‹personne›` · `lancer exercice [‹personne›]` · `demander ‹personne› administrer prod ‹minutes›` · `valider demande` · `attendre ‹minutes›` · `abac ‹personne› ‹heure› ‹lieu›`. Actions : lire, ecrire, approuver, administrer.",
    verbs: {
      mkrole: { words: ["creer", "definir"], run: mkRole },
      grant: { words: ["accorder", "autoriser"], run: grant },
      assign: { words: ["affecter", "attribuer", "assigner"], run: assign },
      revoke: { words: ["retirer", "revoquer", "enlever"], run: revoke },
      delrole: { words: ["supprimer", "effacer"], run: delRole },
      test: { words: ["tester", "essayer"], run: testCmd },
      rights: { words: ["droits", "droit", "matrice"], run: showDroits },
      roles: { words: ["roles", "role"], run: showRoles },
      needs: { words: ["besoins", "fiches"], run: needsTable },
      control: { words: ["controler", "conformite"], run: controlCmd },
      deny: { words: ["interdire"], run: ruleCmd },
      pay: { words: ["virement", "virer"], run: pay },
      audit: { words: ["auditer", "audit", "revue"], run: auditCmd },
      off: { words: ["desactiver", "suspendre"], run: disable },
      exo: { words: ["lancer", "exercice", "simuler"], run: exo },
      req: { words: ["demander", "requerir"], run: request },
      okv: { words: ["valider"], run: validate },
      wait: { words: ["attendre", "patienter"], run: waitCmd },
      abac: { words: ["abac"], run: abacCmd },
      time: { words: ["heure", "horloge"], run: timeCmd },
    },
    intro() {
      out("Le Registre des Clés", "title");
      out("À Port-443, la Guilde accorde depuis dix ans les droits d'accès « au coup par coup » : un ajout pour dépanner, un autre pour un projet, jamais un retrait. Plus personne ne sait qui peut quoi. Maître Ada t'engage pour un audit autorisé, sur des données fictives : bâtir un vrai modèle de droits, évalué par un vrai moteur, et voir ce que Mallory pourrait en faire avec un mot de passe volé.", "");
    },
  };
})();
