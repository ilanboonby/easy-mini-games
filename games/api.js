"use strict";
/* Les Guichets de l'API : BOLA, niveau fonction, affectation de masse, exposition de données,
   limitation de débit (seau à jetons), validation, API oubliées, authentification. Serveur REST simulé. */
(function () {
  const F = () => f();
  const TTL = 15;           // durée de vie d'un jeton court, en minutes
  const TOTAL = 5000;       // lignes dans /transactions
  const KB_PER_ROW = 0.5;
  const RATE_GOAL = 40;     // tentatives de Mallory tolérées sur la fenêtre
  const ATT_SECONDS = 50;
  const IBAN = "FR76300010000000001042";
  const STATIC_KEY = "pk_live_7Hq2xM9";
  const PROF0 = { nom: "Alice Martin", email: "alice@port443.fr", role: "client", solde: 2450 };

  const ACC = [
    { n: 1041, uuid: "a3b8f1c2-7d4e-4f6a-9b21-5c0e8d7a1f33", titulaire: "Alice Martin", solde: 2450, iban: "FR76300010000000001041", hash: "$2b$10$Zk3QeV9mXr1aT8", note: "cliente depuis 2019" },
    { n: 1042, uuid: "c91d2e77-0b3a-4a58-8e6f-2d4b9a6c3e10", titulaire: "Bob Durand", solde: 18900, iban: IBAN, hash: "$2b$10$Qp7LwN2dYc5uB1", note: "VIP : plafond relevé, ne pas relancer" },
    { n: 1043, uuid: "5e07b4d9-31c8-4b92-a6d0-8f1e2c7b9a45", titulaire: "Carole Nguyen", solde: 730.5, iban: "FR76300010000000001043", hash: "$2b$10$Hs4TnK8vWe0mJz", note: "litige en cours" },
    { n: 1044, uuid: "e2a6c0f8-94b1-47d3-8c5e-1b7f3d9a6e02", titulaire: "Dimitri Roche", solde: 51200, iban: "FR76300010000000001044", hash: "$2b$10$Bd9XcR3gLy6oPf", note: "surveillance anti-fraude active" },
    { n: 1045, uuid: "08f3d7a1-6c2e-4e95-b4a8-7d0c5e1f9b36", titulaire: "Farid Haddad", solde: 120, iban: "FR76300010000000001045", hash: "$2b$10$Vm1ZuA5kEq7tSw", note: "ancien client, compte dormant" },
  ];
  const SPEC = [["GET", "/profil", 5210], ["PATCH", "/profil", 340], ["GET", "/comptes/{id}", 8120], ["GET", "/transactions", 4410], ["POST", "/virements", 960], ["GET", "/admin/utilisateurs", 35]];
  const LOG = SPEC.concat([["GET", "/v1/comptes/{id}", 1870]]);
  const REASON = { 200: "OK", 201: "Created", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 410: "Gone", 413: "Payload Too Large", 422: "Unprocessable Entity", 429: "Too Many Requests", 500: "Internal Server Error" };

  const nf = n => String(n).replace(".", ",");
  const clockStr = m => { const t = 540 + m; return String(Math.floor(t / 60) % 24).padStart(2, "0") + ":" + String(t % 60).padStart(2, "0"); };
  const pj = o => JSON.stringify(o, null, 2).replace(/(\n\s+)\{([^{}\[\]]*?)\}/g, (m, a, b) => a + "{ " + b.replace(/\n\s*/g, " ").trim() + " }");

  /* ============ Seau à jetons (vrai algorithme sur une chronologie fixe) ============ */
  const LEG = (() => { const t = [0, 100, 200, 300, 400]; for (let s = 3000; s <= 57000; s += 3000) t.push(s); [30000, 30100, 30200, 30300].forEach(v => t.push(v)); return t.sort((a, b) => a - b); })();
  const ATT = (() => { const t = []; for (let s = 10000; s < 60000; s += 100) t.push(s); return t; })();
  function bucket(C, r, times) {
    let tok = C, last = 0; const res = [];
    for (const t of times) {
      tok = Math.min(C, tok + (t - last) / 1000 * r); last = t;
      const before = tok; let ok = false, retry = 0;
      if (tok >= 1 - 1e-9) { tok -= 1; ok = true; } else retry = Math.max(1, Math.ceil((1 - tok) / r - 1e-9));
      res.push({ t, ok, before, after: tok, retry });
    }
    return res;
  }
  function rateStats() {
    const x = F(), L = bucket(x.cap, x.rate, LEG), A = bucket(x.cap, x.rate, ATT);
    return { L, A, legRej: L.filter(e => !e.ok), attPass: A.filter(e => e.ok).length };
  }

  /* ============ Validation (partagée par le serveur et la rediffusion) ============ */
  function validate(rq) {
    const x = F(), p = rq.path;
    if (x.corpsMax && rq.size > x.corpsMax) return { status: 413, msg: `corps de ${rq.size} octets, maximum ${x.corpsMax}` };
    if (p === "/transactions") {
      const raw = rq.query.limit; let lim = 20;
      if (raw !== undefined) {
        if (x.strict && !/^[0-9]+$/.test(raw)) return { status: 400, msg: "limit doit être un entier positif" };
        lim = parseInt(raw, 10);
        if (x.strict && lim < 1) return { status: 400, msg: "limit doit être au moins 1" };
        if (Number.isNaN(lim)) lim = 20;
        if (lim < 0) lim = TOTAL;
      }
      if (x.pageMax && lim > x.pageMax) return { status: 400, msg: `limit ${lim} supérieur au maximum ${x.pageMax}` };
      return { ok: true, lim: Math.min(lim, TOTAL) };
    }
    if (p === "/virements" && rq.method === "POST") {
      const b = rq.body;
      if (x.strict) {
        if (!b || typeof b !== "object" || Array.isArray(b)) return { status: 422, msg: "un objet JSON est attendu" };
        const extra = Object.keys(b).filter(k => !["iban", "montant", "libelle"].includes(k));
        if (extra.length) return { status: 422, msg: "champ inattendu : " + extra.join(", ") };
        if (typeof b.iban !== "string" || !/^FR\d{2}[0-9A-Z]{10,30}$/.test(b.iban)) return { status: 422, msg: "iban invalide" };
        if (typeof b.montant !== "number" || !Number.isFinite(b.montant)) return { status: 422, msg: "montant doit être un nombre" };
        if (b.montant <= 0) return { status: 422, msg: "montant doit être strictement positif" };
      }
      if (x.montantMax && b && typeof b.montant === "number" && b.montant > x.montantMax) return { status: 422, msg: `montant supérieur au maximum ${x.montantMax}` };
      return { ok: true };
    }
    return { ok: true };
  }
  const CORPUS = [
    { id: "L1", legit: true, label: "GET /transactions?limit=20", rq: { method: "GET", path: "/transactions", query: { limit: "20" }, size: 0 } },
    { id: "L2", legit: true, label: "GET /transactions?limit=100 (export de l'appli)", rq: { method: "GET", path: "/transactions", query: { limit: "100" }, size: 0 } },
    { id: "L3", legit: true, label: "POST /virements, 250 euros", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: 250, libelle: "Loyer" }, size: 96 } },
    { id: "L4", legit: true, label: "POST /virements, 5000 euros (le plus gros réel)", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: 5000, libelle: "Travaux" }, size: 98 } },
    { id: "L5", legit: true, label: "POST /virements, libellé de 1,2 Ko", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: 80, libelle: "…" }, size: 1300 } },
    { id: "A1", label: "GET /transactions?limit=100000", rq: { method: "GET", path: "/transactions", query: { limit: "100000" }, size: 0 }, effect: "les 5000 lignes (≈ 2,4 Mo) sont renvoyées : mémoire, bande passante et base de données saturées" },
    { id: "A2", label: "GET /transactions?limit=-1", rq: { method: "GET", path: "/transactions", query: { limit: "-1" }, size: 0 }, effect: "la valeur négative est traitée comme « sans limite » : tout est renvoyé" },
    { id: "A3", label: "POST /virements, montant = -500", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: -500 }, size: 60 }, effect: "le virement est inversé : le compte émetteur est CRÉDITÉ de 500" },
    { id: "A4", label: "POST /virements, montant = \"abc\"", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: "abc" }, size: 60 }, effect: "erreur 500 non gérée (NaN dans le calcul du solde) : comportement imprévisible" },
    { id: "A5", label: "POST /virements, montant = 250 000", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: 250000 }, size: 62 }, effect: "montant cinquante fois supérieur à tout usage réel : accepté sans réflexion" },
    { id: "A6", label: "POST /virements, corps de 300 Ko", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: 10, libelle: "…" }, size: 300000 }, effect: "300 Ko lus, analysés et stockés pour un virement : épuisement de la mémoire à grande échelle" },
    { id: "A7", label: "POST /virements, champ inattendu \"frais\": 0", rq: { method: "POST", path: "/virements", query: {}, body: { iban: IBAN, montant: 10, frais: 0 }, size: 70 }, effect: "un champ que personne n'a prévu est accepté : porte ouverte à l'affectation de masse" },
  ];

  /* ============ Le serveur de la banque (simulé) ============ */
  function who() {
    const x = F();
    return { aucun: "(aucune authentification)", alice: "Authorization: Bearer tok_alice_81f3", admin: "Authorization: Bearer tok_admin_c07a", cle: "X-API-Key: " + STATIC_KEY, emis: "Authorization: Bearer eyJ…(jeton court)" }[x.ident];
  }
  function authn() {
    const x = F(), id = x.ident;
    if (id === "aucun") return { err: { status: 401, headers: { "WWW-Authenticate": "Bearer" }, body: { erreur: "authentification requise" } } };
    if (id === "cle") {
      if (x.auth) return { err: { status: 401, body: { erreur: "clé API révoquée : utilisez un jeton court" }, revoked: true } };
      return { me: { name: "partenaire", compte: 0, role: "admin" } };
    }
    if (id === "emis") {
      if (!x.tok) return { err: { status: 401, body: { erreur: "aucun jeton émis : utilisez emettre" } } };
      if (x.clock - x.tok.iat >= TTL) return { err: { status: 401, body: { erreur: "jeton expiré", exp: clockStr(x.tok.iat + TTL) }, expired: true } };
      return { me: { name: "alice", compte: 1041, role: x.prof.role, scopes: x.tok.scopes } };
    }
    if (id === "admin") return { me: { name: "admin", compte: 1000, role: "admin" } };
    return { me: { name: "alice", compte: 1041, role: x.prof.role } };
  }
  const idOf = a => F().uuid ? a.uuid : a.n;
  const accFull = (a, legacy) => ({ id: legacy ? a.n : idOf(a), titulaire: a.titulaire, solde: a.n === 1041 ? F().prof.solde : a.solde, iban: a.iban, hash_mdp: a.hash, note_interne: a.note });
  const accSafe = a => ({ id: idOf(a), titulaire: a.titulaire, solde: a.n === 1041 ? F().prof.solde : a.solde, iban: a.iban });
  function profileOf(me) {
    const x = F();
    if (me.name === "admin") return { compte: 1000, nom: "Hugo Lenoir", role: "admin" };
    if (me.name === "partenaire") return { service: "partenaire-compta", role: "admin" };
    return Object.assign({ compte: x.uuid ? ACC[0].uuid : 1041 }, x.prof);
  }
  const notAllowed = allow => ({ status: 405, headers: { Allow: allow }, body: { erreur: "méthode non autorisée" } });

  function serve(rq) {
    const x = F(), p = rq.path; let m;
    if ((m = p.match(/^\/v1\/comptes\/(\d+)$/))) {
      if (rq.method !== "GET") return notAllowed("GET");
      if (x.v1 === "retired") return { status: 410, headers: { Deprecation: "true" }, body: { erreur: "version retirée", migration: "utiliser /comptes/{id} en version courante" } };
      let me = null;
      if (x.v1 === "auth") { const au = authn(); if (au.err) return au.err; me = au.me; }
      const a = ACC.find(k => k.n === +m[1]);
      if (!a) return { status: 404, body: { erreur: "compte introuvable" }, me };
      return { status: 200, body: accFull(a, true), me, legacy: true, acc: a };
    }
    const au = authn(); if (au.err) return au.err;
    const me = au.me;
    const r = route(rq, me, m);
    r.me = me; return r;
  }
  function route(rq, me) {
    const x = F(), p = rq.path; let m;
    const need = s => (me.scopes && !me.scopes.includes(s)) ? { status: 403, body: { erreur: "portée insuffisante", requise: s, accordees: me.scopes }, scope: true } : null;
    if (rq.bad) return { status: 400, body: { erreur: "JSON invalide" } };
    if (p === "/profil") {
      if (rq.method === "GET") return need("comptes:lire") || { status: 200, body: profileOf(me) };
      if (rq.method === "PATCH") {
        const v = validate(rq); if (!v.ok) return { status: v.status, body: { erreur: v.msg } };
        if (me.name !== "alice") return { status: 403, body: { erreur: "ce profil de test appartient à Alice : utilise « jeton alice »" } };
        const b = rq.body;
        if (!b || typeof b !== "object" || Array.isArray(b)) return { status: 400, body: { erreur: "un objet JSON est attendu" } };
        const keys = Object.keys(b).filter(k => !["__proto__", "constructor", "prototype"].includes(k));
        if (x.white) {
          const bad = keys.filter(k => !["nom", "email"].includes(k));
          if (bad.length) return { status: 422, body: { erreur: "champ(s) non modifiable(s)", champs: bad }, mass: true };
        }
        const before = JSON.stringify(x.prof);
        keys.forEach(k => { x.prof[k] = b[k]; });
        return { status: 200, body: Object.assign({ compte: x.uuid ? ACC[0].uuid : 1041 }, x.prof), massChanged: JSON.stringify(x.prof) !== before && (x.prof.role !== PROF0.role || x.prof.solde !== PROF0.solde) };
      }
      return notAllowed("GET, PATCH");
    }
    if ((m = p.match(/^\/comptes\/([^/]+)$/))) {
      if (rq.method !== "GET") return notAllowed("GET");
      const s = need("comptes:lire"); if (s) return s;
      const id = m[1].toLowerCase();
      const a = x.uuid ? ACC.find(k => k.uuid === id) : (/^\d+$/.test(id) ? ACC.find(k => k.n === +id) : null);
      if (!a) return { status: 404, body: { erreur: "compte introuvable" } };
      if (x.owner && a.n !== me.compte) return { status: 403, body: { erreur: "ce compte ne vous appartient pas" }, foreign: true, acc: a };
      return { status: 200, body: x.filtre ? accSafe(a) : accFull(a), acc: a };
    }
    if (p === "/transactions") {
      if (rq.method !== "GET") return notAllowed("GET");
      const s = need("comptes:lire"); if (s) return s;
      const v = validate(rq); if (!v.ok) return { status: v.status, body: { erreur: v.msg } };
      return { status: 200, body: { total: TOTAL, renvoyees: v.lim, taille_approx: v.lim * KB_PER_ROW >= 1000 ? nf((v.lim * KB_PER_ROW / 1024).toFixed(1)) + " Mo" : nf((v.lim * KB_PER_ROW).toFixed(1)) + " Ko", lignes: v.lim ? ["2026-10-04 · Boulangerie · -3,40", "2026-10-03 · Salaire · +2100,00", "…"] : [] } };
    }
    if (p === "/virements") {
      if (rq.method !== "POST") return notAllowed("POST");
      const s = need("virements:creer"); if (s) return s;
      const v = validate(rq); if (!v.ok) return { status: v.status, body: { erreur: v.msg } };
      const b = rq.body;
      if (!b || typeof b !== "object") return { status: 400, body: { erreur: "un objet JSON est attendu" } };
      if (typeof b.montant !== "number") return { status: 500, body: { erreur: "erreur interne", detail: "NaN dans le calcul du solde" } };
      return { status: 201, body: { id: "vir_881", statut: "accepté", montant: b.montant }, vir: true };
    }
    if (p === "/admin/utilisateurs") {
      if (rq.method !== "GET") return notAllowed("GET");
      const s = need("admin:lire"); if (s) return s;
      if (x.fonction && me.role !== "admin") return { status: 403, body: { erreur: "droits administrateur requis" }, fn: true };
      const list = ACC.map(a => ({ id: idOf(a), nom: a.titulaire, email: a.titulaire.split(" ")[0].toLowerCase() + "@port443.fr", role: a.n === 1041 ? x.prof.role : "client" }));
      list.push({ id: 1000, nom: "Hugo Lenoir", email: "hugo@port443.fr", role: "admin" });
      return { status: 200, body: { utilisateurs: list }, admin: true };
    }
    return { status: 404, body: { erreur: "route inconnue" } };
  }

  /* ============ Notes ============ */
  const notes = {
    bola: ["BOLA : l'autorisation au niveau de l'objet", "Broken Object Level Authorization (API1 de l'OWASP API Security Top 10, aussi appelée IDOR) : l'API accepte un identifiant fourni par le client (/comptes/1042) sans vérifier que l'objet appartient à l'appelant. Correction : vérifier la propriété à chaque accès, côté serveur, à partir de l'identité du jeton. Les identifiants non devinables (UUID) gênent l'énumération mais ne remplacent JAMAIS le contrôle."],
    fonction: ["Autorisation au niveau de la fonction", "Une route d'administration (/admin/...) doit exiger le rôle ou la portée adéquats, par défaut et pour chaque méthode. Cacher le bouton dans l'interface ou ne pas publier l'URL n'est pas un contrôle : le serveur doit refuser (403). Le rôle doit venir d'une source que l'utilisateur ne peut pas modifier."],
    masse: ["Affectation de masse (mass assignment)", "Si l'API recopie tout le corps JSON dans l'objet, un client peut y ajouter des champs sensibles (role, solde). Correction : une liste blanche de champs modifiables par route (ici nom et email), tout le reste est refusé. Ne jamais lier automatiquement le corps entier à un modèle de données."],
    expo: ["Exposition excessive de données", "L'API renvoyait des champs inutiles au client (hash_mdp, note_interne), en comptant sur l'interface pour les masquer. Correction : renvoyer une représentation explicite (DTO, liste blanche en sortie) plutôt que l'objet de base de données brut. Ce qu'on ne renvoie pas ne peut pas fuiter."],
    debit: ["Limitation de débit : le seau à jetons", "Un seau de capacité C se remplit à r jetons par seconde ; chaque requête consomme un jeton. Vide, il répond 429 Too Many Requests avec un en-tête Retry-After (secondes à attendre). La capacité autorise des rafales courtes (chargement d'une page), le rythme borne le débit moyen : sur une durée T, un client obtient au plus C + r × T requêtes. Une clé de limitation par client, et des limites plus strictes sur les routes sensibles (connexion)."],
    validation: ["Valider chaque entrée côté serveur", "Un schéma (types, bornes, champs connus, tailles) rejette les entrées absurdes avant tout traitement : 400 ou 422 pour un corps invalide, 413 pour un corps trop gros. Pagination bornée : taille de page par défaut et maximum, jamais « tout ». Les bornes se règlent sur l'usage légitime réel, avec une marge raisonnable."],
    inventaire: ["L'inventaire des API", "Les API oubliées (shadow, zombie) sont un classique : une ancienne version (/v1) sans les protections modernes, encore appelée par une vieille appli. On ne protège que ce qu'on connaît : comparer la spécification aux journaux de trafic, versionner avec une date de retrait, puis couper. Protéger l'ancienne version sans la retirer laisse un code à maintenir et des failles historiques."],
    auth: ["Authentification des API : clé statique, jeton court, portées", "Une clé statique ne s'expire jamais, n'identifie aucun utilisateur et donne les mêmes pouvoirs à tous ses porteurs : fuitée, elle sert indéfiniment. Un jeton à durée courte (ici 15 minutes) limite la fenêtre d'abus ; les portées (comptes:lire, virements:creer) appliquent le moindre privilège ; il est lié à un utilisateur et se renouvelle. Les secrets se stockent et se font tourner hors du code."],
  };

  /* ============ Entités et lieux ============ */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle t'a remis un mandat écrit : audit de l'API de la banque de la cité, sur des données de démonstration." },
    mandat: { names: ["mandat", "mandat d audit", "autorisation"], label: "le mandat d'audit", take: true, desc: () => "Mandat d'audit signé par la banque de Port-443 : tests autorisés sur l'API de démonstration, comptes fictifs d'Alice, de Bob et d'autres clients de test. Rien en dehors." },
    gaston: { npc: true, names: ["gaston", "guichetier", "serveur"], label: "Gaston, le guichetier (le serveur de l'API)", desc: () => "Gaston, le guichetier, qui représente le SERVEUR de l'API. Il répond à chaque requête qu'on glisse sous la vitre." },
    tableau: { names: ["tableau", "routes", "panneau", "console"], label: "le tableau des routes", vis: () => S.room === "guichets",
      desc: () => { const x = F(); return `Console de test de l'API de la banque (les requêtes marchent depuis n'importe quel lieu).\nRoutes : GET /profil · PATCH /profil · GET /comptes/{id} · GET /transactions?limit= · POST /virements · GET /admin/utilisateurs\nSyntaxe : \`GET /comptes/1042\`, \`PATCH /profil {"nom":"Alice B."}\`. Identité : \`jeton alice|admin|aucun\` (actuelle : ${x.ident}).\nCorrections du serveur (\`corriger ‹mesure›\`) :\n  propriete : ${x.owner ? "EN PLACE" : "absente"} · uuid : ${x.uuid ? "EN PLACE" : "absent"} · fonction : ${x.fonction ? "EN PLACE" : "absente"} · liste blanche : ${x.white ? "EN PLACE" : "absente"} · filtrage : ${x.filtre ? "EN PLACE" : "absent"}\nAussi : \`parcourir\` (tester les identifiants voisins).`; } },
    portier: { npc: true, names: ["portier", "videur", "gardien du portique"], label: "le Portier", desc: () => "Le Portier du portique. Il compte les requêtes qui passent et distribue des jetons de passage." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", vis: () => S.room === "portique", desc: () => "Mallory, qui s'acharne sur le formulaire de connexion avec une liste de mots de passe, dix essais par seconde. (Simulation : c'est un rejeu de journal, rien ne part vraiment.)" },
    seau: { names: ["seau", "seau a jetons", "bucket", "jetons"], label: "le seau à jetons", vis: () => S.room === "portique",
      desc: () => { const x = F(); return `Le seau à jetons : capacité ${nf(x.cap)}, rythme ${nf(x.rate)} jeton(s) par seconde.\nPlein au départ. Chaque requête prend un jeton ; seau vide = 429 avec Retry-After.\n\`regler capacite ‹n›\` · \`regler rythme ‹n›\` (par seconde, ex. 0,5) · \`simuler\` pour rejouer une minute de trafic.\nObjectif : Alice (usage normal) jamais bloquée, Mallory au plus ${RATE_GOAL} essais passés en ${ATT_SECONDS} s.`; } },
    greffier: { npc: true, names: ["greffier", "validateur"], label: "le Greffier", desc: () => "Le Greffier du schéma, qui lit chaque formulaire avant de le laisser aller plus loin." },
    registre: { names: ["registre", "regles", "reglages"], label: "le registre des règles", vis: () => S.room === "greffe",
      desc: () => { const x = F(); return `Règles actuelles du schéma :\n  taille de page maximum : ${x.pageMax || "aucune"} · montant maximum : ${x.montantMax || "aucun"} · corps maximum : ${x.corpsMax ? x.corpsMax + " octets" : "aucun"} · types : ${x.strict ? "stricts" : "souples"}\n\`regler page ‹n›\` · \`regler montant ‹n›\` · \`regler corps ‹octets›\` · \`regler types strict|souple\`\nPuis \`rejouer\` : 5 requêtes légitimes et 7 abusives passent par tes règles. Tu peux aussi envoyer des requêtes à la main (\`GET /transactions?limit=100000\`).`; } },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, qui écoute le trafic de la passerelle (c'est son métier de surveillante, avec mandat) et lit les journaux." },
    catalogue: { names: ["catalogue", "inventaire des routes", "journaux"], label: "le catalogue des routes", vis: () => S.room === "archives",
      desc: () => "Deux piles : la spécification officielle (OpenAPI) et les journaux de la passerelle sur 30 jours. `recenser` les compare. `retirer v1` ou `proteger v1` agissent sur une ancienne version." },
    gardien: { npc: true, names: ["gardien", "gardien du coffre"], label: "le Gardien", desc: () => "Le Gardien du coffre des clés, plus habitué aux serrures qu'aux jetons." },
    cle: { names: ["cle", "cle statique", "cle api"], label: "la clé statique", vis: () => S.room === "coffre",
      desc: () => `Une clé API ${F().auth ? "révoquée" : "en service"} : ${STATIC_KEY}. Un partenaire comptable l'utilise depuis 2022, elle figure aussi dans le code d'une appli distribuée (fictif). Elle n'a ni date d'expiration, ni limite de pouvoirs.\n\`jeton cle\` pour tester avec elle, \`attendre ‹minutes›\` pour avancer l'horloge.` },
    horloge: { names: ["horloge", "pendule"], label: "l'horloge du coffre", vis: () => S.room === "coffre",
      desc: () => `Il est ${clockStr(F().clock)} (début d'audit : 09:00). \`attendre ‹minutes›\` avance l'horloge. Durée de vie d'un jeton court : ${TTL} minutes.` },
  };

  const rooms = {
    hall: { name: "Le hall de la Guilde", short: "Hall", alias: ["hall", "guilde"], ents: ["ada", "mandat"], exits: { est: "guichets", nord: "portique", ouest: "greffe", sud: "archives", bas: "coffre" },
      desc: () => "Le hall de la Guilde, d'où partent cinq couloirs : à l'est, les guichets de la banque (l'API) ; au nord, le portique de limitation ; à l'ouest, le greffe des schémas ; au sud, les archives des routes ; en bas, le coffre des clés." },
    guichets: { name: "Les guichets de l'API", short: "Guichets", alias: ["guichets", "guichet", "api"], ents: ["gaston", "tableau"], exits: { ouest: "hall" },
      desc: () => "Une rangée de guichets. Chaque route de l'API est un guichet (profil, comptes, virements, administration). Tu glisses une requête sous la vitre de Gaston, il répond. Une console de test, sur le tableau des routes, enregistre tout." },
    portique: { name: "Le portique de limitation", short: "Portique", alias: ["portique", "limitation"], ents: ["portier", "mallory", "seau"], exits: { sud: "hall" },
      desc: () => "Un portique à tourniquet. Le Portier y compte les passages. Mallory s'y est massée avec une longue liste de mots de passe ; Alice, elle, vient juste regarder son solde." },
    greffe: { name: "Le greffe des schémas", short: "Greffe", alias: ["greffe", "schemas", "validation"], ents: ["greffier", "registre"], exits: { est: "hall" },
      desc: () => "Un bureau aux murs tapissés de formulaires types. Le Greffier vérifie que chaque requête ressemble au gabarit avant de la transmettre aux guichets." },
    archives: { name: "Les archives des routes", short: "Archives", alias: ["archives", "routes", "inventaire"], ents: ["eve", "catalogue"], exits: { nord: "hall" },
      desc: () => "Des étagères de spécifications, de vieux classeurs de versions, et la pile des journaux de la passerelle. Ève y lit les traces de ce qui est vraiment appelé." },
    coffre: { name: "Le coffre des clés", short: "Coffre", alias: ["coffre", "cles"], ents: ["gardien", "cle", "horloge"], exits: { haut: "hall" },
      desc: () => "Une cave, une horloge murale, un coffre. Au centre, sous cloche, la clé API statique du partenaire comptable." },
  };

  /* ============ Objectif et indices ============ */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.bolaSeen) return "bola";
    if (!x.owner) return "bolafix";
    if (!x.bolaBlk) return "bolatest";
    if (!x.uuid) return "uuid";
    if (!x.uuidOk) return "uuidtest";
    if (!x.admSeen) return "adm";
    if (!x.fonction) return "admfix";
    if (!(x.admBlk && x.admOk)) return "admtest";
    if (!x.massSeen) return "mass";
    if (!x.white) return "massfix";
    if (!x.massBlk) return "masstest";
    if (!x.filtre) return "expofix";
    if (!x.expoOk) return "expotest";
    if (!x.rateSeen) return "rate";
    if (!x.rateOk) return "ratefix";
    if (!x.valSeen) return "val";
    if (!x.valOk) return "valfix";
    if (!x.invSeen) return "inv";
    if (!x.v1Seen) return "v1";
    if (x.v1 !== "retired") return "v1fix";
    if (!x.v1Gone) return "v1test";
    if (!x.keyForever) return "key";
    if (!x.auth) return "keyfix";
    if (!(x.scopeOk && x.expOk)) return "tok";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada est dans le hall de la Guilde.", "`parler ada`"],
    bola: () => ["Aux guichets (est du hall), identifie-toi comme Alice, regarde ton compte, puis change l'identifiant dans l'URL.", "`aller est`, `jeton alice`, `GET /comptes/1041`, puis `GET /comptes/1042`."],
    bolafix: () => ["Alice a lu le compte de Bob. Le serveur doit vérifier que l'objet appartient à l'appelant.", "`corriger propriete`"],
    bolatest: () => ["Rejoue la requête qui avait fuité.", "`GET /comptes/1042`. Tu peux aussi essayer `parcourir`."],
    uuid: () => ["Même refusés, les identifiants 1041, 1042… se devinent un à un. Rends-les imprévisibles.", "`corriger uuid`"],
    uuidtest: () => ["Il faut maintenant connaître l'UUID de son propre compte : le profil le donne.", "`GET /profil`, puis `GET /comptes/‹uuid d'Alice›` (copie-le depuis la réponse)."],
    adm: () => ["Une route d'administration existe. Essaie-la avec le jeton d'une simple cliente.", "`jeton alice`, `GET /admin/utilisateurs`"],
    admfix: () => ["Une cliente ne devrait pas lister les utilisateurs : contrôle le rôle sur la route.", "`corriger fonction`"],
    admtest: () => ["Vérifie les deux côtés : Alice est refusée, l'administrateur de test passe encore.", "`jeton alice`, `GET /admin/utilisateurs`, puis `jeton admin`, `GET /admin/utilisateurs`."],
    mass: () => ["Le profil se met à jour avec PATCH. Que se passe-t-il si tu ajoutes un champ que l'interface ne propose pas ?", `\`jeton alice\`, \`PATCH /profil {"nom":"Alice B.","role":"admin"}\``],
    massfix: () => ["Le serveur recopie tout le corps dans l'objet. Il ne doit accepter que les champs prévus.", "`corriger liste blanche`"],
    masstest: () => ["Rejoue l'attaque.", `\`PATCH /profil {"nom":"Alice B.","role":"admin"}\``],
    expofix: () => ["Regarde de nouveau ce que renvoie GET /comptes/‹id› : certains champs ne servent à personne.", "`corriger filtrage`"],
    expotest: () => ["Relis ton propre compte pour constater la différence.", "`GET /profil` pour l'UUID, puis `GET /comptes/‹uuid›`."],
    rate: () => ["Au portique (nord du hall), lance la simulation du trafic avec les réglages actuels.", "`aller nord`, `simuler`"],
    ratefix: () => ["Capacité = rafale tolérée, rythme = débit moyen. Alice charge sa page par rafales de 5 requêtes puis fait une requête toutes les 3 secondes. Mallory ne doit pas passer plus de 40 essais.", "`regler capacite 8`, `regler rythme 0,5`, `simuler`. Ajuste jusqu'au vert."],
    val: () => ["Au greffe (ouest du hall), rejoue le corpus de requêtes avec les règles actuelles.", "`aller ouest` (depuis le hall), `rejouer`"],
    valfix: () => ["Règle une borne par type d'abus, assez haut pour les requêtes légitimes (export de 100 lignes, virements jusqu'à 5000, libellé de 1,2 Ko), assez bas pour les abusives.", "Par exemple `regler page 100`, `regler montant 10000`, `regler corps 4096`, `regler types strict`, puis `rejouer`."],
    inv: () => ["Aux archives (sud du hall), compare ce que la spécification annonce et ce que les journaux montrent.", "`aller sud` (depuis le hall), `recenser`"],
    v1: () => ["Une route de l'ancienne version n'est pas dans la spécification. Va voir si elle est protégée.", "`jeton aucun`, `GET /v1/comptes/1042`"],
    v1fix: () => ["Une ancienne version sans protections est une dette : retire-la.", "`retirer v1`"],
    v1test: () => ["Vérifie que l'ancienne route est bien coupée.", "`GET /v1/comptes/1042`"],
    key: () => ["Au coffre (en bas du hall), la clé statique du partenaire : essaie-la, laisse passer du temps, essaie encore.", "`aller bas`, `jeton cle`, `GET /admin/utilisateurs`, `attendre 1440`, `GET /admin/utilisateurs`."],
    keyfix: () => ["Remplace la clé statique par des jetons courts avec portées.", "`corriger auth`"],
    tok: () => ["Émets un jeton limité à la lecture. Teste ce qu'il ne permet pas, puis ce qui se passe quand il vieillit.", `\`emettre comptes:lire\`, \`POST /virements {"iban":"${IBAN}","montant":50}\` (403), \`attendre 20\`, \`GET /profil\` (401).`],
    end: () => ["Rends compte à Maître Ada, dans le hall.", "Retourne au hall (haut, nord, est, ouest ou sud selon l'endroit, selon la sortie indiquée), puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ============ Dialogues ============ */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; give("mandat");
          say("Maître Ada", "La banque de la cité a ouvert son API aux applis mobiles et aux partenaires. Elle nous a donné un mandat pour la tester : comptes fictifs, aucune donnée réelle, et uniquement pour corriger. Une API est une rangée de guichets que n'importe quel programme peut interroger : si un guichet oublie une vérification, quelqu'un finira par la trouver.");
          say("Maître Ada", "Commence par les guichets, à l'est : un jeton d'Alice, un identifiant de compte, et regarde ce que le serveur te répond. Tu testes, tu constates, tu corriges.");
          out("Tu reçois **le mandat d'audit**.", "ok");
        } else if (x.end) say("Maître Ada", "L'API de la banque est bien mieux gardée. Bon travail !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas terminé. `indice` si tu bloques. Les cinq couloirs : est (guichets), nord (portique), ouest (greffe), sud (archives), bas (coffre).");
        break;
      case "gaston":
        if (!x.quest) say("Gaston", "Mandat ? Maître Ada voudrait vous voir d'abord.");
        else say("Gaston", "Je réponds à toute requête bien formée qui m'arrive avec un jeton valable. Chaque route est un guichet : je regarde le jeton, puis je sers ce qu'on me demande. Que le jeton soit celui du propriétaire de l'objet demandé, ça, je ne le vérifie que si on m'a appris à le faire. Utilise le tableau des routes.");
        break;
      case "portier":
        say("Portier", `Je distribue des jetons de passage : un par requête. Mon seau en contient ${nf(F().cap)} au départ et se remplit de ${nf(F().rate)} par seconde. Plein : j'autorise des rafales. Vide : je réponds 429 « Too Many Requests » et j'indique Retry-After, le nombre de secondes à patienter. Règle-moi, puis \`simuler\`.`);
        break;
      case "mallory":
        say("Mallory", "Un portier gentil, ça n'existe pas. Dix mots de passe à la seconde, tant qu'on ne me stoppe pas : avec 500 essais, quelqu'un finira bien par avoir un mot de passe faible. (Simulation de journal : aucune vraie connexion.)");
        break;
      case "greffier":
        say("Greffier", "Un bon schéma dit ce qu'il accepte, pas ce qu'il refuse : types, bornes, tailles, champs connus. Tout le reste est rejeté avant d'atteindre le moindre code métier. Mais attention aux bornes trop serrées : refuser un virement légitime est aussi un bug. Je rejoue les requêtes avec `rejouer`.");
        break;
      case "eve":
        say("Ève", "J'écoute la passerelle : ce qui est documenté, ce qui est appelé. Les deux listes ne coïncident pas toujours. Quand une version est « abandonnée », qui s'assure que plus personne ne l'appelle ? `recenser` compare les deux piles.");
        break;
      case "gardien":
        say("Gardien", F().auth ? "Plus de clé statique : des jetons de quinze minutes, avec des portées. Je regrette un peu la vieille clé : elle était belle sous sa cloche." : "Cette clé ne s'use jamais, elle ouvre tout, et vingt personnes en ont une copie. Teste-la : `jeton cle`, puis une requête, puis laisse passer du temps (`attendre`).");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ============ Verbes ============ */
  function setIdent(c) {
    const x = F();
    if (!x.quest) { out("Parle d'abord à Maître Ada.", "sys"); return; }
    const t = norm(c.rawArg);
    const map = { alice: "alice", admin: "admin", administrateur: "admin", cle: "cle", emis: "emis", court: "emis", aucun: "aucun", aucune: "aucun", anonyme: "aucun" };
    const k = map[t.split(" ").pop()];
    if (!t || !k) { out("Quelle identité ? `jeton alice` · `jeton admin` (compte de test administrateur) · `jeton cle` (clé statique) · `jeton emis` (jeton court) · `jeton aucun`", "err"); return; }
    x.ident = k;
    out(`Les requêtes partent maintenant avec : ${who()}`, "ok");
    if (k === "emis" && !x.tok) out("(Aucun jeton court émis pour l'instant : `emettre ‹portée›` après avoir corrigé l'authentification.)", "sys");
  }

  function parseBody(txt) {
    if (!txt) return { body: undefined };
    if (txt[0] === "{" || txt[0] === "[") { try { return { body: JSON.parse(txt) }; } catch (e) { return { bad: true }; } }
    const b = {};
    txt.split(/[\s,]+/).filter(Boolean).forEach(kv => {
      const i = kv.indexOf("="); if (i < 1) return;
      let v = kv.slice(i + 1); if (/^-?\d+(\.\d+)?$/.test(v)) v = +v; else if (v === "true") v = true; else if (v === "false") v = false;
      b[kv.slice(0, i)] = v;
    });
    return { body: b };
  }
  function printRes(rq, res) {
    const hs = Object.entries(res.headers || {}).map(([k, v]) => `\n   ${k}: ${v}`).join("");
    code(`→ ${rq.method} ${rq.url}\n   ${who()}${rq.bodyTxt ? "\n   corps : " + (rq.bodyTxt.length > 70 ? rq.bodyTxt.slice(0, 70) + "…" : rq.bodyTxt) : ""}\n← ${res.status} ${REASON[res.status] || ""}${hs}\n${pj(res.body)}`);
  }
  function mkReq(method, url, bodyTxt) {
    const [path, qs] = url.split("?"); const query = {};
    (qs || "").split("&").filter(Boolean).forEach(kv => { const i = kv.indexOf("="); try { query[decodeURIComponent(i < 0 ? kv : kv.slice(0, i))] = i < 0 ? "" : decodeURIComponent(kv.slice(i + 1)); } catch (e) { /* ignore */ } });
    const pb = parseBody(bodyTxt);
    return { method, url, path, query, body: pb.body, bad: pb.bad, bodyTxt, size: bodyTxt.length };
  }
  function http(c) {
    const x = F();
    if (!x.quest) { out("Parle d'abord à Maître Ada.", "sys"); return; }
    let method, rest = c.rawArg.trim();
    if (/^(get|post|put|patch|delete)$/.test(c.verb)) method = c.verb.toUpperCase();
    else { const mm = rest.match(/^(\S+)\s*([\s\S]*)$/); method = mm ? mm[1].toUpperCase() : ""; rest = mm ? mm[2] : ""; }
    const m = rest.match(/^(\S+)\s*([\s\S]*)$/);
    if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method) || !m || m[1][0] !== "/") { out("Syntaxe : `GET /comptes/1042` · `PATCH /profil {\"nom\":\"Alice B.\"}` · `POST /virements {\"iban\":\"" + IBAN + "\",\"montant\":50}`. Un chemin commence par /.", "err"); return; }
    const rq = mkReq(method, m[1], m[2].trim());
    const res = serve(rq);
    printRes(rq, res);
    after(rq, res);
  }

  function after(rq, res) {
    const x = F(), me = res.me;
    // fuite de données sur les comptes
    if (res.acc && res.status === 200 && res.body.hash_mdp && !x.filtre) {
      if (!x.expoSeen) { x.expoSeen = true; out("Remarque : la réponse contient aussi hash_mdp et note_interne. Un client n'a que faire de ces champs ; garde-le en tête.", "sys"); }
    }
    if (res.legacy && res.status === 200 && res.acc.n !== 1041 && !x.v1Seen) {
      x.v1Seen = true;
      out(x.v1 === "auth" ? "Même avec l'authentification ajoutée, la v1 sert le compte d'un AUTRE client : l'ancien code n'a ni contrôle de propriété ni filtrage." : "**Fuite** : l'ancienne route répond à n'importe qui, sans authentification, sans contrôle de propriété ni filtrage (hash_mdp compris). La correction UUID ne l'a jamais touchée.", "err");
    }
    if (res.legacy && res.status === 200 && x.v1 === "auth" && res.acc.n !== 1041 && x.v1Seen) out("Authentifiée, mais toujours sans contrôle de propriété : l'ancienne v1 reste une faille. Mieux vaut la retirer.", "err");
    if (me && me.name === "alice" && res.acc && !res.legacy) {
      const foreign = res.acc.n !== 1041;
      if (res.status === 200 && foreign && !x.owner) {
        x.bolaSeen = true;
        out(`**Fuite** : avec le jeton d'Alice, tu lis le compte de ${res.acc.titulaire} (solde, IBAN, hash du mot de passe) en changeant seulement l'identifiant. Le serveur n'a jamais demandé : « ce compte est-il bien celui de l'appelant ? »`, "err");
        fig("requete");
      } else if (res.foreign && x.owner && !x.uuid) {
        x.bolaBlk = true; note("bola");
        out("Refusé : la propriété est vérifiée. (Mais 403 révèle que ce compte existe : on peut encore énumérer les numéros.)", "ok");
        fig("requete");
      } else if (res.status === 200 && !foreign && x.uuid && !x.uuidOk) {
        x.uuidOk = true;
        out("Ton propre compte répond avec l'UUID. Les numéros 1041, 1042… ne sont plus acceptés : un attaquant n'a plus de voisinage à parcourir.", "ok");
        fig("requete");
      }
      if (res.status === 200 && !foreign && x.filtre && !x.expoOk && x.owner) {
        x.expoOk = true; note("expo");
        out("Plus de hash_mdp ni de note_interne : seul ce dont le client a besoin est renvoyé.", "ok");
      }
    }
    // niveau fonction
    if (res.admin && me && me.name === "alice" && me.role !== "admin" && !x.admSeen) {
      x.admSeen = true;
      out("**Fuite** : une simple cliente liste tous les utilisateurs (noms, e-mails, rôles). La route d'administration existe, et rien n'y contrôle le rôle.", "err");
    }
    if (res.fn && me && me.name === "alice") { x.admBlk = true; out("Refusé : le rôle est vérifié sur la route.", "ok"); }
    if (res.admin && me && me.name === "admin" && x.fonction) { x.admOk = true; out("L'administrateur de test passe toujours : la correction ne casse pas l'usage légitime.", "ok"); }
    if (x.admBlk && x.admOk && !x.admNote) { x.admNote = true; note("fonction"); }
    // affectation de masse
    if (rq.path === "/profil" && rq.method === "PATCH") {
      if (res.massChanged && !x.white) {
        x.massSeen = true;
        out(`**Fuite** : le serveur a recopié tous les champs du corps. Alice est désormais « ${x.prof.role} » et son solde affiche ${x.prof.solde}. L'interface ne propose pas ces champs, mais l'API les accepte.` + (x.fonction ? " Et le contrôle du rôle sur /admin devient inutile : le rôle est lu dans un champ que l'utilisatrice vient de modifier." : ""), "err");
      } else if (res.mass && x.massSeen && !x.massBlk) { x.massBlk = true; note("masse"); out("Refusé : seuls nom et email sont modifiables.", "ok"); }
    }
    // authentification
    if (res.status === 200 && x.ident === "cle" && !x.auth && x.clock >= 60 && !x.keyForever) {
      x.keyForever = true;
      out(`**La clé répond toujours**, ${Math.floor(x.clock / 60)} h plus tard, avec tous les pouvoirs (elle a même listé les utilisateurs). Elle n'expire pas, ne peut pas être limitée, et le jour où elle fuite il faut la changer pour tous ses utilisateurs en même temps.`, "err");
      fig("jetons");
    }
    if (res.revoked) out("La clé statique est refusée : elle est révoquée.", "ok");
    if (res.scope && x.ident === "emis" && rq.path === "/virements") { x.scopeOk = true; out("Refusé : le jeton n'a que la portée comptes:lire. Un jeton volé ne permet pas de virer de l'argent.", "ok"); }
    if (res.expired) { x.expOk = true; out("Refusé : le jeton court a expiré. Un jeton volé ne sert que quelques minutes.", "ok"); }
    if (x.scopeOk && x.expOk && !x.authNote) { x.authNote = true; note("auth"); fig("jetons"); }
    // v1 retirée
    if (rq.path.startsWith("/v1/") && res.status === 410 && x.v1 === "retired" && !x.v1Gone) {
      x.v1Gone = true; note("inventaire"); out("410 Gone : l'ancienne version est coupée. Les vieilles applis doivent migrer.", "ok"); fig("versions");
    }
    // effet des requêtes à la main sur le corpus
    if (res.vir && rq.body && typeof rq.body.montant === "number" && rq.body.montant < 0) out("Effet : un montant négatif inverse le virement, le compte émetteur est CRÉDITÉ.", "err");
    if (rq.path === "/transactions" && res.status === 200 && res.body.renvoyees >= 1000) out(`Effet : ${res.body.renvoyees} lignes (${res.body.taille_approx}) renvoyées pour une seule requête.`, "err");
  }

  function sweep() {
    const x = F();
    if (!x.quest) { out("Parle d'abord à Maître Ada.", "sys"); return; }
    if (x.uuid) { out("Les identifiants sont des UUID : 2^122 valeurs possibles, pas de voisinage à parcourir. Un balayage numérique renverrait 404 partout.", "ok"); return; }
    out(`Test d'identifiants voisins de 1041 à 1046, avec l'identité « ${x.ident} » :`, "sys");
    const rows = []; let leak = 0, exist = 0;
    for (let n = 1040; n <= 1046; n++) {
      const rq = mkReq("GET", "/comptes/" + n, ""), res = serve(rq);
      const own = n === 1041;
      if (res.status === 200 && !own) leak++;
      if (res.status !== 404) exist++;
      rows.push(`GET /comptes/${n} -> ${res.status} ${REASON[res.status]}`);
    }
    code(rows.join("\n"));
    if (x.ident !== "alice") { out("(Utilise `jeton alice` pour un test réaliste.)", "sys"); return; }
    if (leak) out(`${leak} comptes d'autres clients lisibles : tout le fichier clients s'énumère en quelques requêtes.`, "err");
    else out(`Plus rien n'est lisible, mais ${exist - 1} comptes répondent 403 au lieu de 404 : on sait lesquels existent. Des identifiants imprévisibles fermeraient aussi cette fenêtre.`, "sys");
  }

  const origProf = () => Object.assign({}, PROF0);
  function fix(c) {
    const x = F(), t = norm(c.rawArg);
    if (/auth|jeton|portee|expir/.test(t)) {
      if (S.room !== "coffre") { out("L'authentification se règle au coffre des clés (en bas du hall).", "sys"); return; }
      if (!x.keyForever) { out("Rien à corriger pour l'instant : teste d'abord la clé statique (`jeton cle`, une requête, `attendre 1440`, une requête).", "sys"); return; }
      if (x.auth) { out("Déjà en place.", "sys"); return; }
      x.auth = true;
      out(`La clé statique est révoquée. Le serveur émet désormais des jetons de ${TTL} minutes, liés à un utilisateur, avec des portées (comptes:lire, virements:creer, admin:lire pour un administrateur). \`emettre ‹portée›\` pour en obtenir un.`, "ok");
      return;
    }
    if (S.room !== "guichets") { out("Les corrections de code du serveur se font aux guichets (est du hall).", "sys"); return; }
    if (/propri|owner|bola|idor/.test(t)) {
      if (!x.bolaSeen) { out("Rien à corriger pour l'instant : reproduis d'abord la faille (`GET /comptes/1042` avec `jeton alice`).", "sys"); return; }
      if (x.owner) { out("Déjà en place.", "sys"); return; }
      x.owner = true; out("Chaque accès à un compte compare désormais le propriétaire de l'objet à l'identité tirée du jeton, jamais à une valeur fournie par le client. Rejoue la requête pour vérifier.", "ok");
    } else if (/uuid|identifiant|opaque/.test(t)) {
      if (!x.owner) { out("Les identifiants imprévisibles ne remplacent pas le contrôle de propriété : commence par `corriger propriete`.", "sys"); return; }
      if (x.uuid) { out("Déjà en place.", "sys"); return; }
      x.uuid = true; out("Les comptes sont désormais désignés par des UUID aléatoires. Le serveur ne répond plus aux numéros.", "ok");
    } else if (/fonction|role|admin|droit/.test(t)) {
      if (!x.admSeen) { out("Rien à corriger pour l'instant : essaie d'abord la route d'administration avec `jeton alice`.", "sys"); return; }
      if (x.fonction) { out("Déjà en place.", "sys"); return; }
      x.fonction = true; out("Les routes /admin exigent maintenant le rôle administrateur. Teste avec Alice (refusée) et avec l'administrateur de test (accepté).", "ok");
    } else if (/blanche|liste|champ|masse/.test(t)) {
      if (!x.massSeen) { out("Rien à corriger pour l'instant : essaie d'abord d'ajouter un champ sensible à PATCH /profil.", "sys"); return; }
      if (x.white) { out("Déjà en place.", "sys"); return; }
      x.white = true; x.prof = origProf();
      out("PATCH /profil n'accepte plus que les champs nom et email ; le reste est refusé avec un 422. Le profil d'Alice a été restauré depuis la sauvegarde (rôle client, solde 2450).", "ok");
    } else if (/filtr|dto|expos|serial/.test(t)) {
      if (!x.expoSeen) { out("Rien à corriger pour l'instant : lis d'abord un de tes comptes.", "sys"); return; }
      if (x.filtre) { out("Déjà en place.", "sys"); return; }
      x.filtre = true; out("La réponse est désormais construite champ par champ (id, titulaire, solde, iban) au lieu de renvoyer l'enregistrement de la base. Relis ton compte.", "ok");
    } else out("Quelle mesure ? `corriger propriete` · `corriger uuid` · `corriger fonction` · `corriger liste blanche` · `corriger filtrage` (et `corriger auth` au coffre)", "err");
  }

  function setRule(c) {
    const x = F();
    const m = c.rawArg.trim().match(/^(\S+)\s+(\S+)$/);
    if (S.room !== "portique" && S.room !== "greffe") { out("Les réglages se font au portique (seau à jetons) ou au greffe (schéma).", "sys"); return; }
    if (!m) { out(S.room === "portique" ? "`regler capacite ‹n›` ou `regler rythme ‹n›` (jetons par seconde, ex. 0,5)" : "`regler page ‹n›` · `regler montant ‹n›` · `regler corps ‹octets›` · `regler types strict|souple`", "err"); return; }
    const k = norm(m[1]), raw = m[2], v = parseFloat(raw.replace(",", "."));
    if (S.room === "portique") {
      if (!Number.isFinite(v) || !/^[\d.,]+$/.test(raw)) { out("Donne un nombre.", "err"); return; }
      if (/^capac|^seau/.test(k)) { if (v < 1 || v > 1000 || !Number.isInteger(v)) { out("La capacité est un entier entre 1 et 1000.", "err"); return; } x.cap = v; }
      else if (/^rythme|^debit|^taux/.test(k)) { if (v < 0.01 || v > 1000) { out("Le rythme se règle entre 0,01 et 1000 jetons par seconde.", "err"); return; } x.rate = v; }
      else { out("Au portique : `regler capacite ‹n›` ou `regler rythme ‹n›`.", "err"); return; }
      out(`Seau : capacité ${nf(x.cap)}, rythme ${nf(x.rate)}/s. \`simuler\` pour tester.`, "ok");
      return;
    }
    if (/^types?/.test(k)) {
      if (/^strict/.test(norm(raw))) x.strict = true; else if (/^souple|^lax|^libre/.test(norm(raw))) x.strict = false; else { out("`regler types strict` ou `regler types souple`", "err"); return; }
      out(`Types ${x.strict ? "stricts : nombres réels, montant > 0, iban au bon format, aucun champ inattendu" : "souples : rien n'est vérifié"}. \`rejouer\` pour tester.`, "ok"); return;
    }
    if (!Number.isFinite(v) || v < 1 || !/^\d+$/.test(raw)) { out("Donne un entier positif.", "err"); return; }
    if (/^page|^limit/.test(k)) x.pageMax = v;
    else if (/^montant/.test(k)) x.montantMax = v;
    else if (/^corps|^taille/.test(k)) x.corpsMax = v;
    else { out("Au greffe : `regler page|montant|corps ‹n›` ou `regler types strict|souple`.", "err"); return; }
    out(`Règle enregistrée : page ${x.pageMax || "illimitée"}, montant ${x.montantMax || "illimité"}, corps ${x.corpsMax ? x.corpsMax + " octets" : "illimité"}. \`rejouer\` pour tester.`, "ok");
  }

  function simulate() {
    const x = F();
    if (S.room !== "portique") { out("La simulation se lance au portique (nord du hall).", "sys"); return; }
    const { L, A, legRej, attPass } = rateStats();
    out(`Réglage : capacité ${nf(x.cap)}, rythme ${nf(x.rate)}/s. Une minute de trafic rejouée, un seau par client :`, "sys");
    const wins = [];
    for (let s = 10; s < 60; s += 10) wins.push(`${String(s).padStart(2)}–${String(s + 10).padStart(2)} s : ${A.filter(e => e.t >= s * 1000 && e.t < (s + 10) * 1000 && e.ok).length} passent sur 100`);
    const firstRej = A.find(e => !e.ok);
    code(`Alice (usage normal) : ${L.length} requêtes, ${legRej.length} refusée(s) par 429\nMallory (connexion, 10/s) : ${A.length} tentatives, ${attPass} passent, ${A.length - attPass} refusées\n${wins.join("\n")}` +
      (firstRej ? `\n\nExemple de refus (Mallory, t = ${nf(firstRej.t / 1000)} s) :\nHTTP/1.1 429 Too Many Requests\nRetry-After: ${firstRej.retry}` : "\n\n(aucun refus : le seau ne bloque rien)"));
    x.rateSeen = true;
    if (legRej.length) { out(`Alice est bloquée : la première fois à t = ${nf(legRej[0].t / 1000)} s (Retry-After ${legRej[0].retry} s). Un seau trop petit ou trop lent gêne l'usage normal, notamment les rafales de chargement de page.`, "err"); }
    if (attPass > RATE_GOAL) out(`Mallory fait trop d'essais : ${attPass} passent en ${ATT_SECONDS} s (≈ capacité + rythme × ${ATT_SECONDS} = ${nf(x.cap)} + ${nf(x.rate)} × ${ATT_SECONDS}). Vise ${RATE_GOAL} au plus.`, "err");
    if (!legRej.length && attPass <= RATE_GOAL) {
      if (!x.rateOk) { x.rateOk = true; note("debit"); out("Réglage validé : un usage normal passe, la force brute est freinée, et les refus portent un Retry-After.", "ok"); }
      else out("Réglage toujours valable.", "ok");
    }
    fig("seau");
  }

  function replay() {
    const x = F();
    if (S.room !== "greffe") { out("Le rejeu se fait au greffe (ouest du hall).", "sys"); return; }
    const rows = [], todo = new Set(); let legBlocked = 0, abPass = 0, abBlocked = 0;
    const hint = { A1: "page", A2: "page", A3: "types", A4: "types", A5: "montant", A6: "corps", A7: "types" };
    CORPUS.forEach(it => {
      const v = validate(it.rq);
      if (!v.ok) {
        rows.push(`${it.id} BLOQUÉE ${v.status}  ${it.label}  (${v.msg})`);
        if (it.legit) { legBlocked++; rows.push("     ↳ requête LÉGITIME refusée : règle trop stricte"); } else abBlocked++;
      } else {
        const st = it.rq.method === "GET" ? 200 : (typeof it.rq.body.montant === "number" ? 201 : 500);
        rows.push(`${it.id} acceptée ${st}  ${it.label}`);
        if (!it.legit) { abPass++; todo.add(hint[it.id]); rows.push("     ↳ " + it.effect); }
      }
    });
    code(rows.join("\n"));
    x.valSeen = true;
    out(`Légitimes passées : ${5 - legBlocked}/5 · abusives bloquées : ${abBlocked}/7`, abPass || legBlocked ? "sys" : "ok");
    if (legBlocked) out("Une règle bloque des requêtes légitimes : desserre-la (export de 100 lignes, virements jusqu'à 5000, libellé de 1,2 Ko).", "err");
    if (abPass) out("À traiter encore : " + [...todo].map(k => ({ page: "la pagination (`regler page ‹n›`)", types: "les types et champs (`regler types strict`)", montant: "le montant maximum (`regler montant ‹n›`)", corps: "la taille du corps (`regler corps ‹octets›`)" }[k])).join(" ; ") + ".", "err");
    if (!legBlocked && !abPass && !x.valOk) { x.valOk = true; note("validation"); out("Toutes les requêtes légitimes passent, toutes les abusives sont rejetées avant d'atteindre le code métier.", "ok"); }
    fig("validation");
  }

  function census() {
    const x = F();
    if (S.room !== "archives") { out("L'inventaire se fait aux archives (sud du hall).", "sys"); return; }
    const key = r => r[0] + " " + r[1];
    const spec = new Set(SPEC.map(key)), extra = LOG.filter(r => !spec.has(key(r)));
    code(`Spécification officielle (OpenAPI) : ${SPEC.length} routes\nJournaux de la passerelle (30 jours) : ${LOG.length} routes distinctes\n\nAppelées mais ABSENTES de la spécification :\n${extra.map(r => `  ${r[0]} ${r[1]}  ${r[2]} appels`).join("\n")}`);
    if (!x.invSeen) { x.invSeen = true; say("Ève", "L'ancienne appli mobile « Banque Lite 1.x » appelle encore /v1. On la croyait éteinte depuis un an."); }
    out("Une route qui n'est pas dans la spécification n'est ni revue, ni testée, ni protégée par les nouveaux contrôles. Va voir ce qu'elle renvoie : `jeton aucun`, `GET /v1/comptes/1042`.", "sys");
    fig("versions");
  }
  function retire(c) {
    const x = F();
    if (S.room !== "archives") { out("La gestion des versions se fait aux archives (sud du hall).", "sys"); return; }
    if (!/v1/.test(norm(c.rawArg))) { out("`retirer v1`", "err"); return; }
    if (!x.v1Seen) { out("Rien à retirer pour l'instant : inspecte d'abord /v1 (`jeton aucun`, `GET /v1/comptes/1042`).", "sys"); return; }
    if (x.v1 === "retired") { out("Déjà retirée.", "sys"); return; }
    x.v1 = "retired"; out("/v1 répond désormais 410 Gone, avec un message de migration. Vérifie : `GET /v1/comptes/1042`.", "ok");
  }
  function protect(c) {
    const x = F();
    if (S.room !== "archives") { out("La gestion des versions se fait aux archives (sud du hall).", "sys"); return; }
    if (!/v1/.test(norm(c.rawArg))) { out("`proteger v1`", "err"); return; }
    if (!x.v1Seen) { out("Inspecte d'abord /v1 (`jeton aucun`, `GET /v1/comptes/1042`).", "sys"); return; }
    if (x.v1 !== "open") { out("Déjà fait.", "sys"); return; }
    x.v1 = "auth"; out("/v1 exige maintenant un jeton. Teste avec `jeton alice` : est-ce suffisant ? Sinon, `retirer v1`.", "ok");
  }

  function issue(c) {
    const x = F();
    if (S.room !== "coffre") { out("Les jetons s'émettent au coffre (en bas du hall).", "sys"); return; }
    if (!x.auth) { out("Le serveur n'émet pas encore de jetons : tout le monde utilise la clé statique. (`corriger auth`)", "sys"); return; }
    const want = c.rawArg.split(/[\s,]+/).filter(Boolean);
    const valid = ["comptes:lire", "virements:creer", "admin:lire"];
    if (!want.length || want.some(s => !valid.includes(s))) { out("Portées possibles : `emettre comptes:lire` · `emettre comptes:lire virements:creer` · admin:lire (réservée aux administrateurs).", "err"); return; }
    if (want.includes("admin:lire") && x.prof.role !== "admin") { out("Refusé : le serveur n'émet que les portées permises par le rôle de l'utilisateur (Alice est cliente).", "err"); return; }
    x.tok = { scopes: want, iat: x.clock }; x.ident = "emis";
    code(`Jeton émis (signé par le serveur) :\n${pj({ sub: "alice", scope: want.join(" "), iat: clockStr(x.clock), exp: clockStr(x.clock + TTL) })}`);
    out("Tes requêtes partent maintenant avec ce jeton court.", "ok");
  }
  function wait(c) {
    const x = F();
    if (!x.quest) { out("Parle d'abord à Maître Ada.", "sys"); return; }
    const m = c.rawArg.trim().match(/^(\d+)/), n = m ? +m[1] : 0;
    if (!n || n > 3000) { out("`attendre ‹minutes›` (1 à 3000), par exemple `attendre 20` ou `attendre 1440` pour un jour.", "err"); return; }
    x.clock += n; out(`${n} minute(s) passent. Il est ${clockStr(x.clock)}${Math.floor((540 + x.clock) / 1440) > 0 ? " (jour +" + Math.floor((540 + x.clock) / 1440) + ")" : ""}.`, "sys");
  }

  /* ============ Fin ============ */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Le serveur ne doit jamais faire confiance à ce que le client lui envoie : l'identifiant, le corps, la taille de page, la version appelée, la clé. Chaque guichet vérifie lui-même qui demande, quoi, et combien. Et personne ne protège ce qu'il a oublié : on tient à jour la liste des guichets.");
    say("Maître Ada", "Une dernière chose : les tests sont toujours autorisés, jamais improvisés. Tu avais un mandat, des comptes fictifs, un but de correction. C'est cela qui fait de toi une auditrice et pas une Mallory.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Les guichets = les routes de l'API ; Gaston = le serveur.** Une API REST expose des ressources par chemin et méthode (GET /comptes/{id}). Le serveur est la seule autorité : tout ce qui vient du client (URL, en-têtes, corps, jeton) est une entrée non fiable.");
    out("**Le casier de Bob = BOLA (IDOR).** Changer l'identifiant dans l'URL donnait accès à l'objet d'un autre : c'est la faille la plus fréquente des API (API1 de l'OWASP API Security Top 10). La parade est un contrôle de propriété à chaque accès, côté serveur. Les UUID empêchent d'énumérer, ils ne remplacent pas le contrôle ; et leur 403 contre 404 montre qu'une réponse même refusée peut renseigner.");
    out("**Le guichet « Administration » = autorisation au niveau de la fonction.** Une route sensible ouverte à tout porteur de jeton valide. Le rôle doit être contrôlé par route et par méthode, et venir d'une source que l'utilisateur ne maîtrise pas.");
    out("**Le formulaire qui recopie tout = affectation de masse.** Lier le corps JSON à l'objet sans liste blanche laisse le client écrire role ou solde. Et l'exposition excessive est le symétrique en sortie : renvoyer l'objet brut (hash_mdp, notes internes) en comptant sur l'interface pour masquer. Les deux relèvent de l'autorisation au niveau des propriétés (API3:2023).");
    out("**Le portique = le seau à jetons.** Capacité C, rythme r : sur une durée T un client obtient au plus C + r × T requêtes. Le 429 et Retry-After disent au client légitime quand revenir. La force brute sur une connexion demande en plus des limites plus strictes par compte et des mécanismes de blocage ; la limitation seule, par adresse, se contourne en changeant d'adresse.");
    out("**Le Greffier = la validation par schéma.** Types, bornes, champs connus, tailles de corps, taille de page maximale : rejet précoce de l'absurde (400, 413, 422). Des bornes trop serrées bloquent des clients légitimes : on les règle sur l'usage réel.");
    out("**Les archives = l'inventaire d'API.** /v1 oubliée, sans les contrôles modernes : une API fantôme (shadow) ou zombie. On compare spécification et trafic, on date le retrait, puis on coupe.");
    out("**La clé sous cloche = la clé statique ; le jeton de quinze minutes = le jeton court.** Une clé statique n'expire pas et ne se limite pas ; un jeton court, lié à un utilisateur et à des portées (le moindre privilège), borne les dégâts d'une fuite. OAuth 2.0 et OpenID Connect standardisent ces mécanismes.");
    out("**Les simplifications du jeu.** (1) Le serveur est un petit simulateur : pas de vrai réseau, pas de base de données, pas de signature cryptographique des jetons. (2) La chronologie du seau à jetons est fixe et rejouée par client ; en vrai il faut une clé de limitation fiable (compte, jeton, adresse), un stockage partagé entre serveurs et des limites adaptées à chaque route. (3) La validation du jeu ne couvre que quelques champs ; en pratique on valide par schéma OpenAPI ou JSON Schema, à la passerelle et dans le service. (4) Les autres risques (SSRF, consommation d'API tierces, mauvaise configuration) existent aussi. (5) Tout est fictif : ne teste que ce que tu as mandat de tester.");
    out("Rappel utile : **le client dit ce qu'il veut ; seul le serveur décide qui a le droit, de quoi, et combien.**", "ok");
  }

  /* ============ Schémas ============ */
  const figs = {
    requete: () => {
      const x = F();
      return {
        cap: x.owner ? "Le serveur compare le propriétaire de l'objet à l'identité du jeton : l'identifiant fourni par le client ne suffit plus." : "Le serveur renvoie l'objet demandé sans comparer son propriétaire à l'identité du jeton.",
        svg: SVG(216, "Requête et vérification de propriété",
          R(8, 16, 120, 46) + T(68, 36, "Alice", "f-b") + T(68, 52, "compte 1041", "f-s") +
          AR(128, 39, 292, 39) + T(210, 31, "requête", "f-s") +
          R(292, 16, 120, 46) + T(352, 36, "Serveur", "f-b") + T(352, 52, "API banque", "f-s") +
          T(210, 84, "GET /comptes/" + (x.uuid ? "c91d2e77-…" : "1042"), "f-b") +
          R(8, 96, 404, 56, x.owner ? "f-ok" : "f-bad") +
          T(210, 118, x.owner ? "propriétaire du compte (Bob) ≠ jeton (Alice)" : "aucune comparaison propriétaire / jeton", x.owner ? "ft-ok" : "ft-bad") +
          T(210, 140, x.owner ? "→ 403 refusé ✔" : "→ 200 : le compte de Bob est renvoyé ✘", x.owner ? "ft-ok f-b" : "ft-bad f-b") +
          R(8, 164, 404, 40, x.uuid ? "f-ok" : "f-bad") +
          T(210, 188, x.uuid ? "identifiants UUID : impossibles à énumérer" : "identifiants 1041, 1042, 1043… : faciles à énumérer", x.uuid ? "ft-ok" : "ft-bad"))
      };
    },
    seau: () => {
      const x = F(), { L, legRej, attPass } = rateStats(), C = x.cap, r = x.rate;
      const x0 = 34, x1 = 404, y0 = 32, y1 = 112;
      const px = t => (x0 + t / 60000 * (x1 - x0)).toFixed(1), py = v => (y1 - Math.max(0, Math.min(1, v / C)) * (y1 - y0)).toFixed(1);
      const pts = [`${px(0)},${py(C)}`];
      L.forEach(e => { pts.push(`${px(e.t)},${py(e.before)}`, `${px(e.t)},${py(e.after)}`); });
      const last = L[L.length - 1]; pts.push(`${px(60000)},${py(Math.min(C, last.after + (60000 - last.t) / 1000 * r))}`);
      const marks = legRej.map(e => T(px(e.t), y1 - 4, "✘", "ft-bad f-b")).join("");
      return {
        cap: "Niveau du seau d'Alice pendant une minute d'usage normal (en bas, 0 jeton ; en haut, seau plein). Chaque requête retire un jeton, le rythme le remplit.",
        svg: SVG(232, "Seau à jetons",
          T(210, 16, `capacité ${nf(C)} jetons · rythme ${nf(r)} par seconde`, "f-b") +
          LN(x0, y1, x1, y1) + LN(x0, y0, x0, y1) + T(x0 - 4, y0 + 4, nf(C), "f-s", "end") + T(x0 - 4, y1 + 3, "0", "f-s", "end") + T(x0, y1 + 14, "0 s", "f-s", "start") + T(x1, y1 + 14, "60 s", "f-s", "end") +
          `<polyline points="${pts.join(" ")}" class="f-ln f-pub" fill="none"/>` + marks +
          T(210, 152, legRej.length ? `Alice : ${legRej.length} requête(s) refusée(s) (429) ✘` : "Alice : aucune requête refusée ✔", legRej.length ? "ft-bad" : "ft-ok") +
          T(210, 174, `Mallory : ${attPass} tentatives sur 500 passent en ${ATT_SECONDS} s`, attPass <= RATE_GOAL ? "ft-ok" : "ft-bad") +
          T(210, 198, `au plus capacité + rythme × ${ATT_SECONDS} s = ${nf(C)} + ${nf(r)} × ${ATT_SECONDS}`, "f-s") +
          T(210, 216, "la capacité permet la rafale, le rythme borne le débit moyen", "f-s"))
      };
    },
    versions: () => {
      const x = F(); let body = T(8, 18, "Spécification (OpenAPI)", "f-b", "start") + T(222, 18, "Trafic observé (journaux)", "f-b", "start") + LN(8, 26, 412, 26);
      LOG.forEach((r, i) => {
        const y = 46 + i * 22, extra = i >= SPEC.length;
        if (!extra) body += T(8, y, r[0] + " " + r[1], "f-s", "start");
        else body += T(8, y, "(absente de la spécification)", x.v1 === "retired" ? "f-s" : "f-s ft-bad", "start");
        body += T(222, y, `${r[0]} ${r[1]}  ${r[2]}`, extra ? (x.v1 === "retired" ? "f-s ft-ok" : "f-s ft-bad f-b") : "f-s", "start");
      });
      body += T(210, 46 + LOG.length * 22 + 6, x.v1 === "retired" ? "/v1 retirée : 410 Gone ✔" : x.v1 === "auth" ? "/v1 protégée mais toujours présente : dette à retirer" : "une route active que personne n'a documentée ✘", x.v1 === "retired" ? "ft-ok f-b" : "ft-bad f-b");
      return { cap: "L'inventaire compare ce qui est documenté à ce qui est réellement appelé. Une route hors spécification échappe à toute revue.", svg: SVG(46 + LOG.length * 22 + 20, "Inventaire des versions d'API", body) };
    },
    validation: () => {
      const x = F();
      const steps = [
        [`① corps ≤ ${x.corpsMax ? x.corpsMax + " octets" : "(aucune limite)"}`, !!x.corpsMax],
        ["② JSON bien formé, sinon 400", true],
        [`③ types ${x.strict ? "stricts, montant > 0, champs connus" : "souples (rien n'est vérifié)"}`, !!x.strict],
        [`④ limit ≤ ${x.pageMax || "(aucune)"} · montant ≤ ${x.montantMax || "(aucun)"}`, !!(x.pageMax && x.montantMax)],
        ["⑤ autorisation, puis logique métier", true],
      ];
      let body = "";
      steps.forEach((s, i) => { const y = 10 + i * 40; body += R(8, y, 404, 32, s[1] ? "f-ok" : "f-bad") + T(20, y + 20, s[0], s[1] ? "ft-ok" : "ft-bad", "start"); });
      return { cap: "Le flux de validation : chaque requête traverse des contrôles de plus en plus fins avant d'atteindre le code métier. Vert = configuré.", svg: SVG(222, "Flux de validation", body) };
    },
    jetons: () => {
      const x = F();
      return {
        cap: "Une clé statique ne s'expire pas et donne tous les pouvoirs ; un jeton court, lié à un utilisateur et à des portées, limite les dégâts d'une fuite.",
        svg: SVG(196, "Clé statique et jeton court",
          R(8, 12, 196, 130, x.auth ? "" : "f-bad") + T(106, 34, "Clé statique", x.auth ? "f-b" : "f-b ft-bad") +
          T(18, 62, "n'expire jamais", "f-s", "start") + T(18, 82, "mêmes pouvoirs pour tous", "f-s", "start") + T(18, 102, "aucune identité d'utilisateur", "f-s", "start") + T(18, 122, "fuite = changer pour tous", "f-s", "start") +
          R(216, 12, 196, 130, x.auth ? "f-ok" : "") + T(314, 34, "Jeton court + portées", x.auth ? "f-b ft-ok" : "f-b") +
          T(226, 62, "expire en 15 minutes", "f-s", "start") + T(226, 82, "portées : comptes:lire…", "f-s", "start") + T(226, 102, "lié à un utilisateur", "f-s", "start") + T(226, 122, "renouvelable, révocable", "f-s", "start") +
          T(210, 172, x.auth ? "jetons courts en service ✔" : "clé statique en service ✘", x.auth ? "ft-ok f-b" : "ft-bad f-b"))
      };
    },
  };

  GAMES.api = {
    id: "api", order: 25, title: "Les Guichets de l'API", pageTitle: "API Quest", subtitle: "aventure textuelle · sécurité des API REST",
    blurb: "Teste l'API REST de la banque : change un identifiant, ajoute un champ, rafale de requêtes... puis corrige chaque faille.",
    concept: "Sécurité des API : BOLA, limitation de débit, validation",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    figAlias: { requete: ["bola", "idor", "propriete", "owner"], seau: ["debit", "limite", "bucket", "rate", "jetons"], versions: ["inventaire", "v1", "version"], validation: ["flux", "valid", "schema"], jetons: ["auth", "cle", "token", "portee"] },
    help: "Spécifiques : `GET|POST|PATCH ‹chemin› [corps JSON]` · `jeton alice|admin|cle|emis|aucun` · `corriger ‹mesure›` · `parcourir` · `regler ‹réglage› ‹valeur›` · `simuler` · `rejouer` · `recenser` · `retirer v1` · `emettre ‹portée›` · `attendre ‹minutes›`",
    verbs: {
      http: { words: ["get", "post", "put", "patch", "delete", "requete", "appeler"], run: http },
      ident: { words: ["jeton", "identite", "token"], run: setIdent },
      fix: { words: ["corriger", "durcir", "patcher", "securiser"], run: fix },
      sweep: { words: ["parcourir", "balayer", "voisins"], run: sweep },
      setrule: { words: ["regler", "fixer", "definir"], run: setRule },
      simulate: { words: ["simuler", "rafale"], run: simulate },
      replay: { words: ["rejouer", "corpus"], run: replay },
      census: { words: ["recenser", "cartographier", "decouvrir"], run: census },
      retire: { words: ["retirer", "decommissionner"], run: retire },
      protect: { words: ["proteger"], run: protect },
      issue: { words: ["emettre", "delivrer", "generer"], run: issue },
      wait: { words: ["attendre", "patienter", "avancer"], run: wait },
    },
    setup() {
      const x = F();
      Object.assign(x, { ident: "aucun", prof: origProf(), cap: 1000, rate: 1000, pageMax: 0, montantMax: 0, corpsMax: 0, strict: false, v1: "open", clock: 0, tok: null });
    },
    intro() {
      out("Les Guichets de l'API", "title");
      out("La banque de Port-443 a ouvert son API aux applis mobiles et aux partenaires. Un guichet par route : on glisse une requête, le serveur répond en JSON. Mais un guichet qui oublie une vérification, un formulaire qui accepte trop, une vieille porte oubliée dans un couloir : voilà comment les fuites arrivent.\nMaître Ada t'a obtenu un mandat d'audit. Tu vas tester l'API de démonstration (comptes fictifs), constater chaque faille, puis la corriger.", "");
    },
  };
})();
