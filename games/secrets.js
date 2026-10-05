"use strict";
/* Le Coffre aux Secrets : secrets dans le code, historique git, détection (motifs + entropie), révocation,
   coffre de secrets, jetons minimaux, gestionnaire de mots de passe, k-anonymité (SHA-256 réel), rotation. */
(function () {
  const X = () => {
    const x = f();
    if (!x.init) {
      x.init = true; x.thr = 5; x.rev = {}; x.tested = {}; x.vlog = []; x.vt = 2; x.id = null;
      x.pw = {}; BOB.forEach(([s, p]) => { x.pw[s] = p; }); x.gen = {}; x.rules = { horaires: true };
    }
    return x;
  };
  const F = X;
  const H = s => { const m = {}; for (const ch of s) m[ch] = (m[ch] || 0) + 1; let h = 0; for (const k in m) { const p = m[k] / s.length; h -= p * Math.log2(p); } return h; };
  const n2 = n => n.toFixed(2).replace(".", ",");
  const mask = v => (v.length <= 12 ? v : v.slice(0, 8) + "…" + v.slice(-3));

  /* ---------- l'historique du dépôt « export-clients » ---------- */
  const SK = "p443_live_9fK2xQ7mWb4Zc81LdR3vTy6HnA05sEjU", SS = "Zk8vQ2mX7pL4wN9tR3yB6hJ1", JOB = "ExportClientsNightlyJobRunner";
  const CFG = ['BUCKET = "exports-clients"', 'API_KEY = "' + SK + '"', 'SESSION_ID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"', 'PLACEHOLDER = "CHANGE_ME_CHANGE_ME_CHANGE_ME"'];
  const SIGLINE = 'SIGNING_SECRET = "' + SS + '"';
  const COMMITS = [
    { id: "e41c0d2", date: "02 mars", who: "Léo", msg: "init : squelette de l'API d'export", files: [
      { n: "app.py", s: "A", del: [], add: ["import os", 'BASE_URL = "https://api.port443.example/v2"', 'JOB_NAME = "' + JOB + '"', "def export_clients():", '    return fetch(BASE_URL + "/clients")'] },
      { n: "README.md", s: "A", del: [], add: ["# export-clients", "Génère l'export nocturne des clients."] }] },
    { id: "7ab93f1", date: "09 mars", who: "Léo", msg: "ajout de la config du stockage", files: [
      { n: "config.py", s: "A", del: [], add: CFG },
      { n: "app.py", s: "M", del: [], add: ["from config import API_KEY, BUCKET"] }] },
    { id: "c5d8e07", date: "11 mars", who: "Léo", msg: "ajout du client de signature", files: [
      { n: "signer.py", s: "A", del: [], add: [SIGLINE, 'BUILD_SHA = "9c1e5d0a47b2f83e6a1d"', "def sign(msg):", "    return hmac(SIGNING_SECRET, msg)"] }] },
    { id: "91fa6b3", date: "16 mars", who: "Léo", msg: "oups : on retire config.py du dépôt", files: [
      { n: "config.py", s: "D", del: CFG, add: [] },
      { n: "app.py", s: "M", del: ["from config import API_KEY, BUCKET"], add: ['API_KEY = os.environ["API_KEY"]'] }] },
    { id: "2d70ae8", date: "17 mars", who: "Léo", msg: "signer : lit la variable d'environnement", files: [
      { n: "signer.py", s: "M", del: [SIGLINE], add: ['SIGNING_SECRET = os.environ["SIGNING_SECRET"]'] }] },
    { id: "f08b3c6", date: "14 avr.", who: "Léo", msg: "doc : mise à jour du README", files: [
      { n: "README.md", s: "M", del: [], add: ["Les secrets sont lus dans l'environnement."] }] },
  ];
  const redact = l => (F().cleaned ? l.split(SK).join("[retiré]").split(SS).join("[retiré]") : l);
  function headTree() {
    const t = {};
    COMMITS.forEach(c => c.files.forEach(fl => {
      if (fl.s === "D") delete t[fl.n]; else if (fl.s === "A") t[fl.n] = fl.add.slice();
      else t[fl.n] = (t[fl.n] || []).filter(l => !fl.del.includes(l)).concat(fl.add);
    }));
    return t;
  }
  function scan(scope, dets) {
    const x = F(), hits = [];
    const look = (cid, file, lines) => lines.forEach(raw => {
      const l = redact(raw), re = /"([A-Za-z0-9_\-+/=]{20,})"/g; let m;
      while ((m = re.exec(l))) {
        const v = m[1], e = H(v); let rule = null;
        if (dets.m && /^p443_live_[A-Za-z0-9]{32}$/.test(v)) rule = "motif « p443_live_ »";
        else if (dets.e && e >= x.thr) rule = "entropie " + n2(e) + " ≥ seuil " + n2(x.thr);
        if (rule) hits.push({ cid, file, v, e, rule });
      }
    });
    if (scope === "head") { const t = headTree(); Object.keys(t).forEach(n => look("HEAD", n, t[n])); }
    else COMMITS.forEach(c => c.files.forEach(fl => look(c.id, fl.n, fl.add)));
    return hits;
  }

  /* ---------- données des autres étapes ---------- */
  const OPTS = { code: "secret écrit dans le code", dotenv: "fichier .env hors du dépôt (.gitignore)", env: "variables d'environnement du service", coffre: "gestionnaire de secrets (le coffre)" };
  // niveaux : 0 = échec, 1 = partiel, 2 = tient
  const SCEN = [
    ["dépôt qui fuit", "Le dépôt de code fuit (comme chez Léo)", { code: [0, "la clé est dans les commits : c'est exactement la fuite de Léo"], dotenv: [2, "le .env n'est pas versionné, à condition d'être dans .gitignore (un .env commité = la même fuite)"], env: [2, "rien dans le dépôt : le secret est injecté au lancement"], coffre: [2, "rien dans le dépôt : le code ne contient que l'adresse du coffre"] }],
    ["disque ou sauvegarde volé", "Un portable ou une sauvegarde de disque est volé", { code: [0, "le code est copié partout, sauvegardes comprises"], dotenv: [0, "fichier en clair sur le disque du poste et de ses sauvegardes"], env: [1, "pas dans le code, mais souvent écrit en clair dans un script de lancement ou un fichier de service"], coffre: [2, "le secret n'est jamais écrit sur le disque de l'application : il est demandé à la volée"] }],
    ["processus compromis", "Un processus de l'application est compromis", { code: [0, "le secret est lisible dans les fichiers et la mémoire"], dotenv: [0, "lisible par le processus et par tout programme du même utilisateur"], env: [0, "lisible dans l'environnement du processus (printenv, /proc), hérité par les processus enfants"], coffre: [1, "le secret est en mémoire de l'app, mais limité à son rôle, avec un bail court, et chaque lecture est journalisée et révocable"] }],
    ["qui a lu quoi ? (audit)", "On doit savoir qui a lu quel secret, et quand", { code: [0, "aucune trace : tout lecteur du code l'a"], dotenv: [0, "aucune trace de lecture"], env: [0, "aucune trace de lecture"], coffre: [2, "chaque accès est journalisé : identité, chemin, heure, résultat (refus compris)"] }],
    ["changer sans redéployer", "Il faut changer le secret sans tout redéployer", { code: [0, "modifier le code, relire, redéployer"], dotenv: [0, "refaire le fichier sur chaque machine"], env: [1, "possible, mais il faut redémarrer ou redéployer le service"], coffre: [2, "on publie une nouvelle version : l'application la lit à sa prochaine demande"] }],
  ];
  const optOf = raw => {
    const r = raw.toLowerCase();
    if (/\.env|dotenv|fichier/.test(r)) return "dotenv";
    if (/variable|environ|\benv\b/.test(r)) return "env";
    if (/coffre|vault|gestionnaire|secret/.test(r)) return "coffre";
    if (/code|dur|clair/.test(r)) return "code";
    return null;
  };
  const BUCKETS = [["exports-clients", "exports", 1240], ["paie", "paie", 310], ["archives", "archives", 18900], ["sauvegardes", "sauvegardes", 10950]];
  const ALLRES = BUCKETS.map(b => b[1]);
  const RTXT = { read: "lecture seule", write: "lecture + écriture", admin: "administrateur" };
  const dur = m => (m === Infinity ? "jamais" : m < 60 ? m + " min" : m < 1440 ? Math.round(m / 6) / 10 + " h" : Math.round(m / 144) / 10 + " j");
  const resTxt = r => (r.length === 4 ? "tous les buckets" : r.map(k => BUCKETS.find(b => b[1] === k)[0]).join(", "));
  function parseTok(raw) {
    const t = norm(raw);
    let rights = null;
    if (/admin|total|tous droits/.test(t)) rights = "admin"; else if (/ecri|write|modif|supprim/.test(t)) rights = "write"; else if (/lectur|lire|read/.test(t)) rights = "read";
    let res = [];
    if (/\btout\b|\btous\b|\ball\b/.test(t) || raw.includes("*")) res = ALLRES.slice();
    else ALLRES.forEach(k => { if (t.includes(k.slice(0, 5))) res.push(k); });
    let ttl;
    if (/eternel|permanent|jamais|illimit|infini|sans expiration/.test(t)) ttl = Infinity;
    else { const m = t.match(/(\d+)\s*(secondes?|sec|s|minutes?|min|m|heures?|h|jours?|j)\b/); if (m) { const u = m[2][0]; ttl = +m[1] * (u === "s" ? 1 / 60 : u === "m" ? 1 : u === "h" ? 60 : 1440); } }
    return { rights, res, ttl };
  }
  const theft = tok => BUCKETS.filter(b => tok.res.includes(b[1])).map(b => `${b[0].padEnd(16)} ${String(b[2]).padStart(6)} objets   ${tok.rights === "admin" ? "lire, modifier, supprimer" : tok.rights === "write" ? "lire, modifier" : "lire"}`);

  const BOB = [["mail", "soleil2020"], ["forge", "soleil2020"], ["wiki", "soleil2020"], ["vpn", "port443!"], ["badge", "Xk7#mP2$vQ9wLz4n"]];
  const LEAKED = [["soleil2020", 48211], ["password", 9912345], ["123456", 37359195], ["azerty", 2216384], ["qwerty", 3912816], ["port443!", 1842], ["letmein", 233210], ["motdepasse", 118345], ["admin123", 52117], ["bonjour1", 90234], ["hunter2", 14562], ["iloveyou", 3301234]];
  const LEAKMAP = new Map(LEAKED.map(([p, n]) => [sha256(p), [p, n]]));
  const bucket = pre => {
    const res = []; LEAKMAP.forEach(([p, n], h) => { if (h.startsWith(pre)) res.push({ s: h.slice(5), n }); });
    for (let i = 0; i < 9; i++) { const h = sha256("autre:" + pre + ":" + i); res.push({ s: h.slice(0, 59), n: 1 + (parseInt(h.slice(60, 64), 16) % 900) }); }
    return res.sort((a, b) => (a.s < b.s ? -1 : 1));
  };
  const bitsNaive = pw => { let pool = 0; if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10; if (/[^A-Za-z0-9]/.test(pw)) pool += 33; return Math.round(pw.length * Math.log2(pool || 1)); };
  const weak = site => { const x = F(), pw = x.pw[site]; return Object.values(x.pw).filter(p => p === pw).length > 1 || pw.length < 12 || LEAKMAP.has(sha256(pw)); };
  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-=?@^_";
  function randPw(len) {
    let s = "";
    const lim = 256 - (256 % ALPHA.length);
    while (s.length < len) {
      const b = new Uint8Array(len * 2);
      if (typeof crypto !== "undefined" && crypto.getRandomValues) crypto.getRandomValues(b); else for (let i = 0; i < b.length; i++) b[i] = Math.floor(Math.random() * 256);
      for (const v of b) { if (v < lim && s.length < len) s += ALPHA[v % ALPHA.length]; }
    }
    return s;
  }
  const NIGHT = [
    { t: "02:00", who: "app-export", ip: "10.4.0.12", op: "lecture secret/export", n: 1, ok: true, bad: false },
    { t: "02:00", who: "app-export", ip: "10.4.0.12", op: "lecture secret/signature", n: 1, ok: true, bad: false },
    { t: "03:05", who: "(clé révoquée)", ip: "203.0.113.77", op: "GET exports-clients", n: 14, ok: false, bad: true },
    { t: "03:12", who: "app-export", ip: "203.0.113.77", op: "lecture secret/export", n: 412, ok: true, bad: true },
    { t: "08:41", who: "alice", ip: "10.4.0.21", op: "écriture secret/db", n: 1, ok: true, bad: false },
    { t: "09:15", who: "leo", ip: "10.4.0.30", op: "métadonnées", n: 3, ok: true, bad: false },
    { t: "11:30", who: "app-export", ip: "10.4.0.12", op: "lecture secret/export", n: 1, ok: true, bad: false },
    { t: "15:02", who: "leo", ip: "10.4.0.30", op: "lecture secret/signature", n: 1, ok: false, bad: false },
  ];
  const RULES = {
    horaires: [e => { const h = +e.t.slice(0, 2); return h < 8 || h >= 19; }, "accès hors des heures de bureau (avant 08 h ou après 19 h)"],
    ip: [e => !e.ip.startsWith("10.4."), "adresse source hors du réseau de la Guilde (10.4.x.x)"],
    volume: [e => e.n > 50, "plus de 50 lectures dans la même minute"],
    refus: [e => !e.ok && e.n >= 5, "5 refus ou plus d'affilée"],
  };

  const notes = {
    types: ["Les types de secrets", "Un secret est une valeur dont la connaissance donne un pouvoir : clés d'API, jetons d'accès, mots de passe, clés privées (SSH, TLS), chaînes de connexion à une base, secrets de signature. Ils ne doivent être ni dans le code, ni dans une messagerie, et chacun doit pouvoir être remplacé à tout moment."],
    historique: ["Git n'oublie rien", "Un dépôt git conserve chaque version de chaque fichier. Supprimer un fichier ajoute un commit qui le retire de la version actuelle, mais les commits anciens le contiennent toujours (git show). Tout clone, fork ou cache en garde une copie. Un secret commité est un secret compromis, même « supprimé » ensuite."],
    entropie: ["L'entropie, pour repérer les secrets", "L'entropie de Shannon mesure l'imprévisibilité de la répartition des caractères d'une chaîne, en bits par caractère. Un mot lisible tourne autour de 2,5 à 3,5 ; une chaîne aléatoire dense dépasse 4,5 (maximum : log2 de la taille de l'alphabet, soit 4 pour de l'hexadécimal). Les détecteurs combinent des motifs (préfixes connus) et un seuil d'entropie : trop haut, on rate des secrets ; trop bas, on noie l'équipe de faux positifs."],
    revocation: ["Révoquer d'abord, nettoyer ensuite", "Dès qu'un secret a fuité, on le considère comme connu de l'attaquant : on le révoque ou on le fait tourner immédiatement, on le remplace, et seulement ensuite on nettoie l'historique et on enquête sur son usage. Réécrire l'historique ne reprend pas les copies déjà faites ; la révocation, si."],
    coffre: ["Le coffre de secrets", "Un gestionnaire de secrets (Vault, AWS Secrets Manager, etc.) stocke les secrets chiffrés et les remet à la demande à une identité authentifiée, selon une politique (rôle), avec un bail limité dans le temps et un journal de chaque accès, refus compris. Un fichier .env ou des variables d'environnement évitent le dépôt, mais n'offrent ni audit, ni contrôle fin, ni rotation simple."],
    moindre: ["Moindre privilège et durée de vie", "Un jeton doit avoir la portée minimale (une action sur une ressource) et la durée la plus courte possible. Une clé administrateur éternelle transforme chaque fuite en catastrophe ; un jeton qui ne lit qu'un seul bucket pendant un quart d'heure rend le vol presque inutile."],
    gestionnaire: ["Le gestionnaire de mots de passe", "Un mot de passe unique par site empêche le « credential stuffing » : la fuite d'un service ne donne pas accès aux autres. Un gestionnaire génère des mots de passe aléatoires longs et les chiffre avec une clé dérivée d'une seule phrase de passe maître : longue, unique, mémorisée, jamais stockée en clair."],
    kanon: ["La k-anonymité des fuites", "Pour savoir si un mot de passe a fuité sans le révéler : on calcule son empreinte localement, on n'envoie que son préfixe (quelques caractères), le serveur renvoie toutes les empreintes qui commencent ainsi, et la comparaison du suffixe se fait chez soi. Le serveur ne voit qu'un groupe de k candidats. C'est le principe de « Have I Been Pwned »."],
    rotation: ["Rotation et détection", "Les secrets doivent changer régulièrement (rotation planifiée, idéalement automatique et sans interruption grâce à deux versions qui se chevauchent) et immédiatement en cas de soupçon. La surveillance des journaux d'accès (heure inhabituelle, adresse inconnue, volume anormal, refus répétés) révèle l'usage anormal ; trop de fausses alertes la rend inutile."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle a l'air de quelqu'un qui n'a pas dormi depuis l'alerte du matin." },
    leo: { npc: true, names: ["leo", "developpeur", "dev"], label: "Léo, développeur", desc: () => "Léo, développeur de la Guilde, les épaules basses. C'est lui qui a poussé la clé dans le dépôt, il y a quelques semaines, « juste pour tester »." },
    journal: { names: ["journal", "historique", "commits", "depot", "tableau"], label: "le journal du dépôt", vis: () => S.room === "depot",
      desc: () => "Le grand tableau de l'historique du dépôt `export-clients` : six commits. `journal` les liste, `afficher ‹commit›` montre ce que chacun a changé." },
    scanner: { names: ["detecteur", "scanner", "chercheur"], label: "le détecteur de secrets", vis: () => S.room === "depot",
      desc: () => `Un détecteur de secrets, comme les vrais (gitleaks, GitHub secret scanning) : il cherche des **motifs** connus (un préfixe de clé) et des chaînes à forte **entropie** de Shannon (≥ ${n2(F().thr)} bits par caractère, à partir de 20 caractères).\n\`analyser tete\` : la version actuelle · \`analyser historique\` : tous les commits · \`seuil ‹bits›\` · \`entropie ‹texte›\`.` },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", vis: () => S.room === "depot", desc: () => "Mallory, assise sur le mur du dépôt, un ordinateur sur les genoux. Elle n'essaie même pas de se cacher : tout ce qui est public lui appartient." },
    console: { names: ["console", "guichet", "console des cles"], label: "la console des clés", vis: () => S.room === "guichet",
      desc: () => "La console qui gère toutes les clés et jetons de la Guilde.\n`revoquer ‹cle|signature›` : tuer un secret · `simuler vol ancienne` / `simuler vol` : voir ce que Mallory ferait d'un secret volé · `emettre jeton ‹droits› ‹ressource› ‹durée›` : délivrer un jeton.\nDroits : lecture, ecriture, admin. Ressources : exports, paie, archives, sauvegardes, tout. Durées : 15 min, 2 h, 3 j, eternel…" },
    ancienne: { names: ["ancienne cle", "vieille cle", "cle", "api key"], label: "l'ancienne clé de Léo", vis: () => S.room === "guichet",
      desc: () => { const x = F(); return `L'ancienne clé de Léo : ${mask(SK)}.\nDroits : administrateur (tout). Ressource : tous les buckets. Expiration : jamais. Statut : ${x.rev.cle ? "RÉVOQUÉE" : "active"}.\n(Léo l'avait créée en admin « pour ne pas avoir de problème de droits ».)`; } },
    dotenv: { names: ["dotenv", "env", "fichier env", "fichier"], label: "un fichier .env", vis: () => S.room === "coffre",
      desc: () => "Un fichier `.env` posé à côté de l'application : une ligne NOM=valeur par secret. Il est simple, il n'est pas dans le dépôt (si le .gitignore le dit), mais il reste en clair sur le disque." },
    variables: { names: ["variables", "variables environnement", "environnement"], label: "des variables d'environnement", vis: () => S.room === "coffre",
      desc: () => "Les variables d'environnement du service : le secret est injecté au lancement du programme, qui le lit avec os.environ. Pratique, 12-factor, mais visibles par tout le processus et ses enfants." },
    vault: { names: ["coffre", "vault", "gestionnaire de secrets"], label: "le coffre de secrets", vis: () => S.room === "coffre",
      desc: () => { const x = F(); return "Un coffre de secrets : chaque secret est chiffré, rangé sous un chemin (`secret/export`, `secret/signature`), et remis seulement à une identité dont la politique le permet, avec un bail de 15 minutes. Chaque demande est journalisée." + (x.vault ? "\nCommandes : `identifier ‹leo|app-export|mallory›` · `obtenir secret/export` · `journal`." : "\n(Pas encore adopté : `tester ‹option›` puis `adopter ‹option›`.)"); } },
    alice: { npc: true, names: ["alice"], label: "Alice", vis: () => S.room === "coffre", desc: () => "Alice, ingénieure plateforme de la Guilde. Elle gère les déploiements et se méfie de tout ce qui est « temporaire »." },
    bob: { npc: true, names: ["bob"], label: "Bob", vis: () => S.room === "cabinet", desc: () => "Bob, qui retient ses mots de passe par cœur. Autrement dit : il en a très peu, et il les réutilise." },
    trousseau: { names: ["trousseau", "gestionnaire", "gestionnaire de mots de passe"], label: "le trousseau du gestionnaire", vis: () => S.room === "cabinet",
      desc: () => {
        const x = F();
        const lines = Object.keys(x.pw).map(s => `${s.padEnd(6)} ${x.gen[s] ? "généré, " + x.pw[s].length + " car." : "dans la tête de Bob : " + x.pw[s].length + " car."}${weak(s) ? "   ← faible ou réutilisé" : ""}`).join("\n");
        return `Le trousseau (${x.master ? "chiffré par ta phrase maître" : "pas encore de phrase maître : `definir maitre ‹phrase›`"}) :\n${lines}\n\`auditer\` · \`definir maitre ‹phrase›\` · \`generer ‹site|tout›\``;
      } },
    registre: { names: ["registre", "registre des fuites", "serveur", "base"], label: "le Registre des fuites", vis: () => S.room === "cabinet",
      desc: () => "Le Registre des fuites de Port-443 : une base d'empreintes SHA-256 de mots de passe apparus dans des fuites publiques (fictives ici). On ne lui donne jamais un mot de passe.\n`hacher ‹mot de passe›` (ou `hacher @site` pour un mot de passe du trousseau) · `interroger ‹préfixe›` (sans argument : le préfixe de la dernière empreinte) · `comparer ‹mot de passe›`." },
    eve: { npc: true, names: ["eve"], label: "Ève", vis: () => S.room === "veille", desc: () => "Ève, qui écoutait tout dans l'ancien temps. Depuis que la Guilde l'a engagée, elle écoute les journaux." },
    releve: { names: ["releve", "alertes", "regles", "journal des acces"], label: "le tableau des alertes", vis: () => S.room === "veille",
      desc: () => { const x = F(); return "Le tableau des alertes : le journal d'accès de la nuit et les règles de détection.\nRègles actives : " + (Object.keys(x.rules).filter(k => x.rules[k]).join(", ") || "aucune") + ".\n`journal` · `activer alerte ‹horaires|ip|volume|refus›` · `desactiver alerte ‹…›` · `surveiller` · `tourner ‹secret›` · `planifier rotation ‹jours›`."; } },
  };

  const rooms = {
    atelier: { name: "L'atelier des développeurs", short: "Atelier", alias: ["atelier"], ents: ["ada", "leo"], exits: { nord: "depot", est: "coffre", ouest: "guichet", sud: "cabinet" },
      desc: () => "Des écrans, des tasses de café froid et un grand panneau : « Les secrets ne se commitent pas. » Quelqu'un l'a affiché ce matin. Au nord, le dépôt de code ; à l'est, la salle du coffre ; à l'ouest, le guichet des clés ; au sud, le cabinet des mots de passe." },
    depot: { name: "Le dépôt de code", short: "Dépôt", alias: ["depot", "code"], ents: ["journal", "scanner", "mallory"], exits: { sud: "atelier" },
      desc: () => "Une salle tapissée de rouleaux : chaque version de chaque fichier de la Guilde, depuis le début. Rien ne s'y perd. Un détecteur de secrets ronronne dans un coin ; sur le mur, une silhouette est assise, ordinateur sur les genoux." },
    coffre: { name: "La salle du coffre", short: "Coffre", alias: ["coffre", "salle du coffre"], ents: ["alice", "dotenv", "variables", "vault"], exits: { ouest: "atelier" },
      desc: () => "Une pièce froide. Sur une table, trois façons de ranger un secret : un fichier .env, une rangée de variables d'environnement, et, au fond, une porte blindée : le coffre." },
    guichet: { name: "Le guichet des clés", short: "Guichet", alias: ["guichet", "cles"], ents: ["console", "ancienne"], exits: { est: "atelier" },
      desc: () => "Un comptoir de laiton. Derrière la vitre, la console qui crée, révoque et surveille toutes les clés de la Guilde. Sur le comptoir, une vieille clé trop grosse, dont Léo n'osait pas se séparer." },
    cabinet: { name: "Le cabinet des mots de passe", short: "Cabinet", alias: ["cabinet", "mots de passe"], ents: ["bob", "trousseau", "registre"], exits: { nord: "atelier", est: "veille" },
      desc: () => "Un cabinet de curiosités où chaque tiroir porte un nom de site. Bob tient dans la main un carnet cornu. Le trousseau du gestionnaire est posé sur un pupitre, et un guichet vitré annonce : « Registre des fuites ». À l'est, la tour de veille." },
    veille: { name: "La tour de veille", short: "Veille", alias: ["veille", "tour"], ents: ["eve", "releve"], exits: { ouest: "cabinet" },
      desc: () => "Tout en haut, une pièce ronde dont les murs sont des écrans de journaux défilants. Ici, rien ne se passe sans qu'on l'écrive quelque part." },
  };

  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.sawLog) return "log";
    if (!x.shown) return "show";
    if (!x.headScan) return "head";
    if (!x.found1) return "scan";
    if (!x.found2) return "thr";
    if (!(x.rev.cle && x.rev.sig)) return "rev";
    if (!x.cleaned) return "clean";
    if (Object.keys(x.tested).length < 3) return "test";
    if (!x.vault) return "adopt";
    if (!x.vRead) return "vread";
    if (!x.vDeny) return "vdeny";
    if (!x.vLog) return "vlog";
    if (!x.oldSim) return "old";
    if (!x.tokGood) return "token";
    if (!x.simGood) return "steal";
    if (!x.audited) return "audit";
    if (!x.master) return "master";
    if (!x.kFound) return "kfound";
    if (!x.genAll) return "gen";
    if (!x.kClean) return "kclean";
    if (!x.tuned) return "rules";
    if (!x.rotated) return "rotate";
    if (!x.plan) return "plan";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend à l'atelier.", "`parler ada`"],
    log: () => ["Le dépôt de code est au nord. Commence par relire son historique.", "`aller nord`, puis `journal`."],
    show: () => ["Ouvre un commit pour voir ce qu'il a changé. Celui qui ajoute la config du stockage est suspect.", "`afficher 7ab93f1`"],
    head: () => ["Lance le détecteur sur la version actuelle du code : trouve-t-il quelque chose ?", "`analyser tete`"],
    scan: () => ["La version actuelle est propre. Mais git garde tout : fais analyser tout l'historique.", "`analyser historique`"],
    thr: () => ["Le détecteur a trouvé la clé grâce à son motif, mais pas autre chose. Ouvre les autres commits (`afficher c5d8e07`), repère une chaîne suspecte, mesure son entropie et baisse le seuil en dessous.", "`entropie Zk8vQ2mX7pL4wN9tR3yB6hJ1` donne 4,58 : essaie `seuil 4.4` puis `analyser historique`. (Le seuil le plus bas qui évite les faux positifs est autour de 4,3.)"],
    rev: () => ["Deux secrets ont fuité. Avant de toucher à l'historique : tuer les secrets, au guichet des clés (ouest de l'atelier).", "`aller sud`, `aller ouest`, `revoquer cle`, `revoquer signature`."],
    clean: () => ["Les secrets sont morts. Maintenant seulement, nettoie l'historique au dépôt.", "`aller est`, `aller nord`, `nettoyer historique`."],
    test: () => ["Alice t'attend au coffre (est de l'atelier). Compare trois façons de ranger un secret.", "`parler alice`, puis `tester code`, `tester dotenv`, `tester env`, `tester coffre`."],
    adopt: () => ["Tu as comparé : quel rangement tient face à tous les scénarios ?", "`adopter coffre`"],
    vread: () => ["Fais lire le secret au service d'export, avec sa propre identité.", "`identifier app-export` puis `obtenir secret/export`."],
    vdeny: () => ["Vérifie que le coffre refuse à ceux qui n'ont pas la politique : Léo, ou Mallory.", "`identifier leo` puis `obtenir secret/signature`."],
    vlog: () => ["Qu'est-ce que le coffre a retenu de tout cela ?", "`journal` (dans la salle du coffre)"],
    old: () => ["Au guichet des clés : mesure ce que Mallory aurait pu faire avec la vieille clé de Léo.", "`aller ouest` (depuis l'atelier), `simuler vol ancienne`."],
    token: () => ["Le service d'export a besoin de lire un seul bucket, pendant son job de 10 minutes. Émets-lui exactement cela.", "`emettre jeton lecture exports 15 min`"],
    steal: () => ["Rejoue le vol : que peut faire Mallory de ton jeton, 3 heures plus tard ?", "`simuler vol`"],
    audit: () => ["Bob t'attend au cabinet (sud de l'atelier). Regarde d'abord comment il gère ses mots de passe.", "`aller sud`, `parler bob`, `auditer`."],
    master: () => ["Un gestionnaire n'a besoin que d'un seul secret mémorisé : une phrase de passe maître, longue et inédite (au moins 4 mots, 20 caractères).", "`definir maitre cheval agrafe lampadaire sentier nuage`"],
    kfound: () => ["Le mot de passe de Bob a-t-il déjà fuité ? Demande au Registre sans lui donner le mot de passe : empreinte locale, puis seulement le préfixe.", "`hacher soleil2020`, puis `interroger ‹les 5 premiers caractères›`, puis `comparer soleil2020`."],
    gen: () => ["Remplace chaque mot de passe faible ou réutilisé par un mot de passe aléatoire unique.", "`generer tout`"],
    kclean: () => ["Vérifie qu'un des nouveaux mots de passe n'est pas dans les fuites, sans le révéler : `@site` désigne le mot de passe du trousseau.", "`hacher @wiki`, `interroger ‹préfixe›`, `comparer @wiki`."],
    rules: () => ["Va à la tour de veille (est du cabinet) : Ève a vu quelque chose dans le journal de la nuit. Règle les alertes pour détecter l'intrusion sans faux positif.", "`aller est`, `journal`, `desactiver alerte horaires`, `activer alerte ip`, `surveiller`."],
    rotate: () => ["L'identité du service est compromise. Fais tourner ses secrets.", "`tourner export`"],
    plan: () => ["Planifie une rotation régulière : 90 jours ou moins.", "`planifier rotation 30`"],
    end: () => ["Rends compte à Maître Ada.", "Retourne à l'atelier, puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Ce matin, une alerte : le dépôt `export-clients` est resté public par erreur pendant trois heures. Il contenait une clé d'API de la Guilde, poussée par Léo. Il me jure l'avoir supprimée…");
          say("Léo", "Je l'ai retirée du code ! Le fichier n'existe plus !");
          say("Maître Ada", "Les robots de Mallory ne dorment jamais. Ton audit : retrouver tout ce qui a fuité, y compris les vieux commits, réagir dans le bon ordre, puis mettre en place une vraie gestion des secrets : où les ranger, quels jetons émettre, quel gestionnaire de mots de passe, quelle surveillance. Tout est simulé sur des données fictives, mais la logique est celle des vrais outils.");
          note("types"); out("Commence par le dépôt : `aller nord`, puis `journal`.", "sys");
        } else if (x.end) say("Maître Ada", "La Guilde dort mieux. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", hints[objective()]()[0]);
        break;
      case "leo":
        if (!x.found1) say("Léo", "Je voulais juste tester le stockage. Après j'ai supprimé config.py : tu vois bien que c'est réglé, non ?");
        else if (!x.s1) say("Léo", "Attends… supprimer le fichier n'efface pas les anciens commits ? Ah. Et j'avais créé cette clé en administrateur…");
        else say("Léo", "Maintenant, je ne mets plus rien de sensible dans le code. Et je sais pourquoi : l'historique se souvient.");
        break;
      case "mallory":
        if (!x.found1) say("Mallory", "Je ne fais que lire ce qui est public. Je lis le dépôt du premier au dernier commit, moi : toi aussi, tu devrais.");
        else if (!x.s1) say("Mallory", "Tu as trouvé ? Alors dépêche-toi : tant que ma clé ouvre quelque chose, peu importe ce que tu fais de l'historique. C'est la clé qui compte, pas le fichier.");
        else say("Mallory", "Une clé morte ne me sert à rien. Les prochains qui perdent un secret ne seront pas aussi réactifs.");
        break;
      case "alice":
        if (!x.s1) { say("Alice", "Je m'occupe du coffre, mais d'abord, colmate la fuite : révoque, puis nettoie. Après, on parlera rangement."); break; }
        if (!x.vault) {
          say("Alice", "Voilà le problème : où l'appli de Léo doit-elle lire ses secrets ? Trois idées traînent sur la table : un fichier .env, des variables d'environnement, ou le coffre. Teste-les contre cinq scénarios d'incident : `tester code`, `tester dotenv`, `tester env`, `tester coffre`. Puis `adopter ‹option›`.");
        } else if (!x.s2) say("Alice", "Le coffre est adopté. Vérifie qu'il fait son travail : identifie-toi (`identifier app-export`), demande un secret (`obtenir secret/export`), essaie avec une identité qui n'a pas le droit, puis lis le `journal`.");
        else say("Alice", "Le coffre tourne. Prochaine étape : les jetons, au guichet des clés.");
        break;
      case "bob":
        if (!x.s3) say("Bob", "Je n'en ai pas pour longtemps : tu as fini avec les jetons ? Reviens me voir ensuite, j'ai un carnet à te montrer.");
        else if (!x.audited) say("Bob", "Mes mots de passe ? Je n'en utilise que quelques-uns, je les connais par cœur ! `soleil2020` sur presque tout, ça ne craint rien, non ? Fais `auditer` pour voir.");
        else if (!x.s4) say("Bob", "Je n'aime pas les gestionnaires : un seul mot de passe pour tout, c'est un point de défaillance, non ? Sauf que celui-là, personne ne le voit jamais, et tout le reste devient aléatoire.");
        else say("Bob", "Je ne retiens plus qu'une phrase. Je dors beaucoup mieux.");
        break;
      case "eve":
        if (!x.s4) say("Ève", "Je lis les journaux. Reviens quand le cabinet de Bob sera en ordre.");
        else if (!x.tuned) say("Ève", "Cette nuit, il s'est passé quelque chose que le journal montre. Mais mes règles d'alerte ne sont pas bien réglées. `journal` pour lire, `activer alerte ‹horaires|ip|volume|refus›` et `desactiver alerte ‹…›` pour régler, `surveiller` pour tester.");
        else if (!x.rotated) say("Ève", "Quelqu'un utilise l'identité du service d'export depuis une adresse inconnue. L'identité est compromise : fais tourner ses secrets. `tourner export`.");
        else if (!x.plan) say("Ève", "Et pour l'avenir : une rotation régulière, avant qu'on ait besoin de s'en apercevoir. `planifier rotation ‹jours›`.");
        else say("Ève", "Je surveille. Rapporte à Maître Ada.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- étape 1 : détecter ---------- */
  function gitLog() {
    const x = F();
    out("Journal du dépôt export-clients (du plus récent au plus ancien) :", "sys");
    code(COMMITS.slice().reverse().map((c, i) => `${c.id}  ${c.date.padEnd(8)} ${c.who}  ${c.msg}${i === 0 ? "  (HEAD)" : ""}`).join("\n"));
    out("`afficher ‹commit›` pour voir ce qu'un commit a changé (ex. `afficher 7ab93f1`).", "sys");
    x.sawLog = true;
  }
  function showCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "depot") { out("Les commits se consultent au dépôt (nord de l'atelier).", "sys"); return; }
    if (!t) { out("Quel commit ? `afficher ‹commit›` (voir `journal`).", "err"); return; }
    const w = t.split(" ")[0];
    const cm = /^(tete|head|dernier)/.test(w) ? COMMITS[COMMITS.length - 1] : COMMITS.find(k => w.length >= 3 && k.id.startsWith(w));
    if (!cm) { out("Aucun commit ne commence par « " + w + " ». `journal` les liste.", "err"); return; }
    const L = [`commit ${cm.id}  ·  ${cm.date}  ·  ${cm.who}`, "    " + cm.msg, ""];
    cm.files.forEach(fl => {
      L.push(`${fl.n}  (${fl.s === "A" ? "nouveau fichier" : fl.s === "D" ? "fichier supprimé" : "modifié"})`);
      fl.del.forEach(l => L.push("- " + redact(l))); fl.add.forEach(l => L.push("+ " + redact(l))); L.push("");
    });
    code(L.join("\n").trim());
    x.shown = true;
    if (cm.id === "7ab93f1" && !x.cleaned) out("Une clé d'API en clair dans le code : voilà ce que Léo a poussé. Les trois autres constantes du fichier sont-elles des secrets ? Un détecteur doit savoir les distinguer.", "sys");
    if (cm.id === "c5d8e07" && !x.cleaned) out("Une constante de signature : certaines chaînes de ce commit ont-elles l'air aléatoires, d'autres non ? Mesure-les : `entropie ‹texte›`.", "sys");
    if (cm.id === "91fa6b3") { x.sawDel = true; out("Léo a supprimé `config.py`. Mais regarde le journal : le commit précédent contient toujours le fichier entier. Git ne perd rien : il suffit d'un `git show`.", "sys"); }
  }
  function scanCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "depot") { out("Le détecteur est au dépôt (nord de l'atelier).", "sys"); return; }
    const head = /tete|head|courant|actuel/.test(t), wm = /motif/.test(t), we = /entrop/.test(t);
    const dets = { m: wm || !we, e: we || !wm };
    out(`Analyse de ${head ? "la version actuelle (HEAD)" : "tout l'historique (6 commits)"} · détecteurs : ${[dets.m && "motifs", dets.e && "entropie ≥ " + n2(x.thr) + " bits/car. (20 car. min.)"].filter(Boolean).join(" + ")}`, "sys");
    const hits = scan(head ? "head" : "hist", dets);
    if (!hits.length) out("Aucun secret détecté.", "ok");
    else code(hits.map(h => `${h.cid}  ${h.file}\n    ${h.rule}\n    ${mask(h.v)}  (${h.v.length} car., ${n2(h.e)} bits/car.)`).join("\n"));
    const real = hits.filter(h => h.v === SK || h.v === SS), fp = hits.filter(h => h.v !== SK && h.v !== SS);
    if (fp.length) out(`Attention : ${fp.length} signalement(s) sont probablement des faux positifs (noms, identifiants, UUID) : ${fp.map(h => "« " + mask(h.v) + " »").join(", ")}. Un seuil trop bas noie les vraies alertes dans le bruit.`, "err");
    if (head) {
      x.headScan = true;
      if (!real.length) out("La version actuelle ne contient aucun secret : Léo avait raison sur ce point. Mais la clé a bel et bien fuité : le dépôt ne se résume pas à sa dernière version. `analyser historique`.", "sys");
    } else {
      if (real.some(h => h.v === SK) && !x.found1) {
        x.found1 = true;
        out("Trouvée ! La clé est dans le commit 7ab93f1, supprimé de la version actuelle par 91fa6b3, mais toujours lisible dans l'historique.", "err");
        note("historique"); fig("histo");
      }
      if (real.some(h => h.v === SS) && !x.found2) {
        x.found2 = true;
        out("Un deuxième secret, sans préfixe reconnaissable : le détecteur ne l'a repéré que par son entropie.", "err"); note("entropie");
      }
      if (x.found1 && !x.found2 && dets.e) out("Rien d'autre ? Le commit c5d8e07 (« ajout du client de signature ») ressemble pourtant à un oubli du même genre. Ouvre-le (`afficher c5d8e07`), mesure les chaînes qui semblent aléatoires (`entropie ‹texte›`) et règle `seuil ‹bits›` en dessous.", "sys");
      if (real.length === 2 && !fp.length) out("Les deux secrets sont localisés, sans faux positif. Au guichet des clés, il faut maintenant réagir.", "ok");
    }
  }
  function entropyCmd(c) {
    const s = c.rawArg.replace(/^["«']+|["»']+$/g, "").trim();
    if (!s) { out("`entropie ‹texte›` : mesure l'entropie de Shannon d'une chaîne, ex. `entropie password`.", "err"); return; }
    const e = H(s), d = new Set(s).size;
    out(`« ${mask(s)} » : ${s.length} caractères dont ${d} distincts. Entropie : **${n2(e)} bits par caractère** (plafond pour cette longueur : ${n2(Math.log2(s.length))}).`, "ok");
    out(e < 3.2 ? "Faible : un mot, un nom, un motif répétitif. Rien d'un secret aléatoire."
      : e < 4 ? "Zone grise : typique d'un identifiant lisible, d'un UUID ou d'un hexadécimal (plafond de 4 bits). Plutôt pas un secret."
        : e < 4.4 ? "Haute, mais un nom long en CamelCase peut aussi y arriver. À regarder à la main."
          : "Très haute : répartition dense et imprévisible de caractères, comme un secret généré aléatoirement.", "sys");
  }
  function thrCmd(c) {
    const x = F(), m = c.rawArg.replace(",", ".").match(/(\d+(?:\.\d+)?)/);
    if (!m) { out(`Seuil actuel : ${n2(x.thr)} bits par caractère. Pour le changer : \`seuil ‹nombre›\`, ex. \`seuil 4.4\`.`, "sys"); return; }
    const v = parseFloat(m[1]);
    if (v < 1 || v > 6.5) { out("Un seuil raisonnable se situe entre 1 et 6,5 bits par caractère.", "err"); return; }
    x.thr = v;
    const n = scan("hist", { e: true }).length;
    out(`Seuil réglé à ${n2(v)} bits. À ce niveau, la détection par entropie signalerait ${n} chaîne(s) dans l'historique. Relance \`analyser historique\` pour voir lesquelles.`, "ok");
    if (n >= 4) out("Beaucoup de signalements : les vrais secrets seront noyés parmi les faux positifs.", "sys");
  }

  /* ---------- étape 1 bis : réagir ---------- */
  function checkStep1() {
    const x = F();
    if (x.rev.cle && x.rev.sig && x.cleaned && !x.s1) {
      x.s1 = true; note("revocation"); fig("ordre", !!x.badOrder);
      say("Maître Ada", x.badOrder ? "Tout est maintenant en règle, mais dans le mauvais ordre : le temps que tu nettoies, Mallory avait déjà ce qu'elle voulait. Retiens la leçon : la révocation d'abord." : "Dans le bon ordre : on tue le secret, puis on range. Mallory peut garder ses copies, elles ne valent plus rien.");
      out("Le service d'export est à l'arrêt (clé morte) : il faut lui fournir des accès propres. Alice t'attend à la salle du coffre (`aller est` depuis l'atelier).", "sys");
    }
  }
  function revokeCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "guichet") { out("Les secrets se révoquent au guichet des clés (ouest de l'atelier).", "sys"); return; }
    const which = /sign/.test(t) ? "sig" : /cle|api|key|p443/.test(t) ? "cle" : /tout|deux/.test(t) ? "all" : null;
    if (!which) { out("Quoi révoquer ? `revoquer cle` (la clé d'API) ou `revoquer signature` (le secret de signature).", "err"); return; }
    for (const w of which === "all" ? ["cle", "sig"] : [which]) {
      if ((w === "cle" && !x.found1) || (w === "sig" && !x.found2)) { out("La console n'a aucune alerte pour cet élément : localise-le d'abord avec le détecteur du dépôt.", "err"); continue; }
      if (x.rev[w]) { out("Déjà révoqué.", "sys"); continue; }
      x.rev[w] = true;
      if (w === "cle") {
        out("Tu révoques l'ancienne clé d'API.", "ok");
        code(`${mask(SK)}   statut : RÉVOQUÉE`);
        out("Toute requête qui la présente reçoit désormais « 401 Unauthorized ». Un essai de Mallory, quelques secondes plus tard :", "sys");
        code(`03:20  GET /exports-clients/list   (${mask(SK)})  ->  401  clé révoquée`);
        if (x.badOrder) out("Trop tard pour ce qu'elle a déjà copié, mais la fuite est enfin bouchée.", "err");
        else out("Mallory garde son exemplaire de la clé, il ne vaut plus rien.", "ok");
        if (!x.appDown) { x.appDown = true; out("Conséquence normale : l'export nocturne de la Guilde utilisait cette clé, il est maintenant en panne. C'est le prix d'une révocation, et la raison de bien préparer des accès de remplacement.", "sys"); }
      } else {
        out("Tu invalides le secret de signature.", "ok");
        code("SIGNING_SECRET (Zk8vQ2…)   statut : INVALIDÉ");
        out("Les signatures calculées avec lui ne seront plus acceptées : Mallory ne peut plus fabriquer de faux exports signés.", "ok");
      }
    }
    checkStep1();
  }
  function cleanCmd() {
    const x = F();
    if (S.room !== "depot") { out("L'historique se nettoie au dépôt (nord de l'atelier).", "sys"); return; }
    if (!(x.found1 && x.found2)) { out("Tu ne sais pas encore exactement quoi retirer : localise d'abord tous les secrets avec le détecteur.", "err"); return; }
    if (x.cleaned) { out("L'historique est déjà nettoyé.", "sys"); return; }
    const live = [!x.rev.cle && "cle", !x.rev.sig && "sig"].filter(Boolean);
    x.cleaned = true;
    out("Tu lances la réécriture de l'historique (en vrai : git filter-repo ou BFG, puis un push forcé). Les commits 7ab93f1 et c5d8e07 sont réécrits sans les valeurs ; tous les identifiants de commits suivants changent.", "sys");
    if (live.length) {
      x.badOrder = true;
      out("L'opération dure 40 minutes, pendant lesquelles les secrets sont toujours valides. Le journal de la console :", "err");
      if (live.includes("cle")) code(`03:14  ${mask(SK)}  GET /exports-clients/list         200\n03:14  ${mask(SK)}  GET /exports-clients/2026-03.csv  200  (14 Mo)\n03:15  ${mask(SK)}  GET /exports-clients/2026-02.csv  200  (13 Mo)\n...    12 400 lignes de clients copiées`);
      if (live.includes("sig")) code("03:31  signature valide  POST /exports/verify   12 faux exports acceptés");
      out("Réécrire l'historique n'a rien repris : Mallory avait déjà cloné le dépôt (comme n'importe quel robot), et le secret restait valide pendant toute l'opération. Même après un push forcé, les clones, les forks et parfois les caches de l'hébergeur gardent les anciens commits. Seule la révocation aurait tout neutralisé. Il reste à la faire maintenant : `revoquer cle`, `revoquer signature` au guichet.", "err");
    } else out("Les secrets étaient déjà morts : cette réécriture n'est que de l'hygiène (éviter que les détecteurs et les curieux retombent dessus). Les forks et clones existants doivent être re-clonés. `analyser historique` ne trouve maintenant plus rien.", "ok");
    checkStep1();
  }

  /* ---------- étape 2 : où ranger les secrets ---------- */
  const SYM = ["✘", "~", "✔"];
  function testCmd(c) {
    const x = F();
    if (S.room !== "coffre") { out("Les rangements se comparent à la salle du coffre (est de l'atelier).", "sys"); return; }
    const o = optOf(c.rawArg);
    if (!o) { out("Quelle option ? `tester code`, `tester dotenv`, `tester env` ou `tester coffre`.", "err"); return; }
    out(`Option : **${OPTS[o]}**. Cinq incidents simulés :`, "sys");
    const lv = [0, 0, 0];
    code(SCEN.map(([, title, r]) => { lv[r[o][0]]++; return `${SYM[r[o][0]]} ${title}\n    ${r[o][1]}`; }).join("\n"));
    out(`Bilan : ${lv[2]} tenu(s), ${lv[1]} partiel(s), ${lv[0]} échec(s).`, lv[0] ? "err" : "ok");
    x.tested[o] = true;
    if (Object.keys(x.tested).length >= 3 && !x.vault) out("Tu as de quoi te décider : `adopter ‹option›`.", "sys");
  }
  function adoptCmd(c) {
    const x = F();
    if (S.room !== "coffre") { out("L'adoption se décide à la salle du coffre (est de l'atelier).", "sys"); return; }
    const o = optOf(c.rawArg);
    if (!o) { out("Adopter quoi ? `adopter code|dotenv|env|coffre`.", "err"); return; }
    if (!x.s1) { say("Alice", "D'abord la fuite : révoque et nettoie."); return; }
    if (Object.keys(x.tested).length < 3) { say("Alice", "Compare au moins trois options avec `tester` avant de choisir : c'est le but de l'exercice."); return; }
    if (x.vault) { out("Le coffre est déjà adopté.", "sys"); return; }
    if (o === "code") say("Alice", "Non. C'est exactement ce qu'on vient de passer la matinée à réparer.");
    else if (o === "dotenv" || o === "env") say("Alice", `Mieux que le code : le dépôt n'est plus en cause. Mais regarde ton tableau : ni audit, ni rotation sans redéploiement, ni protection si le processus ou le disque est atteint. ${o === "dotenv" ? "Un .env oublié par un « git add . » refait la même fuite." : "Les variables d'environnement se lisent dans /proc et sont héritées par tous les processus enfants."} Pour une équipe, ce n'est qu'un palier. Une autre option ?`);
    else {
      x.vault = true; fig("stockage");
      say("Alice", "Le coffre. Le secret n'est plus dans le code ni sur le disque : l'application s'authentifie auprès du coffre, qui lui remet seulement ce que sa politique autorise, pour 15 minutes, et note tout. Le service d'export a son rôle `app-export`. Essaie-le : `identifier app-export`, `obtenir secret/export`.");
    }
  }
  function checkStep2() {
    const x = F();
    if (x.vault && x.vRead && x.vDeny && x.vLog && !x.s2) {
      x.s2 = true; note("coffre");
      say("Alice", "Voilà : le rôle du service passe, les autres sont refusés, et tout est dans le journal. Prochaine étape : un nouveau jeton pour le service d'export, au guichet des clés (`aller ouest` depuis l'atelier). Mais cette fois, avec une portée et une durée raisonnables.");
    }
  }
  const clock = n => `${String(14 + Math.floor(n / 60)).padStart(2, "0")}:${String(n % 60).padStart(2, "0")}`;
  function identCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "coffre") { out("Le coffre est à la salle du coffre (est de l'atelier).", "sys"); return; }
    if (!x.vault) { say("Alice", "Le coffre n'est pas encore en service : `tester` et `adopter coffre` d'abord."); return; }
    const who = /mallory/.test(t) ? "mallory" : /app|export|service/.test(t) ? "app-export" : /leo|dev/.test(t) ? "leo" : null;
    if (!who) { out("Qui ? `identifier leo`, `identifier app-export` ou `identifier mallory`.", "err"); return; }
    x.id = who;
    out(who === "app-export" ? "Tu te présentes au coffre comme **app-export**, le service d'export. Son identité est prouvée par la plateforme qui l'exécute, pas par un mot de passe écrit quelque part."
      : who === "leo" ? "Tu te présentes comme **leo**, développeur : un humain, avec un accès aux métadonnées seulement."
        : "Tu te présentes comme **mallory** : aucune politique n'est attachée à cette identité.", "ok");
  }
  function getCmd(c) {
    const x = F(), r = c.rawArg.toLowerCase();
    if (S.room !== "coffre") { out("Les secrets se demandent au coffre (salle du coffre).", "sys"); return; }
    if (!x.vault) { say("Alice", "Le coffre n'est pas encore en service."); return; }
    if (!x.id) { out("Identifie-toi d'abord : `identifier ‹leo|app-export|mallory›`.", "err"); return; }
    const m = r.match(/secret\/([a-z0-9_-]+)/) || (/export/.test(r) ? [0, "export"] : /sign/.test(r) ? [0, "signature"] : null);
    if (!m) { out("Quel chemin ? `obtenir secret/export` ou `obtenir secret/signature`.", "err"); return; }
    const path = "secret/" + m[1];
    if (!["export", "signature"].includes(m[1])) { out(`404 : « ${path} » n'existe pas. Chemins : secret/export, secret/signature.`, "err"); return; }
    x.vt += 3; const ok = x.id === "app-export";
    x.vlog.push({ t: clock(x.vt), who: x.id, op: "lecture", path, ok });
    if (ok) {
      x.vRead = true;
      code(`GET ${path}   identité : ${x.id}\n-> 200   valeur : ••••••••••••  (non affichée)\n-> bail : 15 min, renouvelable, révocable\n-> entrée ajoutée au journal d'accès`);
      out("Le service obtient son secret, pour une durée limitée, sans qu'il soit écrit nulle part sur son disque.", "ok");
    } else {
      x.vDeny = true;
      code(`GET ${path}   identité : ${x.id}\n-> 403 Forbidden   (aucune politique ne couvre ce chemin pour « ${x.id} »)\n-> tentative ajoutée au journal d'accès`);
      out(x.id === "leo" ? "Même Léo est refusé : un humain n'a pas besoin de lire les secrets de production (en cas d'urgence, une procédure « verre brisé » avec approbation existe). Le refus est journalisé." : "Refusé, et la tentative est journalisée : c'est ainsi qu'on repère un intrus.", "ok");
    }
    checkStep2();
  }
  function vaultLog() {
    const x = F();
    if (!x.vault) { out("Le coffre n'est pas encore en service : il n'y a pas de journal d'accès à lire.", "sys"); return; }
    out("Journal d'accès du coffre :", "sys");
    const all = [{ t: "13:41", who: "alice", op: "écriture", path: "secret/export", ok: true }, { t: "13:41", who: "alice", op: "écriture", path: "secret/signature", ok: true }].concat(x.vlog);
    code(all.map(e => `${e.t}  ${e.who.padEnd(11)} ${e.op.padEnd(9)} ${e.path.padEnd(17)} ${e.ok ? "ok" : "REFUSÉ"}`).join("\n"));
    out("Qui, quoi, quand, avec quel résultat : y compris les refus. Un fichier .env ou une variable d'environnement ne garde aucune trace de ce genre.", "sys");
    if (x.vRead && x.vDeny && !x.vLog) { x.vLog = true; checkStep2(); }
  }

  /* ---------- étape 3 : jetons ---------- */
  function checkStep3() {
    const x = F();
    if (x.tokGood && x.simGood && !x.s3) {
      x.s3 = true; note("moindre"); fig("jeton", x.token);
      say("Alice", "Le jeton est livré au service par le coffre, valable un quart d'heure. Même volé, il ne sert presque à rien : un bucket en lecture, déjà expiré. Mallory aurait beau chercher, il n'y a plus de clé éternelle à ramasser.");
      out("Bob t'attend au cabinet des mots de passe (au sud de l'atelier).", "sys");
    }
  }
  function simCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "guichet") { out("La simulation se lance au guichet des clés (ouest de l'atelier).", "sys"); return; }
    if (/ancien|vieille|cle|admin|leo/.test(t)) {
      out("Reconstitution (environnement de test, comme avant la révocation) : Mallory présente l'ancienne clé de Léo, trois heures après sa fuite.", "sys");
      code(theft({ rights: "admin", res: ALLRES }).concat(["+ peut créer d'autres clés : persistance"]).join("\n"));
      out("Un seul secret volé = quatre buckets lisibles, modifiables, supprimables (sauvegardes comprises), pour toujours. La clé administrateur éternelle est le pire cas.", "err");
      x.oldSim = true; return;
    }
    if (!x.token) { out("Aucun jeton n'a encore été émis : `emettre jeton ‹droits› ‹ressource› ‹durée›`.", "sys"); return; }
    const tk = x.token;
    out(`Reconstitution : Mallory vole ton jeton (${RTXT[tk.rights]} sur ${resTxt(tk.res)}, ${dur(tk.ttl)}) dans un journal de build, et l'essaie 3 heures plus tard.`, "sys");
    if (tk.ttl <= 180) { code("GET /exports-clients/list   jeton émis il y a 3 h\n-> 401  jeton expiré"); out("Le jeton est mort : le vol ne rapporte rien.", "ok"); }
    else {
      code(theft(tk).join("\n")); out(`Le jeton est encore valide ${tk.ttl === Infinity ? "pour toujours" : "pendant " + dur(tk.ttl - 180)}. ${tk.rights === "read" && tk.res.length === 1 ? "Les dégâts sont limités à la lecture d'un seul bucket, mais une durée plus courte les supprimerait." : "Plus la portée est large, plus le vol coûte cher."}`, tk.rights === "read" && tk.res.length === 1 ? "sys" : "err");
    }
    if (x.tokGood) x.simGood = true;
    checkStep3();
  }
  function emitCmd(c) {
    const x = F();
    if (S.room !== "guichet") { out("Les jetons s'émettent au guichet des clés (ouest de l'atelier).", "sys"); return; }
    if (!x.vault) { out("Pas de jeton sans endroit sûr où le ranger : adopte d'abord le coffre (Alice, salle du coffre).", "err"); return; }
    if (!x.oldSim) { out("Avant d'émettre quoi que ce soit, regarde ce que permettait l'ancienne clé : `simuler vol ancienne`.", "sys"); return; }
    const tk = parseTok(c.rawArg);
    if (!tk.rights || !tk.res.length || tk.ttl === undefined) { out("Il me faut des droits, une ressource et une durée : `emettre jeton ‹lecture|ecriture|admin› ‹exports|paie|archives|sauvegardes|tout› ‹15 min|2 h|eternel›`.", "err"); return; }
    x.token = tk;
    const id = "p443_tok_" + sha256(c.rawArg + x.vt).slice(0, 16);
    code(`jeton     ${id}\ndroits    ${RTXT[tk.rights]}\nressource ${resTxt(tk.res)}\nexpire    ${dur(tk.ttl)}`);
    const appOK = tk.res.includes("exports") && tk.rights !== null && tk.ttl >= 10;
    out("Test de l'export nocturne (il lit le bucket exports-clients pendant 10 minutes) :", "sys");
    if (!tk.res.includes("exports")) out("Échec : « 403 » : ce jeton ne couvre pas le bucket exports-clients.", "err");
    else if (tk.ttl < 10) out(`Échec : le jeton expire au bout de ${dur(tk.ttl)}, avant la fin du job (10 min).`, "err");
    else out("Succès : l'export tourne.", "ok");
    const bad = [];
    if (tk.rights !== "read") bad.push("droits trop larges : l'export ne fait que lire, il n'a besoin ni d'écrire ni de supprimer");
    if (!(tk.res.length === 1 && tk.res[0] === "exports")) bad.push("portée trop large : il ne lui faut que le bucket exports-clients");
    if (tk.ttl > 60) bad.push(tk.ttl === Infinity ? "un jeton éternel est une clé qui attend d'être volée" : "durée trop longue : une heure suffit largement pour un job de 10 minutes");
    if (appOK && !bad.length) { x.tokGood = true; out("C'est le jeton minimal : une action, une ressource, quelques minutes. Le coffre le remet au service `app-export`. Vérifie ce que vaudrait un vol : `simuler vol`.", "ok"); }
    else { x.tokGood = false; if (bad.length) out("À resserrer : " + bad.join(" ; ") + ".", "err"); if (!appOK) out("Il doit au moins permettre le travail : reprends.", "sys"); }
  }

  /* ---------- étape 4 : mots de passe ---------- */
  const COMMON = ["correct horse battery staple", "je t aime", "mot de passe", "motdepasse", "azerty", "soleil", "port443", "123456", "qwerty", "password"];
  function auditCmd() {
    const x = F();
    if (S.room !== "cabinet") { out("L'audit des mots de passe se fait au cabinet (sud de l'atelier).", "sys"); return; }
    out("Audit des mots de passe de Bob :", "sys");
    const rows = Object.keys(x.pw).map(s => {
      const pw = x.pw[s], dup = Object.values(x.pw).filter(p => p === pw).length, v = [];
      if (dup > 1) v.push(`réutilisé ×${dup}`); if (LEAKMAP.has(sha256(pw))) v.push("connu des listes"); if (pw.length < 12) v.push("court");
      return `${s.padEnd(6)} ${String(pw.length).padStart(2)} car.  ≈${String(bitsNaive(pw)).padStart(3)} bits*  ${v.length ? v.join(", ") : "ok"}`;
    });
    code(rows.join("\n"));
    out("(* estimation naïve : longueur × log2 de l'alphabet. Elle surestime les mots de passe humains : « soleil2020 » vaut sur le papier ≈ 52 bits, et en pratique presque rien, car c'est un mot courant avec une année.)", "sys");
    const w = Object.keys(x.pw).find(s => s === "wiki");
    const same = Object.keys(x.pw).filter(s => s !== w && x.pw[s] === x.pw[w]);
    if (same.length) out(`Simulation de « credential stuffing » : le wiki (peu protégé) fuit, avec le mot de passe de Bob. Mallory l'essaie partout : **${same.join(" et ")}** tombent aussi. 1 fuite = ${same.length + 1} comptes perdus.`, "err");
    else out("Aucun mot de passe réutilisé : une fuite sur un site ne se propage plus aux autres.", "ok");
    x.audited = true; checkStep4();
  }
  function masterCmd(c) {
    const x = F();
    if (S.room !== "cabinet") { out("Le trousseau est au cabinet (sud de l'atelier).", "sys"); return; }
    const p = c.rawArg.replace(/^(maitre|master|mdp maitre|phrase maitre|phrase)\s+/i, "").trim();
    if (!p || /^(maitre|master)$/i.test(p)) { out("`definir maitre ‹phrase de passe›` : au moins 4 mots, 20 caractères.", "err"); return; }
    if (x.master) { out("La phrase maître est déjà définie.", "sys"); return; }
    const words = p.split(/\s+/), np = norm(p);
    if (words.length < 4 || p.length < 20) { say("Bob", `Trop court (${words.length} mot(s), ${p.length} caractères) : une phrase de passe maître doit être longue : au moins 4 mots et 20 caractères. C'est la seule chose que tu devras retenir.`); return; }
    if (new Set(words.map(norm)).size < words.length) { say("Bob", "Il y a des mots répétés : chaque mot doit apporter de l'imprévisible."); return; }
    if (COMMON.some(w => np.includes(w)) || Object.values(x.pw).some(q => np.includes(norm(q)))) { say("Bob", "Cette phrase contient une expression connue ou un de mes anciens mots de passe : c'est le premier endroit où un attaquant cherche. Invente quelque chose d'unique."); return; }
    x.master = true;
    let k = sha256(p); for (let i = 1; i < 3000; i++) k = sha256(k + p);
    out("Phrase maître acceptée. Le gestionnaire dérive une clé de chiffrement à partir d'elle (ici 3 000 tours de SHA-256 ; en vrai, Argon2 ou PBKDF2 avec un sel) :", "ok");
    code("clé du trousseau = " + k.slice(0, 16) + "…   (jamais stockée, jamais envoyée)");
    out(`${words.length} mots tirés au hasard dans une liste de 7 776 mots (méthode « diceware ») donneraient environ ${Math.round(words.length * 12.9)} bits : 6 mots sont recommandés. L'essentiel : longue, unique, mémorisée, et jamais réutilisée ailleurs.`, "sys");
    checkStep4();
  }
  function genCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "cabinet") { out("Le trousseau est au cabinet (sud de l'atelier).", "sys"); return; }
    if (!x.master) { say("Bob", "Où veux-tu ranger tout ça ? Sans phrase maître, le trousseau n'est pas chiffré : `definir maitre ‹phrase›` d'abord."); return; }
    const L = Math.max(8, Math.min(64, parseInt((t.match(/\d+/) || [20])[0], 10)));
    const sites = /tout|tous/.test(t) ? Object.keys(x.pw).filter(weak) : Object.keys(x.pw).filter(s => t.split(" ").includes(s));
    if (!sites.length) { out(/tout|tous/.test(t) ? "Plus rien à remplacer : tout est déjà fort et unique." : "Quel site ? `generer wiki`, `generer tout` ou `generer mail 24`. (Sites : " + Object.keys(x.pw).join(", ") + ".)", /tout|tous/.test(t) ? "ok" : "err"); return; }
    sites.forEach(s => {
      x.pw[s] = randPw(L); x.gen[s] = true;
      out(`${s} : nouveau mot de passe aléatoire de ${L} caractères (${x.pw[s].slice(0, 3)}…), ≈ ${Math.round(L * Math.log2(ALPHA.length))} bits, rangé dans le trousseau.`, "ok");
    });
    if (L < 12) out("Court : 12 caractères aléatoires au minimum.", "sys");
    if (Object.keys(x.pw).every(s => !weak(s)) && !x.genAll) { x.genAll = true; out("Plus aucun mot de passe réutilisé, court ou connu. Bob n'a rien à retenir, sauf la phrase maître.", "ok"); note("gestionnaire"); }
    checkStep4();
  }
  function pwArg(raw) {
    const x = F(), a = raw.trim();
    if (!a) { out("De quel mot de passe parles-tu ? Un texte, ou `@site` pour un mot de passe du trousseau.", "err"); return null; }
    if (a.startsWith("@")) {
      const s = norm(a.slice(1));
      if (!(s in x.pw)) { out(`Pas de site « ${s} » dans le trousseau (${Object.keys(x.pw).join(", ")}).`, "err"); return null; }
      return { pw: x.pw[s], site: s, label: `du mot de passe du site « ${s} »` };
    }
    const pw = a.replace(/^["«]|["»]$/g, "");
    return { pw, site: null, label: `de « ${pw} »` };
  }
  function hashCmd(c) {
    const x = F();
    if (S.room !== "cabinet") { out("Le calcul d'empreinte se fait au cabinet (sud de l'atelier).", "sys"); return; }
    const r = pwArg(c.rawArg); if (!r) return;
    const h = sha256(r.pw); x.lastHash = h;
    out(`Ton appareil calcule, en local, l'empreinte SHA-256 ${r.label} :`, "sys");
    code(`préfixe (5 car.)  : ${h.slice(0, 5)}\nsuffixe (59 car.) : ${h.slice(5)}`);
    out(`Seul le **préfixe** sortira de ton appareil : \`interroger ${h.slice(0, 5)}\``, "sys");
  }
  function queryCmd(c) {
    const x = F();
    let a = c.rawArg.trim().toLowerCase();
    if (S.room !== "cabinet") { out("Le Registre des fuites est au cabinet (sud de l'atelier).", "sys"); return; }
    if (!a || /^dernier/.test(a)) { if (!x.lastHash) { out("Calcule d'abord une empreinte : `hacher ‹mot de passe›`.", "err"); return; } a = x.lastHash.slice(0, 5); out(`(Préfixe de la dernière empreinte calculée : ${a}.)`, "sys"); }
    if (/^[0-9a-f]{64}$/.test(a)) { out("Tu viens d'envoyer l'empreinte COMPLÈTE : le Registre sait maintenant exactement quel mot de passe tu testes (il lui suffit de la chercher dans sa base). Plus de k-anonymité ! N'envoie que les 5 premiers caractères.", "err"); return; }
    if (!/^[0-9a-f]{5}$/.test(a)) { out("Le Registre attend exactement 5 caractères hexadécimaux : le préfixe de l'empreinte (`hacher ‹mot de passe›` te le donne).", "err"); return; }
    const list = bucket(a); x.lastQ = { pre: a, list };
    out(`Le Registre reçoit **${a}** et renvoie les ${list.length} empreintes de sa base qui commencent ainsi (suffixe : nombre de fuites) :`, "sys");
    code(list.map(e => `${e.s}:${e.n}`).join("\n"));
    out(`Ce que le serveur sait : un préfixe de 5 caractères (1 048 576 possibles) et la liste qu'il a renvoyée. Parmi ces ${list.length} candidats, il ne peut pas dire lequel est le tien. (Dans la vraie vie : plusieurs centaines par préfixe.) À toi de chercher ton suffixe : \`comparer ‹mot de passe›\`.`, "sys");
    if (!x.shownK) { x.shownK = true; fig("kanon", x.lastQ); }
  }
  function compareCmd(c) {
    const x = F();
    if (S.room !== "cabinet") { out("La comparaison se fait au cabinet (sud de l'atelier).", "sys"); return; }
    const r = pwArg(c.rawArg); if (!r) return;
    const h = sha256(r.pw), pre = h.slice(0, 5), suf = h.slice(5);
    if (!x.lastQ || x.lastQ.pre !== pre) { out(`Tu n'as pas encore interrogé le Registre avec le préfixe de cette empreinte (${pre}) : \`hacher ‹…›\` puis \`interroger ${pre}\`.`, "err"); return; }
    const hit = x.lastQ.list.find(e => e.s === suf);
    out(`Comparaison locale du suffixe avec les ${x.lastQ.list.length} réponses :`, "sys");
    if (hit) {
      x.kFound = true;
      out(`Trouvé : ce mot de passe est apparu **${hit.n.toLocaleString("fr-FR")} fois** dans des fuites. Il est dans tous les dictionnaires des attaquants : à changer partout où il sert.`, "err");
      note("kanon");
    } else {
      out("Absent de la base : ce mot de passe n'est pas connu des fuites publiques. (Absent ne veut pas dire fort : mais, aléatoire et long, il l'est.)", "ok");
      if (r.site && x.gen[r.site]) { x.kClean = true; note("kanon"); }
    }
    checkStep4();
  }
  function checkStep4() {
    const x = F();
    if (x.audited && x.master && x.kFound && x.genAll && x.kClean && !x.s4) {
      x.s4 = true;
      say("Bob", "Moi qui trouvais que `soleil2020` faisait l'affaire… En quelques minutes : mots de passe uniques, générés, rangés derrière une seule phrase. Et j'ai vérifié sans jamais révéler mon mot de passe à personne.");
      out("Ève t'attend à la tour de veille : `aller est`.", "sys");
    }
  }

  /* ---------- étape 5 : surveillance et rotation ---------- */
  function nightLog() {
    out("Journal d'accès de la nuit (secrets de la Guilde) :", "sys");
    code(NIGHT.map(e => `${e.t}  ${e.who.padEnd(15)} ${e.ip.padEnd(13)} ${(e.n > 1 ? "×" + e.n + " " : "") + e.op}${e.ok ? "" : "  REFUSÉ"}`).join("\n"));
    out("Des milliers de lignes de journaux : personne ne les lit à la main. Une règle d'alerte doit lire à notre place : `activer alerte ‹horaires|ip|volume|refus›`, puis `surveiller`.", "sys");
  }
  function ruleCmd(c) {
    const x = F(), t = norm(c.rawArg), on = !/^desactiver/.test(c.verb);
    if (S.room !== "veille") { out("Les règles d'alerte se règlent à la tour de veille (est du cabinet).", "sys"); return; }
    const k = Object.keys(RULES).find(r => t.includes(r.slice(0, 4)));
    if (!k) { out("Quelle règle ? " + Object.keys(RULES).map(r => `\`${r}\``).join(", ") + ". Ex. `activer alerte ip`.", "err"); return; }
    x.rules[k] = on;
    out(`Règle « ${k} » ${on ? "activée" : "désactivée"} : ${RULES[k][1]}.`, "ok");
  }
  function watchCmd() {
    const x = F();
    if (S.room !== "veille") { out("La surveillance est à la tour de veille (est du cabinet).", "sys"); return; }
    const act = Object.keys(RULES).filter(k => x.rules[k]);
    if (!act.length) { out("Aucune règle active : rien n'est surveillé. `activer alerte ‹horaires|ip|volume|refus›`.", "err"); return; }
    out("Règles actives : " + act.join(", ") + ". Application au journal de la nuit :", "sys");
    let tp = 0, fp = 0, miss = 0;
    const rows = NIGHT.map(e => {
      const hit = act.filter(k => RULES[k][0](e)).length > 0;
      if (hit && e.bad) tp++; else if (hit) fp++; else if (e.bad) miss++;
      return `${e.t}  ${e.who.padEnd(15)} ${e.ip.padEnd(13)} ${hit ? (e.bad ? "ALERTE  (vraie)" : "ALERTE  (fausse)") : e.bad ? "silence (RATÉE)" : "silence"}`;
    });
    code(rows.join("\n"));
    out(`${tp} vraie(s) alerte(s) sur 2, ${fp} fausse(s) alerte(s), ${miss} intrusion(s) non détectée(s).`, miss || fp ? "err" : "ok");
    if (fp) out("Les accès de 02:00 sont l'export nocturne légitime : une règle « horaires » seule les signale à tort chaque nuit. À force de fausses alertes, plus personne ne lit les alertes.", "sys");
    if (miss) out("Une intrusion passe entre les mailles : d'autres règles (adresse, refus répétés) couvrent ce que le volume seul ne voit pas.", "sys");
    if (tp === 2 && !fp) {
      if (!x.tuned) {
        x.tuned = true;
        say("Ève", "Voilà ce que j'avais vu : à 03:05, quelqu'un a testé la clé révoquée (14 refus) ; à 03:12, il s'est servi de l'identité du service d'export, depuis une adresse hors du réseau, pour lire 412 secrets en quatre minutes. Un jeton ou une identité volé sur un poste de build. Il faut faire tourner ses secrets : `tourner export`.");
      }
    }
  }
  function rotateCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "veille") { out("La rotation se déclenche depuis la tour de veille (est du cabinet).", "sys"); return; }
    if (!x.tuned) { say("Ève", "Pas encore : établis d'abord ce qui s'est passé. `surveiller` avec les bonnes règles."); return; }
    if (x.rotated) { out("Déjà fait.", "sys"); return; }
    if (!/export|signature|tout|app/.test(t)) { out("Quel secret ? `tourner export` fait tourner les secrets du service d'export.", "err"); return; }
    x.rotated = true;
    code("secret/export       v1 -> v2   (v1 reste valide 5 min : chevauchement)\nsecret/signature    v1 -> v2   (idem)\nidentité app-export : sessions et baux existants invalidés\n03:41  app-export  203.0.113.77  lecture secret/export  ->  401  session invalidée");
    out("Le service lit la version 2 à sa prochaine demande : aucun redéploiement, aucune coupure. C'est l'avantage du coffre choisi plus tôt. Les accès de Mallory, eux, échouent.", "ok");
    out("Un détail qui compte : deux versions se chevauchent brièvement. Sans ce chevauchement, une rotation coupe les services qui n'ont pas encore la nouvelle valeur.", "sys");
  }
  function planCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "veille") { out("La rotation se planifie depuis la tour de veille (est du cabinet).", "sys"); return; }
    if (!x.rotated) { say("Ève", "D'abord, traite l'incident en cours (`tourner export`)."); return; }
    if (x.plan) { out(`Déjà planifié : tous les ${x.plan} jours.`, "sys"); return; }
    if (/jamais|aucun/.test(t)) { say("Ève", "« Jamais » est exactement la politique qui nous a menés ici."); return; }
    let n = /mensuel/.test(t) ? 30 : /hebdo/.test(t) ? 7 : /annuel/.test(t) ? 365 : (t.match(/\d+/) ? parseInt(t.match(/\d+/)[0], 10) : 0);
    if (!n || n < 1) { out("Combien de jours ? `planifier rotation 30`.", "err"); return; }
    if (n > 365) { say("Ève", `${n} jours : autant dire jamais. Un secret volé sans qu'on le sache reste utile à l'attaquant pendant tout ce temps.`); return; }
    if (n > 90) { say("Ève", `${n} jours, c'est long : un secret volé en silence reste exploitable tout ce temps. Descends à 90 jours ou moins.`); return; }
    x.plan = n;
    out(`Rotation planifiée : tous les ${n} jours${n < 7 ? " (à condition qu'elle soit automatique : à la main, on l'oublie)" : ""}, avec deux versions qui se chevauchent. Et en plus, la rotation immédiate dès qu'une alerte le justifie.`, "ok");
    note("rotation"); fig("ordre", !!x.badOrder);
    say("Ève", "Rotation régulière pour borner la durée d'un vol silencieux, rotation immédiate pour réagir, alertes pour s'en apercevoir. Va rapporter à Maître Ada.");
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "La clé de Léo est morte, l'historique est propre, les secrets vivent dans un coffre qui note chaque accès, le service d'export n'a plus qu'un jeton minuscule qui expire vite, Bob a un gestionnaire, et Ève a des règles d'alerte qui crient seulement quand il faut. Mallory est repartie : il n'y a plus rien à ramasser.");
    say("Léo", "Je commence à comprendre pourquoi vous dites qu'un secret commité est un secret perdu.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le dépôt et son historique = git.** Chaque commit est une photo complète du projet ; supprimer un fichier ajoute une photo sans lui, mais les anciennes photos existent toujours (`git show`). Tout clone ou fork copie tout cet historique. Un secret commité est donc à considérer comme public.");
    out("**Le détecteur = gitleaks, trufflehog, GitHub secret scanning.** Des motifs (préfixes de clés connus) plus l'entropie de Shannon : un secret aléatoire a une répartition de caractères plus dense qu'un mot. Le seuil est un compromis entre faux négatifs et faux positifs. Les bons outils analysent aussi l'historique et peuvent bloquer un push (push protection).");
    out("**Révoquer, puis nettoyer = la règle d'or.** Un secret exposé doit être considéré comme déjà copié : on le révoque ou on le fait tourner d'abord, puis on le remplace, et seulement ensuite on réécrit l'historique (git filter-repo, BFG) en prévenant tout le monde de re-cloner. La réécriture ne reprend pas les clones, forks, caches, ni les logs de CI : seule la révocation neutralise.");
    out("**Le .env, les variables d'environnement, le coffre.** Le `.env` est en clair sur le disque (et dangereux s'il est commité) ; les variables d'environnement sont lisibles par le processus et ses enfants (via `/proc`, un crash dump, un log de debug). Un gestionnaire de secrets (Vault, AWS Secrets Manager, Azure Key Vault, etc.) ajoute : authentification de l'application, politiques fines, baux courts, journal d'audit, rotation. Il ne protège pas d'une application déjà compromise qui lit le secret pendant son bail : il en limite la durée et laisse une trace.");
    out("**Le jeton minimal = principe du moindre privilège.** Portée minimale (un bucket, en lecture) et durée courte (jetons de type OAuth, STS, URL pré-signées) : un vol devient presque inoffensif, alors qu'une clé administrateur éternelle donne tout, pour toujours.");
    out("**Le trousseau et le Registre des fuites = gestionnaire de mots de passe et Have I Been Pwned.** Un mot de passe unique par site coupe le credential stuffing ; la phrase maître dérive une clé de chiffrement par une fonction lente (Argon2, PBKDF2). Pour savoir si un mot de passe a fuité : on calcule son empreinte en local, on envoie seulement un préfixe de 5 caractères, le serveur renvoie tous les suffixes qui lui correspondent (plusieurs centaines), et on compare chez soi. C'est la k-anonymité : le serveur ne voit qu'un groupe de candidats.");
    out("**La tour de veille = surveillance des accès et rotation.** Alerter sur l'heure, l'origine, le volume et les refus répétés ; régler les règles pour éviter le bruit ; faire tourner immédiatement un secret suspect, et régulièrement les autres, avec deux versions valides en parallèle pour ne pas casser les services.");
    out("**Les simplifications du jeu.** (1) L'entropie de Shannon d'une chaîne courte n'est qu'un indice : un mot de passe humain peut avoir une haute entropie apparente et être faible, et inversement ; les vrais outils ajoutent des listes de motifs par fournisseur et vérifient parfois le secret auprès du fournisseur. (2) Le coffre simulé ignore le « secret zéro » : l'application doit prouver son identité au coffre (identité de plateforme, certificat…), ce qui est un vrai sujet. (3) Les scénarios de comparaison sont qualitatifs ; un coffre mal configuré ou un `.env` bien protégé par les droits du système peuvent changer la donne. (4) Le Registre utilise SHA-256 et peu de candidats par préfixe : Have I Been Pwned utilise SHA-1 (5 caractères hexadécimaux) et renvoie plusieurs centaines de suffixes ; la k-anonymité protège le mot de passe, pas le fait que quelqu'un fasse la vérification. (5) Les mots de passe sont tirés avec le générateur aléatoire du navigateur, comme le fait un vrai gestionnaire, mais le trousseau du jeu n'est pas réellement chiffré. (6) La détection d'anomalies se limite à quatre règles à seuil fixe, là où les vrais systèmes corrèlent beaucoup plus de signaux et gèrent la fatigue d'alerte.");
    out("Rappel utile : **un secret exposé est un secret perdu : on le révoque d'abord, on le range dans un coffre, on le limite en portée et en durée, et on le renouvelle.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    histo: cl => {
      const ids = ["e41c0d2", "7ab93f1", "c5d8e07", "91fa6b3", "2d70ae8", "f08b3c6"], lab = ["init", "config", "signer", "retire", "env", "README"];
      let b = "";
      ids.forEach((id, i) => {
        const x = 34 + i * 68, bad = (i === 1 || i === 2) && !cl;
        b += R(x - 26, 16, 52, 26, bad ? "f-bad" : "") + T(x, 33, id, "f-s") + T(x, 58, lab[i], "f-s");
        if (i < 5) b += AR(x + 26, 29, x + 42, 29);
      });
      b += T(8, 86, "Version actuelle (HEAD)", "f-b", "start") + R(8, 92, 404, 26, "f-ok") + T(16, 109, "aucun secret : config.py supprimé, lit l'environnement", "ft-ok f-s", "start");
      b += T(8, 142, "Commit 7ab93f1, toujours dans l'historique", "f-b", "start") + R(8, 148, 404, 26, cl ? "f-ok" : "f-bad") +
        T(16, 165, cl ? "API_KEY = [retiré]  (histoire réécrite)" : 'API_KEY = "p443_live_9fK2…sEjU"', cl ? "ft-ok f-s" : "ft-bad f-s", "start");
      b += T(210, 200, cl ? "copies déjà faites (clones, forks, caches) : non reprises" : "chaque clone du dépôt contient ces commits", "f-s");
      return { cap: cl ? "L'historique est réécrit : plus de secret dans les commits. Mais seule la révocation neutralise les copies déjà faites." : "Supprimer config.py retire la clé de la version actuelle, pas des commits précédents : l'historique la contient toujours.", svg: SVG(214, "Historique de commits et fuite", b) };
    },
    ordre: bad => {
      let b = T(106, 16, "Bonne réaction", "f-b ft-ok") + T(314, 16, "Mauvaise réaction", "f-b ft-bad");
      const L = [["1. Révoquer la clé", "la clé meurt immédiatement"], ["2. Remplacer", "nouvelle clé, portée minimale"], ["3. Nettoyer + enquêter", "historique, journaux, copies"]];
      const Rr = [["1. Nettoyer d'abord", "(la clé reste valide)"], ["2. Mallory a copié", "avec la clé encore valide"], ["3. Révocation trop tard", "les données sont déjà parties"]];
      L.forEach((t, i) => { b += R(8, 26 + i * 52, 196, 38, "f-ok") + T(106, 42 + i * 52, t[0], "f-b") + T(106, 57 + i * 52, t[1], "f-s"); if (i < 2) b += AR(106, 64 + i * 52, 106, 78 + i * 52); });
      Rr.forEach((t, i) => { b += R(216, 26 + i * 52, 196, 38, "f-bad") + T(314, 42 + i * 52, t[0], "f-b") + T(314, 57 + i * 52, t[1], "f-s"); if (i < 2) b += AR(314, 64 + i * 52, 314, 78 + i * 52, "f-bad"); });
      b += T(210, 194, bad === undefined ? "L'ordre compte : révoquer d'abord" : bad ? "Ton parcours : nettoyage avant révocation ✘" : "Ton parcours : révocation d'abord ✔", bad ? "ft-bad f-b" : "ft-ok f-b");
      return { cap: "Un secret exposé est déjà copié : seule sa révocation protège. Nettoyer l'historique en premier laisse la clé valide pendant toute l'opération.", svg: SVG(206, "Ordre de réaction à une fuite", b) };
    },
    stockage: () => {
      const cols = ["code", "dotenv", "env", "coffre"], cx = [230, 280, 330, 380];
      let b = "";
      cols.forEach((c, i) => { b += T(cx[i], 20, c, "f-b"); });
      SCEN.forEach((s, r) => {
        const y = 52 + r * 28;
        b += T(8, y, s[0], "f-s", "start") + LN(8, y + 10, 410, y + 10, "f-dash");
        cols.forEach((c, i) => { const lv = s[2][c][0]; b += T(cx[i], y, SYM[lv], lv === 2 ? "ft-ok f-b" : lv === 1 ? "f-b" : "ft-bad f-b"); });
      });
      b += T(210, 208, "✔ tient   ~ partiel   ✘ échoue", "f-s") + T(210, 226, "du plus exposé (code) au plus maîtrisé (coffre)", "f-s");
      return { cap: "Chaque option face aux cinq incidents du jeu : seul le coffre tient (ou limite) dans tous les cas, et lui seul laisse un journal d'accès.", svg: SVG(236, "Hiérarchie de stockage des secrets", b) };
    },
    jeton: tk => {
      const t = tk || { rights: "read", res: ["exports"], ttl: 15 }, short = ["exports", "paie", "archives", "sauvegardes"];
      let b = T(8, 16, "Ancienne clé : admin, éternelle", "f-b", "start");
      short.forEach((s, i) => { b += R(8 + i * 103, 24, 97, 26, "f-bad") + T(56 + i * 103, 41, s, "f-s ft-bad"); });
      b += T(8, 84, `Jeton : ${RTXT[t.rights]}, ${dur(t.ttl)}`, "f-b", "start");
      short.forEach((s, i) => {
        const has = t.res.includes(s);
        b += R(8 + i * 103, 92, 97, 26, has ? (t.rights === "read" ? "f-ok" : "f-bad") : "") + T(56 + i * 103, 109, s, has ? (t.rights === "read" ? "f-s ft-ok" : "f-s ft-bad") : "f-s");
      });
      b += T(8, 148, "Si Mallory le vole 3 h plus tard :", "f-s", "start") +
        T(8, 166, "clé éternelle : 4 buckets lisibles, modifiables, supprimables", "ft-bad f-s", "start") +
        T(8, 184, t.ttl <= 180 ? "jeton : expiré, 401, rien à voler" : "jeton : encore valide, portée ci-dessus", t.ttl <= 180 ? "ft-ok f-s" : "ft-bad f-s", "start");
      return { cap: "Moindre privilège : le jeton du service n'ouvre qu'un bucket en lecture et expire vite. La clé administrateur éternelle ouvrait tout, pour toujours.", svg: SVG(196, "Jeton minimal contre clé administrateur", b) };
    },
    kanon: a => {
      const pre = a && a.pre ? a.pre : "a3f9c";
      const b = R(8, 24, 150, 96) + T(83, 42, "ton appareil", "f-b") + T(83, 62, "mot de passe", "f-s") + T(83, 78, "SHA-256 en local", "f-s") + T(83, 100, pre + "|0b7e…", "f-s ft-pub") +
        R(262, 24, 150, 96, "f-bad") + T(337, 42, "registre fuites", "f-b") + T(337, 62, "ne voit que", "f-s") + T(337, 78, pre, "f-b ft-bad") + T(337, 100, "ne sait pas lequel", "f-s") +
        AR(158, 54, 262, 54, "f-pub") + T(210, 47, "préfixe", "f-s") + AR(262, 100, 158, 100, "f-pub") + T(210, 93, "suffixes", "f-s") +
        T(210, 146, "comparaison du suffixe : chez toi, pas chez le serveur", "f-s") +
        T(210, 168, "5 caractères hexa : 1 048 576 groupes possibles", "f-s") +
        T(210, 190, "ni mot de passe ni empreinte complète envoyés", "f-s");
      return { cap: "k-anonymité : seul le préfixe de l'empreinte quitte ton appareil ; le serveur renvoie tout le groupe de suffixes correspondants, et tu cherches le tien localement.", svg: SVG(204, "k-anonymité d'une vérification de fuite", b) };
    },
  };

  GAMES.secrets = {
    id: "secrets", order: 14, title: "Le Coffre aux Secrets", pageTitle: "Secrets Quest", subtitle: "aventure textuelle · gestion des secrets",
    blurb: "Une clé d'API a fuité dans le dépôt : retrouve-la dans l'historique, réagis dans le bon ordre, puis range, limite et surveille les secrets.",
    concept: "Gestion des secrets, gestionnaires de mots de passe",
    start: "atelier", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    refig(name) { const x = F(); fig(name, name === "histo" ? !!x.cleaned : name === "ordre" ? (x.s1 ? !!x.badOrder : undefined) : name === "jeton" ? x.token || null : name === "kanon" ? x.lastQ || null : undefined); },
    figAlias: { histo: ["historique", "commits", "fuite", "git"], ordre: ["reaction", "revocation", "ordre"], stockage: ["rangement", "coffre", "secrets"], jeton: ["jetons", "privilege", "portee"], kanon: ["anonymat", "fuites", "hibp", "k"] },
    help: "Spécifiques : `journal` · `afficher ‹commit›` · `analyser tete|historique` · `entropie ‹texte›` · `seuil ‹bits›` · `revoquer cle|signature` · `nettoyer historique` · `tester ‹option›` · `adopter ‹option›` · `identifier ‹nom›` · `obtenir secret/‹nom›` · `simuler vol [ancienne]` · `emettre jeton ‹droits› ‹ressource› ‹durée›` · `auditer` · `definir maitre ‹phrase›` · `generer ‹site|tout›` · `hacher ‹mdp ou @site›` · `interroger ‹préfixe›` · `comparer ‹mdp ou @site›` · `activer|desactiver alerte ‹règle›` · `surveiller` · `tourner export` · `planifier rotation ‹jours›`",
    verbs: {
      journal: { words: ["journal", "log"], run: () => { switch (S.room) { case "depot": gitLog(); break; case "coffre": vaultLog(); break; case "veille": nightLog(); break; default: out("Il y a un journal au dépôt (commits), à la salle du coffre (accès) et à la tour de veille (alertes).", "sys"); } } },
      show: { words: ["afficher", "show"], run: showCmd },
      scan: { words: ["analyser", "scanner", "analyse"], run: scanCmd },
      entropy: { words: ["entropie", "mesurer"], run: entropyCmd },
      thr: { words: ["seuil"], run: thrCmd },
      revoke: { words: ["revoquer", "invalider"], run: revokeCmd },
      clean: { words: ["nettoyer", "purger", "reecrire"], run: cleanCmd },
      test: { words: ["tester", "comparer options"], run: testCmd },
      adopt: { words: ["adopter", "choisir"], run: adoptCmd },
      ident: { words: ["identifier", "se connecter", "connecter"], run: identCmd },
      get: { words: ["obtenir", "demander", "retirer"], run: getCmd },
      sim: { words: ["simuler", "voler"], run: simCmd },
      emit: { words: ["emettre", "delivrer"], run: emitCmd },
      audit: { words: ["auditer", "audit"], run: auditCmd },
      master: { words: ["definir", "fixer"], run: masterCmd },
      gen: { words: ["generer", "tirer"], run: genCmd },
      hash: { words: ["hacher", "empreinte"], run: hashCmd },
      query: { words: ["interroger", "envoyer"], run: queryCmd },
      cmp: { words: ["comparer"], run: compareCmd },
      rule: { words: ["activer", "desactiver"], run: ruleCmd },
      watch: { words: ["surveiller", "detecter"], run: watchCmd },
      rotate: { words: ["tourner", "renouveler"], run: rotateCmd },
      plan: { words: ["planifier", "programmer"], run: planCmd },
    },
    intro() {
      out("Le Coffre aux Secrets", "title");
      out("Un matin, à Port-443 : une alerte. Le dépôt de code `export-clients` de la Guilde est resté public par erreur pendant trois heures, et il contenait une clé d'API que Léo, un développeur, avait poussée « juste pour tester ». Il l'a supprimée depuis, jure-t-il. Mallory, elle, n'a pas besoin qu'on lui prête quoi que ce soit : ses robots lisent tout ce qui est public.\nMaître Ada t'engage pour retrouver ce qui a fuité, réagir dans le bon ordre, puis installer une vraie gestion des secrets. Tout est simulé sur des données fictives.", "");
    },
  };
})();
