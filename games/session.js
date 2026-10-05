"use strict";
/* Les Tickets de Port-443 : cycle de vie d'une session (identifiants, fixation, cookies, expiration, révocation, modèles, liaison). */
(function () {
  const F = () => f();
  const HOST = "banque.port443", SUB = "blog.banque.port443", DAY = 86400;
  const ALICE = { agent: "Firefox/131 (Linux)", ip: "82.64.10.5" };
  const ALICE4G = { agent: ALICE.agent, ip: "82.64.200.9" };
  const MAL = { agent: "curl/8.5", ip: "203.0.113.77" };
  const MALSP = { agent: ALICE.agent, ip: MAL.ip };
  const KEY = "cle-secrete-du-serveur-port443";

  /* ---------- Outils : durées, aléa à graine, HMAC réel (sha256 du moteur) ---------- */
  const UNITS = { s: 1, sec: 1, seconde: 1, secondes: 1, min: 60, minute: 60, minutes: 60, h: 3600, heure: 3600, heures: 3600, j: DAY, jour: DAY, jours: DAY };
  function durs(txt) {
    const t = norm(txt), re = /(\d+)\s*([a-z]+)/g, r = []; let m;
    while ((m = re.exec(t))) { const u = UNITS[m[2]]; if (!u) return null; r.push(parseInt(m[1], 10) * u); }
    return r.length ? r : null;
  }
  function fmtDur(s) {
    if (s < 60) return s + " s";
    if (s < 3600) return Math.round(s / 60) + " min";
    if (s < DAY) { const h = Math.floor(s / 3600), m = Math.round((s % 3600) / 60); return h + " h" + (m ? " " + m + " min" : ""); }
    const j = Math.floor(s / DAY), h = Math.round((s % DAY) / 3600); return j + " j" + (h ? " " + h + " h" : "");
  }
  function fmtYears(sec) {
    if (sec < 1) return "moins d'une seconde";
    if (sec < 120) return Math.round(sec) + " secondes";
    if (sec < 7200) return Math.round(sec / 60) + " minutes";
    if (sec < 2 * DAY) return Math.round(sec / 3600) + " heures";
    const y = sec / 31557600;
    if (y < 1000) return Math.round(sec / DAY) < 700 ? Math.round(sec / DAY) + " jours" : y.toFixed(1) + " ans";
    const [m, e] = y.toExponential(1).split("e"); return m + " × 10^" + parseInt(e, 10) + " ans";
  }
  const stamp = t => new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC";
  function rnd32() {
    const x = F(); x.rs = (x.rs + 0x6D2B79F5) | 0; let t = x.rs;
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return (t ^ (t >>> 14)) >>> 0;
  }
  const hex8 = n => n.toString(16).padStart(8, "0");
  const rand128 = () => hex8(rnd32()) + hex8(rnd32()) + hex8(rnd32()) + hex8(rnd32());
  const hexBytes = h => { const r = []; for (let i = 0; i < h.length; i += 2) r.push(parseInt(h.substr(i, 2), 16)); return r; };
  // le sha256 du moteur ne lit que du texte : on lui prête, un instant, un TextEncoder qui renvoie ces octets
  function shaBytes(bytes) {
    const TE = window.TextEncoder;
    window.TextEncoder = function () { this.encode = () => Uint8Array.from(bytes); };
    try { return hexBytes(sha256("")); } finally { window.TextEncoder = TE; }
  }
  function hmacBytes(key, msg) {
    let k = key.slice(); if (k.length > 64) k = shaBytes(k);
    while (k.length < 64) k.push(0);
    return shaBytes(k.map(b => b ^ 0x5c).concat(shaBytes(k.map(b => b ^ 0x36).concat(msg))));
  }
  const strBytes = s => Array.from(new TextEncoder().encode(s));
  const hmacHex = (key, msg) => hmacBytes(strBytes(key), strBytes(msg)).map(b => b.toString(16).padStart(2, "0")).join("");
  const bytesB64u = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const net = ip => ip.split(".").slice(0, 2).join(".");
  const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
  const yes = s => /^(oui|o|true|on|1|yes|actif)$/.test(s);
  const no = s => /^(non|n|false|off|0|no|aucun)$/.test(s);

  /* ---------- Serveur de sessions simulé ---------- */
  function newId(user) {
    const x = F(), g = x.cfg.gen;
    if (g === "counter") return String(4000 + (x.cnt++));
    if (g === "time") { while (x.srv[String(x.clock)]) x.clock++; return String(x.clock); }
    if (g === "hash") return sha256(user).slice(0, 16);
    return rand128();
  }
  function anon(req) {
    const x = F(), id = newId("anon");
    x.srv[id] = { id, user: null, auth: false, created: x.clock, last: x.clock, agent: req.agent, ip: req.ip, lastIp: req.ip, lastAgent: req.agent, dev: "anonyme", fam: 0 };
    return x.srv[id];
  }
  // un client présente éventuellement un ticket (o.sid) avant de se connecter : fixation si on le conserve
  function login(user, req, o) {
    o = o || {}; const x = F();
    let s = o.sid && x.srv[o.sid];
    if (s && !x.cfg.regen) {
      s.user = user; s.auth = true; s.agent = req.agent; s.ip = req.ip; s.lastIp = req.ip; s.lastAgent = req.agent; s.last = x.clock; s.fixed = true;
      return s;
    }
    if (s) delete x.srv[o.sid];
    const id = newId(user);
    x.srv[id] = { id, user, auth: true, created: x.clock, last: x.clock, agent: req.agent, ip: req.ip, lastIp: req.ip, lastAgent: req.agent, dev: o.dev || "PC portable", fam: o.fam || 0 };
    return x.srv[id];
  }
  function check(id, req) {
    const x = F(), c = x.cfg, s = x.srv[id];
    if (!s) return { ok: false, why: "ticket inconnu du serveur (jamais émis, expiré ou invalidé)", kind: "inconnu" };
    if (c.abs && x.clock - s.created > c.abs) { delete x.srv[id]; return { ok: false, why: "ticket expiré : durée de vie absolue dépassée (" + fmtDur(c.abs) + ")", kind: "abs" }; }
    if (c.idle && x.clock - s.last > c.idle) { delete x.srv[id]; return { ok: false, why: "ticket expiré : inactif depuis plus de " + fmtDur(c.idle), kind: "idle" }; }
    if (c.bind !== "none" && s.auth) {
      if (req.agent !== s.agent) return { ok: false, why: "l'agent utilisateur diffère de celui de la connexion : ticket refusé et alerte levée", kind: "agent" };
      if (c.bind === "agentip" && req.ip !== s.ip) return { ok: false, why: "l'adresse diffère de celle de la connexion : ticket refusé", kind: "ip" };
      if (c.bind === "risque" && net(req.ip) !== net(s.ip)) return { ok: false, why: "réseau inhabituel : le serveur demande le mot de passe avant d'accepter ce ticket (ré-authentification)", kind: "stepup" };
    }
    s.last = x.clock; s.lastIp = req.ip; s.lastAgent = req.agent;
    return { ok: true, s };
  }
  const aliceSessions = () => Object.values(F().srv).filter(s => s.user === "alice" && s.auth);
  function purgeAlice() { const x = F(); aliceSessions().forEach(s => delete x.srv[s.id]); }
  function freshAlice(dev) { purgeAlice(); return login("alice", ALICE, { dev: dev || "PC portable" }); }
  function aliceNow() { const l = aliceSessions().filter(s => check(s.id, ALICE).ok); return l.length ? l[0] : freshAlice(); }
  function hijack(id, req, label) {
    const r = check(id, req);
    if (r.ok && r.s.auth) { out(label + " : le serveur répond **200 OK**. Mallory est connectée sous le compte « " + r.s.user + " » : solde, virements, adresse de livraison, tout est à elle.", "err"); return true; }
    out(label + " : **refusé**. " + (r.why || "ticket sans compte attaché") + ".", "ok"); return false;
  }
  // succès = l'attaque réussit ; retourne "hit" (1re réussite), "blk" (1er échec après réussite), "no"
  function res(k, succ) {
    const x = F();
    if (succ) { x.hit[k] = true; return "hit"; }
    if (!x.blk[k]) { x.hit[k] = true; x.blk[k] = true; return "blk"; }
    return "no";
  }
  const setCookieLine = val => { const c = F().ck; return "Set-Cookie: " + c.name + "=" + val + "; Path=" + c.path + (c.domain ? "; Domain=" + c.domain : "") + (c.secure ? "; Secure" : "") + (c.httpOnly ? "; HttpOnly" : "") + "; SameSite=" + cap(c.sameSite); };
  function validCookie(c) {
    const e = [];
    if (c.sameSite === "none" && !c.secure) e.push("SameSite=None exige l'attribut Secure : un navigateur récent rejette le cookie sinon");
    if (/^__Host-/.test(c.name)) {
      if (!c.secure) e.push("le préfixe __Host- exige l'attribut Secure");
      if (c.domain) e.push("le préfixe __Host- interdit l'attribut Domain (cookie lié à l'hôte exact)");
      if (c.path !== "/") e.push("le préfixe __Host- exige Path=/");
    } else if (/^__Secure-/.test(c.name) && !c.secure) e.push("le préfixe __Secure- exige l'attribut Secure");
    return e;
  }

  /* ---------- Entropie ---------- */
  const SPACES = [
    ["counter", "compteur", 50, "une cinquantaine de sessions actives voisines du ticket de Mallory"],
    ["time", "horodatage", 60, "une minute de secondes autour de sa propre connexion"],
    ["hash", "hachage d'un nom", 1000, "un dictionnaire de mille prénoms courants (le hachage se refait à l'identique)"],
    ["random", "aléa fort", Math.pow(2, 128), "128 bits tirés au hasard"],
  ];
  const bitsOf = n => Math.log2(n);
  const TRIES = 1e6; // essais par seconde supposés (chiffre pédagogique)
  const secsFor = n => n / 2 / TRIES;

  /* ---------- Carnet ---------- */
  const notes = {
    ids: ["Des identifiants imprévisibles", "Le ticket de session est un secret : qui le connaît EST l'utilisateur. Un compteur, une heure ou un hachage du nom se devinent ou se recalculent. L'identifiant doit sortir d'un générateur cryptographique (CSPRNG) et porter au moins 64 bits d'entropie réelle (128 en pratique). L'entropie se mesure : longueur × log2(taille de l'alphabet), mais seulement si chaque caractère est vraiment tiré au hasard."],
    fixation: ["La fixation de session", "L'attaquant obtient un ticket (anonyme) et l'impose à la victime (lien, cookie posé depuis un sous-domaine). Si le serveur garde le même ticket après la connexion, l'attaquant, qui le connaît déjà, devient la victime. Parade : toujours régénérer l'identifiant à chaque changement de privilège (connexion, élévation) et détruire l'ancien."],
    attributs: ["Les attributs du cookie", "HttpOnly : le JavaScript ne peut pas lire le cookie (un XSS ne l'emporte plus, mais peut encore agir depuis la page). Secure : jamais envoyé en clair sur http. SameSite=Lax/Strict : pas envoyé dans les requêtes inter-sites (CSRF). Domain absent : cookie réservé à l'hôte exact, pas à ses sous-domaines. Préfixe __Host- : le navigateur impose Secure, Path=/ et pas de Domain, et empêche un sous-domaine de poser un cookie du même nom."],
    fuite: ["La fuite par l'URL", "Un identifiant dans l'adresse se retrouve dans l'historique, les journaux du serveur et des mandataires, les liens copiés-collés, et l'en-tête Referer envoyé aux sites tiers. Le ticket ne voyage que dans un cookie. Une Referrer-Policy stricte limite en plus ce que les liens sortants révèlent."],
    expiration: ["L'expiration : inactivité et durée absolue", "Le délai d'inactivité ferme une session abandonnée. La durée absolue la ferme même si quelqu'un l'entretient en continu (un ticket volé et « pingué » ne meurt jamais avec la seule inactivité). Les deux sont décidés et vérifiés PAR LE SERVEUR : un Max-Age côté cookie n'est qu'un conseil au navigateur."],
    souvenir: ["« Se souvenir de moi »", "Ne jamais prolonger la session elle-même. On émet un jeton durable séparé (aléatoire, stocké haché côté serveur, cookie HttpOnly/Secure) qui ne peut qu'ouvrir une nouvelle session de moindre privilège. Il est rotatif : chaque usage le remplace. Si un ancien jeton est rejoué, c'est qu'il a été copié : on révoque toute la famille et on redemande le mot de passe."],
    deconnexion: ["Déconnexion et révocation", "Effacer le cookie ne détruit rien : un ticket copié reste valable. La déconnexion doit supprimer la session côté serveur. Un changement de mot de passe doit révoquer toutes les autres sessions, et l'utilisateur doit pouvoir lister ses appareils et en révoquer un. Sans cela, un vol n'est jamais « guéri »."],
    modeles: ["Opaque, signé ou JWT", "Session opaque : un identifiant aléatoire, l'état est chez le serveur ; révocation immédiate. Cookie signé / JWT : l'état est dans le jeton, protégé par une signature (HMAC) qui détecte toute falsification ; aucune base à consulter, mais pas de révocation avant l'expiration, sauf à tenir une liste noire (donc un état serveur). Le choix dépend du besoin de révoquer. La signature ne chiffre pas : le contenu se lit."],
    liaison: ["Liaison à l'appareil et anomalies", "Lier la session à l'agent utilisateur et au réseau repère certains vols. Mais ces valeurs ne sont pas secrètes (un agent se copie) et l'adresse change légitimement (4G, voyage). Une liaison stricte à l'IP déconnecte des innocents. Mieux : refuser un changement d'agent, et demander un nouveau mot de passe si le réseau change fortement. C'est une défense en plus, pas à la place des autres."],
  };

  /* ---------- Entités et lieux ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle supervise l'audit du guichet de la banque." },
    guichetiere: { npc: true, names: ["guichetiere", "guichet", "dame"], label: "la guichetière", desc: () => "La guichetière de la banque : elle remet à chaque client un ticket numéroté, et le reconnaît ensuite à ce seul ticket." },
    alice: { npc: true, names: ["alice"], label: "Alice", desc: () => "Alice, cliente de la banque, qui utilise un PC portable et un téléphone." },
    bob: { npc: true, names: ["bob", "fabricant"], label: "Bob", vis: () => S.room === "atelier", desc: () => "Bob, qui fabrique les tickets de la banque à la chaîne." },
    machine: { names: ["machine", "presse", "generateur", "fabrique"], label: "la machine à tickets", vis: () => S.room === "atelier",
      desc: () => {
        const x = F(), g = x.cfg.gen;
        const ex = g === "counter" ? ["4038", "4039", "4040"] : g === "time" ? [String(x.clock - 5), String(x.clock - 3), String(x.clock - 1)] : g === "hash" ? ["bob", "carol", "dave"].map(n => sha256(n).slice(0, 16)) : [0, 1, 2].map(i => sha256("echantillon" + i).slice(0, 32));
        return "La machine à tickets. Mode actuel : **" + GENS[g] + "**. Derniers tickets émis (exemples) :\n  " + ex.join("\n  ") + "\n`generateur compteur|horodatage|hachage|aleatoire` · `entropie` pour mesurer · `regenerer oui|non` (nouveau ticket à la connexion : " + (x.cfg.regen ? "OUI" : "non") + ").";
      } },
    pot: { names: ["pot", "pot de cookies", "cookies", "cookie", "bocal"], label: "le pot de cookies d'Alice", vis: () => S.room === "navigateur",
      desc: () => {
        const c = F().ck, x = F();
        return "Le pot de cookies du navigateur d'Alice :\n  nom       : " + c.name + "\n  HttpOnly  : " + (c.httpOnly ? "oui" : "non") + "\n  Secure    : " + (c.secure ? "oui" : "non") + "\n  SameSite  : " + cap(c.sameSite) + (x.blk.piege || c.sameSite !== "none" ? "" : "  (réglage hérité)") + "\n  Domain    : " + (c.domain || "(aucun : hôte exact)") + "\n  Path      : " + c.path + "\nTransport du ticket : " + (x.cfg.urlIds ? "cookie ET adresse (?sid=)" : "cookie seulement") + " · Referrer-Policy : " + REFS[x.cfg.referer] + ".\n`cookie httponly|secure oui|non` · `cookie samesite none|lax|strict` · `cookie domaine ‹hôte|aucun›` · `cookie chemin ‹/›` · `cookie nom ‹nom›` · `transport cookie|url` · `referer aucun|origine|complet` · `auditer`.";
      } },
    greffier: { npc: true, names: ["greffier", "clerc"], label: "le greffier du registre", vis: () => S.room === "registre", desc: () => "Le greffier tient le registre : il y note chaque ticket émis, l'heure de dernier usage et l'appareil." },
    registre: { names: ["registre", "livre"], label: "le registre des sessions", vis: () => S.room === "registre",
      desc: () => {
        const x = F(), c = x.cfg, n = Object.keys(x.srv).length;
        return "Le registre des sessions (" + n + " ticket" + (n > 1 ? "s" : "") + " actif" + (n > 1 ? "s" : "") + "). Heure du serveur : " + stamp(x.clock) + ".\n  délai d'inactivité : " + (c.idle ? fmtDur(c.idle) : "aucun") + " · durée absolue : " + (c.abs ? fmtDur(c.abs) : "aucune") + "\n  « se souvenir de moi » : " + MEMS[c.mem] + "\n  déconnexion : " + (c.logout === "serveur" ? "supprime la session côté serveur" : "efface seulement le cookie du navigateur") + "\n  changement de mot de passe : " + (c.revokeAll ? "révoque les autres sessions" : "ne révoque rien") + "\n  liaison à l'appareil : " + BINDS[c.bind] + "\n`delais ‹inactivité› ‹absolue›` (ex. delais 15min 8h) · `souvenir non|fixe|rotatif` · `deconnexion client|serveur` · `revocation oui|non` · `liaison aucune|agent|agent+ip|risque` · `appareils` · `revoquer ‹n›` · `attendre ‹durée›`.";
      } },
    tableau: { names: ["modeles", "etagere", "panneau"], label: "le panneau des trois modèles", vis: () => S.room === "modeles",
      desc: () => "Trois façons de fabriquer un ticket :\n  opaque : un identifiant aléatoire, tout est dans le registre.\n  signé : un cookie qui contient les données (utilisateur, expiration) + une signature HMAC.\n  JWT : même idée, au format standard (en-tête.données.signature), souvent à durée courte.\n`essayer opaque|signe|jwt` joue la même attaque sur chacun · `liste oui|non` (liste noire pour les jetons signés : " + (F().cfg.deny ? "OUI" : "non") + ") · `comparer` · `adopter ‹modèle›`.",
    },
    mallory: { npc: true, names: ["mallory"], label: "Mallory (jouée pour l'audit)", vis: () => S.room === "repaire", desc: () => "Mallory, l'attaquante. Dans ce bac à sable, elle est simulée par la Guilde : tout est fictif." },
    eve: { npc: true, names: ["eve"], label: "Ève", vis: () => S.room === "repaire", desc: () => "Ève écoute sur le réseau du café, sans rien modifier." },
    console: { names: ["console", "attaques", "menu"], label: "la console d'attaques simulées", vis: () => S.room === "repaire",
      desc: () => "Attaques que tu peux rejouer (`simuler ‹nom›`) :\n  deviner · fixer · xss · ecoute · piege · sous · fuite\n  rejouer (ticket volé, après un délai) · ping (maintien en vie) · souvenir · deconnexion · mdp · anomalie\nChacune se joue contre la configuration ACTUELLE du serveur et du cookie." },
  };
  const GENS = { counter: "compteur", time: "horodatage", hash: "hachage du nom", random: "aléa fort (128 bits)" };
  const REFS = { complet: "complet (ancien réglage)", origine: "origine seule", aucun: "aucun Referer" };
  const MEMS = { non: "désactivé", fixe: "jeton durable fixe (30 j)", rotatif: "jeton durable rotatif (30 j)" };
  const BINDS = { none: "aucune", agent: "agent utilisateur", agentip: "agent + adresse exacte", risque: "agent + risque réseau" };

  const rooms = {
    guichet: { name: "Le guichet de la banque", short: "Guichet", alias: ["guichet", "hall"], ents: ["ada", "guichetiere", "alice"], exits: { nord: "atelier", est: "navigateur", sud: "registre", ouest: "repaire", haut: "modeles" },
      desc: () => "Le guichet de la banque de Port-443. La guichetière remet un ticket à chaque client, et ne le reconnaît ensuite qu'à ce ticket. Au nord, l'atelier qui les fabrique ; à l'est, le pot de cookies du navigateur ; au sud, le registre ; à l'ouest, le bac à sable de Mallory ; en haut, l'étage des modèles." },
    atelier: { name: "L'atelier des tickets", short: "Atelier", alias: ["atelier", "fabrique"], ents: ["bob", "machine"], exits: { sud: "guichet" },
      desc: () => "Une presse à tickets ronronne. Comment fabrique-t-on un ticket que personne ne pourra deviner ? La machine peut numéroter, dater, hacher le nom du client ou tirer au sort." },
    navigateur: { name: "Le pot de cookies", short: "Navigateur", alias: ["navigateur", "pot", "cookies"], ents: ["pot"], exits: { ouest: "guichet" },
      desc: () => "Le navigateur d'Alice : un grand pot où chaque ticket est rangé avec ses attributs, qui disent à qui il peut être montré, quand et par quoi il peut être lu." },
    registre: { name: "Le registre des sessions", short: "Registre", alias: ["registre", "archives"], ents: ["greffier", "registre"], exits: { nord: "guichet" },
      desc: () => "Un grand livre, une pendule, une pile de tickets expirés : le serveur y note qui est connecté, depuis quand, avec quel appareil, et décide de la fin de chaque ticket." },
    modeles: { name: "L'étage des modèles", short: "Modèles", alias: ["modeles", "etage"], ents: ["tableau"], exits: { bas: "guichet" },
      desc: () => "Trois fabriques de tickets côte à côte : l'opaque, le signé et le JWT. Chacune a ses atouts et ses angles morts." },
    repaire: { name: "Le bac à sable de Mallory", short: "Bac à sable", alias: ["repaire", "bac sable", "mallory"], ents: ["mallory", "eve", "console"], exits: { est: "guichet" },
      desc: () => "Une salle d'audit isolée où la Guilde fait jouer Mallory contre le guichet, sur des données fictives. Une console permet de lancer chaque attaque contre la configuration actuelle." },
  };

  /* ---------- Objectif et indices ---------- */
  const ATT = ["xss", "ecoute", "piege", "sous"];
  const objective = () => {
    const x = F(), c = x.cfg;
    if (!x.quest) return "quest";
    if (!x.logged) return "login";
    if (!x.hit.guess) return "guess1";
    if (!x.ent) return "ent";
    if (c.gen !== "random") return "gen";
    if (!x.blk.guess) return "guess2";
    if (!x.hit.fix) return "fix1";
    if (!c.regen) return "fix2";
    if (!x.blk.fix) return "fix3";
    for (const a of ATT) { if (!x.hit[a]) return a; if (!x.blk[a]) return a + "_fix"; }
    if (!x.hit.fuite) return "fuite1";
    if (c.urlIds) return "fuite2";
    if (!x.blk.fuite) return "fuite3";
    if (!x.hit.replay) return "replay1";
    if (!c.idle && !c.abs) return "delais";
    if (!x.blk.replay) return "replay2";
    if (!x.blk.ping) return "ping";
    if (!x.hit.mem) return "mem1";
    if (c.mem !== "rotatif") return "mem2";
    if (!x.blk.mem) return "mem3";
    if (!x.hit.out) return "out1";
    if (c.logout !== "serveur") return "out2";
    if (!x.blk.out) return "out3";
    if (!x.hit.pwd) return "pwd1";
    if (!x.revoked) return "pwd2";
    if (!c.revokeAll) return "pwd3";
    if (!x.blk.pwd) return "pwd4";
    if (Object.keys(x.mdl).length < 3) return "mdl";
    if (!x.cmp) return "cmp";
    if (x.adopt !== "opaque") return "adopt";
    if (!x.hit.bind) return "bind1";
    if (!x.bindOk) return "bind2";
    if (!x.end) return "end";
    return "fin";
  };
  function nav(dest) {
    if (S.room === dest) return "";
    const d = []; let r = S.room;
    if (r !== "guichet") { d.push(Object.keys(rooms[r].exits)[0]); r = "guichet"; }
    if (dest !== "guichet") d.push(Object.keys(rooms.guichet.exits).find(k => rooms.guichet.exits[k] === dest));
    return d.map(k => "`aller " + k + "`").join(", ") + ", ";
  }
  const H = (dest, cmds) => nav(dest) + cmds.map(c => "`" + c + "`").join(", ") + ".";
  const hints = {
    quest: () => ["Maître Ada attend au guichet.", H("guichet", ["parler ada"])],
    login: () => ["Regarde comment le serveur fabrique le ticket d'Alice quand elle se connecte.", H("guichet", ["connexion"])],
    guess1: () => ["Chez Mallory, tente de deviner le ticket d'Alice avec la fabrication actuelle (un compteur).", H("repaire", ["simuler deviner"])],
    ent: () => ["Mesure l'entropie des différentes fabrications, à l'atelier.", H("atelier", ["entropie"]) + " Essaie aussi `entropie 32 16` (32 caractères hexadécimaux)."],
    gen: () => ["Change le générateur de la machine pour un tirage cryptographique.", H("atelier", ["generateur aleatoire"])],
    guess2: () => ["Rejoue la tentative de Mallory contre ce nouveau générateur.", H("repaire", ["simuler deviner"])],
    fix1: () => ["Autre attaque : Mallory impose un ticket à Alice AVANT sa connexion (fixation).", H("repaire", ["simuler fixer"])],
    fix2: () => ["Le serveur garde le même ticket avant et après la connexion. Fais-lui émettre un nouveau ticket à l'authentification.", H("atelier", ["regenerer oui"])],
    fix3: () => ["Rejoue l'attaque par fixation.", H("repaire", ["simuler fixer"])],
    xss: () => ["Un script injecté dans une page (XSS) lit les cookies d'Alice. Vois ce que Mallory récupère.", H("repaire", ["simuler xss"])],
    xss_fix: () => ["Interdis au JavaScript de lire le cookie, puis rejoue.", H("navigateur", ["cookie httponly oui"]) + " Puis " + H("repaire", ["simuler xss"])],
    ecoute: () => ["Alice suit un vieux lien en http depuis le Wi-Fi du café, Ève écoute.", H("repaire", ["simuler ecoute"])],
    ecoute_fix: () => ["Interdis l'envoi du cookie en clair, puis rejoue.", H("navigateur", ["cookie secure oui"]) + " Puis " + H("repaire", ["simuler ecoute"])],
    piege: () => ["Une page piégée envoie un formulaire à la banque depuis un autre site.", H("repaire", ["simuler piege"])],
    piege_fix: () => ["Empêche l'envoi du cookie dans les requêtes inter-sites (Lax ou Strict), puis rejoue.", H("navigateur", ["cookie samesite lax"]) + " Puis " + H("repaire", ["simuler piege"])],
    sous: () => ["Un sous-domaine mal tenu (blog.banque.port443) voit ou fixe le cookie de la banque.", H("repaire", ["simuler sous"])],
    sous_fix: () => ["Rends le cookie exclusif à l'hôte exact, puis nomme-le avec le préfixe __Host-, et rejoue.", H("navigateur", ["cookie domaine aucun", "cookie nom __Host-sid"]) + " Puis " + H("repaire", ["simuler sous"])],
    fuite1: () => ["La banque accepte aussi le ticket dans l'adresse (?sid=). Vois ce qui fuit.", H("repaire", ["simuler fuite"])],
    fuite2: () => ["Le ticket ne doit voyager que dans le cookie.", H("navigateur", ["transport cookie"]) + " (`referer origine` limite en plus ce que les liens sortants révèlent)."],
    fuite3: () => ["Rejoue l'attaque par l'adresse.", H("repaire", ["simuler fuite"])],
    replay1: () => ["Mallory a gardé le ticket volé. Laisse passer une journée puis rejoue-le.", H("registre", ["attendre 1 j"]) + " Puis " + H("repaire", ["simuler rejouer"])],
    delais: () => ["Le serveur doit expirer les tickets : une durée d'inactivité et une durée absolue.", H("registre", ["delais 15min 8h"])],
    replay2: () => ["Rejoue le vieux ticket volé.", H("repaire", ["simuler rejouer"])],
    ping: () => ["Mallory entretient un ticket volé en l'utilisant toutes les 5 minutes. Vois si l'inactivité suffit (sinon, ajoute une durée absolue).", H("repaire", ["simuler ping"]) + " Pour tester sans limite absolue : `delais 15min` à la place, puis `delais 15min 8h`."],
    mem1: () => ["Le « se souvenir de moi » actuel utilise un jeton durable fixe. Vois ce qu'il permet.", H("repaire", ["simuler souvenir"])],
    mem2: () => ["Rends le jeton rotatif : chaque usage le remplace.", H("registre", ["souvenir rotatif"])],
    mem3: () => ["Rejoue : que se passe-t-il quand un ancien jeton réapparaît ?", H("repaire", ["simuler souvenir"])],
    out1: () => ["Alice clique sur « Se déconnecter » alors que Mallory a copié son ticket.", H("repaire", ["simuler deconnexion"])],
    out2: () => ["La déconnexion doit détruire la session côté serveur.", H("registre", ["deconnexion serveur"])],
    out3: () => ["Rejoue la déconnexion.", H("repaire", ["simuler deconnexion"])],
    pwd1: () => ["Alice change son mot de passe parce qu'elle craint un vol. Mallory a copié le ticket de son PC.", H("repaire", ["simuler mdp"])],
    pwd2: () => ["Regarde les appareils connectés d'Alice et révoque celui qui est suspect (adresse ou agent inhabituels).", H("registre", ["appareils", "revoquer ‹n›"])],
    pwd3: () => ["Fais en sorte qu'un changement de mot de passe révoque toutes les autres sessions.", H("registre", ["revocation oui"])],
    pwd4: () => ["Rejoue le changement de mot de passe.", H("repaire", ["simuler mdp"])],
    mdl: () => ["À l'étage des modèles, joue la même attaque sur chacun des trois modèles.", H("modeles", ["essayer opaque", "essayer signe", "essayer jwt"])],
    cmp: () => ["Mets les trois modèles côte à côte.", H("modeles", ["comparer"])],
    adopt: () => ["Pour une banque, qui doit pouvoir révoquer immédiatement, quel modèle ?", H("modeles", ["adopter opaque"])],
    bind1: () => ["Dernier angle : un ticket volé utilisé depuis un autre appareil. Vois les trois cas.", H("repaire", ["simuler anomalie"])],
    bind2: () => ["Teste les liaisons : `liaison agent`, `liaison agent+ip`, `liaison risque`, en rejouant l'attaque à chaque fois. Cherche celle qui bloque Mallory sans punir Alice.", H("registre", ["liaison risque"]) + " Puis " + H("repaire", ["simuler anomalie"])],
    end: () => ["Rends compte à Maître Ada.", H("guichet", ["parler ada"])],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- Dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "La banque a un problème : des comptes sont visités par des inconnus, sans mot de passe volé. La guichetière donne un ticket à chaque client et ne le reconnaît qu'à ce ticket. Qui possède le ticket possède le compte.");
          say("Maître Ada", "Ton audit : comment le ticket est fabriqué, transporté et invalidé. Chaque faille se joue en simulation, contre la vraie configuration du serveur que tu règles toi-même. Commence par voir Alice se connecter : `connexion`.");
        } else if (x.end) say("Maître Ada", "Les tickets de Port-443 sont enfin dignes de confiance. Bien joué.");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas terminé. `indice` si tu bloques.");
        break;
      case "guichetiere":
        say("Guichetière", "Je donne un ticket à chaque client à son arrivée, et je le note au registre. Ensuite, à chaque requête, je regarde le ticket : je ne demande plus le mot de passe. C'est pratique… tant que personne d'autre ne détient ce ticket. Essaie `connexion` pour voir Alice en recevoir un.");
        break;
      case "alice":
        say("Alice", "Je me connecte depuis mon PC et mon téléphone, et parfois depuis le Wi-Fi du café. Je n'ai jamais donné mon ticket à personne… je ne savais même pas que j'en avais un.");
        break;
      case "bob":
        say("Bob", "Je peux numéroter les tickets (1, 2, 3…), les dater, les calculer depuis le nom du client, ou les tirer au sort. Les trois premiers sont faciles à fabriquer, donc faciles à imiter. `generateur ‹mode›` règle la machine, `entropie` mesure ce que vaut chaque mode.");
        break;
      case "greffier":
        say("Greffier", "Je note tout : l'heure de dernier usage de chaque ticket, l'appareil, l'adresse. Par défaut, un ticket ne meurt jamais… et une déconnexion n'efface que la copie d'Alice. À toi de décider quand un ticket doit mourir.");
        break;
      case "mallory":
        say("Mallory", "Je rejoue mes attaques sur ordre de la Guilde. Choisis-les dans la console : `simuler ‹nom›`.");
        break;
      case "eve":
        say("Ève", "J'écoute le réseau du café. Si ce qui passe est en clair, je lis tout. Sinon, je vois seulement du bruit chiffré.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- Commandes : fabrication ---------- */
  function need(room, msg) { if (S.room !== room) { out(msg, "sys"); return false; } return true; }
  function genCmd(c) {
    if (!need("atelier", "La machine à tickets est à l'atelier (au nord du guichet).")) return;
    const t = norm(c.rawArg), x = F();
    const m = /^(compteur|numero|counter)/.test(t) ? "counter" : /^(horodatage|heure|date|temps)/.test(t) ? "time" : /^(hachage|hash|nom)/.test(t) ? "hash" : /^(aleatoire|aleatoires|random|csprng|fort)/.test(t) ? "random" : null;
    if (!m) { out("Quel mode ? `generateur compteur` · `generateur horodatage` · `generateur hachage` · `generateur aleatoire`", "err"); return; }
    x.cfg.gen = m;
    out("La machine fabrique maintenant des tickets en mode **" + GENS[m] + "**.", "ok");
    if (m !== "random") out("(Ce mode se devine : mesure-le avec `entropie`.)", "sys");
    else out("Chaque ticket est tiré au hasard sur 128 bits. (Dans le jeu, c'est un générateur à graine fixe pour rejouer la partie ; dans la vraie vie, on utilise le CSPRNG du système.)", "sys");
  }
  function entropyCmd(c) {
    const x = F(), nums = (c.rawArg.match(/\d+/g) || []).map(Number);
    if (nums.length >= 2 && nums[0] > 0 && nums[1] > 1) {
      const b = nums[0] * Math.log2(nums[1]);
      out("Un ticket de " + nums[0] + " caractères tirés au hasard parmi " + nums[1] + " symboles : " + nums[0] + " × log2(" + nums[1] + ") = **" + b.toFixed(1) + " bits** d'entropie. Attention : ce calcul n'est valable que si chaque caractère est réellement tiré au hasard.", "ok");
      x.ent = true; return;
    }
    out("Entropie réelle contre l'attaque de Mallory (essais supposés : 1 million par seconde, en moyenne la moitié de l'espace) :", "sys");
    let t = "mode                 espace de recherche   bits    temps moyen\n";
    SPACES.forEach(s => {
      const sp = s[2] > 1e9 ? "2^128" : String(s[2]);
      t += s[1].padEnd(20) + " " + sp.padEnd(20) + " " + bitsOf(s[2]).toFixed(1).padStart(6) + "  " + fmtYears(secsFor(s[2])) + "\n";
    });
    code(t.trimEnd());
    out("Ce qui compte, c'est l'espace que l'attaquant doit réellement explorer, pas la longueur apparente du ticket. Un compteur n'a qu'environ 6 bits utiles : l'attaquant connaît son propre numéro. `entropie ‹longueur› ‹alphabet›` calcule pour un ticket de ton choix (ex. `entropie 32 16`). Recommandation : au moins 64 bits réels, 128 en pratique.", "");
    x.ent = true;
  }
  function regenCmd(c) {
    if (!need("atelier", "Ce réglage est à l'atelier (au nord du guichet).")) return;
    const t = norm(c.rawArg), x = F();
    if (yes(t)) { x.cfg.regen = true; out("Désormais, à chaque connexion, le serveur émet un NOUVEAU ticket et détruit l'ancien.", "ok"); }
    else if (no(t)) { x.cfg.regen = false; out("Le serveur garde le même ticket avant et après la connexion (réglage fragile).", "sys"); }
    else out("`regenerer oui` ou `regenerer non`", "err");
  }

  /* ---------- Commandes : navigateur ---------- */
  function cookieCmd(c) {
    if (!need("navigateur", "Le pot de cookies est dans le navigateur (à l'est du guichet).")) return;
    const x = F(), parts = c.rawArg.trim().split(/\s+/), k = norm(parts[0] || ""), v = (parts.slice(1).join(" ") || "").trim(), vn = norm(v);
    const nc = Object.assign({}, x.ck);
    if (k === "httponly" || k === "http only") { if (yes(vn)) nc.httpOnly = true; else if (no(vn)) nc.httpOnly = false; else return out("`cookie httponly oui|non`", "err"); }
    else if (k === "secure") { if (yes(vn)) nc.secure = true; else if (no(vn)) nc.secure = false; else return out("`cookie secure oui|non`", "err"); }
    else if (k === "samesite") { if (/^(none|lax|strict)$/.test(vn)) nc.sameSite = vn; else return out("`cookie samesite none|lax|strict`", "err"); }
    else if (k === "domaine" || k === "domain") {
      if (!v || no(vn) || /^(hote|host|exact)/.test(vn)) nc.domain = "";
      else if (v.toLowerCase() === HOST) nc.domain = HOST;
      else return out("Un site ne peut poser un cookie que pour son propre domaine (" + HOST + ") ou l'omettre. `cookie domaine aucun` ou `cookie domaine " + HOST + "`", "err");
    }
    else if (k === "chemin" || k === "path") { if (/^\/\S*$/.test(v)) nc.path = v; else return out("`cookie chemin /` (un chemin commence par /)", "err"); }
    else if (k === "nom" || k === "name") { if (/^[A-Za-z_][A-Za-z0-9_-]{0,30}$/.test(v)) nc.name = v; else return out("`cookie nom ‹nom›` (ex. cookie nom __Host-sid)", "err"); }
    else return out("Quel attribut ? `cookie httponly|secure oui|non` · `cookie samesite none|lax|strict` · `cookie domaine ‹hôte|aucun›` · `cookie chemin ‹/›` · `cookie nom ‹nom›`", "err");
    const before = validCookie(x.ck), e = validCookie(nc).filter(m => before.indexOf(m) < 0);
    if (e.length) {
      out("Le navigateur **rejetterait** ce cookie : " + e.join(" ; ") + ". Réglage refusé.", "err"); return;
    }
    x.ck = nc;
    code(setCookieLine("‹ticket›"));
    out("Réglage accepté.", "ok");
    if (S.figs.indexOf("cookie") < 0) fig("cookie");
  }
  function transportCmd(c) {
    if (!need("navigateur", "Ce réglage est dans le navigateur (à l'est du guichet).")) return;
    const t = norm(c.rawArg), x = F();
    if (/^cookie/.test(t)) { x.cfg.urlIds = false; out("Le serveur n'accepte et n'émet plus le ticket que dans le cookie : plus de « ?sid= » dans les adresses.", "ok"); }
    else if (/^(url|adresse|lien)/.test(t)) { x.cfg.urlIds = true; out("Le serveur accepte et émet aussi le ticket dans l'adresse (?sid=), pour les navigateurs sans cookies. Ancien réglage risqué.", "sys"); }
    else out("`transport cookie` ou `transport url`", "err");
  }
  function refererCmd(c) {
    if (!need("navigateur", "Ce réglage est dans le navigateur (à l'est du guichet).")) return;
    const t = norm(c.rawArg), x = F();
    if (/^(aucun|no|none)/.test(t)) x.cfg.referer = "aucun";
    else if (/^(origine|origin|strict)/.test(t)) x.cfg.referer = "origine";
    else if (/^(complet|full|unsafe)/.test(t)) x.cfg.referer = "complet";
    else return out("`referer aucun` · `referer origine` (strict-origin-when-cross-origin) · `referer complet` (ancien : adresse entière)", "err");
    out("Referrer-Policy : " + REFS[x.cfg.referer] + ".", "ok");
  }
  function auditCmd() {
    if (!need("navigateur", "L'audit du cookie se fait dans le navigateur (à l'est du guichet).")) return;
    const x = F(), c = x.ck;
    const L = [[c.httpOnly, "HttpOnly : le JavaScript ne lit pas le cookie"], [c.secure, "Secure : jamais envoyé en clair"], [c.sameSite !== "none", "SameSite Lax ou Strict : pas d'envoi inter-sites"], [!c.domain, "Domain absent : réservé à l'hôte exact"], [/^__Host-/.test(c.name), "Préfixe __Host- : le navigateur impose les règles"], [!x.cfg.urlIds, "Ticket jamais dans l'adresse"], [x.cfg.referer !== "complet", "Referrer-Policy stricte"]];
    out("Audit du cookie de session :", "sys");
    code(L.map(l => (l[0] ? "[ok] " : "[ ! ] ") + l[1]).join("\n"));
    out(L.every(l => l[0]) ? "Tout est en règle." : "Il reste des points à corriger : chacun correspond à une attaque que tu peux rejouer chez Mallory.", L.every(l => l[0]) ? "ok" : "sys");
  }

  /* ---------- Commandes : serveur ---------- */
  function waitCmd(c) {
    const d = durs(c.rawArg), x = F();
    if (!d) { out("Attendre combien ? `attendre 30min` · `attendre 2 h` · `attendre 1 j`", "err"); return; }
    const s = Math.min(d[0], 400 * DAY);
    x.clock += s;
    out("Le temps passe : " + fmtDur(s) + ". Il est maintenant " + stamp(x.clock) + ".", "sys");
  }
  function delaysCmd(c) {
    if (!need("registre", "Les délais se règlent au registre (au sud du guichet).")) return;
    const x = F(), t = norm(c.rawArg);
    if (/^(aucun|non|zero)/.test(t)) { x.cfg.idle = 0; x.cfg.abs = 0; out("Plus aucun délai : un ticket ne meurt jamais tout seul.", "sys"); return; }
    const d = durs(c.rawArg);
    if (!d) { out("`delais ‹inactivité› ‹absolue›`, par exemple `delais 15min 8h`. Un seul nombre règle l'inactivité seule.", "err"); return; }
    x.cfg.idle = d[0]; if (d.length > 1) x.cfg.abs = d[1];
    if (x.cfg.abs && x.cfg.idle >= x.cfg.abs) { x.cfg.idle = 0; x.cfg.abs = 0; out("L'inactivité doit être plus courte que la durée absolue. Réglage annulé.", "err"); return; }
    out("Délai d'inactivité : " + fmtDur(x.cfg.idle) + " · durée absolue : " + (x.cfg.abs ? fmtDur(x.cfg.abs) : "aucune") + ".", "ok");
  }
  function memCmd(c) {
    if (!need("registre", "Ce réglage est au registre (au sud du guichet).")) return;
    const t = norm(c.rawArg), x = F();
    if (/^(non|aucun|desactiv)/.test(t)) x.cfg.mem = "non";
    else if (/^(fixe|fix)/.test(t)) x.cfg.mem = "fixe";
    else if (/^(rotatif|rotation|tourne)/.test(t)) x.cfg.mem = "rotatif";
    else return out("`souvenir non` · `souvenir fixe` · `souvenir rotatif`", "err");
    out("« Se souvenir de moi » : " + MEMS[x.cfg.mem] + ".", "ok");
  }
  function logoutCmd(c) {
    if (!need("registre", "Ce réglage est au registre (au sud du guichet).")) return;
    const t = norm(c.rawArg), x = F();
    if (/^serveur/.test(t)) { x.cfg.logout = "serveur"; out("Le bouton « Se déconnecter » supprime désormais la session dans le registre.", "ok"); }
    else if (/^client/.test(t)) { x.cfg.logout = "client"; out("Le bouton « Se déconnecter » n'efface que le cookie du navigateur (réglage fragile).", "sys"); }
    else out("`deconnexion client` ou `deconnexion serveur`", "err");
  }
  function revokeAllCmd(c) {
    if (!need("registre", "Ce réglage est au registre (au sud du guichet).")) return;
    const t = norm(c.rawArg), x = F();
    if (yes(t)) { x.cfg.revokeAll = true; out("Changer le mot de passe révoque désormais toutes les autres sessions du compte.", "ok"); }
    else if (no(t)) { x.cfg.revokeAll = false; out("Changer le mot de passe ne touche plus aux sessions existantes.", "sys"); }
    else out("`revocation oui` ou `revocation non`", "err");
  }
  function bindCmd(c) {
    if (!need("registre", "Ce réglage est au registre (au sud du guichet).")) return;
    const t = c.rawArg.toLowerCase(), x = F();
    if (/risque|score/.test(t)) x.cfg.bind = "risque";
    else if (/agent/.test(t) && /ip|adresse|reseau/.test(t)) x.cfg.bind = "agentip";
    else if (/agent/.test(t)) x.cfg.bind = "agent";
    else if (/aucun|non|none/.test(t)) x.cfg.bind = "none";
    else return out("`liaison aucune` · `liaison agent` · `liaison agent+ip` · `liaison risque`", "err");
    out("Liaison de la session : " + BINDS[x.cfg.bind] + ".", "ok");
  }
  function devicesCmd() {
    if (!need("registre", "La liste des appareils est au registre (au sud du guichet).")) return;
    const x = F(), l = aliceSessions();
    if (!l.length) { out("Aucune session active pour Alice.", "sys"); return; }
    x.list = l.map(s => s.id);
    out("Appareils connectés au compte d'Alice :", "sys");
    code(l.map((s, i) => {
      const odd = net(s.lastIp) !== net(s.ip) || s.lastAgent !== s.agent;
      return (i + 1) + ". " + s.dev.padEnd(14) + " connecté " + stamp(s.created).slice(5) + " depuis " + s.ip + "\n   dernière activité : il y a " + fmtDur(Math.max(0, x.clock - s.last)) + ", " + s.lastIp + ", " + s.lastAgent + (odd ? "\n   ⚠ activité inhabituelle (adresse ou agent différents de la connexion)" : "");
    }).join("\n"));
    out("`revoquer ‹n›` met fin à une de ces sessions.", "sys");
  }
  function revokeCmd(c) {
    if (!need("registre", "La révocation se fait au registre (au sud du guichet).")) return;
    const x = F(), m = /\d+/.exec(c.rawArg), l = aliceSessions();
    if (!m || !l[+m[0] - 1]) { out("Quel appareil ? `appareils` donne la liste, puis `revoquer ‹n›`.", "err"); return; }
    const s = l[+m[0] - 1], odd = net(s.lastIp) !== net(s.ip) || s.lastAgent !== s.agent;
    delete x.srv[s.id];
    if (odd) { x.revoked = true; out("Session « " + s.dev + " » révoquée : l'intrus (" + s.lastIp + ", " + s.lastAgent + ") est éjecté, son ticket est mort côté serveur.", "ok"); }
    else out("Session « " + s.dev + " » révoquée. Ce n'était pas l'intrus : Alice devra se reconnecter sur cet appareil. Cherche la ligne marquée ⚠.", "sys");
  }

  /* ---------- Connexion d'Alice ---------- */
  function connectCmd() {
    if (!need("guichet", "La connexion d'Alice se joue au guichet.")) return;
    const x = F(), s = freshAlice();
    out("Alice tape son mot de passe, correct. Le serveur crée une session dans son registre et renvoie son ticket :", "sys");
    code("Session (côté serveur) : " + s.id + " → { utilisateur: alice, créée: " + stamp(s.created) + ", appareil: " + s.dev + " }\n" + setCookieLine(s.id));
    out("Dès lors, Alice n'a plus à prouver son identité : son navigateur renvoie le ticket à chaque requête (`Cookie: " + F().ck.name + "=" + s.id + "`). Le ticket EST son identité.", "");
    if (!x.logged) { x.logged = true; fig("cycle"); }
  }

  /* ---------- Attaques simulées ---------- */
  function simCmd(c) {
    if (!need("repaire", "Les attaques se lancent depuis le bac à sable de Mallory (à l'ouest du guichet).")) return;
    const t = norm(c.rawArg);
    const map = [[/^deviner|^devin/, simGuess], [/^fix/, simFix], [/^xss|^script/, simXss], [/^ecoute|^sniff|^clair/, simSniff], [/^piege|^csrf|^samesite/, simCsrf], [/^sous/, simSub], [/^fuite|^url|^referer/, simLeak], [/^rejou|^replay/, simReplay], [/^ping|^vie/, simPing], [/^souv|^remember/, simMem], [/^decon|^logout/, simLogout], [/^mdp|^mot de passe|^motdepasse/, simPwd], [/^anomal|^liaison|^appareil/, simBind]];
    const m = map.find(e => e[0].test(t));
    if (!m) { out("Quelle attaque ? `simuler deviner|fixer|xss|ecoute|piege|sous|fuite|rejouer|ping|souvenir|deconnexion|mdp|anomalie`", "err"); return; }
    m[1]();
  }

  // (1) identifiants prévisibles
  function simGuess() {
    const x = F(), g = x.cfg.gen;
    purgeAlice();
    const a = login("alice", ALICE, { dev: "PC portable" });
    x.clock += 9;
    const m = login("mallory", MAL, { dev: "curl" });
    out("Alice se connecte, puis Mallory ouvre son PROPRE compte neuf, 9 secondes plus tard. Mode des tickets : " + GENS[g] + ". Ticket d'Alice : secret. Ticket de Mallory : " + m.id + ".", "sys");
    const tries = []; let found = null, n = 0;
    if (g === "counter") { const k = parseInt(m.id, 10); for (let i = 1; i <= 50 && !found; i++) { n++; const gs = String(k - i); tries.push(gs); const r = check(gs, MAL); if (r.ok && r.s.user === "alice") found = gs; } }
    else if (g === "time") { const k = parseInt(m.id, 10); for (let i = 1; i <= 60 && !found; i++) { n++; const gs = String(k - i); tries.push(gs); const r = check(gs, MAL); if (r.ok && r.s.user === "alice") found = gs; } }
    else if (g === "hash") {
      const dict = ["admin", "root", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "alice"];
      for (const nm of dict) { if (found) break; n++; const gs = sha256(nm).slice(0, 16); tries.push(nm + " → " + gs); const r = check(gs, MAL); if (r.ok && r.s.user === "alice") found = gs; }
    } else {
      let seed = 777; const r32 = () => { seed = (seed + 0x6D2B79F5) | 0; let t = seed; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return (t ^ (t >>> 14)) >>> 0; };
      for (let i = 0; i < 20000 && !found; i++) { n++; const gs = hex8(r32()) + hex8(r32()) + hex8(r32()) + hex8(r32()); const r = x.srv[gs]; if (r && r.user === "alice") found = gs; if (i < 2) tries.push(gs); }
    }
    code("Essais de Mallory (" + n + ") :\n" + tries.slice(0, 5).join("\n") + (tries.length > 5 ? "\n… (" + (tries.length - 5) + " autres)" : ""));
    if (found) {
      out("Au bout de **" + n + " essai" + (n > 1 ? "s" : "") + "**, le ticket « " + found + " » ouvre la session d'Alice. Mallory est connectée en tant qu'alice sans avoir touché à son mot de passe.", "err");
      out(g === "hash" ? "Un hachage n'est pas un secret : on le recalcule pour chaque nom possible (le vrai SHA-256 a été calculé ici)." : "Un ticket prévisible n'est pas un secret : Mallory a déduit celui d'Alice du sien.", "sys");
    } else out("**Échec : " + n + " essais, 0 succès.** La probabilité qu'un seul essai tombe juste est d'environ " + (x.cfg.gen === "random" ? "2^-128" : "faible") + " : à un million d'essais par seconde, il faudrait en moyenne " + fmtYears(secsFor(Math.pow(2, 128))) + ".", "ok");
    const r = res("guess", !!found);
    if (r === "blk") { note("ids"); }
  }

  // (2) fixation de session
  function simFix() {
    const x = F();
    const an = anon(MAL), vec = [];
    if (x.cfg.urlIds) vec.push("le serveur accepte un ticket dans l'adresse (?sid=)");
    if (!/^__Host-/.test(x.ck.name)) vec.push("un sous-domaine peut poser un cookie « " + x.ck.name + " » pour toute la banque");
    out("1. Mallory visite la banque sans se connecter : le serveur lui remet un ticket ANONYME : " + an.id.slice(0, 12) + (an.id.length > 12 ? "…" : "") + ".", "sys");
    out("2. Elle envoie à Alice un lien qui impose ce ticket (" + (vec.length ? vec.join(" ; ") : "par un autre moyen") + ") : https://" + HOST + "/connexion?sid=" + an.id.slice(0, 8) + "…", "sys");
    const s = login("alice", ALICE, { sid: an.id, dev: "PC portable" });
    out("3. Alice, sans méfiance, se connecte avec ce ticket imposé. Le serveur " + (s.id === an.id ? "**conserve le même ticket**" : "émet un **nouveau ticket** (" + s.id.slice(0, 8) + "…) et détruit l'ancien") + ".", "sys");
    const ok = hijack(an.id, MAL, "4. Mallory présente le ticket qu'elle connaissait déjà");
    const r = res("fix", ok);
    if (r === "hit") out("La connexion d'Alice a « promu » un ticket que Mallory possédait déjà. Le correctif est côté serveur : changer d'identifiant à chaque connexion (`regenerer oui`, à l'atelier).", "sys");
    if (r === "blk") { note("fixation"); fig("fixation", true); }
    else if (r === "hit") fig("fixation", false);
  }

  // (3) vol et fuite de cookie
  function simXss() {
    const x = F(), s = aliceNow(), c = x.ck;
    out("Un commentaire piégé sur le site (une faille XSS : voir le jeu sur les injections) exécute un script dans la page d'Alice. Le script fait : envoyer document.cookie à Mallory.", "sys");
    const leaked = !c.httpOnly;
    code("document.cookie  →  \"" + (leaked ? c.name + "=" + s.id : "") + "\"" + (leaked ? "" : "   (cookie HttpOnly : invisible pour le JavaScript)"));
    if (leaked) {
      x.stolen = { id: s.id, t: x.clock };
      out("Mallory reçoit le ticket d'Alice.", "err");
      hijack(s.id, MAL, "Mallory le présente depuis chez elle");
    } else out("Le script ne voit rien à envoyer. (Il peut encore émettre des requêtes depuis la page d'Alice tant qu'elle est ouverte : HttpOnly protège le ticket, pas contre le XSS lui-même. Il faut aussi corriger la faille.)", "ok");
    const r = res("xss", leaked);
    if (r === "blk") fig("cookie");
    attDone(r);
  }
  function simSniff() {
    const x = F(), s = aliceNow(), c = x.ck;
    out("Alice, sur le Wi-Fi du café, suit un vieux lien en http://" + HOST + "/ (sans « s »). Ève écoute le réseau.", "sys");
    const sent = !c.secure;
    code("GET / HTTP/1.1  (http, en clair)\nHost: " + HOST + "\n" + (sent ? "Cookie: " + c.name + "=" + s.id : "(aucun cookie : le navigateur ne montre pas un cookie Secure en clair)"));
    if (sent) { x.stolen = { id: s.id, t: x.clock }; out("Ève lit le ticket dans la requête en clair.", "err"); hijack(s.id, MAL, "Ève le passe à Mallory"); }
    else out("Le navigateur n'a pas joint le cookie : il ne l'envoie qu'en https. (HSTS, qui force l'https, compléterait la protection.)", "ok");
    const r = res("ecoute", sent);
    if (r === "blk") fig("cookie");
    attDone(r);
  }
  function simCsrf() {
    const x = F(), c = x.ck;
    aliceNow();
    out("Alice visite la page « Promo gratuite » de Mallory. Un formulaire invisible envoie un virement à la banque depuis un AUTRE site (requête POST inter-sites).", "sys");
    const sent = c.sameSite === "none";
    code("POST https://" + HOST + "/virement  (to=mallory, montant=500)\nOrigin: https://promo.evil.example\nCookie: " + (sent ? c.name + "=…" : "(non envoyé : SameSite=" + cap(c.sameSite) + ")"));
    if (sent) out("**500 pièces d'or virées à Mallory.** Le navigateur a joint le cookie tout seul. (SameSite=None l'autorise : réglage hérité.)", "err");
    else out("Virement refusé : sans cookie, la banque ne reconnaît pas Alice. SameSite=" + cap(c.sameSite) + " interdit l'envoi du cookie dans un POST inter-sites.", "ok");
    out("À savoir : sous Lax, un simple lien (GET) inter-site porte encore le cookie, et Strict le retient aussi : n'effectue donc jamais d'action avec un GET. (Le jeton CSRF est un autre complément.)", "sys");
    const r = res("piege", sent);
    if (r === "blk") fig("cookie");
    attDone(r);
  }
  function simSub() {
    const x = F(), c = x.ck;
    aliceNow();
    out("Le blog " + SUB + " héberge des pages d'utilisateurs : l'une est piégée.", "sys");
    const wide = !!c.domain, pref = /^__Host-/.test(c.name);
    out((wide ? "✘" : "✔") + " Lecture : " + (wide ? "le cookie a un attribut Domain=" + c.domain + " : le navigateur l'envoie AUSSI à tous les sous-domaines. Le blog le reçoit dans chaque requête (son serveur le voit, son script lit un cookie non HttpOnly)." : "le cookie est lié à l'hôte exact : le blog ne le reçoit pas."), wide ? "err" : "ok");
    out((pref ? "✔" : "✘") + " Pose : le blog essaie de poser « " + c.name + " » pour toute la banque (Domain=" + HOST + ") avec le ticket de Mallory. " + (pref ? "Le préfixe __Host- l'interdit : seul l'hôte exact peut poser ce cookie, et la banque ignore tout autre nom." : "Le navigateur l'accepte : c'est une fixation de session par cookie (« cookie tossing »)."), pref ? "ok" : "err");
    const r = res("sous", wide || !pref);
    if (r === "blk") fig("cookie");
    attDone(r);
  }
  function attDone(r) {
    const x = F();
    if (r === "blk" && ATT.every(a => x.blk[a]) && S.notes.indexOf("attributs") < 0) { note("attributs"); out("Cookie durci : HttpOnly, Secure, SameSite, hôte exact et préfixe __Host-. `auditer` (dans le navigateur) fait le bilan.", "ok"); }
  }

  // (4) fuite par l'adresse
  function simLeak() {
    const x = F(), s = aliceNow(), url = x.cfg.urlIds;
    out("Alice consulte son compte. " + (url ? "Le serveur ajoute le ticket aux adresses (réécriture d'URL) : https://" + HOST + "/compte?sid=" + s.id.slice(0, 10) + "…" : "L'adresse reste propre : https://" + HOST + "/compte (le ticket est dans le cookie)."), "sys");
    const ref = x.cfg.referer, full = "https://" + HOST + "/compte?sid=" + s.id.slice(0, 10) + "…";
    const rows = [
      "journal du serveur ou du mandataire : GET " + (url ? "/compte?sid=" + s.id.slice(0, 10) + "…" : "/compte"),
      "historique du navigateur / lien copié-collé : " + (url ? full : "https://" + HOST + "/compte"),
      "clic sur un lien vers partenaire.example, en-tête Referer : " + (ref === "aucun" ? "(aucun)" : ref === "origine" ? "https://" + HOST + "/" : url ? full : "https://" + HOST + "/compte"),
    ];
    code(rows.join("\n"));
    if (url) { out("Le ticket est dans l'adresse : il fuit dans les journaux, l'historique, les liens partagés, et dans le Referer si la politique est « complet ».", "err"); }
    else out("Aucun ticket dans l'adresse : rien à voler par les journaux, l'historique ou le Referer. " + (ref === "complet" ? "(Pense tout de même à `referer origine` : l'adresse complète fuit toujours des informations.)" : ""), "ok");
    const r = res("fuite", url);
    if (r === "blk") note("fuite");
  }

  // (5) expiration
  function simReplay() {
    const x = F(); let st = x.stolen;
    if (!st || !x.srv[st.id]) { const s = aliceNow(); st = x.stolen = { id: s.id, t: x.clock }; out("(Le ticket volé plus tôt n'existe plus : Mallory en vole un nouveau pour la démonstration.)", "sys"); }
    const el = x.clock - st.t;
    out("Mallory rejoue le ticket volé il y a " + fmtDur(el) + ". Délai d'inactivité : " + (x.cfg.idle ? fmtDur(x.cfg.idle) : "aucun") + ", durée absolue : " + (x.cfg.abs ? fmtDur(x.cfg.abs) : "aucune") + ".", "sys");
    if (el < 3600) { out("Trop tôt pour que ce soit parlant : `attendre 1 j` d'abord, puis rejoue.", "sys"); return; }
    const ok = hijack(st.id, MAL, "Rejeu");
    const r = res("replay", ok);
    if (r === "hit") out("Un ticket qui ne meurt jamais est un vol permanent. Le serveur doit expirer les sessions (`delais`, au registre).", "sys");
  }
  function simPing() {
    const x = F(), s = login("alice", ALICE, { dev: "PC portable" }), id = s.id, c = x.cfg;
    out("Mallory vient de voler un ticket d'Alice. Alice ne s'en sert plus, mais Mallory l'utilise toutes les 5 minutes pendant 24 h pour qu'il ne soit jamais inactif.", "sys");
    let stop = null, t = 0;
    for (; t < DAY; t += 300) { x.clock += 300; const r = check(id, MAL); if (!r.ok) { stop = r; break; } }
    if (stop) {
      out("Le ticket est coupé après " + fmtDur(t + 300) + " : " + stop.why + ".", "ok");
      if (stop.kind === "abs") out("Avec un seul délai d'inactivité, Mallory le maintiendrait en vie indéfiniment ; la durée absolue le coupe quoi qu'il arrive.", "sys");
      x.hit.ping = true; x.blk.ping = true; note("expiration");
    } else {
      x.hit.ping = true;
      out("Après 24 h, Mallory est toujours connectée : son activité empêche l'inactivité de jouer. " + (c.abs ? "" : "Ajoute une durée absolue : `delais 15min 8h`."), "err");
    }
  }
  function simMem() {
    const x = F(), c = x.cfg;
    if (c.mem === "non") { out("Le « se souvenir de moi » est désactivé : rien à rejouer. (`souvenir fixe` ou `souvenir rotatif` au registre.)", "sys"); return; }
    purgeAlice(); x.rem = {};
    const fam = (x.fam = (x.fam || 0) + 1), T1 = rand128();
    x.rem[sha256(T1)] = { user: "alice", fam, used: false, exp: x.clock + 30 * DAY };
    const s1 = login("alice", ALICE, { dev: "PC portable", fam });
    out("1. Alice se connecte en cochant « se souvenir de moi ». Elle reçoit sa session ET un jeton durable séparé (30 jours), dont le serveur ne garde que le hachage (sha256).", "sys");
    code("session  : " + s1.id.slice(0, 12) + "…\nsouvenir : " + T1.slice(0, 12) + "…  (stocké haché : " + sha256(T1).slice(0, 12) + "…)");
    out("2. Mallory copie ce jeton (disque d'un PC partagé).", "sys");
    delete x.srv[s1.id]; x.clock += 2 * DAY;
    out("3. Deux jours plus tard, Alice rouvre son navigateur : il a perdu le cookie de session mais présente le jeton durable.", "sys");
    const e1 = x.rem[sha256(T1)];
    let T2 = T1;
    if (c.mem === "rotatif") { e1.used = true; T2 = rand128(); x.rem[sha256(T2)] = { user: "alice", fam, used: false, exp: x.clock + 30 * DAY }; }
    const s2 = login("alice", ALICE, { dev: "PC portable", fam });
    out("   Le serveur ouvre une session neuve (" + s2.id.slice(0, 8) + "…)" + (c.mem === "rotatif" ? " et remplace le jeton : l'ancien est marqué « déjà utilisé » (nouveau : " + T2.slice(0, 8) + "…)." : " mais garde le même jeton."), "sys");
    out("4. Mallory présente à son tour le jeton qu'elle avait copié :", "sys");
    const e = x.rem[sha256(T1)]; let ok;
    if (e && e.used) {
      Object.keys(x.rem).forEach(h => { if (x.rem[h].fam === fam) delete x.rem[h]; });
      Object.values(x.srv).forEach(s => { if (s.fam === fam) delete x.srv[s.id]; });
      out("**Rejeu détecté** : ce jeton avait déjà servi. Le serveur ne sait pas qui est le vrai, il révoque TOUTE la famille (le jeton d'Alice aussi) et lui demandera son mot de passe. Le vol est signalé, plutôt qu'invisible.", "ok"); ok = false;
    } else {
      const sm = login("alice", MAL, { dev: "curl", fam });
      out("Le jeton est valide : **le serveur ouvre à Mallory une session au nom d'Alice** (" + sm.id.slice(0, 8) + "…), sans mot de passe et sans que personne le remarque, pendant 30 jours.", "err"); ok = true;
    }
    const r = res("mem", ok);
    if (r === "blk") note("souvenir");
  }

  // (6) déconnexion et révocation
  function simLogout() {
    const x = F(), s = freshAlice(), id = s.id;
    out("Mallory a copié le ticket d'Alice (elle l'a vu passer sur un PC partagé). Alice termine et clique sur « Se déconnecter ». Le navigateur efface son cookie." , "sys");
    if (x.cfg.logout === "serveur") { delete x.srv[id]; out("Le serveur supprime aussi la session de son registre.", "sys"); }
    else out("Le serveur, lui, ne fait rien : la session reste dans le registre.", "sys");
    const ok = hijack(id, MAL, "Mallory présente son ticket copié");
    const r = res("out", ok);
    if (r === "hit") out("Se déconnecter n'a servi à rien contre cette copie : il faut détruire la session côté serveur (`deconnexion serveur`, au registre).", "sys");
  }
  function simPwd() {
    const x = F();
    purgeAlice();
    const pc = login("alice", ALICE, { dev: "PC portable" }), ph = login("alice", ALICE4G, { dev: "Téléphone" });
    out("Alice est connectée sur son PC et sur son téléphone. Mallory a copié le ticket du PC. Alice, inquiète, change son mot de passe depuis son téléphone.", "sys");
    if (x.cfg.revokeAll) { delete x.srv[pc.id]; out("Le serveur révoque toutes les autres sessions du compte (le PC), garde le téléphone.", "sys"); }
    else out("Le serveur change le mot de passe, et ne touche pas aux sessions existantes.", "sys");
    const ok = hijack(pc.id, MAL, "Mallory rejoue le ticket du PC");
    const r = res("pwd", ok);
    if (r === "hit") out("Changer le mot de passe ne suffit pas : l'intrus est déjà entré, son ticket ne dépend plus du mot de passe. Va voir au registre qui est connecté : `appareils`, puis `revoquer ‹n›`.", "sys");
    if (r === "blk") { note("deconnexion"); }
  }

  // (8) liaison
  function simBind() {
    const x = F(), s = freshAlice(), id = s.id;
    const b = x.cfg.bind;
    out("Liaison actuelle : " + BINDS[b] + ". Le ticket d'Alice (PC portable, Firefox, 82.64.10.5) est volé. Trois requêtes :", "sys");
    const a = check(id, MAL), ar = a.ok;
    out((ar ? "✘ " : "✔ ") + "A. Mallory (curl, 203.0.113.77) : " + (ar ? "acceptée" : "refusée, " + a.why) + ".", ar ? "err" : "ok");
    const l = check(id, ALICE4G), lr = l.ok;
    out((lr ? "✔ " : "✘ ") + "B. Alice, en roaming sur la 4G (même navigateur, autre adresse 82.64.200.9) : " + (lr ? "acceptée" : "refusée, " + l.why + " (faux positif : une innocente est punie)") + ".", lr ? "ok" : "err");
    const cc = check(id, MALSP), cr = cc.ok;
    out((cr ? "✘ " : "✔ ") + "C. Mallory qui a recopié l'agent d'Alice (203.0.113.77) : " + (cr ? "acceptée : un agent n'est pas un secret" : "refusée, " + cc.why) + ".", cr ? "err" : "ok");
    const good = !ar && lr && !cr;
    const r = res("bind", ar || cr);
    if (good) { x.bindOk = true; if (S.notes.indexOf("liaison") < 0) { note("liaison"); } out("Mallory est bloquée dans les deux cas et Alice n'est pas déconnectée : c'est le bon compromis. La liaison reste une défense en plus des autres, pas un remplacement.", "ok"); }
    else if (!lr) out("Cette liaison punit Alice dès qu'elle change de réseau. Il y a mieux.", "sys");
    else if (ar) out("Sans liaison adaptée, le ticket volé marche depuis n'importe où. Essaie `liaison agent`, `liaison agent+ip` et `liaison risque` (au registre), en rejouant à chaque fois.", "sys");
    else if (cr) out("Un agent utilisateur se copie : cette liaison n'arrête pas une attaquante qui l'a observé. Il faut aussi surveiller le réseau.", "sys");
  }

  /* ---------- Les trois modèles ---------- */
  function modelRun(m) {
    const x = F(), now = x.clock, user = "alice";
    const store = {}, deny = {};
    let tok, exp, issue, verify;
    if (m === "opaque") {
      tok = rand128(); store[tok] = { user, exp: now + 8 * 3600 };
      issue = () => tok;
      verify = t => { const s = store[t]; return s ? (s.exp > F().clock ? { ok: true, user: s.user } : { ok: false, why: "expiré" }) : { ok: false, why: "ticket inconnu du registre" }; };
    } else if (m === "signe") {
      exp = now + 8 * 3600;
      const p = b64u(JSON.stringify({ u: user, exp })); tok = p + "." + hmacHex(KEY, p).slice(0, 32);
      verify = t => {
        const [p2, sig] = t.split("."); if (!sig || hmacHex(KEY, p2).slice(0, 32) !== sig) return { ok: false, why: "signature invalide : le contenu a été modifié" };
        if (deny[sig]) return { ok: false, why: "ticket dans la liste noire" };
        const d = JSON.parse(unb64u(p2) || "{}"); return d.exp > F().clock ? { ok: true, user: d.u, left: d.exp - F().clock } : { ok: false, why: "expiré" };
      };
    } else {
      exp = now + 900;
      const h = b64u('{"alg":"HS256","typ":"JWT"}'), p = b64u(JSON.stringify({ sub: user, iat: now, exp, jti: "t1" }));
      tok = h + "." + p + "." + bytesB64u(hmacBytes(strBytes(KEY), strBytes(h + "." + p)));
      verify = t => {
        const [h2, p2, sig] = t.split("."); if (!sig) return { ok: false, why: "jeton mal formé" };
        let hd; try { hd = JSON.parse(unb64u(h2)); } catch (e) { return { ok: false, why: "en-tête illisible" }; }
        if (hd.alg !== "HS256") return { ok: false, why: "algorithme non attendu (le serveur impose HS256)" };
        if (bytesB64u(hmacBytes(strBytes(KEY), strBytes(h2 + "." + p2))) !== sig) return { ok: false, why: "signature invalide : le contenu a été modifié" };
        const d = JSON.parse(unb64u(p2) || "{}"); if (deny[d.jti]) return { ok: false, why: "jti dans la liste noire" };
        return d.exp > F().clock ? { ok: true, user: d.sub, left: d.exp - F().clock } : { ok: false, why: "expiré" };
      };
    }
    out("Modèle **" + { opaque: "opaque", signe: "cookie signé", jwt: "JWT en cookie" }[m] + "**. Le serveur émet à Alice :", "sys");
    code(tok);
    out("(" + tok.length + " caractères" + (m === "opaque" ? " : un simple identifiant, le reste est dans le registre" : " : les données (utilisateur, expiration) sont DANS le jeton, lisibles en base64 ; la signature HMAC-SHA-256, calculée avec la clé secrète du serveur, les protège") + ".)", "");
    out("**Test 1 : falsification.** Mallory veut devenir « admin ».", "");
    let forged;
    if (m === "opaque") forged = tok.slice(0, -1) + (tok.slice(-1) === "0" ? "1" : "0");
    else if (m === "signe") { const [p2, sig] = tok.split("."); const d = JSON.parse(unb64u(p2)); d.u = "admin"; forged = b64u(JSON.stringify(d)) + "." + sig; }
    else { const [h2, p2, sig] = tok.split("."); const d = JSON.parse(unb64u(p2)); d.sub = "admin"; forged = h2 + "." + b64u(JSON.stringify(d)) + "." + sig; }
    const fv = verify(forged);
    out((fv.ok ? "✘ " : "✔ ") + (m === "opaque" ? "Elle modifie un caractère du ticket : " : "Elle remplace l'utilisateur dans les données en gardant l'ancienne signature : ") + (fv.ok ? "accepté !" : "refusé (" + fv.why + ")."), fv.ok ? "err" : "ok");
    out("**Test 2 : déconnexion.** Mallory a copié le ticket valide ; Alice se déconnecte ; une minute plus tard Mallory le présente.", "");
    if (m === "opaque") delete store[tok];
    else if (x.cfg.deny) { if (m === "signe") deny[tok.split(".")[1]] = true; else deny["t1"] = true; }
    x.clock += 60;
    const rv = verify(tok); x.clock -= 60;
    out((rv.ok ? "✘ " : "✔ ") + (rv.ok ? "Le ticket est **encore accepté**, pour " + fmtDur(rv.left) + " : le serveur n'a rien à supprimer, tout est dans le jeton." : "Refusé (" + rv.why + ")" + (m !== "opaque" ? " : mais le serveur a dû tenir une liste noire, c'est un état serveur : on retombe sur un registre." : " : la ligne du registre n'existe plus.")), rv.ok ? "err" : "ok");
    if (!x.cfg.deny || m === "opaque") x.mdl[m] = { forged: !fv.ok, revocable: !rv.ok, len: tok.length };
    else if (!x.mdl[m]) out("(Résultat non retenu pour la comparaison : désactive la liste noire avec `liste non` et rejoue `essayer " + m + "`.)", "sys");
  }
  function tryCmd(c) {
    if (!need("modeles", "Les modèles sont à l'étage (`aller haut` depuis le guichet).")) return;
    const t = norm(c.rawArg);
    const m = /^opaque/.test(t) ? "opaque" : /^(signe|signed|cookie)/.test(t) ? "signe" : /^(jwt|jeton)/.test(t) ? "jwt" : null;
    if (!m) { out("`essayer opaque` · `essayer signe` · `essayer jwt`", "err"); return; }
    modelRun(m);
  }
  function denyCmd(c) {
    if (!need("modeles", "Ce réglage est à l'étage des modèles.")) return;
    const t = norm(c.rawArg), x = F();
    if (yes(t)) { x.cfg.deny = true; out("Liste noire activée pour les jetons signés : une déconnexion y inscrit le jeton. Rejoue `essayer signe`.", "ok"); }
    else if (no(t)) { x.cfg.deny = false; out("Liste noire désactivée.", "sys"); }
    else out("`liste oui` ou `liste non`", "err");
  }
  function compareCmd() {
    if (!need("modeles", "La comparaison se fait à l'étage des modèles.")) return;
    const x = F(), M = x.mdl;
    if (Object.keys(M).length < 3) { out("Joue d'abord les trois : `essayer opaque`, `essayer signe`, `essayer jwt`.", "sys"); return; }
    const yn = b => b ? "oui" : "non";
    code("                         opaque    signé     JWT\n" +
      "résiste à la falsif.     " + yn(M.opaque.forged).padEnd(10) + yn(M.signe.forged).padEnd(10) + yn(M.jwt.forged) + "\n" +
      "révocation immédiate     " + yn(M.opaque.revocable).padEnd(10) + yn(M.signe.revocable).padEnd(10) + yn(M.jwt.revocable) + "\n" +
      "serveur sans état        " + "non".padEnd(10) + yn(!x.cfg.deny).padEnd(10) + yn(!x.cfg.deny) + "\n" +
      "taille du ticket         " + (M.opaque.len + " c.").padEnd(10) + (M.signe.len + " c.").padEnd(10) + M.jwt.len + " c.");
    out("La signature détecte la falsification dans les trois cas. La différence est la RÉVOCATION : le ticket opaque se révoque à l'instant ; les jetons signés restent valables jusqu'à l'expiration (d'où des durées courtes pour les JWT, avec un jeton de rafraîchissement) ou exigent une liste noire. Pour une banque, qui doit pouvoir couper un ticket volé immédiatement, l'opaque convient. `adopter ‹modèle›` pour choisir.", "");
    if (!x.cmp) { x.cmp = true; note("modeles"); }
    fig("modeles");
  }
  function adoptCmd(c) {
    if (!need("modeles", "Le choix se fait à l'étage des modèles.")) return;
    const t = norm(c.rawArg), x = F();
    const m = /^opaque/.test(t) ? "opaque" : /^(signe|signed)/.test(t) ? "signe" : /^jwt/.test(t) ? "jwt" : null;
    if (!m) { out("`adopter opaque` · `adopter signe` · `adopter jwt`", "err"); return; }
    if (!x.cmp) { out("Compare d'abord les trois modèles avec `comparer`.", "sys"); return; }
    x.adopt = m; x.cfg.model = m;
    if (m === "opaque") out("La banque adopte des sessions opaques : révocation immédiate, déconnexion et changement de mot de passe efficaces. Le prix : un registre à consulter à chaque requête.", "ok");
    else out("La banque adopte " + (m === "signe" ? "le cookie signé" : "le JWT") + ". Conséquence visible : un ticket volé reste utilisable jusqu'à l'expiration, sans moyen de le couper sauf liste noire. Pour une banque, ce n'est pas assez : reconsidère l'opaque (`adopter opaque`).", "err");
  }

  /* ---------- Fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Voilà le cycle complet : fabriquer un ticket imprévisible, le renouveler à la connexion, le transporter dans un cookie durci, le faire expirer, le tuer côté serveur à la déconnexion, le surveiller. Chaque maillon que tu as réglé protégeait contre une attaque différente.");
    say("Guichetière", "Je ne reconnaîtrai plus personne sur la seule foi d'un numéro facile à deviner. Merci.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le ticket de la guichetière = l'identifiant de session.** HTTP ne retient rien d'une requête à l'autre : après la connexion, le serveur remet un identifiant que le navigateur renvoie à chaque requête (en général dans un cookie). Qui présente l'identifiant EST l'utilisateur : voler le ticket équivaut à voler le compte, sans toucher au mot de passe.");
    out("**La machine à tickets = le générateur d'identifiants.** Un compteur, une heure ou le hachage d'un nom se devinent ou se recalculent. Il faut un générateur cryptographique (CSPRNG) et assez d'entropie (au moins 64 bits réels, 128 en pratique). Les générateurs ordinaires des langages (Math.random et similaires) ne conviennent pas.");
    out("**Le ticket imposé à Alice = la fixation de session.** Si l'identifiant ne change pas à la connexion, l'attaquant qui l'a fixé avant devient la victime. On régénère l'identifiant à chaque changement de privilège. Le préfixe __Host- et le refus des identifiants dans l'adresse ferment les voies d'injection.");
    out("**Les attributs du pot de cookies = HttpOnly, Secure, SameSite, Domain, préfixes.** HttpOnly cache le cookie au JavaScript (un XSS ne peut plus l'emporter, mais agit toujours depuis la page : corriger la faille reste nécessaire). Secure l'interdit en clair. SameSite coupe l'envoi inter-sites. L'absence de Domain l'enferme à l'hôte exact. Le préfixe __Host- fait vérifier le tout par le navigateur.");
    out("**Le registre et son greffier = l'état côté serveur.** Les délais d'inactivité et absolu, la déconnexion qui supprime vraiment la session, la révocation globale au changement de mot de passe et la liste des appareils sont des décisions du serveur. Un jeton « se souvenir de moi » est séparé de la session, stocké haché, et rotatif pour détecter le rejeu.");
    out("**Les trois modèles = sessions opaques, cookies signés et JWT.** Une signature HMAC détecte toute falsification, mais ne permet pas de révoquer : sans liste noire (donc un état), un jeton copié vaut jusqu'à son expiration. Les JWT sont surtout utiles quand plusieurs services doivent vérifier sans interroger une base ; ils ne sont pas chiffrés, et le serveur doit imposer l'algorithme.");
    out("**La liaison à l'appareil = une défense en profondeur.** Changer d'agent utilisateur ou de réseau peut signaler un vol, mais ces valeurs se copient et changent légitimement : refuser tout changement d'IP punit les innocents. Une ré-authentification en cas de changement fort est un meilleur compromis.");
    out("**Les simplifications du jeu.** (1) Le temps, le réseau, le navigateur et le serveur sont simulés ; l'aléa est un générateur à graine fixe pour rejouer la partie (en vrai : le CSPRNG du système). (2) Les règles de cookies sont résumées : « même site » et « même origine » sont distincts, Lax a quelques exceptions, les navigateurs n'appliquent pas tous les mêmes valeurs par défaut. (3) La comparaison de signature se fait ici avec ===, alors qu'il faut une comparaison à temps constant ; la clé est une constante du jeu. (4) Les attaques sont des modèles jouets sur des données fictives, sans technique réutilisable. (5) Le CSRF (jeton) et le XSS ont leurs propres jeux. (6) On utilise un cookie par session ; les frameworks réels (et leurs bibliothèques de sessions) font tout cela pour toi : utilise-les plutôt que de réécrire.");
    out("Rappel utile : **un ticket de session est un secret : fabrique-le au hasard, renouvelle-le à la connexion, protège-le dans le navigateur, fais-le expirer, et sache le tuer côté serveur.**", "ok");
  }

  /* ---------- Schémas ---------- */
  const okBad = b => b ? "ft-ok" : "ft-bad";
  const figs = {
    cycle: () => {
      const x = F(), c = x.cfg, k = x.ck;
      const rows = [
        ["1 · Création", c.gen === "random" ? ["identifiant aléatoire 128 bits", true] : ["identifiant devinable (" + GENS[c.gen] + ")", false]],
        ["2 · Connexion", c.regen ? ["nouvel identifiant à l'authentification", true] : ["même identifiant : fixation possible", false]],
        ["3 · Transport", (k.httpOnly && k.secure && k.sameSite !== "none" && !c.urlIds) ? ["cookie durci, jamais dans l'adresse", true] : ["cookie ou adresse exposés", false]],
        ["4 · Usage", c.bind !== "none" ? ["lié à l'appareil (" + BINDS[c.bind] + ")", true] : ["aucune liaison à l'appareil", false]],
        ["5 · Expiration", (c.idle && c.abs) ? ["inactivité " + fmtDur(c.idle) + ", absolue " + fmtDur(c.abs), true] : ["pas de délai complet", false]],
        ["6 · Fin", (c.logout === "serveur" && c.revokeAll) ? ["déconnexion et révocation côté serveur", true] : ["le ticket copié survit", false]],
      ];
      let b = "";
      rows.forEach((r, i) => { const y = 14 + i * 40; b += R(8, y, 130, 30, r[1][1] ? "f-ok" : "f-bad") + T(73, y + 20, r[0], "f-b") + AR(138, y + 15, 160, y + 15) + T(168, y + 19, r[1][0], "f-s " + okBad(r[1][1]), "start"); });
      return { cap: "Les six maillons de la vie d'un ticket, avec l'état actuel de ta configuration : vert = solide, rouge = faille.", svg: SVG(264, "Cycle de vie d'une session", b) };
    },
    cookie: () => {
      const k = F().ck, c = F().cfg;
      const rows = [
        ["HttpOnly", "un script injecté (XSS) lit le cookie", k.httpOnly],
        ["Secure", "écoute en clair sur http", k.secure],
        ["SameSite", "envoi depuis un autre site (CSRF)", k.sameSite !== "none"],
        ["sans Domain", "lecture par un sous-domaine", !k.domain],
        ["__Host-", "cookie imposé depuis un sous-domaine", /^__Host-/.test(k.name)],
        ["pas d'URL", "fuite par l'adresse et le Referer", !c.urlIds],
      ];
      let b = T(8, 16, "attribut", "f-b", "start") + T(112, 16, "ce qu'il empêche", "f-b", "start") + T(412, 16, "état", "f-b", "end") + LN(8, 24, 412, 24);
      rows.forEach((r, i) => { const y = 48 + i * 32; b += T(8, y, r[0], "f-b", "start") + T(112, y, r[1], "f-s", "start") + T(412, y, r[2] ? "✔ actif" : "✘ absent", "f-s " + okBad(r[2]), "end"); });
      return { cap: "Chaque attribut du cookie ferme une attaque précise. Le schéma reflète le cookie d'Alice tel que tu l'as réglé.", svg: SVG(244, "Attributs de cookie et ce qu'ils empêchent", b) };
    },
    fixation: (fixed) => {
      const x = fixed === undefined ? F().cfg.regen : fixed;
      let b = T(60, 16, "Mallory", "f-b") + T(210, 16, "Alice", "f-b") + T(360, 16, "Serveur", "f-b") + LN(60, 22, 60, 218, "f-dash") + LN(210, 22, 210, 218, "f-dash") + LN(360, 22, 360, 218, "f-dash");
      b += AR(60, 50, 358, 50) + T(210, 42, "1 · demande un ticket anonyme T", "f-s");
      b += AR(60, 84, 208, 84) + T(134, 76, "2 · lien avec T", "f-s");
      b += AR(210, 118, 358, 118) + T(284, 110, "3 · connexion avec T", "f-s");
      b += R(208, 130, 204, 40, x ? "f-ok" : "f-bad") + T(310, 148, x ? "nouveau ticket T2, T détruit" : "T devient le ticket d'Alice", "f-s f-b " + okBad(x)) + T(310, 163, x ? "régénération à la connexion" : "pas de régénération", "f-s");
      b += AR(60, 194, 358, 194, x ? "f-dash f-ln" : "f-bad") + T(210, 186, "4 · Mallory utilise T", "f-s");
      b += T(210, 214, x ? "✘ refusé : T n'existe plus" : "✔ elle est connectée en tant qu'Alice", "f-b " + (x ? "ft-ok" : "ft-bad"));
      return { cap: x ? "Après : le serveur change de ticket à l'authentification, celui que Mallory connaît ne mène nulle part." : "Avant : le ticket que Mallory a imposé devient celui d'Alice une fois connectée, et Mallory le connaît déjà.", svg: SVG(232, "Fixation de session avant et après", b) };
    },
    modeles: () => {
      const m = F().cfg.model, M = F().mdl, sel = m;
      const cx = { opaque: 258, signe: 318, jwt: 380 };
      let b = "";
      if (F().adopt) b += `<rect x="${cx[sel] - 28}" y="4" width="56" height="152" rx="6" class="f-box f-ok"/>`;
      b += T(8, 16, "critère", "f-b", "start") + T(cx.opaque, 16, "opaque", "f-b") + T(cx.signe, 16, "signé", "f-b") + T(cx.jwt, 16, "JWT", "f-b") + LN(8, 24, 412, 24);
      const rows = [["résiste à la falsification", ["✔", "✔", "✔"], [1, 1, 1]], ["révocation immédiate", ["✔", "✘", "✘"], [1, 0, 0]], ["serveur sans état", ["✘", "✔", "✔"], [0, 1, 1]], ["taille du ticket", ["32", "~70", "~160"], [1, 1, 1]]];
      rows.forEach((r, i) => { const y = 48 + i * 30; b += T(8, y, r[0], "", "start"); ["opaque", "signe", "jwt"].forEach((k, j) => { b += T(cx[k], y, r[1][j], r[2][j] ? "ft-ok f-b" : "ft-bad f-b"); }); });
      b += T(210, 186, "liste noire : révocation possible, mais un état est de retour", "f-s") + T(210, 206, "signature = intégrité ; ce n'est pas du chiffrement", "f-s");
      return { cap: "Comparaison des trois modèles de tickets ; la colonne cadrée est celle que la banque a adoptée.", svg: SVG(222, "Comparaison des modèles de sessions", b) };
    },
  };

  GAMES.session = {
    id: "session", order: 35, title: "Les Tickets de Port-443", pageTitle: "Session Quest", subtitle: "aventure textuelle · sessions et cookies",
    blurb: "Fabrique, transporte et invalide les tickets de session d'une banque, contre un attaquant simulé.",
    concept: "Sessions et cookies : fixation, vol, expiration, révocation",
    start: "guichet", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    refig(name) { fig(name, name === "fixation" ? !!F().cfg.regen : undefined); },
    figAlias: { cycle: ["vie", "cycle", "session"], cookie: ["attributs", "cookies", "attribut"], fixation: ["fixer", "avant", "apres"], modeles: ["modele", "comparaison", "jwt"] },
    help: "Spécifiques : `connexion` · `generateur ‹mode›` · `entropie` · `regenerer oui|non` · `cookie ‹attribut› ‹valeur›` · `transport cookie|url` · `referer ‹politique›` · `auditer` · `delais ‹inactivité› ‹absolue›` · `attendre ‹durée›` · `souvenir ‹mode›` · `deconnexion client|serveur` · `revocation oui|non` · `liaison ‹mode›` · `appareils` · `revoquer ‹n›` · `simuler ‹attaque›` · `essayer ‹modèle›` · `comparer` · `adopter ‹modèle›`",
    setup() {
      const x = F();
      Object.assign(x, {
        clock: 1760000000, cnt: 41, rs: 1592324660, srv: {}, rem: {}, hit: {}, blk: {}, mdl: {},
        cfg: { gen: "counter", regen: false, urlIds: true, idle: 0, abs: 0, mem: "fixe", logout: "client", revokeAll: false, bind: "none", referer: "complet", model: "opaque", deny: false },
        ck: { name: "sid", httpOnly: false, secure: false, sameSite: "none", domain: HOST, path: "/" },
      });
    },
    verbs: {
      connect: { words: ["connexion", "connecter", "login"], run: connectCmd },
      gen: { words: ["generateur", "generer", "fabriquer"], run: genCmd },
      entropy: { words: ["entropie"], run: entropyCmd },
      regen: { words: ["regenerer", "regeneration", "renouveler"], run: regenCmd },
      cookie: { words: ["cookie", "attribut", "regler"], run: cookieCmd },
      transport: { words: ["transport"], run: transportCmd },
      referer: { words: ["referer", "referrer"], run: refererCmd },
      audit: { words: ["auditer", "audit", "bilan cookie"], run: auditCmd },
      wait: { words: ["attendre", "patienter", "avancer"], run: waitCmd },
      delays: { words: ["delais", "delai", "expiration"], run: delaysCmd },
      mem: { words: ["souvenir", "memoriser"], run: memCmd },
      logout: { words: ["deconnexion"], run: logoutCmd },
      revokeAll: { words: ["revocation"], run: revokeAllCmd },
      bind: { words: ["liaison", "lier"], run: bindCmd },
      devices: { words: ["appareils", "appareil"], run: devicesCmd },
      revoke: { words: ["revoquer", "revoque"], run: revokeCmd },
      sim: { words: ["simuler", "tenter", "attaquer"], run: simCmd },
      tryM: { words: ["essayer", "emettre"], run: tryCmd },
      deny: { words: ["liste"], run: denyCmd },
      compare: { words: ["comparer"], run: compareCmd },
      adopt: { words: ["adopter", "choisir"], run: adoptCmd },
    },
    intro() {
      out("Les Tickets de Port-443", "title");
      out("À la banque de Port-443, la guichetière donne un ticket à chaque client, puis ne le reconnaît qu'à ce ticket : plus besoin de redemander le mot de passe. Mais qui détient un ticket est le client. Des comptes sont visités par des inconnus alors qu'aucun mot de passe n'a fuité.\nMaître Ada t'envoie examiner comment ce ticket est fabriqué, transporté et invalidé : c'est la session web.", "");
    },
  };
})();
