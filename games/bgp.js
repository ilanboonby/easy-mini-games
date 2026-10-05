"use strict";
/* Les Routes de Port-443 : BGP (annonces, sélection de chemin, plus long préfixe), détournement, fuite de routes, filtrage, RPKI/ROA. */
(function () {
  const F = () => f();
  const NORD = 64496, SUD = 64497, ME = 64500, REG = 64502, BANK = 64510, CAFE = 64511, MAL = 64666;
  const ASN = [NORD, SUD, ME, REG, BANK, CAFE, MAL];
  const NAME = { [NORD]: "Nord", [SUD]: "Sud", [ME]: "Port-443", [REG]: "Régio", [BANK]: "Banque", [CAFE]: "Café", [MAL]: "Mallory" };
  const PFX = {
    [NORD]: ["100.64.0.0/13"], [SUD]: ["100.72.0.0/13"], [ME]: ["192.0.2.0/24"],
    [REG]: ["198.18.0.0/16", "198.18.64.0/18"], [BANK]: ["203.0.112.0/23"], [CAFE]: ["198.51.100.0/24"], [MAL]: ["100.96.0.0/16"],
  };
  // [fournisseur, client] puis pairs
  const C2P = [[NORD, ME], [SUD, REG], [SUD, BANK], [REG, BANK], [ME, CAFE], [SUD, CAFE], [NORD, MAL]];
  const P2P = [[NORD, SUD], [ME, REG]];
  const LP = { soi: 1000, client: 200, pair: 100, fournisseur: 50 };
  const BANKIP = "203.0.113.80", BANKBLOCK = "203.0.112.0/23";
  const COLLECTORS = [NORD, SUD, REG];

  /* ---------- adresses IPv4 et préfixes CIDR (calcul réel) ---------- */
  const ip2n = s => {
    const m = String(s).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); if (!m) return null;
    const p = m.slice(1).map(Number); if (p.some(v => v > 255)) return null;
    return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
  };
  const n2ip = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const maskOf = l => l === 0 ? 0 : (0xFFFFFFFF << (32 - l)) >>> 0;
  const PC = {};
  function P(s) {
    if (PC[s]) return PC[s];
    const m = String(s).trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/); if (!m) return null;
    const a = ip2n(m[1]), l = +m[2]; if (a === null || l > 32) return null;
    const mask = maskOf(l), base = (a & mask) >>> 0;
    return (PC[s] = { base, len: l, mask, aligned: base === a, str: n2ip(base) + "/" + l });
  }
  const covers = (c, ip) => ((ip & c.mask) >>> 0) === c.base;
  const contains = (big, small) => big.len <= small.len && ((small.base & big.mask) >>> 0) === big.base;
  const bits = n => (n >>> 0).toString(2).padStart(32, "0");

  /* ---------- relations et topologie ---------- */
  function rel(a, b) { // relation de b vue depuis a
    if (C2P.some(([p, c]) => p === a && c === b)) return "client";
    if (C2P.some(([p, c]) => p === b && c === a)) return "fournisseur";
    if (P2P.some(([u, v]) => (u === a && v === b) || (u === b && v === a))) return "pair";
    return null;
  }
  const nbrs = a => ASN.filter(b => rel(a, b));
  const pathStr = p => p.map(a => NAME[a]).join(" ");
  const RELFR = { soi: "local", client: "client", pair: "pair", fournisseur: "fourn." };
  const ALIAS = { nord: NORD, sud: SUD, moi: ME, nous: ME, port: ME, p443: ME, "443": ME, regio: REG, banque: BANK, bank: BANK, cafe: CAFE, mallory: MAL };
  function asOf(s) {
    const n = norm(String(s)).replace(/\s+/g, "").replace(/^as/, "");
    if (/^\d+$/.test(n) && NAME[+n]) return +n;
    if (ALIAS[n]) return ALIAS[n];
    const k = Object.keys(ALIAS).find(a => a.length >= 3 && n.startsWith(a));
    return k ? ALIAS[k] : null;
  }
  const asIn = raw => { for (const t of norm(raw).split(" ")) { const a = asOf(t); if (a) return a; } return null; };
  const ownerOf = pfx => { const c = P(pfx); return ASN.find(a => PFX[a].some(q => contains(P(q), c))) || null; };

  /* ---------- RPKI : validation d'origine (RFC 6811) ---------- */
  function validate(pfx, origin) {
    const c = P(pfx), cov = F().roas.filter(r => contains(P(r.pfx), c));
    if (!cov.length) return { st: "inconnu", cov };
    const ok = cov.find(r => r.asn === origin && c.len <= r.max);
    if (ok) return { st: "valide", cov, by: ok };
    return { st: "invalide", cov, why: cov.some(r => r.asn === origin) ? "longueur" : "origine" };
  }
  const ST = { valide: "✓", invalide: "✗", inconnu: "?" };

  /* ---------- le moteur BGP simplifié ---------- */
  function anns() {
    const x = F(), L = [];
    ASN.forEach(a => PFX[a].forEach(p => L.push({ pfx: p, as: a, path: [] })));
    if (x.hij) L.push({ pfx: x.hij.pfx, as: MAL, path: x.hij.forge ? [BANK] : [] });
    return L;
  }
  const exportOk = (n, a, r) => r.rel === "soi" || r.rel === "client" || rel(n, a) === "client" || (n === CAFE && F().leak);
  function cands(a, p, pc, best, down, rej, recv, logs) {
    const x = F(), out = [];
    for (const n of nbrs(a)) {
      const r = best[n]; if (!r || !exportOk(n, a, r)) continue;
      const path = [n].concat(r.path);
      if (path.includes(a)) continue;
      const orig = path[path.length - 1];
      let why = null;
      if (x.rov[a] === "drop" && validate(p, orig).st === "invalide") why = "rov";
      else if (x.filt[a] && x.filt[a][n] && !x.filt[a][n].some(al => contains(P(al), pc))) why = "filtre";
      else if (down.has(a + ">" + n)) why = "limite";
      if (why) { rej.set(a + ">" + n + "|" + p + "|" + why, { a, n, p, why }); continue; }
      if (x.rov[a] === "log" && validate(p, orig).st === "invalide") logs.add(a + "|" + p + "|" + orig);
      (recv[a + ">" + n] = recv[a + ">" + n] || new Set()).add(p);
      const rr = rel(a, n); out.push({ path, from: n, rel: rr, lp: LP[rr] });
    }
    // préférence locale, puis chemin d'AS le plus court, puis le plus petit numéro de voisin
    return out.sort((u, v) => v.lp - u.lp || u.path.length - v.path.length || u.from - v.from);
  }
  function run(down) {
    const tab = {}, rounds = [], rej = new Map(), recv = {}, logs = new Set(), L = anns();
    ASN.forEach(a => tab[a] = {});
    for (const p of [...new Set(L.map(e => e.pfx))]) {
      const org = L.filter(e => e.pfx === p), pc = P(p);
      let best = {};
      org.forEach(e => best[e.as] = { path: e.path, from: null, rel: "soi", lp: LP.soi });
      const hist = [best];
      for (let k = 1; k <= 14; k++) {
        const nb = {}; let changed = false;
        org.forEach(e => nb[e.as] = best[e.as]);
        for (const a of ASN) {
          if (nb[a]) continue;
          const c = cands(a, p, pc, best, down, rej, recv, logs);
          if (c[0]) nb[a] = c[0];
          const o = best[a], n2 = nb[a];
          if (!o !== !n2 || (o && n2 && (o.from !== n2.from || o.path.join() !== n2.path.join()))) changed = true;
        }
        best = nb; hist.push(best);
        if (!changed) break;
      }
      ASN.forEach(a => { if (best[a]) tab[a][p] = best[a]; });
      rounds.push({ p, hist });
    }
    return { tab, rounds, rej, recv, logs };
  }
  function compute() {
    const x = F(), down = new Map();
    let res;
    for (let pass = 0; pass < 4; pass++) {
      res = run(new Set(down.keys()));
      let more = false;
      Object.keys(x.maxp).forEach(k => {
        const got = (res.recv[k] || new Set()).size;
        if (!down.has(k) && got > x.maxp[k]) { down.set(k, got); more = true; }
      });
      if (!more) break;
    }
    res.down = down;
    return res;
  }
  function lpm(a, ip, res) {
    let best = null;
    for (const [p, r] of Object.entries(res.tab[a])) { const c = P(p); if (covers(c, ip) && (!best || c.len > best.c.len)) best = { p, c, r }; }
    return best;
  }
  function trace(src, ip, res) {
    const hops = [src]; let a = src;
    for (let i = 0; i < 10; i++) {
      const b = lpm(a, ip, res);
      if (!b) return { fate: "none", hops };
      if (b.r.from === null) return { fate: a === MAL ? "mallory" : a === BANK ? "bank" : "other", hops, pfx: b.p };
      a = b.r.from; hops.push(a);
    }
    return { fate: "loop", hops };
  }
  const hopsStr = h => h.map(a => NAME[a]).join("→");
  const viaCafe = t => t.hops.slice(1, -1).includes(CAFE);

  /* ---------- certificats TLS jouets ---------- */
  const TRUST = ["CA-Port443"];
  const certSig = (name, issuer, key) => sha256("cert|" + issuer + "|" + name + "|" + key).slice(0, 16);
  const BANKCERT = { name: "banque.port443", issuer: "CA-Port443", key: "K-banque", sig: certSig("banque.port443", "CA-Port443", "K-banque") };
  const MALCERT = { name: "banque.port443", issuer: "CA-Mallory", key: "K-mallory", sig: certSig("banque.port443", "CA-Mallory", "K-mallory") };
  function certCheck(c) {
    const sigOk = c.sig === certSig(c.name, c.issuer, c.key), nameOk = c.name === "banque.port443", trusted = TRUST.includes(c.issuer);
    return { sigOk, nameOk, trusted, ok: sigOk && nameOk && trusted };
  }
  const certText = c => { const k = certCheck(c); return "certificat reçu : nom=" + c.name + "  émetteur=" + c.issuer + "\nsignature recalculée = " + certSig(c.name, c.issuer, c.key) + "  (" + (k.sigOk ? "cohérente" : "incohérente") + ")\nnom correspond à banque.port443 : " + (k.nameOk ? "oui" : "NON") + "\németteur dans ma liste de confiance " + JSON.stringify(TRUST) + " : " + (k.trusted ? "oui" : "NON") + "\n=> " + (k.ok ? "certificat ACCEPTÉ" : "certificat REFUSÉ"); };

  /* ---------- carnet ---------- */
  const notes = {
    as: ["AS et préfixes", "Internet est un réseau de réseaux. Chaque réseau géré par une organisation est un système autonome (AS), identifié par un numéro (AS64500…). Un AS possède des blocs d'adresses, les préfixes, écrits en CIDR : 203.0.112.0/23 veut dire « les adresses dont les 23 premiers bits sont ceux-là » (512 adresses). Les AS se parlent avec BGP : chacun annonce à ses voisins les préfixes qu'il sait atteindre. Rien, dans BGP lui-même, ne vérifie qu'un AS a le droit d'annoncer ce qu'il annonce."],
    annonce: ["Annonce et sélection de chemin", "Une annonce BGP dit « j'atteins ce préfixe, par ce chemin d'AS ». Chaque AS qui la reçoit ajoute son numéro en tête et la retransmet. Pour un même préfixe reçu de plusieurs voisins, il en retient une : d'abord la préférence locale la plus haute (une règle de l'opérateur, ici dictée par la relation : client > pair > fournisseur), puis le chemin d'AS le plus court, puis un critère de départage. BGP n'optimise donc pas la distance ni la vitesse : il applique des politiques, souvent économiques."],
    lpm: ["Le plus long préfixe gagne", "Un routeur peut avoir plusieurs routes qui couvrent une même adresse (un /16 et un /18 par exemple). Il retient la plus spécifique : le plus long préfixe. Cette règle passe AVANT la comparaison des chemins : une route plus spécifique l'emporte même si son chemin est mauvais, et même si elle vient d'un fournisseur. C'est ce qui permet d'affiner le trafic… et ce qui rend le détournement par sous-préfixe si puissant."],
    detour: ["Le détournement de préfixe", "Un AS qui annonce un préfixe qui n'est pas à lui peut capter du trafic : annoncer le même préfixe fait concurrence au vrai propriétaire (le gagnant dépend des politiques de chaque AS, donc une partie seulement d'Internet est détournée) ; annoncer un sous-préfixe plus long gagne partout où l'annonce est acceptée. Le trafic capté peut être jeté (trou noir : la banque est injoignable), relayé (l'attaquant observe en passant) ou terminé chez lui (il joue la banque). TLS limite les dégâts : l'attaquant ne peut pas présenter un certificat valide pour la banque, un client qui vérifie refuse la connexion. Il voit tout de même qui parle à qui."],
    fuite: ["La fuite de routes", "Une fuite de routes (route leak) n'est pas une attaque : c'est une erreur de politique. Un client relie deux fournisseurs et, par une règle d'export trop large, retransmet à l'un ce qu'il a appris de l'autre. Comme les routes de clients sont préférées, le trafic de nombreux réseaux se jette dans un petit lien qui n'a jamais été prévu pour ça. Règle d'or « valley-free » : une route apprise d'un fournisseur ou d'un pair ne se transmet qu'à ses clients."],
    filtrage: ["Filtrer ses clients", "Le premier rempart est chez le fournisseur : pour chaque client, une liste des préfixes qu'il a le droit d'annoncer (prefix-list, souvent tirée des registres), et une limite du nombre de préfixes acceptés (max-prefix : si le client en annonce soudain des centaines, la session est coupée). Cela arrête fuites et détournements nés de ses clients. Mais cela suppose que chaque fournisseur le fasse pour les siens, et personne ne filtre pour tout Internet."],
    rpki: ["RPKI et ROA", "Dans la RPKI, le titulaire d'un préfixe publie une ROA signée : « ce préfixe, jusqu'à la longueur maximale L, peut être annoncé par cet AS ». Un routeur qui valide l'origine classe chaque annonce : valide (une ROA couvre le préfixe, l'AS d'origine et la longueur concordent), invalide (couvert par une ROA mais l'origine ou la longueur ne concordent pas), inconnu (aucune ROA ne le couvre). Il peut journaliser ou rejeter les invalides. Une longueur maximale trop large est un piège : elle autorise des sous-préfixes qu'un attaquant peut annoncer en copiant l'AS d'origine."],
    limites: ["Les limites de la RPKI", "La validation d'origine ne regarde que le DERNIER AS du chemin. Un attaquant qui annonce « Mallory puis Banque » respecte l'origine : l'annonce est valide, mais le chemin est un mensonge. Il faut d'autres garde-fous : ASPA (chaque AS déclare ses fournisseurs autorisés, ce qui détecte les chemins impossibles et les fuites), BGPsec (signer le chemin, peu déployé), et la surveillance publique des annonces pour repérer l'anormal. Enfin, tout dépend de l'adoption : un détournement n'est stoppé que là où l'on valide, et chez ceux qui sont derrière."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, venue superviser un audit de routage. Tout ce que tu fais ici est simulé, autorisé, et sur des réseaux fictifs." },
    bob: { npc: true, names: ["bob", "poste", "ordinateur de bob", "navigateur"], label: "Bob et son poste de travail", desc: () => "Bob, de l'équipe interne, devant son navigateur. Il veut simplement consulter son compte à la banque (" + BANKIP + "). Son navigateur est réglé en mode TLS " + F().tls + "." },
    carte: { names: ["carte", "topologie", "reseau", "ecran", "mur"], label: "la carte des AS", vis: () => S.room === "noc", desc: () => carteText(), onExamine: () => { const x = F(); if (!x.carte) { x.carte = true; note("as"); } fig("topo"); } },
    console: { names: ["console", "terminal", "routeur"], label: "la console du routeur", vis: () => S.room === "noc", desc: () => "La console du routeur de Port-443 Net (AS64500). Commandes : `table` (la table de routage), `route ‹ip›`, `propager ‹préfixe›`, `tracer ‹ip›`, `couverture`. Les réglages (`filtrer`, `limite`, `rov`, `tls`) se font ici, au centre d'exploitation." },
    ecran: { names: ["ecran des annonces", "annonces", "collecteurs", "observatoire"], label: "le mur des annonces publiques", vis: () => S.room === "obs", desc: () => "Un mur d'écrans qui affiche, en continu, les annonces vues par les collecteurs publics (des routeurs qui écoutent Nord, Sud et Régio). Lecture guidée : `surveiller`." },
    alice: { npc: true, names: ["alice"], label: "Alice, gérante du Café", desc: () => "Alice, qui gère le petit réseau du Café du Peering (AS64511) en plus de la cafetière. Son café est client de Port-443 Net, et de Sud pour la redondance." },
    routeurcafe: { names: ["routeur", "routeur du cafe", "box"], label: "le routeur du café", vis: () => S.room === "cafe", desc: () => "Le routeur du café : deux liens, un vers Port-443 Net, un vers Sud. Sa politique d'export (ce qu'il annonce à chaque voisin) est écrite sur une étiquette : " + (F().leak ? "« tout annoncer à tout le monde » (une erreur de copier-coller)." : "« n'annoncer que 198.51.100.0/24 ».") + " Une erreur d'export, c'est le sujet : `fuite`." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, laptop sur les genoux, un badge « audit autorisé » bien visible. Le contrat limite son exercice au bloc de la banque : " + BANKBLOCK + ". Mode actuel de son trafic capté : " + F().mode + "." },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, qui tient l'observatoire des annonces publiques. Elle ne touche à rien : elle compare ce qu'on annonce avec ce qui devrait l'être." },
    greffier: { npc: true, names: ["greffier", "registre", "greffier du registre"], label: "le Greffier du Registre", desc: () => "Le Greffier du Registre des ressources : il sait qui possède quel bloc d'adresses, et publie les autorisations signées (ROA). Commandes : `roa`, `publier roa ‹préfixe› ‹longueur max› ‹AS›`, `valider ‹préfixe› ‹AS›`, `retirer roa`." },
  };

  function carteText() {
    return "La carte des systèmes autonomes (7 AS) :\n" +
      "  Nord (AS64496) et Sud (AS64497) : transitaires, pairs entre eux.\n" +
      "  Port-443 Net (AS64500, c'est toi) : client de Nord, pair de Régio, fournisseur de Café.\n" +
      "  Régio (AS64502) : client de Sud, pair de Port-443 Net.\n" +
      "  Banque (AS64510) : client de Sud ET de Régio. Bloc : " + BANKBLOCK + " (le serveur : " + BANKIP + ").\n" +
      "  Café (AS64511) : client de Port-443 Net ET de Sud.\n" +
      "  Mallory (AS64666) : cliente de Nord (« audit autorisé »).\n" +
      "`schema topo` pour le dessin, `schema relations` pour les règles.";
  }

  const rooms = {
    noc: { name: "Le centre d'exploitation de Port-443 Net", short: "Centre d'exploitation", alias: ["noc", "centre", "exploitation"], ents: ["ada", "bob", "carte", "console"], exits: { nord: "obs", est: "registre", ouest: "cafe", sud: "ruelle" },
      desc: () => "Un centre d'exploitation réseau : écrans, une grande carte des AS, la console du routeur d'AS64500. Bob y travaille dans un coin. Au nord, l'observatoire des annonces publiques. À l'est, le Registre des ressources. À l'ouest, le Café du Peering. Au sud, une ruelle où Mallory a installé son exercice." },
    obs: { name: "L'observatoire des annonces", short: "Observatoire", alias: ["observatoire", "obs"], ents: ["eve", "ecran"], exits: { sud: "noc" },
      desc: () => "Une salle sombre éclairée par des écrans qui défilent : les annonces BGP que voient des collecteurs publics. Ève les lit avec une patience de pêcheuse." },
    registre: { name: "Le Registre des ressources", short: "Registre", alias: ["registre", "rpki"], ents: ["greffier"], exits: { ouest: "noc" },
      desc: () => "Un comptoir de chêne et des casiers de parchemins signés : le Registre qui sait quel organisme détient quel bloc d'adresses. C'est ici que se publient les ROA de la RPKI." },
    cafe: { name: "Le Café du Peering", short: "Café", alias: ["cafe", "peering"], ents: ["alice", "routeurcafe"], exits: { est: "noc" },
      desc: () => "Un café qui sent le grain torréfié, et qui possède son propre AS : une bonne cafetière, deux fibres, un routeur derrière le comptoir. Alice y sert les clients et administre le réseau." },
    ruelle: { name: "La ruelle de Mallory", short: "Ruelle", alias: ["ruelle", "mallory"], ents: ["mallory"], exits: { nord: "noc" },
      desc: () => "Une ruelle où Mallory a branché son laptop sur une prise de service. Pour l'exercice, elle annonce, au nom de son AS (AS64666), ce que le contrat l'autorise à annoncer. Commandes : `detourner ‹préfixe›`, `mode ‹trou|relais|usurper›`, `retirer`." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F(), v = x.vis || {};
    if (!x.quest) return "quest";
    if (!x.carte) return "carte";
    if (!x.prop) return "propag";
    if (!x.tab) return "table";
    if (Object.keys(x.lpmW).length < 2) return "lpm";
    if (!x.cov1) return x.hij && x.hij.pfx === BANKBLOCK ? "cov1" : "hij1";
    if (!x.cov2) return x.hij && x.hij.pfx === "203.0.113.0/24" ? "cov2" : "hij2";
    if (!x.tr) return "trace";
    if (!(v.trou && v.relais && v.usurper)) return "modes";
    if (x.hij && !x.leakSeen) return "clear";
    if (!x.leak && !x.leakSeen) return "leak";
    if (!(x.filtOk || x.limTrig)) return "filt";
    if (!x.alice) return "alice";
    if (!x.vU) return "unk";
    if (!x.roaBank) return "roa";
    if (!(x.vV && x.vI)) return "vv";
    if (x.rov[ME] !== "drop") return "rov";
    if (!x.cov3) return x.hij && x.hij.pfx === "203.0.113.0/24" ? "cov3" : "hij3";
    if (!x.cov4) return x.rov[NORD] === "drop" ? "cov4" : "nord";
    if (!x.mon) return x.hij && x.hij.forge ? "mon" : "forge";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend au centre d'exploitation.", "`parler ada`"],
    carte: () => ["Regarde d'abord à quoi ressemble ton Internet : il y a une carte au mur.", "`examiner carte`"],
    propag: () => ["Pour comprendre une annonce, regarde-la se propager de voisin en voisin. Le bloc de la banque est " + BANKBLOCK + ".", "`propager " + BANKBLOCK + "`"],
    table: () => ["Voici ce que ton routeur a retenu. Consulte sa table de routage.", "`table`"],
    lpm: () => ["Fais deviner à ton routeur où envoyer des paquets pour des adresses chez Régio, qui annonce un /16 et un /18 plus précis. Essaie une adresse dans le /18, puis une hors du /18.", "`route 198.18.70.9` puis `route 198.18.200.1`"],
    hij1: () => ["Va voir Mallory : première partie de l'exercice, elle annonce le MÊME préfixe que la banque.", "`aller sud`, puis `detourner " + BANKBLOCK + "`"],
    cov1: () => ["Regarde qui, dans la topologie, envoie maintenant son trafic vers la banque… ou vers Mallory.", "`couverture`"],
    hij2: () => ["Deuxième partie : un préfixe plus spécifique. Le serveur de la banque est " + BANKIP + " : quel /24 de ton bloc le contient ?", "Chez Mallory (ruelle, au sud) : `detourner 203.0.113.0/24`"],
    cov2: () => ["Compare avec le cas précédent.", "`couverture`"],
    trace: () => ["Suis un paquet de ton réseau jusqu'au serveur de la banque, saut par saut.", "`tracer " + BANKIP + "`"],
    modes: () => ["Que fait Mallory du trafic qu'elle capte ? Trois comportements : trou, relais, usurper. Teste chacun avec Bob (centre d'exploitation) qui visite la banque (`tls` strict). Il manque : " + [["trou", "trou"], ["relais", "relais"], ["usurper", "usurper"]].filter(a => !(F().vis || {})[a[0]]).map(a => a[1]).join(", ") + ".", "Chez Mallory : `mode trou` ; au centre : `visiter banque`. Puis `mode relais`, `visiter banque`, puis `mode usurper`, `visiter banque`."],
    clear: () => ["Mallory doit retirer ses annonces avant la suite.", "`aller sud`, puis `retirer`"],
    leak: () => ["Autre incident : au Café du Peering (ouest du centre), Alice relie deux fournisseurs. Simule une erreur d'export.", "`aller ouest`, puis `fuite`"],
    filt: () => ["Ton côté doit se protéger d'un client qui se trompe : au centre, ne laisse Café annoncer que son propre préfixe (198.51.100.0/24).", "`aller est` puis `filtrer cafe 198.51.100.0/24`  (ou `limite cafe 3`)"],
    alice: () => ["Il reste à Alice de corriger l'erreur chez elle.", "`aller ouest`, puis `parler alice`"],
    unk: () => ["Passons à la cryptographie du routage. Au Registre (est du centre), demande à quel point on peut se fier à une annonce : valide, invalide ou inconnue. Pour l'instant, aucune autorisation n'est publiée.", "`aller est`, puis `valider " + BANKBLOCK + " 64666`"],
    roa: () => ["La banque délègue à la Guilde la publication de son autorisation. Elle doit couvrir le bloc, une longueur maximale et l'AS de la banque (64510). Choisis la longueur la plus stricte.", "`publier roa " + BANKBLOCK + " 23 64510`"],
    vv: () => ["Teste la validation : une origine exacte, puis un /24 annoncé par le bon AS. Que se passe-t-il ? Il manque : " + [!F().vV && "un cas valide", !F().vI && "un cas invalide"].filter(Boolean).join(" et ") + ".", "`valider " + BANKBLOCK + " 64510` (valide) ; `valider 203.0.113.0/24 64510` ou `valider " + BANKBLOCK + " 64666` (invalide)"],
    rov: () => ["Ton routeur peut rejeter les annonces invalides. Retourne au centre d'exploitation.", "`aller ouest`, puis `rov rejeter` (`rov` seul pour l'état)"],
    hij3: () => ["Rejoue le détournement le plus violent, le /24, pour voir ce que ta protection change.", "`aller sud`, puis `detourner 203.0.113.0/24`"],
    cov3: () => ["Qui est protégé, maintenant ?", "`couverture`"],
    nord: () => ["Ton routeur est protégé, mais pas les autres. Nord est le fournisseur de Mallory : s'il rejette les invalides, l'annonce s'arrête à la source. Demande-le depuis le centre d'exploitation.", "Au centre d'exploitation : `rov demander nord`"],
    cov4: () => ["Revérifie la couverture.", "`couverture`"],
    forge: () => ["Dernier test : et si Mallory copie l'AS d'origine de la banque dans son chemin ?", "Chez Mallory : `detourner " + BANKBLOCK + " forge`"],
    mon: () => ["La RPKI ne voit pas le mensonge. Qui le verrait ? Va à l'observatoire (nord du centre).", "`aller nord`, puis `surveiller`"],
    end: () => ["Rends compte à Maître Ada.", "`parler ada` (au centre d'exploitation)"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Bienvenue au centre d'exploitation de Port-443 Net, AS64500. Pour qu'un paquet aille de chez toi à la banque, des dizaines de réseaux indépendants doivent s'entendre. Ils le font avec BGP : chacun annonce à ses voisins les blocs d'adresses qu'il sait atteindre, et chacun croit ses voisins sur parole.");
          say("Maître Ada", "Aujourd'hui, audit autorisé : comprendre comment les chemins se choisissent, voir ce que peut faire une annonce mensongère (celle de Mallory, ou une simple erreur d'Alice), puis poser les défenses : filtrer ses clients, signer les autorisations d'origine avec la RPKI, et savoir ce qu'elles ne couvrent pas. Tout est simulé.");
          out("Commence par regarder la carte : `examiner carte`.", "sys");
        } else if (objective() === "end") ending();
        else if (x.end) say("Maître Ada", "Le réseau est mieux défendu. Merci !");
        else say("Maître Ada", "L'audit continue. " + hints[objective()]()[0]);
        break;
      case "bob":
        say("Bob", "Moi, je veux juste consulter mon compte : `visiter banque`. Mon navigateur est en mode TLS " + x.tls + " : `tls strict` vérifie les certificats, `tls laxiste` me laisse cliquer sur « continuer quand même » (ce que je fais, par paresse). Si tu veux me voir sur une page non chiffrée : `visiter banque en clair`.");
        break;
      case "mallory":
        if (!x.cov1 && !x.hij) say("Mallory", "Mon contrat est clair : le bloc de la banque, " + BANKBLOCK + ", rien d'autre. Première étape : j'annonce le même préfixe qu'elle, comme si elle était à moi. `detourner " + BANKBLOCK + "`.");
        else say("Mallory", "Je peux annoncer " + BANKBLOCK + " (même préfixe) ou l'un de ses /24 (203.0.112.0/24 ou 203.0.113.0/24) : `detourner ‹préfixe›`, avec `forge` en plus si je veux copier l'AS d'origine dans mon chemin. Ce que je fais du trafic : `mode trou` (je le jette), `mode relais` (je le transmets à la vraie banque en le lisant au passage), `mode usurper` (je réponds moi-même, avec mon certificat). `retirer` pour stopper.");
        break;
      case "alice":
        if (!x.leak && !x.alice) say("Alice", "Mon café a deux liens : Port-443 Net et Sud, pour ne jamais tomber. Une bêtise de configuration d'export peut arriver à n'importe qui : si tu veux voir l'effet, on simule, dis `fuite`.");
        else if (x.leak && !(x.filtOk || x.limTrig)) say("Alice", "Je vois mon routeur annoncer tout et n'importe quoi, c'est mon erreur ! Mais tu es mon fournisseur : protège d'abord ton côté (filtrage au centre d'exploitation), je corrigerai après. Un client peut se tromper à tout moment.");
        else if (x.leak) { x.leak = false; x.alice = true; say("Alice", "Voilà : j'ai ajouté une règle d'export (je n'annonce que 198.51.100.0/24 à mes deux fournisseurs). Merci d'avoir filtré de ton côté : si je me trompe encore, personne ne le sentira."); out("La fuite est colmatée à la source.", "ok"); }
        else say("Alice", "Mon routeur n'annonce plus que mon préfixe. Un café ? C'est offert.");
        break;
      case "eve":
        say("Ève", "Des collecteurs publics, branchés sur Nord, Sud et Régio, enregistrent chaque annonce qu'ils voient. Moi, je les compare à ce que je sais : qui possède quoi, quelles relations existent. `surveiller` te montre mes alertes. " + (x.hij || x.leak ? "Il y a du mouvement en ce moment." : "Rien de louche pour l'instant."));
        break;
      case "greffier":
        say("Greffier", "Je tiens la liste de qui possède quel bloc, et je publie des ROA : des autorisations signées « tel préfixe, jusqu'à telle longueur, peut être annoncé par tel AS ». Avec `valider ‹préfixe› ‹AS›`, je te dis ce qu'un routeur en penserait : valide, invalide ou inconnu. `roa` liste ce qui est publié.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes de consultation ---------- */
  function tableText(a, res) {
    const rows = Object.entries(res.tab[a]).map(([p, r]) => ({ p, r, c: P(p) })).sort((u, v) => u.c.base - v.c.base || u.c.len - v.c.len);
    const roas = F().roas.length > 0;
    return "table de " + NAME[a] + " (AS" + a + ")\n" + "préfixe".padEnd(16) + "chemin".padEnd(17) + "relation" + (roas ? " RPKI" : "") + "\n" +
      rows.map(({ p, r }) => p.padEnd(16) + (r.from === null ? "(local)" : pathStr(r.path)).padEnd(17) + RELFR[r.rel] + (r.from === null ? "" : " " + r.lp) + (roas ? "  " + ST[validate(p, r.path.length ? r.path[r.path.length - 1] : a).st] : "")).join("\n") +
      (roas ? "\nRPKI : ✓ valide, ✗ invalide, ? inconnu" : "");
  }
  function tableCmd(c) {
    const x = F(), a = c.rawArg ? asIn(c.rawArg) : ME;
    if (!a) { out("Quel AS ? `table` (le tien), ou `table nord`, `table sud`…", "err"); return; }
    const res = compute();
    out("Ton terminal affiche la table de routage (la meilleure route retenue pour chaque préfixe) :", "sys");
    code(tableText(a, res));
    if (a === ME) {
      out("Colonnes : le chemin d'AS retenu, la relation avec le voisin qui l'a donné, et sa préférence locale (client 200, pair 100, fournisseur 50). Regarde la ligne " + BANKBLOCK + " : tu passes par " + (res.tab[ME][BANKBLOCK] ? pathStr(res.tab[ME][BANKBLOCK].path) : "?") + ".", "ok");
      if (!x.tab) { x.tab = true; fig("topo"); }
    }
  }
  function propager(c) {
    const x = F(), m = c.rawArg.match(/\d+\.\d+\.\d+\.\d+\/\d+/);
    if (!m || !P(m[0])) { out("Quel préfixe ? `propager " + BANKBLOCK + "` (un préfixe CIDR annoncé par quelqu'un).", "err"); return; }
    const pf = P(m[0]).str, res = compute(), rd = res.rounds.find(r => r.p === pf);
    if (!rd) { out("Personne n'annonce " + pf + " pour l'instant. Préfixes annoncés : " + res.rounds.map(r => r.p).join(", ") + ".", "sys"); return; }
    const lines = [], L = anns().filter(e => e.pfx === pf);
    L.forEach(e => lines.push("étape 0 : " + NAME[e.as] + " annonce " + pf));
    for (let k = 1; k < rd.hist.length; k++) {
      ASN.forEach(a => {
        const r = rd.hist[k][a], o = rd.hist[k - 1][a];
        if (!r || r.from === null || (o && o.from === r.from && o.path.join() === r.path.join())) return;
        lines.push("étape " + k + " : " + NAME[a] + " retient la route de " + NAME[r.from] + " : chemin « " + pathStr(r.path) + " » (" + RELFR[r.rel] + ", préf. " + r.lp + ")" + (o ? "  [remplace l'ancienne]" : ""));
      });
    }
    out("Propagation de " + pf + ", étape par étape (chaque AS ajoute son numéro et retransmet à ses voisins, selon les relations) :", "sys");
    code(lines.join("\n"));
    const best = rd.hist[rd.hist.length - 1], skip = [];
    ASN.forEach(n => { const r = best[n]; if (!r) return; nbrs(n).forEach(a => { if (!exportOk(n, a, r) && skip.length < 2 && r.from !== null && a !== r.from) skip.push(NAME[n] + " ne transmet pas à " + NAME[a] + " (" + rel(n, a) + ") la route apprise de son " + r.rel + " " + NAME[r.from]); }); });
    if (skip.length) out("Règle « valley-free » en action : " + skip.join(" ; ") + ". Un réseau ne sert pas de transit gratuit entre ses voisins.", "sys");
    const cs = cands(ME, pf, P(pf), best, new Set(), new Map(), {}, new Set());
    if (cs.length > 1 && best[ME] && best[ME].from !== null) out("Port-443 reçoit " + cs.length + " routes pour ce préfixe : " + cs.map(r => "« " + pathStr(r.path) + " » (" + RELFR[r.rel] + ", " + r.lp + ", " + r.path.length + " saut" + (r.path.length > 1 ? "s" : "") + ")").join(" et ") + ". Retenue : celle dont la préférence locale est la plus haute, même si ce n'est pas la plus courte.", "ok");
    if (!x.prop) { x.prop = true; note("annonce"); fig("relations"); }
  }
  function route(c) {
    const x = F(), m = c.rawArg.match(/\d+\.\d+\.\d+\.\d+/), ip = m ? ip2n(m[0]) : null;
    if (ip === null) { out("Quelle adresse IPv4 ? `route " + BANKIP + "`", "err"); return; }
    const res = compute(), rows = Object.entries(res.tab[ME]).map(([p, r]) => ({ p, r, c: P(p) })).filter(e => covers(e.c, ip)).sort((u, v) => v.c.len - u.c.len);
    x.lastIp = ip;
    out("Ton routeur cherche toutes les routes qui couvrent " + n2ip(ip) + " :", "sys");
    if (!rows.length) { code("aucune route ne couvre " + n2ip(ip) + "\n=> paquet jeté (pas de route par défaut dans cette zone d'Internet)"); return; }
    code(rows.map((e, i) => e.p.padEnd(16) + (e.r.from === null ? "local" : "via " + NAME[e.r.from] + (e.r.path.length > 1 ? " (" + pathStr(e.r.path) + ")" : "")) + (i === 0 ? "   <== le plus long préfixe : retenue" : "")).join("\n") + "\nlongueurs : " + rows.map(e => "/" + e.c.len).join(" ") + " ; adresse = " + bits(ip).replace(/(.{8})(?=.)/g, "$1."));
    const w = rows[0];
    out(rows.length > 1 ? "Plusieurs routes couvrent cette adresse : la plus spécifique (" + w.p + ") gagne, sans comparer les chemins ni les préférences." : "Une seule route couvre cette adresse : " + w.p + ".", "ok");
    if (!x.lpmW[w.p]) { x.lpmW[w.p] = true; if (Object.keys(x.lpmW).length <= 2) fig("plus"); }
    if (Object.keys(x.lpmW).length >= 2 && !x.lpmN) { x.lpmN = true; note("lpm"); }
  }
  function tracer(c) {
    const x = F(), m = c.rawArg.match(/\d+\.\d+\.\d+\.\d+/), ip = m ? ip2n(m[0]) : null;
    if (ip === null) { out("Quelle adresse ? `tracer " + BANKIP + "` ou `tracer " + BANKIP + " depuis nord`.", "err"); return; }
    let src = ME; const d = c.rawArg.match(/(?:depuis|from)\s+(\S+)/i);
    if (d) { src = asOf(d[1]); if (!src) { out("Je ne connais pas cet AS. (nord, sud, regio, cafe, banque, mallory)", "err"); return; } }
    const res = compute(), t = trace(src, ip, res);
    out("Trace d'un paquet de " + NAME[src] + " vers " + n2ip(ip) + " (chaque AS applique le plus long préfixe de SA table) :", "sys");
    code(t.hops.map((a, i) => { const b = lpm(a, ip, res); return (i + 1) + ". " + NAME[a].padEnd(9) + (b ? b.p.padEnd(16) + (b.r.from === null ? "livre ici" : "→ " + NAME[b.r.from]) : "aucune route"); }).join("\n"));
    if (t.fate === "bank") out("Le paquet arrive chez la banque en " + t.hops.length + " AS : " + hopsStr(t.hops) + ".", "ok");
    else if (t.fate === "mallory") { out("Le paquet arrive chez MALLORY, pas chez la banque : " + hopsStr(t.hops) + ". Le préfixe qui a servi : " + t.pfx + ".", "err"); if (src === ME) x.tr = true; }
    else if (t.fate === "none") out("Le paquet est jeté : plus aucune route.", "err");
    else out("Le paquet arrive à destination.", "ok");
    if (viaCafe(t)) out("Attention : le paquet traverse le café (" + hopsStr(t.hops) + "), un petit lien de 100 Mb/s qui n'a jamais été conçu pour du transit. Pertes et latence garanties.", "err");
    if (x.hij && x.tr && !x.trNote) { x.trNote = true; fig("topo"); }
  }
  function couverture() {
    const x = F(), res = compute(), rows = [NORD, SUD, ME, REG, CAFE].map(a => ({ a, t: trace(a, ip2n(BANKIP), res) }));
    out("Où va le trafic vers " + BANKIP + " (le serveur de la banque), vu de chaque AS :", "sys");
    code(rows.map(({ a, t }) => NAME[a].padEnd(9) + (t.fate === "bank" ? "OK  " : t.fate === "mallory" ? "CAPTURÉ " : "perdu ") + hopsStr(t.hops)).join("\n"));
    const ok = rows.filter(r => r.t.fate === "bank").length, bad = rows.filter(r => r.t.fate === "mallory").length;
    out(ok + " AS sur " + rows.length + " atteignent la banque" + (bad ? ", " + bad + " envoient leur trafic chez Mallory" : "") + ".", bad ? "err" : "ok");
    const h = x.hij;
    if (h && !h.forge && h.pfx === BANKBLOCK) {
      x.cov1 = true; out("Même préfixe : chacun choisit selon SES politiques (relation, puis longueur du chemin). Seul le fournisseur de Mallory, qui préfère une route de client à une route de pair, est trompé ; Port-443 prend la route de son pair Régio. Un détournement par même préfixe est partiel.", "sys");
    } else if (h && !h.forge && h.pfx === "203.0.113.0/24") {
      const rv = x.rov;
      if (!rv[ME]) { x.cov2 = true; x.lastIp = ip2n(BANKIP); note("detour"); out("Sous-préfixe : le /24 est plus spécifique que le /23 de la banque. Le plus long préfixe gagne PARTOUT où l'annonce est acceptée, peu importe les chemins : presque tout le monde est détourné. C'est le détournement le plus efficace.", "err"); fig("plus"); }
      else if (rv[ME] === "drop" && !rv[NORD]) { x.cov3 = true; out("Ton routeur n'accepte plus l'annonce invalide : elle n'entre pas dans ta table. Pourtant ton trafic est toujours capté : il passe par Régio, qui ne valide pas et l'envoie chez Mallory. La RPKI ne protège que là où l'on valide, et seulement ceux qui sont derrière. Il faut que Nord (le fournisseur de Mallory) valide aussi.", "ok"); }
      else if (rv[ME] === "drop" && rv[NORD] === "drop") { x.cov4 = true; out("Nord rejette l'annonce invalide dès qu'elle arrive de Mallory : elle ne se propage plus du tout. Plus on valide près de la source, plus la protection s'étend.", "ok"); fig("topo"); }
    } else if (h && h.forge) out("Chemin forgé : l'annonce prétend venir de la banque. Les AS qui valident l'origine ne voient rien d'anormal.", "sys");
  }

  /* ---------- Mallory : détournement ---------- */
  function detourner(c) {
    const x = F();
    if (S.room !== "ruelle") { out("Mallory est dans la ruelle (au sud du centre).", "sys"); return; }
    const m = c.rawArg.match(/\d+\.\d+\.\d+\.\d+\/\d+/); const forge = /forg|usurp/.test(norm(c.rawArg));
    if (!m || !P(m[0])) { say("Mallory", "Quel préfixe ? `detourner " + BANKBLOCK + "` (même préfixe), ou `detourner 203.0.113.0/24` (plus spécifique)."); return; }
    const pc = P(m[0]);
    if (!pc.aligned) { say("Mallory", "Ce n'est pas un préfixe valide : les bits de poids faible doivent être à zéro (essaie " + pc.str + ")."); return; }
    if (!contains(P(BANKBLOCK), pc)) { say("Mallory", "Hors périmètre : mon contrat d'audit ne couvre que le bloc de la banque, " + BANKBLOCK + ". Je n'annonce rien d'autre."); return; }
    if (pc.len > 24) { say("Mallory", "Un préfixe plus long que /24 serait filtré presque partout : les réseaux refusent les annonces plus fines que /24 pour ne pas gonfler les tables. Reste sur /23 ou /24."); return; }
    x.hij = { pfx: pc.str, forge };
    const res = compute(), t = trace(ME, ip2n(BANKIP), res), acc = ASN.filter(a => a !== MAL && res.tab[a][pc.str] && res.tab[a][pc.str].path.includes(MAL)).map(a => NAME[a]);
    out("Mallory annonce " + pc.str + " depuis son AS64666" + (forge ? ", avec le chemin « Mallory Banque » (elle copie l'AS d'origine de la banque)" : "") + ".", "err");
    out(acc.length ? "L'annonce est retenue par : " + acc.join(", ") + "." : "L'annonce n'a été retenue par personne.", "sys");
    if (res.rej.size) { const rs = [...res.rej.values()].filter(e => e.why === "rov"); if (rs.length) out("Rejetée par validation RPKI chez : " + [...new Set(rs.map(e => NAME[e.a]))].join(", ") + ".", "ok"); }
    out("Trafic de Port-443 vers la banque : " + hopsStr(t.hops) + (t.fate === "mallory" ? "  <== chez Mallory !" : "."), t.fate === "mallory" ? "err" : "ok");
    x.lastIp = ip2n(BANKIP);
    out("`couverture` pour voir tout le monde" + (x.cov2 ? ", `tracer " + BANKIP + "` pour le détail." : "."), "sys");
    if (pc.str === "203.0.113.0/24" && !forge) fig("plus");
  }
  function retirer(c) {
    const x = F();
    if (S.room === "registre") {
      if (!x.roas.length) { say("Greffier", "Aucune ROA à retirer."); return; }
      x.roas = []; x.roaBank = false; x.loose = false; say("Greffier", "Toutes les ROA sont retirées : tout redevient « inconnu ». À toi de publier les bonnes.");
      if (x.rov[ME]) out("Ton routeur valide toujours, mais il ne rejettera plus rien tant qu'aucune ROA ne couvre les préfixes.", "sys");
      return;
    }
    if (S.room !== "ruelle") { out("`retirer` : chez Mallory (annonces) ou au Registre (`retirer roa`).", "sys"); return; }
    if (!x.hij) { say("Mallory", "Je n'annonce rien en ce moment."); return; }
    x.hij = null; say("Mallory", "Annonce retirée. Les tables se réorganisent : tout revient comme avant (après quelques instants dans la vraie vie, parfois plusieurs minutes).");
  }
  function modeCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "ruelle") { out("Ce réglage est chez Mallory (ruelle).", "sys"); return; }
    const v = /trou/.test(t) ? "trou" : /relais|copie|copier/.test(t) ? "relais" : /usurp|termin|jouer/.test(t) ? "usurper" : null;
    if (!v) { out("`mode trou` (jeter) · `mode relais` (transmettre à la vraie banque en observant) · `mode usurper` (répondre à la place de la banque).", "err"); return; }
    x.mode = v;
    say("Mallory", v === "trou" ? "Je jette ce que je reçois : la banque disparaît pour les victimes. C'est le trou noir (la plupart des détournements accidentels ressemblent à ça)." : v === "relais" ? "Je transmets au vrai serveur, par un autre chemin que je garde sous le coude, et je regarde passer. L'utilisateur ne remarque rien d'autre qu'un léger retard. (Simplification : ça demande une vraie route de sortie.)" : "Je réponds moi-même à la place de la banque, avec mon propre serveur et mon propre certificat.");
    out("Mode de Mallory : " + v + ". Teste avec Bob : `visiter banque` (au centre d'exploitation).", "sys");
  }

  /* ---------- Bob visite la banque ---------- */
  function visiter(c) {
    const x = F();
    if (S.room !== "noc") { out("Bob est au centre d'exploitation.", "sys"); return; }
    if (!/banque|bank|compte/.test(norm(c.rawArg))) { out("`visiter banque` (ou `visiter banque en clair`).", "err"); return; }
    const clair = /clair|http\b|sans tls/.test(norm(c.rawArg)), res = compute(), t = trace(ME, ip2n(BANKIP), res);
    x.vis = x.vis || {};
    out("Bob tape l'adresse de la banque dans son navigateur" + (clair ? " (en HTTP, sans TLS)" : " (HTTPS, TLS " + x.tls + ")") + ". Son paquet suit : " + hopsStr(t.hops) + ".", "sys");
    if (t.fate === "none") { say("Bob", "Rien ne répond. Plus aucune route vers la banque."); return; }
    if (t.fate === "bank") {
      if (clair) { out("La page s'affiche. Mais en HTTP, tout ce qui circule se lit sur le chemin : pas de défense si quelqu'un se met au milieu.", "ok"); return; }
      code("ClientHello  SNI=banque.port443 (en clair)\n" + certText(BANKCERT));
      out("Bob se connecte à la vraie banque. Le certificat est accepté.", "ok");
      if (viaCafe(t)) out("(Mais son trafic traverse le café : c'est lent et saccadé.)", "err");
      return;
    }
    const mode = x.mode;
    if (mode === "trou") {
      out("Bob attend. Toujours rien. « Délai dépassé » : la banque est injoignable pour lui, alors qu'elle fonctionne parfaitement. Les paquets vont chez Mallory, qui les jette (trou noir).", "err"); x.vis.trou = true;
    } else if (mode === "relais") {
      x.vis.relais = true;
      if (clair) { code("Mallory observe (HTTP) :\nPOST /connexion  login=bob  mot_de_passe=mdp-fictif-123\n=> contenu lisible : identifiants volés (fictifs)"); out("En clair, le relais révèle tout. Le détournement a transformé Mallory en témoin de la conversation.", "err"); return; }
      code("ClientHello  SNI=banque.port443 (en clair)\n" + certText(BANKCERT) + "\nMallory observe : 192.0.2.17 → " + BANKIP + ":443, SNI banque.port443, 5 120 octets chiffrés\n=> contenu illisible");
      out("La connexion aboutit : Bob parle bien à la vraie banque, par un chemin que Mallory a détourné. Le certificat est celui de la banque. Mallory voit qui parle à qui (adresses, nom du site, volumes) mais pas le contenu : TLS limite les dégâts, sans les supprimer.", "ok");
    } else {
      if (clair) { out("Mallory sert une fausse page en HTTP. Bob saisit son mot de passe fictif. Rien ne l'en protégeait.", "err"); return; }
      code("ClientHello  SNI=banque.port443 (en clair)\n" + certText(MALCERT));
      if (x.tls === "strict") {
        out("Le navigateur de Bob affiche « connexion non sécurisée » et refuse d'envoyer quoi que ce soit : Mallory est capable de répondre à la place de la banque, mais pas d'obtenir un certificat de l'émetteur de confiance pour banque.port443. Aucun mot de passe n'a fuité.", "ok"); x.vis.usurper = true; note("detour");
      } else {
        out("Bob clique sur « continuer quand même ». Mallory lit son login et son mot de passe fictifs. Tout l'intérêt de TLS tient à ce que le client VÉRIFIE : mets-le en `tls strict`.", "err");
      }
    }
  }
  function tlsCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "noc") { out("Le réglage du navigateur de Bob se fait au centre d'exploitation.", "sys"); return; }
    const v = /laxiste|ignorer|tolerant/.test(t) ? "laxiste" : /strict|verifier|stricte/.test(t) ? "strict" : null;
    if (!v) { out("`tls strict` (le navigateur refuse un certificat invalide) ou `tls laxiste` (il laisse continuer). Actuel : " + x.tls + ".", "err"); return; }
    x.tls = v; out("Navigateur de Bob : TLS " + v + ".", "ok");
  }

  /* ---------- fuite de routes et défenses côté client ---------- */
  function fuite() {
    const x = F();
    if (S.room !== "cafe") { out("L'erreur d'export, c'est chez Alice : au Café (ouest du centre).", "sys"); return; }
    if (x.alice) { say("Alice", "Mon export est corrigé : je n'annonce plus que mon préfixe. On ne refait pas l'erreur."); return; }
    if (x.hij) { say("Alice", "Pas pendant que Mallory joue : demande-lui de `retirer` d'abord (au sud du centre)."); return; }
    if (x.leak) { out("La fuite est déjà active : " + (x.filtOk ? "ton filtre l'arrête de ton côté." : "regarde ce que fait ton routeur : `table`, `tracer " + BANKIP + "`."), "sys"); return; }
    const before = compute(), tb = trace(ME, ip2n(BANKIP), before), nb = (before.recv[ME + ">" + CAFE] || new Set()).size;
    x.leak = true; const res = compute(), t = trace(ME, ip2n(BANKIP), res), nr = (res.recv[ME + ">" + CAFE] || new Set()).size;
    out("Alice « colle » une règle d'export trop large : son routeur retransmet à chaque fournisseur tout ce qu'il a appris de l'autre.", "err");
    code("avant : Café annonce " + nb + " préfixe à Port-443 Net\naprès : Café annonce " + nr + " préfixes à Port-443 Net\nroute de Port-443 vers " + BANKIP + " :\n  avant : " + hopsStr(tb.hops) + "\n  après : " + hopsStr(t.hops) + (res.down.size ? "\n(session avec Café coupée par ta limite)" : "") + (x.filtOk ? "\n(les routes non autorisées sont rejetées par ton filtre)" : ""));
    if (viaCafe(t)) out("Les routes d'un client sont préférées (200 contre 100 pour un pair) : ton routeur envoie maintenant le trafic de la banque par le café, bien que ce chemin soit plus long. Pas d'attaque ici, juste une erreur de politique, et un petit lien qui va saturer.", "err");
    else if (x.filtOk || res.down.size) out("Ton routeur n'est pas affecté : la protection a fonctionné.", "ok");
    const sud = trace(SUD, ip2n("192.0.2.5"), res);
    if (viaCafe(sud)) out("Et ce n'est pas tout : Sud, qui reçoit aussi la fuite par son lien avec Café, envoie désormais le trafic destiné à Port-443 par le café (" + hopsStr(sud.hops) + "). Ton filtre ne protège que ton côté.", "err");
    x.leakSeen = true; note("fuite"); fig("topo");
    out("Protège ton côté : au centre d'exploitation, `filtrer cafe 198.51.100.0/24` ou `limite cafe 3`.", "sys");
  }
  function filtrer(c) {
    const x = F();
    if (S.room !== "noc") { out("Les filtres se posent sur la console du routeur, au centre d'exploitation.", "sys"); return; }
    const a = asIn(c.rawArg.replace(/\d+\.\d+\.\d+\.\d+\/\d+/g, ""));
    if (!a) { out("Quel client ? `filtrer cafe 198.51.100.0/24`", "err"); return; }
    if (a !== CAFE) { out("Tu ne filtres que tes clients. Port-443 Net n'a qu'un client : Café (`filtrer cafe ‹préfixes›`).", "sys"); return; }
    const ps = (c.rawArg.match(/\d+\.\d+\.\d+\.\d+\/\d+/g) || []);
    if (!ps.length) { out("Quels préfixes autoriser ? `filtrer cafe 198.51.100.0/24`", "err"); return; }
    const bad = ps.find(p => !P(p) || !P(p).aligned);
    if (bad) { out("« " + bad + " » n'est pas un préfixe CIDR valide (bits d'hôte non nuls ou format incorrect).", "err"); return; }
    const list = ps.map(p => P(p).str);
    x.filt[ME] = x.filt[ME] || {}; x.filt[ME][CAFE] = list;
    const res = compute(), ownOk = !!res.tab[ME]["198.51.100.0/24"], rj = [...res.rej.values()].filter(e => e.why === "filtre" && e.a === ME);
    out("Filtre posé sur la session avec Café : seuls sont acceptés " + list.join(", ") + " (et leurs sous-préfixes).", "ok");
    if (rj.length) out("Rejetées par le filtre : " + [...new Set(rj.map(e => e.p))].join(", ") + ".", "ok");
    if (!ownOk) { out("Attention : tu as aussi coupé Café lui-même : son préfixe 198.51.100.0/24 n'est pas dans ta liste, donc plus personne ne sait l'atteindre par toi. Un filtre trop strict est une panne. Corrige la liste.", "err"); x.filtOk = false; return; }
    x.filtOk = true; note("filtrage");
    const t = trace(ME, ip2n(BANKIP), res);
    out("Route de Port-443 vers la banque : " + hopsStr(t.hops) + (viaCafe(t) ? " (toujours par le café !)" : " : normale") + ".", viaCafe(t) ? "err" : "ok");
    if (x.leak) out("Ton côté est protégé, mais Alice doit corriger sa configuration : les autres fournisseurs de Café ne filtrent peut-être pas.", "sys");
  }
  function limite(c) {
    const x = F();
    if (S.room !== "noc") { out("Les limites se posent sur la console du routeur, au centre d'exploitation.", "sys"); return; }
    const a = asIn(c.rawArg.replace(/\b\d{1,4}\b/g, ""));
    if (a !== CAFE) { out("`limite cafe ‹nombre›` : le nombre maximum de préfixes que Café peut annoncer.", "err"); return; }
    const m = c.rawArg.replace(/64511/g, "").match(/\b(\d{1,3})\b/), n = m ? +m[1] : 0;
    if (n < 1) { out("Quelle limite ? `limite cafe 3`", "err"); return; }
    x.maxp[ME + ">" + CAFE] = n;
    const res = compute(), k = ME + ">" + CAFE;
    if (res.down.has(k)) {
      x.limTrig = true; note("filtrage");
      out("La session avec Café reçoit " + res.down.get(k) + " préfixes pour une limite de " + n + " : elle est COUPÉE. La fuite est arrêtée de ton côté…", "ok");
      out("…mais Café lui-même est aussi injoignable par toi tant que la session reste coupée : le max-prefix protège, il ne dépanne pas. Un filtre précis (`filtrer cafe …`) est plus fin.", "sys");
    } else out("Limite posée : Café peut annoncer jusqu'à " + n + " préfixes (il en annonce " + ((res.recv[k] || new Set()).size) + " pour l'instant). Au-delà, la session est coupée.", "ok");
  }

  /* ---------- RPKI ---------- */
  function roaCmd() {
    const x = F();
    if (S.room !== "registre") { out("Le Registre est à l'est du centre.", "sys"); return; }
    if (!x.roas.length) { say("Greffier", "Aucune ROA publiée : tous les préfixes sont « inconnus » pour un routeur qui valide."); return; }
    code("ROA publiées\n" + x.roas.map(r => r.pfx.padEnd(16) + "max /" + r.max + "   AS" + r.asn + " (" + NAME[r.asn] + ")   sig " + r.sig).join("\n"));
  }
  function publier(c) {
    const x = F();
    if (S.room !== "registre") { out("Les ROA se publient au Registre (est du centre).", "sys"); return; }
    const m = c.rawArg.match(/(\d+\.\d+\.\d+\.\d+\/\d+)\s+(?:\/)?(\d{1,2})\s+(?:as)?\s*(\d+)/i);
    if (!m) { out("`publier roa ‹préfixe› ‹longueur max› ‹AS›`, par exemple `publier roa " + BANKBLOCK + " 23 64510`.", "err"); return; }
    const pc = P(m[1]), max = +m[2], asn = +m[3];
    if (!pc || !pc.aligned) { say("Greffier", "Ce n'est pas un préfixe valide."); return; }
    const own = ownerOf(pc.str);
    if (!own) { say("Greffier", "Ce bloc n'est à personne dans mon registre : je ne signe pas pour un bloc sans titulaire."); return; }
    if (!NAME[asn]) { say("Greffier", "AS" + asn + " ? Je ne connais pas ce numéro d'AS."); return; }
    if (own === BANK && pc.str !== BANKBLOCK && !contains(P(BANKBLOCK), pc)) { say("Greffier", "Hors du bloc."); return; }
    if (asn !== own) { say("Greffier", "Ce bloc appartient à " + NAME[own] + " (AS" + own + "). Je n'autorise que son titulaire à désigner qui l'annonce : la ROA ne se publie pas pour AS" + asn + " (" + NAME[asn] + ") sans accord du titulaire. (C'est précisément ce que la signature protège.)"); return; }
    if (max < pc.len) { say("Greffier", "La longueur maximale (/" + max + ") ne peut pas être plus courte que le préfixe lui-même (/" + pc.len + ")."); return; }
    if (max > 24) { say("Greffier", "Au-delà de /24, personne n'accepte l'annonce de toute façon : /24 au maximum en IPv4."); return; }
    if (x.roas.some(r => r.pfx === pc.str && r.max === max && r.asn === asn)) { say("Greffier", "Cette ROA est déjà publiée."); return; }
    const sig = sha256("ROA|" + pc.str + "|" + max + "|" + asn).slice(0, 16);
    x.roas.push({ pfx: pc.str, max, asn, sig });
    say("Greffier", "Publié : « " + pc.str + ", jusqu'à /" + max + ", par AS" + asn + " ». Signature du Registre : " + sig + ".");
    if (pc.str === BANKBLOCK && asn === BANK) {
      x.roaBank = true; x.loose = max > pc.len;
      out(x.loose ? "Attention : longueur maximale /" + max + " pour un préfixe /" + pc.len + ". Elle autorise AS64510 à annoncer aussi des /" + max + ", donc elle autorise aussi un attaquant à annoncer un /" + max + " qui cite AS64510 comme origine (voir `valider`). Plus stricte = plus sûre : `retirer roa` puis `publier roa " + BANKBLOCK + " 23 64510`." : "ROA stricte : seul le /23 exact, par la banque, est valide.", x.loose ? "err" : "ok");
    }
  }
  function valider(c) {
    const x = F();
    if (S.room !== "registre") { out("Le Greffier est au Registre (est du centre).", "sys"); return; }
    const m = c.rawArg.match(/(\d+\.\d+\.\d+\.\d+\/\d+)\s+(?:as)?\s*(\d+)/i);
    if (!m || !P(m[1])) { out("`valider ‹préfixe› ‹AS›`, par exemple `valider 203.0.113.0/24 64510` : la même chose qu'un routeur calcule pour chaque annonce.", "err"); return; }
    const pf = P(m[1]).str, asn = +m[2], v = validate(pf, asn);
    code("annonce testée : " + pf + " (/" + P(pf).len + ")  origine AS" + asn + (NAME[asn] ? " (" + NAME[asn] + ")" : "") + "\nROA qui couvrent le préfixe : " + (v.cov.length ? "\n" + v.cov.map(r => "  " + r.pfx + " max /" + r.max + " AS" + r.asn + " -> " + (r.asn === asn ? "AS ok" : "AS différent") + ", longueur " + (P(pf).len <= r.max ? "ok" : "trop longue")).join("\n") : "aucune") + "\n=> " + v.st.toUpperCase() + (v.st === "invalide" ? "  (" + (v.why === "longueur" ? "longueur dépasse la longueur maximale" : "l'origine ne correspond à aucune ROA") + ")" : ""));
    if (v.st === "inconnu") { out("Inconnu : aucune ROA ne couvre ce préfixe. Un routeur ne peut ni l'accepter par confiance ni le rejeter : il ne sait pas.", "sys"); x.vU = true; }
    else if (v.st === "valide") { out("Valide : une ROA couvre ce préfixe, avec la bonne origine et une longueur permise.", "ok"); x.vV = true; }
    else { out("Invalide : un routeur qui rejette les invalides refusera cette annonce.", "err"); x.vI = true; }
    if (x.vV && x.vI && !x.noteR) { x.noteR = true; note("rpki"); fig("roa"); }
  }
  function rovCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "noc") { out("Le réglage de la validation se fait au centre d'exploitation.", "sys"); return; }
    const MODES = { off: "désactivée", log: "observer (journaliser seulement)", drop: "rejeter les invalides" };
    if (!t) {
      const res = compute();
      code("validation d'origine (ROV)\n" + ASN.filter(a => a !== MAL).map(a => NAME[a].padEnd(9) + (MODES[x.rov[a] || "off"])).join("\n") + (res.logs.size ? "\njournal de Port-443 : " + res.logs.size + " annonce(s) invalide(s) vue(s) et ACCEPTÉE(S)" : ""));
      out("`rov observer` · `rov rejeter` · `rov demander ‹AS›` (convaincre un autre réseau).", "sys"); return;
    }
    const dem = t.match(/^demander\s+(.+)/);
    if (dem) {
      const a = asOf(dem[1]);
      if (!a || a === ME) { out("`rov demander nord` (ou sud, regio, cafe, banque).", "err"); return; }
      if (a === MAL) { say("Mallory", "Ha. Non. Mon routeur ne rejette rien du tout."); return; }
      if (x.rov[ME] !== "drop") { say("Maître Ada", "On ne demande pas aux autres ce qu'on ne fait pas soi-même : active d'abord `rov rejeter` chez toi."); return; }
      x.rov[a] = "drop";
      out(NAME[a] + " accepte de rejeter les annonces invalides. (Dans la vraie vie : des mois de projet, un opérateur à la fois, et chaque AS décide pour lui.)", "ok");
      if (a === NORD && x.hij) out("L'annonce de Mallory vient de Nord : elle est maintenant rejetée dès l'entrée. Relance `couverture`.", "sys");
      return;
    }
    const v = /rejeter|drop|refuser|bloquer/.test(t) ? "drop" : /observer|journal|log|surveiller/.test(t) ? "log" : /desactiver|off|arreter/.test(t) ? "off" : /activer/.test(t) ? "ask" : null;
    if (v === "ask") { out("Activer, oui, mais comment ? `rov observer` : tu journalises les invalides sans les écarter (prudent au début, mais inefficace) ; `rov rejeter` : tu les écartes.", "sys"); return; }
    if (!v) { out("`rov observer`, `rov rejeter`, `rov desactiver`, ou `rov demander ‹AS›`.", "err"); return; }
    if (v !== "off" && !x.roas.length) { out("Aucune ROA n'est publiée : tout est « inconnu », la validation ne pourrait rien rejeter. Publie d'abord des ROA au Registre.", "sys"); }
    x.rov[ME] = v; out("Validation d'origine de Port-443 : " + MODES[v] + ".", "ok");
    if (v === "log") out("Tu verras les invalides dans `rov`, mais ils restent acceptés : l'attaque réussit quand même. Pour protéger, il faut rejeter.", "sys");
    if (v === "drop") out("Dès maintenant, toute annonce invalide reçue par ton routeur est écartée avant de rejoindre ta table.", "sys");
  }
  function surveiller() {
    const x = F();
    if (S.room !== "obs") { out("L'observatoire est au nord du centre d'exploitation.", "sys"); return; }
    const res = compute(), al = new Map();
    const dir = (u, v) => { const r = rel(u, v); return r === "fournisseur" ? "up" : r === "client" ? "down" : "flat"; };
    COLLECTORS.forEach(cl => Object.entries(res.tab[cl]).forEach(([p, r]) => {
      if (r.from === null) return;
      const origin = r.path[r.path.length - 1], own = ownerOf(p), hops = [cl].concat(r.path);
      if (origin !== own) al.set("o|" + p + "|" + origin, "origine inattendue : " + p + " annoncé par " + NAME[origin] + ", titulaire connu : " + NAME[own] + (P(p).len > 23 && own === BANK ? " (sous-préfixe)" : ""));
      let phase = 0, vf = true, unknown = false;
      for (let i = 0; i < hops.length - 1; i++) {
        if (!rel(hops[i], hops[i + 1])) { unknown = true; al.set("a|" + hops[i] + "|" + hops[i + 1], "chemin suspect : « " + pathStr(r.path) + " » contient l'adjacence " + NAME[hops[i]] + "–" + NAME[hops[i + 1]] + ", absente de la base des relations connues"); continue; }
        const d = dir(hops[i], hops[i + 1]);
        if (d === "up") { if (phase > 0) vf = false; } else if (d === "flat") { if (phase > 0) vf = false; phase = 1; } else phase = 2;
      }
      if (!vf && !unknown) al.set("l|" + hops.join(), "fuite probable : le chemin « " + pathStr(r.path) + " » (vu par " + NAME[cl] + ") redescend puis remonte : un client retransmet d'un fournisseur à l'autre");
    }));
    out("Ève ouvre le tableau de bord des collecteurs (vus par Nord, Sud, Régio). Alertes :", "sys");
    code(al.size ? [...al.values()].map(s => "! " + s).join("\n") : "(aucune anomalie : toutes les annonces vues ont l'origine attendue et un chemin plausible)");
    if (al.size) out("Ces alertes ne bloquent rien : elles préviennent des humains, qui pourront appeler le fournisseur fautif, ou, mieux, rejeter l'annonce.", "ok");
    if (x.hij && x.hij.forge && [...al.keys()].some(k => k.startsWith("a|"))) {
      if (!x.mon) { x.mon = true; note("limites"); fig("roa"); out("Voilà ce qu'aucune ROA ne verra : l'origine est la bonne, le MENSONGE est dans le chemin. Seule une surveillance qui connaît les vraies adjacences (ou ASPA, qui les rend vérifiables) le repère.", "ok"); }
    } else if (!al.size && x.hij && x.hij.forge) out("Aucune alerte : l'annonce forgée n'est pas arrivée jusqu'aux collecteurs.", "sys");
    else if (x.hij && !x.hij.forge) out("Détourné et visible : un détournement ordinaire se voit tout de suite dans les annonces publiques. Le forger pour imiter l'origine, c'est la suite.", "sys");
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Tu as vu des annonces se propager, des chemins se choisir selon des politiques, un /24 plus fort qu'un /23, un trafic détourné vers Mallory, une fuite née d'une simple erreur de copier-coller. Et tu as posé les défenses : filtrer tes clients, publier des ROA strictes, rejeter les invalides, obtenir que ton fournisseur en fasse autant, surveiller.");
    say("Maître Ada", "Retiens la dernière leçon : la RPKI vérifie qui a le droit d'annoncer un préfixe, pas par où passe le chemin. Il faut ASPA et la surveillance pour couvrir le reste, et tout cela ne vaut que s'il est adopté. Internet reste une confiance partagée, qu'on remplace peu à peu par de la preuve.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Les réseaux de la carte = les systèmes autonomes (AS).** Chaque AS a un numéro (ASN) et des blocs d'adresses ; Nord et Sud jouent les transitaires (fournisseurs d'accès à Internet pour les autres), Régio un opérateur régional, la banque et le café des clients qui paient pour être joignables. Les AS s'échangent des annonces avec BGP, le protocole de routage entre réseaux : « je sais atteindre ce préfixe, par ce chemin d'AS ».");
    out("**La propagation pas à pas = les messages UPDATE de BGP.** Chaque AS ajoute son numéro en tête du chemin (AS_PATH) et retransmet. Pour un même préfixe, un routeur choisit selon la préférence locale (une politique de l'opérateur : on préfère ce qui rapporte, client, à ce qui est gratuit, pair, à ce qui coûte, fournisseur), puis le chemin d'AS le plus court, puis des critères de départage. Les règles « valley-free » (gagner de l'argent avec ses clients, ne pas servir de transit gratuit à ses pairs et fournisseurs) donnent à Internet sa forme de colline.");
    out("**Le plus long préfixe = la règle de la table de routage.** Avant de comparer des chemins, le routeur retient, parmi les routes qui couvrent l'adresse, celle dont le préfixe est le plus long. Les /24 sont la limite pratique en IPv4 : au-delà, les annonces sont généralement filtrées.");
    out("**Mallory = un détournement de préfixe (BGP hijack).** Une annonce du même préfixe n'est suivie que par les AS dont les politiques la préfèrent ; une annonce d'un sous-préfixe l'emporte partout où elle est acceptée. C'est le scénario de l'incident célèbre de 2008, où un opérateur annonça un /24 de YouTube pour le bloquer chez lui mais l'annonce déborda de son pays : YouTube resta injoignable pour une grande partie du monde pendant environ deux heures. Le trafic capté peut être jeté, relayé ou terminé. TLS limite les dégâts : le certificat de la banque ne peut pas être présenté par Mallory. Mais l'attaque touche aussi les protocoles plus faibles que TLS (DNS, courrier, mises à jour sans signature).");
    out("**Alice = une fuite de routes.** Un client multi-hébergé qui retransmet à un fournisseur ce qu'il a appris d'un autre. Les routes de clients étant préférées, le trafic de grands réseaux s'engouffre dans de petits liens : c'est arrivé plusieurs fois, y compris à de grands opérateurs, par simple erreur de configuration.");
    out("**Le filtrage des clients = prefix-list et max-prefix.** C'est la défense la plus ancienne et la plus efficace : un fournisseur n'accepte d'un client que les préfixes qu'il a le droit d'annoncer, et coupe la session si leur nombre explose. Coût : il faut maintenir les listes (souvent à partir des registres) ; limite : chaque fournisseur ne protège que les siens.");
    out("**Le Greffier = la RPKI.** Les titulaires de ressources reçoivent un certificat de leur registre régional, et signent des ROA (préfixe, longueur maximale, AS autorisé). Un routeur qui valide l'origine (RFC 6811) classe chaque annonce valide, invalide ou inconnue, puis applique une politique : en général, rejeter les invalides. La longueur maximale compte : trop large, elle laisse passer des sous-préfixes forgés.");
    out("**Ève = la surveillance publique.** Des collecteurs reçoivent les tables de nombreux réseaux ; des services comparent origines, sous-préfixes et adjacences avec ce qu'ils savent. Elle ne bloque rien mais permet de réagir vite.");
    out("**Les simplifications du jeu.** (1) Un AS est un seul routeur : pas de BGP interne (iBGP), pas de multiples liens ; en vrai un AS peut avoir des dizaines de points de contact, des routes différentes pour des routeurs différents. (2) Préférence locale fixée par la relation ; les vrais opérateurs la règlent librement, avec aussi MED, communautés, politiques de transit sélectives. Le départage final par le plus petit numéro de voisin est une commodité : en vrai, c'est l'identifiant du routeur, l'ancienneté de la route… (3) Propagation en tours synchrones, sans minuteries ni délais de convergence. (4) Les préfixes sont de la documentation et des plages privées, pas de routes par défaut, pas d'agrégation, IPv4 seul, filtre implicite à /24. (5) Le relais de Mallory suppose une route de sortie vers la vraie banque qui ne repasse pas par elle ; elle existe en pratique (préfixes forgés, chemins plus longs ou statiques), mais c'est tout un art. (6) Les ROA du jeu sont signées par un hachage simple, pas la vraie chaîne de certificats des registres régionaux ; le Greffier fait aussi office de dépôt, de validateur et de cache. Le déploiement réel est partiel : beaucoup de grands réseaux valident, d'autres non, et c'est toute la difficulté. (7) Le certificat TLS jouet est un hachage : la vérification de la signature, la chaîne, la révocation et la transparence sont absentes. (8) Un attaquant peut aussi utiliser un détournement pour obtenir un vrai certificat auprès d'une autorité qui vérifie la possession d'un domaine par le réseau : d'où les validations depuis plusieurs points de vue, que le jeu ne montre pas.");
    out("Rappel utile : **BGP croit ses voisins sur parole. Filtre tes clients, signe tes préfixes (ROA strictes), rejette les invalides, surveille les annonces, garde TLS strict, et sache que la RPKI ne protège pas le chemin.**", "ok");
  }

  /* ---------- schémas ---------- */
  const POS = { [NORD]: [82, 34], [SUD]: [345, 34], [MAL]: [40, 122], [ME]: [125, 122], [REG]: [240, 122], [BANK]: [362, 122], [CAFE]: [240, 206] };
  const seg = (a, b, cls, arrow, k) => {
    const [x1, y1] = POS[a], [x2, y2] = POS[b], dx = x2 - x1, dy = y2 - y1, l = Math.hypot(dx, dy), ux = dx / l, uy = dy / l, s = k || 24;
    const q = n => Math.round(n);
    return (arrow ? AR : LN)(q(x1 + ux * s), q(y1 + uy * s * 0.8), q(x2 - ux * s), q(y2 - uy * s * 0.8), cls);
  };
  function topoFig() {
    const x = F(), res = compute(), ip = ip2n(BANKIP);
    let body = "";
    C2P.forEach(([p, c]) => body += seg(p, c, ""));
    P2P.forEach(([u, v]) => body += seg(u, v, "f-dash"));
    ASN.forEach(a => {
      let cls = "";
      if (a === BANK) cls = "f-pub"; else if (a === MAL) cls = "f-priv";
      else { const t = trace(a, ip, res); cls = t.fate === "bank" ? "f-ok" : t.fate === "mallory" ? "f-bad" : ""; }
      const [cx, cy] = POS[a];
      body += R(cx - 38, cy - 17, 76, 34, cls) + T(cx, cy - 1, NAME[a], "f-b") + T(cx, cy + 12, "AS" + a, "f-s");
    });
    const t = trace(ME, ip, res);
    for (let i = 0; i < t.hops.length - 1; i++) body += seg(t.hops[i], t.hops[i + 1], t.fate === "mallory" ? "f-bad" : "f-ok", true, 26);
    body += T(210, 240, "Chemin de Port-443 vers " + BANKIP + " :", "f-s") + T(210, 258, hopsStr(t.hops) + (t.fate === "mallory" ? "  (chez Mallory !)" : ""), "f-b" + (t.fate === "mallory" ? " ft-bad" : " ft-ok"));
    body += T(8, 288, "plein : fournisseur au-dessus · tirets : pairs", "f-s", "start");
    body += T(8, 304, "vert : atteint la banque · rouge : trafic capté", "f-s", "start");
    return {
      cap: "Les sept AS de Port-443, leurs relations, et ce que chacun fait du trafic vers le serveur de la banque (vert : arrive chez elle ; rouge : capté par Mallory). La flèche montre le chemin choisi par Port-443." + (x.leak ? " (Une fuite est en cours.)" : ""),
      svg: SVG(316, "Topologie des AS et chemins choisis", body),
    };
  }
  function plusFig() {
    const x = F(), ip = x.lastIp != null ? x.lastIp : ip2n(BANKIP), res = compute();
    const rows = Object.entries(res.tab[ME]).map(([p, r]) => ({ p, r, c: P(p) })).filter(e => covers(e.c, ip)).sort((u, v) => v.c.len - u.c.len);
    let body = T(8, 18, "Destination " + n2ip(ip), "f-b", "start") + T(8, 36, bits(ip).replace(/(.{8})(?=.)/g, "$1."), "f-s", "start");
    rows.slice(0, 4).forEach((e, i) => {
      const y = 52 + i * 44, bad = e.r.path.length ? e.r.path[e.r.path.length - 1] === MAL : false, w = Math.round(250 * e.c.len / 32);
      body += T(8, y + 12, e.p, "f-b" + (i === 0 ? "" : ""), "start") + T(8, y + 30, e.r.from === null ? "(local)" : "via " + pathStr(e.r.path), "f-s", "start") +
        R(150, y, w, 18, i === 0 ? (bad ? "f-bad" : "f-ok") : "") + T(150 + w + 6, y + 13, "/" + e.c.len, "f-s", "start") + (i === 0 ? T(150, y + 34, "▲ le plus long préfixe : retenue", "f-s " + (bad ? "ft-bad" : "ft-ok"), "start") : "");
    });
    if (!rows.length) body += T(210, 90, "aucune route ne couvre cette adresse", "f-b");
    const h = 62 + Math.max(1, Math.min(4, rows.length)) * 44 + 24;
    body += T(210, h - 6, "avant toute comparaison de chemin ou de préférence", "f-s");
    return { cap: "Le routeur retient, parmi les routes qui couvrent l'adresse, celle qui a le plus de bits en commun avec elle : le plus long préfixe. Un détournement par sous-préfixe exploite exactement ça.", svg: SVG(h + 4, "Plus long préfixe", body) };
  }
  function roaFig() {
    const x = F();
    let body = T(8, 18, "ROA publiées", "f-b", "start"), y = 36;
    if (!x.roas.length) { body += T(8, y + 4, "(aucune : tout est « inconnu »)", "f-s", "start"); y += 22; }
    x.roas.forEach(r => { body += T(8, y + 4, r.pfx + "  max /" + r.max + "  AS" + r.asn, "f-s", "start"); y += 18; });
    y += 14; body += T(8, y, "Annonces vues pour ce bloc", "f-b", "start"); y += 16;
    const L = anns().filter(e => contains(P(BANKBLOCK), P(e.pfx)));
    L.forEach(e => {
      const orig = e.path.length ? e.path[e.path.length - 1] : e.as, v = validate(e.pfx, orig), cls = v.st === "valide" ? "f-ok" : v.st === "invalide" ? "f-bad" : "";
      body += R(8, y, 404, 40, cls) + T(16, y + 17, e.pfx + "  origine AS" + orig + (e.as === MAL ? " (chemin Mallory" + (e.path.length ? " Banque)" : ")") : ""), "f-s", "start") +
        T(16, y + 33, (v.st === "valide" ? "VALIDE" : v.st === "invalide" ? "INVALIDE (" + (v.why === "longueur" ? "longueur" : "origine") + ")" : "INCONNU"), "f-b " + (v.st === "valide" ? "ft-ok" : v.st === "invalide" ? "ft-bad" : ""), "start");
      y += 48;
    });
    body += T(210, y + 8, "valide = couvert + longueur ≤ max + origine = AS autorisé", "f-s") + T(210, y + 26, "ne regarde que le DERNIER AS du chemin : le reste est libre", "f-s");
    return { cap: "Validation d'origine : chaque annonce est comparée aux ROA. Valide, invalide ou inconnue. Une annonce « Mallory Banque » a pour origine la banque : valide, bien que fausse.", svg: SVG(y + 40, "Validation d'origine par ROA", body) };
  }
  function relFig() {
    const body =
      T(8, 18, "Qui reçoit quoi (règles d'export) :", "f-b", "start") +
      R(8, 28, 404, 44, "f-ok") + T(16, 46, "route apprise d'un CLIENT", "f-b", "start") + T(16, 64, "→ annoncée à tous (clients, pairs, fournisseurs)", "f-s", "start") +
      R(8, 80, 404, 44, "f-pub") + T(16, 98, "route apprise d'un PAIR ou d'un FOURNISSEUR", "f-b", "start") + T(16, 116, "→ annoncée à mes clients seulement", "f-s", "start") +
      T(8, 150, "Préférence locale (qui choisir en premier) :", "f-b", "start") +
      R(8, 160, 130, 36, "f-ok") + T(73, 176, "client : 200", "f-b") + T(73, 190, "il me paie", "f-s") +
      R(145, 160, 130, 36) + T(210, 176, "pair : 100", "f-b") + T(210, 190, "gratuit", "f-s") +
      R(282, 160, 130, 36, "f-bad") + T(347, 176, "fournisseur : 50", "f-b") + T(347, 190, "je le paie", "f-s") +
      T(210, 222, "chemin valley-free : monter (vers fournisseurs),", "f-s") + T(210, 238, "au plus un pas de côté (pair), puis descendre", "f-s") +
      T(210, 258, "Fuite = descendre, puis remonter", "f-s ft-bad");
    return { cap: "Relations client, fournisseur et pair : elles décident quelles routes sont transmises, et lesquelles sont préférées. C'est de l'économie avant d'être de la géographie.", svg: SVG(268, "Relations client fournisseur pair", body) };
  }
  const figs = { topo: topoFig, plus: plusFig, roa: roaFig, relations: relFig };

  GAMES.bgp = {
    id: "bgp", order: 33, title: "Les Routes de Port-443", pageTitle: "BGP Quest", subtitle: "aventure textuelle · BGP et RPKI",
    blurb: "Dirige un AS : vois les chemins se choisir, un préfixe se faire détourner, une fuite se produire, puis pose les défenses.",
    concept: "BGP : routage entre réseaux, détournement de préfixes, RPKI",
    start: "noc", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.hij = null; x.roas = []; x.rov = {}; x.filt = {}; x.maxp = {}; x.leak = false; x.mode = "trou"; x.tls = "strict"; x.lpmW = {}; x.vis = {}; },
    refig(name) { fig(name); },
    figAlias: { topo: ["carte", "topologie", "reseau", "chemins", "as"], plus: ["lpm", "prefixe", "longprefixe", "detournement"], roa: ["rpki", "validation", "origine"], relations: ["regles", "relation", "valley", "client", "pair"] },
    help: "Spécifiques : `table` · `route ‹ip›` · `propager ‹préfixe›` · `tracer ‹ip› [depuis ‹AS›]` · `couverture` · `visiter banque` · `tls ‹strict|laxiste›` · `filtrer cafe ‹préfixes›` · `limite cafe ‹n›` · `rov ‹rejeter|observer›` · `detourner ‹préfixe›` · `mode ‹…›` · `retirer` · `fuite` · `publier roa ‹préfixe› ‹max› ‹AS›` · `roa` · `valider ‹préfixe› ‹AS›` · `surveiller`",
    verbs: {
      table: { words: ["table", "rib", "routes"], run: tableCmd },
      route: { words: ["route", "chercher", "lookup"], run: route },
      propager: { words: ["propager", "diffuser", "propagation"], run: propager },
      tracer: { words: ["tracer", "traceroute", "suivre"], run: tracer },
      couverture: { words: ["couverture", "portee", "impact"], run: couverture },
      detourner: { words: ["detourner", "hijack", "usurper"], run: detourner },
      retirer: { words: ["retirer", "annuler", "stopper"], run: retirer },
      mode: { words: ["mode"], run: modeCmd },
      visiter: { words: ["visiter", "surfer", "connecter"], run: visiter },
      tls: { words: ["tls", "navigateur"], run: tlsCmd },
      fuite: { words: ["fuite", "fuiter"], run: fuite },
      filtrer: { words: ["filtrer", "filtre"], run: filtrer },
      limite: { words: ["limite", "limiter"], run: limite },
      roa: { words: ["roa", "roas"], run: roaCmd },
      publier: { words: ["publier"], run: publier },
      valider: { words: ["valider", "classer"], run: valider },
      rov: { words: ["rov"], run: rovCmd },
      surveiller: { words: ["surveiller", "alertes", "monitorer"], run: surveiller },
    },
    intro() {
      out("Les Routes de Port-443", "title");
      out("Aucun réseau ne connaît tout Internet : chacun connaît ses voisins, et croit ce qu'ils lui annoncent. Tu diriges l'exploitation réseau de Port-443 Net (AS64500), un petit opérateur entre des fournisseurs, un pair, un café, et la banque de la ville. Maître Ada supervise un audit autorisé : voir comment les chemins se choisissent, ce que peut faire une annonce mensongère (celle de Mallory) ou une erreur (celle d'Alice), et comment s'en protéger. Tout est simulé.", "");
    },
  };
})();
