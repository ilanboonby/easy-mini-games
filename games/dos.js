"use strict";
/* Le Siège de Port-443 : déni de service, compris et défendu dans un simulateur jouet de capacité.
   Tout est en requêtes par seconde (chiffres jouets) ; le simulateur est déterministe, pas de hasard. */
(function () {
  const F = () => f();

  /* ---------- le simulateur ---------- */
  const NS = 12, DT = 5;                       // 12 pas de 5 secondes
  const CAP = { bw: 1000, q: 256, conn: 300, cpu: 400, db: 200 };
  const CDN_BW = 6000, SYN_TO = 5, INST_CPU = 150, LAG = 2, THRASH = 0.75;
  const COST = { cache: 5, cdn: 80, queue: 3, amont: 40, inst: 20 };
  const LEG = { groups: [{ n: 338, per: 0.5 }, { n: 1, per: 16 }], total: 185, mix: { page: 140, rech: 40, rel: 5 }, slots: 12, held: 74, vitrine: 40, wv: 0.5 };
  const KC = { page: { cpu: 1, db: 0 }, rech: { cpu: 3, db: 2 }, rel: { cpu: 12, db: 5 } };
  const KD = { page: { cpu: 0.6, db: 0 }, rech: { cpu: 1, db: 0.2 }, rel: { cpu: 0, db: 0 } };
  const CREDIT = { page: 1, rech: 0.7, rel: 0.3 };
  const ATK = 110, FACTOR = 28, OPEN = { relais: 28, annuaire: 40 };
  const THRESH = 0.88;

  const syn = (a, b, rate) => t => (t >= a && t < b) ? [{ cls: "syn", rate, target: "banque", bw: 0.1, groups: [{ n: rate, per: 1 }] }] : [];
  const refl = (a, b) => t => (t >= a && t < b) ? [{ cls: "refl", rate: ATK * FACTOR, target: "vitrine", bw: 1, groups: [{ n: 2000, per: ATK * FACTOR / 2000 }] }] : [];
  const app = (a, b, sw) => t => (t < a || t >= b) ? [] : [t < sw ? { cls: "app", rate: 400, target: "banque", bw: 1, groups: [{ n: 10, per: 40 }] } : { cls: "app", rate: 200, target: "banque", bw: 1, groups: [{ n: 400, per: 0.5 }] }];
  const slow = (a, b) => t => (t >= a && t < b) ? [{ cls: "slow", rate: 14, open: 14, max: 280, age: (t - a + 1) * DT, target: "banque", bw: 0.01, groups: [] }] : [];
  const all = (...fs) => t => fs.flatMap(g => g(t));
  const WAVES = {
    1: { name: "La foule qui ne conclut jamais", type: "protocolaire", stream: syn(2, 12, 600) },
    2: { name: "Le tonnerre des échos", type: "volumétrique, par réflexion", stream: refl(2, 10) },
    3: { name: "Les curieux insatiables", type: "applicative", stream: app(2, 12, 6) },
    4: { name: "Les clients qui prennent leur temps", type: "applicative lente", stream: slow(1, 12) },
    final: { name: "Le grand siège", type: "combiné", stream: all(slow(1, 12), syn(2, 12, 500), refl(3, 9), app(4, 12, 8)) },
  };
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  function stepSim(w, t, c, st) {
    const hostile = w.stream(t);
    st.inst += st.pend.filter(v => v === t).length; st.pend = st.pend.filter(v => v > t);
    const cdn = !!c.cdn;
    const legB = c.hole === "banque" ? 0 : LEG.total, legV = c.hole === "vitrine" ? 0 : LEG.vitrine;
    const hs = hostile.filter(s => s.target !== c.hole && !(s.cls === "refl" && c.amont));
    const hostIn = hostile.reduce((a, s) => a + s.rate, 0);
    // 1. bande passante (tuyau partagé par la banque et la vitrine)
    const bwLoad = legB + legV + hs.reduce((a, s) => a + s.rate * s.bw, 0);
    const capBw = cdn ? CDN_BW : CAP.bw;
    const pbw = Math.min(1, capBw / Math.max(1, bwLoad));
    // 2. file des connexions semi-ouvertes (jamais atteinte avec CDN : le bord termine les poignées de main)
    const synR = hs.filter(s => s.cls === "syn").reduce((a, s) => a + s.rate * pbw, 0);
    const occ = (c.cookies || cdn) ? 0 : synR * SYN_TO;
    const pq = clamp((CAP.q - occ) / LEG.slots, 0, 1);
    // 3. places de connexion tenues par les clients lents
    let held = 0;
    hs.filter(s => s.cls === "slow").forEach(s => { held += Math.min(s.max, s.open * Math.min(c.delai || 1e9, s.age)); });
    if (cdn) held = 0;
    const pconn = clamp((CAP.conn - held) / LEG.held, 0, 1);
    // 4. limitation de débit par adresse (requêtes HTTP seulement, après la poignée de main)
    const lim = c.limit || 0;
    const gp = g => lim ? g.n * Math.min(g.per, lim) : g.n * g.per;
    const legPass = legB ? LEG.groups.reduce((a, g) => a + gp(g), 0) : 0;
    const legLimLost = legB - legPass;
    const legEff = legPass * pbw * pq * pconn;
    const apps = hs.filter(s => s.cls === "app");
    const appRate = apps.reduce((a, s) => a + s.groups.reduce((b, g) => b + gp(g), 0) * pbw, 0);
    // 5. travail demandé à l'origine (cache et CDN ôtent une partie)
    const hit = { page: cdn ? 0.9 : c.cache ? 0.6 : 0, rech: c.cache ? 0.5 : 0, rel: 0 }, hitH = c.cache ? 0.05 : 0;
    const rk = {}; Object.keys(LEG.mix).forEach(k => rk[k] = legEff * LEG.mix[k] / LEG.total);
    const synCpu = (c.cookies && !cdn) ? synR * 0.05 : 0;
    const demand = tbl => {
      let cpu = synCpu, db = 0;
      Object.keys(rk).forEach(k => { cpu += rk[k] * (1 - hit[k]) * tbl[k].cpu; db += rk[k] * (1 - hit[k]) * tbl[k].db; });
      cpu += appRate * (1 - hitH) * tbl.rech.cpu; db += appRate * (1 - hitH) * tbl.rech.db;
      return { cpu, db };
    };
    const capCpu0 = CAP.cpu + INST_CPU * st.inst;
    let d = demand(KC), degr = false;
    if (c.degrade && (d.cpu > capCpu0 || d.db > CAP.db)) { d = demand(KD); degr = true; }
    const over = d.cpu > capCpu0 || d.db > CAP.db;
    const f_ = over && !c.queue ? THRASH : 1;
    const pc = d.cpu > 0 ? Math.min(1, capCpu0 * f_ / d.cpu) : 1, pd = d.db > 0 ? Math.min(1, CAP.db * f_ / d.db) : 1;
    const pk = { page: pc, rech: Math.min(pc, pd), rel: Math.min(pc, pd) };
    let servedB = 0;
    Object.keys(rk).forEach(k => { servedB += rk[k] * (hit[k] + (1 - hit[k]) * pk[k]) * (degr ? CREDIT[k] : 1); });
    const servedV = legV * pbw;
    const avail = (servedB + LEG.wv * servedV) / (LEG.total + LEG.wv * LEG.vitrine);
    // autoscaling : démarre un serveur si le processeur dépasse 85 %, disponible deux pas plus tard
    const cpuU = d.cpu / capCpu0;
    if (c.scale > 0 && cpuU > 0.85 && st.inst + st.pend.length < c.scale) st.pend.push(t + LAG);
    const cost = (c.cache ? COST.cache : 0) + (cdn ? COST.cdn : 0) + (c.queue ? COST.queue : 0) + (c.amont ? COST.amont : 0) + st.inst * COST.inst;
    const hostPass = hs.reduce((a, s) => a + (s.cls === "refl" ? (cdn ? 0 : s.rate * pbw) : s.cls === "syn" ? (c.cookies || cdn ? 0 : s.rate * pbw) : s.cls === "slow" ? (cdn ? 0 : Math.min(s.max, s.open * Math.min(c.delai || 1e9, s.age))) : 0), 0) + appRate;
    return {
      t, hostIn, hostPass, legOff: LEG.total + LEG.vitrine, avail, degr, inst: st.inst, cost, lost: legLimLost,
      util: { bw: bwLoad / capBw, q: (occ + LEG.slots) / CAP.q, conn: (held + LEG.held) / CAP.conn, cpu: cpuU, db: d.db / CAP.db },
    };
  }
  function simulate(wid, cfg) {
    const w = WAVES[wid], st = { inst: 0, pend: [] }, steps = [];
    for (let t = 0; t < NS; t++) steps.push(stepSim(w, t, cfg, st));
    const peak = { bw: 0, q: 0, conn: 0, cpu: 0, db: 0 };
    steps.forEach(s => Object.keys(peak).forEach(k => { peak[k] = Math.max(peak[k], s.util[k]); }));
    const avail = steps.reduce((a, s) => a + s.avail, 0) / NS, cost = steps.reduce((a, s) => a + s.cost, 0);
    const lost = steps.reduce((a, s) => a + s.lost, 0) / (NS * LEG.total);
    return { wid, steps, peak, avail, cost, lost, ok: avail >= THRESH, degr: steps.some(s => s.degr), minAvail: Math.min(...steps.map(s => s.avail)) };
  }
  const RES = { bw: "la bande passante", q: "la file des connexions semi-ouvertes", conn: "les places de connexion du serveur", cpu: "le processeur", db: "la base de données" };
  const RESU = { bw: "Bande passante", q: "File SYN", conn: "Connexions", cpu: "Processeur", db: "Base de données" };
  const saturated = r => Object.keys(r.peak).filter(k => r.peak[k] > 1.0);
  const pct = v => String(Math.round(v * 100)).padStart(5) + "%";
  const money = v => Math.round(v).toLocaleString("fr-FR") + " €";
  const num = v => Math.round(v).toLocaleString("fr-FR");
  const fixedCost = c => (c.cache ? COST.cache : 0) + (c.cdn ? COST.cdn : 0) + (c.queue ? COST.queue : 0) + (c.amont ? COST.amont : 0);
  const newCfg = () => ({ cookies: false, cache: false, cdn: false, queue: false, degrade: false, scale: 0, limit: 0, delai: 0, amont: false, hole: null });
  const ownOK = () => { const x = F(); return !!(x.audited && x.closed && x.closed.relais && x.closed.annuaire && x.antispoof); };
  const lawAns = { 1: "illegal", 2: "legal", 3: "illegal", 4: "illegal", 5: "legal" };
  const lawDone = () => { const l = F().law || {}; return Object.keys(lawAns).every(k => l[k]); };

  /* ---------- carnet ---------- */
  const notes = {
    types: ["Trois familles de déni de service", "Un déni de service (DoS) épuise une ressource pour que les vrais clients ne passent plus ; distribué (DDoS), il vient de milliers de sources, donc on ne peut pas simplement bloquer « l'attaquant ». Volumétrique : on remplit le tuyau (bande passante). Protocolaire : on épuise les tables d'état de la pile réseau (file de connexions semi-ouvertes) avec très peu de débit. Applicative : des requêtes d'apparence légitime visent un point coûteux (recherche, génération) : processeur, base de données, places de connexion. À chaque famille sa ressource saturée, donc sa parade : on ne soigne pas un tuyau plein en ajoutant des processeurs."],
    file: ["La file de connexions et les SYN cookies", "Une connexion TCP s'ouvre en trois temps : SYN, SYN-ACK, ACK. Entre le 2e et le 3e, le serveur garde une entrée « semi-ouverte » dans une file de taille finie, pendant un délai (5 s ici). Si les SYN arrivent plus vite que la file ne se vide (débit × délai > taille : 600 × 5 = 3 000 places demandées pour 256), elle est pleine et les nouveaux clients, légitimes compris, sont refusés. Avec les SYN cookies, le serveur ne réserve rien : il encode l'état dans le numéro de séquence du SYN-ACK et ne recrée la connexion que si l'ACK correct revient. Les adresses usurpées ne répondent jamais : leur entrée disparaît. Limites : un peu de calcul, quelques options TCP perdues, et rien contre une inondation qui remplit le tuyau."],
    amplification: ["Réflexion et amplification (en chiffres jouets)", "Réflexion : l'attaquant envoie de petites requêtes à un service ouvert à tous en y mettant comme adresse d'origine celle de la victime (usurpation) ; le service répond à la victime. Amplification : la réponse est plus grosse que la requête (facteur 28 ici : 110 requêtes/s deviennent 3 080 réponses/s). La victime voit des milliers de sources innocentes, jamais l'attaquant : bloquer par adresse est vain. Parades : le filtrage à l'entrée (anti-usurpation, BCP 38 : un réseau ne laisse sortir que des paquets dont la source est dans ses propres adresses), fermer ou restreindre les services ouverts à Internet (ou limiter la taille de leurs réponses), et, pour la victime, le filtrage en amont."],
    amont: ["Filtrage amont et trou noir", "Le fournisseur d'accès voit le trafic AVANT ton tuyau : il peut jeter une classe de paquets (ici, les réponses que personne n'a demandées) ou annoncer un « trou noir » : tout le trafic vers une adresse est jeté, l'attaque comme les clients légitimes. On sacrifie une cible pour sauver le reste du tuyau. À utiliser avec discernement : jamais sur ce qu'on veut protéger, seulement sur une cible secondaire ; l'attaquant a alors atteint son but pour cette cible ; et le trou noir ne sait pas que l'attaque est finie : il faut le retirer. Un filtre trop large fait aussi des dégâts collatéraux."],
    limite: ["La limitation de débit par adresse", "Plafonner les requêtes par seconde et par adresse arrête les sources très bavardes. Limites mesurées dans le jeu : (1) une attaque distribuée reste sous le plafond (400 adresses à 0,5/s ressemblent à 400 clients normaux) ; (2) un réseau partagé (bureau, école, opérateur mobile derrière une même adresse NAT) ressemble à une source géante : faux positifs quand le plafond descend sous son débit ; (3) les adresses usurpées ou changeantes l'esquivent ; (4) elle agit au niveau applicatif, après la poignée de main : inutile contre un tuyau plein ou une file SYN pleine. Un outil de plus, pas la solution : il faut mesurer l'attaque bloquée ET le légitime bloqué."],
    echelle: ["Capacité, mise à l'échelle, CDN et coût", "La mise à l'échelle automatique ajoute des serveurs quand la charge monte : elle aide pour le processeur, mais avec un délai de démarrage (10 s ici), un coût par serveur et par pas, et une base de données unique ne grossit pas avec elle. Le CDN (réseau de diffusion de contenu) répartit des points de présence : il sert le contenu en cache depuis la périphérie, absorbe le volume et termine à ta place les connexions semi-ouvertes ou lentes ; coût élevé. Le cache évite de recalculer, mais des requêtes toutes différentes le contournent. Absorber une attaque a un prix (déni de portefeuille) : il faut arbitrer disponibilité et coût."],
    degrade: ["Défense applicative et dégradation élégante", "Requêtes lentes : un client qui envoie ses octets au compte-gouttes occupe une place sans presque rien consommer ; un délai maximal par requête (timeout) les libère, à condition de ne pas être trop généreux. Points coûteux : la recherche et la génération de documents sont à protéger, mettre en cache ou différer. File d'attente : faire patienter proprement vaut mieux que s'effondrer ; sans elle, la surcharge fait perdre en plus un quart de la capacité (ici). Dégradation élégante : servir moins, mais servir (pages allégées, recherche sur cache, relevés envoyés plus tard). Un service réduit vaut mieux qu'un service éteint."],
    plan: ["Le plan de réponse", "Détecter : courbes et seuils d'alerte, pour savoir avant que les clients se plaignent. Décider : qui tranche, avec quels outils et quels sacrifices (trou noir, coût). Communiquer : aux clients (ce qui est touché, ce qu'on fait, quand la prochaine nouvelle, sans détails qui aident l'attaquant ni promesses vides), en interne, au fournisseur. Retour d'expérience sans chercher de coupable : qu'a-t-on saturé, à quelle vitesse, qu'a-t-on appris, qu'automatiser. Et garder des contacts joignables : le fournisseur est le premier recours."],
    loi: ["Ce que fait réellement la loi", "En France, entraver ou fausser le fonctionnement d'un système de traitement automatisé de données est un délit (article 323-2 du code pénal : jusqu'à 5 ans de prison et 150 000 € d'amende, davantage dans certains cas). Mettre à disposition sans motif légitime un outil conçu pour cela (les « stressers » ou « booters » loués à la minute) est aussi puni (323-3-1), tout comme la tentative. Des lois comparables existent presque partout. Seul un test autorisé par écrit, sur son propre système ou un périmètre convenu (avec l'accord de l'hébergeur), est légitime. « Riposter » contre les machines sources est illégal : ce sont souvent des victimes. Le jeu, la colère ou le militantisme n'y changent rien. (Repère pédagogique, pas un avis juridique.)"],
  };

  /* ---------- lieux et personnages ---------- */
  const tableauDesc = () => {
    const x = F(), c = x.cfg, on = b => b ? "ACTIF" : "inactif";
    return "Le tableau des défenses (coût par pas de " + DT + " s) :\n" + [
      `  SYN cookies            : ${on(c.cookies)}   (0 €)`,
      `  cache applicatif       : ${on(c.cache)}   (${COST.cache} €)`,
      `  CDN                    : ${on(c.cdn)}   (${COST.cdn} €)`,
      `  salle d'attente        : ${on(c.queue)}   (${COST.queue} €)`,
      `  dégradation élégante   : ${on(c.degrade)}   (0 €)`,
      `  mise à l'échelle       : ${c.scale ? "jusqu'à " + c.scale + " serveurs en plus" : "inactive"}   (${COST.inst} € par serveur actif)`,
      `  limite par adresse     : ${c.limit ? c.limit + " req/s" : "aucune"}`,
      `  délai des requêtes     : ${c.delai ? c.delai + " s" : "aucun"}`,
      `  chez le fournisseur    : filtre « réponses » ${on(c.amont)} (${COST.amont} €), trou noir : ${c.hole || "aucun"}`,
      `  notre propre réseau    : anti-usurpation ${on(x.antispoof)}, relais ${x.closed.relais ? "coupé" : "OUVERT"}, annuaire ${x.closed.annuaire ? "coupé" : "OUVERT"}`,
      `  coût fixe par pas      : ${fixedCost(c)} € (+ serveurs ajoutés)`,
    ].join("\n");
  };
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, sur la place du Marché. Elle te confie l'exploitation de la porte pendant le siège." },
    bob: { npc: true, names: ["bob", "marchand"], label: "Bob", desc: () => "Bob, marchand de la place, tablette à la main : il essaie de passer commande en ligne depuis ce matin." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, capuche baissée, devant le simulateur. Dans cet exercice autorisé, elle joue l'attaquante : c'est elle qui « envoie » la charge, dans la machine seulement." },
    eve: { npc: true, names: ["eve", "ève"], label: "Ève", desc: () => "Ève, qui écoute les lignes et lit les courbes. Elle regarde surtout quand ça commence." },
    simulateur: { names: ["simulateur", "machine", "banc", "console"], label: "le simulateur de siège", desc: () => "Un banc d'essai à pas de temps fixe : 12 pas de " + DT + " secondes. Il fait vivre trafic légitime, trafic hostile et capacités (bande passante, files, processeur, base de données) avec des chiffres jouets. `lancer 1` à `lancer 4`, puis `lancer final`. `courbe` redessine la dernière partie, `alerte ‹n›` règle ton seuil d'alerte (en % de disponibilité)." },
    alice: { npc: true, names: ["alice"], label: "Alice", desc: () => "Alice, ingénieure d'exploitation, qui connaît chaque serveur par son prénom." },
    tableau: { names: ["tableau", "defenses", "tableau des defenses"], label: "le tableau des défenses", desc: tableauDesc },
    filesyn: { names: ["file", "file de connexions", "semi ouvertes", "backlog"], label: "la file des connexions", desc: () => `La file des connexions semi-ouvertes : ${CAP.q} places. Chaque demande d'ouverture (SYN) en réserve une pendant ${SYN_TO} s, le temps que le troisième message de la poignée de main arrive. Elle se règle ici : ${F().cfg.cookies ? "les SYN cookies sont actifs, la file ne réserve plus rien" : "sans les SYN cookies, chaque SYN prend une place"} (`+ "`schema file`)." },
    services: { names: ["services", "services ouverts", "relais", "annuaire"], label: "la liste des services ouverts", desc: () => "La liste de ce que NOTRE réseau expose à tout Internet, y compris des services oubliés. `auditer` les passe en revue ; `couper relais` ou `couper annuaire` en ferme un ; `activer anti usurpation` filtre les paquets sortants à la frontière." },
    technicien: { npc: true, names: ["technicien", "fournisseur", "chef"], label: "le Technicien du fournisseur", desc: () => "Le technicien d'astreinte du fournisseur d'accès. Il voit passer les paquets avant ton tuyau et a deux leviers : filtrer une classe de trafic, ou jeter tout le trafic vers une adresse." },
    consolef: { names: ["console du fournisseur", "console fournisseur", "pupitre"], label: "le pupitre du fournisseur", desc: () => "Le pupitre : `filtrer reponses` (jeter les réponses non sollicitées), `filtrer rien`, `trou noir vitrine` ou `trou noir banque`, `rouvrir`. Cible possible : vitrine (le site de présentation du marché) ou banque (la porte : le serveur web de la banque)." },
    plan: { names: ["plan", "plan de reponse", "tableau blanc"], label: "le plan de réponse", desc: () => { const x = F(); const m = b => b ? "[x]" : "[ ]"; return `Le plan de réponse, au tableau blanc :\n  ${m(x.alert > 0)} Détecter : alerte réglée (\`alerte ‹n›\` à la tour)\n  ${m(x.done.final)} Décider : tenir le grand siège (\`lancer final\`)\n  ${m(x.comm)} Communiquer : \`communiquer ‹1-4›\`\n  ${m(x.retex)} Retour d'expérience : \`retex\``; } },
    code: { names: ["code", "code penal", "loi", "livre"], label: "le code pénal", desc: () => "Un code pénal ouvert sur un lutrin. `loi` présente cinq situations ; juge-les avec `juger ‹n› legal` ou `juger ‹n› illegal`." },
  };

  const rooms = {
    place: { name: "La place du Marché", short: "Place", alias: ["place", "marche"], ents: ["ada", "bob"], exits: { nord: "tour", ouest: "machines", est: "fournisseur", sud: "crise" },
      desc: () => "La place du Marché de Port-443, étrangement calme : les étals sont prêts, mais la porte, le serveur web de la banque, ne s'ouvre plus. Au nord, la tour des courbes et son simulateur. À l'ouest, la salle des machines. À l'est, le relais du fournisseur d'accès. Au sud, la cellule de crise." },
    tour: { name: "La tour des courbes", short: "Tour des courbes", alias: ["tour", "courbes"], ents: ["simulateur", "mallory", "eve"], exits: { sud: "place" },
      desc: () => "Une tour de verre où les courbes de trafic défilent sur les murs. Au centre, le simulateur de siège ; Mallory, bras croisés, attend le feu vert pour jouer l'assiégeante dans la machine. Ève relève les yeux des écrans à chaque pic." },
    machines: { name: "La salle des machines", short: "Salle des machines", alias: ["machines", "salle des machines", "serveurs"], ents: ["alice", "tableau", "filesyn", "services"], exits: { est: "place" },
      desc: () => "Des baies de serveurs ronronnent. Alice y règle les défenses, du tableau mural jusqu'à la file de connexions. Une liste punaisée recense les services que la cité expose à Internet." },
    fournisseur: { name: "Le relais du fournisseur", short: "Fournisseur", alias: ["fournisseur", "relais"], ents: ["technicien", "consolef"], exits: { ouest: "place" },
      desc: () => "Le point où le tuyau de Port-443 rejoint le réseau du fournisseur d'accès. Ici on voit passer le trafic avant qu'il n'arrive chez toi." },
    crise: { name: "La cellule de crise", short: "Cellule de crise", alias: ["crise", "cellule"], ents: ["plan", "code"], exits: { nord: "place" },
      desc: () => "Une salle sobre, un tableau blanc, un téléphone, et un code pénal ouvert sur un lutrin. C'est ici qu'on décide, qu'on communique et qu'on tire les leçons." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.ran[1]) return "run1";
    if (!x.done[1]) return "fix1";
    if (!x.ran[2]) return "run2";
    if (!x.done[2]) return "fix2";
    if (!ownOK()) return "own";
    if (!x.ran[3]) return "run3";
    if (!x.done[3]) return "fix3";
    if (!x.ran[4]) return "run4";
    if (!x.done[4]) return "fix4";
    if (!(x.alert > 0)) return "alert";
    if (!lawDone()) return "loi";
    if (!x.ran.final) return "run5";
    if (!x.done.final) return "fix5";
    if (!x.comm) return "comm";
    if (!x.retex) return "retex";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend sur la place du Marché.", "`parler ada`"],
    run1: () => ["Avant de régler quoi que ce soit, regarde le siège tel qu'il est : le simulateur est à la tour des courbes, au nord.", "`aller nord`, puis `lancer 1`."],
    fix1: () => ["La ressource saturée est la file de connexions semi-ouvertes. Quelle défense évite de réserver une place par demande d'ouverture ? Elle se règle à la salle des machines (ouest de la place).", "`aller sud`, `aller ouest`, `activer cookies`, puis retourne à la tour (`aller est`, `aller nord`) et `lancer 1`. Tu peux comprendre la file avec `schema file`."],
    run2: () => ["Deuxième siège : un autre type de charge. Retourne au simulateur.", "`lancer 2` à la tour des courbes."],
    fix2: () => ["Le tuyau est plein : rien de ce que tu règles sur tes serveurs ne change cela. Il faut du tuyau, ou que le fournisseur jette ce trafic en amont, ou sacrifier une cible secondaire (pas la banque !).", "Le plus économique : `aller est` (chez le fournisseur), `filtrer reponses`. Autres voies : `activer cdn` (cher) ou `trou noir vitrine` (sacrifie la vitrine). Puis `lancer 2` à la tour."],
    own: () => {
      const x = F();
      if (!x.audited) return ["Une réflexion n'existe que parce que des réseaux laissent des services ouverts à tous et des paquets usurpés sortir. Es-tu l'un de ces réseaux ? Regarde ce que NOTRE réseau expose, à la salle des machines.", "`aller sud`, `aller ouest`, `auditer`."];
      return ["Ferme ce qui ne doit pas répondre à tout Internet, puis filtre à la frontière les paquets sortants dont la source n'est pas à nous.", "`couper relais`, `couper annuaire`, `activer anti usurpation` (salle des machines)."];
    },
    run3: () => ["Troisième siège : applicatif. Retourne à la tour.", "`lancer 3` à la tour des courbes."],
    fix3: () => {
      const r = F().last;
      return r && r.wid === "3" && r.peak.db > 1 ? ["La base de données est le point faible : ajouter des serveurs web ne la fera pas grossir. Deux temps dans cette attaque : d'abord quelques adresses très bavardes, puis beaucoup d'adresses discrètes. Un plafond par adresse aide pour le premier ; pour le second, servir moins.", "`limiter 20` (ou plus bas, mesure les faux positifs), `activer degrade`, éventuellement `activer cache` ; à la salle des machines."]
        : ["Regarde quelle ressource sature et pourquoi. Deux temps dans cette attaque : quelques adresses très bavardes, puis beaucoup d'adresses discrètes.", "À la salle des machines : `limiter 20`, `activer degrade` (et, si tu veux, `activer cache`), puis `lancer 3`."];
    },
    run4: () => ["Quatrième siège : le plus discret. Retourne au simulateur.", "`lancer 4` à la tour des courbes."],
    fix4: () => ["Très peu de débit, et pourtant ça bloque : des clients qui ne finissent jamais leur requête occupent toutes les places. Que faire des requêtes trop lentes ?", "`delai 10` à la salle des machines (une valeur trop grande, comme 30, ne suffit pas), puis `lancer 4`."],
    alert: () => ["Il manque l'étape « détecter » : un seuil d'alerte (en % de disponibilité du trafic légitime). À la tour des courbes, Ève a un avis.", "`alerte 90` à la tour des courbes."],
    loi: () => ["Avant le grand siège, passe par la cellule de crise : cinq situations à juger, d'après ce que dit la loi.", "`aller sud` (puis `aller sud` depuis la tour si besoin), `loi`, puis `juger 1 illegal`, `juger 2 legal`, `juger 3 illegal`, `juger 4 illegal`, `juger 5 legal`."],
    run5: () => ["Le grand siège réunit tout. Garde les défenses que tu as comprises, vérifie `etat`, puis lance-le à la tour. Disponibilité d'abord, coût ensuite.", "`lancer final` à la tour des courbes."],
    fix5: () => {
      const c = F().cfg, miss = [];
      if (!c.cookies && !c.cdn) miss.push("`activer cookies`");
      if (!c.amont && !c.cdn && c.hole !== "vitrine") miss.push("`filtrer reponses` (chez le fournisseur)");
      if (!c.degrade) miss.push("`activer degrade`");
      if (!c.limit && !c.scale && !c.cdn) miss.push("`limiter 20`");
      if (!c.delai && !c.cdn) miss.push("`delai 10`");
      return ["Le grand siège cumule les quatre : regarde `courbe` et le diagnostic de la dernière partie pour voir ce qui sature.", miss.length ? "Il manque probablement : " + miss.join(", ") + ". Puis `lancer final`." : "Compare le coût et la disponibilité, ajuste (`etat`), puis `lancer final`."];
    },
    comm: () => ["Le siège est levé : reste à prévenir ceux qui l'ont subi. À la cellule de crise.", "`communiquer` liste quatre messages ; choisis le bon avec `communiquer ‹n›`."],
    retex: () => ["Dernière phase du plan : le retour d'expérience, à la cellule de crise.", "`retex`"],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Siège terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Port-443 est assiégée. Depuis ce matin, la porte, le serveur web de la banque, est saturée : des milliers de requêtes inutiles, et Bob n'arrive plus à passer commande. Tu es responsable de l'exploitation. Tout se passe dans un simulateur : la « charge » est un nombre de requêtes par seconde, les capacités sont des chiffres jouets. Rien de réel n'est attaqué, aucun outil n'existe ici.");
          say("Maître Ada", "Il y a trois grandes familles d'attaques : volumétrique (on remplit le tuyau), protocolaire (on épuise une table d'état réseau) et applicative (on abuse d'une page coûteuse). Chacune sature une ressource différente, donc se combat différemment. Tu vas jouer quatre sièges, un par idée, puis le grand siège qui les réunit ; ton score mêlera disponibilité du trafic légitime et coût.");
          note("types"); out("Va à la tour des courbes : `aller nord`, puis `lancer 1`. `schema ressource` donne la carte des ressources.", "sys"); fig("ressource");
        } else if (objective() === "end") ending();
        else if (x.end) say("Maître Ada", "La porte tient. Et nous avons un plan, c'est ça la vraie victoire.");
        else say("Maître Ada", "Le siège n'est pas fini. `indice` si tu bloques.");
        break;
      case "bob":
        if (x.end) say("Bob", "Ma commande est passée, et même un message clair de la banque ! Merci.");
        else if (x.done.final) say("Bob", "Ça repasse ! Un peu plus sobre, mais ça passe.");
        else if (x.done[4]) say("Bob", "Je peux enfin consulter mon compte. Mais Ada dit que le pire reste à venir.");
        else if (x.done[1]) say("Bob", "Je me connecte, puis ça ralentit de nouveau... Tu changes de problème à chaque fois ?");
        else say("Bob", "La page tourne, tourne, et puis plus rien. Ce n'est pas ma connexion : tous les marchands ont le même souci !");
        break;
      case "mallory":
        say("Mallory", "Je joue l'assiégeante du simulateur : chiffres jouets, aucune machine réelle, accord signé de la Guilde. Hors de ce cadre, je ne le ferais pas : saturer le service d'autrui est un délit, même « pour voir ». Va voir la cellule de crise pour ce que dit la loi (`loi`).");
        break;
      case "eve":
        if (!(x.alert > 0)) say("Ève", "Moi, je repère le début de l'attaque sur la courbe, mais personne ne me prévient : il faudrait un seuil d'alerte. `alerte 90` : « prévenez-moi dès que moins de 90 % du trafic légitime est servi ». Sinon, on l'apprend par les plaintes de Bob.");
        else say("Ève", `Ton alerte sonnera sous ${x.alert} % de disponibilité. Détecter, c'est la première phase du plan : décider vient ensuite.`);
        break;
      case "alice":
        say("Alice", "Mon tableau : `activer ‹cookies|cache|cdn|attente|degrade|anti usurpation›` et `desactiver ‹...›`, `echelle ‹n›` (serveurs en plus, 0 = aucun), `limiter ‹n›` (req/s par adresse, 0 = aucune), `delai ‹s›` (durée maximale d'une requête, 0 = aucune), `couper ‹service›`, `auditer`, `etat`. Chaque défense a un coût par pas : une défense qui ruine la cité n'en est pas une.");
        break;
      case "technicien":
        say("Technicien", "Chez nous, on voit le trafic avant ton tuyau. Deux leviers : `filtrer reponses` (je jette les réponses que personne n'a demandées ; 40 € par pas) et `trou noir ‹cible›` (je jette TOUT ce qui va vers une adresse : l'attaque, mais aussi les clients). Le trou noir se garde pour une cible qu'on peut sacrifier, et il faut `rouvrir` ensuite. Jamais sur la banque : c'est ce que tu veux protéger.");
        note("amont");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  const here = (room, msg) => { if (S.room !== room) { out(msg, "sys"); return false; } return true; };
  const waveId = t => {
    if (/^(1|un|syn|protocolaire|premier)$/.test(t)) return "1";
    if (/^(2|deux|volumetrique|reflexion|echo|echos)$/.test(t)) return "2";
    if (/^(3|trois|applicatif|applicative|recherche)$/.test(t)) return "3";
    if (/^(4|quatre|lent|lente|lents)$/.test(t)) return "4";
    if (/^(5|final|grand|dernier|combine|tout)$/.test(t)) return "final";
    return null;
  };

  const DIAG = {
    bw: "BANDE PASSANTE saturée : le tuyau est plein avant même que tes serveurs voient les paquets. Aucun réglage du serveur n'y change rien : il faut du tuyau (CDN), ou que le trafic soit jeté en amont (fournisseur), ou sacrifier une cible.",
    q: "FILE DES CONNEXIONS SEMI-OUVERTES pleine : chaque demande d'ouverture réserve une place pendant " + SYN_TO + " s ; les nouveaux, légitimes compris, trouvent la porte « complète ». Le débit est modeste, c'est l'ÉTAT qui sature.",
    conn: "PLACES DE CONNEXION occupées par des clients qui n'avancent pas : un débit minuscule, mais toutes les places sont prises par des requêtes jamais terminées.",
    cpu: "PROCESSEUR saturé : trop de travail applicatif pour la capacité disponible.",
    db: "BASE DE DONNÉES saturée : un point coûteux (la recherche) est appelé en boucle. Les serveurs web pourraient être dix fois plus nombreux : la base resterait seule.",
  };
  function printRun(r, c) {
    const rows = ["  t   hostile  servi     BP   FILE    CNX    CPU    BDD"];
    r.steps.forEach(s => rows.push(`${String(s.t * DT).padStart(3)}s ${String(Math.round(s.hostIn)).padStart(7)} ${pct(s.avail)}${pct(s.util.bw)}${pct(s.util.q)}${pct(s.util.conn)}${pct(s.util.cpu)}${pct(s.util.db)}${s.degr ? " d" : ""}`));
    code(rows.join("\n"));
    out("(servi : part du trafic légitime servie, pondérée ; BP bande passante, FILE file SYN, CNX places de connexion ; « d » : mode dégradé)", "sys");
  }
  function runCmd(c) {
    const x = F();
    if (!here("tour", "Le simulateur est à la tour des courbes (nord de la place).")) return;
    const id = waveId(norm(c.rawArg));
    if (!id) { out("Quel siège ? `lancer 1` à `lancer 4`, puis `lancer final`.", "err"); return; }
    const need = id === "final" ? [1, 2, 3, 4] : id === "1" ? [] : [+id - 1];
    const miss = need.find(n => !x.done[n]);
    if (miss) { say("Ève", `Pas dans le désordre : chaque siège t'apprend une ressource, et il faut avoir contenu le siège ${miss} d'abord (disponibilité d'au moins ${Math.round(THRESH * 100)} %).`); return; }
    const w = WAVES[id];
    out(`Siège ${id === "final" ? "final" : id} : « ${w.name} » (${w.type})`, "title");
    const intro = {
      1: "Mallory : « Des demandes d'ouverture de connexion, avec des adresses inventées. Le serveur répond et attend la suite, qui ne vient jamais. 600 par seconde. »",
      2: "Mallory : « Je n'envoie que 110 petites requêtes par seconde, à des services ouverts, en me faisant passer pour ta vitrine. Ce sont eux qui répondent, en plus gros, vers toi. »",
      3: "Mallory : « Des recherches toutes différentes sur la banque. D'abord quelques adresses très actives, puis des centaines d'adresses discrètes. »",
      4: "Mallory : « Peu de débit : 14 nouvelles connexions par seconde, qui envoient leur requête au compte-gouttes, sans jamais finir. »",
      final: "Mallory : « Tout à la fois, cette fois : connexions lentes, SYN, échos, recherches. À toi de tenir, sans ruiner la cité. »",
    }[id];
    out(intro, "npc");
    const r = simulate(id, x.cfg);
    printRun(r, x.cfg);
    x.ran[id] = true; x.last = { wid: id, peak: r.peak, avail: r.avail, cost: r.cost, steps: r.steps.map(s => ({ hostIn: s.hostIn, hostPass: s.hostPass, avail: s.avail })) };
    const sat = saturated(r);
    if (sat.length) { out("Ressource saturée (pic " + sat.map(k => `${RESU[k].toLowerCase()} ${Math.round(r.peak[k] * 100)} %`).join(", ") + ") :", "sys"); sat.forEach(k => out("· " + DIAG[k], "err")); }
    else out("Aucune ressource n'a dépassé sa capacité.", "ok");
    if (r.lost > 0.001) out(`Faux positifs : ${Math.round(r.lost * 1000) / 10} % du trafic légitime a été bloqué par ta limite par adresse (le réseau partagé du collège, sous le plafond de ${x.cfg.limit} req/s).`, "err");
    if (r.degr) out("Dégradation élégante : sous la charge, le service a servi moins (recherche réduite aux résultats en cache, relevés différés, pages allégées), mais il a servi.", "ok");
    if (x.cfg.hole) out(`Le trou noir sur « ${x.cfg.hole} » est resté actif pendant tout le test, même quand l'attaque était terminée : il ne sait pas qu'elle a cessé. ${x.cfg.hole === "banque" ? "Et tu as éteint toi-même la porte que tu devais protéger." : "La vitrine est hors ligne : c'est le prix payé."}`, "err");
    if (x.cfg.scale && r.steps.some(s => s.inst > 0)) out(`Mise à l'échelle : jusqu'à ${Math.max(...r.steps.map(s => s.inst))} serveur(s) ajouté(s), avec deux pas de délai avant d'être utiles.`, "sys");
    // détection
    const a = x.alert || 0, t60 = r.steps.find(s => s.avail < 0.6), tA = a ? r.steps.find(s => s.avail * 100 < a) : null;
    if (tA) out(`Détection : ton alerte (${a} %) sonne à ${tA.t * DT} s.${t60 ? " Les premières plaintes de Bob arrivent à " + t60.t * DT + " s." : ""}`, "sys");
    else if (t60) out(`Détection : sans alerte (ou seuil jamais franchi), on l'apprend par les plaintes de Bob, à ${t60.t * DT} s.`, "sys");
    out(`Résultat : disponibilité moyenne **${Math.round(r.avail * 1000) / 10} %**, coût **${money(r.cost)}**. ${r.ok ? "Siège contenu." : "Siège non contenu (il faut au moins " + Math.round(THRESH * 100) + " %)."}`, r.ok ? "ok" : "err");
    if (r.ok) { x.done[id] = true; x.best[id] = Math.max(x.best[id] || 0, r.avail); }
    if (id === "final") x.fin = { avail: r.avail, cost: r.cost, peak: r.peak, steps: r.steps.length, cfg: { ...x.cfg }, tA: tA ? tA.t * DT : null, t60: t60 ? t60.t * DT : null, lost: r.lost, degr: r.degr };
    // contenus pédagogiques à la première partie de chaque type
    if (id === "1") { note("file"); if (!x.shown1) { x.shown1 = true; fig("file"); } }
    if (id === "2") {
      note("amplification");
      if (!x.shown2) out(`Analyse des sources : ${num(2000)} adresses différentes, toutes des serveurs légitimes. Mallory n'y figure pas. 110 requêtes/s × facteur 28 = ${num(ATK * FACTOR)} réponses/s. Bloquer « les méchants » par adresse est impossible : ce sont des innocents. \`schema amplification\``, "sys");
      if (!x.shown2) { x.shown2 = true; fig("amplification"); }
    }
    if (!x.shownC) { x.shownC = true; out("`courbe` dessine la courbe de ce siège (trafic légitime servi, trafic hostile qui arrive et qui passe).", "sys"); }
    if (id === "final" && r.ok) {
      const sc = Math.round(r.avail * 100 * 0.7 + 30 * (1 - Math.min(1, r.cost / 3000)));
      x.score = sc;
      out(`Score : ${sc}/100 (disponibilité sur 70, économie sur 30 : 0 € de défense = 30, 3 000 € ou plus = 0). ${sc >= 88 ? "Excellent : la porte tient sans ruiner la cité." : sc >= 75 ? "Correct : tu peux encore resserrer le coût ou la disponibilité." : "Passable : la cité a tenu, mais chèrement ou de justesse."}`, "ok");
      if (!x.shownF) { x.shownF = true; fig("courbe"); }
    }
  }
  function curveCmd() {
    if (!F().last) { out("Aucune courbe : lance d'abord un siège (`lancer 1`).", "sys"); return; }
    fig("courbe");
  }
  function alertCmd(c) {
    const x = F(), n = parseFloat(norm(c.rawArg).replace(",", "."));
    if (!here("tour", "Les alertes se règlent à la tour des courbes (nord de la place).")) return;
    if (!isFinite(n)) { out(x.alert ? `Alerte actuelle : sous ${x.alert} % de disponibilité. Pour la changer : \`alerte ‹pourcentage›\` (ex. \`alerte 90\`).` : "Aucune alerte réglée. `alerte 90` préviendra dès que moins de 90 % du trafic légitime est servi.", "sys"); return; }
    if (n <= 0 || n >= 100) { out("Un seuil entre 1 et 99 % : trop haut, l'alerte sonne pour rien ; trop bas, elle sonne trop tard.", "err"); return; }
    x.alert = Math.round(n);
    out(`Alerte réglée : tu seras prévenu quand moins de ${x.alert} % du trafic légitime sera servi. Les prochains sièges indiqueront à quel pas elle aurait sonné, face aux plaintes des clients.`, "ok");
    if (x.alert < 70) out("Remarque : avec un seuil aussi bas, tu seras prévenu quand le mal est déjà fait.", "sys");
  }

  const DEFN = { cookies: "SYN cookies", cache: "cache applicatif", cdn: "CDN", queue: "salle d'attente", degrade: "dégradation élégante", antispoof: "anti-usurpation" };
  function defKey(t) {
    if (/cookie/.test(t)) return "cookies";
    if (/\bcdn\b|diffusion/.test(t)) return "cdn";
    if (/cache/.test(t)) return "cache";
    if (/attente|\bfile\b/.test(t)) return "queue";
    if (/degrad|elegan/.test(t)) return "degrade";
    if (/usurp|ingress|bcp|entree/.test(t)) return "antispoof";
    if (/echelle|scal/.test(t)) return "scale";
    return null;
  }
  const SAYS = {
    cookies: ["Les SYN cookies sont actifs : le serveur ne réserve plus de place pour une demande d'ouverture, il encode l'état dans sa réponse et ne reconstruit la connexion que si le bon ACK revient. Les adresses inventées ne reviendront jamais.", "Les SYN cookies sont désactivés : chaque SYN reprend une place de la file."],
    cache: [`Cache applicatif actif (${COST.cache} € par pas) : pages et recherches fréquentes sont resservies sans recalcul. Mais des recherches toutes différentes le contournent.`, "Cache désactivé."],
    cdn: [`CDN actif (${COST.cdn} € par pas) : le contenu est servi depuis des points de présence répartis, la capacité d'absorption passe à ${CDN_BW}, et les poignées de main et clients lents sont terminés au bord. C'est efficace et cher.`, "CDN désactivé."],
    queue: [`Salle d'attente active (${COST.queue} € par pas) : en cas de surcharge, on fait patienter et on jette proprement, au lieu de laisser la machine s'effondrer (sans elle, on perd en plus un quart de capacité).`, "Salle d'attente désactivée."],
    degrade: ["Dégradation élégante active : quand le serveur est débordé, il sert moins mais sert (pages allégées, recherche réduite aux résultats en cache, relevés envoyés plus tard par courriel). Les clients y perdent un peu, pas tout.", "Dégradation élégante désactivée."],
    antispoof: ["Filtrage anti-usurpation actif à la frontière de NOTRE réseau : un paquet qui sort avec une adresse source qui n'est pas la nôtre est jeté. Chacun qui le fait chez soi prive les attaquants de leur déguisement. Le coût est nul, le bénéfice profite aux autres : c'est une affaire de bon voisinage.", "Filtrage anti-usurpation désactivé."],
  };
  function toggleCmd(c, on) {
    const x = F(), t = norm(c.rawArg);
    if (!here("machines", "Les défenses se règlent à la salle des machines (ouest de la place).")) return;
    const k = defKey(t);
    if (!t || !k) { out("Quelle défense ? `activer cookies`, `cache`, `cdn`, `attente`, `degrade`, `anti usurpation` ou `echelle ‹n›`. `etat` montre le tableau.", "err"); return; }
    if (k === "scale") { setScale(on ? (parseInt((t.match(/\d+/) || ["4"])[0], 10)) : 0); return; }
    if (k === "antispoof") x.antispoof = on; else x.cfg[k] = on;
    out(SAYS[k][on ? 0 : 1], on ? "ok" : "sys");
    if (k === "cdn" && on) { note("echelle"); out("Le CDN coûte " + COST.cdn + " € par pas : sur 12 pas, " + money(COST.cdn * NS) + ". Regarde le coût dans les résultats.", "sys"); }
    if (k === "degrade" && on) note("degrade");
    if (k === "queue" && on) note("degrade");
  }
  function setScale(n) {
    const x = F();
    if (!here("machines", "La mise à l'échelle se règle à la salle des machines (ouest de la place).")) return;
    if (!isFinite(n) || n < 0 || n > 8) { out("`echelle ‹n›` : de 0 (aucune) à 8 serveurs supplémentaires au maximum.", "err"); return; }
    x.cfg.scale = n;
    if (!n) { out("Mise à l'échelle désactivée.", "sys"); return; }
    out(`Mise à l'échelle : jusqu'à ${n} serveur(s) en plus (${INST_CPU} de capacité processeur chacun, ${COST.inst} € par pas et par serveur actif), démarrés quand le processeur dépasse 85 %, avec ${LAG * DT} s de délai. Elle n'agrandit ni le tuyau, ni la file, ni la base de données.`, "ok");
    note("echelle");
  }
  function scaleCmd(c) { const m = norm(c.rawArg).match(/\d+/); setScale(m ? parseInt(m[0], 10) : NaN); }
  function limitCmd(c) {
    const x = F(), t = norm(c.rawArg).replace(",", ".");
    if (!here("machines", "La limite par adresse se règle à la salle des machines (ouest de la place).")) return;
    if (/^(aucune|non|off|rien)$/.test(t)) { x.cfg.limit = 0; out("Aucune limite par adresse.", "sys"); return; }
    const n = parseFloat(t);
    if (!isFinite(n)) { out(`Limite actuelle : ${x.cfg.limit ? x.cfg.limit + " req/s par adresse" : "aucune"}. Pour la régler : \`limiter ‹requêtes par seconde›\` (ex. \`limiter 20\`, \`limiter 0\` pour l'enlever).`, "err"); return; }
    if (n < 0 || n > 1000) { out("Une limite entre 0 (aucune) et 1000 requêtes par seconde.", "err"); return; }
    x.cfg.limit = n;
    if (n === 0) { out("Aucune limite par adresse.", "sys"); return; }
    const pass = (cnt, per) => Math.round(cnt * Math.min(per, n) * 10) / 10;
    const fp = Math.max(0, LEG.groups[1].per - n);
    out(`Limite : ${n} requêtes/s par adresse. Mesure sur les groupes de sources du jeu :`, "ok");
    code([
      `clients ordinaires   338 adresses × 0,5/s  = 169/s  → passent ${pass(338, 0.5)}/s`,
      `collège (réseau partagé)  1 adresse × 16/s  =  16/s  → passent ${pass(1, 16)}/s   ${fp > 0 ? "FAUX POSITIF : " + Math.round(fp * 10) / 10 + "/s légitimes bloqués" : "aucun faux positif"}`,
      `attaque concentrée    10 adresses × 40/s   = 400/s  → passent ${pass(10, 40)}/s`,
      `attaque dispersée    400 adresses × 0,5/s  = 200/s  → passent ${pass(400, 0.5)}/s`,
    ].join("\n"));
    out(n < 0.5 ? "Sous 0,5/s, même un client ordinaire est coupé." : n >= 16 ? "Le collège est épargné, mais l'attaque concentrée passe encore en grande partie." : "Le collège (un réseau partagé) commence à être pénalisé.", "sys");
    out("Remarque : l'attaque dispersée reste sous TOUTE limite raisonnable. Le plafond par adresse ne peut pas la voir.", "sys");
    note("limite"); if (!x.shownL) { x.shownL = true; fig("limite"); }
  }
  function delaiCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!here("machines", "Le délai des requêtes se règle à la salle des machines (ouest de la place).")) return;
    if (/^(aucun|aucune|non|off|rien)$/.test(t)) { x.cfg.delai = 0; out("Aucun délai maximal : un client lent peut garder sa place indéfiniment.", "sys"); return; }
    const n = parseFloat(t);
    if (!isFinite(n)) { out(`Délai actuel : ${x.cfg.delai ? x.cfg.delai + " s" : "aucun"}. \`delai ‹secondes›\` (ex. \`delai 10\`, \`delai 0\` pour aucun).`, "err"); return; }
    if (n < 0 || n > 600) { out("Un délai entre 0 et 600 secondes.", "err"); return; }
    x.cfg.delai = n;
    if (!n) { out("Aucun délai maximal.", "sys"); return; }
    const h = Math.min(280, 14 * n);
    out(`Délai maximal : ${n} s pour terminer une requête. Les clients lents du jeu ouvrent 14 connexions par seconde : au maximum ${Math.round(h)} places seraient tenues (sur ${CAP.conn}), le trafic légitime en a besoin d'environ ${LEG.held}. ${CAP.conn - h >= LEG.held ? "Il en reste assez." : "Ce n'est pas assez court : les places manqueront."}${n < 3 ? " Attention : un délai trop court coupe aussi les vrais clients sur une connexion lente (non simulé ici)." : ""}`, CAP.conn - h >= LEG.held ? "ok" : "err");
    note("degrade");
  }
  function stateOut() { code(tableauDesc()); }

  function cutCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!here("machines", "Les services se coupent à la salle des machines (ouest de la place).")) return;
    const ks = /tout|tous/.test(t) ? ["relais", "annuaire"] : /relais|echo/.test(t) ? ["relais"] : /annuaire|resolveur/.test(t) ? ["annuaire"] : [];
    if (!ks.length) { out("Quel service ? `couper relais` ou `couper annuaire` (`auditer` donne la liste).", "err"); return; }
    ks.forEach(k => {
      if (x.closed[k]) { out(`Le ${k} est déjà coupé.`, "sys"); return; }
      x.closed[k] = true;
      out(k === "relais" ? "Le relais d'écho ouvert est coupé : il ne répondra plus à n'importe qui. (Si un service doit rester joignable, on le restreint à ses clients et on limite la taille de ses réponses.)" : "L'annuaire ouvert est coupé à Internet : il ne répond plus qu'aux machines de la cité.", "ok");
    });
    if (x.audited) out("`auditer` pour revoir l'exposition.", "sys");
  }
  function auditCmd() {
    const x = F();
    if (!here("machines", "L'audit de l'exposition se fait à la salle des machines (ouest de la place).")) return;
    x.audited = true;
    const open = ["relais", "annuaire"].filter(k => !x.closed[k]);
    const sent = 100;
    const refl_ = open.reduce((a, k) => a + sent * OPEN[k], 0);
    out("Audit de NOTRE réseau, avec Mallory dans le rôle d'un tiers malveillant (simulé) :", "title");
    code([
      "Service           facteur  état",
      `web public          1      ouvert, légitime`,
      `relais d'écho      ×${OPEN.relais}      ${x.closed.relais ? "coupé" : "OUVERT À TOUT INTERNET"}`,
      `annuaire           ×${OPEN.annuaire}      ${x.closed.annuaire ? "coupé" : "OUVERT À TOUT INTERNET"}`,
      "",
      `Test 1 : un tiers envoie ${sent} requêtes/s à chaque service ouvert,`,
      `en se faisant passer pour la victime : elle reçoit ${num(refl_)} réponses/s${refl_ ? "  ← nous servons de réflecteur" : "  (rien ne rebondit sur nous)"}`,
      `Test 2 : un de nos locataires envoie ${sent} paquets/s avec une adresse`,
      `source qui n'est pas la sienne : ${x.antispoof ? "JETÉS à la frontière (anti-usurpation)" : "ILS SORTENT (aucun filtrage à la sortie)"}`,
    ].join("\n"));
    if (open.length) out(`Services à fermer : ${open.join(", ")}. \`couper ${open[0]}\`.`, "err");
    if (!x.antispoof) out("Pas de filtrage à la sortie : `activer anti usurpation`.", "err");
    if (!open.length && x.antispoof) out("Plus de réflecteur chez nous, plus d'usurpation depuis chez nous : notre part du problème est réglée. Reste que les autres réseaux doivent en faire autant.", "ok");
    note("amplification");
    if (!x.shownA2) { x.shownA2 = true; fig("amplification"); }
  }
  function ampCmd(c) {
    const m = c.rawArg.replace(",", ".").match(/[\d.]+/g) || [];
    if (m.length < 2) { out("`amplifier ‹débit› ‹facteur›` : par exemple `amplifier 110 28` (110 requêtes/s, réponses 28 fois plus nombreuses ou plus grosses).", "err"); return; }
    const a = parseFloat(m[0]), b = parseFloat(m[1]);
    if (!(a > 0) || !(b > 0) || a > 1e6 || b > 1e4) { out("Des nombres positifs raisonnables, s'il te plaît.", "err"); return; }
    out(`${num(a)} requêtes/s × facteur ${num(b)} = ${num(a * b)} réponses/s vers la victime. L'attaquant paie ${num(a)} ; la victime encaisse ${num(a * b)}. ${a * b > CAP.bw ? "Au-delà de la bande passante de " + CAP.bw + " : le tuyau de la banque est plein." : "Encore sous la capacité du tuyau."} Chiffres jouets, à des fins de compréhension.`, "sys");
  }

  const FILT = "reponses";
  function filterCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!here("fournisseur", "Le filtrage amont se règle chez le fournisseur (est de la place).")) return;
    if (/^(rien|aucun|non|off|retirer|arreter)/.test(t)) { x.cfg.amont = false; out("Le filtre amont est retiré.", "sys"); return; }
    if (!/repon|retour|echo/.test(t)) { out("`filtrer reponses` : le fournisseur jette les réponses non sollicitées (celles que personne chez nous n'a demandées). Seule classe disponible ici.", "err"); return; }
    x.cfg.amont = true;
    say("Technicien", "C'est fait : toute réponse qui arrive sans qu'une requête de ta part l'ait provoquée est jetée à notre porte, avant ton tuyau. 40 € par pas. Collatéral possible : les réponses légitimes à TES requêtes ; ici, la banque n'en émet pas de ce genre.");
    note("amont");
  }
  function holeCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!here("fournisseur", "Le trou noir se demande chez le fournisseur (est de la place).")) return;
    const k = /vitrine/.test(t) ? "vitrine" : /banque|porte/.test(t) ? "banque" : null;
    if (!k) { out("Quelle cible ? `trou noir vitrine` ou `trou noir banque` (la porte).", "err"); return; }
    x.cfg.hole = k;
    if (k === "banque") say("Technicien", "Tu es sûr·e ? Si je jette tout ce qui va vers la banque, l'attaque s'arrête... et la banque aussi. L'attaquant aura gagné. C'est fait, mais teste et tu verras.");
    else say("Technicien", "Entendu : tout ce qui va vers la vitrine est jeté. L'attaque ne la touche plus, mais personne ne la voit non plus. Et je ne sais pas quand l'attaque cesse : dis-moi de `rouvrir`.");
    out("Un trou noir sacrifie une cible pour sauver le reste du tuyau. La banque, c'est ce que tu protèges : n'y touche pas.", "sys");
    note("amont");
  }
  function reopenCmd() {
    const x = F();
    if (!here("fournisseur", "Cela se demande chez le fournisseur (est de la place).")) return;
    if (!x.cfg.hole) { out("Rien n'est en trou noir.", "sys"); return; }
    out(`Le trafic vers « ${x.cfg.hole} » est de nouveau acheminé.`, "ok"); x.cfg.hole = null;
  }

  /* loi, communication, retour d'expérience */
  const CASES = {
    1: "Lancer une inondation « pour voir » sur le site d'un concurrent, la nuit, en se disant qu'il l'a bien mérité.",
    2: "Tester la charge de notre propre préproduction, avec l'accord écrit de la direction et de l'hébergeur, dans une fenêtre convenue.",
    3: "Contre-attaquer les machines qui nous inondent pour les mettre hors service.",
    4: "Louer à des inconnus l'accès à un réseau d'ordinateurs infectés, « pour des tests ».",
    5: "Demander à notre propre fournisseur de jeter le trafic vers notre vitrine pendant l'attaque (trou noir).",
  };
  const WHY = {
    1: "Entraver le fonctionnement d'un système d'autrui, c'est l'article 323-2, même sans profit ni rancune, même « pour jouer ».",
    2: "Un test de charge sur ses propres systèmes, dans un périmètre convenu et avec l'accord de l'hébergeur, est légitime : c'est ainsi qu'on mesure sa capacité.",
    3: "Le « hack back » est illégal : les machines sources sont presque toujours des victimes infectées, et ce n'est pas à toi de les attaquer. On signale, on filtre, on demande au fournisseur.",
    4: "Fournir ou louer un tel moyen est puni (323-3-1, avec en plus la complicité des attaques menées), et ces machines appartiennent à des victimes.",
    5: "C'est de la défense de ton propre trafic, par ton propre fournisseur, avec son accord.",
  };
  function lawCmd() {
    if (!here("crise", "Le code pénal est à la cellule de crise (sud de la place).")) return;
    out("Cinq situations à juger : `juger ‹n› legal` ou `juger ‹n› illegal`.", "title");
    Object.keys(CASES).forEach(k => out(`${k}. ${CASES[k]}`));
  }
  function judgeCmd(c) {
    const x = F(), t = norm(c.rawArg).split(" ");
    if (!here("crise", "On juge à la cellule de crise (sud de la place), devant le code pénal.")) return;
    const n = t[0], a = (t[1] || "").replace(/^(i)?l?legal.*/, m => m);
    if (!CASES[n] || !t[1]) { out("`juger ‹n› legal` ou `juger ‹n› illegal`, avec n de 1 à 5 (`loi` les liste).", "err"); return; }
    const v = /^ill?egal|^interdit|^non|^delit/.test(t[1]) ? "illegal" : /^legal|^legit|^autoris|^oui|^permis/.test(t[1]) ? "legal" : null;
    if (!v) { out("Réponds `legal` ou `illegal`.", "err"); return; }
    x.law = x.law || {};
    if (v === lawAns[n]) { x.law[n] = true; out(`Exact. ${WHY[n]}`, "ok"); }
    else out(`Pas tout à fait. ${WHY[n]}`, "err");
    if (lawDone()) { note("loi"); out("Les cinq situations sont jugées. Retiens : ce qui rend un test légitime, c'est l'autorisation et le périmètre, pas l'intention.", "ok"); }
    else out(`Jugées exactement : ${Object.keys(x.law).length}/5.`, "sys");
  }
  const MSGS = {
    1: ["Silence radio : on répare d'abord, on dira quelque chose après.", "Les clients ne savent pas si le problème vient d'eux, de la banque ou d'un piratage : ils appellent, s'inquiètent, et la rumeur remplit le vide."],
    2: ["« Un petit incident technique, rien d'inquiétant, tout va bien. »", "Minimiser détruit la confiance dès que les clients constatent le contraire."],
    3: ["« Notre site est ralenti par un afflux de trafic hostile. À ce stade, rien n'indique que vos données soient touchées. Les virements en ligne peuvent être lents ; l'agence reste ouverte. Prochaine information dans 30 minutes. »", "Factuel : ce qui est touché, ce qui ne l'est pas, ce qu'on fait, quand on reparle."],
    4: ["Publier la liste complète des défenses et de leurs seuils exacts, pour rassurer.", "Ce serait un guide de contournement pour l'attaquant."],
  };
  function commCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!here("crise", "La communication se prépare à la cellule de crise (sud de la place).")) return;
    if (!x.done.final) { out("Pas encore : tant que le grand siège n'est pas contenu, il n'y a pas de message final à publier. Mais on communique AUSSI pendant l'attaque : retiens-le.", "sys"); return; }
    if (!MSGS[t]) { out("Quel message ? Choisis avec `communiquer ‹n›` :", "title"); Object.keys(MSGS).forEach(k => out(`${k}. ${MSGS[k][0]}`)); return; }
    if (t === "3") { x.comm = true; out("Message publié. " + MSGS[3][1], "ok"); say("Bob", "Enfin quelqu'un qui dit ce qui se passe, et quand on en reparle !"); note("plan"); }
    else out("Mauvais choix : " + MSGS[t][1], "err");
  }
  function retexCmd() {
    const x = F();
    if (!here("crise", "Le retour d'expérience se fait à la cellule de crise (sud de la place).")) return;
    if (!x.fin) { out("Pas de retour d'expérience sans événement : tiens d'abord le grand siège (`lancer final`).", "sys"); return; }
    const r = x.fin, pk = r.peak, top = Object.keys(pk).sort((a, b) => pk[b] - pk[a])[0];
    out("Retour d'expérience (sans chercher de coupable)", "title");
    const L = [
      `Ce qui s'est passé : disponibilité ${Math.round(r.avail * 1000) / 10} %, coût ${money(r.cost)}, score ${x.score || "?"}/100.`,
      `Ressource la plus sous tension : ${RES[top]} (pic ${Math.round(pk[top] * 100)} %).`,
      r.tA !== null ? `Détection : l'alerte a sonné à ${r.tA} s${r.t60 !== null ? ", les plaintes seraient venues à " + r.t60 + " s" : ""}.` : (r.t60 !== null ? `Détection : aucune alerte ; les plaintes à ${r.t60} s. Le seuil d'alerte est à revoir.` : "Détection : le service n'est jamais tombé sous 60 %."),
      r.cfg.cdn ? "Choix coûteux : le CDN absorbe tout, mais il pèse " + money(COST.cdn * NS) + " sur 12 pas. À réserver aux pics, ou à mettre en place à la demande." : "Le coût est resté contenu : des défenses ciblées (cookies, filtre amont, plafond par adresse, délai, dégradation) font plus que l'argent.",
      r.cfg.limit && r.cfg.limit < 16 ? "Ta limite par adresse a pénalisé le réseau partagé du collège : à revoir." : "Aucun faux positif notable de ta limite par adresse.",
    ];
    L.forEach(l => out("· " + l));
    out("À automatiser et à répéter : alertes sur les courbes, contact joignable chez le fournisseur, gabarit de message pour les clients, exercice de simulation chaque trimestre, vérification de l'anti-usurpation et des services ouverts.", "sys");
    x.retex = true; note("plan");
  }

  /* ---------- fin de partie ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", `La porte tient. Disponibilité ${Math.round((x.fin ? x.fin.avail : 0) * 1000) / 10} % pendant le grand siège, pour ${money(x.fin ? x.fin.cost : 0)}. Et surtout, tu as vu pourquoi : chaque attaque épuise une ressource précise, et la bonne défense est celle qui protège CETTE ressource, au bon endroit, au bon prix.`);
    say("Maître Ada", "Mallory range ses chiffres jouets. Souviens-toi : tout ceci était un exercice autorisé. Dans la vraie vie, le même geste vers le système d'autrui est un délit.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La porte assiégée = un service exposé à Internet.** Un déni de service (DoS) n'entre pas : il épuise une ressource (bande passante, état réseau, processeur, base de données, places de connexion) jusqu'à ce que les vrais clients ne passent plus. Distribué (DDoS), il vient de milliers de sources.");
    out("**Les trois sièges = les trois familles.** Volumétrique (remplir le tuyau), protocolaire (épuiser la file des connexions semi-ouvertes, d'où les SYN cookies), applicative (abuser d'un point coûteux ou garder des connexions ouvertes sans rien faire).");
    out("**Les échos = réflexion et amplification.** Un service ouvert répond à une adresse usurpée, avec une réponse plus grosse que la requête. La parade durable est ailleurs que chez la victime : anti-usurpation à la sortie des réseaux (BCP 38) et services ouverts fermés ou restreints.");
    out("**Le fournisseur = le filtrage amont et le trou noir.** Seul l'amont peut jeter du volume avant qu'il ne remplisse ton tuyau. Le trou noir sacrifie une cible : à utiliser sur du secondaire, avec discernement, et à retirer ensuite.");
    out("**La limite par adresse, l'échelle, le CDN, le cache, la salle d'attente, la dégradation.** Chacun protège une ressource, a un coût et une limite : le plafond par adresse ne voit pas une attaque distribuée et pénalise les réseaux partagés ; l'autoscaling n'agrandit pas la base ; le CDN est cher ; le cache est contourné par des requêtes toutes différentes ; servir moins vaut mieux que ne plus servir.");
    out("**Le plan de réponse.** Détecter (courbes, alertes), décider (outils, sacrifices), communiquer (honnêtement, sans détails exploitables), apprendre (retour d'expérience).");
    out("**Les simplifications du jeu.** (1) Les chiffres sont jouets : un vrai tuyau se compte en gigabits et une vraie attaque en millions de paquets par seconde ; les proportions seules sont réalistes. (2) Un pas de 5 secondes et une file de 256 places ne ressemblent pas à un vrai noyau (files, délais et retransmissions sont plus nuancés). (3) Le comportement d'un CDN, d'un fournisseur d'accès ou d'un autoscaler réel est bien plus subtil (cache froid, routage, quotas, facturation à l'usage). (4) Les attaquants réels s'adaptent en continu, mélangent les vecteurs et n'annoncent pas leurs phases. (5) Il n'y a pas de véritable détail technique d'attaque ici, volontairement : seulement ce qu'il faut pour comprendre et défendre.");
    out("Rappel utile : **identifie la ressource saturée, protège-la au bon endroit, mesure le légitime bloqué, et prépare le plan avant l'attaque, pas pendant.** Le déni de service est un délit : on ne le teste que sur ce qu'on possède, avec autorisation.", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    ressource: () => {
      const x = F(), pk = x.last ? x.last.peak : null;
      const rows = [["Bande passante", "bw", "volumétrique"], ["File de connexions (SYN)", "q", "protocolaire"], ["Places de connexion", "conn", "lente / protocolaire"], ["Processeur", "cpu", "applicative"], ["Base de données", "db", "applicative"]];
      let b = "";
      rows.forEach(([lab, k, ty], i) => {
        const y = 34 + i * 40, u = pk ? pk[k] : 0, w = Math.min(u, 2) / 2 * 330;
        b += T(8, y - 6, lab, "f-s", "start") + T(412, y - 6, ty, "f-s", "end") + `<rect x="8" y="${y}" width="330" height="14" rx="3" fill="none" stroke="var(--line)"/>`;
        if (w > 0) b += `<rect x="8" y="${y}" width="${w.toFixed(1)}" height="14" rx="3" fill="${u > 1 ? "var(--bad)" : "var(--ok)"}"/>`;
        b += T(412, y + 12, pk ? Math.round(u * 100) + " %" : "—", u > 1 ? "ft-bad f-b" : "f-s", "end");
      });
      b += LN(173, 26, 173, 232, "f-dash") + T(173, 246, "100 % = saturé", "f-s");
      return {
        cap: pk ? `Pic d'utilisation de chaque ressource pendant le dernier siège (${x.last.wid === "final" ? "final" : "n° " + x.last.wid}) : une barre qui dépasse 100 % est la ressource saturée. Chaque famille d'attaque vise la sienne.` : "Les cinq ressources de la porte et la famille d'attaque qui vise chacune. Lance un siège : les barres montreront laquelle sature.",
        svg: SVG(256, "Ressource saturée selon le type d'attaque", b),
      };
    },
    file: () => {
      const x = F(), c = x.cfg, rate = 600, occ = c.cookies || c.cdn ? 0 : Math.min(1, (rate * SYN_TO) / CAP.q);
      const nb = 32, filled = Math.round(occ * nb) + (occ === 0 ? 0 : 0);
      let b = T(8, 16, `File des connexions semi-ouvertes : ${CAP.q} places (1 case = 8)`, "f-s", "start");
      for (let i = 0; i < nb; i++) {
        const cx = 8 + (i % 16) * 25.5, cy = 26 + Math.floor(i / 16) * 24;
        b += `<rect x="${cx}" y="${cy}" width="22" height="18" rx="3" fill="${i < filled ? "var(--bad)" : "none"}" stroke="${i < filled ? "var(--bad)" : "var(--line)"}"/>`;
      }
      b += T(8, 90, `${rate} SYN/s × ${SYN_TO} s d'attente = ${num(rate * SYN_TO)} places demandées`, "f-s", "start");
      if (occ >= 1) b += R(8, 104, 190, 40, "f-bad") + T(103, 120, "client légitime", "f-b") + T(103, 136, "porte complète ✗", "ft-bad") + AR(198, 124, 238, 124, "f-bad") + T(300, 128, "refusé : file pleine", "ft-bad f-s");
      else b += R(8, 104, 190, 40, "f-ok") + T(103, 120, "client légitime", "f-b") + T(103, 136, "accepté ✓", "ft-ok") + AR(198, 124, 238, 124) + T(300, 128, "poignée de main OK", "ft-ok f-s");
      b += T(8, 176, c.cookies || c.cdn ? "SYN cookies : le serveur ne réserve rien ;" : "Sans cookies : une place par SYN, même usurpé ;", c.cookies || c.cdn ? "ft-ok f-s" : "ft-bad f-s", "start");
      b += T(8, 192, c.cookies || c.cdn ? "l'état est dans le numéro de séquence, vérifié au retour de l'ACK." : "les adresses inventées ne répondent jamais : la place expire après 5 s.", "f-s", "start");
      return { cap: c.cookies || c.cdn ? "Avec SYN cookies (ou un CDN qui termine les connexions), la file ne se remplit plus : les nouveaux clients passent." : "Chaque SYN réserve une place pendant 5 secondes : à 600 par seconde, la file de 256 places est pleine bien avant la fin. Les nouveaux clients, légitimes compris, trouvent la porte complète.", svg: SVG(204, "File de connexions et SYN cookies", b) };
    },
    amplification: () => {
      const x = F(), cl = x.closed || {}, open = ["relais", "annuaire"].filter(k => !cl[k]);
      const out_ = ATK * FACTOR;
      let b = R(8, 20, 92, 50) + T(54, 40, "Mallory", "f-b") + T(54, 58, "110 req/s", "f-s") +
        AR(100, 45, 150, 45, "f-bad") + T(125, 36, "source =", "f-s") + T(125, 66, "victime", "f-s") +
        R(150, 14, 120, 62, "f-bad") + T(210, 34, "services ouverts", "f-b ft-bad") + T(210, 52, "(2000 réflecteurs)", "f-s") + T(210, 68, `facteur ×${FACTOR}`, "f-s") +
        AR(270, 45, 318, 45, "f-bad") + T(294, 36, num(out_), "ft-bad f-s") +
        R(318, 20, 94, 50, "f-bad") + T(365, 40, "vitrine", "f-b") + T(365, 58, "reçoit tout", "f-s");
      b += T(8, 100, `110 × ${FACTOR} = ${num(out_)} réponses/s pour 110 requêtes envoyées`, "ft-bad f-s", "start");
      b += T(8, 118, "La victime ne voit que des innocents : bloquer par adresse est vain.", "f-s", "start");
      b += T(8, 148, "Notre propre réseau :", "f-b", "start");
      b += T(8, 168, `relais d'écho ×${OPEN.relais} : ${cl.relais ? "coupé ✓" : "OUVERT ✗"}`, cl.relais ? "ft-ok f-s" : "ft-bad f-s", "start");
      b += T(8, 184, `annuaire ×${OPEN.annuaire} : ${cl.annuaire ? "coupé ✓" : "OUVERT ✗"}`, cl.annuaire ? "ft-ok f-s" : "ft-bad f-s", "start");
      b += T(8, 200, `anti-usurpation à la sortie : ${x.antispoof ? "actif ✓" : "inactif ✗"}`, x.antispoof ? "ft-ok f-s" : "ft-bad f-s", "start");
      b += T(8, 224, open.length || !x.antispoof ? "Chaque réseau qui ne filtre pas fournit aux attaquants un déguisement ou un écho." : "Notre réseau n'aide plus personne à attaquer.", "f-s", "start");
      return { cap: "Réflexion et amplification, en chiffres jouets : l'attaquant dépense peu, la victime reçoit beaucoup, depuis des sources qui n'ont rien à se reprocher. Les parades durables sont chez les autres réseaux : anti-usurpation, services fermés.", svg: SVG(236, "Réflexion et amplification", b) };
    },
    courbe: () => {
      const x = F(), L = x.last;
      if (!L) return { cap: "Aucun siège joué pour l'instant.", svg: SVG(60, "Courbe", T(210, 34, "(lance un siège)", "f-s")) };
      const st = L.steps, n = st.length, X = i => 44 + i * (360 / (n - 1));
      const mx = Math.max(1, ...st.map(s => s.hostIn));
      const pa = st.map((s, i) => `${X(i).toFixed(1)},${(112 - s.avail * 90).toFixed(1)}`).join(" ");
      const ph = st.map((s, i) => `${X(i).toFixed(1)},${(230 - s.hostIn / mx * 80).toFixed(1)}`).join(" ");
      const pp = st.map((s, i) => `${X(i).toFixed(1)},${(230 - s.hostPass / mx * 80).toFixed(1)}`).join(" ");
      let b = T(8, 14, "Trafic légitime servi (%)", "f-b", "start") + LN(44, 22, 44, 112) + LN(44, 112, 404, 112) +
        T(40, 28, "100", "f-s", "end") + T(40, 114, "0", "f-s", "end") + LN(44, 22, 404, 22, "f-dash") +
        `<polyline points="${pa}" fill="none" stroke="var(--ok)" stroke-width="2.2"/>`;
      if (x.alert) b += `<line x1="44" y1="${(112 - x.alert * 0.9).toFixed(1)}" x2="404" y2="${(112 - x.alert * 0.9).toFixed(1)}" stroke="var(--you)" stroke-dasharray="3 4"/>` + T(404, (112 - x.alert * 0.9 - 3).toFixed(1), `alerte ${x.alert} %`, "ft-priv f-s", "end");
      b += T(8, 138, "Trafic hostile : qui arrive / qui passe les défenses", "f-b", "start") + LN(44, 144, 44, 230) + LN(44, 230, 404, 230) +
        T(40, 156, num(mx), "f-s", "end") + T(40, 232, "0", "f-s", "end") +
        `<polyline points="${ph}" fill="none" stroke="var(--bad)" stroke-width="2" stroke-dasharray="5 3"/>` +
        `<polyline points="${pp}" fill="none" stroke="var(--you)" stroke-width="2.2"/>`;
      b += T(44, 250, "0 s", "f-s") + T(404, 250, `${(n - 1) * DT} s`, "f-s") + T(10, 270, "─ ─ arrive", "ft-bad f-s", "start") + T(112, 270, "── passe", "ft-priv f-s", "start") + T(214, 270, "── servi", "ft-ok f-s", "start");
      return { cap: `Dernier siège (${L.wid === "final" ? "final" : "n° " + L.wid}) : disponibilité ${Math.round(L.avail * 1000) / 10} %, coût ${money(L.cost)}. Plus l'écart entre « arrive » et « passe » est grand, plus tes défenses travaillent.`, svg: SVG(280, "Courbe du trafic légitime et hostile avec défenses", b) };
    },
    limite: () => {
      const L = F().cfg.limit || 0, lab = L ? `limite : ${L} req/s` : "pas de limite";
      const rows = [["clients ordinaires", 0.5, 338, "ok"], ["collège (1 adresse)", 16, 1, "ok"], ["attaque concentrée", 40, 10, "bad"], ["attaque dispersée", 0.5, 400, "bad"]];
      const sx = v => 150 + Math.min(v, 45) / 45 * 260;
      let b = T(8, 14, `Débit par adresse (req/s) · ${lab}`, "f-s", "start");
      rows.forEach(([name, per, cnt, kind], i) => {
        const y = 36 + i * 42, pass = L ? Math.min(per, L) : per;
        b += T(8, y + 12, name, "f-s", "start") + T(8, y + 26, `${cnt} adresse${cnt > 1 ? "s" : ""}`, "f-s", "start");
        b += `<rect x="150" y="${y}" width="${(sx(per) - 150).toFixed(1)}" height="12" rx="3" fill="none" stroke="${kind === "ok" ? "var(--ok)" : "var(--bad)"}"/>` +
          `<rect x="150" y="${y}" width="${Math.max(1, sx(pass) - 150).toFixed(1)}" height="12" rx="3" fill="${kind === "ok" ? "var(--ok)" : "var(--bad)"}"/>` + T(sx(per) + 4, y + 10, per + "/s", "f-s", "start");
        if (L && per > L) b += T(150, y + 26, kind === "ok" ? "FAUX POSITIF : bloqué" : "bloqué en partie", kind === "ok" ? "ft-bad f-s" : "ft-ok f-s", "start");
      });
      if (L) b += `<line x1="${sx(L).toFixed(1)}" y1="26" x2="${sx(L).toFixed(1)}" y2="200" stroke="var(--you)" stroke-dasharray="3 4"/>`;
      b += T(8, 214, "L'attaque dispersée ressemble à des clients ordinaires : aucun plafond ne la voit.", "f-s", "start");
      return { cap: "Barre pleine : ce qui passe sous la limite ; contour : le débit réel de chaque groupe d'adresses. Un plafond bas arrête l'attaque concentrée mais pénalise le réseau partagé ; l'attaque dispersée passe toujours.", svg: SVG(224, "Limitation de débit par adresse", b) };
    },
  };

  GAMES.dos = {
    id: "dos", order: 32, title: "Le Siège de Port-443", pageTitle: "DoS Quest", subtitle: "aventure textuelle · déni de service",
    blurb: "Le marché est assiégé : règle les défenses d'un simulateur de capacité, du tuyau à la base de données.",
    concept: "Déni de service : comprendre et défendre",
    start: "place", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.cfg = newCfg(); x.ran = {}; x.done = {}; x.best = {}; x.closed = {}; x.antispoof = false; x.alert = 0; x.law = {}; },
    refig(name) { fig(name); },
    figAlias: { ressource: ["resource", "carte"], file: ["syn", "cookies", "connexions"], amplification: ["reflexion", "echo", "amplif"], courbe: ["trafic", "graphique"], limite: ["debit", "rate"] },
    help: "Spécifiques : `lancer ‹1-4|final›` · `courbe` · `alerte ‹%›` · `activer`/`desactiver ‹défense›` · `echelle ‹n›` · `limiter ‹n›` · `delai ‹s›` · `couper ‹service›` · `auditer` · `amplifier ‹débit› ‹facteur›` · `filtrer reponses` · `trou noir ‹cible›` · `rouvrir` · `etat` · `loi` · `juger ‹n› ‹legal|illegal›` · `communiquer ‹n›` · `retex`",
    verbs: {
      run: { words: ["lancer", "simuler", "assieger", "siege"], run: runCmd },
      curve: { words: ["courbe", "courbes", "graphique"], run: curveCmd },
      alert: { words: ["alerte", "seuil", "alarme"], run: alertCmd },
      activate: { words: ["activer", "enclencher", "allumer"], run: c => toggleCmd(c, true) },
      deactivate: { words: ["desactiver", "eteindre", "retirer"], run: c => toggleCmd(c, false) },
      scale: { words: ["echelle", "autoscaling", "dimensionner"], run: scaleCmd },
      limit: { words: ["limiter", "limite", "plafonner", "plafond"], run: limitCmd },
      timeout: { words: ["delai", "delais", "timeout", "patience"], run: delaiCmd },
      state: { words: ["etat", "config", "configuration", "defenses"], run: stateOut },
      cut: { words: ["couper", "interdire"], run: cutCmd },
      audit: { words: ["auditer", "audit"], run: auditCmd },
      amp: { words: ["amplifier", "amplification"], run: ampCmd },
      filter: { words: ["filtrer", "filtre"], run: filterCmd },
      hole: { words: ["trou noir", "blackhole", "sacrifier"], run: holeCmd },
      reopen: { words: ["rouvrir", "retablir"], run: reopenCmd },
      law: { words: ["loi", "droit"], run: lawCmd },
      judge: { words: ["juger", "trancher"], run: judgeCmd },
      comm: { words: ["communiquer", "message"], run: commCmd },
      retex: { words: ["retex", "retour"], run: retexCmd },
    },
    intro() {
      out("Le Siège de Port-443", "title");
      out("Le marché de Port-443 est assiégé. Depuis ce matin, la porte, le serveur web de la banque, est saturée : Bob n'arrive plus à passer commande. Maître Ada te nomme responsable de l'exploitation. Tout se passe dans un simulateur de capacité : la « charge » est un nombre de requêtes par seconde, les capacités sont des chiffres jouets, et il n'existe ici aucun outil d'attaque réel : seulement de quoi comprendre et défendre.");
    },
  };
  GAMES.dos._sim = { simulate, WAVES, newCfg };
})();
