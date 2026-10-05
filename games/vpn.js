"use strict";
/* Le Tunnel de Port-443 : VPN, WireGuard, IPsec. Simulation pédagogique : petits nombres, chiffrement jouet, vraie logique de routage. */
(function () {
  const F = () => f();

  /* ---------- constantes de la simulation ---------- */
  const P = 1019, GEN = 2; // groupe jouet pour Diffie-Hellman (en vrai : Curve25519)
  const A_PRIV = 347, GW_PRIV = 618, M_PRIV = 555;
  const A_PUB = modpow(GEN, A_PRIV, P), GW_PUB = modpow(GEN, GW_PRIV, P), M_PUB = modpow(GEN, M_PRIV, P);
  const EPH = [[283, 731], [409, 152], [517, 866], [164, 905]]; // clés éphémères privées (Alice, passerelle) par poignée de main
  const LAN = "192.168.4.23", TUN = "10.8.0.2", GW = "198.51.100.7", CAFE_DNS = "192.168.4.1", GW_DNS = "10.8.0.1", CAFE_PUB = "192.0.2.80";
  const INTRA = "10.20.0.5", NEWS = "203.0.113.50";

  /* ---------- adresses et CIDR (calcul réel) ---------- */
  const ipn = s => s.split(".").reduce((a, b) => a * 256 + Number(b), 0);
  const okIp = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split(".").every(o => +o <= 255);
  function parseCidrs(txt) {
    const parts = String(txt).split(/[,\s;]+/).filter(Boolean);
    if (!parts.length) return null;
    const res = [];
    for (const p of parts) {
      const m = p.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
      if (!m || !okIp(m[1]) || (m[2] !== undefined && +m[2] > 32)) return null;
      const bits = m[2] === undefined ? 32 : +m[2];
      res.push({ txt: m[1] + "/" + bits, net: ipn(m[1]), bits });
    }
    return res;
  }
  const inCidr = (ip, c) => { const size = 2 ** (32 - c.bits); return Math.floor(ipn(ip) / size) === Math.floor(c.net / size); };
  const inAllowed = ip => (parseCidrs(F().allowed) || []).some(c => inCidr(ip, c));
  const yes = s => /^(oui|on|true|1|actif|active|activer|yes)/i.test(s.trim());
  const no = s => /^(non|off|false|0|inactif|desactive|desactiver|no)/i.test(s.trim());

  /* ---------- chiffrement jouet : flux dérivé de SHA-256, étiquette d'authentification ---------- */
  const hexOf = a => a.map(b => b.toString(16).padStart(2, "0")).join("");
  function stream(key, ctr, n) {
    const o = []; let i = 0;
    while (o.length < n) { const h = sha256(key + "|" + ctr + "|" + i++); for (let j = 0; j < 64; j += 2) o.push(parseInt(h.substr(j, 2), 16)); }
    return o.slice(0, n);
  }
  const xorb = (bytes, key, ctr) => { const k = stream(key, ctr, bytes.length); return bytes.map((b, i) => b ^ k[i]); };
  const enc = (key, ctr, s) => xorb(Array.from(new TextEncoder().encode(s)), key, ctr);
  const dec = (key, ctr, bytes) => new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(xorb(bytes, key, ctr)));
  const tagOf = (key, ctr, bytes) => sha256(key + "|tag|" + ctr + "|" + hexOf(bytes)).slice(0, 16);
  const visible = s => s.replace(/[^\x20-\x7e]/g, "·");
  const dots = (s, n) => s.length > n ? s.slice(0, n) + "…" : s;

  /* ---------- trafic d'Alice : quatre flux, routés selon la configuration ---------- */
  function flows() {
    const x = F();
    return [
      { kind: "dns", label: "DNS : intranet.guilde", dst: x.dns, proto: "UDP", port: 53, data: "A? intranet.guilde.port443", who: "résolveur" },
      { kind: "web", label: "Intranet (fiche de paie)", dst: INTRA, proto: "TCP", port: x.https ? 443 : 80,
        data: x.https ? "TLS 1.3 : contenu chiffré [SNI : intranet.guilde.port443]" : "GET /paie · Cookie: session=alice-9f3a", clearText: !x.https },
      { kind: "dns", label: "DNS : actualites", dst: x.dns, proto: "UDP", port: 53, data: "A? actualites.port443", who: "résolveur" },
      { kind: "web", label: "Site d'actualités (HTTPS)", dst: NEWS, proto: "TCP", port: 443, data: "TLS 1.3 : contenu chiffré [SNI : actualites.port443]" },
    ];
  }
  function routeOf(p) {
    const x = F();
    if (x.up && !x.cut && inAllowed(p.dst)) return "tunnel";
    return x.kill ? "blocked" : "clear";
  }
  const ROUTE_TXT = { tunnel: "→ dans le tunnel", clear: "→ EN CLAIR sur le Wi-Fi", blocked: "→ BLOQUÉ (kill switch)" };
  function seal(p) {
    const x = F(); x.ctr = (x.ctr || 0) + 1;
    const plain = `${TUN}>${p.dst}|${p.proto}/${p.port}|${p.data}`;
    const ct = enc(x.key, x.ctr, plain), tg = tagOf(x.key, x.ctr, ct);
    x.rec = { plain, ct, tg, ctr: x.ctr };
    return { ctr: x.ctr, plain, ct, tg, len: Math.ceil((28 + p.data.length) / 16) * 16 + 32 + 28 };
  }
  // ce que voit le Wi-Fi pour un flux (consomme un compteur si le paquet est scellé)
  function wifiView(p, r) {
    if (r === "blocked") return null;
    if (r === "clear") return `${LAN} → ${p.dst}   ${p.proto}/${p.port}\n   contenu : ${p.data}`;
    const s = seal(p);
    return `${LAN} → ${GW}   UDP/51820   (${s.len} octets)\n   contenu : ${hexOf(s.ct).slice(0, 28)}…`;
  }
  const mode = () => { const n = flows().map(routeOf).filter(r => r === "tunnel").length; return n === 0 ? "clear" : n === 4 ? "tunnel" : "split"; };

  /* ---------- poignée de main (Diffie-Hellman jouet) ---------- */
  function newHs() {
    const x = F(), n = x.n || 0, [ea, eb] = EPH[n % EPH.length]; x.n = n + 1;
    const Ea = modpow(GEN, ea, P), Eb = modpow(GEN, eb, P), shared = modpow(Eb, ea, P);
    return { n: n + 1, ea, eb, Ea, Eb, shared, same: shared === modpow(Ea, eb, P) };
  }
  const sessionKey = h => sha256(`wg-toy:${h.shared}:${h.Ea}:${h.Eb}`);

  /* ---------- carnet ---------- */
  const notes = {
    tunnel: ["Le tunnel", "Sur un réseau qu'on ne contrôle pas (café, hôtel), n'importe qui peut observer les paquets. Un VPN crée un tunnel chiffré entre ton appareil et une passerelle de confiance : ce qui traverse le réseau local est opaque, et ton trafic ressort ensuite depuis la passerelle."],
    encaps: ["L'encapsulation", "Le paquet d'origine (ses en-têtes et son contenu) est chiffré en entier, puis devient la charge utile d'un nouveau paquet adressé à la passerelle. Le réseau local ne voit que l'en-tête externe. La passerelle déchiffre, vérifie l'étiquette d'authentification, et réexpédie le paquet d'origine."],
    cles: ["Les clés WireGuard", "Chaque pair a une paire de clés : une clé privée, secrète, et une clé publique qui en est dérivée à sens unique. On échange les clés publiques (idéalement par un canal fiable) et on les inscrit dans la configuration : la clé publique de la passerelle sert à vérifier qu'on parle bien à elle, et pas à un imposteur."],
    eph: ["L'échange de clés éphémère", "Les deux pairs génèrent des clés Diffie-Hellman éphémères, échangent les parties publiques, et calculent chacun le même secret partagé, sans qu'il ne circule. Les clés éphémères sont effacées et renouvelées régulièrement : une clé privée volée plus tard ne permet pas de déchiffrer le trafic enregistré avant (confidentialité persistante)."],
    meta: ["Les métadonnées restent visibles", "Même dans le tunnel, le réseau local voit encore : ton adresse, l'adresse de la passerelle, le protocole, la taille et le rythme des paquets, les heures d'activité. Il ne voit plus le contenu, ni les destinations réelles, ni les noms de sites demandés."],
    dns: ["La fuite DNS", "Avant de se connecter, un site se résout en adresse par une requête DNS. Si le résolveur reste celui du café, ou si ces requêtes ne passent pas dans le tunnel, le café apprend quels sites tu visites même si le reste est chiffré. Parades : DNS dans le tunnel, et AllowedIPs complet (0.0.0.0/0) si on veut tout protéger."],
    kill: ["Le kill switch", "Si le tunnel tombe (coupure, plantage du client), l'ordinateur peut renvoyer discrètement le trafic en clair par le réseau local. Un kill switch est une règle de pare-feu qui bloque tout ce qui ne passe pas par le tunnel : on perd la connexion, mais rien ne fuit. Il suppose un tunnel complet."],
    confiance: ["La confiance déplacée", "Un VPN ne supprime pas l'observateur : il le remplace. Le fournisseur (ou la passerelle) voit tout ce qui sort du tunnel : destinations, noms DNS, et contenu quand il n'est pas chiffré par HTTPS. Il ne rend pas anonyme (comptes, cookies, empreinte du navigateur) et ne remplace pas HTTPS."],
    ipsec: ["IPsec : IKE, ESP, AH, tunnel et transport", "IPsec est l'autre grande famille de VPN. IKE négocie les algorithmes, authentifie les pairs et dérive les clés. ESP chiffre et authentifie, AH n'authentifie que (rien n'est caché). Mode transport : on protège la charge utile, l'en-tête IP reste. Mode tunnel : tout le paquet d'origine est encapsulé, avec un nouvel en-tête IP."],
  };

  /* ---------- entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, qui supervise cet audit autorisé. Elle tient sa tasse à deux mains : le thé du Quai est détestable, mais la table est près de la prise." },
    gerant: { npc: true, names: ["gerant", "patron", "cafetier", "barman"], label: "le gérant du café", desc: () => "Le gérant du Café du Quai, tablier à rayures. Son routeur Wi-Fi journalise les connexions « pour la sécurité du service »." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, la capuche relevée, un renifleur de paquets ouvert sur sa tablette. Dans cet audit autorisé, elle joue l'attaquante du café. Tout reste simulé." },
    ordi: { names: ["ordi", "ordinateur", "portable", "laptop"], label: "l'ordinateur portable d'Alice", desc: () => `L'ordinateur d'Alice. Adresse sur le Wi-Fi : ${LAN}. Résolveur DNS donné par le café : ${CAFE_DNS}. Commandes : \`connecter\`, \`tester\`, \`couper tunnel\`, \`reconnecter\`, \`regler ‹champ› ‹valeur›\`.` },
    config: { names: ["config", "configuration", "wg0", "fichier", "conf"], label: "le fichier de configuration wg0.conf", desc: () => "Le fichier wg0.conf d'Alice, de type WireGuard.",
      onExamine() { const x = F(); out("Le fichier est affiché ci-dessous. Tu peux le modifier : `regler allowedips ‹réseaux›`, `regler dns ‹adresse›`, `regler killswitch oui|non`, `regler https oui|non`.", "sys"); code(confText()); } },
    etabli: { names: ["etabli", "forge", "atelier"], label: "l'établi à clés", desc: () => "Un établi de cuivre et de verre : on y fabrique des paires de clés. `generer cles` en tire une, au hasard simulé." },
    cles: { names: ["cles", "paire de cles", "cle privee", "cle publique"], label: "ta paire de clés", desc: () => `Ta clé privée : **${A_PRIV}** (secrète : elle ne quitte jamais l'ordinateur). Ta clé publique : **${A_PUB}** = ${GEN}^${A_PRIV} mod ${P}. À ta connaissance, personne ne sait remonter de l'une à l'autre... à condition d'utiliser de vrais grands nombres (voir bilan).` },
    cle_gw: { names: ["cle passerelle", "cle de la passerelle", "empreinte"], label: "la clé publique de la passerelle", desc: () => `La clé publique de la passerelle : **${GW_PUB}**, relevée sur la passerelle elle-même et confirmée par Maître Ada sur papier. C'est le « Peer PublicKey » de ta configuration.` },
    sentinelle: { npc: true, names: ["sentinelle", "passerelle gardienne", "gardienne"], label: "la Sentinelle de la passerelle", desc: () => "La Sentinelle, une silhouette de métal sombre qui garde l'entrée du tunnel. Elle déchiffre ce qui lui arrive, vérifie les étiquettes, et réexpédie vers l'intérieur et vers Internet." },
    passerelle: { names: ["passerelle", "gateway", "serveur", "serveur vpn"], label: "la passerelle VPN de la Guilde",
      desc: () => `La passerelle de la Guilde. Adresse publique : ${GW}, port UDP 51820. Adresse dans le tunnel : ${GW_DNS}. Clé publique : **${GW_PUB}**.`,
      onExamine() { const x = F(); if (!x.gw) { x.gw = true; give("cle_gw"); out("Tu notes la clé publique de la passerelle, et tu la compares à l'empreinte que Maître Ada t'avait donnée sur papier : elles correspondent. C'est elle qu'on inscrira comme « Peer ».", "ok"); } } },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, l'oreille toujours collée à une antenne. Elle écoute tout ce qui passe, sans jamais rien modifier. Ici, elle tient les écrans de l'observatoire." },
    ecrans: { names: ["ecrans", "ecran", "moniteurs"], label: "les écrans d'Ève", desc: () => "Trois écrans : ce que voit le Wi-Fi du café, ce que voit la passerelle, ce que voit le site visité. `comparer` les affiche pour le trafic d'Alice." },
    passeur: { npc: true, names: ["passeur", "vendeur", "fournisseur"], label: "le Passeur, fournisseur commercial de VPN", desc: () => "Le Passeur, sourire de vendeur : « Navigue anonymement, protège-toi partout ! », annonce son enseigne. Il loue des passerelles à des milliers de clients." },
  };
  function confText() {
    const x = F();
    return `[Interface]
PrivateKey = ${A_PRIV}
Address = ${TUN}/32
DNS = ${x.dns}

[Peer]
PublicKey = ${GW_PUB}
Endpoint = ${GW}:51820
AllowedIPs = ${x.allowed}
PersistentKeepalive = 25

# (hors fichier) kill switch : ${x.kill ? "OUI" : "non"} · navigateur en HTTPS partout : ${x.https ? "OUI" : "non"}`;
  }

  const rooms = {
    cafe: { name: "Le Café du Quai", short: "Café", alias: ["cafe", "quai"], ents: ["ada", "gerant", "mallory"], exits: { nord: "passerelle", est: "atelier", ouest: "observatoire", sud: "comptoir" },
      desc: () => "Un café du port, tables en bois, Wi-Fi gratuit (mot de passe écrit sur l'ardoise : « port443 », comme tout le monde le sait). Alice travaille près de la fenêtre. Au nord, la passerelle de la Guilde. À l'est, l'atelier des clés. À l'ouest, l'observatoire d'Ève. Au sud, le comptoir du Passeur." },
    atelier: { name: "L'atelier des clés", short: "Atelier", alias: ["atelier", "cles"], ents: ["etabli"], exits: { ouest: "cafe" },
      desc: () => "Un atelier calme, des clés suspendues, une odeur de laiton. C'est ici qu'on fabrique les paires de clés." },
    passerelle: { name: "La passerelle de la Guilde", short: "Passerelle", alias: ["passerelle", "tunnel"], ents: ["passerelle", "sentinelle"], exits: { sud: "cafe" },
      desc: () => "Une porte blindée au bout d'un couloir : l'entrée du tunnel. De l'autre côté, le réseau de la Guilde et, au-delà, Internet. La Sentinelle monte la garde." },
    observatoire: { name: "L'observatoire d'Ève", short: "Observatoire", alias: ["observatoire"], ents: ["eve", "ecrans"], exits: { est: "cafe" },
      desc: () => "Une pièce pleine d'antennes et d'écrans, dont trois sont tournés vers le trafic d'Alice. Un panneau : « Observer n'est pas modifier. »" },
    comptoir: { name: "Le comptoir du Passeur", short: "Comptoir", alias: ["comptoir", "passeur"], ents: ["passeur"], exits: { nord: "cafe" },
      desc: () => "Un comptoir lumineux, des affiches d'un bleu rassurant : « 10 000 serveurs, 0 inquiétude ». Le Passeur propose de t'abonner à sa passerelle." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.sniff) return "sniff";
    if (!x.keys) return "keys";
    if (!x.gw) return "gw";
    if (!x.up) return x.pend ? "derive" : "up";
    if (!x.tested) return "test1";
    if (!x.full) return "full";
    if (!x.compared) return "compare";
    if (!x.killOK) return "kill";
    if (x.cut) return "reconn";
    if (!x.ipsecA) return "ipsecA";
    if (!x.ipsecB) return "ipsecB";
    if (!x.usurp) return "usurp";
    if (!x.stolen) return "stolen";
    if (!x.provSeen) return "prov";
    if (!x.provHttps) return "https";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend au café.", "`parler ada`"],
    sniff: () => ["Avant de protéger quoi que ce soit, regarde ce que le Wi-Fi laisse voir. Mallory a un renifleur.", "`ecouter` (au café)"],
    keys: () => ["Un tunnel commence par des clés. L'atelier est à l'est du café.", "`aller est`, `generer cles`"],
    gw: () => ["Il faut aussi la clé publique de la passerelle, relevée sur place.", "`aller ouest`, `aller nord`, `examiner passerelle`"],
    up: () => ["Tu as les deux clés : monte le tunnel. L'ordinateur d'Alice fait la poignée de main avec la passerelle.", "`connecter`"],
    derive: () => { const h = F().hs; return ["La poignée de main attend ton calcul : le secret partagé, c'est la clé éphémère publique de la passerelle élevée à ta clé éphémère privée, modulo p. La calculatrice est là pour ça.", `\`calc ${h.Eb}^${h.ea} mod ${P}\` puis \`deriver ‹résultat›\` (résultat attendu : ${h.shared}).`]; },
    test1: () => ["Envoie le trafic d'Alice : quatre requêtes habituelles.", "`tester`"],
    full: () => ["Tout ne part pas dans le tunnel : relis `examiner config` et regarde AllowedIPs et DNS. `schema` montre les routes.", "`regler allowedips 0.0.0.0/0`, `regler dns 10.8.0.1`, puis `tester`"],
    compare: () => ["Va voir ce que chaque observateur perçoit désormais : l'observatoire est à l'ouest du café.", "`aller ouest`, `comparer`"],
    kill: () => {
      const x = F();
      if (!x.killLeak) return ["Et si le tunnel tombait en pleine séance ? Simule la panne, puis teste.", "`couper tunnel`, puis `tester`"];
      if (!x.kill) return ["Ça a fui. Ajoute une règle qui bloque tout ce qui ne passe pas par le tunnel, puis re-teste pendant la panne.", "`regler killswitch oui`, puis `tester`"];
      return ["Le kill switch est actif : teste pendant la panne (le tunnel doit être coupé).", "`couper tunnel`, puis `tester`"];
    },
    reconn: () => ["Le client doit se reconnecter : le tunnel renégocie des clés éphémères neuves.", "`reconnecter`"],
    ipsecA: () => ["La Sentinelle parle aussi IPsec. Cas « nomade » : Alice doit atteindre le réseau de la Guilde et Internet via la passerelle. Quel mode, quel protocole ? Essaie des combinaisons : `parler sentinelle` rappelle le choix.", "`aller nord` (depuis le café), puis `ipsec nomade tunnel esp`"],
    ipsecB: () => ["Cas « serveurs » : deux serveurs de la Guilde se parlent directement et sont eux-mêmes les extrémités. Il n'y a pas besoin de nouvelle adresse externe.", "`ipsec serveurs transport esp`"],
    usurp: () => ["Que se passe-t-il si Mallory se fait passer pour la passerelle ? Laisse-la essayer, au café.", "`aller sud`, puis `usurper`"],
    stolen: () => ["Plus tard, Mallory vole la clé privée de la passerelle. Peut-elle relire le trafic qu'elle a enregistré ?", "`attaquer` (au café, avec Mallory)"],
    prov: () => ["Le Passeur propose son VPN à la place de la passerelle de la Guilde. Que verrait-il ? Il tient des journaux.", "`aller sud`, `aller sud`, puis `journaux`"],
    https: () => ["Une requête de l'intranet sort en HTTP clair : le fournisseur la lirait. Passe-la en HTTPS, puis regarde à nouveau ses journaux.", "`regler https oui`, puis `journaux` (au comptoir)"],
    end: () => ["Rends compte à Maître Ada, au café.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; x.allowed = "10.8.0.0/24"; x.dns = CAFE_DNS; x.kill = false; x.https = false;
          give("ordi"); give("config");
          say("Maître Ada", "Bienvenue au Café du Quai. Alice, de la Guilde, doit travailler d'ici aujourd'hui. Le Wi-Fi est gratuit, donc ouvert à tous : le gérant, les clients, et Mallory voient passer les paquets. Notre audit est autorisé et tout est simulé : nous n'attaquons personne.");
          say("Maître Ada", "Ton rôle : protéger Alice avec un tunnel VPN vers notre passerelle, puis vérifier honnêtement ce qui est protégé et ce qui ne l'est pas. Voici son ordinateur et son fichier de configuration. Commence par regarder ce que le Wi-Fi laisse voir : Mallory a un renifleur.");
          out("Tu reçois **l'ordinateur d'Alice** et **wg0.conf**. Commence par `ecouter`.", "sys");
        } else if (x.end) say("Maître Ada", "Alice travaille tranquille, et nous savons ce que le tunnel couvre... et ce qu'il ne couvre pas. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "Ce n'est pas fini. `indice` si tu bloques.");
        break;
      case "gerant":
        if (!x.up || x.cut) say("Gérant", "Mon routeur journalise qui se connecte et vers quoi : pour la sécurité du service, bien sûr. Je ne lis pas les paquets, mais n'importe quel client avec un renifleur peut le faire. Ce n'est pas mon rayon.");
        else say("Gérant", `Votre ordinateur parle beaucoup à ${GW}, en UDP. Je vois le volume et les horaires. De quoi il parle ? Aucune idée : c'est illisible.`);
        break;
      case "mallory":
        if (!x.quest) say("Mallory", "Je suis cliente comme les autres. Ada a des papiers signés, je n'ai pas le droit de rien faire de plus que ce qu'elle autorise.");
        else say("Mallory", "Mon renifleur lit le Wi-Fi : `ecouter`. Quand tu auras un tunnel, je peux tenter de me faire passer pour la passerelle (`usurper`), ou de relire le trafic enregistré avec une clé volée (`attaquer`).");
        break;
      case "eve":
        say("Ève", "Je ne modifie rien : j'écoute. `comparer` te montre, pour chacun des quatre flux d'Alice, ce que voient trois observateurs : le Wi-Fi du café (le gérant et Mallory), la passerelle, et le site visité.");
        break;
      case "sentinelle":
        say("Sentinelle", "Je parle WireGuard (tu l'as vu) et IPsec. Pour IPsec : IKE négocie, puis ESP chiffre et authentifie, AH authentifie sans chiffrer. Deux cas à régler : le « nomade » (Alice, laptop vers moi, pour joindre le réseau de la Guilde et Internet) et les « serveurs » (deux machines qui se parlent directement). Syntaxe : `ipsec ‹nomade|serveurs› ‹tunnel|transport› ‹esp|ah›`. Essaie des combinaisons : je te montre les paquets.");
        break;
      case "passeur":
        if (!x.provSeen) say("Passeur", "Mon VPN protège tout : Wi-Fi public, hôtels, aéroports ! Je fais passer tout le trafic de mes clients par mes serveurs. Pour ma tranquillité et la tienne, je tiens des journaux... `journaux` si tu veux voir ce qu'ils pourraient contenir.");
        else say("Passeur", "Je ne vends rien, promis. Mais techniquement, oui, je vois tout ce qui sort de mon tunnel. Et si on me réclame mes journaux par la loi, ou si je me fais pirater, c'est tout un historique qui sort. Pour un VPN, la question est toujours : à qui fais-tu confiance ?");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function needQuest() { if (!F().quest) { out("Va d'abord voir Maître Ada.", "sys"); return true; } return false; }

  function listen() {
    const x = F();
    if (S.room !== "cafe") { out("Le renifleur de Mallory est au café.", "sys"); return; }
    if (needQuest()) return;
    const fl = flows(), md = mode();
    out("Le renifleur de Mallory (autorisé par l'audit) affiche ce qui passe sur le Wi-Fi pendant qu'Alice travaille :", "sys");
    const lines = [];
    fl.forEach(p => { const v = wifiView(p, routeOf(p)); if (v) lines.push(v); });
    code(lines.length ? lines.join("\n") : "(rien : le kill switch bloque tout)");
    if (md === "clear") {
      out("Tout est lisible : les noms de sites demandés (DNS), l'adresse de l'intranet, et même le cookie de session d'Alice dans la requête HTTP. Seul le contenu du site d'actualités est chiffré (HTTPS), mais son nom (SNI) et son adresse sont visibles.", "err");
      if (!x.sniff) { x.sniff = true; note("tunnel"); fig("vues"); }
    } else if (md === "tunnel") {
      out("Il ne reste que des paquets UDP vers la passerelle, d'apparence aléatoire. Rien de lisible : mais leur nombre, leur taille et leur rythme le sont.", "ok");
      x.sniff = true; note("tunnel"); note("meta");
    } else if (md === "split") {
      out("Une partie du trafic est dans le tunnel, une autre part en clair. Compare avec `schema split`.", "err");
      x.sniff = true; note("tunnel");
    } else x.sniff = true;
  }

  function keygen() {
    const x = F();
    if (S.room !== "atelier") { out("Les clés se fabriquent à l'atelier (à l'est du café).", "sys"); return; }
    if (needQuest()) return;
    if (x.keys) { out("Tu as déjà ta paire de clés : `examiner cles`.", "sys"); return; }
    x.keys = true; give("cles");
    out("Le tirage au sort (simulé) donne une clé privée. L'établi en dérive la clé publique par une opération à sens unique : g^privée mod p.", "ok");
    code(`clé privée  a = ${A_PRIV}      (SECRÈTE)\nclé publique A = ${GEN}^${A_PRIV} mod ${P} = ${A_PUB}   (à partager)`);
    out("En vrai, ce sont des nombres de 256 bits (Curve25519), écrits en base64 : 44 caractères. La clé privée ne quitte jamais l'ordinateur ; la publique va dans la configuration de la passerelle.", "sys");
    note("cles");
  }

  function connect() {
    const x = F();
    if (needQuest()) return;
    if (!x.keys) { out("Il te faut d'abord une paire de clés (`aller est`, `generer cles`).", "err"); return; }
    if (!x.gw) { out("Il te faut la clé publique de la passerelle (`aller nord` puis `examiner passerelle`) : sans elle, comment savoir à qui on parle ?", "err"); return; }
    if (x.up) { out(x.cut ? "Le tunnel est coupé : `reconnecter`." : "Le tunnel est déjà monté.", "sys"); return; }
    if (!x.pend) { x.hs = newHs(); x.pend = true; }
    const h = x.hs;
    out("Poignée de main avec la passerelle. L'ordinateur vérifie que la clé publique reçue correspond à celle de la configuration, puis les deux côtés échangent des clés éphémères :", "sys");
    code(`Alice  → passerelle : Ea = ${GEN}^${h.ea} mod ${P} = ${h.Ea}   (ea = ${h.ea} reste secret)\npasserelle → Alice  : Eb = ${GEN}^${h.eb} mod ${P} = ${h.Eb}   (eb reste secret à la passerelle)`);
    out(`Le secret partagé est s = Eb^ea mod p (côté Alice) = Ea^eb mod p (côté passerelle). À toi de le calculer côté Alice : \`calc ${h.Eb}^${h.ea} mod ${P}\`, puis \`deriver ‹résultat›\`.`, "sys");
  }
  function derive(c) {
    const x = F();
    if (!x.pend) { out("Rien à dériver pour l'instant : `connecter` d'abord.", "sys"); return; }
    const m = c.rawArg.match(/-?\d+/);
    if (!m) { out("`deriver ‹nombre›` : le résultat de ton calcul.", "err"); return; }
    const v = +m[0], h = x.hs;
    if (v !== h.shared) {
      if (v === h.Ea || v === h.Eb) out("Ce nombre est une clé publique éphémère : elle circule déjà sur le réseau. Le secret est le résultat de Eb^ea mod p.", "err");
      else out(`Ce n'est pas ça : ton ordinateur et la passerelle ne partageraient pas la même clé, et le premier paquet serait rejeté (étiquette d'authentification invalide). Vérifie : \`calc ${h.Eb}^${h.ea} mod ${P}\`.`, "err");
      return;
    }
    x.pend = false; x.up = true; x.cut = false; x.key = sessionKey(h);
    out(`Côté passerelle : Ea^eb mod p = ${h.Ea}^${h.eb} mod ${P} = **${modpow(h.Ea, h.eb, P)}**. Même secret, sans qu'il n'ait jamais circulé.`, "ok");
    out("Les deux côtés dérivent la clé de session en la mélangeant avec les clés publiques, puis effacent leurs clés éphémères privées.", "sys");
    code(`clé de session = SHA-256("wg-toy:${h.shared}:${h.Ea}:${h.Eb}")\n               = ${x.key.slice(0, 32)}…`);
    out("Tunnel monté. `tester` pour envoyer le trafic d'Alice.", "ok");
    note("eph"); fig("echange");
  }
  function reconnect() {
    const x = F();
    if (!x.up) { out("Pas de tunnel à rétablir : `connecter`.", "sys"); return; }
    if (!x.cut) { out("Le tunnel n'est pas coupé.", "sys"); return; }
    x.cut = false; const h = newHs(); x.hs = h; x.key = sessionKey(h);
    out(`Le client se reconnecte et renégocie en arrière-plan : nouvelles clés éphémères (Ea = ${h.Ea}, Eb = ${h.Eb}), nouvelle clé de session. L'ancienne est perdue : même un enregistrement de la précédente séance ne sert plus à rien.`, "ok");
  }
  function cutCmd() {
    const x = F();
    if (!x.up) { out("Il n'y a pas de tunnel à couper.", "sys"); return; }
    if (x.cut) { out("Le tunnel est déjà coupé.", "sys"); return; }
    x.cut = true;
    out("Panne simulée : le Wi-Fi vacille et le client VPN perd la connexion (il retire ses routes). `tester` pour voir ce que fait l'ordinateur d'Alice pendant la coupure.", "sys");
  }

  function testCmd() {
    const x = F();
    if (needQuest()) return;
    const fl = flows(), rs = fl.map(routeOf);
    out(`Alice lance ses quatre requêtes habituelles ${!x.up ? "(pas de tunnel)" : x.cut ? "(tunnel coupé)" : "(tunnel monté)"} :`, "sys");
    code(fl.map((p, i) => `${i + 1}. ${p.label.padEnd(26)} ${ROUTE_TXT[rs[i]]}`).join("\n"));
    const firstT = rs.findIndex((r, i) => r === "tunnel" && fl[i].kind === "web") >= 0 ? rs.findIndex((r, i) => r === "tunnel" && fl[i].kind === "web") : rs.indexOf("tunnel");
    if (firstT >= 0) {
      fl.forEach((p, i) => { if (rs[i] === "tunnel" && i !== firstT) seal(p); });
      const p = fl[firstT], s = seal(p);
      if (!x.shownEnc) {
        x.shownEnc = true;
        out(`Prenons la requête ${firstT + 1}. Voici son encapsulation :`, "sys");
        code(`1. paquet d'origine (dans l'ordinateur, jamais sur le Wi-Fi) :\n   ${TUN} → ${p.dst}  ${p.proto}/${p.port}  « ${p.data} »\n\n2. chiffré avec la clé de session (compteur ${s.ctr}) :\n   ${hexOf(s.ct).slice(0, 56)}…  (${s.ct.length} octets)\n   étiquette d'authentification : ${s.tg}\n\n3. paquet réellement envoyé sur le Wi-Fi :\n   [IP ${LAN} → ${GW}] [UDP 51820] [en-tête WG, compteur ${s.ctr}] [données chiffrées] [étiquette]`);
        const ok = tagOf(x.key, s.ctr, s.ct) === s.tg;
        out(`La passerelle vérifie l'étiquette : ${ok ? "valide" : "INVALIDE"}. Elle déchiffre et retrouve : « ${dec(x.key, s.ctr, s.ct)} », qu'elle réexpédie.`, "ok");
        note("encaps"); fig("paquet");
      }
    }
    x.tested = x.tested || (x.up && !x.cut);
    if (!x.up) { out("Tout part en clair : c'est ce que le Wi-Fi voit. `connecter` pour monter le tunnel (après avoir fabriqué les clés et relevé celle de la passerelle).", "err"); return; }
    if (x.cut) {
      const clearN = rs.filter(r => r === "clear").length, blkN = rs.filter(r => r === "blocked").length;
      if (clearN) {
        x.killLeak = true;
        out(`${clearN} requêtes sont parties en clair par le Wi-Fi alors qu'Alice croit être protégée. Le gérant et Mallory voient tout, sans qu'aucune alerte ne s'affiche. Sans kill switch, le plus dangereux est que la panne passe inaperçue.`, "err");
        if (!x.kill) out("Parade : `regler killswitch oui`, puis re-teste pendant la panne.", "sys");
      } else if (blkN === 4 && x.kill) {
        x.killOK = true;
        out("Rien ne part : le pare-feu bloque tout ce qui ne passe pas par le tunnel. Alice n'a plus de connexion, mais plus rien ne fuit. C'est le but d'un kill switch. `reconnecter` pour rétablir le tunnel.", "ok");
        note("kill"); fig("split");
      }
      return;
    }
    const dnsLeak = fl.some((p, i) => p.kind === "dns" && rs[i] === "clear");
    const clearN = rs.filter(r => r === "clear").length, blkN = rs.filter(r => r === "blocked").length;
    if (dnsLeak) { out("Fuite DNS : les questions « quelle est l'adresse de… ? » partent au résolveur du café, en clair. Le café apprend les noms des sites visités (intranet.guilde.port443, actualites.port443), même si le reste est chiffré.", "err"); note("dns"); }
    if (rs.some((r, i) => fl[i].kind === "web" && r === "clear")) out("Le trafic vers le site d'actualités (203.0.113.50) est hors du tunnel : AllowedIPs ne couvre que 10.8.0.0/24. C'est du « split tunneling » : seule la partie listée passe par la passerelle.", "err");
    if (blkN) out(`${blkN} flux sont bloqués : avec le kill switch, tout ce qui sort du tunnel est interdit. Un kill switch suppose un tunnel complet (AllowedIPs 0.0.0.0/0).`, "err");
    if (clearN || blkN) { x.leakSeen = true; fig("split"); out("`examiner config` pour corriger AllowedIPs et DNS.", "sys"); }
    else { x.full = true; out("Tout le trafic, DNS compris, passe dans le tunnel.", "ok"); fig("split"); }
  }

  function setCmd(c) {
    const x = F();
    if (needQuest()) return;
    const m = c.rawArg.match(/^(allowed[ _-]?ips|routes?|dns|kill[ _-]?switch|https)\s*=?\s*(.*)$/i);
    if (!m) { out("Que régler ? `regler allowedips ‹réseaux›` · `regler dns ‹adresse›` · `regler killswitch oui|non` · `regler https oui|non`", "err"); return; }
    const k = m[1].toLowerCase().replace(/[ _-]/g, ""), v = m[2].trim();
    if (!v) { out("Il manque la valeur. `examiner config` montre l'état actuel.", "err"); return; }
    const live = x.up ? " (appliqué à chaud, comme `wg syncconf`)" : "";
    if (/^(allowedips|route)/.test(k)) {
      const list = parseCidrs(v);
      if (!list) { out("Format invalide. Attendu : des réseaux CIDR séparés par des virgules, par exemple `0.0.0.0/0` ou `10.8.0.0/24, 10.20.0.0/16`.", "err"); return; }
      x.allowed = list.map(c => c.txt).join(", ");
      out(`AllowedIPs = ${x.allowed}${live}`, "ok");
      out(list.some(c => c.bits === 0) ? "0.0.0.0/0 : tout le trafic IPv4 passe par le tunnel." : "Seules ces destinations passeront dans le tunnel : c'est du split tunneling. Tout le reste sort en clair par le Wi-Fi.", "sys");
    } else if (k === "dns") {
      if (!okIp(v)) { out("Une adresse IPv4 est attendue, par exemple `10.8.0.1`.", "err"); return; }
      x.dns = v; out(`DNS = ${v}${live}`, "ok");
      out(inAllowed(v) ? "Cette adresse est dans AllowedIPs : les requêtes DNS passeront dans le tunnel." : "Cette adresse n'est PAS dans AllowedIPs : les requêtes partent par le Wi-Fi, en clair, vers ce résolveur.", "sys");
    } else if (/^kill/.test(k)) {
      if (yes(v)) { x.kill = true; out("Kill switch activé : tout paquet qui ne passe pas par le tunnel est bloqué.", "ok"); }
      else if (no(v)) { x.kill = false; out("Kill switch désactivé.", "sys"); }
      else out("`regler killswitch oui` ou `non`.", "err");
    } else if (k === "https") {
      if (yes(v)) { x.https = true; out("Le navigateur d'Alice utilise HTTPS pour l'intranet (la requête devient chiffrée de bout en bout, vers le serveur).", "ok"); }
      else if (no(v)) { x.https = false; out("HTTPS désactivé pour l'intranet (HTTP clair).", "sys"); }
      else out("`regler https oui` ou `non`.", "err");
    }
  }

  function compare() {
    const x = F();
    if (S.room !== "observatoire") { out("Les écrans d'Ève sont à l'observatoire (à l'ouest du café).", "sys"); return; }
    if (needQuest()) return;
    const fl = flows(), rs = fl.map(routeOf), md = mode();
    out("Pour chaque flux d'Alice, ce que voient trois observateurs :", "sys");
    const lines = [];
    fl.forEach((p, i) => {
      const r = rs[i]; let w, g, s;
      if (r === "blocked") { w = "rien (bloqué)"; g = "rien"; s = "rien"; }
      else if (r === "clear") { w = `${p.dst}:${p.port} · ${dots(p.data, 40)}`; g = "ne voit rien"; s = p.kind === "dns" ? `résolveur du café (${p.dst}) : question lisible` : `source ${CAFE_PUB} (le café)`; }
      else { const sl = seal(p); w = `vers ${GW}:51820 · ${sl.len} o · ${hexOf(sl.ct).slice(0, 12)}…`; g = `${p.dst}:${p.port} · ${dots(p.data, 40)}`; s = p.kind === "dns" ? `résolveur de la passerelle (${GW_DNS})` : `source ${GW} (la passerelle)`; }
      lines.push(`${i + 1}. ${p.label}\n   Wi-Fi (gérant, Mallory) : ${w}\n   Passerelle              : ${g}\n   Site / résolveur        : ${s}`);
    });
    code(lines.join("\n\n"));
    if (md === "clear") out("Le Wi-Fi voit tout. Il n'y a pas de passerelle ni de tunnel.", "err");
    else {
      x.compared = true; note("meta");
      out("Le gérant voit encore l'adresse de la passerelle, le volume et le rythme : pas le contenu, ni les destinations réelles. La passerelle voit désormais ce que le café voyait : elle est le nouvel observateur de confiance. Et le site voit la passerelle, pas Alice.", md === "tunnel" ? "ok" : "err");
    }
    fig("vues");
  }

  function journals() {
    const x = F();
    if (S.room !== "comptoir") { out("Les journaux du Passeur sont au comptoir (au sud du café).", "sys"); return; }
    if (needQuest()) return;
    if (!x.up || x.cut) { out("Aucun trafic d'Alice ne passe par le Passeur : ton tunnel (celui de la Guilde) est coupé ou pas monté. Reconnecte-le d'abord (`connecter` ou `reconnecter`) : on regarde ce qu'un fournisseur verrait de ce même trafic.", "sys"); return; }
    out("Le Passeur t'ouvre ses journaux : voici ce qu'un fournisseur de VPN peut consigner, pour le trafic d'Alice si elle passait par lui (tout ce que vous lui envoyez dans le tunnel) :", "sys");
    const fl = flows(), rs = fl.map(routeOf), lines = [];
    fl.forEach((p, i) => {
      if (rs[i] !== "tunnel") { lines.push(`(flux ${i + 1} : ne passe pas par lui, il n'en sait rien)`); return; }
      lines.push(`${new Date(Date.UTC(2026, 9, 5, 14, i, 0)).toISOString().slice(11, 19)}  compte alice  → ${p.dst}:${p.port}  ${p.proto}\n         ${p.data}`);
    });
    code(lines.join("\n"));
    if (!x.provSeen) { x.provSeen = true; note("confiance"); fig("vues"); }
    const clearWeb = fl.some((p, i) => rs[i] === "tunnel" && p.clearText);
    out(clearWeb ? "Il lit ton HTTP clair, ton cookie de session et les noms de sites. Même quand le contenu est en HTTPS, il connaît les destinations et les horaires. Le VPN a déplacé la confiance du café vers lui." : "Le contenu HTTPS lui reste opaque : il ne voit que les destinations, les noms (SNI, DNS) et les horaires. Mais il sait quand même qui visite quoi.", clearWeb ? "err" : "ok");
    if (x.https && clearWeb === false && x.provSeen) x.provHttps = true;
    if (!x.https) out("Pour réduire ce que le fournisseur lit, chiffre de bout en bout : `regler https oui`, puis `journaux` à nouveau.", "sys");
    else out("Un VPN ne remplace pas HTTPS : le tunnel s'arrête à la passerelle, HTTPS continue jusqu'au serveur. Et il n'anonymise pas : le compte (alice), les cookies et l'empreinte du navigateur te désignent toujours.", "sys");
  }

  function ipsecCmd(c) {
    const x = F();
    if (S.room !== "passerelle") { out("La Sentinelle négocie IPsec à la passerelle (au nord du café).", "sys"); return; }
    if (needQuest()) return;
    const t = norm(c.rawArg).split(" ");
    const sc = t.includes("nomade") || t.includes("alice") ? "A" : t.includes("serveurs") || t.includes("serveur") ? "B" : null;
    const md = t.includes("tunnel") ? "tunnel" : t.includes("transport") ? "transport" : null;
    const pr = t.includes("esp") ? "esp" : t.includes("ah") ? "ah" : null;
    if (!sc || !md || !pr) { out("`ipsec ‹nomade|serveurs› ‹tunnel|transport› ‹esp|ah›`, par exemple `ipsec nomade tunnel esp`.", "err"); return; }
    if (!x.ipsecSeen) { x.ipsecSeen = true; out("IKE (UDP 500, ou 4500 si NAT) négocie d'abord : algorithmes, authentification des pairs, échange Diffie-Hellman, puis crée les associations de sécurité (SA) qui servent à ESP ou AH.", "sys"); }
    const inner = sc === "A" ? `IP ${TUN}→${INTRA} | TCP 80 | GET /paie` : `IP 10.20.0.5→10.20.0.9 | TCP 5432 | requête SQL`;
    const A = sc === "A";
    const o1 = A ? `${LAN} → ${GW}` : "10.20.0.5 → 10.20.0.9", o2 = A ? `${LAN} → ${GW}` : "10.20.0.5 → 10.20.0.9";
    let pk;
    if (md === "tunnel" && pr === "esp") pk = `[IP ${o1} · proto 50 (ESP)] [ESP : SPI, n°] [▒▒ ${inner} ▒▒] [trailer ESP] [ICV]\n   ▒ = chiffré`;
    else if (md === "transport" && pr === "esp") pk = `[IP ${o2} · proto 50 (ESP)] [ESP : SPI, n°] [▒▒ ${A ? "TCP 80 | GET /paie" : "TCP 5432 | requête SQL"} ▒▒] [trailer ESP] [ICV]`;
    else if (md === "tunnel") pk = `[IP ${o1} · proto 51 (AH)] [AH : SPI, n°, ICV] [${inner}]  ← EN CLAIR, seulement signé`;
    else pk = `[IP ${o2} · proto 51 (AH)] [AH : SPI, n°, ICV] [${A ? "TCP 80 | GET /paie" : "TCP 5432 | requête SQL"}]  ← EN CLAIR, seulement signé`;
    out(`Cas ${A ? "« nomade »" : "« serveurs »"}, mode ${md}, ${pr.toUpperCase()} : paquet sur le réseau :`, "sys");
    code(pk);
    if (!x.figIpsec) { x.figIpsec = true; fig("ipsec"); }
    if (pr === "ah") { out("AH authentifie et protège l'intégrité, mais ne chiffre rien : le contenu reste lisible par le gérant. (De plus, AH couvre des champs de l'en-tête IP, ce qui le rend incompatible avec le NAT.) Pour la confidentialité, c'est ESP, qui authentifie aussi.", "err"); return; }
    if (A) {
      if (md === "tunnel") { x.ipsecA = true; out("C'est la bonne combinaison pour un nomade : le paquet d'origine (adresses internes comprises) est chiffré en entier et réexpédié par la passerelle, derrière un nouvel en-tête IP. C'est le mode « passerelle ».", "ok"); note("ipsec"); }
      else out("En mode transport, l'en-tête IP d'origine est conservé : le paquet serait adressé à la passerelle elle-même, qui ne le retransmettrait pas vers l'intranet ni Internet. Pour qu'une passerelle relaie le trafic d'un nomade, il faut encapsuler tout le paquet : mode tunnel.", "err");
    } else {
      if (md === "transport") { x.ipsecB = true; out("Bien vu : les deux serveurs sont les extrémités. Pas besoin d'un nouvel en-tête (ce serait 20 octets de plus par paquet pour rien) : on protège juste la charge utile.", "ok"); note("ipsec"); }
      else out("Ça fonctionne, mais on encapsule un paquet dont l'extrémité est déjà l'hôte lui-même : 20 octets de plus par paquet pour rien. Le mode tunnel sert surtout aux passerelles (site à site, nomades). Ici, le mode transport suffit.", "err");
    }
  }

  function usurp() {
    const x = F();
    if (S.room !== "cafe") { out("Mallory est au café.", "sys"); return; }
    if (needQuest()) return;
    if (!x.gw) { say("Mallory", "Je n'ai pas encore de passerelle à imiter. Va d'abord relever sa clé publique."); return; }
    out("Mallory capte la connexion et répond à la place de la passerelle, avec sa propre paire de clés :", "sys");
    code(`clé publique reçue par l'ordinateur : ${M_PUB}\nclé attendue (wg0.conf, Peer)       : ${GW_PUB}`);
    x.usurp = true;
    out("L'ordinateur compare : les clés diffèrent, la poignée de main est refusée. Mallory ne peut pas se faire passer pour la passerelle, car elle n'a pas la clé privée correspondant à la clé publique inscrite dans la configuration. C'est tout l'intérêt de relever la clé de la passerelle par un canal fiable.", "ok");
    out("Si Alice avait accepté n'importe quelle clé à la première connexion, Mallory aurait été le « pair » : elle aurait tout déchiffré et réexpédié (attaque de l'homme du milieu). Vérifier l'empreinte, c'est le rôle de ce qu'on appelle l'authentification des pairs.", "sys");
    fig("echange");
  }

  function attack(c) {
    const x = F();
    if (S.room !== "cafe") { out("Mallory est au café.", "sys"); return; }
    if (needQuest()) return;
    if (!x.rec) { say("Mallory", "Je n'ai rien d'enregistré à relire. Fais d'abord travailler Alice dans le tunnel : `tester`."); return; }
    if (c.rawArg && !/tunnel|trafic|cle|dechiffr|passerelle|voler|vol/.test(norm(c.rawArg))) { out("`attaquer` (sans argument) : Mallory tente de relire le trafic enregistré avec la clé privée volée.", "err"); return; }
    const r = x.rec;
    out(`Un an plus tard, Mallory a volé la clé privée statique de la passerelle (${GW_PRIV}). Elle a aussi enregistré tous les paquets chiffrés du Wi-Fi. Elle tente de relire celui-ci (compteur ${r.ctr}) :`, "sys");
    const staticShared = modpow(A_PUB, GW_PRIV, P), sk = sha256(`wg-toy-static:${staticShared}`);
    code(`paquet enregistré : ${hexOf(r.ct).slice(0, 56)}…\nclé dérivée des clés statiques : ${sk.slice(0, 24)}…\ndéchiffrement → ${dots(visible(dec(sk, r.ctr, r.ct)), 60)}`);
    out("Du bruit : la clé de session dépendait du secret éphémère, et les clés éphémères privées ont été effacées après la poignée de main. Voler la clé statique plus tard ne donne pas accès au passé : c'est la confidentialité persistante (forward secrecy).", "ok");
    out("Contre-exemple : un tunnel qui n'aurait utilisé QUE les clés statiques :", "sys");
    const ct2 = enc(sk, r.ctr, r.plain);
    code(`même contenu chiffré avec la clé dérivée des clés statiques : ${hexOf(ct2).slice(0, 40)}…\nMallory, avec la clé statique volée → ${dec(sk, r.ctr, ct2)}`);
    out("Là, tout l'historique serait lisible. Les clés éphémères évitent cela.", "err");
    x.stolen = true; fig("echange");
  }

  /* ---------- épilogue et bilan ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Alice travaille derrière un tunnel complet : le café ne voit plus que du chiffré vers notre passerelle, le DNS ne fuit plus, un kill switch coupe tout si le tunnel tombe, et Mallory ne peut ni imiter la passerelle ni relire le passé. Retiens aussi les limites : ce que voit la passerelle, et ce que HTTPS fait que le VPN ne fait pas.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le Café du Quai = un réseau non fiable.** Wi-Fi public, hôtel, aéroport : le gérant et n'importe qui sur le même réseau peuvent observer, voire modifier, ce qui passe. **La passerelle = le serveur VPN**, que tu choisis de croire.");
    out("**Le tunnel et l'encapsulation.** Le paquet d'origine, avec ses adresses et son contenu, est chiffré en entier et devient la charge utile d'un nouveau paquet (en-tête IP externe + UDP + en-tête VPN). La passerelle déchiffre, vérifie l'étiquette d'authentification, puis réexpédie le paquet d'origine. WireGuard est en UDP (port 51820 par défaut) ; IPsec utilise le protocole ESP (n° 50) ou AH (n° 51) directement sur IP, et IKE en UDP 500/4500.");
    out("**Les clés WireGuard et la poignée de main.** Clé privée et clé publique Curve25519 (32 octets). La clé publique de la passerelle dans « Peer » authentifie la passerelle : Mallory ne peut pas l'imiter. À chaque session, des clés éphémères Diffie-Hellman sont échangées, et le secret partagé dérive des clés symétriques (ChaCha20-Poly1305). WireGuard renégocie environ toutes les deux minutes et efface les clés éphémères : c'est la confidentialité persistante.");
    out("**AllowedIPs, split tunneling et fuite DNS.** Dans WireGuard, AllowedIPs sert à la fois de table de routage (quoi envoyer dans le tunnel) et de filtre à l'arrivée. Avec 0.0.0.0/0, tout passe par la passerelle ; avec une liste, seul ce qui la correspond. Le split tunneling est légitime (économiser la bande passante, atteindre l'imprimante locale), mais ce qui reste hors du tunnel est visible du réseau local. Les requêtes DNS comptent : un résolveur hors tunnel révèle les noms visités. Autres fuites à garder en tête : IPv6, WebRTC, applications qui contournent le VPN.");
    out("**Le kill switch.** Règle de pare-feu qui interdit tout trafic hors tunnel (sauf la connexion vers la passerelle elle-même). Si le tunnel tombe, rien ne fuit. Il suppose un tunnel complet : avec un split tunneling, tout ce qui est hors liste serait bloqué.");
    out("**IPsec : IKE, ESP, AH, modes tunnel et transport.** IKEv2 négocie algorithmes et clés et authentifie les pairs (certificats, secret partagé). ESP chiffre et authentifie ; AH authentifie seulement, sans chiffrer, et gêne le NAT : il est rare aujourd'hui. Mode transport : on garde l'en-tête IP d'origine et on protège la charge utile (hôte à hôte). Mode tunnel : on encapsule tout le paquet derrière un nouvel en-tête IP (passerelle à passerelle, nomade à passerelle).");
    out("**Ce que voit chaque observateur.** Le café voit encore l'adresse de la passerelle, la taille et le rythme des paquets (métadonnées). La passerelle voit les destinations et le contenu non chiffré. Le site voit l'adresse de la passerelle, pas la tienne. **Le Passeur = n'importe quel fournisseur de VPN** : tu déplaces la confiance du café vers lui. Il voit tout ce qui sort du tunnel et peut journaliser, ou être contraint de livrer ses journaux, ou être piraté.");
    out("**VPN n'est ni anonymat, ni HTTPS.** Ton compte, tes cookies, ton empreinte de navigateur te désignent toujours ; l'adresse de la passerelle est partagée par d'autres clients, mais ce n'est pas un anonymat. Et le tunnel s'arrête à la passerelle : sans HTTPS, le reste du chemin est en clair. Les deux protections se complètent.");
    out("**Les simplifications du jeu.** (1) Le groupe Diffie-Hellman (p = 1019) est trivial à casser par recherche exhaustive : en vrai, Curve25519 (256 bits) rend cette attaque impossible. (2) Le chiffrement jouet (flux dérivé de SHA-256 + étiquette) remplace ChaCha20-Poly1305 ; pas de vrai protocole Noise IK (échange avec clés statiques et éphémères mêlées), ni protection anti-rejeu, ni cookies anti-DoS. (3) La coupure du tunnel est modélisée comme la disparition des routes (comportement de nombreux clients) ; un WireGuard pur avec 0.0.0.0/0 laisse en général les paquets sans issue plutôt que de les laisser fuir, mais le kill switch protège contre l'arrêt du client, le split tunneling et d'autres cas. (4) On n'a pas parlé d'OpenVPN, de WireGuard multi-pairs, de MTU, ni du chiffrement post-quantique. (5) Un seul fournisseur et quatre flux : en vrai il y en a des centaines.");
    out("Rappel utile : **un VPN chiffre le trajet entre ton appareil et la passerelle, pas au-delà : il déplace la confiance du réseau local vers le fournisseur, il n'anonymise pas, et il ne dispense pas de HTTPS.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    paquet: () => ({
      cap: "Avant : le paquet d'origine est lisible sur le Wi-Fi. Après : il est chiffré en entier et devient la charge utile d'un paquet adressé à la passerelle.",
      svg: SVG(230, "Encapsulation d'un paquet",
        T(8, 16, "Sans VPN (sur le Wi-Fi)", "f-b", "start") +
        R(8, 24, 404, 44, "f-bad") + R(14, 30, 120, 32) + T(74, 44, "IP", "f-s") + T(74, 57, "→ 10.20.0.5", "f-s") + R(140, 30, 64, 32) + T(172, 50, "TCP 80", "f-s") + R(210, 30, 196, 32, "f-bad") + T(308, 50, "GET /paie (lisible)", "f-s ft-bad") +
        T(8, 94, "Avec VPN (sur le Wi-Fi)", "f-b", "start") +
        R(8, 102, 404, 84, "f-ok") + R(14, 108, 100, 32) + T(64, 122, "IP externe", "f-s") + T(64, 135, "→ passerelle", "f-s") + R(118, 108, 70, 32) + T(153, 128, "UDP 51820", "f-s") + R(192, 108, 76, 32) + T(230, 128, "en-tête WG", "f-s") + R(342, 108, 64, 32) + T(374, 128, "étiquette", "f-s") +
        R(14, 146, 392, 34, "f-priv") + T(210, 160, "chiffré : IP 10.8.0.2→10.20.0.5 | TCP 80 | GET /paie", "f-s ft-priv") + T(210, 174, "(le paquet d'origine, en entier)", "f-s ft-priv") +
        T(210, 206, "Le réseau voit : adresse de passerelle, UDP, taille.", "f-s") + T(210, 222, "Ni la destination réelle, ni le contenu.", "f-s"))
    }),
    echange: () => {
      const x = F(), h = x.hs;
      const hasH = !!h;
      return {
        cap: hasH ? `Échange éphémère (jouet : p = ${P}, g = ${GEN}). Seules les valeurs publiques voyagent. Le secret ${h.shared} n'apparaît jamais sur le réseau.` : `Échange de clés (jouet : p = ${P}, g = ${GEN}). Seules les valeurs publiques voyagent.`,
        svg: SVG(250, "Échange de clés Diffie-Hellman",
          R(8, 10, 110, 40) + T(63, 28, "Alice", "f-b") + T(63, 43, "ordinateur", "f-s") +
          R(302, 10, 110, 40) + T(357, 28, "Passerelle", "f-b") + T(357, 43, "198.51.100.7", "f-s") +
          LN(63, 50, 63, 232, "f-dash") + LN(357, 50, 357, 232, "f-dash") +
          T(63, 76, hasH ? `ea = ${h.ea}` : "ea (éphémère)", "f-s ft-priv") + T(357, 76, hasH ? `eb = ${h.eb}` : "eb (éphémère)", "f-s ft-priv") +
          T(63, 92, "secrète", "f-s") + T(357, 92, "secrète", "f-s") +
          AR(70, 116, 350, 116, "f-pub") + T(210, 108, hasH ? `Ea = ${GEN}^${h.ea} mod ${P} = ${h.Ea}` : "Ea = g^ea mod p", "f-s ft-pub") +
          AR(350, 150, 70, 150, "f-pub") + T(210, 142, hasH ? `Eb = ${GEN}^${h.eb} mod ${P} = ${h.Eb}` : "Eb = g^eb mod p", "f-s ft-pub") +
          T(210, 126, "(Ève voit Ea et Eb)", "f-s ft-bad") +
          T(8, 184, hasH ? `Eb^ea = ${h.shared}` : "Eb^ea mod p", "f-b ft-ok", "start") + T(412, 184, hasH ? `Ea^eb = ${h.shared}` : "Ea^eb mod p", "f-b ft-ok", "end") +
          T(210, 184, "=", "f-b") +
          T(210, 214, "même secret des deux côtés, jamais envoyé", "f-s ft-ok") +
          T(210, 236, "clé de session = SHA-256(secret, Ea, Eb)", "f-s"))
      };
    },
    vues: () => {
      const md = mode();
      const bad = "ft-bad", ok = "ft-ok";
      const wifi = md === "clear" ? [["source", LAN, bad], ["destination", "toutes + noms DNS", bad], ["contenu", "HTTP lisible, SNI", bad], ["volume, rythme", "visibles", bad]]
        : md === "tunnel" ? [["source", LAN, bad], ["destination", "passerelle seule", ok], ["contenu", "chiffré", ok], ["volume, rythme", "visibles", bad]]
          : [["source", LAN, bad], ["destination", "passerelle + fuites", bad], ["contenu", "chiffré + fuites", bad], ["volume, rythme", "visibles", bad]];
      const gw = md === "clear" ? [["source", "pas de tunnel", ""], ["destination", "-", ""], ["contenu", "-", ""], ["journaux", "-", ""]]
        : [["source", "Alice (10.8.0.2)", bad], ["destination", "réelles", bad], ["contenu", "lisible si HTTP", bad], ["journaux", "possibles", bad]];
      const site = md === "clear" ? [["adresse source", "192.0.2.80 (café)", bad], ["te reconnaît", "compte, cookie", bad], ["lieu", "le café", bad], ["IP d'Alice", "oui", bad]]
        : [["adresse source", "198.51.100.7 (GW)", ok], ["te reconnaît", "compte, cookie", bad], ["lieu", "celui de la GW", ok], ["IP d'Alice", "non", ok]];
      const col = (x0, title, rows, c) => R(x0, 8, 130, 160, c) + T(x0 + 65, 26, title, "f-b") + rows.map((r, i) => T(x0 + 65, 46 + i * 31, r[0], "f-s") + T(x0 + 65, 60 + i * 31, r[1], "f-s " + r[2])).join("");
      return {
        cap: "Ce que voit chaque observateur (rouge : exposé, vert : caché). Le tunnel cache le contenu et les destinations au café, mais la passerelle voit tout ce qui sort, et le site te reconnaît par ton compte.",
        svg: SVG(190, "Ce que voit chaque observateur", col(6, "Wi-Fi du café", wifi, "f-bad") + col(145, "Passerelle (VPN)", gw, "f-pub") + col(284, "Site visité", site, "f-ok") + T(210, 184, md === "clear" ? "état actuel : sans tunnel" : md === "tunnel" ? "état actuel : tunnel complet" : "état actuel : tunnel partiel", "f-s"))
      };
    },
    split: () => {
      const x = F(), fl = flows(), rs = fl.map(routeOf);
      const rows = [[fl[0], 0, "DNS → " + x.dns], [fl[1], 1, "intranet " + INTRA], [fl[3], 3, "actualités " + NEWS]];
      const laneT = 56, laneC = 140;
      const lines = rows.map(([, i, label], k) => {
        const y = 40 + k * 44, r = rs[i], ty = r === "tunnel" ? laneT : laneC;
        const cls = r === "tunnel" ? "f-ok" : r === "blocked" ? "f-bad f-dash" : "f-bad";
        return T(8, y + 4, label, "f-s", "start") + AR(190, y, 300, ty + (r === "tunnel" ? 0 : 0), cls);
      }).join("");
      return {
        cap: `AllowedIPs = ${x.allowed}. Ce qui correspond va dans le tunnel (vert), le reste part en clair sur le Wi-Fi (rouge) ou est bloqué par le kill switch (pointillés). ${x.up && !x.cut ? "Tunnel monté." : x.up ? "Tunnel coupé." : "Pas de tunnel."}`,
        svg: SVG(190, "Split tunneling",
          R(300, 30, 112, 52, "f-ok") + T(356, 52, "Tunnel chiffré", "f-b") + T(356, 70, "→ passerelle", "f-s") +
          R(300, 114, 112, 52, "f-bad") + T(356, 136, "Wi-Fi du café", "f-b") + T(356, 154, "en clair", "f-s") +
          T(8, 18, "Alice (ordinateur)", "f-b", "start") + lines +
          T(8, 184, `kill switch : ${x.kill ? "oui" : "non"}`, "f-s", "start"))
      };
    },
    ipsec: () => ({
      cap: "Mode transport : l'en-tête IP d'origine reste, seule la charge utile est protégée. Mode tunnel : tout le paquet d'origine est chiffré et encapsulé derrière un nouvel en-tête IP.",
      svg: SVG(200, "IPsec : transport et tunnel",
        T(8, 16, "Transport (ESP)", "f-b", "start") +
        R(8, 24, 404, 38) + R(12, 28, 84, 30) + T(54, 47, "IP d'origine", "f-s") + R(100, 28, 50, 30) + T(125, 47, "ESP", "f-s") + R(154, 28, 190, 30, "f-priv") + T(249, 47, "TCP | données (chiffrés)", "f-s ft-priv") + R(348, 28, 60, 30) + T(378, 47, "fin+ICV", "f-s") +
        T(8, 90, "Tunnel (ESP)", "f-b", "start") +
        R(8, 98, 404, 38) + R(12, 102, 78, 30) + T(51, 121, "IP nouvel", "f-s") + R(94, 102, 46, 30) + T(117, 121, "ESP", "f-s") + R(144, 102, 200, 30, "f-priv") + T(244, 121, "IP orig. | TCP | données", "f-s ft-priv") + R(348, 102, 60, 30) + T(378, 121, "fin+ICV", "f-s") +
        T(8, 168, "AH : authentifie seulement, rien n'est chiffré.", "f-s ft-bad", "start") + T(8, 188, "ESP : chiffre et authentifie (le choix courant).", "f-s ft-ok", "start"))
    }),
  };

  GAMES.vpn = {
    id: "vpn", order: 8, title: "Le Tunnel de Port-443", pageTitle: "VPN Quest", subtitle: "aventure textuelle · VPN, IPsec, WireGuard",
    blurb: "Protège Alice sur le Wi-Fi du café : clés, encapsulation, DNS, kill switch, et ce que le VPN ne cache pas.",
    concept: "VPN, IPsec, WireGuard",
    start: "cafe", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    figAlias: { paquet: ["encapsulation", "tunnel"], echange: ["cles", "diffie", "dh"], vues: ["observateurs", "metadonnees"], split: ["routes", "dns", "allowedips"], ipsec: ["transport", "esp"] },
    help: "Spécifiques : `ecouter` · `generer cles` · `connecter` · `deriver ‹nombre›` · `tester` · `regler allowedips|dns|killswitch|https ‹valeur›` · `couper tunnel` · `reconnecter` · `comparer` · `ipsec ‹nomade|serveurs› ‹tunnel|transport› ‹esp|ah›` · `usurper` · `attaquer` · `journaux`",
    verbs: {
      listen: { words: ["ecouter", "sniffer", "capturer", "renifler"], run: listen },
      keygen: { words: ["generer", "forger", "fabriquer"], run: keygen },
      connect: { words: ["connecter", "monter", "brancher", "demarrer"], run: connect },
      derive: { words: ["deriver", "secret"], run: derive },
      test: { words: ["tester", "envoyer", "naviguer", "travailler"], run: testCmd },
      set: { words: ["regler", "configurer", "editer", "modifier", "changer"], run: setCmd },
      cut: { words: ["couper", "deconnecter", "debrancher", "simuler"], run: cutCmd },
      reconn: { words: ["reconnecter", "retablir", "rebrancher"], run: reconnect },
      compare: { words: ["comparer", "observer"], run: compare },
      journals: { words: ["journaux", "journal", "logs"], run: journals },
      ipsec: { words: ["ipsec", "negocier", "choisir"], run: ipsecCmd },
      usurp: { words: ["usurper", "imiter"], run: usurp },
      attack: { words: ["attaquer", "dechiffrer", "voler"], run: attack },
    },
    intro() {
      out("Le Tunnel de Port-443", "title");
      out("Le Café du Quai de Port-443 offre son Wi-Fi : pratique, gratuit, et ouvert à tous. Alice, de la Guilde, doit y travailler aujourd'hui. Le gérant, les clients et Mallory voient passer ses paquets.\nMaître Ada t'engage, pour un audit autorisé et entièrement simulé, afin de construire un tunnel VPN vers la passerelle de la Guilde, puis d'en vérifier honnêtement les limites.", "");
    },
  };
})();
