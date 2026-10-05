"use strict";
/* Le Café du Wi-Fi : réseau ouvert, WEP, WPA2-Personnel (PMK/PTK, poignée de main), attaque hors ligne,
   WPA3-SAE, PMF, faux point d'accès et 802.1X. SHA-256 réel du moteur ; RC4 réel ; échange SAE jouet (modpow). */
(function () {
  const F = () => f();
  const SSID = "CafeDuPort", AP = "a4:5e:60:00:44:30", STA = "02:b0:b0:00:01:7e";
  const ITER = 1000;          // « PBKDF2 » simulé : 1000 tours de SHA-256 (le vrai : 4096 tours de HMAC-SHA1)
  const P = 2147483647;       // premier de Mersenne 2^31-1 : groupe jouet pour le SAE simulé
  const GPU = 1e7;            // essais/s supposés pour quelques GPU contre WPA2
  const FIRST = "croissant";
  const OLD_MSG = "GET /fidelite?user=bob&carte=4421";

  /* ---------- dictionnaire de Mallory : mots courants + variantes classiques ---------- */
  const WORDS = ["croissant", "expresso", "bienvenue", "motdepasse", "port443", "soleil", "azerty", "bonjour", "password", "internet", "chocolat", "baguette", "qwerty", "welcome", "boulangerie", "12345678", "cafeduport", "wifigratuit", "cappuccino", "clientvip"];
  const CANDS = (() => {
    const s = new Set();
    WORDS.forEach(w => [w, w[0].toUpperCase() + w.slice(1), w + "1", w + "123", w + "2024", w + "!"].forEach(c => { if (c.length >= 8 && c.length <= 63) s.add(c); }));
    return [...s];
  })();

  /* ---------- briques cryptographiques (simulées, mais vraiment calculées) ---------- */
  function pmk(pass) { const s = pass + SSID; let h = sha256(SSID + "|" + pass); for (let i = 1; i < ITER; i++) h = sha256(h + s); return h; }
  function ptk(pm, an, sn) {
    const b = "PTK|" + pm + "|" + AP + "|" + STA + "|" + an + "|" + sn;
    const full = sha256(b + "|1") + sha256(b + "|2");
    return { kck: full.slice(0, 32), kek: full.slice(32, 64), tk: full.slice(64, 96) };
  }
  const micOf = (kck, body) => sha256("MIC|" + kck + "|" + body).slice(0, 32);
  function handshake(pass, n) {
    const an = sha256("anonce" + n).slice(0, 32), sn = sha256("snonce" + n).slice(0, 32);
    const k = ptk(pmk(pass), an, sn);
    return { n, an, sn, mic: micOf(k.kck, "EAPOL-2|" + sn) };
  }
  const guessMic = (pass, cap) => micOf(ptk(pmk(pass), cap.an, cap.sn).kck, "EAPOL-2|" + cap.sn);
  const bytesOf = s => Array.from(new TextEncoder().encode(s));
  const hx = a => a.map(b => b.toString(16).padStart(2, "0")).join("");
  function stream(key, n) {
    const o = [];
    for (let c = 0; o.length < n; c++) { const h = sha256(key + "|" + c); for (let i = 0; i < 64 && o.length < n; i += 2) o.push(parseInt(h.substr(i, 2), 16)); }
    return o;
  }
  const encrypt = (key, msg) => { const m = bytesOf(msg), k = stream(key, m.length); return m.map((b, i) => b ^ k[i]); };
  const decrypt = (key, bytes) => { const k = stream(key, bytes.length); return bytes.map((b, i) => b ^ k[i]); };
  const printable = a => a.every(b => b >= 32 && b < 127);
  const txt = a => String.fromCharCode(...a);
  const sh = h => h.slice(0, 12) + "…";

  /* RC4 réel (pour la démonstration WEP) */
  function rc4(key, n) {
    const s = Array.from({ length: 256 }, (_, i) => i); let j = 0;
    for (let i = 0; i < 256; i++) { j = (j + s[i] + key[i % key.length]) & 255; [s[i], s[j]] = [s[j], s[i]]; }
    const o = []; let a = 0, b = 0;
    for (let t = 0; t < n; t++) { a = (a + 1) & 255; b = (b + s[a]) & 255; [s[a], s[b]] = [s[b], s[a]]; o.push(s[(s[a] + s[b]) & 255]); }
    return o;
  }
  const WEPKEY = [0x43, 0x61, 0x66, 0x65, 0x31]; // clé WEP-40 secrète de la vieille borne
  function mulberry(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
  function wepDemo() {
    const r = mulberry(443), seen = new Map(); let n = 0, iv = 0;
    for (;;) { n++; iv = Math.floor(r() * 16777216); if (seen.has(iv)) break; seen.set(iv, n); }
    const key = [(iv >> 16) & 255, (iv >> 8) & 255, iv & 255, ...WEPKEY];
    const p1 = bytesOf("GET /index.html "), p2 = bytesOf("pw=cafe-bob-2024"), ks = rc4(key, 16);
    const c1 = p1.map((b, i) => b ^ ks[i]), c2 = p2.map((b, i) => b ^ ks[i]);
    const x12 = c1.map((b, i) => b ^ c2[i]);
    return { n, first: seen.get(iv), iv, c1, c2, rec: txt(x12.map((b, i) => b ^ p1[i])) };
  }

  /* SAE jouet (inspiré de Dragonfly) : élément de mot de passe + échange de Diffie-Hellman masqué par lui */
  function pwe(pass) {
    for (let c = 1; ; c++) {
      const v = parseInt(sha256(pass + "|" + SSID + "|" + c).slice(0, 8), 16) % P;
      if (v > 1 && modpow(v, (P - 1) / 2, P) === 1) return v;   // « hunt-and-peck » : on cherche un carré
    }
  }
  const rnd = (tag, n) => 2 + parseInt(sha256(tag + n).slice(0, 8), 16) % (P - 3);
  function sae(clientPass, apPass, n) {
    const a = rnd("sae-a", n), b = rnd("sae-b", n);
    const A = modpow(pwe(clientPass), a, P), B = modpow(pwe(apPass), b, P);
    const Kc = modpow(B, a, P), Ka = modpow(A, b, P);
    return { A, B, Kc, Ka, ok: sha256("conf" + Kc + A + B) === sha256("conf" + Ka + A + B), a, b };
  }

  /* ---------- utilitaires de présentation ---------- */
  function dur(s) {
    if (s < 1) return "moins d'une seconde";
    if (s < 60) return Math.round(s) + " secondes";
    if (s < 3600) return Math.round(s / 60) + " minutes";
    if (s < 86400) return Math.round(s / 3600) + " heures";
    const d = s / 86400; if (d < 365) return Math.round(d) + " jours";
    const y = d / 365.25; if (y < 1e6) return Math.round(y).toLocaleString("fr-FR") + " ans";
    return "environ 10^" + Math.floor(Math.log10(y)) + " ans";
  }
  function brute(pass) {
    let cs = 0;
    if (/[a-z]/.test(pass)) cs += 26; if (/[A-Z]/.test(pass)) cs += 26; if (/[0-9]/.test(pass)) cs += 10; if (/[^a-zA-Z0-9]/.test(pass)) cs += 33;
    const total = Math.pow(cs, pass.length);
    return { cs, total, s: total / 2 / GPU, exp: Math.round(Math.log10(total)) };
  }
  const inDict = pw => CANDS.includes(pw);
  const capValid = () => { const x = F(); return !!(x.cap && x.cap.v === x.pv && x.mode === "wpa2"); };
  const modeName = () => ({ wpa2: "WPA2-Personnel", wpa3: "WPA3-Personnel (SAE)", ent: "WPA3-Entreprise (802.1X)" })[F().mode];
  const tail = c => c.rawArg.replace(/^(la\s+|ma\s+|une\s+)?(phrase de passe|phrase|mot de passe|mdp)\s*/i, "").trim();

  /* ---------- carnet ---------- */
  const notes = {
    evol: ["De l'ouvert au WPA3", "Réseau ouvert : rien n'est chiffré, tout se lit à la radio. WEP (1997) : RC4 avec un vecteur d'initialisation (IV) de 24 bits envoyé en clair et vite réutilisé ; clé retrouvée en quelques minutes. WPA (2003) : rustine transitoire. WPA2 (2004) : AES-CCMP et poignée de main à quatre messages, solide si la phrase de passe l'est. WPA3 (2018) : échange SAE, trames de gestion protégées, confidentialité persistante."],
    pmk: ["PMK et PTK : deux clés", "En WPA2-Personnel, la phrase de passe et le nom du réseau (SSID) donnent la clé maîtresse PMK par PBKDF2 (4096 tours de HMAC-SHA1, 256 bits) : le SSID joue le rôle de sel. À chaque connexion, la PMK, les adresses MAC et deux nonces aléatoires (ANonce, SNonce) donnent une clé de session PTK : KCK (calcule les MIC), KEK (protège la clé de groupe) et TK (chiffre les données)."],
    hand: ["La poignée de main à quatre messages", "① l'AP envoie son ANonce ; ② le client répond avec son SNonce et un MIC ; ③ l'AP envoie la clé de groupe (chiffrée) et un MIC ; ④ le client acquitte. La phrase ne circule jamais : le MIC prouve qu'on connaît la PTK, donc la PMK, donc la phrase. Mais tout ce qu'il faut pour vérifier une hypothèse passe en clair dans l'air (messages ① et ②)."],
    offline: ["L'attaque hors ligne", "Une fois la poignée de main captée, l'attaquant peut tester des phrases chez lui : pour chaque candidat il calcule PMK, puis PTK, puis le MIC, et compare à celui capté. Personne ne le voit, aucune limite d'essais, et un GPU enchaîne des millions de candidats par seconde. Toute phrase devinable (mot courant, variante classique) tombe."],
    long: ["Une phrase de passe longue", "Seule la longueur et l'imprévisibilité protègent contre cette attaque : chaque caractère de plus multiplie l'effort. Une phrase d'au moins 16 caractères, composée de mots peu liés ou aléatoires, unique à ce réseau, résiste. Attention : citation, chanson ou « mot + année » restent devinables, quelle que soit leur longueur."],
    sae: ["WPA3-SAE et confidentialité persistante", "SAE (Dragonfly) est un échange authentifié par mot de passe : chaque côté mélange la phrase à un Diffie-Hellman éphémère. Une capture ne permet de tester aucune phrase : chaque hypothèse exige un échange en direct avec l'AP, qui peut limiter et journaliser les échecs. Les clés de session ne dépendent pas que de la phrase : même si elle fuit plus tard, les anciennes captures restent illisibles (confidentialité persistante, contrairement à WPA2-PSK)."],
    mgmt: ["Trames de gestion : déauth et PMF", "En WPA2, les trames de gestion (désauthentification, dissociation) ne sont pas authentifiées : n'importe qui peut en forger une au nom de l'AP et chasser un client, qui se reconnecte aussitôt et refait la poignée de main que l'attaquant guette. Les trames de gestion protégées (PMF, 802.11w) rendent ces faux messages inopérants ; WPA3 les impose. Le brouillage radio, lui, reste possible."],
    twin: ["Le faux point d'accès (evil twin)", "Le nom d'un réseau (SSID) n'est pas une identité : un faux AP avec le même nom et un signal plus fort attire les appareils qui se reconnectent automatiquement. En WPA2 ou WPA3-Personnel, la phrase étant partagée, quiconque la connaît (ardoise du café !) peut jouer le faux AP : la phrase prouve « tu fais partie du groupe », pas « tu es le bon point d'accès ». Il voit alors tout ce qui n'est pas chiffré de bout en bout."],
    eap: ["WPA-Entreprise (802.1X) et défenses", "Avec 802.1X, chaque personne a son identifiant ; un serveur RADIUS authentifie via EAP et prouve son identité par un certificat que le client vérifie (autorité de confiance épinglée) : le faux AP échoue. Les clés sont individuelles, sans phrase partagée. Défenses complémentaires : HTTPS partout, VPN sur un réseau qu'on ne contrôle pas, ne jamais accepter une alerte de certificat."],
  };

  /* ---------- entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle a obtenu de Rosa une autorisation écrite : audit du Wi-Fi du café, tout est simulé, rien n'est tenté sur un autre réseau." },
    rosa: { npc: true, names: ["rosa", "patronne", "cafetiere"], label: "Rosa, la patronne", desc: () => "Rosa, la patronne du Café du Port. Elle a mis un mot de passe sur le Wi-Fi « pour que les clients puissent se connecter » et l'a écrit sur l'ardoise." },
    ardoise: { names: ["ardoise", "menu", "tableau"], label: "l'ardoise du café", desc: () => `L'ardoise du café : « Croissants 1,50 · Express 1,20 · Wi-Fi : ${SSID} — phrase de passe : ${F().pass} ».` },
    adaptateur: { names: ["adaptateur", "antenne", "adaptateur radio"], label: "ton adaptateur radio", desc: () => "Un adaptateur Wi-Fi en mode moniteur : il lit les trames qui passent à portée. Usage autorisé, sur le café, avec l'accord de Rosa." },
    routeur: { names: ["routeur", "box", "point d acces", "borne cafe"], label: "le routeur du café", vis: () => S.room === "cave",
      desc: () => { const x = F(); return `Le routeur du café. SSID : ${SSID}. Mode : ${modeName()}.` + (x.mode === "ent" ? "\nServeur RADIUS : radius.cafe.port443 (certificat de l'autorité du café). Identifiants individuels." : `\nPhrase de passe : « ${x.pass} » (${x.pass.length} caractères).` + `\nTrames de gestion protégées (PMF) : ${x.mode === "wpa3" ? "OUI (obligatoire en WPA3)" : "non"}.`) + "\nRéglages : `changer phrase ‹texte›` · `activer wpa3` · `activer entreprise`"; } },
    borneo: { names: ["borne ouverte", "ouverte", "ouvert", "open", "borne 1"], label: "la borne ouverte", vis: () => S.room === "musee", desc: () => "Une vieille borne « Café-Gratuit », sans aucun chiffrement. `ecouter ouvert` pour voir ce qu'on capte." },
    bornew: { names: ["borne wep", "wep", "borne 2"], label: "la borne WEP", vis: () => S.room === "musee", desc: () => "Une borne de 1999, protégée par une clé WEP de 40 bits. `ecouter wep` pour capter son trafic." },
    portable: { names: ["portable", "ordinateur", "laptop", "pc mallory"], label: "le portable de Mallory", vis: () => S.room === "terrasse", desc: () => "Le portable de Mallory : un adaptateur en mode moniteur et un dictionnaire de mots de passe courants. Commandes : `ecouter`, `desauthentifier bob`, `attaquer`, `dechiffrer`." },
    capture: { names: ["capture", "poignee de main", "handshake"], label: "la capture", vis: () => !!F().cap, desc: () => { const c = F().cap; return `Capture de la poignée de main de Bob (messages ① et ②) :\n  AP ${AP} ↔ client ${STA}\n  ANonce ${c.an}\n  SNonce ${c.sn}\n  MIC    ${c.mic}\nCe sont exactement les éléments qu'il faut pour tester des phrases hors ligne.`; } },
    bob: { npc: true, names: ["bob"], label: "Bob", desc: () => "Bob, client fidèle du café, le nez dans son téléphone. Il se connecte au Wi-Fi avec la phrase de l'ardoise." },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, assise dans un coin, un casque sur les oreilles… et un adaptateur radio dans le sac. Elle écoute, sans jamais parler, sans jamais toucher à rien." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, l'attaquante de service pour cet audit autorisé. Son portable est ouvert devant elle." },
    camionnette: { names: ["camionnette", "van", "faux point d acces", "faux ap", "evil twin", "twin"], label: "une camionnette garée", vis: () => S.room === "rue",
      desc: () => { const x = F(); return `Une camionnette blanche. À l'intérieur, Mallory a posé un faux point d'accès qui diffuse « ${SSID} », comme le café, mais avec un signal bien plus fort.` + (x.mode === "ent" ? "\nIl lui manque une chose : un certificat signé par l'autorité du café." : "\nElle a lu la phrase de passe sur l'ardoise, à travers la vitre.") + "\n`connecter bob` pour voir ce que fait le téléphone de Bob."; } },
  };

  const rooms = {
    comptoir: { name: "Le comptoir du Café du Port", short: "Comptoir", alias: ["comptoir", "cafe"], ents: ["ada", "rosa", "ardoise"], exits: { nord: "cave", est: "terrasse", ouest: "musee", sud: "rue" },
      desc: () => "Odeur de café et de croissants. Rosa sert au comptoir ; une ardoise annonce les prix… et le Wi-Fi. Au nord, l'arrière-boutique et le routeur. À l'est, la terrasse. À l'ouest, le petit musée des vieilles bornes. Au sud, la rue." },
    cave: { name: "L'arrière-boutique", short: "Arrière-boutique", alias: ["arriere boutique", "arriere", "boutique", "routeur"], ents: ["routeur"], exits: { sud: "comptoir" },
      desc: () => "Des cageots, un frigo, et sur une étagère le routeur du café avec ses voyants verts." },
    terrasse: { name: "La terrasse", short: "Terrasse", alias: ["terrasse"], ents: ["bob", "eve", "mallory", "portable", "capture"], exits: { ouest: "comptoir" },
      desc: () => "Quelques tables au soleil. Bob consulte son téléphone ; Ève écoute, dans son coin ; Mallory a ouvert son portable. Dans un audit autorisé, tout le monde ici joue son rôle." },
    musee: { name: "Le musée des vieilles bornes", short: "Musée", alias: ["musee", "bornes"], ents: ["borneo", "bornew"], exits: { est: "comptoir" },
      desc: () => "Rosa conserve ici deux antiquités encore branchées pour la démonstration : une borne ouverte et une borne WEP. Deux étapes de l'histoire du Wi-Fi à portée de ton adaptateur." },
    rue: { name: "La rue du Port", short: "Rue", alias: ["rue", "dehors"], ents: ["camionnette"], exits: { nord: "comptoir" },
      desc: () => "La rue, devant la vitrine du café. Une camionnette blanche est garée en face, moteur éteint, un peu trop proche." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.evol) return "museum";
    if (!x.pmkSeen) return "pmk";
    if (!x.hsNote) return "capt";
    if (!x.atk1) return "atk1";
    if (x.pv === 0) return "newpass";
    if (!x.atk2) return capValid() ? "atk2" : "capt2";
    if (x.mode === "wpa2") return "w3";
    if (!x.pmfSeen) return "pmf";
    if (!x.w3atk) return "w3atk";
    if (!x.pfs) return "pfs";
    if (!x.twin) return "twin";
    if (!x.entOn) return "ent";
    if (!x.entTest) return "ent2";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend au comptoir.", "`parler ada`"],
    museum: () => { const x = F(); return ["Le musée des vieilles bornes est à l'ouest du comptoir. Écoute les deux anciens réseaux avec ton adaptateur" + (x.sawOpen ? " (il te reste la borne WEP)." : x.sawWep ? " (il te reste la borne ouverte)." : "."), "`aller ouest` (depuis le comptoir), puis `ecouter ouvert` et `ecouter wep`."]; },
    pmk: () => ["Le café est en WPA2. Regarde l'ardoise, puis va voir le routeur à l'arrière-boutique : comment la phrase de passe devient-elle une clé ?", "`examiner ardoise`, `aller nord`, `examiner routeur`, puis `deriver croissant` (la phrase de l'ardoise)."],
    capt: () => ["Bob est connecté depuis ce matin : aucune poignée de main à observer. Rends-toi sur la terrasse : Mallory sait en provoquer une.", "`aller est` (depuis le comptoir), `ecouter`, puis `desauthentifier bob`."],
    atk1: () => ["Mallory a capté la poignée de main. Elle peut maintenant tester des phrases chez elle, hors ligne. Tu peux aussi vérifier une hypothèse à la main.", "`deriver croissant` (compare le MIC), puis `attaquer` sur la terrasse."],
    newpass: () => ["« croissant » est tombée en une fraction de seconde. Rosa doit changer de phrase : longue et imprévisible. Va à l'arrière-boutique.", "`aller ouest`, `aller nord`, puis `changer phrase ‹au moins 16 caractères›`, par exemple `changer phrase le croissant du port est tiede`."],
    capt2: () => ["Nouvelle phrase, donc nouvelle PMK : l'ancienne capture ne sert plus. Mallory doit en refaire une.", "`aller sud`, `aller est`, `desauthentifier bob` (sur la terrasse)."],
    atk2: () => ["Laisse Mallory retenter sa chance avec la nouvelle capture.", "`attaquer` (sur la terrasse)."],
    w3: () => ["Une phrase longue tient, mais WPA2 laisse toujours des captures exploitables (et des trames de gestion forgeables). Passe le routeur à la génération suivante.", "`aller ouest`, `aller nord`, `activer wpa3` (arrière-boutique)."],
    pmf: () => ["Retourne sur la terrasse : Mallory peut-elle encore chasser Bob ?", "`aller sud`, `aller est`, `desauthentifier bob`."],
    w3atk: () => ["Reste à voir si Mallory peut encore deviner la phrase à partir d'une capture.", "`attaquer` (sur la terrasse)."],
    pfs: () => ["Dernier scénario : Mallory a enregistré une session hier ; aujourd'hui, la phrase de passe fuite. Que peut-elle lire ?", "`dechiffrer` (sur la terrasse)."],
    twin: () => ["Une camionnette est garée dans la rue (sud du comptoir). Regarde-la, puis observe ce que fait le téléphone de Bob.", "`aller sud` (depuis le comptoir), `examiner camionnette`, `connecter bob`."],
    ent: () => ["Une phrase partagée ne prouve pas qui est le point d'accès. Pour le personnel du café, il faut mieux : le routeur doit apprendre à prouver son identité.", "`aller nord` (depuis la rue), `aller nord`, `activer entreprise`."],
    ent2: () => ["Rejoue la scène de la camionnette.", "`aller sud`, `aller sud`, `connecter bob`."],
    end: () => ["Rends compte à Maître Ada, au comptoir.", "`aller nord` (depuis la rue), puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; give("adaptateur");
          say("Maître Ada", "Bienvenue au Café du Port. Rosa voudrait un Wi-Fi sûr, et c'est ton audit. Avec son autorisation écrite, tu vas suivre l'évolution de la sécurité Wi-Fi, voir ce qu'une attaquante comme Mallory peut faire, et corriger. Tout est simulé : on n'attaque jamais un réseau qui n'est pas le sien.");
          say("Maître Ada", "Voici un adaptateur radio en mode moniteur. Commence par le petit musée des vieilles bornes, à l'ouest : un réseau ouvert et un réseau WEP, deux étapes de l'histoire.");
          out("`aller ouest` puis `ecouter ouvert` et `ecouter wep`.", "sys");
        } else if (x.end) say("Maître Ada", "Le café a un Wi-Fi digne de ce nom. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas fini. `indice` si tu bloques.");
        break;
      case "rosa":
        if (!x.quest) say("Rosa", "Maître Ada voulait te voir. Un café ?");
        else if (!x.atk1) say("Rosa", "Le Wi-Fi ? C'est du WPA2, avec une phrase de passe sur l'ardoise : « croissant », mon plat préféré. Facile à retenir pour les clients, non ?");
        else if (x.pv === 0) say("Rosa", "Mon mot de passe n'a pas tenu une seconde ?! D'accord : change la phrase au routeur, à l'arrière-boutique. Et je la réécrirai sur l'ardoise… enfin, peut-être pas.");
        else if (!x.entOn) say("Rosa", "Je note la phrase sur l'ardoise pour les clients. Mais elle a parlé d'un faux point d'accès : ça me préoccupe.");
        else say("Rosa", "Les clients ont la phrase de l'ardoise pour le Wi-Fi invité, le personnel a son compte. Un café pour te remercier ?");
        break;
      case "eve":
        if (!x.cap) say("Ève", "Je ne fais qu'écouter : tout ce qui passe par les airs est à portée de n'importe qui. Ce qui compte, c'est ce que les trames révèlent. Tape `ecouter` pour voir ce que j'entends.");
        else say("Ève", "Je n'ai rien touché : j'ai seulement entendu la poignée de main. Elle passe en clair, c'est ce qui la rend dangereuse… et tout l'intérêt d'une phrase longue.");
        break;
      case "bob":
        say("Bob", "Je me suis connecté ce matin avec la phrase de l'ardoise. Mon téléphone se reconnecte tout seul à « " + SSID + " » dès qu'il le voit : pratique !");
        break;
      case "mallory":
        if (!x.pmkSeen) say("Mallory", "Je ne fais rien tant que tu n'as pas compris ce que protège la phrase de passe. Va voir le routeur et `deriver` la phrase de l'ardoise.");
        else if (!x.cap) say("Mallory", "Bob est connecté depuis ce matin : pas de poignée de main à capter. Mais je peux le déconnecter : `desauthentifier bob`.");
        else if (!x.atk1) say("Mallory", "J'ai les messages ① et ②. Hors ligne, je teste mon dictionnaire. `attaquer`.");
        else say("Mallory", "`desauthentifier bob` pour provoquer une poignée de main, `attaquer` pour deviner la phrase, `dechiffrer` pour une vieille capture, et sinon je suis dans la camionnette.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function listen(c) {
    const x = F(), t = norm(c.rawArg);
    if (!S.inv.includes("adaptateur")) { out("Tu n'as pas d'adaptateur radio : maître Ada doit te le confier (`parler ada`).", "sys"); return; }
    if (S.room === "musee") {
      if (/ouver|open|gratuit/.test(t)) {
        out("Ton adaptateur capte la borne ouverte :", "sys");
        code("trame 1  Bob → cafe-fidelite.port443\n  GET /login?user=bob&pass=soleil42 HTTP/1.1\ntrame 2  cafe-fidelite.port443 → Bob\n  Set-Cookie: session=7f3a91c2d0\ntrame 3  Alice → portail\n  POST /messages  « RDV à 18h, apporte la clé USB »");
        out("Tout est lisible, pour tout le monde : mots de passe, cookies de session, messages. Aucune clé, rien à casser.", "err");
        x.sawOpen = true;
      } else if (/wep/.test(t)) {
        const d = wepDemo(), h = a => hx(a.slice(0, 8)) + "…";
        out("Ton adaptateur capte la borne WEP. Chaque trame est chiffrée par RC4 avec la clé secrète précédée d'un IV de 24 bits, envoyé en clair.", "sys");
        out(`Il n'y a que 2^24 = 16 777 216 IV possibles. Au bout de ${d.n.toLocaleString("fr-FR")} trames seulement, l'IV ${hx([(d.iv >> 16) & 255, (d.iv >> 8) & 255, d.iv & 255])} sert pour la deuxième fois (trames n°${d.first} et n°${d.n}) : même clé RC4, donc même flux de chiffrement.`, "sys");
        code(`trame ${d.first}  chiffré : ${h(d.c1)}   (clair deviné : « GET /index.html »)\ntrame ${d.n}  chiffré : ${h(d.c2)}   (clair : inconnu)\nXOR des deux chiffrés = XOR des deux clairs\nclair de la trame ${d.n} retrouvé : « ${d.rec} »`);
        out("Sans connaître la clé, on lit le contenu. En pratique, des attaques statistiques (FMS, PTW) retrouvent même la clé après quelques dizaines de milliers de trames. WEP est irrécupérable.", "err");
        x.sawWep = true;
      } else { out("Quelle borne ? `ecouter ouvert` ou `ecouter wep`.", "err"); return; }
      if (x.sawOpen && x.sawWep && !x.evol) {
        x.evol = true; note("evol"); fig("evol");
        say("Maître Ada", "Voilà l'histoire ancienne. Rosa a mis le café en WPA2 : retourne au comptoir, regarde l'ardoise, puis va voir le routeur à l'arrière-boutique.");
      }
      return;
    }
    if (S.room === "terrasse") {
      if (!x.quest) { out("Va d'abord voir Maître Ada.", "sys"); return; }
      const sample = hx(encrypt(sha256("tk" + x.pv + x.mode), OLD_MSG)).slice(0, 40);
      out("Ève et toi écoutez les ondes autour de « " + SSID + " » :", "sys");
      if (x.mode === "wpa2") {
        code(`balise    ${AP}  SSID=${SSID}  sécurité=WPA2-PSK / AES-CCMP\ndonnées   ${STA} → ${AP}\n  ${sample}…\n(autres trames : illisibles)`);
        out(x.cap ? "Tu as déjà la poignée de main de Bob (`examiner capture`)." : "Bob est connecté depuis ce matin : aucune poignée de main n'a été émise depuis. Les données sont chiffrées avec la PTK de Bob ; sans poignée de main, il n'y a rien à tester.", "sys");
      } else if (x.mode === "wpa3") {
        const e = sae(x.pass, x.pass, 7);
        code(`balise    ${AP}  SSID=${SSID}  sécurité=WPA3-SAE, PMF obligatoire\nSAE commit   scalaire/élément de Bob : ${e.A}\nSAE commit   scalaire/élément de l'AP : ${e.B}\ndonnées   ${STA} → ${AP}\n  ${sample}…`);
        out("Les messages SAE sont visibles, mais ils ne permettent de tester aucune phrase hors ligne.", "sys");
      } else {
        code(`balise    ${AP}  SSID=${SSID}  sécurité=WPA3-Enterprise (802.1X)\nEAP       identité externe « anonyme@cafe.port443 », tunnel TLS vers radius.cafe.port443\ndonnées   ${STA} → ${AP}\n  ${sample}…`);
        out("Le tunnel EAP est chiffré, et chaque session a sa propre clé.", "sys");
      }
      return;
    }
    out("Rien d'intéressant à écouter ici : essaie au musée (`ecouter ouvert`, `ecouter wep`) ou sur la terrasse (`ecouter`).", "sys");
  }

  function derive(c) {
    const x = F(), pw = tail(c);
    if (!x.quest) { out("Va d'abord voir Maître Ada.", "sys"); return; }
    if (!pw) { out("Quelle phrase ? `deriver ‹phrase de passe›` (essaie celle de l'ardoise).", "err"); return; }
    const pm = pmk(pw);
    out(`Dérivation de la PMK (PBKDF2 simulé : ${ITER} tours de SHA-256, avec le SSID « ${SSID} » comme sel) :`, "sys");
    let line = `PMK( « ${pw} », ${SSID} ) = ${pm}`, ar = { pass: pw, pm, ptk: null };
    if (x.cap) {
      const k = ptk(pm, x.cap.an, x.cap.sn), mic = micOf(k.kck, "EAPOL-2|" + x.cap.sn), same = mic === x.cap.mic;
      line += `\nPTK = PRF(PMK, MAC AP, MAC client, ANonce, SNonce)\n  KCK = ${k.kck}\n  MIC recalculé = ${sh(mic)}\n  MIC capturé   = ${sh(x.cap.mic)}`;
      ar.ptk = k;
      code(line);
      out(same ? "Les deux MIC sont identiques : cette phrase est la bonne. C'est exactement le test que Mallory automatise." : "Les MIC diffèrent : ce n'est pas la phrase du réseau (une seule lettre fausse change tout).", same ? "err" : "ok");
    } else {
      code(line);
      out("Une PMK ne dépend que de la phrase et du SSID : elle est la même pour tout le monde sur ce réseau. Pour la clé de session (PTK), il faut en plus les deux nonces d'une connexion.", "sys");
    }
    x.lastDerive = pw;
    if (!x.pmkSeen) { x.pmkSeen = true; note("pmk"); }
    fig("pmk", ar);
    if (x.pmkSeen && !x.cap && !x.sawPmkMsg) { x.sawPmkMsg = true; say("Maître Ada", "Toute la sécurité du café repose sur cette phrase. Reste à voir si on peut la deviner : sur la terrasse, Mallory joue l'attaquante de l'audit."); }
  }

  function deauth(c) {
    const x = F();
    if (S.room !== "terrasse") { out("Cela se joue sur la terrasse (est du comptoir).", "sys"); return; }
    if (!x.pmkSeen) { say("Mallory", "Pas encore : comprends d'abord ce que la phrase protège. `deriver ‹phrase›` à l'arrière-boutique."); return; }
    if (!/bob|client|tous|tout|telephone/.test(norm(c.rawArg))) { out("Qui chasser du réseau ? `desauthentifier bob`", "err"); return; }
    out("Mallory forge une trame de désauthentification qui semble venir du point d'accès :", "sys");
    code(`Deauth  src=${AP} (usurpé)  dst=${STA}  raison=7`);
    if (x.mode !== "wpa2") {
      out("Bob ne bronche pas : la trame n'est pas authentifiée par la clé de session (PMF, 802.11w), il l'ignore. Mallory ne peut plus le chasser par ce moyen.", "ok");
      if (!x.pmfSeen) { x.pmfSeen = true; note("mgmt"); }
      return;
    }
    x.nhs = (x.nhs || 0) + 1;
    x.cap = Object.assign(handshake(x.pass, x.nhs), { v: x.pv });
    out("En WPA2, les trames de gestion ne sont pas protégées : Bob croit que le point d'accès le renvoie, et se reconnecte aussitôt. La poignée de main complète passe dans l'air, et Ève l'entend :", "err");
    const s = h => h.slice(0, 16) + "…";
    code(`① AP → Bob   ANonce = ${s(x.cap.an)}\n② Bob → AP   SNonce = ${s(x.cap.sn)}   MIC = ${s(x.cap.mic)}\n③ AP → Bob   clé de groupe (chiffrée avec la KEK) + MIC\n④ Bob → AP   acquittement + MIC`);
    out("La phrase n'a pas circulé, mais ① et ② contiennent tout ce qu'il faut pour tester une hypothèse (`examiner capture`).", "sys");
    if (!x.hsNote) { x.hsNote = true; note("hand"); note("mgmt"); }
    fig("hand", true);
  }

  function attack() {
    const x = F();
    if (S.room !== "terrasse") { out("Mallory est sur la terrasse (est du comptoir).", "sys"); return; }
    if (x.mode === "ent") { say("Mallory", "Plus de phrase partagée à deviner : chaque personne a son compte, et son échange est protégé par un tunnel TLS vérifié. Je n'ai rien à attaquer ici."); return; }
    if (x.mode === "wpa3") return attackSae();
    if (!capValid()) { say("Mallory", "Je n'ai aucune poignée de main à jour sous la main. `desauthentifier bob` d'abord."); return; }
    const cap = x.cap;
    out(`Mallory lance son dictionnaire (${WORDS.length} mots courants × variantes = ${CANDS.length} candidats) sur la capture. Pour chaque candidat : PMK, PTK, MIC, comparaison.`, "sys");
    const t0 = performance.now(); let tries = 0, found = null;
    for (const w of CANDS) { tries++; if (guessMic(w, cap) === cap.mic) { found = w; break; } }
    const ms = Math.max(1, Math.round(performance.now() - t0));
    const b0 = performance.now(), nb = 5; for (let i = 0; i < nb; i++) pmk("essai" + i);
    const rate = Math.round(nb / Math.max(0.001, (performance.now() - b0) / 1000)); x.rate = rate;
    if (found) {
      out(`Trouvée en ${tries} essai${tries > 1 ? "s" : ""} (${ms} ms) : « ${found} ». Hors ligne, sans que le réseau se doute de rien.`, "err");
    } else out(`${tries} candidats testés (${ms} ms) : aucun ne correspond au MIC capturé. La phrase n'est pas dans le dictionnaire.`, "ok");
    out(`Rythme mesuré dans ton navigateur : environ ${rate.toLocaleString("fr-FR")} candidats par seconde. (Contre le vrai PBKDF2, quelques GPU atteignent de l'ordre de ${GPU.toLocaleString("fr-FR")} candidats par seconde : ton navigateur est très loin du compte.)`, "sys");
    if (found) {
      if (!x.atk1) { x.atk1 = true; note("offline"); say("Maître Ada", "Une capture, un dictionnaire, et la phrase tombe. Elle était choisie pour être mémorisée : c'est justement ce que cherchent les dictionnaires. Rosa doit changer de phrase."); }
      return;
    }
    const b = brute(x.pass), years = b.s / 31557600;
    out(`Estimation d'audit (force brute à l'aveugle, jeu de ${b.cs} symboles détecté, ${x.pass.length} caractères) : environ 10^${b.exp} possibilités, soit en moyenne ${dur(b.s)} à ${GPU.toLocaleString("fr-FR")} essais par seconde.`, years >= 100 ? "ok" : "err");
    if (years >= 100) { x.atk2 = true; out("Hors de portée : la phrase résiste au dictionnaire et à la force brute. Note : l'estimation suppose des caractères imprévisibles ; une phrase tirée d'une chanson ou d'un proverbe se devinerait plus vite.", "ok"); note("long"); say("Maître Ada", "Voilà la bonne pratique pour WPA2 : longue, imprévisible, propre à ce réseau. Mais elle reste vulnérable à tout ce qui la révèle, et une capture hors ligne reste possible. La génération suivante change la donne."); }
    else say("Mallory", "Elle n'est pas dans mon dictionnaire, mais elle est courte : un GPU l'avale en force brute. Rosa doit l'allonger (16 caractères ou plus, imprévisibles).");
  }

  function attackSae() {
    const x = F();
    if (!x.pmfSeen) { out("Mallory : « Essaie d'abord de chasser Bob (`desauthentifier bob`) pour voir ce qu'il reste des anciennes méthodes. »", "sys"); return; }
    const e0 = sae(x.pass, x.pass, 7);
    out("Mallory a capté l'échange SAE de Bob (valeurs A et B ci-dessous). Peut-elle tester des phrases hors ligne ?", "sys");
    code(`SAE : A (Bob) = ${e0.A}   B (AP) = ${e0.B}\nPour tester un candidat, il faudrait calculer K = pwe^(a·b), donc connaître un exposant secret (a ou b),\nque personne n'a jamais transmis.`);
    out("Non : la capture ne donne aucun moyen de vérifier une hypothèse. Le seul oracle, c'est le vrai point d'accès, en direct. Mallory se met à jouer le client :", "sys");
    let found = null, idx = 0, lines = [];
    CANDS.forEach((w, i) => { const e = sae(w, x.pass, 100 + i); if (i < 5) lines.push(`essai ${i + 1} : « ${w} »  A=${e.A}  → confirmation de l'AP : ${e.ok ? "valide" : "refusée"}`); if (e.ok && found === null) { found = w; idx = i + 1; } });
    code(lines.join("\n") + "\nAP : 5 échecs en peu de temps : accès temporaire refusé, alerte dans le journal.");
    const mins = Math.ceil(CANDS.length / 5);
    out(`Chaque essai est un échange réel avec l'AP, qui limite (ici ≈ 5 essais par minute) et journalise les échecs. Tout le dictionnaire (${CANDS.length} candidats) prendrait au moins ${mins} minutes, sous les yeux de qui lit le journal, au lieu d'une fraction de seconde hors ligne et en silence.`, found ? "err" : "ok");
    out(found ? `Cette fois, « ${found} » a bien été trouvée (essai n°${idx}), mais lentement et bruyamment.` : "Aucune phrase du dictionnaire ne passe : avec une phrase longue, c'est sans espoir.", found ? "err" : "ok");
    if (x.rate) out(`(Pour mémoire : WPA2 permettait environ ${x.rate.toLocaleString("fr-FR")} essais par seconde dans ton navigateur, des millions sur GPU, sans témoin.)`, "sys");
    if (!x.w3atk) { x.w3atk = true; fig("offline"); say("Maître Ada", "Le coût de chaque essai est passé de quelques microsecondes à une interaction réelle. WPA3 ne sauve pas « croissant », mais il supprime l'attaque silencieuse et massive."); }
  }

  function decryptCmd() {
    const x = F();
    if (S.room !== "terrasse") { out("Cela se joue sur la terrasse (est du comptoir).", "sys"); return; }
    if (!x.w3atk) { say("Mallory", "Pas encore : voyons d'abord ce que WPA3 change pour les essais (`attaquer`)."); return; }
    out("Scénario : hier, Mallory a enregistré une session de Bob, sans rien casser. Aujourd'hui, la phrase de passe du café fuite (ardoise photographiée, ex-employé bavard…). Que peut-elle lire ?", "sys");
    /* WPA2 : la PTK est une fonction de PMK (donc de la phrase) et des nonces publics */
    const an = sha256("old-an").slice(0, 32), sn = sha256("old-sn").slice(0, 32);
    const tk2 = ptk(pmk(x.pass), an, sn).tk, c2 = encrypt(tk2, OLD_MSG);
    const back2 = txt(decrypt(ptk(pmk(x.pass), an, sn).tk, c2));
    out("Si le café avait été en WPA2 :", "title");
    code(`session capturée : ${hx(c2).slice(0, 40)}…\nnonces vus dans la poignée de main : ${sh(an)}  ${sh(sn)}\nMallory : PMK(phrase) → PTK(nonces) → déchiffrement\nrésultat : « ${back2} »`);
    out("Tout est lisible : en WPA2-PSK, qui connaît la phrase et a capté la poignée de main retrouve la PTK, et lit même les sessions passées.", "err");
    /* WPA3 : la clé vient d'un Diffie-Hellman éphémère dont les exposants ont été effacés */
    const e = sae(x.pass, x.pass, 31), tk3 = sha256("TK|" + e.Kc).slice(0, 32), c3 = encrypt(tk3, OLD_MSG);
    const attempt = sha256("TK|" + ((e.A * e.B) % P)).slice(0, 32), bad = decrypt(attempt, c3);
    out("Avec WPA3-SAE :", "title");
    code(`session capturée : ${hx(c3).slice(0, 40)}…\nvaleurs publiques : A = ${e.A}   B = ${e.B}\nMallory connaît la phrase donc pwe, mais pas les exposants a et b (effacés)\nsa meilleure tentative de clé donne : ${hx(bad).slice(0, 40)}…  (illisible)`);
    out("Illisible : la clé de session dépend d'exposants éphémères oubliés après la session. Retrouver K reviendrait à résoudre un logarithme discret. La fuite de la phrase ne rouvre pas le passé : c'est la confidentialité persistante.", "ok");
    if (!x.pfs) { x.pfs = true; note("sae"); say("Maître Ada", "Voilà pourquoi WPA3 compte, même quand une phrase finit par fuiter. Reste un angle mort : qui prouve que le point d'accès est le bon ? Rosa, regarde dehors la camionnette."); }
  }

  function changeCmd(c) {
    const x = F();
    if (S.room !== "cave") { out("Le routeur est à l'arrière-boutique (nord du comptoir).", "sys"); return; }
    if (x.mode === "ent") { out("En mode entreprise, il n'y a plus de phrase partagée : chaque personne a son compte sur le serveur RADIUS.", "sys"); return; }
    if (!x.atk1) { say("Rosa", "Pourquoi changer ma phrase ? Elle est très bien. (Vois d'abord ce que Mallory en fait : `desauthentifier bob` puis `attaquer` sur la terrasse.)"); return; }
    if (!/^(phrase|mot de passe|mdp|la phrase)/i.test(c.rawArg.trim())) { out("Quelle phrase ? `changer phrase ‹texte›` (au moins 16 caractères, imprévisible).", "err"); return; }
    const pw = tail(c);
    if (pw.length < 8) { out("Le standard WPA2 exige entre 8 et 63 caractères pour une phrase de passe. Mais 8 est un minimum, pas un objectif : vise 16 ou plus.", "err"); return; }
    if (pw.length > 63) { out("Trop longue : WPA2 limite la phrase de passe à 63 caractères.", "err"); return; }
    if (pw === x.pass) { out("C'est déjà la phrase actuelle.", "sys"); return; }
    x.pass = pw; x.pv++; x.cap = null;
    out(`Phrase de passe changée : « ${pw} » (${pw.length} caractères). La PMK est entièrement différente ; Bob et les autres devront se reconnecter avec la nouvelle phrase. Toute ancienne capture est maintenant inutile.`, "ok");
    if (inDict(pw)) out("Attention : cette phrase figure dans les variantes classiques d'un dictionnaire… Mallory risque de la retrouver.", "err");
    else if (pw.length < 12) out("Elle est courte : même hors dictionnaire, la force brute la menace.", "err");
    if (!inDict(pw) && pw.length >= 12 && !x.rosaOk) { x.rosaOk = true; say("Rosa", "C'est plus long à taper, mais soit. Mallory, essaie encore !"); }
  }

  function activate(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "cave") { out("Le routeur est à l'arrière-boutique (nord du comptoir).", "sys"); return; }
    if (/wpa3|sae/.test(t)) {
      if (!x.atk2) { say("Rosa", "Pas si vite : on a une phrase à tester d'abord. (Voir `indice`.)"); return; }
      if (x.mode !== "wpa2") { out("Déjà en WPA3 (ou mieux).", "sys"); return; }
      x.mode = "wpa3"; x.cap = null;
      out("Le routeur passe en WPA3-Personnel : les appareils s'authentifient par l'échange SAE (Dragonfly) au lieu de la poignée de main PSK, et les trames de gestion deviennent protégées (PMF) par obligation.", "ok");
      out("En pratique, beaucoup de réseaux gardent un « mode de transition » WPA2/WPA3 pour les vieux appareils ; il réintroduit la faiblesse WPA2 pour ceux qui l'utilisent. Ici, on passe en WPA3 pur.", "sys");
      return;
    }
    if (/entreprise|enterprise|802|radius|eap/.test(t)) {
      if (!x.twin) { say("Rosa", "C'est lourd à mettre en place : montre-moi d'abord que j'en ai besoin. (Voir `indice`.)"); return; }
      if (x.mode === "ent") { out("Déjà activé.", "sys"); return; }
      x.mode = "ent"; x.entOn = true; x.cap = null;
      out("Le routeur passe en WPA3-Entreprise (802.1X) : chaque membre du personnel a son identifiant, l'authentification passe par un serveur RADIUS (radius.cafe.port443) en EAP, dans un tunnel TLS. Le serveur prouve son identité par un certificat signé par l'autorité du café, que les téléphones sont configurés pour vérifier.", "ok");
      out("Chaque session obtient sa propre clé maîtresse (issue de l'échange EAP), sans phrase partagée.", "sys");
      return;
    }
    out("Quel réglage ? `activer wpa3` ou `activer entreprise`.", "err");
  }

  function connect() {
    const x = F();
    if (S.room !== "rue") { out("Cela se voit dans la rue, devant la camionnette (sud du comptoir).", "sys"); return; }
    if (!x.pfs) { say("Maître Ada", "Pas encore : termine d'abord le scénario de la terrasse (`indice`)."); return; }
    out("Bob sort du café, son téléphone cherche un réseau connu. Deux points d'accès s'annoncent :", "sys");
    code(`${SSID}   ${AP}   signal -71 dBm   (le vrai)\n${SSID}   de:ad:be:ef:44:30   signal -38 dBm   (la camionnette)`);
    out("Le téléphone se reconnecte automatiquement au réseau connu avec le meilleur signal : le faux.", "err");
    if (x.mode !== "ent") {
      const same = x.mode === "wpa2" ? handshake(x.pass, 99).mic === handshake(x.pass, 99).mic : sae(x.pass, x.pass, 55).ok;
      out(x.mode === "wpa2" ? "Mallory connaît la phrase (ardoise) : elle peut mener la poignée de main à terme, le MIC est valide." : "Mallory connaît la phrase (ardoise) : elle peut mener l'échange SAE à terme.", "err");
      out(same ? "Le téléphone de Bob est connecté… au faux point d'accès. Rien ne l'a averti : la phrase prouve l'appartenance au groupe, pas l'identité de la borne." : "Échec.", "err");
      out("Ce que voit Mallory sur son faux point d'accès :", "sys");
      code("http://cafe-fidelite.port443/login   (HTTP)\n  POST user=bob&pass=soleil42        ← lisible, modifiable\nhttps://banque.port443/                (HTTPS)\n  TLS : le certificat de Mallory n'est pas valide pour banque.port443\n  → le navigateur de Bob affiche une alerte ; sans accepter, Mallory ne voit que le nom du site\n    (DNS/SNI) et le volume échangé.");
      out("Un faux AP voit tout ce qui n'est pas protégé de bout en bout. HTTPS et VPN protègent le contenu ; l'authentification du point d'accès, elle, relève du 802.1X.", "sys");
      if (!x.twin) { x.twin = true; note("twin"); fig("twin", false); say("Maître Ada", "Voilà le piège des phrases partagées. Pour le personnel, Rosa a besoin d'une vraie preuve d'identité du point d'accès : le WPA-Entreprise. Retourne à l'arrière-boutique."); }
      return;
    }
    out("Mallory présente son faux serveur RADIUS. Le certificat reçu :", "sys");
    code("Sujet : CN=radius.cafe.port443\nÉmetteur : Mallory CA (auto-signé)\nAttendu par le téléphone : émetteur = « Autorité du Café du Port »");
    out("Le téléphone refuse : le certificat n'est signé par aucune autorité de confiance pour ce profil. La connexion échoue avant que le moindre identifiant ne soit envoyé. Mallory ne peut pas signer au nom de l'autorité du café.", "ok");
    out("Réserve : tout cela suppose que les appareils sont configurés pour vérifier le certificat ; si Bob touche « accepter quand même », la protection tombe.", "sys");
    if (!x.entTest) { x.entTest = true; note("eap"); fig("twin", true); }
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Le café fonctionne désormais en WPA3 : le personnel passe par 802.1X, les clients ont une longue phrase, et HTTPS protège ce qui passe par les ondes. Rosa a même effacé la phrase de l'ardoise : elle la distribue à voix basse.");
    say("Rosa", "Et la phrase « croissant » ? Elle est dans le dictionnaire des pâtissiers, pas dans celui des attaquants !");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }

  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le café, c'est le réseau Wi-Fi et les ondes sont publiques.** N'importe qui à portée peut recevoir toutes les trames. La sécurité du Wi-Fi n'a jamais consisté à cacher le signal, mais à le chiffrer et à authentifier ceux qui parlent.");
    out("**La borne ouverte et la borne WEP = le passé.** Sans chiffrement, tout se lit (mots de passe HTTP, cookies). WEP chiffre avec RC4, mais l'IV de 24 bits est transmis en clair et se répète après quelques milliers de trames : deux trames de même IV partagent le même flux de chiffrement, et leur XOR révèle le XOR des textes clairs. Des attaques statistiques retrouvent la clé elle-même.");
    out("**La phrase de passe et l'ardoise = WPA2-Personnel.** Phrase + SSID → PMK par PBKDF2 : le SSID sert de sel, ce qui rend les tables précalculées spécifiques à chaque nom de réseau (d'où le danger des noms par défaut comme « freebox »). La PMK est la même pour tous les appareils du réseau ; la PTK, elle, est propre à chaque connexion (PMK + MAC + ANonce + SNonce).");
    out("**La poignée de main à quatre messages et le MIC.** Les messages ① et ② exposent ANonce, SNonce et le MIC calculé avec la KCK : avec ça, tout candidat de phrase peut être vérifié hors ligne. Pas besoin de casser AES : on teste des phrases, pas des clés.");
    out("**La désauthentification = trames de gestion non protégées.** Forger un « Deauth » n'exige aucun secret. Le client se reconnecte et refait la poignée de main que l'attaquant attend. Le PMF (802.11w, obligatoire en WPA3) authentifie ces trames. Il n'empêche pas le brouillage radio, simplement les faux messages. (D'autres techniques, comme l'attaque PMKID, capturent même sans client.)");
    out("**Le dictionnaire de Mallory = l'attaque hors ligne.** Chaque candidat coûte un calcul de PMK. Le vrai PBKDF2 (4096 tours de HMAC-SHA1) est plus lent que ta simulation, mais des GPU en font des millions par seconde. Seule la longueur et l'imprévisibilité de la phrase protègent : au moins 16 caractères, unique, de préférence aléatoire (mots tirés au hasard, gestionnaire de mots de passe).");
    out("**WPA3-SAE (Dragonfly) = authentification par mot de passe qui résiste au hors ligne.** Un échange Diffie-Hellman dont l'élément de départ est dérivé de la phrase : une capture ne permet de vérifier aucune hypothèse, chaque essai exige un échange avec l'AP (qui peut limiter et journaliser). Les exposants éphémères sont effacés : même si la phrase fuite plus tard, les anciennes captures restent illisibles (confidentialité persistante). WPA3 ne rend pas « croissant » sûr : il oblige à l'attaquer en direct.");
    out("**La camionnette = le faux point d'accès (evil twin).** Un SSID n'est pas une identité. Avec une phrase partagée, quiconque la connaît peut se faire passer pour le réseau. Contre cela : 802.1X avec vérification du certificat du serveur RADIUS (EAP-TLS ou PEAP, appareils configurés pour refuser un certificat inconnu), HTTPS (avec HSTS), VPN sur les réseaux non maîtrisés, et ne jamais accepter une alerte de certificat. Pour un réseau invité sans phrase, OWE (« Enhanced Open ») chiffre sans authentifier.");
    out("**Les simplifications du jeu.** (1) La PMK est ici 1000 tours de SHA-256 ; le vrai WPA2 utilise PBKDF2-HMAC-SHA1, 4096 tours, 256 bits ; la PTK vient d'une fonction PRF à base de HMAC et les MIC sont des HMAC-SHA1 ou AES-CMAC. Le chiffrement de données est AES-CCMP, simulé ici par un flux dérivé de SHA-256. (2) Le SAE est un jouet : un groupe modulaire de 31 bits, où un logarithme discret serait cassable ; le vrai SAE utilise une courbe elliptique de 256 bits, des scalaires et éléments masqués, et une étape de confirmation plus riche. Il a aussi eu des failles d'implémentation (Dragonblood, 2019, corrigées). (3) Le dictionnaire ne compte qu'une centaine de candidats ; les vrais en contiennent des milliards. Les vitesses des GPU sont des ordres de grandeur. (4) La démonstration WEP se limite à la réutilisation de l'IV ; l'attaque réelle retrouve la clé après quelques dizaines de milliers de trames. (5) KRACK (2017, rejeu du message ③), le brouillage radio, WPS, les modes de transition WPA2/WPA3 et les portails captifs (page de connexion à usurper) ne sont pas simulés. (6) Un faux AP peut aussi viser des appareils qui acceptent sans vérification un certificat ; le jeu suppose des profils bien configurés pour 802.1X.");
    out("Rappel utile : **WPA3 si possible (sinon WPA2-AES) avec une phrase de passe longue et unique, PMF activé, WPA-Entreprise avec certificat vérifié pour le personnel, et HTTPS ou VPN sur tout réseau qu'on ne contrôle pas. Et on ne teste qu'avec autorisation.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    evol: () => {
      const m = F().mode, col = (x, titre, l1, l2, l3, cls) =>
        R(x, 16, 100, 112, cls) + T(x + 50, 38, titre, "f-b") + T(x + 50, 62, l1, "f-s") + T(x + 50, 80, l2, "f-s") + T(x + 50, 98, l3, "f-s");
      const where = m === "wpa2" ? 263 : m === "wpa3" ? 368 : m === "ent" ? 368 : 0;
      return {
        cap: "Du réseau ouvert au WPA3 : chaque génération corrige une faiblesse de la précédente. Le repère indique l'état actuel de ton café.",
        svg: SVG(190, "Évolution de la sécurité Wi-Fi",
          col(3, "Ouvert", "aucune clé", "tout se lit", "✗", "f-bad") + col(108, "WEP 1997", "RC4, IV 24 bits", "clé cassée", "en minutes", "f-bad") +
          col(213, "WPA2 2004", "AES-CCMP", "4 messages", "phrase longue", "f-pub") + col(318, "WPA3 2018", "SAE + PMF", "pas d'attaque", "hors ligne", "f-ok") +
          AR(20, 150, 400, 150) + T(210, 144, "plus sûr", "f-s") + (where ? T(where, 172, "▲ ton café " + (m === "ent" ? "(+802.1X)" : "(maintenant)"), "f-s ft-ok") : T(263, 172, "▲ café (WPA2)", "f-s ft-ok")))
      };
    },
    pmk: (a) => {
      a = a || { pass: F().pass, pm: pmk(F().pass), ptk: null };
      const p = a.pass.length > 16 ? a.pass.slice(0, 15) + "…" : a.pass;
      return {
        cap: "La phrase et le SSID donnent la PMK, identique pour tout le réseau. Avec les adresses MAC et les deux nonces d'une connexion, la PMK donne la PTK, propre à cette connexion.",
        svg: SVG(240, "Dérivation PMK puis PTK",
          R(4, 12, 120, 34) + T(64, 28, "phrase de passe", "f-s") + T(64, 41, "« " + p + " »", "f-b") +
          R(4, 52, 120, 24) + T(64, 68, "SSID : " + SSID, "f-s") +
          AR(124, 30, 156, 44) + AR(124, 64, 156, 52) +
          R(158, 24, 100, 40, "f-pub") + T(208, 42, "PBKDF2", "f-b ft-pub") + T(208, 56, "4096 tours", "f-s") +
          AR(258, 44, 290, 44) + R(292, 24, 124, 40, "f-priv") + T(354, 42, "PMK (256 bits)", "f-b") + T(354, 56, a.pm.slice(0, 14) + "…", "f-s") +
          R(4, 108, 150, 64) + T(79, 124, "PMK  (ci-dessus)", "f-s") + T(79, 140, "MAC de l'AP + du client", "f-s") + T(79, 156, "ANonce + SNonce", "f-s") +
          AR(154, 140, 196, 140) + R(198, 124, 64, 32, "f-pub") + T(230, 144, "PRF", "f-b ft-pub") + AR(262, 140, 290, 140) +
          R(292, 106, 124, 24, "f-priv") + T(354, 122, "KCK : les MIC", "f-s") +
          R(292, 136, 124, 24, "f-priv") + T(354, 152, "KEK : clé groupe", "f-s") +
          R(292, 166, 124, 24, "f-priv") + T(354, 182, "TK : données", "f-s") +
          T(210, 210, "PTK = KCK + KEK + TK : nouvelle à chaque connexion", "f-s") +
          T(210, 228, "PMK fixe (phrase + SSID)  ·  PTK jetable (nonces)", "f-s"))
      };
    },
    hand: (cap) => {
      const c = F().cap, v = c ? c.an.slice(0, 8) + "…" : "3f9a1c0e…", w = c ? c.sn.slice(0, 8) + "…" : "b28e04d1…";
      const hot = cap !== false;
      return {
        cap: "Quatre messages entre le client et le point d'accès. Les messages ① et ② (en rouge) contiennent ANonce, SNonce et un MIC : de quoi tester une phrase hors ligne.",
        svg: SVG(262, "Poignée de main à quatre messages",
          T(70, 18, "Bob (client)", "f-b") + T(350, 18, "Point d'accès", "f-b") + LN(70, 26, 70, 200, "f-dash") + LN(350, 26, 350, 200, "f-dash") +
          T(210, 56, "① ANonce  " + v, "f-s") + AR(346, 62, 74, 62, hot ? "f-bad" : "") +
          T(210, 96, "② SNonce  " + w + "  + MIC", "f-s") + AR(74, 102, 346, 102, hot ? "f-bad" : "") +
          T(210, 136, "③ clé de groupe (chiffrée) + MIC", "f-s") + AR(346, 142, 74, 142) +
          T(210, 176, "④ acquittement + MIC", "f-s") + AR(74, 182, 346, 182) +
          T(210, 218, hot ? "Mallory capte ① et ②" : "Ève pourrait capter ① et ②", "f-s ft-bad") +
          T(210, 236, "Chacun dérive la même PTK : le MIC prouve", "f-s") + T(210, 252, "qu'il connaît la phrase, sans l'envoyer.", "f-s"))
      };
    },
    offline: () => {
      const r = F().rate;
      return {
        cap: "À gauche, WPA2 : une capture, des millions d'essais par seconde en silence. À droite, WPA3-SAE : une capture ne permet de tester rien, chaque essai passe par le vrai point d'accès.",
        svg: SVG(236, "Attaque hors ligne contre WPA2 et WPA3",
          R(4, 14, 204, 206, "f-bad") + T(106, 34, "WPA2-Personnel", "f-b ft-bad") +
          T(106, 58, "1 capture suffit", "f-s") + T(106, 76, "puis chez Mallory :", "f-s") + T(106, 94, "PMK → PTK → MIC", "f-s") + T(106, 112, "comparé au MIC capté", "f-s") +
          T(106, 140, "aucun témoin, pas de limite", "f-s") + T(106, 158, r ? `ici : ≈ ${r.toLocaleString("fr-FR")} essais/s` : "ici : des centaines/s", "f-s") + T(106, 174, "GPU : millions/s", "f-s") +
          T(106, 198, "faible : trouvée", "f-s ft-bad") + T(106, 212, "longue : résiste", "f-s ft-ok") +
          R(216, 14, 200, 206, "f-ok") + T(316, 34, "WPA3-SAE", "f-b ft-ok") +
          T(316, 58, "la capture est inutile", "f-s") + T(316, 76, "aucun candidat testable", "f-s") + T(316, 94, "1 essai = 1 échange", "f-s") + T(316, 112, "avec le vrai AP", "f-s") +
          T(316, 140, "≈ 5 essais par minute", "f-s") + T(316, 158, "échecs limités, journalisés", "f-s") + T(316, 174, "clé éphémère : le passé", "f-s") +
          T(316, 198, "reste illisible même", "f-s ft-ok") + T(316, 212, "si la phrase fuite", "f-s ft-ok"))
      };
    },
    twin: (ent) => {
      ent = ent === undefined ? !!F().entOn : ent;
      return {
        cap: ent ? "Avec 802.1X, le téléphone vérifie le certificat du serveur : le faux point d'accès est refusé malgré son signal." : "Même SSID, signal plus fort : le téléphone choisit le faux. La phrase partagée (ardoise) permet même à Mallory de mener la poignée de main.",
        svg: SVG(240, "Faux point d'accès",
          R(8, 14, 130, 82) + T(73, 34, "Vrai AP", "f-b") + T(73, 50, SSID, "f-s") + T(73, 66, "signal -71 dBm", "f-s") + T(73, 84, ent ? "✓ certificat valide" : "", "f-s ft-ok") +
          R(282, 14, 130, 82, "f-bad") + T(347, 34, "Faux AP", "f-b ft-bad") + T(347, 50, SSID, "f-s") + T(347, 66, "signal -38 dBm", "f-s") + T(347, 84, ent ? "✗ certif. inconnu" : "Mallory voit tout", "f-s ft-bad") +
          R(145, 150, 130, 44, "f-priv") + T(210, 170, "Téléphone de Bob", "f-b") + T(210, 186, "reconnexion auto", "f-s") +
          (ent ? AR(190, 148, 90, 98, "f-pub") + LN(240, 148, 330, 98, "f-bad f-dash")
               : AR(240, 148, 330, 98, "f-bad") + LN(190, 148, 90, 98, "f-dash")) +
          T(210, 218, ent ? "802.1X : le serveur prouve son identité" : "même nom + meilleur signal : le faux gagne", "f-s") +
          T(210, 234, ent ? "(si le profil refuse les certificats inconnus)" : "défense : 802.1X, HTTPS, VPN", "f-s"))
      };
    },
  };

  GAMES.wifi = {
    id: "wifi", order: 11, title: "Le Café du Wi-Fi", pageTitle: "Wi-Fi Quest", subtitle: "aventure textuelle · sécurité du Wi-Fi",
    blurb: "Sécurise le Wi-Fi du café de Port-443 : du réseau ouvert au WPA3, en simulant les vraies attaques.",
    concept: "WPA2, WPA3, sécurité du Wi-Fi",
    start: "comptoir", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.pass = FIRST; x.pv = 0; x.mode = "wpa2"; x.cap = null; x.nhs = 0; },
    refig(name) {
      const x = F();
      if (name === "pmk") fig("pmk", { pass: x.lastDerive || x.pass, pm: pmk(x.lastDerive || x.pass), ptk: null });
      else if (name === "hand") fig("hand", !!x.cap);
      else if (name === "twin") fig("twin", !!x.entOn);
      else fig(name);
    },
    figAlias: { evol: ["histoire", "wep", "wpa"], pmk: ["ptk", "cle", "derivation"], hand: ["poignee", "handshake", "messages"], offline: ["wpa3", "sae", "dictionnaire"], twin: ["faux", "evil", "802", "entreprise"] },
    help: "Spécifiques : `ecouter [ouvert|wep]` · `deriver ‹phrase›` · `desauthentifier bob` · `attaquer` · `dechiffrer` · `changer phrase ‹texte›` · `activer wpa3|entreprise` · `connecter bob`",
    verbs: {
      listen: { words: ["ecouter", "renifler", "sniffer", "capter"], run: listen },
      derive: { words: ["deriver", "derive"], run: derive },
      deauth: { words: ["desauthentifier", "deauth", "deconnecter", "chasser"], run: deauth },
      attack: { words: ["attaquer", "deviner", "craquer", "essayer"], run: attack },
      decrypt: { words: ["dechiffrer", "decrypter"], run: decryptCmd },
      change: { words: ["changer", "modifier"], run: changeCmd },
      activate: { words: ["activer", "configurer", "passer"], run: activate },
      connect: { words: ["connecter", "rejoindre", "reconnecter"], run: connect },
    },
    intro() {
      out("Le Café du Wi-Fi", "title");
      out("Le Café du Port, à Port-443, offre le Wi-Fi à ses clients. Rosa, la patronne, aimerait que ce soit sûr, sans trop savoir ce que ça veut dire. Maître Ada te confie un audit autorisé : suivre l'évolution de la sécurité Wi-Fi, voir comment Mallory attaque pendant qu'Ève écoute, et corriger. Tout est simulé, avec de vrais calculs, sur le réseau du café uniquement.", "");
    },
  };
})();
