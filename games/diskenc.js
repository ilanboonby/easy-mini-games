"use strict";
/* Le Caveau Scellé : chiffrement de disque, hiérarchie de clés, modes de chiffrement, menaces résiduelles,
   sauvegardes chiffrées, séquestre et effacement cryptographique. SHA-256 réel ; tout le reste est un jouet pédagogique. */
(function () {
  const F = () => f();
  const ITER = 3000; // itérations de la dérivation « lente » (SHA-256 réel)
  const LIST = ["azerty", "soleil", "port443", "password", "123456", "qwerty", "bonjour", "motdepasse", "doudou", "football", "letmein", "admin", "guilde", "secret", "caveau"];
  const CAND = LIST.flatMap(w => [w, w + "1", w + "123"]);          // dictionnaire de Mallory : 45 candidates
  const weak = p => p.length < 16 || CAND.includes(p.toLowerCase());
  const SECT = [
    "REGISTRE DES MEMBRES - GUILDE DE PORT-443",
    "alice  maitre serrurier   tel 06 00 00 00 01",
    "bob    cartographe        IBAN FR76 0000 0000",
    "carla  archiviste         tel 06 00 00 00 03",
    "COFFRE DE LA GUILDE       code 4817 (fictif)",
  ];
  const SW = 46; // largeur d'un secteur jouet (octets)

  /* ---------- petite boîte à outils cryptographique (jouet, SHA-256 réel) ---------- */
  const hexOf = s => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, "0")).join("");
  const textOf = h => { let s = ""; for (let i = 0; i < h.length; i += 2) { const c = parseInt(h.substr(i, 2), 16); s += c >= 32 && c < 127 ? String.fromCharCode(c) : "·"; } return s; };
  const xorHex = (a, b) => { let o = ""; for (let i = 0; i < a.length; i += 2) o += (parseInt(a.substr(i, 2), 16) ^ parseInt(b.substr(i % b.length, 2), 16)).toString(16).padStart(2, "0"); return o; };
  const ks = (key, tweak, n) => { let s = "", i = 0; while (s.length < n * 2) s += sha256(key + ":" + tweak + ":" + (i++)); return s.slice(0, n * 2); };
  const encSect = (txt, dek, i) => xorHex(hexOf(txt.padEnd(SW)), ks(dek, "s" + i, SW));           // tweak = numéro de secteur
  const decSect = (hx, dek, i) => textOf(xorHex(hx, ks(dek, "s" + i, SW)));
  const kdf = (pw, salt, iter) => { let h = sha256(salt + "|" + pw); for (let i = 1; i < iter; i++) h = sha256(h + salt + pw); return h.slice(0, 32); };
  const DEK = g => sha256("dek:" + g).slice(0, 32);
  const chk = d => sha256("chk:" + d).slice(0, 8);
  const sh = (s, n) => s.slice(0, n || 8) + "…";
  function mkHdr(phrase, iter, gen) {
    const x = F(); x.ns = (x.ns || 0) + 1;
    const salt = sha256("salt:" + x.ns).slice(0, 8), dek = DEK(gen);
    return { salt, iter, gen, wrapped: xorHex(dek, kdf(phrase, salt, iter)), check: chk(dek) };
  }
  function tryPhrase(h, p) { const kek = kdf(p, h.salt, h.iter), dek = xorHex(h.wrapped, kek); return { kek, dek, ok: chk(dek) === h.check }; }
  const diskHex = (x, i) => encSect(SECT[i], DEK(x.hdr ? x.hdr.gen : 0), i);

  /* amorce (partie non chiffrée du démarrage) et mesures du TPM */
  const BOOT_OK = "amorce-guilde-v1", BOOT_BAD = "amorce-guilde-v1+espion";
  const bootOf = () => (F().tamper ? BOOT_BAD : BOOT_OK);
  function pcrChain(boot) { let p = "0".repeat(64); const st = []; for (const m of ["microprogramme-v7", "amorce:" + boot, "noyau-v6"]) { p = sha256(p + m); st.push([m, p]); } return st; }
  const pcrOf = boot => pcrChain(boot)[2][1];

  /* sauvegarde */
  const BK = sha256("bk:diskenc").slice(0, 32);
  const ARCH = SECT.map((t, i) => encSect(t, BK, i + 100));
  const BKCHK = chk(BK);
  const RK = "RK-" + sha256("rk:diskenc").slice(0, 20).toUpperCase().match(/.{4}/g).join("-");
  const rkKey = code => sha256("rkkey:" + code.toUpperCase().replace(/[^A-Z0-9]/g, "")).slice(0, 32);
  const rkNorm = s => s.toUpperCase().replace(/[^A-Z0-9]/g, "");

  /* mosaïque : un cadenas, un « pixel » = un bloc d'un octet */
  const PAD = [
    "......####......",
    ".....#....#.....",
    ".....#....#.....",
    ".....#....#.....",
    "..############..",
    "..############..",
    "..####....####..",
    "..####....####..",
    "..####....####..",
    "..############..",
  ];
  const MW = 16, MH = 10, GL = "·:+=*#%@&$?!~^oX";
  const MKEY = "mosaique:guilde";
  function mosaic(mode) {
    const kb = parseInt(sha256(MKEY).slice(0, 2), 16), out = [];
    PAD.forEach((row, r) => [...row].forEach((ch, c) => {
      const p = r * MW + c, v = ch === "#" ? 255 : 0;
      const k = mode === "ecb" ? kb : parseInt(sha256(MKEY + ":" + p).slice(0, 2), 16);
      out.push(v ^ k);
    }));
    return out;
  }
  const grid = (cells, fn) => { let s = ""; for (let r = 0; r < MH; r++) { for (let c = 0; c < MW; c++) s += fn(cells[r * MW + c], r * MW + c) + " "; s += "\n"; } return s.trimEnd(); };
  function eveGuess(cells) { // Ève marque tout ce qui diffère de la valeur la plus fréquente
    const cnt = new Map(); cells.forEach(v => cnt.set(v, (cnt.get(v) || 0) + 1));
    const top = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0][0];
    return grid(cells, v => (v === top ? "." : "#"));
  }

  const modeTxt = x => ({ clair: "aucun chiffrement", fichier: "un seul fichier chiffré", volume: x.wiped ? "volume chiffré, entête détruit" : "volume entier chiffré" }[x.mode]);
  const pwTxt = x => ({ on: "allumé et déverrouillé (la clé de données est en mémoire)", sleep: "en veille (la mémoire reste alimentée : la clé y est toujours)", off: "éteint (la mémoire est vidée : plus aucune clé)" }[x.pw]);

  const notes = {
    complet: ["Chiffrer des fichiers ou tout le volume", "Chiffrer un seul fichier laisse fuiter tout le reste : noms, tailles, dates, copies temporaires, fichier d'échange (swap), historiques. Le chiffrement complet du volume (BitLocker, FileVault, LUKS) chiffre tout ce qui est écrit sur le disque, sans que l'utilisateur y pense : un disque démonté ne montre que du bruit. Le mot de passe de session, lui, ne protège PAS le disque : il suffit de le sortir de la machine."],
    cles: ["La hiérarchie des clés", "La phrase de passe ne chiffre pas le disque directement. Elle sert à dériver une clé d'enveloppe (KEK), qui ne fait qu'ouvrir la vraie clé de données (DEK), stockée enveloppée dans l'entête du volume. La DEK chiffre les secteurs. Changer la phrase de passe = ré-envelopper la DEK (quelques octets, instantané) sans toucher aux téraoctets chiffrés. Plusieurs emplacements (phrase, clé de récupération, TPM) peuvent envelopper la même DEK. Seul un changement de DEK impose de tout re-chiffrer."],
    kdf: ["Dérivation lente de clé (KDF)", "Un attaquant qui a le disque a l'entête : il essaie des phrases candidates hors ligne, sans limite ni alerte. Une fonction de dérivation lente (PBKDF2, scrypt, Argon2) multiplie le coût de chaque essai (ici ×3 000 ; en vrai : des centaines de millisecondes et de la mémoire). Elle ralentit l'attaque, elle ne l'empêche pas : seule une phrase de passe longue et imprévisible la sort du possible."],
    modes: ["Le mode de chiffrement compte", "Un chiffrement par blocs ne traite que quelques octets à la fois ; le mode dit comment enchaîner les blocs. En ECB, deux blocs identiques donnent deux blocs chiffrés identiques : les formes et les répétitions du clair restent visibles. Les modes pour disques (XTS) ajoutent un « tweak » qui dépend de la position (secteur, bloc) : le même clair, à deux endroits, donne deux chiffrés différents. Un bon algorithme (AES) ne suffit pas : il faut aussi le bon mode."],
    menaces: ["Les menaces qui restent", "Le chiffrement de disque protège un disque qui sort de la machine, pas toutes les situations : (1) une phrase de passe faible tombe hors ligne ; (2) un portable allumé ou en veille garde les clés en mémoire ; (3) l'attaque de la « femme de chambre » (evil maid) : on trafique la partie non chiffrée du démarrage, puis on récupère la phrase tapée par la victime. Phrase longue, extinction réelle et démarrage vérifié sont les parades."],
    memoire: ["Clés en mémoire : veille et démarrage à froid", "Pour lire le disque en continu, le système garde la DEK en mémoire vive tant qu'il est allumé ou en veille. La mémoire ne s'efface pas instantanément à la coupure (plus longtemps si elle est refroidie) : un attaquant peut en extraire la clé (« cold boot ») en cherchant des motifs de clé. Parades : éteindre complètement avant de laisser la machine, exiger une authentification à la sortie de veille, matériel qui chiffre la mémoire."],
    tpm: ["TPM, démarrage mesuré et PIN", "Le TPM est une puce qui enregistre (« mesure ») chaque composant du démarrage dans des registres (PCR) enchaînés par hachage, et ne libère une clé scellée que si les mesures sont celles attendues. Le démarrage sécurisé (Secure Boot) vérifie en plus la signature de l'amorce. Une amorce trafiquée change les mesures : la clé reste scellée et l'utilisateur est alerté avant d'avoir tapé quoi que ce soit. Un code PIN, dont le TPM limite les essais, évite qu'une machine démarre toute seule entre de mauvaises mains."],
    sauvegarde: ["Sauvegardes chiffrées et séquestre des clés", "Une sauvegarde chez un tiers se chiffre côté client, avec une clé qui ne vit jamais à côté des données (sinon l'hébergeur lit tout). Mais une clé unique, perdue, rend les sauvegardes irrécupérables pour toujours : aucune porte dérobée. Il faut une clé de récupération (séquestre), gardée séparément (coffre, idéalement partagée entre deux personnes) et dont on a testé l'usage. Les clés deviennent LE secret à protéger ET à ne pas perdre."],
    crypto: ["Effacement cryptographique", "Quand les données existent en de multiples copies (sauvegardes, bandes, réplicas, cellules de SSD réaffectées), les effacer toutes est impossible à garantir. Si tout est chiffré, détruire la clé (et TOUTES ses copies, y compris les clés de récupération) rend toutes les copies illisibles d'un coup : c'est le crypto-shredding. Condition : aucune copie de clé ne survit, et l'algorithme reste solide."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Le portable volé contenait les registres de la Guilde : elle veut savoir ce que le voleur peut en tirer, selon la protection du disque." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, qui joue ici le rôle du voleur, dans l'antre où elle expérimente sur des copies. Elle ne vise que les données fictives de l'audit." },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, administratrice curieuse du serveur de sauvegarde hébergé : elle voit tout ce qui est stocké chez elle." },
    portable: { names: ["portable", "ordinateur", "machine", "laptop", "pc"], label: "le portable de test", vis: () => S.room === "atelier",
      desc: () => { const x = F(); return "Le portable de test, un clone de celui de Bob. Disque : " + modeTxt(x) + ". État : " + pwTxt(x) + (x.tpmOn ? ". TPM : amorce mesurée, clé scellée, PIN demandé" : "") + ".\nSur ce banc : `demonter disque` (vue du voleur), `chiffrer fichier`, `chiffrer disque ‹phrase›`, `eteindre portable`, `veille`, `demarrer`, `deverrouiller ‹phrase›`."; } },
    disque: { names: ["disque", "ssd", "volume"], label: "le disque du portable", vis: () => S.room === "atelier",
      onExamine: () => bench(), desc: () => "(Voilà ce que voit celui qui tient le disque, sans l'ordinateur ni sa session.)" },
    entete: { names: ["entete", "header", "enveloppe", "emplacement"], label: "l'entête du volume", vis: () => S.room === "atelier",
      desc: () => { const x = F(); if (!x.vol) return "Pas d'entête : le disque n'est pas encore chiffré en volume."; if (x.wiped) return "L'entête a été détruit : plus aucun emplacement de clé."; const h = x.hdr; return "Entête du volume (lisible par tous, sur le disque) :\n  sel : " + h.salt + "   itérations : " + h.iter + "\n  DEK enveloppée : " + h.wrapped + "\n  empreinte de contrôle : " + h.check + "\n" + (x.tpmOn ? "  emplacement TPM : DEK scellée (PCR + PIN)\n" : "") + "La DEK n'y figure jamais en clair : seulement XOR la clé dérivée de la phrase (la KEK)."; } },
    tpm: { names: ["tpm", "module", "puce"], label: "le module TPM", vis: () => S.room === "atelier",
      desc: () => { const x = F(); return x.tpmOn ? "Le TPM garde une clé scellée : il ne la libère que si les mesures du démarrage sont celles de l'amorce d'origine et si le PIN est correct." : "Une puce de sécurité soudée à la carte mère, pour l'instant inutilisée. Elle mesure le démarrage et peut sceller une clé. `activer tpm ‹PIN›` (quand tu auras vu pourquoi)."; } },
    mosaique: { names: ["mosaique", "cadenas", "image", "tableau"], label: "la mosaïque (un cadenas)", vis: () => S.room === "mosaique",
      desc: () => "Une mosaïque de 16 × 10 carreaux : un cadenas. Chaque carreau est un bloc d'un octet (0 pour le fond, 255 pour le trait). Voici le clair :\n" + PAD.join("\n") + "\n`chiffrer mosaique ecb` ou `chiffrer mosaique tweak`." },
    serveur: { names: ["serveur", "sauvegarde", "nuage", "archive"], label: "le serveur de sauvegarde", vis: () => S.room === "archives",
      desc: () => { const x = F(); return "Le serveur de sauvegarde d'un hébergeur, administré par Ève. Contenu : " + (x.bk === "clair" ? "registres en clair" : x.bk === "chiffre" ? "archive chiffrée côté client" + (x.keyAt === "serveur" ? " + key.txt (la clé, à côté !)" : "") + (x.slot ? " + recuperation.slot (DEK de sauvegarde enveloppée par la clé de récupération)" : "") : "vide") + ".\n`sauvegarder clair|chiffre`, `ecouter serveur`, `ranger cle portable|serveur`, `restaurer sauvegarde ‹code›`."; } },
    coffre: { names: ["coffre", "coffre fort"], label: "le coffre de la Guilde", vis: () => S.room === "archives",
      desc: () => { const x = F(); return "Le coffre de la Guilde, hors du serveur et hors du portable. " + (x.rkState === "coffre" ? "Dedans, une feuille scellée : " + RK : x.rkState === "detruite" ? "La feuille de la clé de récupération a été brûlée." : "Vide pour l'instant."); } },
    rk: { names: ["cle de recuperation", "cle recuperation", "recuperation", "rk"], label: "la clé de récupération", take: false,
      desc: () => "Une feuille portant la clé de récupération : " + RK + ". Dans ta poche, elle n'est pas plus en sécurité que le portable : à ranger dans le coffre (`ranger cle recuperation coffre`) ou à remettre à Maître Ada (`donner cle recuperation a ada`)." },
  };

  const rooms = {
    quai: { name: "Le quai de Port-443", short: "Quai", alias: ["quai", "gare"], ents: ["ada"], exits: { nord: "atelier", est: "mosaique", sud: "cave", ouest: "archives" },
      desc: () => "Le quai de la gare. C'est dans un train que le portable de la Guilde a été volé. Maître Ada y a installé son QG : au nord l'atelier du serrurier (banc d'essai), à l'est la salle des mosaïques, au sud l'antre de Mallory, à l'ouest les archives." },
    atelier: { name: "L'atelier du serrurier", short: "Atelier", alias: ["atelier", "banc"], ents: ["portable", "disque", "entete", "tpm"], exits: { sud: "quai" },
      desc: () => "Un banc d'essai où trône un clone du portable volé, disque démontable, avec son module TPM à côté. Ici, on configure la protection du disque, et on voit ce que verrait un voleur." },
    mosaique: { name: "La salle des mosaïques", short: "Mosaïques", alias: ["mosaique", "mosaiques", "salle"], ents: ["mosaique"], exits: { ouest: "quai" },
      desc: () => "Un mur couvert de petits carreaux : une mosaïque en forme de cadenas, que l'on peut faire « chiffrer » carreau par carreau avec un chiffrement par blocs jouet. Ève s'y est assise pour regarder passer le résultat, sans connaître la clé." },
    cave: { name: "L'antre de Mallory", short: "Antre", alias: ["antre", "cave", "mallory"], ents: ["mallory"], exits: { nord: "quai" },
      desc: () => "Une cave pleine de câbles et de bombes d'air froid. Mallory y rejoue, sur le clone du portable et avec l'accord d'Ada, ce que ferait un voleur : phrases devinées, mémoire capturée, amorce trafiquée. Rien ne sort de cette pièce." },
    archives: { name: "Les archives", short: "Archives", alias: ["archives", "archive"], ents: ["serveur", "coffre", "eve"], exits: { est: "quai" },
      desc: () => "Une salle de classeurs et un petit coffre-fort. Le serveur de sauvegarde est loué à un hébergeur : Ève, qui l'administre, est à côté. Le coffre, lui, appartient à la Guilde." },
  };

  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.sawClear) return "bench";
    if (!x.fileEnc) return "file";
    if (!x.sawFile) return "benchf";
    if (!x.vol) return "vol";
    if (!x.sawVol) return "benchv";
    if (!x.unlockOk) return x.pw !== "off" ? "off1" : "unlock";
    if (!x.rewrap) return x.pw === "off" ? "wake0" : "rewrap";
    if (!x.ecb) return "ecb";
    if (!x.tw) return "tweak";
    if (!x.seenFast) return "atk1";
    if (!x.slowSet) return x.pw === "off" ? "wake1" : "kdf";
    if (!x.seenSlow) return "atk2";
    if (!x.pwStrong) return x.pw === "off" ? "wake2" : "pwfix";
    if (!x.blocked) return "atk3";
    if (!x.memHit) return x.pw === "off" ? "wake3" : "ram1";
    if (!x.memBlock) return x.pw !== "off" ? "off2" : "ram2";
    if (!x.maidWin) return x.pw !== "off" ? "off3" : x.tamper ? "boot1" : "maid1";
    if (!x.tpmOn) return "tpm";
    if (!x.maidBlock) return x.pw !== "off" ? "off4" : x.tamper ? "boot2" : "maid2";
    if (!x.bkClear) return "bk1";
    if (!x.eveClear) return "eve1";
    if (!x.bkEnc) return "bk2";
    if (!x.eveKey) return "eve2";
    if (x.keyAt !== "portable") return "place";
    if (!x.eveBlock) return "eve3";
    if (!x.lost) return "lost";
    if (!x.rkGen) return "rkgen";
    if (x.rkState !== "coffre") return "rksafe";
    if (!x.restored) return "restore";
    if (!x.wiped) return "wipe";
    if (x.rkState !== "detruite") return "rkgone";
    if (!x.proof) return "proof";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend sur le quai.", "`parler ada`"],
    bench: () => ["Va à l'atelier (nord) et regarde ce que voit un voleur qui démonte le disque.", "`aller nord`, puis `demonter disque` (ou `examiner disque`)."],
    file: () => ["Bob avait chiffré son fichier de registres, pas le disque. Reproduis sa protection.", "`chiffrer fichier`"],
    benchf: () => ["Regarde à nouveau le disque sur le banc : qu'est-ce qui reste exposé ?", "`demonter disque`"],
    vol: () => ["Il faut chiffrer tout le volume. Pour reproduire fidèlement le portable de Bob, utilise sa phrase de passe, un mot courant.", "`chiffrer disque soleil123`"],
    benchv: () => ["Rebranche le disque sur le banc du voleur.", "`demonter disque`"],
    off1: () => ["Pour tester l'ouverture du volume, il faut d'abord le verrouiller : éteindre vide la mémoire.", "`eteindre portable`"],
    unlock: () => ["Redonne la phrase de passe : le jeu déroule la dérivation, le déballage, la vérification. Essaie d'abord une mauvaise phrase, tu verras.", "`deverrouiller soleil123`"],
    wake0: () => ["Le portable est éteint : rallume-le en tapant ta phrase.", "`deverrouiller soleil123`"],
    rewrap: () => ["Bob a quitté le service : change la phrase de passe, et regarde ce qui est (ou non) re-chiffré. Garde un mot courant pour la suite de l'audit.", "`changer phrase port443` (puis, si tu es curieux·se, `rechiffrer disque` pour comparer)."],
    ecb: () => ["Va à la salle des mosaïques (est du quai) et chiffre le cadenas bloc par bloc, en mode ECB.", "`aller sud`, `aller est`, puis `chiffrer mosaique ecb`."],
    tweak: () => ["Rechiffre le même cadenas avec un mode qui dépend de la position.", "`chiffrer mosaique tweak`"],
    atk1: () => ["Va à l'antre de Mallory (sud du quai) : elle a le disque et son entête. Que tire-t-elle de la phrase ?", "`attaquer phrase` (dans l'antre)."],
    kdf: () => ["Mallory a trouvé la phrase en un clin d'œil. Rends chaque essai coûteux en réglant la dérivation de clé du volume (à l'atelier).", "`regler kdf lent`"],
    wake1: () => ["Le portable est éteint : rallume-le en tapant ta phrase.", "`deverrouiller ‹ta phrase›` (à l'atelier)."],
    atk2: () => ["Rejoue l'attaque et compare la vitesse.", "`attaquer phrase` dans l'antre."],
    pwfix: () => ["Le temps par essai a augmenté, pas la difficulté de la phrase. Choisis une phrase longue (16 caractères ou plus) qui n'est pas dans un dictionnaire.", "`changer phrase le caveau scelle de port quatre cent quarante trois` (à l'atelier)."],
    wake2: () => ["Le portable est éteint : rallume-le en tapant ta phrase.", "`deverrouiller ‹ta phrase›`."],
    atk3: () => ["Rejoue l'attaque contre la nouvelle phrase.", "`attaquer phrase` dans l'antre."],
    ram1: () => ["Le voleur a la chance de trouver le portable allumé. Que contient sa mémoire ? Va à l'antre.", "`capturer memoire` (dans l'antre)."],
    wake3: () => ["Le portable est éteint : rallume-le d'abord (une machine éteinte n'a plus de clé en mémoire).", "`deverrouiller ‹ta phrase›`, puis `aller sud` ... `capturer memoire`."],
    off2: () => ["Éteins vraiment le portable (atelier), puis refais la capture.", "`eteindre portable`"],
    ram2: () => ["Refais la capture sur le portable éteint.", "`capturer memoire` dans l'antre."],
    off3: () => ["La femme de chambre n'agit que sur un portable éteint (et laissé seul). Éteins-le à l'atelier.", "`eteindre portable`"],
    maid1: () => ["À l'antre, Mallory remplace l'amorce, la partie non chiffrée du démarrage.", "`trafiquer amorce` (dans l'antre)."],
    boot1: () => ["Rentre à l'atelier et rallume le portable comme le ferait la victime.", "`demarrer` (à l'atelier)."],
    tpm: () => ["Fais mesurer le démarrage par le TPM et sceller la clé avec un code PIN, à l'atelier.", "`activer tpm 4821`"],
    off4: () => ["Éteins le portable pour rejouer l'attaque.", "`eteindre portable`"],
    maid2: () => ["Laisse Mallory retrafiquer l'amorce.", "`trafiquer amorce` (dans l'antre)."],
    boot2: () => ["Rallume le portable : que dit le TPM ?", "`demarrer` (à l'atelier)."],
    bk1: () => ["Passons aux sauvegardes : aux archives (ouest du quai), envoie les registres à l'hébergeur, tels quels.", "`aller ouest`, `sauvegarder clair`."],
    eve1: () => ["Demande à Ève ce qu'elle voit sur son serveur.", "`ecouter serveur`"],
    bk2: () => ["Chiffre maintenant la sauvegarde côté client, avant de l'envoyer.", "`sauvegarder chiffre`"],
    eve2: () => ["Regarde ce qu'Ève peut encore faire.", "`ecouter serveur`"],
    place: () => ["La clé est restée à côté des données. Mets-la ailleurs : sur le portable de Bob, par exemple.", "`ranger cle portable`"],
    eve3: () => ["Vérifie qu'Ève est maintenant bloquée.", "`ecouter serveur`"],
    lost: () => ["Le portable de Bob (et la clé) est dans les mains du voleur. Essaie de restaurer la sauvegarde.", "`restaurer sauvegarde`"],
    rkgen: () => ["Il aurait fallu un séquestre : génère une clé de récupération.", "`generer cle recuperation`"],
    rksafe: () => ["Garde cette clé à l'écart du portable et du serveur : dans le coffre de la Guilde.", "`ranger cle recuperation coffre` (ou, au quai, `donner cle recuperation a ada`)."],
    restore: () => ["Teste la restauration avec la clé du coffre : un séquestre non testé ne vaut rien.", "`examiner coffre` pour lire le code, puis `restaurer sauvegarde ‹code›`."],
    wipe: () => ["Dernier chapitre : une cliente demande l'effacement de ses données, partout. Détruis la clé du volume du portable perdu.", "`detruire cle disque`"],
    rkgone: () => ["Détruis aussi la clé de récupération (coffre et emplacement du serveur) : tant qu'une copie existe, l'effacement n'est pas total.", "`detruire cle recuperation`"],
    proof: () => ["Vérifie qu'on ne peut plus rien restaurer.", "`restaurer sauvegarde ‹n'importe quel code›` (aux archives)."],
    end: () => ["Rends compte à Maître Ada.", "`aller` jusqu'au quai, puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- parler ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Un portable de la Guilde a été volé dans le train de nuit. Il contenait les registres des membres. Bob jure qu'il était « protégé par mot de passe ». Mais protégé de quoi, et contre qui ? La réponse dépend de ce que le voleur a entre les mains, et de comment le disque est protégé.");
          say("Maître Ada", "À l'atelier, un clone du portable : on va reproduire sa protection, regarder ce qu'un voleur en tire, puis la renforcer pas à pas. Mallory joue le voleur sur des données fictives. Ève, la curieuse, nous rappellera que les sauvegardes aussi se volent. Commence par `aller nord` : `demonter disque` te montrera la vue du voleur.");
        } else if (x.end) say("Maître Ada", "Les registres sont à l'abri, et ceux qui doivent disparaître ont vraiment disparu. Bon travail.");
        else if (objective() === "end") ending();
        else say("Maître Ada", "Continue l'audit. `indice` si tu bloques, `schema` pour revoir tes schémas.");
        break;
      case "mallory": {
        if (!x.vol) say("Mallory", "Un disque non chiffré, c'est un livre ouvert. Reviens quand tu auras de quoi me défier. (Ici : `attaquer phrase`, `capturer memoire`, `trafiquer amorce`.)");
        else say("Mallory", "Mes outils : `attaquer phrase` (je devine hors ligne depuis l'entête), `capturer memoire` (je fouille la mémoire d'une machine allumée ou en veille), `trafiquer amorce` (je passe quand le portable dort dans une chambre d'hôtel). Tout ça sur la copie d'audit, évidemment.");
        break;
      }
      case "eve":
        if (!x.bk) say("Ève", "Je gère ce serveur pour l'hébergeur. Je ne suis pas méchante, juste curieuse : tout ce qui est déposé ici, je peux le lire. Fais une sauvegarde, tu verras.");
        else say("Ève", "Ce que je vois sur le serveur dépend de ce que tu y déposes... et de ce que tu laisses à côté. `ecouter serveur` si tu veux que je regarde pour toi.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- vue du voleur ---------- */
  function bench() {
    const x = F(); x.benched = true;
    out("Tu retires le disque du portable et tu le branches sur ton propre banc : l'ordinateur, son système et sa session ne sont plus dans la boucle. Voici ce que voit celui qui tient le disque :", "sys");
    const boot = "Partition /boot (nécessairement non chiffrée, il faut bien démarrer) : amorce.bin  sha256 " + sh(sha256(bootOf()), 12);
    if (x.mode === "clair") {
      code("Partition principale (non chiffrée)\n  /home/bob/Documents/registre-membres.txt\n  /home/bob/Documents/salaires-2026.ods\n\nContenu de registre-membres.txt :\n" + SECT.map(s => "  " + s).join("\n") + "\n\n" + boot);
      out("Tout est lisible, sans aucun mot de passe. Le mot de passe de session de Bob protège la session, pas le disque : ici, il n'a servi à rien.", "err");
      if (!x.sawClear) { x.sawClear = true; out("Pour un voleur, démonter le disque suffit. Chiffrons au moins le fichier sensible : `chiffrer fichier`.", "sys"); }
      return;
    }
    if (x.mode === "fichier") {
      code("Partition principale\n  /home/bob/Documents/registre-membres.txt.enc   [chiffré]   " + SECT.length * SW + " octets\n  /home/bob/Documents/salaires-2026.ods             [en clair]\n  /home/bob/.cache/~registre-membres.tmp           [en clair : copie temporaire de l'éditeur]\n  /var/swap (fichier d'échange)  fragment lu : \"...bob  cartographe        IBAN FR76 0000 0000...\"\n\nContenu de registre-membres.txt.enc :\n  " + sh(sha256("fichier"), 24) + " (bruit)\n\n" + boot);
      out("Le fichier est bien chiffré, mais le voleur sait qu'il existe, sa taille, et il lit sans effort la copie temporaire de l'éditeur et un fragment du fichier d'échange (swap). Le chiffrement par fichier laisse fuiter tout ce qu'il n'a pas pensé à couvrir.", "err");
      if (!x.sawFile) { x.sawFile = true; out("Il faut chiffrer tout le volume, pas seulement les fichiers qu'on a pensé à protéger : `chiffrer disque ‹phrase›`.", "sys"); }
      return;
    }
    if (x.wiped) {
      code("Entête du volume : (zone effacée, illisible)\nSecteurs 0 à 4 :\n" + SECT.map((s, i) => "  " + i + "  " + sh(diskHex(x, i), 36)).join("\n") + "\n\n" + boot);
      out("Les secteurs sont toujours là, mais sans entête il n'existe plus aucun moyen d'obtenir la clé de données, même avec la bonne phrase : c'est du bruit pour toujours.", "err");
      x.sawWipe = true; return;
    }
    const h = x.hdr;
    code("Entête du volume (lisible) : sel " + h.salt + "  itérations " + h.iter + "  DEK enveloppée " + sh(h.wrapped, 12) + (x.tpmOn ? "  + emplacement TPM" : "") + "\nAucun nom de fichier, aucune taille, aucun fragment de swap : tout est chiffré.\nSecteurs 0 à 4 :\n" + SECT.map((s, i) => "  " + i + "  " + sh(diskHex(x, i), 36)).join("\n") + "\n\n" + boot);
    out("Du bruit. Pas de nom de fichier, pas de copie temporaire : sans la clé de données, rien. Mais le voleur a l'entête : il peut essayer des phrases de passe à volonté (voir plus loin), et il connaît l'amorce non chiffrée.", "ok");
    if (!x.sawVol) { x.sawVol = true; note("complet"); fig("etats"); out("Le chiffrement du volume ne vaut que si la clé n'est pas à portée : vérifions comment le portable s'ouvre légitimement, avec `eteindre portable` puis `deverrouiller ‹phrase›`.", "sys"); }
  }

  /* ---------- commandes de l'atelier ---------- */
  function benchCmd() { if (S.room !== "atelier") { out("Le disque est sur le banc de l'atelier (nord du quai).", "sys"); return; } bench(); }

  function encrypt(c) {
    const x = F(), t = norm(c.rawArg), raw = c.rawArg;
    if (/^mosaique|^cadenas|^image/.test(t)) return mosaicCmd(t);
    if (/^sauvegarde/.test(t)) return backup({ rawArg: "chiffre", target: "chiffre" });
    if (S.room !== "atelier") { out("Le chiffrement du disque se règle à l'atelier (nord du quai). (Pour la mosaïque : salle des mosaïques ; pour la sauvegarde : archives.)", "sys"); return; }
    if (!x.quest) { out("Va d'abord voir Maître Ada.", "sys"); return; }
    if (/^fichier/.test(t)) {
      if (!x.sawClear) { say("Maître Ada", "Regarde d'abord ce que voit le voleur : `demonter disque`."); return; }
      if (x.mode !== "clair") { out("Le fichier est déjà chiffré.", "sys"); return; }
      x.mode = "fichier"; x.fileEnc = true;
      out("Tu chiffres registre-membres.txt avec une clé tirée d'une phrase. Le fichier devient du bruit. Mais le reste du disque ? `demonter disque` pour voir ce qu'un voleur en tire maintenant.", "ok");
      return;
    }
    if (/^disque|^volume/.test(t)) {
      const m = raw.match(/^(?:disque|volume)\s+(.+)$/i);
      if (!m) { out("`chiffrer disque ‹phrase de passe›`", "err"); return; }
      if (!x.sawFile) { say("Maître Ada", "Pas si vite : regarde d'abord pourquoi chiffrer un seul fichier ne suffit pas (`chiffrer fichier`, puis `demonter disque`)."); return; }
      if (x.vol) { out("Le volume est déjà chiffré. Pour changer la phrase : `changer phrase ‹nouvelle›`.", "sys"); return; }
      const p = m[1].trim();
      if (!CAND.includes(p.toLowerCase())) { say("Maître Ada", "Bob, lui, avait choisi un mot courant. Pour reproduire fidèlement le vol, prends une phrase comme la sienne : « soleil123 » (ou azerty, port443, motdepasse...). On renforcera ensuite."); return; }
      x.vol = true; x.mode = "volume"; x.phrase = p; x.pw = "on"; x.gen = 0; x.hdr = mkHdr(p, 1, 0); x.unlockOk = false;
      const h = x.hdr, kek = kdf(p, h.salt, h.iter);
      out("L'utilitaire génère une clé de données (DEK) aléatoire, la clé qui chiffrera tous les secteurs, puis l'enveloppe :", "ok");
      code("phrase de passe  « " + p + " »\n  ↓ dérivation (SHA-256 × " + h.iter + ", sel " + h.salt + ")\nKEK             " + sh(kek, 16) + "\n  ↓ DEK XOR KEK\nDEK enveloppée  " + sh(h.wrapped, 16) + "   (écrite dans l'entête)\nDEK             " + sh(DEK(0), 16) + "   (jamais écrite en clair)\nsecteur i = secteur ⊕ flux(DEK, i)   (tweak = numéro de secteur)");
      out("Le disque est entièrement chiffré. Le portable est allumé et déverrouillé : la DEK est en mémoire. `demonter disque` pour revoir la vue du voleur.", "sys");
      fig("cles");
      return;
    }
    out("Chiffrer quoi ? `chiffrer fichier` · `chiffrer disque ‹phrase›` · `chiffrer mosaique ecb|tweak` · `chiffrer sauvegarde`.", "err");
  }

  function mosaicCmd(t) {
    const x = F();
    if (S.room !== "mosaique") { out("La mosaïque est dans la salle des mosaïques (est du quai).", "sys"); return; }
    if (!x.vol) { say("Maître Ada", "Chiffre d'abord le volume du portable : cette salle expliquera ce qui se passe à l'intérieur."); return; }
    const mode = /ecb/.test(t) ? "ecb" : /tweak|xts|position|secteur|cbc/.test(t) ? "tweak" : null;
    if (!mode) { out("Quel mode ? `chiffrer mosaique ecb` ou `chiffrer mosaique tweak`.", "err"); return; }
    if (mode === "tweak" && !x.ecb) { say("Maître Ada", "Commence par le plus simple, le mode ECB, qui chiffre chaque bloc séparément."); return; }
    const cells = mosaic(mode), distinct = new Set(cells).size;
    out(mode === "ecb" ? "Chaque carreau (un octet) est chiffré indépendamment, avec la même clé : c(bloc) = bloc ⊕ k. Voici le résultat, chaque valeur étant dessinée par un symbole :" : "Même clé, mais chaque carreau est chiffré avec un tweak qui dépend de sa position p : c(bloc) = bloc ⊕ f(k, p). Voici le résultat :", "sys");
    code(grid(cells, v => GL[v % 16]));
    out("Ève, qui ne connaît pas la clé, compte : " + distinct + " valeur" + (distinct > 1 ? "s" : "") + " différente" + (distinct > 1 ? "s" : "") + " sur " + cells.length + " carreaux. Elle marque tout ce qui diffère de la valeur la plus fréquente :", "sys");
    code(eveGuess(cells));
    if (mode === "ecb") {
      say("Ève", "Un cadenas ! Je n'ai pas la clé, mais deux blocs identiques donnent deux chiffrés identiques : la forme est restée. Je ne lis pas les octets, je lis le motif.");
      out("C'est le défaut du mode ECB : il masque les valeurs, pas la structure. Le même défaut vaut pour des images, des tableaux, des en-têtes de fichiers répétés. Essaie le mode avec tweak : `chiffrer mosaique tweak`.", "err");
      x.ecb = true; fig("mosaique");
    } else {
      say("Ève", "Je ne vois plus rien : du bruit. Chaque carreau a l'air d'une valeur au hasard.");
      out("Avec un tweak, un même clair à deux endroits donne deux chiffrés différents : le motif disparaît. C'est l'esprit des modes pour disques (XTS) ; votre volume utilisait déjà le numéro de secteur comme tweak.", "ok");
      x.tw = true; note("modes"); fig("mosaique");
    }
  }

  function needVol(x, quiet) {
    if (!x.vol) { if (!quiet) out("Le disque n'est pas encore chiffré en volume : `chiffrer disque ‹phrase›`.", "sys"); return true; }
    return false;
  }

  function powerOff() {
    const x = F();
    if (S.room !== "atelier") { out("Le portable est à l'atelier (nord du quai).", "sys"); return; }
    if (x.pw === "off") { out("Il est déjà éteint.", "sys"); return; }
    x.pw = "off";
    out("Tu éteins complètement le portable. La mémoire se vide (en quelques secondes), la clé de données disparaît avec elle : le volume est verrouillé. Pour rouvrir : `deverrouiller ‹phrase›` (ou `demarrer`).", "ok");
  }
  function sleepCmd() {
    const x = F();
    if (S.room !== "atelier") { out("Le portable est à l'atelier (nord du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (x.pw === "off") { out("Il est éteint : rien à mettre en veille.", "sys"); return; }
    x.pw = "sleep";
    out("Tu fermes le capot : veille. L'écran est verrouillé, mais la mémoire reste alimentée... et la clé de données y est toujours, pour que le réveil soit instantané. (`deverrouiller` pour reprendre ; `eteindre portable` pour vraiment verrouiller.)", "sys");
  }

  function walk(h, p) {
    const r = tryPhrase(h, p);
    code("1. dérivation   SHA-256 × " + h.iter + " (sel " + h.salt + ")  →  KEK " + sh(r.kek, 12) + "\n2. déballage    DEK = enveloppe XOR KEK        →  " + sh(r.dek, 12) + "\n3. contrôle      empreinte(DEK) = " + chk(r.dek) + "   attendu : " + h.check + "   → " + (r.ok ? "identique" : "différent"));
    return r;
  }
  function unlock(c) {
    const x = F();
    if (S.room !== "atelier") { out("Le portable est à l'atelier (nord du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (x.wiped) { out("L'entête du volume a été détruit : il n'y a plus de clé à dériver, quelle que soit la phrase.", "err"); return; }
    if (x.pw !== "off") { out("Le volume est déjà ouvert : la clé de données est en mémoire. `eteindre portable` pour le verrouiller.", "sys"); return; }
    if (!c.rawArg) { out("`deverrouiller ‹phrase de passe›`", "err"); return; }
    const r = walk(x.hdr, c.rawArg.trim());
    if (r.ok) {
      x.pw = "on"; x.unlockOk = true;
      out("La clé obtenue ouvre l'enveloppe : la DEK est en mémoire, le volume est monté. Le système déchiffre les secteurs à la volée :", "ok");
      code(SECT.slice(0, 2).map((s, i) => "secteur " + i + " : " + decSect(diskHex(x, i), r.dek, i)).join("\n"));
    } else {
      out("Mauvaise phrase : une autre KEK donne une autre « DEK », dont l'empreinte ne correspond pas. L'entête refuse. Si on déchiffrait quand même, voici le secteur 0 :", "err");
      code(decSect(diskHex(x, 0), r.dek, 0));
      out("Du bruit, et aucune indication sur ce qui était faux dans la phrase.", "sys");
    }
  }

  function startCmd() {
    const x = F();
    if (S.room !== "atelier") { out("Le portable est à l'atelier (nord du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (x.wiped) { out("L'entête du volume a été détruit : le portable ne démarrera plus jamais sur ce disque.", "err"); return; }
    if (x.pw !== "off") { out("Il est déjà allumé. `eteindre portable` d'abord.", "sys"); return; }
    const boot = bootOf(), chain = pcrChain(boot);
    out("Mise sous tension : le microprogramme charge l'amorce depuis la partition /boot (non chiffrée).", "sys");
    if (x.tpmOn) {
      const exp = pcrOf(BOOT_OK), got = chain[2][1];
      code("mesures du TPM\n  microprogramme-v7   → " + sh(chain[0][1], 12) + "\n  amorce              → " + sh(chain[1][1], 12) + "\n  noyau-v6            → " + sh(got, 12) + "\nvaleur scellée (attendue) : " + sh(exp, 12));
      if (got !== exp) {
        out("Le TPM refuse de libérer la clé : les mesures ne sont pas celles de l'amorce d'origine. Aucun écran de saisie n'apparaît : tu es alerté AVANT d'avoir tapé quoi que ce soit.", "ok");
        if (!x.maidBlock) { x.maidBlock = true; x.tamper = false; note("tpm"); fig("menaces"); }
        say("Maître Ada", "Bien vu. Nous rétablissons l'amorce d'origine et nous cherchons qui a touché à la machine. Sans le TPM, tu aurais tapé ta phrase dans un faux écran.");
        x.tamper = false; return;
      }
      out("Les mesures sont celles attendues : le TPM demande le PIN (3 essais avant blocage), puis libère la clé scellée. Pas de phrase à taper.", "ok");
      x.pw = "on"; return;
    }
    if (x.tamper) {
      out("Écran de saisie de la phrase de passe... qui ressemble trait pour trait à l'original. Tu tapes ta phrase.", "sys");
      code("[amorce piégée, journal caché]\nphrase saisie : « " + x.phrase + " »");
      x.maidWin = true; x.tamper = false; x.pw = "on";
      say("Mallory", "Merci pour la phrase. Je repasse chercher le portable ce soir, et je n'aurai même plus besoin de deviner.");
      const r = tryPhrase(x.hdr, x.phrase);
      out("Mallory revient avec le portable éteint et le disque : elle a la phrase, donc la KEK, donc la DEK.", "err");
      code(SECT.slice(0, 3).map((s, i) => "secteur " + i + " : " + decSect(diskHex(x, i), r.dek, i)).join("\n"));
      out("Le chiffrement n'a pas été « cassé » : l'attaque a visé la seule partie non chiffrée, l'amorce, qui sert à demander la phrase. (Ada remet l'amorce d'origine.)", "err");
      note("menaces"); fig("menaces");
      return;
    }
    out("Amorce d'origine. Écran de saisie de la phrase de passe : tu tapes ta phrase, le volume s'ouvre.", "ok");
    x.pw = "on";
  }

  function changePhrase(c) {
    const x = F();
    if (S.room !== "atelier") { out("La phrase se change à l'atelier (nord du quai).", "sys"); return; }
    const m = c.rawArg.match(/^phrase\s+(.+)$/i);
    if (!m) { out("`changer phrase ‹nouvelle phrase de passe›`", "err"); return; }
    if (needVol(x)) return;
    if (x.wiped) { out("L'entête a été détruit.", "err"); return; }
    if (x.pw === "off") { out("Le volume est verrouillé : on ne peut réécrire l'enveloppe qu'avec la clé de données en mémoire. `deverrouiller ‹phrase›` d'abord.", "sys"); return; }
    const p = m[1].trim();
    if (!x.seenSlow && !CAND.includes(p.toLowerCase())) { say("Maître Ada", "Excellent réflexe, mais attends : il faut d'abord montrer à Mallory ce qu'une phrase courante vaut. Garde un mot courant pour l'instant : port443, azerty, motdepasse..."); return; }
    const old = x.hdr, before = diskHex(x, 0), t0 = performance.now();
    x.hdr = mkHdr(p, old.iter, old.gen); x.phrase = p;
    const ms = Math.max(1, Math.round(performance.now() - t0));
    out("Tu tapes la nouvelle phrase. La DEK est déjà en mémoire : seule l'enveloppe change.", "ok");
    code("ancienne enveloppe  " + sh(old.wrapped, 16) + "  (sel " + old.salt + ")\nnouvelle enveloppe  " + sh(x.hdr.wrapped, 16) + "  (sel " + x.hdr.salt + ")\nsecteur 0 avant     " + sh(before, 20) + "\nsecteur 0 après     " + sh(diskHex(x, 0), 20) + "\nsecteurs ré-écrits : 0   ·   enveloppes réécrites : 1   (" + ms + " ms)");
    out("La DEK n'a pas changé, donc tout le volume est resté tel quel : changer la phrase se fait en un instant, même sur 2 To. (Attention : un voleur qui avait copié l'ancien disque garde l'ancienne enveloppe : changer la phrase n'efface pas ce qu'il possède déjà.)", "sys");
    if (!weak(p)) { x.pwStrong = true; out("Phrase longue et imprévisible : voyons si Mallory s'en sort (`attaquer phrase` dans l'antre).", "sys"); }
    if (!x.rewrap) { x.rewrap = true; note("cles"); }
    fig("cles");
  }

  function rekey() {
    const x = F();
    if (S.room !== "atelier") { out("Le disque est à l'atelier (nord du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (x.pw === "off") { out("Déverrouille d'abord (`deverrouiller ‹phrase›`).", "sys"); return; }
    if (x.wiped) { out("L'entête a été détruit.", "err"); return; }
    const gen = x.hdr.gen + 1, before = diskHex(x, 0);
    x.hdr = mkHdr(x.phrase, x.hdr.iter, gen);
    out("Changer la DEK elle-même : il faut lire, déchiffrer avec l'ancienne clé, rechiffrer avec la nouvelle et réécrire CHAQUE secteur.", "ok");
    code("secteur 0 avant  " + sh(before, 20) + "\nsecteur 0 après  " + sh(diskHex(x, 0), 20) + "\nsecteurs ré-écrits : 5 dans ce jeu... et environ 1 000 000 000 sur un disque de 500 Go (des heures)");
    out("Voilà pourquoi on distingue KEK et DEK : changer la phrase coûte un instant ; changer la DEK, des heures. On ne le fait qu'en cas de fuite de la DEK elle-même.", "sys");
  }

  function setKdf(c) {
    const x = F();
    if (!/kdf|derivation|lent/.test(norm(c.rawArg))) { out("`regler kdf lent` règle la dérivation de clé.", "err"); return; }
    if (S.room !== "atelier") { out("Le réglage se fait à l'atelier (nord du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (!x.seenFast) { say("Maître Ada", "Voyons d'abord pourquoi : retourne voir Mallory (`attaquer phrase`), puis reviens."); return; }
    if (x.slowSet) { out("La dérivation est déjà lente.", "sys"); return; }
    if (x.pw === "off") { out("Déverrouille d'abord le volume (`deverrouiller ‹phrase›`).", "sys"); return; }
    x.hdr = mkHdr(x.phrase, ITER, x.hdr.gen); x.slowSet = true;
    out("Tu passes de 1 à " + ITER + " itérations : la KEK est maintenant le résultat de " + ITER + " hachages enchaînés. Pour toi, un déverrouillage prend une fraction de seconde de plus ; pour Mallory, qui doit en faire des milliards, c'est un mur. (En vrai : PBKDF2 avec des centaines de milliers d'itérations, ou Argon2id gourmand en mémoire.)", "ok");
    fig("cles");
  }

  function setTpm(c) {
    const x = F();
    if (!/tpm|module|puce/.test(norm(c.rawArg))) { out("`activer tpm ‹PIN de 4 à 8 chiffres›`", "err"); return; }
    if (S.room !== "atelier") { out("Le TPM est à l'atelier (nord du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (!x.maidWin) { say("Maître Ada", "Voyons d'abord ce qu'il se passe quand le portable dort dans une chambre d'hôtel : `eteindre portable`, puis à l'antre `trafiquer amorce`, puis `demarrer`."); return; }
    if (x.tpmOn) { out("Le TPM est déjà configuré.", "sys"); return; }
    const m = c.rawArg.match(/\b(\d{4,8})\b/);
    if (!m) { out("Choisis un PIN de 4 à 8 chiffres : `activer tpm 4821`.", "err"); return; }
    const chain = pcrChain(BOOT_OK);
    x.tpmOn = true; x.pin = m[1];
    out("Le TPM mesure le démarrage, étape par étape (chaque mesure est hachée avec la précédente), puis scelle une copie de la DEK : elle ne sortira que si les mesures sont celles-ci ET si le PIN est correct.", "ok");
    code(chain.map(([n, p]) => n.padEnd(34) + sh(p, 12)).join("\n") + "\nPIN : " + "*".repeat(m[1].length) + "  (3 essais avant blocage)");
    out("L'amorce reste non chiffrée, mais plus personne ne peut la modifier sans que ça se voie. Le démarrage sécurisé (Secure Boot) y ajoute une vérification de signature.", "sys");
    fig("etats");
  }

  /* ---------- l'antre de Mallory ---------- */
  function attackCmd(c) {
    const x = F();
    if (S.room !== "cave") { out("Mallory est dans son antre (sud du quai).", "sys"); return; }
    if (!/phrase|mot|passe|devin/.test(norm(c.rawArg) + " phrase")) { out("`attaquer phrase`", "err"); return; }
    if (needVol(x)) return;
    if (x.wiped) { out("Mallory : « L'entête est détruit : je n'ai plus rien à attaquer. »", "err"); return; }
    const h = x.hdr;
    out("Mallory copie l'entête (sel " + h.salt + ", " + h.iter + " itération" + (h.iter > 1 ? "s" : "") + ") et essaie, hors ligne, son dictionnaire de " + CAND.length + " candidates (mots courants et variantes « mot1 », « mot123 »). Chaque candidate = une dérivation de clé + un déballage + un contrôle :", "sys");
    const t0 = performance.now(); let tries = 0, found = null;
    for (const w of CAND) { tries++; if (tryPhrase(h, w).ok) { found = w; break; } }
    const ms = Math.max(1, Math.round(performance.now() - t0));
    const nb = h.iter > 1 ? 3 : 300, b0 = performance.now();
    for (let i = 0; i < nb; i++) tryPhrase(h, "essai" + i);
    const rate = Math.max(1, Math.round(nb / Math.max(0.001, (performance.now() - b0) / 1000)));
    if (found) {
      out("Trouvé en " + tries + " essai" + (tries > 1 ? "s" : "") + " (" + ms + " ms) : « " + found + " ». Elle a la KEK, donc la DEK : tout le disque est lisible.", "err");
      code(SECT.slice(0, 2).map((s, i) => "secteur " + i + " : " + decSect(diskHex(x, i), tryPhrase(h, found).dek, i)).join("\n"));
    } else if (!weak(x.phrase)) {
      out(tries + " candidates essayées (" + ms + " ms) : aucune ne fonctionne. La phrase de passe est longue et ne figure dans aucune liste.", "ok");
    } else out(tries + " candidates essayées : aucune ne fonctionne. Cette fois (la liste est minuscule), mais une phrase si courte reste à la portée d'un attaquant sérieux.", "sys");
    out("Rythme mesuré dans ton navigateur : environ " + rate.toLocaleString("fr-FR") + " essais par seconde" + (h.iter > 1 ? " (dérivation lente)." : " (dérivation rapide : SHA-256 seul). Un GPU en fait des milliards.") , "sys");
    if (h.iter === 1) { if (!x.seenFast) x.rateFast = rate; x.seenFast = true; if (found) out("Aucune alerte, aucune limite d'essais : l'entête est entre ses mains. Il faut rendre chaque essai coûteux : à l'atelier, `regler kdf lent`.", "sys"); }
    else {
      if (found && !x.seenSlow) {
        x.rateSlow = rate; x.seenSlow = true; note("kdf");
        out("Même phrase, même résultat... mais chaque essai coûte environ " + Math.round((x.rateFast || rate * ITER) / rate).toLocaleString("fr-FR") + " fois plus cher qu'avant. Cela fait gagner du temps, pas de la sécurité : une phrase courante tombe toujours. Il faut une phrase longue : à l'atelier, `changer phrase ‹phrase d'au moins 16 caractères›`.", "err");
        fig("cles");
      }
      if (!found && !weak(x.phrase)) { if (!x.blocked) { x.blocked = true; note("menaces"); fig("menaces"); } out("Phrase longue + dérivation lente : à ce rythme, l'attaque par dictionnaire sort du possible. Mais Mallory a d'autres idées : une machine allumée ? `capturer memoire`.", "ok"); }
    }
    if (!found && !weak(x.phrase) && h.iter === 1 && !x.blocked) x.blocked = true;
  }

  function memCmd() {
    const x = F();
    if (S.room !== "cave") { out("Mallory est dans son antre (sud du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (x.wiped) { out("L'entête est détruit : même la mémoire ne contiendrait plus de quoi remonter au volume.", "err"); return; }
    if (!x.blocked) { say("Mallory", "Je finis d'abord avec la phrase de passe (`attaquer phrase`)."); return; }
    const inRam = x.pw !== "off", dek = DEK(x.hdr.gen);
    out("Mallory se saisit du portable " + (x.pw === "sleep" ? "en veille" : x.pw === "on" ? "allumé (écran verrouillé)" : "éteint") + " et lit la mémoire vive (en vrai : un démarrage à froid sur une clé USB, ou une bombe d'air froid pour que les bits s'effacent plus lentement). Elle cherche chaque suite de 32 octets dont l'empreinte de contrôle correspond à celle de l'entête :", "sys");
    const lines = []; for (let i = 0; i < 12; i++) lines.push(sha256("ram:" + i).slice(0, 32));
    if (inRam) lines[7] = dek;
    let hit = -1; lines.forEach((l, i) => { if (hit < 0 && chk(l) === x.hdr.check) hit = i; });
    code(lines.map((l, i) => "0x" + (i * 16).toString(16).padStart(4, "0") + "  " + l + (i === hit ? "   <== empreinte de contrôle identique" : "")).join("\n"));
    if (hit >= 0) {
      out("Trouvé : la clé de données est là, en clair, en mémoire. Mallory n'a eu besoin ni de la phrase ni de casser quoi que ce soit : elle déchiffre le disque directement. (Le TPM n'y change rien : la clé a été libérée pour le système.)", "err");
      code(SECT.slice(0, 2).map((s, i) => "secteur " + i + " : " + decSect(diskHex(x, i), lines[hit], i)).join("\n"));
      if (!x.memHit) { x.memHit = true; note("memoire"); }
      out("Remède : éteindre vraiment le portable (`eteindre portable` à l'atelier) avant de le laisser sans surveillance, puis refais cette capture.", "sys");
    } else {
      out("Rien : la mémoire ne contient plus que du bruit. Une machine éteinte depuis plus de quelques secondes (la remanence de la mémoire s'efface vite à température ambiante) n'a plus de clé en mémoire. Mallory se retrouve avec un disque chiffré et une phrase longue.", "ok");
      if (x.memHit && !x.memBlock) { x.memBlock = true; fig("menaces"); }
    }
  }

  function maidCmd(c) {
    const x = F();
    if (!/amorce|boot|demarrage/.test(norm(c.rawArg))) { out("`trafiquer amorce`", "err"); return; }
    if (S.room !== "cave") { out("Mallory opère depuis son antre (sud du quai).", "sys"); return; }
    if (needVol(x)) return;
    if (!x.memBlock) { say("Mallory", "Une chose à la fois : la mémoire d'abord (`capturer memoire`)."); return; }
    if (x.pw !== "off") { out("Mallory : « Cette attaque se joue sur un portable ÉTEINT, laissé seul dans une chambre d'hôtel : éteins-le d'abord (atelier). »", "sys"); return; }
    if (x.tamper) { out("L'amorce est déjà trafiquée : il ne reste plus qu'à attendre que la victime rallume (`demarrer` à l'atelier).", "sys"); return; }
    x.tamper = true;
    out("La « femme de chambre » (evil maid) entre dans la chambre, démarre le portable sur une clé USB (2 minutes), et remplace amorce.bin dans la partition /boot, qui n'est pas chiffrée. Le nouveau programme affiche un faux écran de saisie de phrase, identique à l'original.", "sys");
    code("amorce.bin avant : sha256 " + sh(sha256(BOOT_OK), 16) + "\namorce.bin après : sha256 " + sh(sha256(BOOT_BAD), 16));
    out("Elle repart. Le disque est resté chiffré, rien n'a été cassé. À l'atelier : `demarrer`, comme le ferait la victime au réveil.", "sys");
  }

  /* ---------- archives et sauvegardes ---------- */
  function backup(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "archives") { out("Les sauvegardes se règlent aux archives (ouest du quai).", "sys"); return; }
    if (!x.quest || !x.blocked) { say("Maître Ada", "Finissons d'abord le portable : phrase, mémoire, amorce. Les sauvegardes viennent après."); return; }
    if (!x.maidBlock) { say("Maître Ada", "Finissons d'abord le portable : il reste l'amorce et le TPM."); return; }
    if (/clair/.test(t)) {
      if (x.bk) { out("Une sauvegarde est déjà déposée sur le serveur.", "sys"); return; }
      x.bk = "clair"; x.bkClear = true;
      out("Tu envoies les registres à l'hébergeur par un canal chiffré (TLS), qui les stocke tels quels. Le transport est sûr, le stockage... c'est lui qui décide. `ecouter serveur` pour demander à Ève ce qu'elle voit.", "ok");
    } else if (/chiffr/.test(t)) {
      if (!x.eveClear) { say("Maître Ada", "D'abord, mesure ce que voit l'hébergeur d'une sauvegarde en clair : `sauvegarder clair`, puis `ecouter serveur`."); return; }
      if (x.bk === "chiffre") { out("La sauvegarde est déjà chiffrée côté client.", "sys"); return; }
      x.bk = "chiffre"; x.bkEnc = true; x.keyAt = "serveur";
      out("Tu chiffres l'archive sur le portable, côté client, avec une clé de sauvegarde BK. Pour que « ce soit pratique », l'outil de Bob dépose BK dans un fichier key.txt, à côté de l'archive, sur le serveur.", "ok");
      code("archive.enc    " + ARCH.map(a => sh(a, 6)).join(" ") + "\nkey.txt        " + sh(BK, 12));
      out("Le serveur ne reçoit plus que du chiffré... avec la clé à côté. `ecouter serveur`.", "sys");
    } else out("`sauvegarder clair` ou `sauvegarder chiffre`.", "err");
    fig("sauvegarde");
  }

  function listenCmd() {
    const x = F();
    if (S.room !== "archives") { out("Ève est aux archives (ouest du quai).", "sys"); return; }
    if (!x.bk) { say("Ève", "Il n'y a encore rien sur mon serveur."); return; }
    if (x.bk === "clair") {
      say("Ève", "Je lis ce que tu as déposé, sans effort. Regarde.");
      code(SECT.join("\n"));
      out("L'hébergeur (ou quiconque le compromet, ou une saisie, ou une erreur de configuration) voit tout. Le chiffrement en transit protège le trajet, pas le stockage. Passons au chiffrement côté client : `sauvegarder chiffre`.", "err");
      x.eveClear = true; fig("sauvegarde"); return;
    }
    const files = [["archive.enc", ARCH.join("")]];
    if (x.keyAt === "serveur") files.push(["key.txt", BK]);
    if (x.slot) files.push(["recuperation.slot", xorHex(BK, rkKey(RK))]);
    out("Ève passe en revue chaque fichier du serveur : pour chaque suite de 32 caractères hexadécimaux, elle calcule l'empreinte de contrôle de l'archive et compare.", "sys");
    let key = null;
    for (const [n, body] of files) {
      const cands = n === "archive.enc" ? [] : body.match(/[0-9a-f]{32}/g) || [];
      cands.forEach(cd => { if (!key && chk(cd) === BKCHK) key = cd; });
    }
    code(files.map(([n, b]) => n.padEnd(20) + sh(b, 20)).join("\n"));
    if (key) {
      say("Ève", "key.txt, juste à côté de l'archive : un cadenas avec la clé collée dessus.");
      code(SECT.slice(0, 3).map((s, i) => "secteur " + i + " : " + decSect(ARCH[i], key, i + 100)).join("\n"));
      out("Chiffrer ne sert à rien si la clé vit à côté des données : l'hébergeur lit tout. La clé doit rester ailleurs : sur le portable de Bob (`ranger cle portable`).", "err");
      x.eveKey = true;
    } else {
      say("Ève", "Je n'ai que de l'archive chiffrée et un petit fichier d'enveloppe qui ne m'ouvre rien. Rien de lisible.");
      out("Ève n'a ni la clé, ni de moyen de la retrouver : l'archive reste du bruit pour elle (et pour quiconque pirate le serveur).", "ok");
      if (!x.eveBlock) { x.eveBlock = true; out("La clé doit donc vivre ailleurs que les données. Mais... et si cet « ailleurs » disparaissait ?", "sys"); }
    }
    fig("sauvegarde");
  }

  function storeCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "archives") { out("Les clés se rangent aux archives (ouest du quai).", "sys"); return; }
    if (/recuperation|recup|rk/.test(t)) {
      if (!x.rkGen) { out("Tu n'as pas de clé de récupération.", "sys"); return; }
      if (!/coffre/.test(t)) { out("`ranger cle recuperation coffre`", "err"); return; }
      return rkSafe();
    }
    if (!x.bkEnc) { say("Maître Ada", "Il n'y a pas encore de clé de sauvegarde à ranger."); return; }
    if (/coffre/.test(t)) { say("Maître Ada", "Le coffre est réservé à la clé de récupération (séquestre). La clé de tous les jours vit sur le portable de l'utilisateur."); return; }
    if (/portable|poste|bob/.test(t)) {
      if (x.keyAt === "portable") { out("La clé est déjà sur le portable de Bob.", "sys"); return; }
      x.keyAt = "portable";
      out("Tu déplaces la clé BK dans le trousseau du portable de Bob (lui-même protégé par le chiffrement du volume) et tu effaces key.txt du serveur. `ecouter serveur` pour vérifier qu'Ève est bloquée.", "ok");
      fig("sauvegarde"); return;
    }
    if (/serveur/.test(t)) { out("Au même endroit que les données ? Précisément ce qu'il ne faut pas faire.", "err"); return; }
    out("`ranger cle portable` (clé de tous les jours) ou `ranger cle recuperation coffre`.", "err");
  }
  function rkSafe() {
    const x = F();
    if (x.rkState === "coffre") { out("La clé de récupération est déjà dans le coffre.", "sys"); return; }
    x.rkState = "coffre"; drop("rk");
    out("Tu ranges la feuille dans le coffre de la Guilde : hors du serveur, hors du portable. (En vrai : deux moitiés, confiées à deux personnes différentes, pour que nul n'ait seul la clé, et que nul ne la perde seul.)", "ok");
    fig("sauvegarde");
  }

  function genRk() {
    const x = F();
    if (S.room !== "archives") { out("Cela se prépare aux archives (ouest du quai).", "sys"); return; }
    if (!x.lost) { say("Maître Ada", "Constate d'abord le problème : `restaurer sauvegarde`."); return; }
    if (x.rkGen) { out("La clé de récupération existe déjà.", "sys"); return; }
    x.rkGen = true; x.slot = true; x.rkState = "poche"; give("rk");
    out("Tu génères une clé de récupération aléatoire et tu enveloppes la clé de sauvegarde sous elle : un deuxième emplacement de clé, déposé sur le serveur (sans danger : il n'ouvre rien sans la clé de récupération).", "ok");
    code(RK + "\nrecuperation.slot = BK XOR f(RK) = " + sh(xorHex(BK, rkKey(RK)), 16));
    out("Cette feuille est maintenant dans ta poche : si tu la perds avec le portable, on retombe dans le même piège. Range-la : `ranger cle recuperation coffre`.", "sys");
    fig("sauvegarde");
  }

  function restoreCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "archives") { out("La restauration se fait aux archives (ouest du quai).", "sys"); return; }
    if (x.bk !== "chiffre") { out("Il n'y a pas de sauvegarde chiffrée à restaurer.", "sys"); return; }
    const code0 = c.rawArg.replace(/^sauvegarde\s*/i, "").trim();
    if (x.rkState === "detruite" && x.wiped) {
      if (!x.proof) { x.proof = true; note("crypto"); }
      out("Tu essaies tous les moyens de restaurer l'archive :", "sys");
      code("clé de tous les jours   : sur le disque dont l'entête est détruit → introuvable\nclé de récupération    : feuille brûlée, emplacement du serveur supprimé\narchive.enc            : toujours là, sur le serveur, sur la bande, chez Ève");
      out("Les copies de l'archive existent toujours : des octets partout. Mais plus aucune copie de la clé : tout est du bruit pour toujours. C'est ça, l'effacement cryptographique.", "ok");
      fig("sauvegarde"); return;
    }
    if (x.keyAt !== "portable") { say("Maître Ada", "La clé est encore à côté des données : sépare-la d'abord (`ranger cle portable`)."); return; }
    if (!code0) {
      if (!x.rkGen) {
        x.lost = true;
        out("Bob demande la restauration de la sauvegarde. Mais la clé BK vivait sur son portable... qui est dans les mains du voleur.", "sys");
        out("Impossible. Il n'existe aucune porte dérobée : l'hébergeur ne peut pas t'aider (il n'a jamais eu la clé), et personne ne peut deviner une clé de 128 bits. Les données sont perdues POUR TOUJOURS.", "err");
        say("Maître Ada", "Voilà le prix du chiffrement côté client. Il faut un séquestre : une clé de récupération, gardée à part. Génère-la : `generer cle recuperation`.");
        fig("sauvegarde"); return;
      }
      out("`restaurer sauvegarde ‹clé de récupération›` : le code est sur la feuille du coffre (`examiner coffre`).", "err"); return;
    }
    if (!x.rkGen) { out("Il n'existe pas de clé de récupération.", "err"); return; }
    if (x.rkState === "poche") { say("Maître Ada", "Cette clé est encore dans ta poche : si ta poche disparaît, le séquestre aussi. Range-la d'abord dans le coffre."); return; }
    if (x.rkState === "detruite") { out("La clé de récupération a été détruite.", "err"); return; }
    const kk = xorHex(x.slot ? xorHex(BK, rkKey(RK)) : "00".repeat(16), rkKey(code0));
    if (rkNorm(code0) !== rkNorm(RK) || chk(kk) !== BKCHK) {
      out("Le code ne correspond pas : la clé dérivée donne une BK dont l'empreinte de contrôle est fausse. Aucune indication sur la part juste (et avec 2^80 possibilités, personne ne devine : une vraie clé de récupération en compte 2^128 ou plus). Relis la feuille du coffre : `examiner coffre`.", "err"); return;
    }
    out("La clé de récupération est correcte : tu déballes BK depuis recuperation.slot, puis tu déchiffres l'archive :", "ok");
    code(SECT.slice(0, 3).map((s, i) => "secteur " + i + " : " + decSect(ARCH[i], kk, i + 100)).join("\n"));
    if (!x.restored) {
      x.restored = true; note("sauvegarde");
      say("Maître Ada", "Voilà un séquestre qui a fait son travail : c'est le seul moyen de rouvrir les sauvegardes quand la clé de tous les jours est perdue. Et c'est aussi le talon d'Achille : celui qui détient le coffre détient tout. Il faut donc le protéger comme le reste.");
      say("Maître Ada", "Dernier chapitre. Alice, membre de la Guilde, nous demande d'effacer toutes ses données de nos archives. Or elles existent en copies : le serveur, la bande hors site, le miroir d'Ève, le disque du portable volé. Impossible de toutes les atteindre... mais toutes sont chiffrées : détruis les clés. `detruire cle disque` puis `detruire cle recuperation`.");
    }
    fig("sauvegarde");
  }

  function destroyCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!x.restored) { say("Maître Ada", "Pas encore : on n'efface une clé qu'une fois qu'on sait restaurer ce qui doit l'être."); return; }
    if (/disque|volume|portable|entete/.test(t)) {
      if (x.wiped) { out("L'entête est déjà détruit.", "sys"); return; }
      x.wiped = true;
      out("Commande d'effacement envoyée au portable perdu (en vrai : gestion de parc, dès qu'il se connecte), qui réécrit les quelques dizaines d'octets de l'entête. Les 500 Go de secteurs chiffrés sont toujours là, mais la DEK n'existe plus nulle part :", "ok");
      code("entête (sel, DEK enveloppée, emplacement TPM) : zone écrasée\nsecteurs chiffrés : 500 Go intacts... illisibles");
      out("Réécrire 500 Go sur un SSD est lent et peu fiable (les cellules sont réaffectées en cachette, des copies subsistent). Détruire la clé, un geste de quelques octets, est plus sûr et instantané. Et la clé de récupération ? `detruire cle recuperation`.", "sys");
      if (x.rkState !== "detruite") fig("cles");
    } else if (/recup|rk|coffre|sauvegarde/.test(t)) {
      if (x.rkState === "detruite") { out("La clé de récupération est déjà détruite.", "sys"); return; }
      if (x.rkState !== "coffre") { out("Il n'y a pas de clé de récupération dans le coffre.", "sys"); return; }
      x.rkState = "detruite"; x.slot = false;
      out("Tu brûles la feuille du coffre et tu supprimes recuperation.slot du serveur : plus aucune copie de la clé de récupération.", "ok");
    } else { out("Quelle clé ? `detruire cle disque` ou `detruire cle recuperation`.", "err"); return; }
    if (x.wiped && x.rkState === "detruite") {
      out("Toutes les copies de la clé sont détruites. Vérifie qu'on ne peut plus rien restaurer : `restaurer sauvegarde ‹n'importe quel code›` (aux archives).", "sys");
    }
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Le portable de Bob est toujours dans la nature, et c'est sans importance : disque chiffré en volume, phrase longue, dérivation lente, amorce mesurée, clés de sauvegarde séparées des données, séquestre testé, puis clé détruite. Voleur, Mallory n'a rien tiré du disque ; curieuse, Ève n'a rien lu ; et Alice peut dormir tranquille, ses données ont disparu.");
    say("Maître Ada", "Retiens l'essentiel : on ne protège pas des données, on protège des CLÉS, et l'on choisit à chaque étape qui a le droit de les voir.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le portable volé et le disque démonté = un disque dont l'attaquant a la possession physique.** Un mot de passe de session ne protège rien : le disque se lit sans le système. Seul le chiffrement du volume complet (BitLocker, FileVault, LUKS) rend le contenu illisible, y compris noms, tailles, copies temporaires et swap, que le chiffrement de fichiers laisse fuiter.");
    out("**La phrase de passe, la KEK et la DEK.** La phrase passe par une dérivation de clé (KDF) qui produit une clé d'enveloppe (KEK). La KEK ouvre la clé de données (DEK), stockée enveloppée dans l'entête. Changer la phrase = ré-envelopper la DEK, instantané ; changer la DEK = tout re-chiffrer. Le même principe permet plusieurs emplacements de clé (phrase, récupération, TPM).");
    out("**Le moulin lent = PBKDF2, scrypt, Argon2.** Ici 3 000 hachages SHA-256 enchaînés. Il multiplie le coût de chaque essai de l'attaquant, qui a l'entête et peut essayer sans limite, hors ligne. Mais seule une phrase longue et imprévisible sort l'attaque du possible : la lenteur n'a jamais sauvé « soleil123 ».");
    out("**La mosaïque du cadenas = le mode de chiffrement.** En ECB, blocs identiques → chiffrés identiques : la forme du clair reste visible, même sans la clé. Les modes à tweak (XTS pour les disques, avec le numéro de secteur et la position dans le secteur) font dépendre le chiffré de l'emplacement. L'algorithme (AES) peut être excellent et le résultat catastrophique si le mode est mauvais.");
    out("**Mallory et ses trois attaques.** (1) Phrase faible devinée hors ligne depuis l'entête. (2) Portable allumé ou en veille : la DEK est en mémoire, extractible (cold boot, accès direct à la mémoire) ; parade : éteindre vraiment. (3) La femme de chambre (evil maid) : on trafique l'amorce non chiffrée pour récupérer la phrase ; parade : démarrage mesuré et sécurisé, TPM qui ne libère la clé que si l'amorce est celle d'origine, plus un PIN.");
    out("**Ève et le serveur de sauvegarde = un tiers qui stocke.** Le chiffrement en transit (TLS) ne protège pas le stockage. On chiffre côté client, avec une clé gardée loin des données (key.txt à côté de l'archive annulait tout). Mais une clé unique perdue = données perdues pour toujours : on prévoit une clé de récupération (séquestre), à part, répartie, et testée.");
    out("**Brûler la feuille = l'effacement cryptographique (crypto-shredding).** Détruire toutes les copies de la clé rend illisibles toutes les copies des données, partout (bandes, miroirs, SSD qui réaffectent des cellules), sans les chercher une à une. Il suppose que NULLE copie de la clé ne survit (récupération comprise).");
    out("**Les simplifications du jeu.** (1) Le « chiffrement par blocs » est un XOR avec un flux dérivé de SHA-256 : pédagogique, pas sûr, et non authentifié (en vrai AES-XTS ou AES-GCM, et XTS ne détecte pas qu'on a modifié un bloc). (2) La mosaïque chiffre des blocs d'un octet pour rendre visible ce qui se passe avec des blocs de 16 octets. (3) Le « hachage lent » est une simple répétition de SHA-256 ; en vrai, Argon2id ou scrypt, gourmands en mémoire. (4) La capture de mémoire est résumée en une recherche par empreinte de contrôle ; le vrai démarrage à froid dépend de matériel et de températures. (5) Le TPM, Secure Boot, le PIN et les PCR sont très simplifiés (et non résumés ici : l'attaque DMA, le bus TPM sondé, les clés dans le microprogramme). (6) La clé de récupération est une feuille ; en vrai, partage de secret entre plusieurs personnes. (7) L'effacement distant suppose que l'appareil se connecte : sinon, c'est la destruction de toutes les copies de la clé qui compte. (8) Tout se passe sur des données fictives et à l'abri : aucun outil réel.");
    out("Rappel utile : **chiffre tout le volume, protège la clé plus que les données, éteins vraiment la machine, sépare clés et données, prévois un séquestre testé... et sache que détruire la clé détruit les données.**", "ok");
  }

  /* ---------- schémas ---------- */
  const mark = ok => (ok ? "✔" : "✗");
  const figs = {
    etats: () => {
      const x = F(), cur = x.mode === "volume" ? (x.tpmOn ? 3 : 2) : x.mode === "fichier" ? 1 : 0;
      const cols = ["aucun", "fichier", "volume", "vol.+TPM"], cx = [172, 240, 308, 376];
      const rows = [["contenu des registres", [0, 1, 1, 1]], ["noms, tailles de fichiers", [0, 0, 1, 1]], ["copies temp., swap", [0, 0, 1, 1]], ["amorce piégée (evil maid)", [0, 0, 0, 1]], ["portable allumé / veille", [0, 0, 0, 0]]];
      let b = R(138 + cur * 68, 22, 68, 24 + rows.length * 28, "f-pub");
      cols.forEach((n, i) => { b += T(cx[i], 38, n, "f-s"); });
      rows.forEach(([n, v], r) => { b += T(8, 66 + r * 28, n, "f-s", "start"); v.forEach((ok, i) => { b += T(cx[i], 66 + r * 28, mark(ok), "f-b " + (ok ? "ft-ok" : "ft-bad")); }); });
      b += T(8, 18, "ce que le voleur obtient quand le disque est…", "f-s", "start");
      b += T(210, 66 + rows.length * 28 + 6, "✔ = protégé   ✗ = exposé   (colonne encadrée = ton état)", "f-s");
      return { cap: "Un disque non chiffré se lit tout seul ; le chiffrement de fichier laisse fuiter le reste ; le chiffrement de volume protège un disque éteint ; le TPM ferme la porte à l'amorce piégée. Aucun ne protège une machine allumée.", svg: SVG(66 + rows.length * 28 + 20, "États d'un disque volé selon la protection", b) };
    },
    cles: () => {
      const x = F(), h = x.hdr || { salt: "?", iter: 1, wrapped: "00000000", check: "?", gen: 0 };
      const ph = x.phrase ? (x.phrase.length > 20 ? x.phrase.slice(0, 18) + "…" : x.phrase) : "?";
      const kek = x.phrase ? kdf(x.phrase, h.salt, h.iter) : "0";
      const open = x.pw !== "off";
      let b = "";
      b += R(8, 8, 196, 38, "f-priv") + T(106, 24, "phrase de passe", "f-b") + T(106, 39, "« " + ph + " »", "f-s");
      b += AR(106, 46, 106, 62);
      b += R(8, 62, 196, 38) + T(106, 78, h.iter > 1 ? "dérivation lente (KDF)" : "dérivation rapide (1 hachage)", "f-b") + T(106, 93, "SHA-256 × " + h.iter + ", sel " + h.salt, "f-s");
      b += AR(106, 100, 106, 116);
      b += R(8, 116, 196, 38, "f-pub") + T(106, 132, "KEK : clé d'enveloppe", "f-b ft-pub") + T(106, 147, sh(kek, 10), "f-s");
      b += AR(106, 154, 106, 170);
      b += R(8, 170, 196, 38, x.wiped ? "f-bad" : open ? "f-bad" : "f-ok") + T(106, 186, "DEK : clé de données", "f-b") + T(106, 201, x.wiped ? "perdue pour toujours" : open ? "en mémoire (volume ouvert)" : "absente de la mémoire", "f-s " + (open && !x.wiped ? "ft-bad" : "ft-ok"));
      b += AR(106, 208, 106, 224);
      b += R(8, 224, 196, 38) + T(106, 240, "volume : secteurs chiffrés", "f-b") + T(106, 255, "flux(DEK, n° de secteur)", "f-s");
      b += R(222, 8, 190, 108, x.wiped ? "f-bad" : "") + T(317, 24, "entête (lisible sur le disque)", "f-b");
      b += T(230, 42, "sel : " + h.salt, "f-s", "start") + T(230, 58, "itérations : " + h.iter, "f-s", "start") + T(230, 74, "DEK enveloppée :", "f-s", "start") + T(230, 90, sh(h.wrapped, 14), "f-s ft-pub", "start") + T(230, 106, "contrôle : " + h.check, "f-s", "start");
      b += LN(222, 90, 206, 135, "f-dash") ;
      b += R(222, 130, 190, 132, "f-ok") + T(317, 146, "changer la phrase :", "f-b") + T(317, 162, "nouvelle KEK", "f-s") + T(317, 177, "+ DEK ré-enveloppée", "f-s") + T(317, 192, "volume intact", "f-s ft-ok") + T(317, 214, "changer la DEK :", "f-b") + T(317, 230, "tout re-chiffrer", "f-s ft-bad") + T(317, 245, "(des heures)", "f-s ft-bad");
      return { cap: x.wiped ? "L'entête est détruit : sans lui, plus de KEK utile, plus de DEK. Le volume est du bruit pour toujours." : "La phrase ne chiffre pas le disque : elle ouvre une enveloppe, qui contient la clé de données. Changer la phrase ne touche pas au volume.", svg: SVG(272, "Hiérarchie des clés", b) };
    },
    mosaique: () => {
      const cells = [mosaic("ecb"), mosaic("tweak")], plain = PAD.join("").split("").map(c => (c === "#" ? 1 : 0));
      const hue = v => `hsl(${(v % 16) * 22.5},62%,55%)`;
      const panel = (ox, arr, fill) => { let s = ""; arr.forEach((v, i) => { s += `<rect x="${ox + (i % MW) * 8}" y="${30 + Math.floor(i / MW) * 8}" width="8" height="8" fill="${fill(v)}"/>`; }); return s + `<rect x="${ox}" y="30" width="128" height="80" fill="none" class="f-box"/>`; };
      let b = panel(8, plain, v => (v ? "var(--ink)" : "var(--panel)")) + panel(146, cells[0], hue) + panel(284, cells[1], hue);
      b += T(72, 20, "clair", "f-b") + T(210, 20, "ECB", "f-b ft-bad") + T(348, 20, "tweak (position)", "f-b ft-ok");
      b += T(72, 128, "un cadenas", "f-s") + T(210, 128, new Set(cells[0]).size + " valeurs : forme visible", "f-s ft-bad") + T(348, 128, new Set(cells[1]).size + " valeurs : bruit", "f-s ft-ok");
      b += T(210, 152, "même clé, même clair : seul le mode change", "f-s");
      return { cap: "Chaque carreau est un bloc chiffré, une couleur par valeur chiffrée. En ECB, deux blocs identiques donnent la même couleur : le cadenas apparaît. Avec un tweak lié à la position, chaque carreau est différent.", svg: SVG(164, "ECB contre mode à tweak", b) };
    },
    menaces: () => {
      const x = F(), okPw = !!x.hdr && x.hdr.iter > 1 && !weak(x.phrase || ""), okMem = x.pw === "off", okMaid = !!x.tpmOn;
      const row = (y, ttl, a, ok, how) => R(8, y, 404, 56, ok ? "f-ok" : "f-bad") + T(18, y + 18, ttl, "f-b", "start") + T(18, y + 34, a, "f-s", "start") + T(18, y + 49, how, "f-s", "start") + T(402, y + 22, ok ? "défendu" : "exposé", "f-b " + (ok ? "ft-ok" : "ft-bad"), "end");
      let b = row(6, "1. phrase faible, devinée hors ligne", "Mallory a l'entête : essais illimités, sans alerte.", okPw, "parade : phrase longue (≥ 16) + dérivation lente");
      b += row(70, "2. portable allumé ou en veille", "La DEK est en mémoire : extraction possible.", okMem, "parade : éteindre vraiment (état actuel : " + (x.pw === "off" ? "éteint" : x.pw === "sleep" ? "veille" : "allumé") + ")");
      b += row(134, "3. amorce trafiquée (evil maid)", "La partition /boot n'est pas chiffrée.", okMaid, "parade : TPM + démarrage sécurisé + PIN" + (okMaid ? "" : " (pas encore actif)"));
      return { cap: "Trois menaces qui contournent un « disque chiffré ». Ce schéma montre l'état de ton portable : une machine allumée reste exposée quoi qu'on fasse.", svg: SVG(200, "Menaces résiduelles", b) };
    },
    sauvegarde: () => {
      const x = F(), clear = x.bk === "clair", withKey = x.keyAt === "serveur", bad = clear || withKey;
      let b = R(8, 14, 130, 78, x.keyAt === "portable" ? "f-ok" : "") + T(73, 32, "portable de Bob", "f-b") + T(73, 50, "chiffre côté client", "f-s") + (x.keyAt === "portable" ? KEY(40, 68, "f-priv") + T(84, 72, "clé BK", "f-s", "start") : T(73, 72, x.bk ? "(clé ailleurs)" : "(rien à envoyer)", "f-s"));
      b += AR(138, 52, 252, 52, bad ? "f-bad" : "f-pub") + T(195, 44, clear ? "registres en clair" : x.bk ? "archive chiffrée" : "—", "f-s");
      b += R(252, 14, 160, 118, bad ? "f-bad" : "f-ok") + T(332, 32, "serveur (hébergeur, Ève)", "f-b") + T(332, 52, clear ? "registres LISIBLES" : x.bk ? "archive.enc : bruit" : "(vide)", "f-s " + (clear ? "ft-bad" : ""));
      b += T(332, 72, withKey ? "key.txt : clé à côté ✗" : x.bk === "chiffre" ? "aucune clé ici ✔" : "", "f-s " + (withKey ? "ft-bad" : "ft-ok"));
      b += T(332, 92, x.slot ? "recuperation.slot (BK sous RK)" : "", "f-s");
      b += R(8, 150, 200, 76, x.rkState === "coffre" ? "f-ok" : x.rkState === "detruite" ? "f-bad" : "") + T(108, 168, "coffre de la Guilde", "f-b") + T(108, 188, x.rkState === "coffre" ? "clé de récupération RK ✔" : x.rkState === "poche" ? "RK dans ta poche ✗" : x.rkState === "detruite" ? "RK brûlée : rien ne se restaure" : "(pas de séquestre)", "f-s " + (x.rkState === "coffre" ? "ft-ok" : "")) + T(108, 208, "séparé du serveur et du portable", "f-s");
      b += T(312, 175, "règle : la clé ne vit jamais", "f-s") + T(312, 190, "avec les données ; et il en", "f-s") + T(312, 205, "faut une copie de secours", "f-s") + T(312, 220, "gardée à part", "f-s");
      return { cap: "Chiffrer côté client protège contre l'hébergeur à condition de garder la clé ailleurs ; la clé de récupération, au coffre, évite que la perte du portable emporte les sauvegardes.", svg: SVG(240, "Sauvegarde chiffrée et séparation des clés", b) };
    },
  };

  GAMES.diskenc = {
    id: "diskenc", order: 16, title: "Le Caveau Scellé", pageTitle: "Disk Quest", subtitle: "aventure textuelle · chiffrement de disque et clés",
    blurb: "Un portable de la Guilde est volé dans un train : que peut en tirer le voleur selon la protection du disque ? Clés, modes, sauvegardes et crypto-shredding.",
    concept: "Chiffrement de disque et de sauvegardes, gestion des clés",
    start: "quai", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.mode = "clair"; x.pw = "on"; x.bk = ""; x.keyAt = ""; x.rkState = "none"; },
    give(item, who) { if (item === "rk" && who === "ada") return rkGive(); return false; },
    refig(name) { fig(name); },
    figAlias: { etats: ["disque", "protection", "voleur"], cles: ["hierarchie", "cle", "kek", "dek"], mosaique: ["ecb", "mode", "tweak", "cadenas"], menaces: ["menace", "evil", "maid", "tpm"], sauvegarde: ["backup", "sauvegardes", "sequestre", "recuperation"] },
    help: "Spécifiques : `demonter disque` · `chiffrer fichier|disque ‹phrase›|mosaique ecb|tweak|sauvegarde` · `eteindre portable` · `veille` · `demarrer` · `deverrouiller ‹phrase›` · `changer phrase ‹…›` · `rechiffrer disque` · `regler kdf lent` · `activer tpm ‹PIN›` · `attaquer phrase` · `capturer memoire` · `trafiquer amorce` · `sauvegarder clair|chiffre` · `ecouter serveur` · `ranger cle portable|recuperation coffre` · `generer cle recuperation` · `restaurer sauvegarde ‹code›` · `detruire cle disque|recuperation`",
    verbs: {
      bench: { words: ["demonter", "debrancher", "brancher"], run: benchCmd },
      encrypt: { words: ["chiffrer", "crypter"], run: encrypt },
      off: { words: ["eteindre", "arreter", "verrouiller"], run: powerOff },
      sleep: { words: ["veille", "suspendre"], run: sleepCmd },
      unlock: { words: ["deverrouiller", "debloquer", "ouvrir"], run: unlock },
      start: { words: ["demarrer", "allumer", "rallumer", "redemarrer"], run: startCmd },
      chg: { words: ["changer", "modifier"], run: changePhrase },
      rekey: { words: ["rechiffrer"], run: rekey },
      kdf: { words: ["regler", "renforcer"], run: setKdf },
      tpm: { words: ["activer", "armer"], run: setTpm },
      attack: { words: ["attaquer", "deviner", "craquer"], run: attackCmd },
      mem: { words: ["capturer", "fouiller"], run: memCmd },
      maid: { words: ["trafiquer", "pieger"], run: maidCmd },
      backup: { words: ["sauvegarder", "envoyer"], run: backup },
      listen: { words: ["ecouter", "espionner"], run: listenCmd },
      store: { words: ["ranger", "stocker", "deplacer"], run: storeCmd },
      genrk: { words: ["generer", "creer", "produire"], run: genRk },
      restore: { words: ["restaurer", "recuperer"], run: restoreCmd },
      destroy: { words: ["detruire", "effacer", "bruler", "supprimer"], run: destroyCmd },
    },
    intro() {
      out("Le Caveau Scellé", "title");
      out("Un portable de la Guilde de Port-443 a été volé dans le train de nuit. Dedans : les registres des membres. Bob jure qu'il était « protégé par mot de passe ». Maître Ada veut savoir ce que le voleur peut vraiment en tirer, selon la façon dont le disque est protégé, et comment faire mieux. Tout est simulé sur des données fictives : Mallory joue le voleur avec l'accord d'Ada, et Ève, curieuse, administre le serveur de sauvegarde.", "");
    },
  };
  function rkGive() {
    const x = F();
    if (S.room !== "quai") { out("Maître Ada est au quai.", "sys"); return; }
    if (x.rkState === "coffre") { out("Elle est déjà au coffre.", "sys"); return; }
    if (x.rkState !== "poche") { out("Tu n'as pas cette clé sur toi.", "sys"); return; }
    x.rkState = "coffre"; drop("rk");
    say("Maître Ada", "Je la range dans le coffre de la Guilde : hors du serveur et hors du portable. (En vrai, on la couperait en deux moitiés confiées à deux personnes.)");
    fig("sauvegarde");
  }
})();
