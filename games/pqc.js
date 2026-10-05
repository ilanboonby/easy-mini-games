"use strict";
/* La Tempête Quantique : inventaire cryptographique, Shor, LWE jouet, hybride, agilité, signatures à base de hachage. */
(function () {
  const F = () => f();
  const Q = 97, NN = 4, MM = 8, HALF = 48;          // LWE jouet : modulo, dimension du secret, nombre d'échantillons
  const Y = 5, Z = 15;                               // Mosca : durée de migration (y) et délai avant l'ordinateur quantique (z), en années
  const TARGETS = [15, 21, 33];
  const DHP = 16777213, DHG = 5, DH_A = 9054321, DH_B = 7123457; // Diffie-Hellman jouet (p premier de 24 bits)
  const GUESS = 20000;                               // essais de Mallory sur une valeur inconnue
  const LB = 24;                                     // bits de condensat de la signature de Lamport jouet
  const FORGE_BUDGET = 60000;
  const mod = (a, m) => ((a % m) + m) % m;
  const cen = v => { const c = mod(v, Q); return c > HALF ? c - Q : c; };
  const rng = seed => { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; };
  const ri = (r, lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
  const dot = (a, s) => mod(a.reduce((t, v, i) => t + v * s[i], 0), Q);
  const num = c => { const m = c.rawArg.match(/\d+/); return m ? parseInt(m[0], 10) : NaN; };
  const tx = c => norm(c.rawArg);
  const sgn = n => (n > 0 ? "+" : "") + n;

  /* ---------- LWE jouet ---------- */
  function solveMod(M, v) {
    const n = M.length;
    const a = M.map((r, i) => [...r.map(z => mod(z, Q)), mod(v[i], Q)]);
    for (let c = 0; c < n; c++) {
      let p = c; while (p < n && a[p][c] === 0) p++;
      if (p === n) return null;
      [a[c], a[p]] = [a[p], a[c]];
      const iv = modpow(a[c][c], Q - 2, Q);
      a[c] = a[c].map(z => (z * iv) % Q);
      for (let r = 0; r < n; r++) if (r !== c && a[r][c]) { const k = a[r][c]; a[r] = a[r].map((z, j) => mod(z - k * a[c][j], Q)); }
    }
    return a.map(r => r[n]);
  }
  function genLwe() {
    const x = F();
    for (let seed = 20260; ; seed++) {
      const r = rng(seed);
      const A = Array.from({ length: MM }, () => Array.from({ length: NN }, () => ri(r, 0, Q - 1)));
      const s = Array.from({ length: NN }, () => mod(ri(r, -2, 2), Q));
      const e = Array.from({ length: MM }, () => ri(r, -1, 1));
      if (s.filter(v => v).length < 3) continue;
      if (e.slice(0, NN).filter(v => v).length < 2) continue;
      const b = A.map((row, i) => mod(dot(row, s) + e[i], Q));
      const sp = solveMod(A.slice(0, NN), b.slice(0, NN));
      if (!sp) continue;
      const big = A.slice(NN).filter((row, j) => Math.abs(cen(b[NN + j] - dot(row, sp))) > 1).length;
      if (big < 3) continue;
      x.A = A; x.s = s; x.e = e; x.b = b; return;
    }
  }
  function lweEnc(bit, seed) {
    const x = F(), r = rng(seed);
    let sub = []; for (let i = 0; i < MM; i++) if (r() < 0.5) sub.push(i);
    if (!sub.length) sub = [0];
    const u = Array.from({ length: NN }, (_, j) => mod(sub.reduce((t, i) => t + x.A[i][j], 0), Q));
    const v = mod(sub.reduce((t, i) => t + x.b[i], 0) + bit * HALF, Q);
    return { u, v, sub, bit };
  }
  function lweDec(ct, s) {
    const d = mod(ct.v - dot(ct.u, s), Q);
    const d0 = Math.min(d, Q - d), d1 = Math.min(Math.abs(d - HALF), Q - Math.abs(d - HALF));
    const bit = d1 < d0 ? 1 : 0;
    return { d, bit, noise: cen(d - bit * HALF) };
  }
  const vec = a => "(" + a.join(", ") + ")";

  /* ---------- algorithmes : bits de sécurité ---------- */
  const RSA_BITS = { 1024: 80, 2048: 112, 3072: 128, 4096: 140, 7680: 192, 15360: 256 };
  function parseAlgo(t) {
    const d = (t.match(/\d+/) || [""])[0];
    if (/rsa/.test(t)) { const n = d || "2048"; if (!RSA_BITS[n]) return { err: "Tailles RSA connues : 1024, 2048, 3072, 4096, 7680, 15360." }; return { key: "rsa" + n, name: "RSA-" + n, kind: "asym", c: RSA_BITS[n], q: 0 }; }
    if (/ecdh|ecdsa|ecc|ed25519|x25519|p ?256|courbe|elliptique/.test(t)) return { key: "ecc", name: "ECDH / ECDSA P-256 (courbes elliptiques)", kind: "asym", c: 128, q: 0 };
    if (/aes/.test(t)) { if (!["128", "192", "256"].includes(d)) return { err: "AES existe en 128, 192 ou 256 bits : `evaluer aes 256`." }; return { key: "aes" + d, name: "AES-" + d, kind: "sym", c: +d, q: +d / 2 }; }
    if (/sha/.test(t)) { if (!["256", "384", "512"].includes(d)) return { err: "SHA-2 existe en 256, 384 ou 512 bits : `evaluer sha 384`." }; return { key: "sha" + d, name: "SHA-" + d + " (résistance aux préimages)", kind: "hash", c: +d, q: +d / 2 }; }
    return null;
  }
  const ALG_ROWS = ["rsa2048", "ecc", "aes128", "aes256", "sha256", "sha384"];
  const algoOf = k => parseAlgo(k);

  /* ---------- inventaire de la Guilde ---------- */
  const USAGES = [
    { id: "tls", re: /tls|site|vitrine/, label: "TLS du site vitrine", algo: "échange ECDH P-256, certificat RSA-2048", kind: "asym", nature: "conf", x: 1, dur: "secret : 1 an" },
    { id: "code", re: /code|signature|micrologiciel|firmware|phare/, label: "Signature du micrologiciel des phares", algo: "signature RSA-3072", kind: "asym", nature: "sig", x: 15, dur: "à rester infalsifiable : 15 ans" },
    { id: "vpn", re: /vpn|justice|palais/, label: "VPN du Palais de Justice", algo: "clé par ECDH P-256, trafic en AES-256", kind: "asym", nature: "conf", x: 25, dur: "secret : 25 ans" },
    { id: "sauvegardes", re: /sauvegarde|backup|nuit/, label: "Sauvegardes nocturnes", algo: "AES-256-GCM, clé symétrique", kind: "sym256", nature: "conf", x: 10, dur: "secret : 10 ans" },
    { id: "archives", re: /archive|naissance/, label: "Archives des naissances", algo: "AES-128, clé symétrique", kind: "sym128", nature: "conf", x: 50, dur: "secret : 50 ans" },
    { id: "journaux", re: /journa|empreinte|sceau/, label: "Journaux scellés par empreinte", algo: "SHA-256", kind: "hash256", nature: "int", x: 10, dur: "intégrité : 10 ans" },
  ];
  function verdictOf(u) {
    if (u.kind === "asym") return u.x + Y > Z ? "urgent" : "planifier";
    if (u.kind === "sym128") return "planifier";
    return "ok";
  }
  function explainUsage(u) {
    const v = verdictOf(u);
    if (u.kind === "asym") {
      const s = u.x + Y;
      return `Algorithme asymétrique : Shor le casse entièrement. Règle de Mosca : x + y = ${u.x} + ${Y} = ${s} ans, à comparer à z = ${Z} ans. ${s > Z ? `${s} > ${Z} : ${u.nature === "sig" ? "quand l'ordinateur arrivera, des micrologiciels encore en service pourront être falsifiés" : "ce qui est enregistré aujourd'hui sera lisible avant la fin de sa durée de secret"} : **urgent**.` : `${s} ≤ ${Z} : on a le temps de migrer avant qu'une machine existe, mais il faut le **planifier** (et rester agile).`}`;
    }
    if (u.kind === "sym128") return "Symétrique : Grover divise les bits par deux. AES-128 tombe à 2^64 : sous le seuil prudent de 128 bits effectifs. Pas de panique ni de refonte (même protocole, clé plus longue), mais à **planifier** : passer à AES-256.";
    if (u.kind === "sym256") return "Symétrique : AES-256 garde 256/2 = 128 bits effectifs face à Grover : le seuil est tenu, **ok**.";
    return "Un hachage subit au pire Grover sur les préimages : SHA-256 garde 128 bits effectifs, **ok** (SHA-384 donne plus de marge).";
  }
  const nCls = () => Object.keys(F().cls || {}).length;

  /* ---------- tailles (octets) ---------- */
  const KEX = { x25519: { n: "X25519 seul", c: 32, s: 32, pq: false }, hybride: { n: "X25519 + ML-KEM-768", c: 32 + 1184, s: 32 + 1088, pq: true, hyb: true }, mlkem: { n: "ML-KEM-768 seul", c: 1184, s: 1088, pq: true } };
  const SIG = { ecdsa: { n: "ECDSA P-256", pk: 64, sg: 64, pq: false }, rsa: { n: "RSA-2048", pk: 256, sg: 256, pq: false }, mldsa: { n: "ML-DSA-65", pk: 1952, sg: 3309, pq: true }, falcon: { n: "Falcon-512 (FN-DSA)", pk: 897, sg: 666, pq: true }, slh: { n: "SLH-DSA-128s", pk: 32, sg: 7856, pq: true } };
  const PHARE_MAX = 8000;
  const fmtN = n => n.toLocaleString("fr-FR").replace(/[\u202f\u00a0]/g, " ");

  /* ---------- carnet ---------- */
  const notes = {
    harvest: ["Récolter maintenant, déchiffrer plus tard", "Un adversaire peut enregistrer aujourd'hui du trafic chiffré qu'il ne sait pas lire, et le garder jusqu'à ce qu'il possède un ordinateur quantique. Ce qui compte, c'est la règle de Mosca : si x (durée pendant laquelle le secret doit tenir) + y (durée de la migration) dépasse z (délai avant la machine), il est déjà trop tard pour ces données. Les échanges de clés sont donc la priorité ; les signatures, qu'on ne peut falsifier qu'en temps réel, peuvent suivre (sauf celles qui doivent durer : micrologiciels, racines de confiance)."],
    shor: ["Shor : RSA et courbes elliptiques tombent", "L'algorithme de Shor trouve la période r de a^x mod N. Ensuite tout est classique : si r est pair et a^(r/2) ≢ −1, alors pgcd(a^(r/2) ± 1, N) donne les facteurs. Seule la recherche de période est accélérée par le quantique (transformée de Fourier quantique), de façon exponentielle. Le même principe casse le logarithme discret : Diffie-Hellman et les courbes elliptiques tombent avec RSA."],
    grover: ["Grover : les clés symétriques et les hachages tiennent", "Grover accélère la recherche exhaustive, mais seulement de façon quadratique : 2^n essais deviennent 2^(n/2). AES-128 retombe vers 64 bits effectifs, AES-256 garde 128 bits ; la résistance aux préimages de SHA-256 passe de 256 à 128 bits. Remède : doubler la taille (AES-256, SHA-384), pas changer d'algorithme. En pratique Grover se parallélise mal, ce qui rend le risque réel moindre que ce calcul."],
    lwe: ["Réseaux euclidiens et LWE", "LWE (Learning With Errors) : on publie des équations b = ⟨a, s⟩ + e (mod q) où e est un petit bruit. Sans bruit, c'est de l'algèbre linéaire : l'élimination de Gauss retrouve s. Avec le bruit, retrouver s est difficile, même pour un ordinateur quantique : on ne connaît pas d'algorithme efficace. Le bruit est la clé du problème, et il doit rester assez petit pour que le destinataire légitime, qui connaît s, arrive à décoder. ML-KEM (FIPS 203) en est une version structurée (Module-LWE)."],
    hybride: ["Migration hybride", "On combine un échange classique et un mécanisme post-quantique, et on dérive la clé de session d'un hachage des deux secrets (K = H(K_classique ‖ K_pq)). L'adversaire doit casser les deux : un ordinateur quantique ne suffit pas, une faille mathématique dans le tout nouvel algorithme non plus (SIKE a été cassé en 2022 sur un simple PC classique). X25519+ML-KEM-768 est déjà déployé dans TLS par de nombreux navigateurs et CDN."],
    agilite: ["Agilité cryptographique", "Les algorithmes ont une date de péremption. Un système agile identifie l'algorithme dans le message (identifiant, longueur variable) et le choisit dans un registre négocié, au lieu de figer des tailles ou des noms dans le code : changer d'algorithme devient une configuration, pas une réécriture. Il faut aussi inventorier ses usages, authentifier la négociation (contre les attaques par repli) et pouvoir désactiver les anciens algorithmes."],
    tailles: ["Tailles : le prix du post-quantique", "Les clés et signatures post-quantiques sont plus grosses : ML-KEM-768 échange 1 184 et 1 088 octets (contre 32 pour X25519), une signature ML-DSA-65 pèse 3 309 octets (contre 64 pour ECDSA). Une poignée de main TLS avec chaîne de certificats passe de quelques centaines d'octets à plusieurs dizaines de milliers : paquets supplémentaires, latence, bande passante. D'où l'ordre habituel : échange de clés hybride d'abord, signatures plus tard et avec parcimonie."],
    hashsig: ["Signatures à base de hachage", "Une signature de Lamport ne repose que sur une fonction de hachage : on publie H(sk0) et H(sk1), et pour signer un bit on révèle le secret correspondant. Chaque clé ne sert qu'UNE fois : une seconde signature révèle d'autres secrets, et l'on peut forger des messages. Les schémas réels (LMS et XMSS, avec état ; SLH-DSA, sans état) assemblent des milliers de telles clés dans des arbres de Merkle. Leur sécurité ne dépend que du hachage, mais leurs signatures sont lourdes."],
  };

  /* ---------- entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, un parchemin froissé à la main. Elle a l'air de quelqu'un qui a lu les prévisions du ciel et ne les a pas aimées." },
    eve: { npc: true, names: ["eve"], label: "Ève", vis: () => true, desc: () => "Ève, une collectionneuse patiente, assise devant des étagères de disques durs étiquetés. Elle ne casse rien : elle écoute, elle copie, elle range. Elle a tout son temps." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => S.room === "coffre" ? "Mallory, penchée sur la serrure du coffre, un carnet de hachages à la main. Elle a vu passer tes signatures." : "Mallory, devant un grand abaque où elle fait défiler des puissances. Elle prétend que l'ordinateur quantique qu'elle a vu en rêve ne fait « qu'une seule chose, mais très vite »." },
    alice: { npc: true, names: ["alice"], label: "Alice", desc: () => "Alice, qui prépare l'envoi d'un message important vers l'autre rive du fleuve." },
    bob: { npc: true, names: ["bob"], label: "Bob", desc: () => "Bob, de l'autre côté du pont, qui attend la clé d'Alice. Il garde sa clé secrète de réseau dans sa poche." },
    tableau: { names: ["tableau", "affiche", "tempete", "ciel"], label: "le tableau des prévisions", desc: () => "Sur le tableau : « TEMPÊTE QUANTIQUE : date inconnue, effets certains. Les messages chiffrés d'aujourd'hui sont déjà enregistrés par quelqu'un. » Ada a griffonné dessous : « x + y > z ? »" },
    banc: { names: ["banc", "protocole", "protocoles", "atelier"], label: "le banc des protocoles", desc: () => `Le banc des protocoles de la Guilde. Deux maquettes de message signé :\n  v1 : [version][signature : 256 octets FIXES][corps]\n  v2 : [version][id algo][longueur][signature][corps] + un registre des algorithmes\n\`migrer v1\` / \`migrer v2\` : envoie une signature ML-DSA-65 (3 309 octets) dans chaque format.\nRegistre côté serveur : ${F().srv ? F().srv.join(", ") : "x25519"} · préférences du client : ${CLIENT.join(", ")}.\n\`negocier\` lance la poignée de main, \`activer ‹suite›\` ajoute une suite au registre.` },
    registre: { names: ["registre", "livre", "registre crypto"], label: "le registre des usages cryptographiques", desc: () => {
      const L = USAGES.map(u => `${u.id.padEnd(12)} ${u.label} : ${u.algo} (${u.dur})${F().cls && F().cls[u.id] ? "  → " + F().cls[u.id] : ""}`).join("\n");
      return `Le registre des usages cryptographiques de Port-443 :\n${L}\n\nRègle de Mosca : x (durée de protection) + y (migration : ${Y} ans) > z (arrivée de la machine : ${Z} ans, hypothèse du jeu) ⇒ urgent.\n\`evaluer ‹algo›\` calcule les bits de sécurité (ex. evaluer aes 128), \`classer ‹usage› urgent|planifier|ok\` range un usage.`;
    } },
    abaque: { names: ["abaque", "boulier", "machine", "oracle"], label: "l'abaque de Mallory", desc: () => `L'abaque de Mallory fait défiler a^x mod N. Cible actuelle : **N = ${TARGETS[Math.min(F().ni || 0, 2)]}**.\n\`periode ‹a›\` cherche la période (classiquement, un essai après l'autre) ; \`factoriser ‹a›\` en tire les facteurs avec le pgcd ; \`echelle ‹bits›\` compare les coûts.` },
    pupitre: { names: ["pupitre", "cle publique", "cle", "equations", "treillis"], label: "le pupitre de la clé publique", desc: () => { const x = F(); return `Clé publique LWE jouet : modulo q = ${Q}, secret s de ${NN} entiers, ${MM} équations b = ⟨a, s⟩ + e (mod ${Q}), bruit e ∈ {−1, 0, 1} :\n${x.A.map((r, i) => `  ${i + 1}: a = ${vec(r)}   b = ${x.b[i]}`).join("\n")}\n\`resoudre sans bruit\` · \`resoudre avec bruit\` · \`chiffrer ‹0|1›\` · \`dechiffrer\` · \`bruit ‹B›\``; } },
    echangeur: { names: ["echangeur", "pont", "tuyaux", "valve"], label: "l'échangeur à deux tuyaux", desc: () => "Deux tuyaux relient Alice à Bob : l'un porte un échange classique (Diffie-Hellman jouet, p de 24 bits), l'autre un échange à base de réseaux (la clé LWE du treillis, 32 bits transportés). `echanger` fait passer les deux, `deriver ‹classique|postquantique|hybride›` fabrique la clé de session, `simuler ‹shor|maths|aucune|tout›` laisse Mallory attaquer." },
    balance: { names: ["balance", "poids", "tailles"], label: "la balance des octets", desc: () => `La balance des octets pèse une poignée de main TLS (modèle simplifié : la clé échangée dans les deux sens, plus 3 signatures et 2 clés publiques de certificat).\nLe lien du Phare n'accepte pas plus de ${fmtN(PHARE_MAX)} octets par poignée de main.\n\`tailles\` affiche le barème, \`budget ‹kex› ‹sig›\` pèse une configuration (kex : x25519, hybride, mlkem ; sig : ecdsa, rsa, mldsa, falcon, slh).` },
    coffre: { names: ["coffre", "coffre fort", "serrure", "cadenas"], label: "le coffre à serrure de Lamport", desc: () => `Un coffre dont la serrure n'obéit qu'à des signatures à usage unique : ${LB} positions, chacune avec deux secrets (bit 0 et bit 1), et leurs empreintes publiques.\n\`signer ‹message›\` · \`verifier\` · \`forger\` (Mallory essaie de contrefaire un ordre) · signatures produites : ${(F().sigs || []).length}.` },
  };
  const CLIENT = ["x25519mlkem768", "mlkem768", "x25519"];

  const rooms = {
    hall: { name: "Le Hall de la Guilde", short: "Hall", alias: ["hall", "guilde"], ents: ["ada", "tableau", "banc"], exits: { nord: "audit", est: "tour", ouest: "treillis", sud: "passerelle" },
      desc: () => "Le grand hall de la Guilde, au ciel de verrières. Un tableau des prévisions occupe un mur, un banc de protocoles un autre. Au nord, le bureau d'audit. À l'est, la tour de Mallory. À l'ouest, la salle des treillis. Au sud, la passerelle." },
    audit: { name: "Le bureau d'audit", short: "Audit", alias: ["audit", "bureau"], ents: ["eve", "registre"], exits: { sud: "hall" },
      desc: () => "Des étagères de disques durs étiquetés, un registre ouvert sur un pupitre. Quelqu'un a pris ses aises ici : on dirait qu'elle collectionne tout ce qui passe." },
    tour: { name: "La tour de Mallory", short: "Tour", alias: ["tour", "mallory"], ents: ["mallory", "abaque"], exits: { ouest: "hall" },
      desc: () => "Une tour de pierre, un abaque géant au centre. Les murs sont couverts de petites divisions et de nombres soulignés." },
    treillis: { name: "La salle des treillis", short: "Treillis", alias: ["treillis", "reseau", "reseaux", "salle"], ents: ["pupitre"], exits: { est: "hall" },
      desc: () => "Un plafond de poutres croisées qui dessinent un réseau régulier de points, à l'infini. Sur un pupitre : une clé publique faite de simples équations." },
    passerelle: { name: "La passerelle du fleuve", short: "Passerelle", alias: ["passerelle", "pont", "fleuve"], ents: ["alice", "bob", "echangeur", "balance"], exits: { nord: "hall", est: "coffre" },
      desc: () => "Une passerelle au-dessus du fleuve. Alice est à un bout, Bob à l'autre. Deux tuyaux courent le long du parapet : l'échangeur. Une balance à poids mesure tout ce qui doit passer. À l'est, un petit coffre-fort." },
    coffre: { name: "Le coffre de Lamport", short: "Coffre", alias: ["coffre", "lamport"], ents: ["coffre", "mallory"], exits: { ouest: "passerelle" },
      desc: () => "Une cave minuscule, un coffre blindé dont la serrure est faite de deux rangées de petits verrous : un pour chaque bit possible à chaque position." },
  };

  /* ---------- objectifs et indices ---------- */
  const lweDone = () => { const x = F(); return !!(x.dec && x.nbLow && x.nbHigh); };
  const hybDone = () => { const x = F(); return !!(x.hs && x.hm && x.mode === "hybride"); };
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.eve) return "eve";
    if (Object.keys(x.ev || {}).length < 3) return "eval";
    if (nCls() < USAGES.length) return "classer";
    if (!x.mal) return "mallory";
    if ((x.ni || 0) < TARGETS.length) return "fact";
    if (!x.scale) return "scale";
    if (!x.s0) return "sans";
    if (!x.s1) return "avec";
    if (!x.ct) return "enc";
    if (!x.dec) return "dec";
    if (!(x.nbLow && x.nbHigh)) return "bruit";
    if (!x.exch) return "exch";
    if (x.mode !== "hybride") return "deriv";
    if (!(x.hs && x.hm)) return "sim";
    if (!x.budgetOK) return "budget";
    if (!(x.m1 && x.m2)) return "mig";
    if (!x.nego) return "activer";
    if ((x.sigs || []).length < 1) return "sig1";
    if (!x.forge1 && x.sigs.length === 1) return "forge1";
    if (x.sigs.length < 2) return "sig2";
    if (!x.forgeOK) return "forge2";
    if (!x.end) return "end";
    return "fin";
  };
  const curN = () => TARGETS[Math.min(F().ni || 0, 2)];
  const hints = {
    quest: () => ["Maître Ada attend dans le hall.", "`parler ada`"],
    eve: () => ["Ada a mentionné quelqu'un qui collectionne les disques. Cherche au bureau d'audit, au nord.", "`aller nord`, puis `parler eve`."],
    eval: () => ["Avant de classer quoi que ce soit, mesure ce que le quantique fait aux algorithmes : au moins trois d'entre eux.", "`evaluer rsa 2048`, `evaluer aes 128`, `evaluer sha 256` (ou `ecc`, `aes 256`, `sha 384`)."],
    classer: () => ["Lis le registre (`examiner registre`) et range chaque usage : urgent, planifier ou ok. La règle de Mosca fait le tri pour les algorithmes asymétriques.", "`classer tls planifier`, `classer code urgent`, `classer vpn urgent`, `classer sauvegardes ok`, `classer archives planifier`, `classer journaux ok` (compare x + y à z = 15 pour les asymétriques)."],
    mallory: () => ["Mallory prétend savoir ce que fera la machine. Va l'écouter dans sa tour, à l'est du hall.", "`aller sud` ou `aller est` depuis le hall, puis `parler mallory`."],
    fact: () => [`Trouve les facteurs de N = ${curN()} avec la période de a^x mod N : choisis un a entre 2 et ${curN() - 1}, cherche sa période, puis déduis-en les facteurs. Si ça échoue, change de a.`, `\`periode 2\` puis \`factoriser 2\` (essaie d'autres a si r est impair ou si a^(r/2) ≡ −1).`],
    scale: () => ["Compare le coût de la recherche de période pour un vrai N : classique contre quantique.", "`echelle 2048` (à la tour)."],
    sans: () => ["Va à la salle des treillis (ouest du hall). D'abord, que donnent les équations SANS bruit ?", "`aller ouest`, puis `resoudre sans bruit`."],
    avec: () => ["Maintenant la vraie clé publique, avec son bruit.", "`resoudre avec bruit`"],
    enc: () => ["Chiffre un bit avec la clé publique (aucun secret requis).", "`chiffrer 1` (ou 0)."],
    dec: () => ["Déchiffre-le avec la clé secrète : le bruit va se voir.", "`dechiffrer` (tu peux aussi essayer `dechiffrer sans cle`)."],
    bruit: () => ["Règle le bruit dans le laboratoire : un petit B marche, un grand B casse même le destinataire légitime. Essaie les deux.", "`bruit 1` puis `bruit 12` (ou 30)."],
    exch: () => ["Passerelle (sud du hall) : fais passer les deux échanges.", "`aller sud` (depuis le hall), puis `echanger`."],
    deriv: () => ["Fabrique la clé de session en combinant les deux secrets par un hachage.", "`deriver hybride`"],
    sim: () => ["Laisse Mallory attaquer : d'abord avec un ordinateur quantique (Shor), puis avec une faille mathématique dans le mécanisme post-quantique. La clé hybride doit tenir dans les deux cas.", "`simuler shor` puis `simuler maths` (à la passerelle, clé dérivée en mode hybride)."],
    budget: () => [`Le lien du Phare plafonne à ${fmtN(PHARE_MAX)} octets par poignée de main. Il faut un échange de clés hybride (contre la récolte) qui tienne dans ce budget. Pèse des configurations avec la balance.`, "`tailles` puis `budget hybride ecdsa` (essaie aussi `budget hybride mldsa`)."],
    mig: () => ["Au banc des protocoles (hall) : envoie une signature ML-DSA dans les deux formats de message et compare.", "`aller nord` (depuis la passerelle), `migrer v1`, `migrer v2`."],
    activer: () => ["Le serveur ne connaît que X25519. Regarde la négociation, ajoute une suite au registre, puis renégocie.", "`negocier`, `activer hybride`, `negocier` (au banc des protocoles)."],
    sig1: () => ["Au coffre (passerelle, puis est) : signe un premier ordre avec la clé de Lamport.", "`signer OUVRIR LE COFFRE A NEUF HEURES`, puis `verifier`."],
    forge1: () => ["Demande à Mallory de contrefaire un ordre avec ce qu'elle a vu d'une seule signature.", "`forger`"],
    sig2: () => ["Maintenant, réutilise la même clé pour un autre ordre (c'est ce qu'il ne faut JAMAIS faire).", "`signer FERMER LE COFFRE A MIDI`"],
    forge2: () => ["Mallory a vu deux signatures : laisse-la essayer à nouveau. Si elle échoue, c'est qu'il lui manque des secrets : signe un troisième ordre différent.", "`forger` (puis, si besoin, `signer VERIFIER LES REGISTRES` et `forger`)."],
    end: () => ["Tu as tout vu. Retourne voir Maître Ada dans le hall.", "`parler ada`"],
    fin: () => ["Mission terminée ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- garde-fous ---------- */
  function req(cond, msg) { if (!cond) out(msg, "sys"); return cond; }
  const started = () => req(F().quest, "Va d'abord voir Maître Ada (`parler ada` dans le hall).");
  const inRoom = (r, msg) => req(S.room === r, msg);

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F(), ob = objective();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "La Guilde vient d'apprendre qu'un jour, quelqu'un construira un ordinateur quantique assez grand pour casser RSA et les courbes elliptiques. Personne ne sait quand : dans dix ans, dans trente, peut-être jamais. Mais Mallory, elle, ne l'attend pas les bras croisés : elle enregistre dès aujourd'hui des communications qu'elle ne sait pas encore lire.");
          say("Maître Ada", "Récolter maintenant, déchiffrer plus tard. Il faut préparer la migration de Port-443 : inventorier nos usages, comprendre ce que le quantique casse et ce qu'il épargne, goûter aux nouvelles mathématiques, puis changer sans tout réécrire.");
          out("Commence par le bureau d'audit, au nord (`aller nord`). Il y a quelqu'un à écouter.", "sys");
        } else if (ob === "end") ending();
        else if (x.end) say("Maître Ada", "Port-443 migre à son rythme, et avec méthode. La tempête peut venir.");
        else say("Maître Ada", "La migration n'est pas terminée. `indice` te dit où tu en es, `schema` rappelle ce que tu as appris.");
        break;
      case "eve":
        if (!x.eve) {
          x.eve = true;
          say("Ève", "Bonjour, jeune auditeur·rice. Ne vous inquiétez pas, je ne casse rien. Je copie. Chaque nuit, le trafic chiffré de Port-443 passe par mes câbles : je range tout sur ces disques. Je ne peux rien lire. Pas encore.");
          say("Ève", "Un disque coûte trois fois rien. Et un jour, quelqu'un fabriquera une machine capable de défaire les cadenas d'aujourd'hui : alors je rouvrirai tout. Les secrets qui ne doivent pas tenir plus de quelques années, je m'en fiche. Les autres…");
          out("Ève illustre la menace « récolter maintenant, déchiffrer plus tard ». Retiens la question de Mosca : combien de temps ce secret doit-il tenir, combien de temps faut-il pour migrer, et combien de temps avant la machine ?", "sys");
          note("harvest");
          out("Examine le registre (`examiner registre`) puis mesure les algorithmes avec `evaluer ‹algo›`.", "sys");
        } else say("Ève", "Je range, je range. Les disques sont de moins en moins chers.");
        break;
      case "mallory":
        if (S.room === "coffre") {
          if (!(x.sigs || []).length) say("Mallory", "Un coffre à serrure de Lamport ? Signe quelque chose : je regarde.");
          else say("Mallory", `J'ai vu ${x.sigs.length} signature${x.sigs.length > 1 ? "s" : ""} passer. Chaque signature, ce sont des secrets que tu me livres en clair. \`forger\` : j'essaie de signer mon propre ordre avec ce que j'ai vu.`);
          break;
        }
        if (!x.mal) {
          x.mal = true;
          say("Mallory", "Tu veux savoir ce que fera la machine ? Elle ne sait faire qu'une seule chose, mais elle la fait comme personne : trouver la période d'une suite de puissances. Regarde mon abaque : pour factoriser N, je prends un a, je cherche r tel que a^r ≡ 1 (mod N), et le pgcd fait le reste.");
          say("Mallory", `Moi, je cherche r en essayant 1, 2, 3… Un ordinateur quantique le ferait d'un coup. Voici ma première cible : N = ${curN()}. \`periode ‹a›\`, puis \`factoriser ‹a›\`.`);
        } else if ((x.ni || 0) < TARGETS.length) say("Mallory", `Cible actuelle : N = ${curN()}. Trouve la période r d'un a (\`periode ‹a›\`), puis \`factoriser ‹a›\`. Si r est impair, ou si a^(r/2) vaut −1, change de a.`);
        else say("Mallory", "Tu as compris : toute la magie est dans la période. Le reste, c'est du pgcd, que mon abaque fait très bien tout seul.");
        break;
      case "alice":
        say("Alice", x.exch ? "Notre clé est prête. Reste à décider comment la fabriquer : ce que ça coûte quand on ne combine rien, et quand on combine tout." : "J'ai un message à envoyer à Bob, et Ève écoute le fleuve. Il nous faut une clé commune : `echanger` fait passer les deux tuyaux (il faut d'abord avoir compris les treillis).");
        break;
      case "bob":
        say("Bob", "Je garde ma clé secrète dans ma poche. Alice m'envoie des chiffrés, je les ouvre avec elle. Ceux d'Ève ne lui servent à rien… tant qu'elle ne sait pas résoudre mes équations bruitées.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- étape 1 : inventaire ---------- */
  function evaluate(c) {
    const x = F(); if (!started()) return;
    const t = tx(c);
    if (!t) { out("Quel algorithme ? Par exemple `evaluer rsa 2048`, `evaluer ecc`, `evaluer aes 128`, `evaluer sha 384`.", "err"); return; }
    const a = parseAlgo(t);
    if (!a) { out("Je ne connais pas cet algorithme. Essaie rsa, ecc, aes ou sha (avec la taille).", "err"); return; }
    if (a.err) { out(a.err, "err"); return; }
    x.ev = x.ev || {}; x.ev[a.key] = true;
    out(`${a.name}`, "title");
    if (a.kind === "asym") {
      out(`Classique : environ ${a.c} bits de sécurité (${a.key === "ecc" ? "meilleure attaque : rho de Pollard, exponentielle" : "meilleure attaque : crible algébrique, sous-exponentiel"}).\nQuantique (algorithme de Shor) : temps polynomial en la taille de la clé. Sécurité effective : **≈ 0 bit**. Aucune taille raisonnable ne sauve RSA ou ECC : il faut changer de famille d'algorithme.`, "err");
    } else {
      const lbl = a.kind === "hash" ? "préimage" : "recherche de clé";
      out(`Classique : ${lbl} en 2^${a.c} essais, soit ${a.c} bits.\nQuantique (Grover) : racine carrée du nombre d'essais, 2^(${a.c}/2) = 2^${a.q}. Sécurité effective : **${a.q} bits**. ${a.q >= 128 ? "Le seuil prudent de 128 bits est tenu." : "Sous le seuil prudent de 128 bits : il faut doubler la taille (AES-256, SHA-384)."}`, a.q >= 128 ? "ok" : "err");
      note("grover");
    }
    if (Object.keys(x.ev).length === 3) out("Trois algorithmes évalués. Tu peux maintenant ranger les usages du registre : `classer ‹usage› urgent|planifier|ok`.", "sys");
  }
  function classify(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("audit", "Le registre est au bureau d'audit (nord du hall).")) return;
    if (!x.eve) { out("Va d'abord écouter Ève : `parler eve`.", "sys"); return; }
    const t = tx(c);
    const u = USAGES.find(v => v.re.test(t));
    if (!u) { out("Quel usage ? tls, code, vpn, sauvegardes, archives ou journaux. Exemple : `classer tls planifier`.", "err"); return; }
    const w = /urgen/.test(t) ? "urgent" : /planif|prevoir|renforc/.test(t) ? "planifier" : /\bok\b|aucun|rien|sur|bon|tient/.test(t.replace(u.re, "")) ? "ok" : null;
    if (!w) { out(`Quelle urgence pour « ${u.label} » ? \`classer ${u.id} urgent\`, \`planifier\` ou \`ok\`.`, "err"); return; }
    x.cls = x.cls || {};
    const real = verdictOf(u);
    if (w !== real) {
      out(`${u.label} : « ${w} » ne convient pas.`, "err");
      out(explainUsage(u), "sys");
      return;
    }
    x.cls[u.id] = real;
    out(`✔ ${u.label} : **${real}**. ${explainUsage(u)}`, "ok");
    if (nCls() === USAGES.length) {
      out("Inventaire classé : deux urgences (tout ce qui est asymétrique ET doit durer), deux à planifier, deux solides. Beaucoup de systèmes réels ressemblent à ça.", "ok");
      fig("menaces");
      say("Maître Ada", "Bon travail. Maintenant, comprends POURQUOI les asymétriques tombent : va voir Mallory, dans sa tour à l'est du hall.");
    } else out(`(${nCls()}/${USAGES.length} usages classés)`, "sys");
  }

  /* ---------- étape 2 : Shor ---------- */
  function periodCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("tour", "L'abaque est dans la tour de Mallory (est du hall).")) return;
    if (!x.mal) { out("Parle d'abord à Mallory : `parler mallory`.", "sys"); return; }
    if (nCls() < USAGES.length) { out("Termine d'abord l'inventaire (`indice`).", "sys"); return; }
    const N = curN(), a = num(c);
    if (!(a >= 2 && a < N)) { out(`Choisis un a entre 2 et ${N - 1} : \`periode 2\`.`, "err"); return; }
    const g = gcd(a, N);
    if (g !== 1) { out(`pgcd(${a}, ${N}) = ${g} : tu as eu de la chance, ${g} divise N. Mais avec un N de 600 chiffres, la probabilité de tomber dessus est quasi nulle : la méthode a besoin d'un a premier avec N. Choisis-en un autre.`, "err"); return; }
    const seq = []; let v = 1, r = 0;
    do { v = (v * a) % N; seq.push(v); r++; } while (v !== 1);
    x.last = { a, N, r, t: modpow(a, Math.floor(r / 2), N) }; // dernier essai (période trouvée)
    out(`Abaque classique pour N = ${N}, a = ${a} : on calcule a^x mod N pour x = 1, 2, 3…`, "sys");
    code(`x:        ${seq.map((_, i) => String(i + 1).padStart(3)).join("")}\na^x mod N:${seq.map(s => String(s).padStart(3)).join("")}`);
    out(`La suite retombe sur 1 pour la première fois à x = ${r} : **période r = ${r}**. (Il a fallu ${r} essais ; pour un N de 600 chiffres, la période est elle-même astronomique.) Prochaine étape : \`factoriser ${a}\`.`, "ok");
  }
  function factorCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("tour", "L'abaque est dans la tour de Mallory (est du hall).")) return;
    const a = num(c), N = curN(), L = x.last;
    if (!L || L.N !== N || !(a >= 2)) { out(`Cherche d'abord une période : \`periode ‹a›\` (a entre 2 et ${N - 1}), puis \`factoriser ‹a›\` avec le même a.`, "err"); return; }
    if (L.a !== a) { out(`Ta dernière période concerne a = ${L.a}. Refais \`periode ${a}\` pour ce a.`, "err"); return; }
    const { r } = L;
    if (r % 2) { out(`r = ${r} est impair : on ne peut pas prendre a^(r/2). La méthode échoue pour ce a (cela arrive une fois sur deux environ) : choisis un autre a.`, "err"); return; }
    const t = modpow(a, r / 2, N);
    out(`r = ${r} est pair : a^(r/2) = ${a}^${r / 2} mod ${N} = **${t}**.`, "sys");
    if (t === N - 1) { out(`Mais ${t} ≡ −1 (mod ${N}) : alors a^(r/2) + 1 est un multiple de N et le pgcd ne sépare rien (${gcd(t + 1, N)} puis ${gcd(t - 1, N)}). Mauvais a : choisis-en un autre.`, "err"); return; }
    const g1 = gcd(t - 1, N), g2 = gcd(t + 1, N);
    out(`pgcd(${t} − 1, ${N}) = pgcd(${t - 1}, ${N}) = **${g1}**\npgcd(${t} + 1, ${N}) = pgcd(${t + 1}, ${N}) = **${g2}**\n${N} = ${g1} × ${g2}`, "ok");
    x.fig = { a, N, r, t, g1, g2 };
    x.ni = (x.ni || 0) + 1;
    if (x.ni === 1) { note("shor"); out("Tu viens de refaire à la main ce que fait Shor : transformer la factorisation en recherche de période.", "ok"); }
    fig("periode");
    if (x.ni < TARGETS.length) say("Mallory", `Pas mal. Cible suivante : N = ${curN()}. Certains a vont échouer, c'est normal.`);
    else say("Mallory", "Voilà. Ce que le quantique change, c'est uniquement la recherche de r : au lieu de la chercher un essai à la fois, la transformée de Fourier quantique la lit d'un coup dans une superposition. Compare : `echelle ‹bits›`.");
  }
  function scaleCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("tour", "Cette comparaison se fait à la tour de Mallory.")) return;
    if ((x.ni || 0) < TARGETS.length) { out("Factorise d'abord les trois cibles (`indice`).", "sys"); return; }
    let n = num(c); if (!(n >= 4)) n = 2048; if (n > 100000) n = 100000;
    const rows = [4, 6, 64, 512, 2048]; if (!rows.includes(n)) rows.push(n);
    rows.sort((p, q) => p - q);
    const lines = rows.map(b => {
      const e = Math.round(b * Math.log10(2));
      const cl = b <= 40 ? fmtN(Math.pow(2, b)) : "≈ 10^" + e;
      const qu = fmtN(Math.pow(b, 3));
      return `${String(b).padStart(6)} bits   classique ${cl.padStart(14)} essais   quantique ${qu.padStart(16)} portes`;
    });
    out(`Recherche de la période d'un a modulo N de n bits : essais classiques (jusqu'à environ N = 2^n) contre nombre de portes quantiques (ordre de grandeur n³) :`, "sys");
    code(lines.join("\n"));
    out("L'écart est exponentiel contre polynomial : c'est ce qui tue RSA, Diffie-Hellman et les courbes elliptiques. Mais la machine n'existe pas : les estimations pour RSA-2048 parlent de l'ordre du million de qubits physiques bruités, alors que les machines actuelles en comptent quelques centaines à milliers, bien plus fragiles. La question est « quand », pas « si ».", "sys");
    out("(Précision : le meilleur algorithme CLASSIQUE de factorisation n'est pas la recherche de période, il est sous-exponentiel ; mais RSA-2048 lui résiste quand même.)", "sys");
    x.scale = true;
    say("Mallory", "Maintenant, passons aux nouvelles mathématiques : celles que même ma machine ne sait pas attaquer. Salle des treillis, à l'ouest du hall.");
  }

  /* ---------- étape 3 : LWE ---------- */
  function solveCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("treillis", "Les équations sont dans la salle des treillis (ouest du hall).")) return;
    if (!x.scale) { out("Termine d'abord l'étape de Mallory (`indice`).", "sys"); return; }
    const t = tx(c);
    const first = x.A.slice(0, NN);
    if (/sans/.test(t)) {
      const b0 = x.A.map(r => dot(r, x.s));
      const s2 = solveMod(first, b0.slice(0, NN));
      out(`Mêmes vecteurs a que la clé publique, mais SANS bruit : b = ⟨a, s⟩ mod ${Q} exactement. Les ${NN} premières équations :`, "sys");
      code(first.map((r, i) => `${vec(r)} · s = ${b0[i]}  (mod ${Q})`).join("\n"));
      const ok = x.A.filter((r, i) => dot(r, s2) === b0[i]).length;
      out(`Élimination de Gauss modulo ${Q} : **s = ${vec(s2)}**. Vérification sur les ${MM} équations : ${ok}/${MM} exactes. Sans bruit, c'est de l'algèbre linéaire : quelques opérations suffisent, même pour de grandes dimensions.`, "ok");
      x.s0 = true;
    } else if (/avec|bruit/.test(t)) {
      if (!x.s0) { out("Commence par le cas sans bruit : `resoudre sans bruit`.", "sys"); return; }
      const sp = solveMod(first, x.b.slice(0, NN));
      out("Maintenant la vraie clé publique : b = ⟨a, s⟩ + e. Mallory applique la même élimination sur les 4 premières équations :", "sys");
      code(first.map((r, i) => `${vec(r)} · s = ${x.b[i]}  (mod ${Q})`).join("\n"));
      out(`Gauss donne s' = ${vec(sp)}. Contrôle sur les ${MM - NN} équations restantes (résidu = b − ⟨a, s'⟩, centré) :`, "sys");
      const res = x.A.slice(NN).map((r, j) => cen(x.b[NN + j] - dot(r, sp)));
      const good = x.A.slice(NN).map((r, j) => cen(x.b[NN + j] - dot(r, x.s)));
      code(`résidus avec s'      : ${res.map(sgn).join("  ")}\nrésidus avec le vrai s : ${good.map(sgn).join("  ")}`);
      out(`Avec s', les résidus sont n'importe quoi (grands) ; avec le vrai s, ils sont tous dans {−1, 0, +1}. Gauss a pris le bruit pour de l'information et s'est trompé. Pour s'en sortir il faudrait deviner ${Q}^${NN} secrets, ou résoudre un problème de réseau (plus court vecteur) : difficile quand la dimension grandit (des centaines), même pour un ordinateur quantique.`, "ok");
      x.s1 = true;
      out("Le bruit est donc la clé du problème. Voyons comment chiffrer un bit avec cette clé publique : `chiffrer ‹0|1›`.", "sys");
    } else out("`resoudre sans bruit` puis `resoudre avec bruit`.", "err");
  }
  function encryptCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("treillis", "Le chiffrement LWE se fait dans la salle des treillis.")) return;
    if (!x.s1) { out("Comprends d'abord le rôle du bruit (`resoudre sans bruit`, puis `resoudre avec bruit`).", "sys"); return; }
    const m = c.rawArg.match(/\b[01]\b/);
    if (!m) { out("Un seul bit à la fois : `chiffrer 0` ou `chiffrer 1`.", "err"); return; }
    const bit = +m[0];
    const ct = lweEnc(bit, 9000 + (x.ctr = (x.ctr || 0) + 1));
    x.ct = ct;
    out(`Chiffrer le bit ${bit} avec la clé publique : on additionne un sous-ensemble aléatoire des équations (lignes ${ct.sub.map(i => i + 1).join(", ")}) et on ajoute ${bit} × ⌊q/2⌋ = ${bit * HALF} au second membre.`, "sys");
    code(`u = Σ a_i = ${vec(ct.u)}\nv = Σ b_i + ${bit}×${HALF} = ${ct.v}  (mod ${Q})`);
    out(`Chiffré : (u, v). Mallory voit A, b, u et v, mais pas s. Déchiffre avec \`dechiffrer\`.`, "ok");
  }
  function decryptCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("treillis", "Le déchiffrement LWE se fait dans la salle des treillis.")) return;
    if (!x.ct) { out("Chiffre d'abord un bit : `chiffrer 1`.", "err"); return; }
    if (/sans|mallory|devine|hasard|public/.test(tx(c))) {
      const r = rng(555 + (x.ctr || 0)), sg = Array.from({ length: NN }, () => ri(r, 0, Q - 1));
      const d = lweDec(x.ct, sg);
      out(`Mallory essaie avec un secret au hasard s = ${vec(sg)} : v − ⟨u, s⟩ = ${d.d}. Ce nombre ressemble à n'importe quoi : elle décode « ${d.bit} », un pile ou face (le vrai bit était ${x.ct.bit}). Sans s, le chiffré ne dit rien.`, "err");
      return;
    }
    const d = lweDec(x.ct, x.s);
    const nz = x.ct.sub.map(i => x.e[i]);
    out(`Avec la clé secrète s = ${vec(x.s)} : v − ⟨u, s⟩ = ${x.ct.v} − ${dot(x.ct.u, x.s)} ≡ **${d.d}** (mod ${Q}).`, "sys");
    out(`Ce nombre vaut bit × ${HALF} + (somme des bruits e_i des lignes choisies = ${nz.map(sgn).join(" ")} = ${nz.reduce((p, q) => p + q, 0)}). Il est ${Math.abs(d.noise) <= 24 ? "proche de" : "loin de"} ${d.bit ? HALF : 0} : on décode **${d.bit}**.`, "ok");
    if (d.bit === x.ct.bit) {
      out(`C'est le bit chiffré (${x.ct.bit}). Tant que le bruit total reste sous ⌊q/4⌋ = ${Math.floor(Q / 4)}, le destinataire légitime ne se trompe jamais.`, "ok");
      x.dec = true; note("lwe"); fig("lwe");
      if (!(x.nbLow && x.nbHigh)) out("Dernier réglage : à quel point le bruit peut-il grossir ? `bruit ‹B›` teste un bruit dans [−B, B] (essaie 1 puis 12).", "sys");
    }
  }
  function noiseCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("treillis", "Le réglage du bruit se fait dans la salle des treillis.")) return;
    if (!x.dec) { out("Chiffre et déchiffre d'abord un bit (`chiffrer 1`, `dechiffrer`).", "sys"); return; }
    const B = num(c);
    if (!(B >= 0 && B <= 40)) { out("Choisis B entre 0 et 40 : `bruit 1`, `bruit 12`…", "err"); return; }
    const r = rng(777 + B), e2 = x.A.map(() => ri(r, -B, B));
    const b2 = x.A.map((row, i) => mod(dot(row, x.s) + e2[i], Q));
    let fail = 0, worst = 0;
    for (let mask = 1; mask < 1 << MM; mask++) {
      const sub = []; for (let i = 0; i < MM; i++) if (mask & (1 << i)) sub.push(i);
      let tot = 0; sub.forEach(i => tot += e2[i]); worst = Math.max(worst, Math.abs(tot));
      for (const bit of [0, 1]) {
        const u = Array.from({ length: NN }, (_, j) => mod(sub.reduce((t, i) => t + x.A[i][j], 0), Q));
        const v = mod(sub.reduce((t, i) => t + b2[i], 0) + bit * HALF, Q);
        if (lweDec({ u, v }, x.s).bit !== bit) fail++;
      }
    }
    const tot = 2 * ((1 << MM) - 1);
    out(`Bruit tiré dans [−${B}, ${B}] : e = ${vec(e2)}. On chiffre les ${(1 << MM) - 1} sous-ensembles possibles, pour 0 et pour 1 (${tot} chiffrés), et on déchiffre avec la vraie clé :`, "sys");
    out(`Bruit total maximal observé : ${worst} (limite de décodage ≈ ${Math.floor(Q / 4)}). Déchiffrements ratés : **${fail}/${tot}**.`, fail ? "err" : "ok");
    if (B === 0) out("B = 0 : plus aucun échec, mais plus aucune sécurité non plus : c'est le cas « sans bruit », que Gauss résout tout seul.", "sys");
    else if (!fail) { out("Petit bruit : le destinataire déchiffre toujours. Mais plus le bruit est petit, plus l'attaquant a de chances (dans de vraies dimensions, le bruit est calibré au plus juste).", "sys"); if (B >= 1) x.nbLow = true; }
    else { out("Trop de bruit : même Bob, qui connaît s, se trompe. Il faut un bruit assez grand pour cacher s, mais assez petit pour décoder. C'est le compromis central de LWE (et la raison des choix de paramètres de ML-KEM).", "err"); x.nbHigh = true; }
    if (x.nbLow && x.nbHigh && !x.lweSaid) { x.lweSaid = true; out("Tu maîtrises le compromis. Direction la passerelle (sud du hall) : Alice et Bob ont besoin d'une clé.", "ok"); }
  }

  /* ---------- étape 4 : hybride ---------- */
  const kclOf = () => modpow(modpow(DHG, DH_A, DHP), DH_B, DHP);
  function pqBits() { const r = rng(4242); let n = 0; for (let i = 0; i < 32; i++) n = n * 2 + (i === 0 ? 1 : (r() < 0.5 ? 1 : 0)); return n; }
  const kpqHex = () => pqBits().toString(16).padStart(8, "0");
  const keyOf = (mode, kcl, kpq) => sha256(mode === "classique" ? "DH|" + kcl : mode === "postquantique" ? "PQ|" + kpq : "HYB|" + kcl + "|" + kpq);
  function exchangeCmd() {
    const x = F(); if (!started()) return;
    if (!inRoom("passerelle", "L'échangeur est à la passerelle (sud du hall).")) return;
    if (!lweDone()) { out("Il te faut d'abord maîtriser les treillis (`indice`).", "sys"); return; }
    const A = modpow(DHG, DH_A, DHP), B = modpow(DHG, DH_B, DHP);
    out("Tuyau 1, échange classique (Diffie-Hellman jouet) :", "sys");
    code(`p = ${DHP}, g = ${DHG}\nAlice envoie A = g^a mod p = ${A}\nBob envoie   B = g^b mod p = ${B}\nclé commune K_cl = B^a = A^b mod p = ${kclOf()}`);
    out("Tuyau 2, échange post-quantique (LWE du treillis) : Alice tire 32 bits au hasard et les chiffre un à un avec la clé publique de Bob ; Bob les déchiffre avec s.", "sys");
    const bits = pqBits().toString(2).padStart(32, "0").split("").map(Number);
    let okAll = true; const cts = bits.map((bt, i) => { const ct = lweEnc(bt, 31000 + i); if (lweDec(ct, x.s).bit !== bt) okAll = false; return ct; });
    code(`32 chiffrés LWE (u, v) envoyés, par exemple le premier : u = ${vec(cts[0].u)}, v = ${cts[0].v}\nBob les déchiffre : ${okAll ? "32/32 bits retrouvés" : "erreur de décodage"}\nclé commune K_pq = ${kpqHex()} (32 bits ; en vrai 256 bits)`);
    x.exch = true;
    out("Deux secrets partagés, K_cl et K_pq. Comment en faire UNE clé de session ? `deriver ‹classique|postquantique|hybride›`.", "ok");
  }
  function deriveCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("passerelle", "La dérivation se fait à la passerelle.")) return;
    if (!x.exch) { out("Fais d'abord passer les deux échanges (`echanger`).", "sys"); return; }
    const t = tx(c);
    const mode = /hybrid|combin|deux/.test(t) ? "hybride" : /post|pq|reseau|kem|lwe/.test(t) ? "postquantique" : /class|dh|ecdh/.test(t) ? "classique" : null;
    if (!mode) { out("Quel mode ? `deriver classique`, `deriver postquantique` ou `deriver hybride`.", "err"); return; }
    x.mode = mode; x.lastSim = null;
    const K = keyOf(mode, kclOf(), kpqHex());
    const how = { classique: `K = SHA-256("DH|" + K_cl)`, postquantique: `K = SHA-256("PQ|" + K_pq)`, hybride: `K = SHA-256("HYB|" + K_cl + "|" + K_pq)` }[mode];
    out(`Mode ${mode} :`, "sys");
    code(`${how}\n= ${K}`);
    out(mode === "hybride" ? "Les deux secrets entrent dans le hachage : retrouver K exige de connaître K_cl ET K_pq. (En vrai on utilise une dérivation HKDF, et on lie aussi le transcript.)" : mode === "classique" ? "Un seul secret : si Diffie-Hellman tombe, la clé tombe. C'est l'état actuel de Port-443 : rien ne protège contre la récolte." : "Un seul secret, post-quantique : sûr tant que les réseaux tiennent. Mais ces algorithmes sont jeunes (un candidat, SIKE, est tombé en 2022).", mode === "hybride" ? "ok" : "sys");
    fig("hybride");
    out("Teste-le face à Mallory : `simuler shor`, `simuler maths`, `simuler tout`, `simuler aucune`.", "sys");
  }
  function simulateCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("passerelle", "Mallory attaque l'échange à la passerelle.")) return;
    if (!x.mode) { out("Dérive d'abord une clé : `deriver hybride`.", "sys"); return; }
    const t = tx(c);
    const sc = /tout|deux/.test(t) ? "tout" : /shor|quant/.test(t) ? "shor" : /math|faille|reseau|lattice/.test(t) ? "maths" : /aucun|rien|normal/.test(t) ? "aucune" : null;
    if (!sc) { out("Quel scénario ? `simuler shor` (ordinateur quantique), `maths` (faille dans le mécanisme post-quantique), `tout` ou `aucune`.", "err"); return; }
    const mode = x.mode, kcl = kclOf(), kpq = kpqHex(), K = keyOf(mode, kcl, kpq);
    const needCl = mode !== "postquantique", needPq = mode !== "classique";
    const knowCl = sc === "shor" || sc === "tout", knowPq = sc === "maths" || sc === "tout";
    const title = { shor: "Mallory dispose d'un ordinateur quantique : Shor retrouve l'exposant de Diffie-Hellman (boîte noire simulée : le jeu lui donne a).", maths: "Quelqu'un publie une attaque mathématique contre le mécanisme post-quantique (comme SIKE en 2022) : Mallory connaît K_pq (boîte noire).", tout: "Les deux sont cassés : un ordinateur quantique ET une faille dans le post-quantique.", aucune: "Aucune capacité exceptionnelle : Mallory n'a que ses disques et un PC classique." }[sc];
    out(title, "sys");
    let mcl = needCl ? (knowCl ? kcl : null) : "-", mpq = needPq ? (knowPq ? kpq : null) : "-";
    const unknown = [mcl === null ? "cl" : null, mpq === null ? "pq" : null].filter(Boolean);
    let found = false, key = null, tries = 0;
    if (!unknown.length) { key = keyOf(mode, mcl, mpq); found = key === K; }
    else if (unknown.length === 1) {
      const u = unknown[0];
      for (tries = 0; tries < GUESS && !found; tries++) {
        const kk = u === "cl" ? keyOf(mode, tries, mpq) : keyOf(mode, mcl, tries.toString(16).padStart(8, "0"));
        if (kk === K) { found = true; key = kk; }
      }
      if (!found) { key = keyOf(mode, u === "cl" ? GUESS : mcl, u === "cl" ? mpq : GUESS.toString(16).padStart(8, "0")); }
    } else { key = sha256("au hasard"); }
    out(`Mallory sait : K_cl ${needCl ? (knowCl ? "✔" : "✘") : "(inutile ici)"} · K_pq ${needPq ? (knowPq ? "✔" : "✘") : "(inutile ici)"}.`, "sys");
    if (unknown.length === 1) out(`Pour la valeur qui lui manque, elle essaie ${fmtN(GUESS)} possibilités (${unknown[0] === "cl" ? "2^24" : "2^32"} dans ce jouet ; 2^128 à 2^256 en vrai) : ${found ? "trouvé" : "aucune ne convient"}.`, "sys");
    else if (unknown.length === 2) out("Il lui manque les deux secrets : elle tente une clé au hasard.", "sys");
    code(`clé d'Alice et Bob : ${K.slice(0, 32)}…\nclé de Mallory     : ${key.slice(0, 32)}…`);
    if (found) out(`Les clés sont identiques : le trafic enregistré est lisible. **Clé de session compromise** (mode ${mode}).`, "err");
    else out(`Les clés diffèrent : le trafic enregistré reste illisible. **Clé de session sûre** (mode ${mode}).`, "ok");
    x.lastSim = { mode, sc, found };
    if (mode === "hybride" && !found) { if (sc === "shor") x.hs = true; if (sc === "maths") x.hm = true; }
    if (mode === "classique" && sc === "shor" && found) out("C'est exactement le scénario « récolter maintenant, déchiffrer plus tard » : tout ce qui a été enregistré s'ouvre.", "err");
    if (mode === "postquantique" && sc === "maths" && found) out("Pari risqué : un algorithme jeune seul peut tomber. L'hybride évite de parier sur un seul cheval.", "err");
    if (mode === "hybride" && sc === "tout") out("Si TOUT est cassé, l'hybride ne protège plus : il n'est pas magique, il demande seulement que l'un des deux tienne.", "err");
    fig("hybride");
    if (x.hs && x.hm && !x.hybSaid) { x.hybSaid = true; note("hybride"); out("L'hybride tient face à chaque attaque séparée. Il reste à mesurer ce que cela coûte en octets : la balance (`budget`).", "ok"); say("Maître Ada", "Parfait. Maintenant, pèse le prix : le lien du Phare est étroit."); }
    if (x.hs && x.hm && mode !== "hybride") out("(Dérive le mode hybride pour la suite : `deriver hybride`.)", "sys");
  }

  /* ---------- étape 5 : tailles, agilité, hachage ---------- */
  function sizesCmd() {
    if (!started()) return;
    out("Barème des tailles (octets) :", "sys");
    code(`échange de clés        clé envoyée   réponse\n  X25519                     32        32\n  ML-KEM-768               1184      1088\n  hybride X25519+ML-KEM    1216      1120\nsignatures             clé publique  signature\n  ECDSA P-256                64        64\n  RSA-2048                  256       256\n  ML-DSA-65                1952      3309\n  Falcon-512 (FN-DSA)       897       666\n  SLH-DSA-128s               32      7856`);
    out("Modèle : une poignée de main = la clé du client + la clé du serveur + 3 signatures + 2 clés publiques de certificat. `budget ‹kex› ‹sig›`.", "sys");
  }
  function budgetCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("passerelle", "La balance est à la passerelle (sud du hall).")) return;
    if (!hybDone()) { out("Termine d'abord l'étape hybride (`indice`).", "sys"); return; }
    const t = tx(c).replace(/ /g, "");
    const k = /hybrid/.test(t) ? "hybride" : /mlkem|kyber/.test(t) ? "mlkem" : /x25519|ecdh|classique/.test(t) ? "x25519" : null;
    const s = /mldsa|dilithium/.test(t) ? "mldsa" : /falcon|fndsa/.test(t) ? "falcon" : /slh|sphincs/.test(t) ? "slh" : /ecdsa|ecc/.test(t) ? "ecdsa" : /rsa/.test(t) ? "rsa" : null;
    if (!k || !s) { out("Donne un échange et une signature : `budget hybride ecdsa`. kex : x25519, hybride, mlkem ; sig : ecdsa, rsa, mldsa, falcon, slh.", "err"); return; }
    const K = KEX[k], G_ = SIG[s];
    const kx = K.c + K.s, sg = 3 * G_.sg + 2 * G_.pk, tot = kx + sg;
    const base = KEX.x25519.c + KEX.x25519.s + 3 * SIG.ecdsa.sg + 2 * SIG.ecdsa.pk;
    out(`Configuration : ${K.n} + ${G_.n}`, "title");
    code(`échange de clés : ${K.c} + ${K.s} = ${fmtN(kx)} octets\nsignatures      : 3 × ${G_.sg} + 2 × ${G_.pk} = ${fmtN(sg)} octets\ntotal           : ${fmtN(tot)} octets (${Math.ceil(tot / 1400)} paquet${tot > 1400 ? "s" : ""} de 1 400 octets)\nactuel          : ${fmtN(base)} octets · facteur ×${(tot / base).toFixed(1)}\nbudget du Phare : ${fmtN(PHARE_MAX)} octets`);
    const day = tot * 2000000 / 1e9;
    out(`À 2 millions de poignées de main par jour : ${day.toFixed(1)} Go de trafic de handshake par jour avec cette configuration (contre ${(base * 2000000 / 1e9).toFixed(1)} Go aujourd'hui).`, "sys");
    const problems = [];
    if (!K.pq) problems.push("l'échange de clés n'est pas post-quantique : la récolte reste possible");
    else if (!K.hyb) problems.push("l'échange post-quantique seul n'est pas hybride : on parie tout sur un algorithme jeune");
    if (tot > PHARE_MAX) problems.push(`${fmtN(tot)} octets dépassent le budget de ${fmtN(PHARE_MAX)}`);
    if (problems.length) { out("Refusé : " + problems.join(" ; ") + ".", "err"); return; }
    x.budgetOK = true; x.cfg = k + "+" + s; note("tailles");
    out("Accepté : échange hybride, dans le budget.", "ok");
    if (!G_.pq) out("Les signatures restent classiques : acceptable pour des certificats de courte durée (la falsification exige une machine en temps réel, pas un enregistrement), mais à migrer à terme. Pour cela, il faut de l'agilité.", "sys");
    else out("Signatures post-quantiques compactes, mais Falcon est délicat à implémenter (arithmétique flottante) : à manier avec soin.", "sys");
    fig("hybride");
    say("Maître Ada", "Retourne au hall, au banc des protocoles : je veux savoir si notre format de message sait changer d'algorithme sans qu'on réécrive tout.");
  }
  const SIGBYTES = n => { let s = ""; for (let i = 0; s.length < n * 2; i++) s += sha256("mldsa:" + i); return s.slice(0, n * 2); };
  function migrateCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("hall", "Le banc des protocoles est dans le hall.")) return;
    if (!x.budgetOK) { out("Pèse d'abord une configuration à la balance (`indice`).", "sys"); return; }
    const t = tx(c);
    const body = "VIREMENT 12 PIECES", bh = [...body].map(ch => ch.charCodeAt(0).toString(16).padStart(2, "0")).join("");
    const sig = SIGBYTES(3309), wire = sig + bh;
    if (/v1|1|fixe/.test(t) && !/v2|2/.test(t)) {
      const sRead = wire.slice(0, 512), bRead = wire.slice(512, 512 + bh.length);
      out("Format v1 (champ signature de 256 octets fixes) : on y envoie une signature ML-DSA-65 de 3 309 octets.", "sys");
      code(`serveur lit  signature : ${sRead.slice(0, 24)}… (256 octets sur 3 309)\nserveur lit  corps     : ${bRead.slice(0, 24)}… (devrait être ${bh.slice(0, 24)}…)\nvérification de la signature : ÉCHEC\nlecture du corps : décalée, déformée`);
      out("La taille de la signature était gravée dans le format : tout est décalé. Corriger cela veut dire changer le format, le parseur, les bases de données, les clients : une réécriture, à faire pour chaque changement d'algorithme.", "err");
      x.m1 = true;
    } else if (/v2|2|agile/.test(t)) {
      const len = 3309, sRead = wire.slice(0, len * 2), bRead = wire.slice(len * 2);
      out("Format v2 : [id algo = ml-dsa-65][longueur = 3309][signature][corps], avec un registre des algorithmes côté serveur.", "sys");
      code(`en-tête : algo = ml-dsa-65, longueur = ${len}\nserveur lit  signature : ${sRead.slice(0, 24)}… (${len} octets)\nserveur lit  corps     : ${bRead === bh ? body : "?"}\nregistre["ml-dsa-65"].verifier(...) : ${sRead === sig ? "OK" : "ÉCHEC"}`);
      out("Le message dit lui-même quel algorithme et quelle longueur. Pour passer de RSA à ML-DSA, on ajoute une ligne au registre ; l'ancien format reste lisible pendant la transition, puis on retire l'ancien algorithme. C'est cela, l'agilité.", "ok");
      x.m2 = true;
    } else { out("`migrer v1` ou `migrer v2`.", "err"); return; }
    if (x.m1 && x.m2) { out("Tu as comparé les deux formats. Reste à utiliser l'agilité pour de bon : la négociation du serveur (`negocier`, `activer ‹suite›`).", "sys"); }
  }
  function negotiateCmd() {
    const x = F(); if (!started()) return;
    if (!inRoom("hall", "La négociation se joue au banc des protocoles (hall).")) return;
    if (!(x.m1 && x.m2)) { out("Compare d'abord les formats v1 et v2 (`migrer v1`, `migrer v2`).", "sys"); return; }
    x.srv = x.srv || ["x25519"];
    const pick = CLIENT.find(s => x.srv.includes(s));
    out(`Le client propose, dans l'ordre : ${CLIENT.join(", ")}.\nLe serveur accepte : ${x.srv.join(", ")}.`, "sys");
    out(`Suite retenue : **${pick}**.`, pick === "x25519" ? "err" : "ok");
    if (pick === "x25519") out("Le serveur n'a rien de post-quantique à offrir : l'échange est classique, donc récoltable. Pour corriger, ni le client ni le format n'ont à changer, seulement le registre du serveur : `activer hybride`.", "err");
    else {
      out(pick === "x25519mlkem768" ? "Échange hybride X25519 + ML-KEM-768 : un changement de configuration, pas de réécriture." : "ML-KEM-768 seul : post-quantique, mais sans filet ; préfère l'hybride pendant la transition.", "ok");
      x.nego = true; note("agilite");
      say("Maître Ada", "Voilà de l'agilité. Dernier cas : les signatures dont on ne veut pas dépendre des maths des réseaux. Passerelle, puis le coffre à l'est.");
    }
  }
  function activateCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("hall", "Le registre du serveur se règle au banc des protocoles (hall).")) return;
    if (!(x.m1 && x.m2)) { out("Compare d'abord les formats v1 et v2 (`migrer v1`, `migrer v2`).", "sys"); return; }
    x.srv = x.srv || ["x25519"];
    const t = tx(c);
    const s = /hybrid|x25519 ?mlkem|combin/.test(t) ? "x25519mlkem768" : /mlkem|kyber/.test(t) ? "mlkem768" : /x25519/.test(t) ? "x25519" : null;
    if (!s) { out("Quelle suite ? `activer hybride` (x25519mlkem768), `activer mlkem` ou `activer x25519`.", "err"); return; }
    if (x.srv.includes(s)) { out(`${s} est déjà au registre.`, "sys"); return; }
    x.srv.push(s);
    out(`Une ligne ajoutée au registre du serveur : ${s}. Registre : ${x.srv.join(", ")}. Relance \`negocier\`.`, "ok");
  }

  /* ---------- Lamport jouet ---------- */
  const SK = Array.from({ length: LB }, (_, i) => [0, 1].map(b => sha256("lamport-sk:" + i + ":" + b + ":port443").slice(0, 16)));
  const PK = SK.map(p => p.map(s => sha256(s).slice(0, 16)));
  const digBits = msg => { const h = sha256(msg).slice(0, LB / 4); return h.split("").map(ch => parseInt(ch, 16).toString(2).padStart(4, "0")).join("").split("").map(Number); };
  const revealed = () => {
    const rev = Array.from({ length: LB }, () => [false, false]);
    (F().sigs || []).forEach(sg => sg.bits.forEach((b, i) => { rev[i][b] = true; }));
    return rev;
  };
  function signCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("coffre", "La serrure de Lamport est dans le coffre (passerelle, puis est).")) return;
    if (!x.nego) { out("Termine d'abord l'étape de l'agilité (`indice`).", "sys"); return; }
    const msg = c.rawArg.trim();
    if (!msg) { out("Signer quoi ? `signer OUVRIR LE COFFRE A NEUF HEURES`", "err"); return; }
    x.sigs = x.sigs || [];
    const bits = digBits(msg);
    const sig = bits.map((b, i) => SK[i][b]);
    x.sigs.push({ msg, bits, sig });
    out(`Condensat de « ${msg} » (${LB} premiers bits de SHA-256) : ${bits.join("")}`, "sys");
    out(`Pour chaque position i, on révèle le secret du bit correspondant (sk_i,0 si le bit vaut 0, sk_i,1 sinon) :`, "sys");
    code(sig.slice(0, 5).map((s, i) => `position ${String(i + 1).padStart(2)} : bit ${bits[i]} → ${s}`).join("\n") + `\n… (${LB - 5} autres positions)`);
    out("Signature produite. Vérifie-la avec la clé publique : `verifier`.", "ok");
    x.lastSig = x.sigs.length - 1;
    const n = x.sigs.length;
    if (n >= 2) {
      const both = revealed().filter(p => p[0] && p[1]).length;
      out(`Attention : tu as réutilisé la même clé (${n} signatures). Les positions dont les DEUX secrets sont désormais publics : **${both}/${LB}**. Tout message dont le condensat ne prend que des valeurs déjà révélées est falsifiable.`, "err");
    }
    fig("lamport");
  }
  function verifyCmd(c) {
    const x = F(); if (!started()) return;
    if (!inRoom("coffre", "La serrure de Lamport est dans le coffre.")) return;
    const forged = /forg|fausse|mallory/.test(tx(c));
    const sg = forged ? x.forged : (x.sigs || [])[x.lastSig];
    if (!sg) { out(forged ? "Il n'y a pas de signature de Mallory à vérifier : `forger`." : "Il n'y a rien à vérifier : `signer ‹message›` d'abord.", "err"); return; }
    const bits = digBits(sg.msg);
    const okPos = sg.sig.filter((s, i) => sha256(s).slice(0, 16) === PK[i][bits[i]]).length;
    out(`Vérification de « ${sg.msg} » : pour chaque position, H(secret révélé) doit égaler l'empreinte publique du bit voulu : ${okPos}/${LB} positions valides.`, okPos === LB ? "ok" : "err");
    if (okPos === LB) out(forged ? "Signature VALIDE… et pourtant tu ne l'as jamais signée : la serrure est trompée." : "Signature valide. Seul le détenteur des secrets a pu la produire ; rien n'est caché derrière cette preuve, sauf la sécurité du hachage.", forged ? "err" : "ok");
  }
  function forgeCmd() {
    const x = F(); if (!started()) return;
    if (!inRoom("coffre", "Mallory rôde autour du coffre.")) return;
    if (!(x.sigs || []).length) { say("Mallory", "Je n'ai rien vu passer : je n'ai aucun secret de ta clé. Fais signer quelque chose."); return; }
    const rev = revealed(), n = x.sigs.length;
    const both = rev.filter(p => p[0] && p[1]).length;
    out(`Mallory a observé ${n} signature${n > 1 ? "s" : ""} : elle connaît ${rev.flat().filter(Boolean).length} secrets sur ${2 * LB} (les deux sur ${both} positions). Elle cherche un ordre à son avantage : « VIREMENT 9999 PIECES A MALLORY ref=k », en variant k, jusqu'à ce que chaque bit du condensat tombe sur un secret connu (${fmtN(FORGE_BUDGET)} essais).`, "sys");
    let found = null;
    for (let k = 0; k < FORGE_BUDGET && !found; k++) {
      const m = "VIREMENT 9999 PIECES A MALLORY ref=" + k, b = digBits(m);
      if (b.every((bit, i) => rev[i][bit])) found = { msg: m, bits: b, k };
    }
    if (n === 1) x.forge1 = true;
    if (!found) {
      out(`Aucun ordre trouvé en ${fmtN(FORGE_BUDGET)} essais. Avec une seule signature, il faudrait un message qui a EXACTEMENT le même condensat (1 chance sur 2^${LB} par essai).${n > 1 ? " Il lui manque encore trop de secrets : une troisième signature en révélerait davantage." : ""}`, "ok");
      if (n === 1) out("Mallory a échoué : une clé de Lamport utilisée UNE fois est sûre (au condensat près). Mais regarde ce que tu lui as donné : la moitié des secrets de la serrure.", "sys");
      return;
    }
    found.sig = found.bits.map((b, i) => SK[i][b]);
    x.forged = found;
    out(`Trouvé après ${fmtN(found.k + 1)} essais : **« ${found.msg} »**. Elle assemble sa signature avec les secrets que tu as toi-même révélés :`, "err");
    out("Vérifie : `verifier forgee`.", "sys");
    if (n >= 2) {
      x.forgeOK = true; note("hashsig");
      out("C'est la raison du « à usage unique » : chaque signature révèle la moitié des secrets de la position ; deux signatures en révèlent davantage, et un adversaire peut recombiner. Les schémas réels (LMS, XMSS, SLH-DSA) utilisent une clé neuve par signature, organisées en arbre de Merkle.", "ok");
      fig("lamport");
    } else out("Avec une seule signature, ce succès n'arrive que parce que le condensat de ce jouet est minuscule (24 bits) : une collision se trouve vite. Avec 256 bits, c'est impossible ; réutilise la clé pour voir le vrai danger.", "sys");
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "La tempête n'est pas encore là, et c'est précisément le moment d'agir. Nous avons inventorié, classé, compris pourquoi RSA tombera et pourquoi AES tiendra. Nos échanges de clés sont hybrides, nos formats agiles, nos signatures longues durées surveillées.");
    say("Ève", "Je continuerai à copier, bien sûr. Mais à partir d'aujourd'hui, mes disques ne contiennent plus que du bruit.");
    say("Mallory", "Je reviendrai quand la machine existera. Si les maths tiennent, je repartirai bredouille.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Ève et ses disques = « récolter maintenant, déchiffrer plus tard ».** L'adversaire n'a pas besoin de la machine aujourd'hui, seulement de stockage. La règle de Mosca (x + y > z) dit si un secret est déjà en danger. L'inventaire du registre est le premier geste réel d'une migration (on parle de CBOM, nomenclature cryptographique).");
    out("**Les bits de sécurité effectifs.** Shor casse RSA et les courbes elliptiques (temps polynomial) ; Grover divise seulement par deux les bits des clés symétriques et des préimages de hachage, d'où AES-256 et SHA-384. Les usages « urgents » du jeu sont ceux qui combinent algorithme asymétrique ET durée longue.");
    out("**L'abaque de Mallory = l'algorithme de Shor.** Factoriser N se ramène à trouver la période r de a^x mod N ; ensuite, pgcd(a^(r/2) ± 1, N), calculé classiquement, donne les facteurs (si r est pair et a^(r/2) ≢ −1). Le quantique n'accélère que la recherche de période, via la transformée de Fourier quantique. Le même mécanisme casse le logarithme discret (Diffie-Hellman, courbes elliptiques).");
    out("**La salle des treillis = LWE.** Des équations bruitées b = ⟨a, s⟩ + e mod q : sans bruit, de l'algèbre linéaire ; avec le bruit, un problème de réseau euclidien qu'aucun algorithme connu (classique ou quantique) ne résout efficacement en grande dimension. ML-KEM (FIPS 203, anciennement Kyber) et ML-DSA (FIPS 204, anciennement Dilithium) en sont dérivés. Le bruit doit rester assez petit pour que le destinataire décode : c'est le compromis des paramètres.");
    out("**Les deux tuyaux d'Alice et Bob = un échange hybride.** K = H(K_classique ‖ K_pq) : il faut casser les deux. Cela couvre à la fois la machine quantique (contre l'algorithme classique) et la faille mathématique (contre l'algorithme jeune). X25519+ML-KEM-768 fait déjà partie de TLS dans de nombreux navigateurs et services.");
    out("**La balance et le banc de protocoles = tailles et agilité.** Les objets post-quantiques pèsent plus lourd (ML-KEM-768 : environ 1 Ko dans chaque sens ; ML-DSA-65 : une signature de 3,3 Ko), d'où l'ordre habituel : échange de clés hybride d'abord, signatures plus tard. Un format avec identifiants d'algorithme et longueurs variables, et un registre négocié, permet de changer d'algorithme par configuration.");
    out("**Le coffre de Lamport = signatures à base de hachage.** Une clé de Lamport ne signe qu'une fois ; réutilisée, elle livre assez de secrets pour forger. LMS et XMSS (avec état) et SLH-DSA (FIPS 205, sans état) en font des arbres de milliers de clés à usage unique. Leur sécurité ne repose que sur le hachage, au prix de signatures volumineuses.");
    out("**Les simplifications du jeu.** (1) Tous les paramètres sont minuscules : un LWE à q = 97 et n = 4 se casse instantanément (ML-KEM-768 travaille en dimension 768 sur des anneaux de polynômes, avec q = 3329, et un chiffrement CCA-sûr). (2) Le chiffrement LWE à un bit est la version pédagogique de Regev ; ML-KEM transporte une clé via une transformation de Fujisaki-Okamoto. (3) La recherche de période est classique, et Shor réel utilise l'exponentiation modulaire quantique et la fraction continue ; le « n³ » est un ordre de grandeur. (4) Le calcul des bits de sécurité effectifs divise par deux la clé symétrique : en pratique Grover se parallélise mal et le NIST juge AES-128 encore acceptable (les recommandations prudentes de type CNSA 2.0 demandent AES-256). (5) Le Diffie-Hellman à 24 bits et la boîte noire « quantique » sont des raccourcis du jeu. (6) La Lamport à 24 bits de condensat est un jouet : avec 256 bits, une seule signature est sûre. (7) Les tailles et le modèle de poignée de main sont approximatifs ; la date z = 15 ans est une hypothèse, pas une prédiction. (8) Aucune machine capable de casser RSA-2048 n'existe aujourd'hui.");
    out("Rappel utile : **la migration post-quantique commence maintenant, parce que l'adversaire récolte déjà : inventorier, protéger d'abord les échanges de clés (en hybride), et rester agile.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    menaces: () => {
      const col = k => (k.q === 0 ? "ft-bad" : k.q < 128 ? "ft-priv" : "ft-ok");
      let body = T(8, 20, "algorithme", "f-b f-s", "start") + T(228, 20, "classique", "f-b f-s", "end") + T(300, 20, "quantique", "f-b f-s", "end") + T(412, 20, "verdict", "f-b f-s", "end") + LN(8, 28, 412, 28);
      ALG_ROWS.forEach((k, i) => {
        const a = algoOf(k), y = 50 + i * 28;
        const nm = { rsa2048: "RSA-2048", ecc: "ECC P-256", aes128: "AES-128", aes256: "AES-256", sha256: "SHA-256 (préimage)", sha384: "SHA-384 (préimage)" }[k];
        const ver = a.q === 0 ? "cassé (Shor)" : a.q < 128 ? "affaibli (Grover)" : "tient (Grover)";
        body += T(8, y, nm, "f-s", "start") + T(228, y, String(a.c), "f-s", "end") + T(300, y, a.q === 0 ? "≈ 0" : String(a.q), col(a) + " f-b f-s", "end") + T(412, y, ver, col(a) + " f-s", "end");
      });
      body += LN(8, 205, 412, 205) + T(8, 226, "Seuil prudent : 128 bits effectifs.", "f-s", "start") + T(8, 244, "Mosca : x + y &gt; z ⇒ la donnée récoltée est déjà perdue.", "f-s", "start");
      return { cap: "Ce que le quantique fait aux algorithmes : Shor anéantit l'asymétrique, Grover ne divise les bits symétriques que par deux.", svg: SVG(256, "Menaces par type d'algorithme", body) };
    },
    periode: () => {
      const L = F().fig, nb = Math.min(16, 2 * L.r + 2);
      let bars = "";
      for (let i = 1; i <= nb; i++) {
        const v = modpow(L.a, i, L.N), h = Math.max(4, Math.round(v / L.N * 70)), x0 = 14 + (i - 1) * 24;
        bars += `<rect x="${x0}" y="${100 - h}" width="16" height="${h}" rx="2" fill="${v === 1 ? "var(--ok)" : "var(--you)"}"/>` + T(x0 + 8, 112, String(i), "f-s") + T(x0 + 8, 96 - h, String(v), "f-s");
      }
      const body = T(8, 18, `a^x mod N, avec a = ${L.a} et N = ${L.N}`, "f-b f-s", "start") + bars + LN(10, 100, 412, 100) +
        T(8, 134, `période r = ${L.r}  (premier retour à 1, en vert)`, "ft-ok f-s", "start") +
        T(8, 152, `a^(r/2) = ${L.a}^${L.r / 2} mod ${L.N} = ${L.t}`, "f-s", "start") +
        T(8, 170, `pgcd(${L.t - 1}, ${L.N}) = ${L.g1}   pgcd(${L.t + 1}, ${L.N}) = ${L.g2}`, "f-s", "start") +
        T(8, 188, `${L.N} = ${L.g1} × ${L.g2}`, "ft-priv f-b", "start") +
        T(8, 210, "Seule la recherche de r est quantique ; le pgcd est classique.", "ft-pub f-s", "start");
      return { cap: "Shor : factoriser N revient à trouver la période de a^x mod N. Le quantique accélère cette recherche, le reste est du pgcd.", svg: SVG(222, "Recherche de période pour factoriser", body) };
    },
    lwe: () => {
      const x = F(), X = v => 20 + v * (380 / 96);
      let body = T(8, 18, `b = ⟨a, s⟩ + e  (mod ${Q})   ex. ligne 1 : b = ${x.b[0]}, e = ${sgn(x.e[0])}`, "f-b f-s", "start") +
        R(8, 30, 196, 62, "f-ok") + T(106, 48, "SANS bruit", "ft-ok f-b f-s") + T(106, 64, "Gauss résout : s exact", "f-s") + T(106, 80, "(algèbre linéaire)", "f-s") +
        R(216, 30, 196, 62, "f-bad") + T(314, 48, "AVEC bruit", "ft-bad f-b f-s") + T(314, 64, "Gauss donne s' ≠ s", "f-s") + T(314, 80, "résidus incohérents", "f-s");
      body += T(8, 114, "déchiffrement : d = v − ⟨u, s⟩ = bit × 48 + bruit", "f-s", "start");
      body += `<rect x="${X(0)}" y="126" width="${X(24) - X(0)}" height="18" fill="var(--ok)" opacity=".35"/><rect x="${X(24)}" y="126" width="${X(72.5) - X(24)}" height="18" fill="var(--you)" opacity=".35"/><rect x="${X(72.5)}" y="126" width="${X(96) - X(72.5)}" height="18" fill="var(--ok)" opacity=".35"/>` +
        T(X(0) + 1, 158, "0", "f-s", "start") + T(X(48), 158, "48", "f-s") + T(X(96), 158, "96", "f-s", "end") + T(X(10), 140, "bit 0", "f-s") + T(X(48), 140, "bit 1", "f-s") + T(X(86), 140, "bit 0", "f-s");
      if (x.ct) {
        const d = lweDec(x.ct, x.s);
        body += `<line x1="${X(d.d)}" y1="120" x2="${X(d.d)}" y2="148" stroke="var(--bad)" stroke-width="2"/>` + T(Math.min(Math.max(X(d.d), 40), 380), 176, `d = ${d.d} → bit ${d.bit}, bruit ${sgn(d.noise)}`, "ft-bad f-s");
      } else body += T(210, 176, "chiffre un bit pour voir où tombe d", "f-s");
      body += T(8, 204, "Bruit trop grand : d sort de sa zone, même Bob se trompe.", "f-s", "start") + T(8, 222, "Bruit trop petit : l'attaquant résout.", "f-s", "start");
      return { cap: "LWE jouet : sans bruit, de l'algèbre ; avec bruit, le secret est caché. Le bruit total doit rester dans la bonne zone pour que le destinataire décode.", svg: SVG(234, "LWE avec bruit", body) };
    },
    hybride: () => {
      const x = F(), ls = x.lastSim;
      const body = R(8, 20, 84, 100, "f-pub") + T(50, 44, "Alice", "f-b ft-pub") + R(328, 20, 84, 100, "f-priv") + T(370, 44, "Bob", "f-b ft-priv") +
        T(210, 36, "ECDH (classique)", "f-s ft-bad") + AR(92, 44, 328, 44, "f-bad", true) + T(210, 62, "K_cl : tombe avec Shor", "f-s") +
        T(210, 86, "ML-KEM (réseaux)", "f-s ft-ok") + AR(92, 94, 328, 94, "", true) + T(210, 112, "K_pq : repose sur LWE", "f-s") +
        AR(50, 120, 150, 150, "f-ln") + AR(370, 120, 270, 150) +
        R(110, 150, 200, 44, "f-ok") + T(210, 170, "K = SHA-256(K_cl ‖ K_pq)", "f-b ft-ok") + T(210, 186, x.mode ? `mode : ${x.mode}` : "mode : à dériver", "f-s") +
        (ls ? T(210, 216, `attaque « ${ls.sc} » : ${ls.found ? "clé compromise" : "clé sûre"}`, (ls.found ? "ft-bad" : "ft-ok") + " f-b f-s") : T(210, 216, "casser UN seul des deux ne suffit pas", "f-s")) +
        T(210, 236, "il suffit que l'un des deux tienne", "f-s ft-pub");
      return { cap: "Échange hybride : deux secrets, un hachage. Mallory doit casser les deux mécanismes, pas seulement l'un.", svg: SVG(248, "Échange hybride", body) };
    },
    lamport: () => {
      const rev = revealed(), n = (F().sigs || []).length, both = rev.filter(p => p[0] && p[1]).length;
      let g = "";
      for (let i = 0; i < LB; i++) for (let b = 0; b < 2; b++) {
        const x0 = 28 + i * 16, y0 = 40 + b * 20;
        g += `<rect x="${x0}" y="${y0}" width="12" height="14" rx="2" fill="${rev[i][b] ? "var(--bad)" : "none"}" stroke="${rev[i][b] ? "var(--bad)" : "var(--ok)"}" stroke-width="1.2"/>`;
      }
      const body = T(8, 18, `Clé de Lamport : ${LB} positions × 2 secrets`, "f-b f-s", "start") + T(6, 52, "0", "f-s", "start") + T(6, 72, "1", "f-s", "start") + g +
        T(8, 100, "rouge : secret révélé · vert vide : encore secret", "f-s", "start") +
        T(8, 124, `signatures : ${n} · positions aux 2 secrets publics : ${both}/${LB}`, n > 1 ? "ft-bad f-s" : "f-s", "start") +
        T(8, 148, "signer : révéler le secret du bit ; vérifier : hacher", "f-s", "start") +
        T(8, 170, "à 256 bits : signature = 256 × 32 = 8 192 octets", "f-s", "start") +
        T(8, 190, "réutiliser la clé : le 2e secret fuit, forgeable", "ft-bad f-s", "start");
      return { cap: "Signature de Lamport : une clé = une signature. Chaque signature rend publics la moitié des secrets ; la deuxième aide à forger.", svg: SVG(200, "Signature de Lamport", body) };
    },
  };

  GAMES.pqc = {
    id: "pqc", order: 18, title: "La Tempête Quantique", pageTitle: "PQC Quest", subtitle: "aventure textuelle · cryptographie post-quantique",
    blurb: "Un ordinateur quantique viendra un jour, et Mallory enregistre déjà. Prépare la migration de Port-443.",
    concept: "Cryptographie post-quantique",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    refig(name) { fig(name); },
    figAlias: { menaces: ["menace", "tableau", "algorithmes", "grover"], periode: ["shor", "factorisation", "factoriser"], lwe: ["reseau", "reseaux", "bruit"], hybride: ["hybrid", "echange"], lamport: ["signature", "hachage", "signer"] },
    help: "Spécifiques : `evaluer ‹algo›` · `classer ‹usage› ‹urgence›` · `periode ‹a›` · `factoriser ‹a›` · `echelle ‹bits›` · `resoudre sans|avec bruit` · `chiffrer ‹bit›` · `dechiffrer` · `bruit ‹B›` · `echanger` · `deriver ‹mode›` · `simuler ‹scénario›` · `tailles` · `budget ‹kex› ‹sig›` · `migrer v1|v2` · `negocier` · `activer ‹suite›` · `signer ‹message›` · `verifier` · `forger`",
    verbs: {
      evaluate: { words: ["evaluer", "mesurer", "bits"], run: evaluate },
      classify: { words: ["classer", "classifier", "ranger"], run: classify },
      period: { words: ["periode", "orbite"], run: periodCmd },
      factor: { words: ["factoriser", "deduire", "extraire"], run: factorCmd },
      scale: { words: ["echelle", "comparer"], run: scaleCmd },
      solve: { words: ["resoudre", "gauss", "eliminer"], run: solveCmd },
      encrypt: { words: ["chiffrer", "chiffre"], run: encryptCmd },
      decrypt: { words: ["dechiffrer", "dechiffre"], run: decryptCmd },
      noise: { words: ["bruit"], run: noiseCmd },
      exchange: { words: ["echanger"], run: exchangeCmd },
      derive: { words: ["deriver", "derive"], run: deriveCmd },
      simulate: { words: ["simuler", "attaquer"], run: simulateCmd },
      sizes: { words: ["tailles", "taille", "bareme"], run: sizesCmd },
      budget: { words: ["budget", "peser"], run: budgetCmd },
      migrate: { words: ["migrer"], run: migrateCmd },
      negotiate: { words: ["negocier", "handshake"], run: negotiateCmd },
      activate: { words: ["activer"], run: activateCmd },
      sign: { words: ["signer"], run: signCmd },
      check: { words: ["verifier", "controler"], run: verifyCmd },
      forge: { words: ["forger", "falsifier", "contrefaire"], run: forgeCmd },
    },
    intro() {
      const x = F();
      x.ev = {}; x.cls = {}; x.ni = 0; x.sigs = []; x.ctr = 0; x.srv = ["x25519"];
      genLwe();
      out("La Tempête Quantique", "title");
      out("Port-443 : les prévisions de la Guilde sont formelles. Un jour, quelque part, quelqu'un construira un ordinateur quantique capable de défaire RSA et les courbes elliptiques. Personne ne sait quand. Mais Mallory et Ève, elles, ne perdent pas de temps : elles enregistrent déjà tout ce qui passe, pour le déchiffrer plus tard.\nMaître Ada te charge de préparer la migration. Tout se passe sur des données fictives et des nombres minuscules, pour que tu puisses voir chaque rouage.", "");
      out("Tu disposes d'une calculatrice de poche : `calc 2^10 mod 21`.", "sys");
    },
  };
})();
