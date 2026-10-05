"use strict";
/* L'Atelier des Erreurs : les erreurs d'usage classiques de la cryptographie.
   Tout est calculé pour de vrai, avec des primitives JOUETS bâties sur le SHA-256 du moteur
   (flux, chiffrement par blocs de Feistel, HMAC sur texte hexadécimal, générateur congruentiel). */
(function () {
  const F = () => f();

  /* ---------- petits outils sur les octets ---------- */
  const enc = s => Array.from(new TextEncoder().encode(s));
  const toHex = b => b.map(x => x.toString(16).padStart(2, "0")).join("");
  const fromHex = h => (h.match(/../g) || []).map(x => parseInt(x, 16));
  const xorb = (a, b) => a.slice(0, Math.min(a.length, b.length)).map((v, i) => v ^ b[i]);
  const show = b => b.map(v => (v >= 32 && v < 127 ? String.fromCharCode(v) : "·")).join("");
  const txt = b => b.map(v => String.fromCharCode(v)).join("");
  const rows = (b, n) => { const r = []; for (let i = 0; i < b.length; i += n) r.push(toHex(b.slice(i, i + n)).replace(/(..)(?=.)/g, "$1 ")); return r.join("\n"); };
  const num = n => Math.round(n).toLocaleString("fr-FR");

  /* flux jouet : blocs de SHA-256(clé | nonce | compteur) mis bout à bout (rôle de ChaCha20 ou AES-CTR) */
  function keystream(key, nonce, n) {
    const o = []; let c = 0;
    while (o.length < n) o.push(...fromHex(sha256(key + "|" + nonce + "|" + (c++))));
    return o.slice(0, n);
  }
  const stream = (key, nonce, bytes) => xorb(bytes, keystream(key, nonce, bytes.length));

  /* HMAC jouet : même construction à deux passes (clé XOR ipad/opad), mais sur du texte hexadécimal */
  function hmac(key, msg) {
    let kb = enc(key); if (kb.length > 64) kb = fromHex(sha256(key));
    while (kb.length < 64) kb.push(0);
    const ik = toHex(kb.map(v => v ^ 0x36)), ok = toHex(kb.map(v => v ^ 0x5c));
    return sha256(ok + sha256(ik + toHex(enc(msg))));
  }

  /* chiffrement par blocs jouet : réseau de Feistel à 4 tours, blocs de 8 octets, fonction de tour = SHA-256 */
  const FR = (key, r, R) => fromHex(sha256(key + "|" + r + "|" + toHex(R))).slice(0, 4);
  function blockEnc(key, blk) {
    let L = blk.slice(0, 4), R = blk.slice(4);
    for (let r = 0; r < 4; r++) { const nl = R, nr = xorb(L, FR(key, r, R)); L = nl; R = nr; }
    return L.concat(R);
  }
  function blockDec(key, blk) {
    let L = blk.slice(0, 4), R = blk.slice(4);
    for (let r = 3; r >= 0; r--) { const oR = L, oL = xorb(R, FR(key, r, oR)); L = oL; R = oR; }
    return L.concat(R);
  }
  const chunk8 = b => { const o = []; for (let i = 0; i < b.length; i += 8) o.push(b.slice(i, i + 8)); return o; };
  const pad8 = s => { while (s.length % 8) s += "."; return s; };

  /* hasard reproductible (IV, essais) */
  function rnd() {
    const x = F();
    let t = x.seed = (x.seed + 0x6D2B79F5) | 0;
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /* ---------- données fictives de l'atelier ---------- */
  const K1 = "cle-atelier-1", M1 = "RENDEZ-VOUS AU PORT 443 A MINUIT", M2 = "OK, LE CODE DU COFFRE EST 7319 !";
  const K3 = "cle-atelier-3", KM3 = "cle-mac-3", M3 = "VIRER 10 EUROS A BOB";
  const K4 = ["cle-mac-4", "cle-mac-4-bis"], MSG4 = "OUVRIR LA PORTE";
  const LM = 65521, LA = 17093, LC = 12345, LSEED = 4242; // générateur congruentiel : x' = (a·x + c) mod m
  const SECRET_RNG = "graine-secrete-du-systeme";
  const KH = sha256("cle-codee-en-dur").slice(0, 16), SECRET_KEY = sha256("cle-gardee-dans-le-coffre").slice(0, 16);
  const BACKUP = "PORT443: sauvegarde de la Guilde. Cle du grenier = 8841. Recette de la tarte = a retrouver.";
  const CARNET = "PORT443: carnet des comptes. Compte de Bob = bob / pas-de-panique-42.";
  const PW_OLD = "soleil", PW_NEW = "trois-poules-rouges-sur-la-grande-tour";
  const LIST = ["azerty", "soleil", "port443", "password", "123456", "qwerty", "bonjour", "motdepasse", "doudou", "football", "letmein", "admin"];
  const ITER = 3000;
  const P7 = "la recette secrete de la tarte de la guilde est cachee sous la grande horloge de port quatre cent quarante trois et personne ne doit jamais la dire a mallory qui cherche partout depuis des semaines le moindre indice";
  const K7 = "tour";
  const C7 = () => enc(P7).map((v, i) => v ^ K7.charCodeAt(i % K7.length));
  const ECB_KEY = "cle-registre-ecb", REG_N1 = "abcdef", REG_N2 = "xxxxadmin...";

  /* ---------- cas 1 : réutilisation de nonce ---------- */
  const n1 = () => F().n1fix ? ["N-0002", "N-0003"] : ["N-0001", "N-0001"];
  const C1 = () => stream(K1, n1()[0], enc(M1)), C2 = () => stream(K1, n1()[1], enc(M2));
  const X12 = () => xorb(C1(), C2());

  /* ---------- cas 2 : ECB / CBC ---------- */
  function issue(name) {
    const x = F(), p = pad8("nom=" + name + ";role=client"), pb = enc(p);
    let blocks;
    if (!x.e_fix) blocks = chunk8(pb).map(b => toHex(blockEnc(ECB_KEY, b)));
    else {
      const iv = Array.from({ length: 8 }, () => Math.floor(rnd() * 256)); blocks = [toHex(iv)]; let prev = iv;
      for (const b of chunk8(pb)) { const c = blockEnc(ECB_KEY, xorb(b, prev)); blocks.push(toHex(c)); prev = c; }
    }
    x.toks.push({ name, blocks, plain: x.e_fix ? ["IV"].concat(chunk8(pb).map(txt)) : chunk8(pb).map(txt) });
    if (x.toks.length > 8) x.toks.shift();
    return x.toks[x.toks.length - 1];
  }
  function serverRead(blocks) {
    const x = F(), bs = blocks.map(fromHex);
    let pl;
    if (!x.e_fix) pl = bs.map(b => blockDec(ECB_KEY, b));
    else { pl = []; for (let i = 1; i < bs.length; i++) pl.push(xorb(blockDec(ECB_KEY, bs[i]), bs[i - 1])); }
    const flat = [].concat(...pl), t = txt(flat);
    const ok = /^nom=[A-Za-z0-9._-]*;role=[a-z]+\.*$/.test(t);
    const m = ok && t.match(/;role=([a-z]+)/);
    return { t, shown: show(flat), ok, role: m ? m[1] : null };
  }

  /* ---------- cas 3 : malléabilité / MAC ---------- */
  const m3nonce = () => F().m_fix ? "N-0101" : "N-0100";
  const m3ct = () => stream(K3, m3nonce(), enc(M3));
  const m3tag = () => hmac(KM3, m3nonce() + "|" + toHex(m3ct())).slice(0, 16);

  /* ---------- cas 4 : comparaison non constante ---------- */
  const tag4 = () => hmac(K4[F().t_fix ? 1 : 0], MSG4).slice(0, 8);
  function time4(guess) {
    const t = tag4(), jit = (parseInt(sha256("j" + guess).slice(0, 4), 16) % 9) - 4;
    if (F().t_fix) return 160 + jit;
    let n = 0; while (n < 4 && guess.slice(2 * n, 2 * n + 2) === t.slice(2 * n, 2 * n + 2)) n++;
    return 100 + 25 * n + jit;
  }

  /* ---------- cas 5 : générateur congruentiel / CSPRNG jouet ---------- */
  function nextTok() {
    const x = F();
    if (x.r_fix) return parseInt(sha256("csprng|" + SECRET_RNG + "|" + (x.cnt++)).slice(0, 8), 16);
    x.lstate = (LA * x.lstate + LC) % LM; return x.lstate;
  }
  const peekTok = () => { const x = F(); return x.r_fix ? parseInt(sha256("csprng|" + SECRET_RNG + "|" + x.cnt).slice(0, 8), 16) : (LA * x.lstate + LC) % LM; };
  const fmtTok = v => F().r_fix ? v.toString(16).padStart(8, "0") : String(v).padStart(5, "0");

  /* ---------- cas 6 : clé en dur, dérivation ---------- */
  const stretch = s => { let h = sha256(s); for (let i = 1; i < ITER; i++) h = sha256(h + s); return h; };
  const derive = pw => F().k_fix2 ? stretch("sel-carnet|" + pw).slice(0, 32) : sha256(pw).slice(0, 32);
  const curPw = () => F().k_fix2 ? PW_NEW : PW_OLD;
  const curKeyBackup = () => F().k_fix1 ? SECRET_KEY : KH;
  const backupCt = () => stream(curKeyBackup(), "N-6", enc(BACKUP));
  const carnetCt = () => stream(derive(curPw()), "N-7", enc(CARNET));

  /* ---------- cas 7 : maison ---------- */
  function ic(L) {
    const c = C7(); let tot = 0;
    for (let i = 0; i < L; i++) {
      const col = c.filter((_, j) => j % L === i), cnt = {}; col.forEach(b => cnt[b] = (cnt[b] || 0) + 1);
      const n = col.length; tot += Object.values(cnt).reduce((s, v) => s + v * (v - 1), 0) / (n * (n - 1));
    }
    return tot / L;
  }

  /* ---------- carnet ---------- */
  const notes = {
    nonce: ["Nonce : un numéro à usage unique", "Un chiffrement par flux calcule un flux pseudo-aléatoire à partir de la clé ET d'un nonce, puis le XOR avec le message. Si deux messages partagent le même couple (clé, nonce), les deux utilisent le même flux : C1 ⊕ C2 = M1 ⊕ M2, la clé disparaît du calcul, et deviner un mot de l'un révèle l'autre (« crib dragging »). Règle : un couple (clé, nonce) ne sert JAMAIS deux fois. Valable pour AES-CTR, AES-GCM, ChaCha20..."],
    ecb: ["ECB : les motifs fuient", "En mode ECB, chaque bloc est chiffré séparément avec la même clé : deux blocs identiques donnent deux chiffrés identiques. On voit la structure du message, on peut découper et recoller des blocs (le serveur déchiffre sans s'en apercevoir). Les modes sérieux (CBC avec IV aléatoire, CTR, GCM) font dépendre chaque bloc d'un IV ou d'un compteur. Jamais d'ECB pour des données."],
    auth: ["Chiffrer n'authentifie pas", "Un chiffrement par flux est malléable : changer un bit du chiffré change le même bit du clair, sans connaître la clé. Le chiffrement garantit la confidentialité, pas l'intégrité. Il faut un MAC (par exemple HMAC) calculé sur le chiffré et vérifié AVANT de déchiffrer (chiffrer puis authentifier), avec une clé distincte de celle du chiffrement."],
    temps: ["Comparer en temps constant", "Une comparaison « octet par octet, on s'arrête au premier écart » dure plus longtemps quand le début est correct : le chronomètre révèle le MAC octet par octet (256 essais par octet au lieu de 256^n au total). Comparer toute la longueur sans s'arrêter, avec la fonction dédiée de la bibliothèque (compare_digest, timingSafeEqual...), et ne jamais écrire sa propre comparaison."],
    aleas: ["L'aléa doit être imprévisible", "Un générateur congruentiel linéaire (x' = a·x + c mod m) est rapide et statistiquement correct, mais quelques sorties suffisent à retrouver a et c puis à prédire toute la suite. Pour des jetons, des clés, des nonces : uniquement le générateur cryptographique du système (crypto.getRandomValues dans le navigateur, /dev/urandom, secrets en Python), jamais Math.random ni rand()."],
    dur: ["Pas de clé dans le code", "Une clé écrite dans le programme (ou le dépôt, ou l'application distribuée) est lisible par quiconque en a une copie : un simple « strings » suffit, et la changer exige de redéployer. Les clés vivent dans un coffre à secrets (gestionnaire, HSM, variable d'environnement protégée), avec rotation et droits d'accès limités."],
    kdf: ["Dériver une clé d'un mot de passe", "SHA-256(mot de passe) donne une clé valide mais calculable des milliards de fois par seconde : un dictionnaire la retrouve instantanément. Il faut une fonction de dérivation lente et salée (Argon2id, scrypt, PBKDF2, bcrypt). Elle multiplie le coût de chaque essai, mais ne sauve pas un mot de passe faible : la longueur reste l'essentiel."],
    maison: ["Ne pas inventer sa crypto", "Un « chiffrement maison » (ici XOR avec une clé courte répétée, un Vigenère moderne) tombe à l'analyse de fréquences : l'indice de coïncidence révèle la longueur de clé, puis chaque colonne est un simple décalage, trahi par la lettre la plus fréquente (l'espace). Un algorithme secret n'est pas une preuve de sécurité : les primitives publiques ont été attaquées pendant des années par des centaines d'experts."],
    aead: ["AEAD : les bons outils", "Un chiffrement authentifié (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305) fait en une seule opération confidentialité et intégrité, et authentifie aussi des « données associées » (en-tête). Utilise-le via une bibliothèque éprouvée (libsodium, Web Crypto), avec une clé aléatoire, un nonce jamais réutilisé et le rejet de tout chiffré dont l'étiquette est invalide."],
  };

  /* ---------- entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, un petit carnet de contrats d'audit sous le bras. Tout ce que tu casses ici est simulé, sur des données fictives, et autorisé." },
    gontran: { npc: true, names: ["gontran", "cryptographe", "malchanceux"], label: "Gontran, le cryptographe malchanceux", desc: () => "Gontran, le maître des lieux : lunettes de travers, tablier taché d'encre. Chacun de ses établis contient un système « chiffré » qu'il était très fier d'avoir construit. Il a un talent rare pour choisir la mauvaise option par défaut." },
    etagere: { names: ["etagere", "bibliotheque", "primitives", "boite"], label: "l'étagère des primitives", vis: () => S.room === "atelier",
      desc: () => "Une étagère de boîtes étiquetées : `xor` (flux fait main), `ecb` (blocs, mode simple), `maison` (le chiffrement de Gontran) et `aead` (une bibliothèque de chiffrement authentifié). `construire ‹nom›` monte un système avec la boîte choisie et lance contre lui toutes les attaques de l'atelier." },
    parchemins: { names: ["parchemins", "parchemin", "chiffres", "messages", "chiffre"], label: "les deux parchemins chiffrés", vis: () => S.room === "flux",
      desc: () => { const x = F(); return `Deux messages interceptés entre Alice et Bob, tous deux chiffrés par flux (nonce ${n1()[0]}${x.n1fix ? " et " + n1()[1] : " pour les deux"}) :\n  C1 = ${toHex(C1())}\n  C2 = ${toHex(C2())}\nIls font ${C1().length} octets. \`xor 1 2\` les combine, \`glisser ‹mot›\` essaie un mot probable.`; } },
    ordre: { names: ["ordre", "virement", "ordre de virement"], label: "l'ordre de virement chiffré", vis: () => S.room === "flux",
      desc: () => "Un ordre de virement de la banque de Bob, chiffré par flux. Le format des ordres est public : VIRER ‹montant› EUROS A ‹nom›. `intercepter` le saisit au vol, `modifier ‹position› ‹ancien› ‹nouveau›` altère le chiffré." },
    registre: { names: ["registre", "guichet", "jetons", "machine", "cantine"], label: "le guichet à jetons", vis: () => S.room === "blocs",
      desc: () => `Le guichet délivre un jeton chiffré (blocs de 8 octets) à qui s'inscrit : \`inscrire ‹nom›\`. Le jeton contient « nom=‹nom›;role=client ». \`presenter ‹n›\` montre le jeton n° n au serveur, \`coller ‹n.b› ‹n.b›...\` lui présente un assemblage de blocs. Mode actuel : ${F().e_fix ? "CBC avec IV aléatoire" : "ECB, un bloc après l'autre"}. Les noms ne contiennent que lettres, chiffres, points, tirets.` },
    maisonbox: { names: ["maisonbox", "message maison", "message secret", "rouleau", "message de gontran"], label: "le message « maison » de Gontran", vis: () => S.room === "blocs",
      desc: () => `Un rouleau chiffré avec l'algorithme maison de Gontran (« tellement secret que personne ne l'a regardé ») : chaque octet du texte est XORé avec la clé secrète, répétée en boucle. ${C7().length} octets :\n${rows(C7(), 24)}\nOutils : \`periode\`, \`frequences ‹n›\`, \`deviner ‹clé›\`.` },
    chrono: { names: ["chronometre", "chrono", "porte", "serrure"], label: "le chronomètre de la porte", vis: () => S.room === "horloge",
      desc: () => `La porte de l'atelier s'ouvre si on présente le MAC (4 octets, soit 8 caractères hexadécimaux) de l'ordre « ${MSG4} ». Le chronomètre mesure en microsecondes le temps de réponse de la serveuse. \`tenter ‹mac›\` essaie un MAC, \`balayer ‹préfixe›\` essaie les 256 valeurs de l'octet suivant. Comparaison : ${F().t_fix ? "en temps constant" : "octet par octet, arrêt au premier écart"}.` },
    urne: { names: ["urne", "jetons", "urne a jetons", "generateur"], label: "l'urne à jetons de réinitialisation", vis: () => S.room === "horloge",
      desc: () => `L'urne délivre des jetons de réinitialisation de mot de passe. Générateur : ${F().r_fix ? "source cryptographique (jouet)" : "congruentiel, graine de 16 bits, état sur " + LM + " valeurs"}. \`observer\` demande un jeton pour ton propre compte, \`retrouver\` remonte au fonctionnement, \`predire\` annonce le suivant, \`soumettre ‹jeton›\` le présente pour le compte de la victime.` },
    appli: { names: ["application", "appli", "programme", "paquet", "app"], label: "l'application de Gontran (paquet distribué)", vis: () => S.room === "cellier",
      desc: () => "Le paquet de l'application, tel qu'il est distribué aux utilisateurs. `fouiller application` en affiche les chaînes de caractères lisibles." },
    sauvegarde: { names: ["sauvegarde", "archive", "backup"], label: "la sauvegarde chiffrée", vis: () => S.room === "cellier",
      desc: () => `La sauvegarde de la Guilde, chiffrée par flux avec la clé de l'application :\n${rows(backupCt(), 24)}\n\`dechiffrer sauvegarde ‹clé›\` tente un déchiffrement.` },
    carnet: { names: ["carnet chiffre", "carnet des comptes", "coffre", "coffre fort", "comptes"], label: "le carnet des comptes (chiffré)", vis: () => S.room === "cellier",
      desc: () => `Le carnet des comptes est chiffré avec une clé dérivée d'un mot de passe : ${F().k_fix2 ? "dérivation lente et salée (" + ITER + " tours de SHA-256 : un jouet, en vrai Argon2id ou scrypt)" : "clé = SHA-256(mot de passe), sans sel ni lenteur"}. Rien n'est stocké en clair. \`casser carnet\` essaie le dictionnaire de Mallory (${LIST.length} mots).` },
  };

  const rooms = {
    atelier: { name: "L'atelier de Gontran", short: "Atelier", alias: ["atelier", "hall"], ents: ["ada", "gontran", "etagere"], exits: { nord: "flux", est: "blocs", ouest: "horloge", sud: "cellier" },
      desc: () => "Un atelier encombré d'établis, chacun portant une pancarte « Garanti inviolable ». Les pancartes sont de Gontran. Au nord, l'établi des flux. À l'est, l'établi des blocs. À l'ouest, la salle du chronomètre. Au sud, le cellier des clés." },
    flux: { name: "L'établi des flux", short: "Flux", alias: ["flux", "etabli des flux"], ents: ["parchemins", "ordre"], exits: { sud: "atelier" },
      desc: () => "Des rubans de parchemin couverts d'octets pendent au plafond. Ici, on chiffre « à la volée » en XORant chaque message avec un flux. Deux établis : les parchemins interceptés, et l'ordre de virement." },
    blocs: { name: "L'établi des blocs", short: "Blocs", alias: ["blocs", "etabli des blocs"], ents: ["registre", "maisonbox"], exits: { ouest: "atelier" },
      desc: () => "Des cubes de bois gravés de motifs s'empilent sur la table : des blocs de huit octets. Un guichet délivre des jetons, et un rouleau repose dans un coin : le message maison de Gontran." },
    horloge: { name: "La salle du chronomètre", short: "Chronomètre", alias: ["horloge", "chronometre", "chrono"], ents: ["chrono", "urne"], exits: { est: "atelier" },
      desc: () => "Un grand chronomètre à aiguille fine tourne sur le mur. Sur la table : la porte à code et l'urne qui distribue des jetons de réinitialisation. Ici, tout se mesure et tout se prévoit." },
    cellier: { name: "Le cellier des clés", short: "Cellier", alias: ["cellier", "cles"], ents: ["appli", "sauvegarde", "carnet"], exits: { nord: "atelier" },
      desc: () => "Un cellier frais où Gontran range ses clés « bien cachées » : dans l'application, dans un mot de passe, dans sa mémoire. Une sauvegarde chiffrée et un carnet de comptes sont sur l'étagère." },
  };

  /* ---------- objectif et indices ---------- */
  const OBJ = ["quest", "n_xor", "n_found", "n_fix", "e_pat", "e_forge", "e_fix", "e_block", "m_flip", "m_fix", "m_block", "t_found", "t_fix", "t_block", "r_pred", "r_fix", "r_block", "k_hard", "k_pw", "k_fix1", "k_fix2", "k_retest", "h_found", "build"];
  const objective = () => { const x = F(); if (x.end) return "fin"; for (const k of OBJ) if (!x[k]) return k; return "end"; };
  const hints = {
    quest: () => ["Maître Ada t'attend dans l'atelier.", "`parler ada`"],
    n_xor: () => ["Va à l'établi des flux (nord) et regarde les deux parchemins. Que se passe-t-il si tu combines les deux chiffrés ?", "Depuis l'atelier : `aller nord`, `examiner parchemins`, `xor 1 2`."],
    n_found: () => ["Le XOR des chiffrés vaut le XOR des clairs. Il faut un mot probable : les messages d'Alice commencent souvent par RENDEZ-VOUS. Fais-le glisser sur le XOR, puis agrandis ce que tu apprends.", "`glisser RENDEZ-VOUS` (le fragment lisible est le début du message 2), puis `glisser OK, LE CODE DU COFFRE EST dans 2`, puis `glisser RENDEZ-VOUS AU PORT 443 A MINUIT`."],
    n_fix: () => ["Les deux messages ont le même nonce. Demande à Gontran de les rechiffrer proprement.", "`reparer nonce` (à l'établi des flux)."],
    e_pat: () => ["Va à l'établi des blocs (à l'est de l'atelier). Inscris-toi avec un nom très répétitif et regarde les blocs du jeton.", "Depuis l'atelier : `aller est`, `inscrire aaaaaaaaaaaaaaaaaaaaaaaa` (24 fois la lettre a)."],
    e_forge: () => ["Tu choisis ton nom, donc tu choisis un bloc entier de clair. Fabrique un jeton dont un bloc dit « admin », puis recolle-le au bout d'un jeton normal. Le début du jeton fait « nom=XXXX » sur 8 octets ; le rôle commence juste après « ;role= ».", "`inscrire abcdef` (jeton 2 : blocs « nom=abcd », « ef;role= », « client.. »), `inscrire xxxxadmin...` (jeton 3 : son bloc 3.2 vaut « admin... »), puis `coller 2.1 2.2 3.2`."],
    e_fix: () => ["Gontran peut changer de mode : chaque bloc doit dépendre du précédent, avec un IV aléatoire.", "`reparer mode` (à l'établi des blocs)."],
    e_block: () => ["Rejoue ton collage sur les nouveaux jetons (le jeton 1 et le jeton 2 viennent d'être réémis).", "`coller 1.1 1.2 2.3` (n'importe quel mélange fait l'affaire)."],
    m_flip: () => ["À l'établi des flux, intercepte l'ordre de virement. Le format est public : « VIRER » + espace font 6 caractères, donc le montant commence à la position 6. Change « 10 » en « 90 » sans connaître la clé.", "Depuis l'atelier : `aller nord`, `intercepter`, `modifier 6 10 90`."],
    m_fix: () => ["Le chiffrement ne protège pas l'intégrité. Ajoute une étiquette d'authentification calculée sur le chiffré.", "`reparer mac` (à l'établi des flux)."],
    m_block: () => ["Retente la même altération maintenant que l'étiquette existe.", "`intercepter` puis `modifier 6 10 90`."],
    t_found: () => ["Va à la salle du chronomètre (ouest de l'atelier). Les essais où le début du MAC est correct prennent un peu plus de temps. Balaye l'octet 1 : garde celui qui ressort, puis balaye l'octet suivant, et ainsi de suite.", "Depuis l'atelier : `aller ouest`, `balayer` (octet 1), puis `balayer ‹octet trouvé›` (par exemple `balayer 3f`), puis avec deux octets, trois octets, et enfin `tenter ‹mac complet›`."],
    t_fix: () => ["Il faut que la comparaison dure le même temps quelle que soit la réponse.", "`reparer comparaison` (salle du chronomètre)."],
    t_block: () => ["Refais un balayage : plus aucun octet ne devrait ressortir.", "`balayer`"],
    r_pred: () => ["À l'urne, demande trois jetons pour ton propre compte, remonte à la formule du générateur, puis prédis le jeton qui va être donné à la victime.", "`observer` (trois fois), `retrouver`, `predire`, `soumettre ‹nombre prédit›`."],
    r_fix: () => ["Un générateur prévisible ne doit jamais produire un secret. Remplace-le.", "`reparer aleas` (salle du chronomètre)."],
    r_block: () => ["Refais l'attaque avec la nouvelle source : observe, retrouve, prédis, soumets.", "`observer` (trois fois), `retrouver`, `predire`, `soumettre ‹nombre prédit›`."],
    k_hard: () => ["Au cellier (sud de l'atelier), cherche ce que l'application distribuée contient, puis essaie la clé trouvée sur la sauvegarde.", "Depuis l'atelier : `aller sud`, `fouiller application`, `dechiffrer sauvegarde ‹clé›` (copie la clé affichée)."],
    k_pw: () => ["Le carnet des comptes utilise une clé dérivée d'un mot de passe. Essaie le dictionnaire de Mallory.", "`casser carnet`"],
    k_fix1: () => ["Sors la clé de l'application : elle doit vivre dans un coffre à secrets.", "`reparer cle`"],
    k_fix2: () => ["Rends la dérivation de clé lente et salée.", "`reparer derivation`"],
    k_retest: () => ["Relance l'attaque par dictionnaire et compare le rythme des essais.", "`casser carnet`"],
    h_found: () => ["À l'établi des blocs, le rouleau de Gontran est chiffré par XOR avec une clé courte répétée. Cherche d'abord la longueur de la clé, puis la lettre de chaque colonne.", "Depuis l'atelier : `aller est`, `examiner rouleau`, `periode`, `frequences 4`, puis `deviner ‹clé›` (une lettre par colonne)."],
    build: () => ["Maître Ada veut maintenant un système bien construit : essaie les boîtes de l'étagère, et regarde ce que valent les attaques de l'atelier contre chacune.", "Dans l'atelier : `construire ecb`, `construire xor`, `construire maison`, puis `construire aead`."],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F(), k = objective();
    if (id === "ada") {
      if (!x.quest) {
        x.quest = true;
        say("Maître Ada", "Voici l'atelier de Gontran. Il a construit sept systèmes « chiffrés », tous garantis inviolables. Ils ont un point commun : ils emploient de vraies primitives, mal. Ton audit est autorisé et tout est simulé : tu vas casser chaque système avec des calculs réels, puis le réparer.");
        say("Maître Ada", "La cryptographie échoue rarement parce qu'AES ou SHA-256 sont faibles : elle échoue parce qu'on les utilise mal. Commence par l'établi des flux, au nord. Les primitives de l'atelier sont des jouets bâtis sur le SHA-256 du jeu : la logique des attaques est réelle, pas les tailles.");
        out("`aller nord`, puis `examiner parchemins`.", "sys");
      } else if (x.end) say("Maître Ada", "Gontran a remplacé toutes les pancartes par une seule : « Utiliser une bibliothèque ». Je ne m'y attendais pas.");
      else if (k === "end") ending();
      else if (k === "build") say("Maître Ada", "Tu as réparé chaque établi. Dernière étape : monter un système neuf avec la bonne boîte de l'étagère (`construire ‹nom›`) et lui faire subir toutes les attaques.");
      else if (k === "n_found") say("Maître Ada", "Les messages d'Alice commencent presque toujours par RENDEZ-VOUS. Fais-le glisser sur le XOR des deux chiffrés.");
      else say("Maître Ada", "Continue ton audit. `indice` si tu bloques.");
    } else if (id === "gontran") {
      if (x.end) say("Gontran", "Je ne crée plus rien tout seul. Je lis la documentation. C'est… reposant.");
      else if (k === "n_xor" || k === "n_found") say("Gontran", "Le nonce ? Je prends toujours le même, c'est plus simple à retenir. Et puis le flux dépend de la clé, non ?");
      else if (k === "n_fix") say("Gontran", "Un nonce différent pour chaque message ? Ah. Ça m'évitera ce qui vient de se passer. `reparer nonce`, c'est ça ?");
      else if (/^e_/.test(k)) say("Gontran", "L'ECB, c'est le mode par défaut de ma bibliothèque. Les blocs sont chiffrés indépendamment, c'est rapide. Et propre. Non ?");
      else if (/^m_/.test(k)) say("Gontran", "Mes virements sont chiffrés ! Personne ne peut les lire. Qu'est-ce que ça peut faire, qu'on les modifie ?");
      else if (/^t_/.test(k)) say("Gontran", "Ma comparaison s'arrête dès qu'un octet diffère : c'est plus rapide ! Et la rapidité, c'est la sécurité, non ?");
      else if (/^r_/.test(k)) say("Gontran", "Mon générateur passe tous les tests statistiques. Il n'y a rien de plus aléatoire. Sauf peut-être le mien, en pire.");
      else if (/^k_/.test(k)) say("Gontran", "Ma clé est dans le code : si personne ne regarde, elle est secrète ! Et mon mot de passe est SHA-256, c'est du sérieux.");
      else if (k === "h_found") say("Gontran", "Mon chiffrement maison est secret, donc inviolable : même moi, je ne me rappelle plus comment il marche.");
      else say("Gontran", "J'ai tout écouté. Je suis un peu vexé. Mais un peu plus prudent.");
    } else out("Il ne répond pas.", "sys");
  }

  /* ---------- verbes ---------- */
  const here = (room, label) => { if (S.room !== room) { out(`${label} se trouve ailleurs : ${G.rooms[room].name} (${G.rooms[room].short}).`, "sys"); return false; } return true; };
  const needQuest = () => { if (!F().quest) { out("Parle d'abord à Maître Ada.", "sys"); return false; } return true; };

  function xorCmd(c) {
    const x = F();
    if (!here("flux", "Les parchemins")) return;
    if (!/\b1\b/.test(c.rawArg) || !/\b2\b/.test(c.rawArg)) { out("XOR de quoi ? `xor 1 2` combine les chiffrés C1 et C2.", "err"); return; }
    out("Tu XORes octet par octet C1 et C2 :", "sys");
    code(`C1       ${toHex(C1())}\nC2       ${toHex(C2())}\nC1 ⊕ C2  ${toHex(X12())}`);
    if (x.n1fix) { out("Les nonces sont différents : les deux flux sont indépendants, ce XOR ne vaut plus M1 ⊕ M2 et ne montre aucune structure.", "ok"); return; }
    out("Même nonce, donc même flux : il s'est simplifié dans le calcul. Ce que tu vois vaut exactement M1 ⊕ M2, le XOR des deux clairs, sans la clé. Reste à deviner un mot de l'un pour lire l'autre.", "ok");
    if (!x.n_xor) { x.n_xor = true; fig("xor"); }
  }
  function slide(c) {
    const x = F();
    if (!here("flux", "Les parchemins")) return;
    if (!x.n_xor) { out("Commence par combiner les deux chiffrés : `xor 1 2`.", "sys"); return; }
    const m = c.rawArg.match(/^(.*?)(?:\s+(?:dans|sur)\s+(?:le\s+)?(?:message\s+)?([12]))?$/i);
    const crib = m[1].trim().toUpperCase(), which = m[2] || "1";
    if (crib.length < 3) { out("Donne un mot probable d'au moins 3 caractères : `glisser RENDEZ-VOUS` (message 1 par défaut) ou `glisser ‹mot› dans 2`.", "err"); return; }
    if (crib.length > 32 || /[^\x20-\x7e]/.test(crib)) { out("Le mot probable doit tenir dans 32 caractères ASCII (sans accent).", "err"); return; }
    const X = X12(), cb = enc(crib), truth = which === "1" ? M1 : M2, other = which === "1" ? M2 : M1;
    const res = [];
    for (let o = 0; o + cb.length <= X.length; o++) {
      const fr = xorb(cb, X.slice(o, o + cb.length));
      if (fr.every(v => /[A-Z0-9 ,.!\-]/.test(String.fromCharCode(v)))) {
        const t = txt(fr), sc = [...t].filter(ch => "AEIOU ".includes(ch)).length - [...t].filter(ch => !/[A-Z ]/.test(ch)).length;
        res.push([o, t, sc]);
      }
    }
    res.sort((a, b) => b[2] - a[2]);
    out(`Tu fais glisser « ${crib} » le long du XOR, en supposant qu'il figure dans le message ${which} :`, "sys");
    if (!res.length) out("Aucun décalage ne donne de texte lisible : ce mot n'est pas (là) dans ce message.", "err");
    else code(res.slice(0, 5).map(r => `décalage ${String(r[0]).padStart(2)} : « ${r[1]} »`).join("\n"));
    if (!x.n1fix) {
      // mémorise ce qui est réellement correct
      let changed = false;
      for (let o = 0; o + crib.length <= truth.length; o++) {
        if (truth.slice(o, o + crib.length) !== crib) continue;
        const k1 = (which === "1" ? x.k1 : x.k2).split(""), k2 = (which === "1" ? x.k2 : x.k1).split("");
        for (let i = 0; i < crib.length; i++) { k1[o + i] = crib[i]; k2[o + i] = other[o + i]; }
        if (which === "1") { x.k1 = k1.join(""); x.k2 = k2.join(""); } else { x.k2 = k1.join(""); x.k1 = k2.join(""); }
        changed = true;
      }
      if (changed) {
        out("Un fragment sensé apparaît : ton mot est bien placé, et ce qui sort en face est du texte de l'autre message. Tu retiens ce que tu sais :", "ok");
        code(`Message 1 : ${x.k1}\nMessage 2 : ${x.k2}`);
        if (x.k2.slice(26, 30) === "7319" && !x.n_found) {
          x.n_found = true;
          out("Le message 2 se lit en entier : le code du coffre est **7319**. Sans toucher à la clé, rien qu'avec un nonce réutilisé.", "err");
          note("nonce"); fig("xor");
        } else if (!x.n_found) out("Prolonge le texte connu : un mot plus long révèle plus de l'autre message.", "sys");
      } else if (res.length) out("Un fragment lisible n'est pas toujours un vrai : s'il n'a pas de sens, ton mot n'est pas à cet endroit.", "sys");
    }
  }
  function intercept() {
    const x = F();
    if (!here("flux", "L'ordre de virement")) return;
    const ct = m3ct();
    out(`Tu saisis l'ordre au vol (nonce ${m3nonce()}).`, "sys");
    code("position  " + ct.map((_, i) => String(i).padStart(2)).join(" ") + "\nchiffré   " + ct.map(v => v.toString(16).padStart(2, "0")).join(" ") + (x.m_fix ? "\nétiquette " + m3tag() : ""));
    out(x.m_fix ? "L'ordre porte maintenant une étiquette d'authentification (MAC) calculée sur le nonce et le chiffré, avec une clé de MAC distincte." : "Tu connais le format public : VIRER ‹montant› EUROS A ‹nom›. Tu n'as pas la clé, mais tu sais ce qui se trouve à chaque position.", "sys");
    x.m_seen = true;
  }
  function modify(c) {
    const x = F();
    if (!here("flux", "L'ordre de virement")) return;
    const t = c.rawArg.trim().split(/\s+/);
    const pos = parseInt(t[0], 10), old = t[1], nw = t[2];
    if (!/^\d+$/.test(t[0] || "") || !old || !nw) { out("Syntaxe : `modifier ‹position› ‹ancien› ‹nouveau›`, par exemple `modifier 6 10 90`.", "err"); return; }
    if (old.length !== nw.length) { out("L'ancien et le nouveau texte doivent avoir la même longueur : on ne peut pas décaler les octets d'un chiffré par flux.", "err"); return; }
    if (pos + old.length > M3.length) { out(`Position hors du message (il fait ${M3.length} octets).`, "err"); return; }
    const ct = m3ct(), ct2 = ct.slice();
    for (let i = 0; i < old.length; i++) ct2[pos + i] = ct[pos + i] ^ old.charCodeAt(i) ^ nw.charCodeAt(i);
    out(`Tu XORes les octets ${pos} à ${pos + old.length - 1} du chiffré avec « ${old} » ⊕ « ${nw} » (aucune clé n'intervient) :`, "sys");
    code("avant " + toHex(ct) + "\naprès " + toHex(ct2));
    if (x.m_fix) {
      if (toHex(ct2) === toHex(ct)) { out("Rien n'a changé : l'ordre passe tel quel.", "sys"); return; }
      out("La banque recalcule l'étiquette sur le chiffré reçu : elle ne correspond pas à celle fournie. Sans la clé de MAC, tu ne peux pas en fabriquer une valide. L'ordre est REJETÉ avant tout déchiffrement.", "ok");
      if (!x.m_block) { x.m_block = true; fig("mac"); }
      return;
    }
    const pt = txt(xorb(ct2, keystream(K3, m3nonce(), ct2.length)));
    out(`La banque déchiffre et exécute, sans rien vérifier : « ${pt} »`, pt === M3 ? "sys" : "err");
    if (pt === "VIRER 90 EUROS A BOB") {
      out("Bob reçoit 90 euros au lieu de 10. Tu as modifié le clair prévisiblement, sans connaître la clé : le chiffrement par flux est malléable.", "err");
      if (!x.m_flip) { x.m_flip = true; note("auth"); fig("mac"); }
    } else if (pt !== M3) out("Le résultat est altéré mais pas celui que tu visais : le texte « ancien » doit être EXACTEMENT ce qu'il y a à cette position (ici « 10 » à la position 6).", "sys");
  }

  function issueCmd(c) {
    const x = F();
    if (!here("blocs", "Le guichet à jetons")) return;
    const name = c.rawArg.trim();
    if (!/^[A-Za-z0-9._-]{1,30}$/.test(name)) { out("Nom invalide : 1 à 30 caractères parmi lettres, chiffres, point, tiret (le serveur refuse « ; » et « = »). `inscrire abcdef`", "err"); return; }
    const t = issue(name), n = x.toks.length;
    out(`Jeton ${n} pour « ${name} » ${x.e_fix ? "(CBC : le bloc .1 est l'IV)" : "(ECB)"} :`, "sys");
    code(t.blocks.map((b, i) => `${n}.${i + 1}  ${b}`).join("\n"));
    const dup = [];
    for (let i = 0; i < t.blocks.length; i++) for (let j = i + 1; j < t.blocks.length; j++) if (t.blocks[i] === t.blocks[j]) dup.push(`${n}.${i + 1} = ${n}.${j + 1}`);
    if (dup.length) {
      out("Deux blocs de chiffré sont identiques (" + dup.join(", ") + ") : tu vois que ton nom contenait deux blocs identiques, sans connaître la clé.", "err");
      if (!x.e_pat && !x.e_fix) { x.e_pat = true; note("ecb"); fig("ecb"); }
    } else if (x.e_fix) out("Même texte répété, chiffrés tous différents : le bloc dépend du précédent et de l'IV.", "ok");
  }
  function presentCmd(c) {
    const x = F();
    if (!here("blocs", "Le guichet à jetons")) return;
    const n = parseInt(c.rawArg.trim(), 10), t = x.toks[n - 1];
    if (!t) { out("Quel jeton ? `presenter 1` (tu en as " + x.toks.length + ").", "err"); return; }
    const r = serverRead(t.blocks);
    out(`Le serveur déchiffre : « ${r.shown} » → il te traite en **${r.role}**.`, "sys");
  }
  function pasteCmd(c) {
    const x = F();
    if (!here("blocs", "Le guichet à jetons")) return;
    const refs = [...c.rawArg.matchAll(/(\d+)\.(\d+)/g)].map(m => [+m[1], +m[2]]);
    if (!refs.length) { out("Syntaxe : `coller 1.1 1.2 2.2` (jeton.bloc).", "err"); return; }
    const bl = [];
    for (const [a, b] of refs) { const t = x.toks[a - 1]; if (!t || !t.blocks[b - 1]) { out(`Le bloc ${a}.${b} n'existe pas.`, "err"); return; } bl.push(t.blocks[b - 1]); }
    out("Tu assembles : " + refs.map(r => r.join(".")).join(" + ") + ", et tu présentes le résultat au serveur.", "sys");
    const r = serverRead(bl);
    if (x.e_fix && bl.length === 1) { out("Un seul bloc : il n'y a rien à lire sans IV.", "sys"); return; }
    if (r.ok) {
      out(`Le serveur lit : « ${r.shown} » → rôle **${r.role}**.`, r.role === "admin" ? "err" : "sys");
      if (r.role === "admin" && !x.e_fix) {
        out("Tu es administrateur : le serveur a déchiffré un jeton qu'il n'a jamais émis. L'ECB ne lie pas les blocs entre eux : chacun est valable partout, et tu as choisi un bloc.", "err");
        if (!x.e_forge) { x.e_forge = true; fig("ecb"); }
      }
    } else {
      out(`Le serveur déchiffre : « ${r.shown} » : jeton illisible, REFUSÉ.`, "ok");
      if (x.e_fix && !x.e_block) { x.e_block = true; out("En CBC, chaque bloc dépend du précédent : recoller des blocs d'origines différentes brouille le déchiffrement. (Mais le CBC seul n'authentifie pas non plus : on le verra avec le MAC.)", "ok"); fig("ecb"); }
    }
  }

  function timeCmd(c) {
    const x = F();
    if (!here("horloge", "Le chronomètre")) return;
    const g = c.rawArg.trim().toLowerCase();
    if (!/^[0-9a-f]{8}$/.test(g)) { out("Un MAC fait 4 octets : 8 caractères hexadécimaux. `tenter 00000000`", "err"); return; }
    const t = time4(g);
    if (g === tag4()) {
      out(`${t} µs : MAC accepté, la porte s'ouvre.`, "err");
      if (!x.t_fix && !x.t_found) { x.t_found = true; note("temps"); fig("temps"); out("Tu n'avais jamais calculé de MAC : tu l'as deviné octet par octet. Au lieu de 2^32 essais, 4 × 256 = 1 024 ont suffi.", "err"); }
      else if (x.t_fix) out("(Ce MAC est valide parce qu'il vient d'être publié par le service : le correctif a tourné la clé, mais un MAC déjà connu reste valable pour son message.)", "sys");
    } else out(`${t} µs : MAC refusé.`, "sys");
    out("Compare avec le temps d'un MAC totalement faux (`tenter 00000000`).", "sys");
  }
  function sweepCmd(c) {
    const x = F();
    if (!here("horloge", "Le chronomètre")) return;
    const p = c.rawArg.trim().toLowerCase().replace(/^0x/, "");
    if (!/^([0-9a-f]{2}){0,3}$/.test(p)) { out("Préfixe attendu : 0 à 3 octets en hexadécimal, par exemple `balayer` ou `balayer 3f` ou `balayer 3fa2`.", "err"); return; }
    const k = p.length / 2, ts = [];
    for (let b = 0; b < 256; b++) { const g = p + b.toString(16).padStart(2, "0") + "00".repeat(3 - k); ts.push([b, time4(g), g]); }
    const sorted = ts.slice().sort((a, b) => b[1] - a[1]), med = ts.map(r => r[1]).sort((a, b) => a - b)[128];
    out(`Tu essaies les 256 valeurs de l'octet n° ${k + 1} après le préfixe « ${p || "(vide)"} » et tu chronomètres :`, "sys");
    code(sorted.slice(0, 4).map(r => `octet ${r[0].toString(16).padStart(2, "0")} : ${r[1]} µs`).join("\n") + `\n... médiane des 256 essais : ${med} µs`);
    const gap = sorted[0][1] - sorted[1][1];
    if (x.t_fix) {
      out("Tous les essais prennent le même temps, à quelques microsecondes de bruit près : plus aucun octet ne ressort. La comparaison ne fuit plus.", "ok");
      if (!x.t_block) { x.t_block = true; fig("temps"); }
    } else if (gap > 10) {
      out(`Un octet ressort nettement (+${gap} µs sur le suivant) : c'est le bon.${k === 3 ? "" : " Ajoute-le au préfixe et balaye l'octet suivant."}`, "ok");
      if (k === 3) out(`Les quatre octets sont connus. Présente le MAC complet : \`tenter ${sorted[0][2]}\``, "sys");
    } else out("Aucun octet ne ressort : vérifie ton préfixe (un octet faux plus haut fausse tout).", "sys");
  }

  function observe() {
    const x = F();
    if (!here("horloge", "L'urne")) return;
    if (x.obs.length >= 8) x.obs.shift();
    const v = nextTok(); x.obs.push(v);
    out(`Jeton de réinitialisation reçu pour ton compte : **${fmtTok(v)}** (observation ${x.obs.length}).`, "sys");
    if (x.obs.length === 3 && !x.r_fix) out("Trois sorties consécutives : c'est assez pour tenter `retrouver`.", "sys");
  }
  function recoverCmd() {
    const x = F();
    if (!here("horloge", "L'urne")) return;
    if (x.obs.length < 3) { out(`Il faut au moins 3 observations (tu en as ${x.obs.length}) : \`observer\`.`, "err"); return; }
    const [a0, a1, a2] = x.obs.slice(-3).map(v => v % LM);
    const d1 = (a1 - a0 + LM) % LM, d2 = (a2 - a1 + LM) % LM;
    if (!d1) { out("Deux sorties égales : observe-en une de plus.", "err"); return; }
    const A = (d2 * modpow(d1, LM - 2, LM)) % LM, C = (((a1 - A * a0) % LM) + LM) % LM;
    x.rec = [A, C, a2];
    out(`Tu supposes que le générateur est de la forme x' = a·x + c (mod ${LM}), la forme la plus répandue. Avec x0=${a0}, x1=${a1}, x2=${a2} :`, "sys");
    code(`x1 - x0 = ${d1}      x2 - x1 = ${d2}   (mod ${LM})\na = (x2 - x1) / (x1 - x0) = ${d2} × ${d1}^(${LM}-2) mod ${LM} = ${A}\nc = x1 - a·x0 (mod ${LM}) = ${C}`);
    if (x.r_fix) out("Les nombres sortent, mais n'ont aucune raison d'être justes : les sorties de la source cryptographique ne suivent aucune relation de ce genre. Essaie `predire`, puis `soumettre`.", "sys");
    else out(`Tu viens de retrouver les paramètres du générateur à partir de trois sorties : a = ${A}, c = ${C}. L'état, c'est la dernière sortie.`, "err");
  }
  function predictCmd() {
    const x = F();
    if (!here("horloge", "L'urne")) return;
    if (!x.rec) { out("Retrouve d'abord les paramètres : `retrouver`.", "err"); return; }
    const [A, C, last] = x.rec, p = (A * last + C) % LM;
    x.pred = p;
    out(`Prédiction : a·${last} + c mod ${LM} = **${p}**. C'est le jeton que l'urne donnera ensuite. À présenter avec \`soumettre ${p}\`.`, "sys");
    fig("lcg");
  }
  function submitCmd(c) {
    const x = F();
    if (!here("horloge", "L'urne")) return;
    const s = c.rawArg.trim().toLowerCase();
    if (!s) { out("Quel jeton ? `soumettre ‹nombre›`", "err"); return; }
    const victim = peekTok(), vs = fmtTok(victim);
    const good = x.r_fix ? s === vs : (/^\d+$/.test(s) && parseInt(s, 10) === victim);
    out("La victime demande la réinitialisation de son mot de passe : l'urne lui émet son jeton (que tu ne vois pas). Tu présentes le tien :", "sys");
    if (good) {
      out("Jeton accepté : tu peux réinitialiser le mot de passe de la victime. Tu as prédit un secret que le serveur croyait aléatoire.", "err");
      if (!x.r_pred && !x.r_fix) { x.r_pred = true; note("aleas"); fig("lcg"); }
    } else {
      out("Jeton refusé" + (x.r_fix ? " : le jeton venait d'une source imprévisible, 32 bits tirés sans lien avec les précédents. Les formules ne servaient à rien." : " : ta prédiction ne correspond pas. As-tu observé d'autres jetons depuis le dernier `predire` ?"), x.r_fix ? "ok" : "err");
      if (x.r_fix && !x.r_block) { x.r_block = true; fig("lcg"); }
    }
    nextTok(); // la victime consomme son jeton
  }

  function searchCmd(c) {
    const x = F();
    if (!here("cellier", "L'application")) return;
    if (!/appli|paquet|programme|app/.test(norm(c.rawArg))) { out("Fouiller quoi ? `fouiller application`", "err"); return; }
    out("Tu extrais les chaînes lisibles du paquet (la commande « strings », que n'importe quel utilisateur peut lancer) :", "sys");
    if (x.k_fix1) code(`API_URL        = "https://api.port443.example"\nTIMEOUT_MS     = 3000\nCLE_SAUVEGARDE = lue depuis le coffre à secrets au démarrage\n(aucune clé dans le paquet)`);
    else code(`API_URL        = "https://api.port443.example"\nTIMEOUT_MS     = 3000\nCLE_SAUVEGARDE = "${KH}"\nNONCE_FIXE     = "N-6"`);
    if (x.k_fix1) out("Plus rien d'exploitable : le paquet ne contient plus que de la configuration publique.", "ok");
    else out("Une clé de 16 caractères hexadécimaux. Pour la copier, `dechiffrer sauvegarde ‹clé›`.", "err");
  }
  function decryptCmd(c) {
    const x = F();
    if (!here("cellier", "La sauvegarde")) return;
    const t = c.rawArg.trim().split(/\s+/);
    if (t.length < 2 || !/sauvegarde|archive|backup/.test(norm(t[0]))) { out("`dechiffrer sauvegarde ‹clé›`", "err"); return; }
    const key = t[t.length - 1], pt = stream(key, "N-6", backupCt());
    out(`Tu déchiffres la sauvegarde avec la clé « ${key} » :`, "sys");
    code(show(pt));
    if (txt(pt).startsWith("PORT443:")) {
      out("Lisible : la clé trouvée dans l'application ouvre la sauvegarde. Quiconque possède le paquet possède la clé, et la changer demande de redéployer l'application chez tout le monde.", "err");
      if (!x.k_hard) { x.k_hard = true; note("dur"); }
    } else out(x.k_fix1 ? "Du bruit : la vraie clé n'est plus dans le code." : "Du bruit : ce n'est pas la bonne clé.", "ok");
  }
  function crackCmd(c) {
    const x = F();
    if (!here("cellier", "Le carnet des comptes")) return;
    if (!/carnet|coffre|compte/.test(norm(c.rawArg))) { out("Casser quoi ? `casser carnet`", "err"); return; }
    const ct = carnetCt();
    out(`Mallory essaie son dictionnaire (${LIST.length} mots) : pour chaque mot, elle dérive la clé ${x.k_fix2 ? "(dérivation lente et salée)" : "(SHA-256 du mot)"}, déchiffre et cherche l'en-tête « PORT443: » :`, "sys");
    const t0 = performance.now(); let tries = 0, found = null;
    for (const w of LIST) { tries++; if (txt(stream(derive(w), "N-7", ct)).startsWith("PORT443:")) { found = w; break; } }
    const ms = Math.max(1, Math.round(performance.now() - t0));
    if (found) out(`Trouvé en ${tries} essai${tries > 1 ? "s" : ""} (${ms} ms) : le mot de passe est « ${found} ». Le carnet s'ouvre : « ${CARNET} »`, "err");
    else out(`${tries} essais (${ms} ms) : aucun mot du dictionnaire ne convient. La phrase de passe est longue et imprévisible.`, "ok");
    const nb = x.k_fix2 ? 3 : 400, b0 = performance.now();
    for (let i = 0; i < nb; i++) derive("essai" + i);
    const per = Math.round(nb / Math.max(0.001, (performance.now() - b0) / 1000));
    out(`Rythme mesuré dans ton navigateur : environ ${num(per)} dérivations par seconde.`, "sys");
    if (found && !x.k_pw && !x.k_fix2) { x.k_pw = true; note("kdf"); }
    if (x.k_fix2 && !x.k_retest) { x.k_retest = true; out(`Avec ${ITER} tours, chaque essai coûte ${ITER} fois plus de calculs : le même dictionnaire est ${ITER} fois plus lent à parcourir, et la phrase de passe longue n'y figure pas. Dérivation lente + secret fort : les deux sont nécessaires.`, "ok"); }
  }

  function periodCmd() {
    if (!here("blocs", "Le message maison")) return;
    out("Indice de coïncidence moyen des colonnes, pour chaque longueur de clé possible (≈ 0,07 pour un texte français brut, ≈ 0,04 pour du bruit) :", "sys");
    const lines = [];
    for (let L = 1; L <= 8; L++) { const v = ic(L); lines.push(`longueur ${L} : ${v.toFixed(3)}  ${"#".repeat(Math.round(v * 300))}`); }
    code(lines.join("\n"));
    out("Les longueurs qui ressortent (la vraie et ses multiples) indiquent où le texte « se recolle » : prends la plus petite. Ensuite, `frequences ‹longueur›`.", "sys");
    F().h_per = true;
  }
  function freqCmd(c) {
    const x = F();
    if (!here("blocs", "Le message maison")) return;
    const L = parseInt(c.rawArg.trim(), 10);
    if (!(L >= 1 && L <= 8)) { out("`frequences ‹longueur›` avec une longueur de 1 à 8.", "err"); return; }
    const ct = C7(), lines = [];
    for (let i = 0; i < L; i++) {
      const col = ct.filter((_, j) => j % L === i), cnt = {};
      col.forEach(b => cnt[b] = (cnt[b] || 0) + 1);
      const top = Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([b, n]) => { const k = (+b) ^ 32; return `${(+b).toString(16).padStart(2, "0")}×${n} (clé « ${k >= 32 && k < 127 ? String.fromCharCode(k) : "?"} »)`; });
      lines.push(`colonne ${i + 1} : ${top.join("  ")}`);
    }
    out(`Pour chaque colonne (octets ayant la même lettre de clé), les octets les plus fréquents. Dans un texte français l'espace est le caractère le plus courant : si l'octet est une espace XORée, la clé vaut octet ⊕ 0x20, indiquée entre parenthèses.`, "sys");
    code(lines.join("\n"));
    if (L === K7.length) out("Chaque colonne a un candidat qui revient : une lettre de clé plausible (une lettre, pas un chiffre ni un signe). Assemble-les : `deviner ‹clé›`.", "sys");
    else out("Aucune clé lisible ne se dessine : ce n'est sans doute pas la bonne longueur (`periode`).", "sys");
  }
  function guessCmd(c) {
    const x = F();
    if (!here("blocs", "Le message maison")) return;
    const k = c.rawArg.trim();
    if (!k) { out("`deviner ‹clé›` : la clé est un petit mot, une lettre par colonne.", "err"); return; }
    const pt = C7().map((v, i) => v ^ k.charCodeAt(i % k.length));
    out(`Tu déchiffres avec la clé « ${k} » :`, "sys");
    code(show(pt).match(/.{1,48}/g).join("\n"));
    if (k.toLowerCase() === K7) {
      out("Le texte se lit : la recette de la tarte est cachée sous l'horloge. Le « chiffrement maison » n'a pas résisté plus de quelques minutes à une analyse de fréquences vieille de plusieurs siècles.", "err");
      if (!x.h_found) { x.h_found = true; note("maison"); }
    } else out("Du charabia : au moins une lettre de la clé est fausse. Reprends `frequences`.", "sys");
  }

  const FIXES = [
    [/nonce/, "flux", "n_found", "n_fix"], [/mac|authent/, "flux", "m_flip", "m_fix"], [/mode|cbc|ecb/, "blocs", "e_forge", "e_fix"],
    [/compar|constant|temps/, "horloge", "t_found", "t_fix"], [/alea|generat|random/, "horloge", "r_pred", "r_fix"],
    [/derivation|kdf|lent/, "cellier", "k_pw", "k_fix2"], [/cle|secret|coffre/, "cellier", "k_hard", "k_fix1"],
  ];
  function repairCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!t) { out("Réparer quoi ? `reparer nonce`, `reparer mode`, `reparer mac`, `reparer comparaison`, `reparer aleas`, `reparer cle`, `reparer derivation`.", "err"); return; }
    const fx = FIXES.find(r => r[0].test(t));
    if (!fx) { out("Je ne connais pas cette réparation. `reparer` seul liste les réparations possibles.", "err"); return; }
    const [, room, need, flag] = fx;
    if (!here(room, "Cette réparation")) return;
    if (x[flag]) { out("C'est déjà réparé.", "sys"); return; }
    if (!x[need]) { out("Pas encore : montre d'abord que le défaut est exploitable (`indice`).", "sys"); return; }
    x[flag] = true;
    switch (flag) {
      case "n_fix": {
        x.n1fix = true;
        const X = X12(), fr = xorb(enc("RENDEZ-VOUS"), X.slice(0, 11));
        say("Gontran", "Un nonce par message : N-0002, N-0003. Je les numérote !");
        out("Les deux messages sont rechiffrés avec des nonces distincts. Tu rejoues ton attaque :", "ok");
        code(`C1 ⊕ C2 (nouveaux) = ${toHex(X)}\nglisser RENDEZ-VOUS, décalage 0 : « ${show(fr)} » (au lieu de « OK, LE CODE »)`);
        out("Du bruit : deux flux différents ne s'annulent plus. Le couple (clé, nonce) ne doit servir qu'une fois, et la répétition est fatale (aussi avec AES-GCM). Attention : un nonce aléatoire trop court peut finir par se répéter ; un compteur, ou un nonce de 192 bits (XChaCha20), est plus sûr.", "ok");
        note("nonce"); fig("xor"); break;
      }
      case "e_fix": {
        x.toks = []; issue(REG_N1); issue(REG_N2);
        say("Gontran", "Chaînons les blocs : chacun est mélangé avec le précédent avant d'être chiffré, et un IV aléatoire démarre la chaîne.");
        out("Le guichet est passé en CBC : les jetons 1 (« abcdef ») et 2 (« xxxxadmin... ») viennent d'être réémis avec des IV aléatoires. Le bloc .1 de chaque jeton est son IV. Rejoue ton collage : `coller 1.1 1.2 2.3` par exemple.", "ok");
        break;
      }
      case "m_fix":
        say("Gontran", "On calcule un MAC sur le nonce et le chiffré, avec une clé séparée, et la banque le vérifie AVANT de déchiffrer. Chiffrer puis authentifier.");
        out("L'ordre est réémis (nonce N-0101) avec une étiquette HMAC-SHA-256 tronquée. `intercepter` puis `modifier 6 10 90` pour retenter.", "ok");
        break;
      case "t_fix":
        say("Gontran", "On compare tous les octets, sans s'arrêter, et on cumule les écarts. Le résultat n'est connu qu'à la fin.");
        out("La comparaison est en temps constant (et le service tourne sa clé, donc l'ancien MAC trouvé est périmé). `balayer` pour vérifier que plus rien ne ressort.", "ok");
        break;
      case "r_fix":
        x.obs = []; x.rec = null; x.pred = null; x.cnt = 0;
        say("Gontran", "Fini mon générateur maison : on prend celui du système.");
        out("Les jetons viennent maintenant d'une source cryptographique. Dans un vrai navigateur : `crypto.getRandomValues`. Ici, une source jouet bâtie sur le SHA-256 du jeu, avec une graine secrète. Refais l'attaque : `observer` ×3, `retrouver`, `predire`, `soumettre ‹prédiction›`.", "ok");
        break;
      case "k_fix1":
        say("Gontran", "La clé vit dans un coffre à secrets, lue au démarrage, et change à chaque rotation.");
        out("La clé n'est plus dans le paquet. La sauvegarde a été rechiffrée avec la nouvelle clé. `fouiller application` pour le vérifier.", "ok");
        break;
      case "k_fix2":
        x.k_fix2 = true;
        say("Gontran", "Le carnet est maintenant protégé par une phrase de passe longue, et la clé en est dérivée avec un sel et " + ITER + " tours.");
        out("Le carnet est rechiffré. `casser carnet` pour mesurer l'écart de coût.", "ok");
        break;
    }
  }

  function buildCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (!here("atelier", "L'étagère")) return;
    const kinds = { xor: /^xor/, ecb: /^ecb/, maison: /^maison/, aead: /^aead|gcm|chacha|poly|libsodium|bibliotheque/ };
    const kind = Object.keys(kinds).find(k => kinds[k].test(t));
    if (!kind) { out("Quelle boîte ? `construire xor`, `construire ecb`, `construire maison` ou `construire aead`.", "err"); return; }
    const msgA = "VIRER 10 EUROS A BOB", msgB = "VIRER 10 EUROS A EVE", key = "cle-finale", kmac = "cle-finale-mac";
    let encr, seal, open, desc;
    if (kind === "xor") { desc = "flux XOR avec un nonce fixe, sans MAC"; encr = m => stream(key, "N-0", enc(m)); }
    else if (kind === "maison") { desc = "XOR avec clé courte répétée (maison)"; encr = m => enc(m).map((v, i) => v ^ key.charCodeAt(i % 4)); }
    else if (kind === "ecb") { desc = "chiffrement par blocs en mode ECB, sans MAC"; encr = m => [].concat(...chunk8(enc(pad8(m))).map(b => blockEnc(key, b))); }
    else {
      desc = "AEAD (chiffrer puis authentifier, nonce géré par la bibliothèque)";
      x.ctr = x.ctr || 0;
      seal = m => { const n = x.ctr++, ct = stream(key, "N-" + n, enc(m)); return { n, ct, tag: hmac(kmac, "N-" + n + "|" + toHex(ct)) }; };
      open = o => hmac(kmac, "N-" + o.n + "|" + toHex(o.ct)) === o.tag ? txt(stream(key, "N-" + o.n, o.ct)) : null;
    }
    out(`Tu montes un système : ${desc}. Attaques de l'atelier, calculées pour de vrai :`, "sys");
    const lines = [];
    let leak, pattern, flipOk;
    const flip = "1".charCodeAt(0) ^ "9".charCodeAt(0);
    if (kind === "aead") {
      const a = seal(msgA), b = seal(msgB), r = seal("A".repeat(16));
      leak = toHex(xorb(a.ct, b.ct)) === toHex(xorb(enc(msgA), enc(msgB)));
      pattern = toHex(r.ct.slice(0, 8)) === toHex(r.ct.slice(8, 16));
      flipOk = open({ n: a.n, ct: a.ct.map((v, i) => i === 7 ? v ^ flip : v), tag: a.tag }) !== null;
      if (open(a) !== msgA) { out("Erreur interne : le déchiffrement légitime échoue.", "err"); return; }
    } else {
      const a = encr(msgA), b = encr(msgB), r = encr("A".repeat(16));
      leak = kind === "ecb" ? toHex(a.slice(0, 8)) === toHex(b.slice(0, 8)) : toHex(xorb(a, b)) === toHex(xorb(enc(msgA), enc(msgB)));
      pattern = toHex(r.slice(0, 8)) === toHex(r.slice(8, 16));
      flipOk = true; // sans étiquette, tout chiffré est accepté
    }
    lines.push(`1. deux messages presque identiques, même clé : ${leak ? "FUITE (la ressemblance se voit dans les chiffrés)" : "rien de lisible"}`);
    lines.push(`2. 16 « A » identiques de suite : ${pattern ? "FUITE (blocs identiques, motif visible)" : "aucun motif"}`);
    lines.push(`3. un bit du chiffré changé : ${flipOk ? "ACCEPTÉ (altération invisible)" : "REJETÉ (étiquette invalide)"}`);
    code(lines.join("\n"));
    if (kind === "xor") out("Pas de nonce unique, pas d'étiquette : tout ce qu'on a vu aux établis 1 et 3 s'applique. Ada soupire.", "err");
    else if (kind === "ecb") out("Blocs identiques visibles, pas d'authentification : les établis 2 et 3 ressortent. Ada soupire.", "err");
    else if (kind === "maison") out("La clé courte répétée se casse par fréquences et ne protège ni le motif ni l'intégrité. Ada ne prend même pas la peine de soupirer.", "err");
    else {
      out("Aucune fuite, altération rejetée avant déchiffrement : confidentialité et intégrité, en une seule opération, avec une bibliothèque qui gère le nonce à ta place. C'est la réponse à tous les établis.", "ok");
      if (!x.build) { x.build = true; note("aead"); out("Retourne voir `parler ada`.", "sys"); }
    }
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Sept systèmes cassés, sept systèmes réparés, et une seule leçon : on n'invente pas de cryptographie. Gontran utilise désormais une bibliothèque AEAD, laisse la bibliothèque gérer les nonces, tire ses clés et ses jetons du générateur du système et garde ses secrets dans un coffre.");
    say("Gontran", "Je garde une pancarte, quand même : « Garanti inviolable… par les gens qui lisent la documentation ».");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Les parchemins au même nonce = réutilisation de (clé, nonce) dans un chiffrement par flux** (AES-CTR, AES-GCM, ChaCha20). Le flux étant identique, C1 ⊕ C2 = M1 ⊕ M2 ; un mot probable (« crib dragging ») révèle l'autre message. C'est l'erreur de nombreux protocoles réels (WEP, et des implémentations de GCM avec nonce répété).");
    out("**Le guichet à jetons en ECB = le mode ECB.** Chaque bloc est chiffré seul, donc deux clairs identiques donnent deux chiffrés identiques (le fameux manchot qui reste visible) et on peut découper-coller des blocs. Le CBC, le CTR et le GCM rendent chaque bloc dépendant d'un IV ou d'un compteur.");
    out("**L'ordre de virement modifié = malléabilité.** Dans un chiffrement par flux (et, autrement, en CBC), modifier le chiffré modifie le clair de façon prévisible. Le MAC, vérifié avant déchiffrement, rend toute altération détectable ; « chiffrer puis authentifier » avec des clés distinctes est le schéma sûr.");
    out("**Le chronomètre = attaque par canal temporel sur la comparaison.** Une comparaison qui s'arrête au premier écart dure plus longtemps quand le début est juste, et révèle la valeur octet par octet. La parade : comparaison en temps constant (compare_digest en Python, timingSafeEqual dans Node, CRYPTO_memcmp en C).");
    out("**L'urne congruentielle = générateur non cryptographique.** Quelques sorties d'un générateur linéaire suffisent à retrouver ses paramètres et à prédire la suite. Les secrets (jetons, nonces, clés, identifiants de session) viennent du générateur cryptographique du système : crypto.getRandomValues dans le navigateur, /dev/urandom, secrets en Python.");
    out("**L'application et le carnet = clé en dur et dérivation trop rapide.** Une clé dans le code se lit avec « strings » ; une clé dérivée par un simple SHA-256 tombe à un dictionnaire. On range les clés dans un coffre à secrets avec rotation, et on dérive les clés de mots de passe avec Argon2id, scrypt ou PBKDF2, avec sel et coût réglé.");
    out("**Le rouleau maison = crypto maison.** Un XOR avec clé courte répétée (un Vigenère moderne) tombe à l'indice de coïncidence et à l'analyse de fréquences. Un algorithme tenu secret n'ajoute pas de sécurité : seul le secret de la clé compte (principe de Kerckhoffs).");
    out("**L'étagère = une bibliothèque AEAD.** AES-GCM, ChaCha20-Poly1305 ou XChaCha20-Poly1305, via Web Crypto ou libsodium : confidentialité et intégrité en un seul appel, et rejet de tout chiffré modifié.");
    out("**Les simplifications du jeu.** (1) Toutes les primitives sont des jouets bâtis sur le SHA-256 du moteur : le flux n'est ni ChaCha20 ni AES-CTR, le chiffrement par blocs est un Feistel à 4 tours sur 8 octets (AES : blocs de 16 octets), le HMAC est calculé sur du texte hexadécimal et ses étiquettes sont tronquées à 4 ou 8 octets. (2) Les temps de la porte sont simulés et peu bruités : en réseau réel, ces attaques demandent beaucoup de mesures et des statistiques, mais elles existent. (3) Le générateur congruentiel n'a que 16 bits d'état et ses paramètres sont inconnus de l'attaquant par choix de scénario ; les vrais en ont 32 ou 64, mais sont tout aussi prévisibles par algèbre linéaire. (4) La dérivation « lente » est une simple répétition de SHA-256 (3 000 tours) ; en vrai, Argon2id ou scrypt, calibrés pour ~100 ms et beaucoup de mémoire. (5) L'AEAD du jeu est « chiffrer puis authentifier » avec nos jouets, mais en production, utilise l'AEAD tout fait. (6) On n'a pas vu les attaques par oracle de bourrage ni les erreurs de protocole.");
    out("Rappel utile : **n'invente pas ta crypto. Utilise un chiffrement authentifié (AEAD) éprouvé via une bibliothèque, un nonce jamais réutilisé, des clés aléatoires hors du code, une comparaison en temps constant et l'aléa du système.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    xor: () => {
      const x = F(), c1 = C1(), c2 = C2(), X = X12();
      const k1 = x.k1 || "_".repeat(32), k2 = x.k2 || "_".repeat(32);
      const fixed = x.n1fix;
      return {
        cap: fixed ? "Nonces distincts : les deux flux sont différents, le XOR des chiffrés ne simplifie plus rien." : "Même nonce, même flux : le flux s'annule dans C1 XOR C2, qui vaut M1 XOR M2. Un mot probable révèle l'autre message ; en bas, ce que tu sais déjà.",
        svg: SVG(210, "XOR de deux chiffrés",
          T(8, 20, "C1   " + toHex(c1.slice(0, 12)) + "…", "f-s ft-pub", "start") +
          T(8, 40, "C2   " + toHex(c2.slice(0, 12)) + "…", "f-s ft-priv", "start") +
          LN(8, 48, 300, 48) +
          T(8, 64, "C1^C2  " + toHex(X.slice(0, 12)) + "…", "f-s ft-bad", "start") +
          (fixed ? R(8, 82, 404, 40, "f-ok") + T(210, 106, "flux 1 ≠ flux 2 : ce XOR ne vaut plus M1 XOR M2", "f-s ft-ok")
            : R(8, 82, 404, 40, "f-bad") + T(210, 98, "C1 XOR C2 = (M1 XOR flux) XOR (M2 XOR flux) = M1 XOR M2", "f-s ft-bad") + T(210, 114, "le flux (donc la clé) s'annule", "f-s")) +
          T(8, 150, "M1  " + k1, "f-s", "start") + T(8, 170, "M2  " + k2, "f-s", "start") +
          T(8, 198, fixed ? "(connaissances acquises avant la réparation)" : "_ = encore inconnu : agrandis ton mot probable", "f-s", "start"))
      };
    },
    ecb: () => {
      const x = F(), t = (x.toks && x.toks.length) ? x.toks[x.toks.length - 1] : null;
      let blocks, plain;
      if (t) { blocks = t.blocks; plain = t.plain; }
      else { const pb = chunk8(enc(pad8("nom=" + "a".repeat(24) + ";role=client"))); blocks = pb.map(b => toHex(blockEnc(ECB_KEY, b))); plain = pb.map(txt); }
      const n = Math.min(blocks.length, 6), w = 62;
      let s = T(8, 18, x.e_fix ? "CBC : le chiffré d'un bloc dépend du précédent" : "ECB : un bloc de clair identique → un chiffré identique", "f-s", "start");
      const hue = h => parseInt(h.slice(0, 3), 16) % 360;
      for (let i = 0; i < n; i++) {
        const dup = blocks.some((b, j) => j !== i && b === blocks[i]);
        s += `<rect x="${8 + i * w}" y="30" width="${w - 6}" height="26" rx="4" class="f-box"/>` + T(8 + i * w + (w - 6) / 2, 47, (plain[i] || "").slice(0, 8), "f-s");
        s += AR(8 + i * w + (w - 6) / 2, 58, 8 + i * w + (w - 6) / 2, 76, "");
        s += `<rect x="${8 + i * w}" y="78" width="${w - 6}" height="26" rx="4" class="f-box" fill="hsl(${hue(blocks[i])} 60% 55% / ${dup ? 0.75 : 0.3})"/>` + T(8 + i * w + (w - 6) / 2, 95, blocks[i].slice(0, 6), "f-s");
      }
      s += T(8, 128, "clair : blocs de 8 octets", "f-s", "start") + T(8, 144, "chiffré : même couleur = même chiffré", "f-s", "start");
      const dupAny = blocks.some((b, i) => blocks.indexOf(b) !== i);
      s += dupAny ? T(210, 176, "blocs identiques : le motif transpire", "f-b ft-bad") : T(210, 176, "aucun motif visible", "f-b ft-ok");
      s += T(210, 198, x.e_fix ? "mais le CBC n'authentifie toujours rien" : "et chaque bloc se recolle ailleurs sans que le serveur le voie", "f-s");
      return { cap: x.e_fix ? "Le jeton le plus récent en CBC : chaque chiffré dépend du bloc précédent et de l'IV, donc plus de motif ni de blocs interchangeables." : "Le jeton le plus récent, bloc par bloc : en ECB, des blocs de clair identiques se voient dans le chiffré, et chaque bloc peut être déplacé sans que rien ne casse.", svg: SVG(212, "Blocs ECB et motifs", s) };
    },
    mac: () => {
      const x = F();
      const row = (y, a, b) => T(8, y, a, "f-s", "start") + T(120, y, b, "f-s", "start");
      return {
        cap: x.m_fix ? "Avec un MAC (chiffrer puis authentifier) : toute modification du chiffré invalide l'étiquette, que l'attaquant ne sait pas recalculer sans la clé de MAC." : "Sans authentification : en XORant « 1 » et « 9 » dans le chiffré à la position 6, le clair change de « 10 » en « 90 », sans la clé.",
        svg: SVG(220, "Malléabilité et MAC",
          R(8, 20, 130, 40) + T(73, 40, "nonce + chiffré", "f-b") + T(73, 54, "VIRER 10 EUROS...", "f-s") +
          (x.m_fix ? AR(138, 40, 168, 40) + R(168, 20, 86, 40, "f-ok") + T(211, 40, "étiquette", "f-b ft-ok") + T(211, 54, "HMAC", "f-s") : "") +
          T(210, 90, "Mallory : chiffré[6] XOR= « 1 » XOR « 9 »", "f-s ft-bad") + AR(210, 96, 210, 116, "f-bad") +
          (x.m_fix ? R(8, 120, 404, 54, "f-ok") + T(210, 142, "étiquette recalculée ≠ étiquette reçue", "f-b ft-ok") + T(210, 162, "✗ rejeté avant tout déchiffrement", "f-s ft-ok")
            : R(8, 120, 404, 54, "f-bad") + T(210, 142, "la banque déchiffre et exécute", "f-b ft-bad") + T(210, 162, "VIRER 90 EUROS A BOB", "f-s ft-bad")) +
          T(210, 204, x.m_fix ? "clé de chiffrement ≠ clé de MAC" : "chiffrer ne veut pas dire authentifier", "f-s"))
      };
    },
    temps: () => {
      const fixed = F().t_fix;
      let s = T(8, 18, fixed ? "Après correctif : temps de réponse constant" : "Temps de réponse selon le nombre d'octets corrects", "f-s", "start");
      for (let n = 0; n <= 4; n++) {
        const t = fixed ? 160 : 100 + 25 * n, w = Math.round(t * 1.1);
        s += T(8, 48 + n * 26, n + " octet" + (n > 1 ? "s" : "") + " juste" + (n > 1 ? "s" : ""), "f-s", "start") +
          `<rect x="128" y="${36 + n * 26}" width="${w}" height="14" rx="3" fill="var(--${fixed ? "ok" : "bad"})"/>` + T(134 + w, 48 + n * 26, t + " µs", "f-s", "start");
      }
      s += T(210, 190, fixed ? "rien à mesurer : plus de fuite" : "chaque octet juste ajoute ≈ 25 µs : on le lit au chronomètre", "f-s " + (fixed ? "ft-ok" : "ft-bad"));
      return { cap: fixed ? "Comparaison en temps constant : tous les essais durent pareil (au bruit près)." : "Comparaison qui s'arrête au premier écart : le temps trahit le nombre d'octets corrects, donc on devine octet par octet (4×256 essais au lieu de 2^32).", svg: SVG(206, "Fuite temporelle", s) };
    },
    lcg: () => {
      const x = F(), obs = x.obs.slice(-3);
      let s = T(8, 18, x.r_fix ? "Source cryptographique : aucune relation entre les sorties" : "Générateur congruentiel : x' = a·x + c mod " + LM, "f-s", "start");
      const bx = [8, 118, 228], lab = ["x0", "x1", "x2"];
      for (let i = 0; i < 3; i++) {
        s += R(bx[i], 36, 92, 40, obs[i] !== undefined ? "f-pub" : "") + T(bx[i] + 46, 52, lab[i], "f-s") + T(bx[i] + 46, 68, obs[i] !== undefined ? fmtTok(obs[i]) : "?", "f-b");
        if (i < 2) s += AR(bx[i] + 92, 56, bx[i + 1], 56, x.r_fix ? "f-dash" : "");
      }
      s += AR(320, 56, 336, 56, x.r_fix ? "f-dash" : "f-bad") + R(338, 36, 74, 40, x.pred && !x.r_fix ? "f-bad" : "") + T(375, 52, "suivant", "f-s") + T(375, 68, x.pred ? String(x.pred) : "?", "f-b " + (x.pred && !x.r_fix ? "ft-bad" : ""));
      if (x.rec && !x.r_fix) s += T(210, 110, `a = ${x.rec[0]}   c = ${x.rec[1]}   (retrouvés avec 3 sorties)`, "f-s ft-bad") + T(210, 130, "l'état = la dernière sortie : tout l'avenir est connu", "f-s ft-bad");
      else if (x.r_fix) s += T(210, 110, "pas de formule à retrouver : la prédiction tombe à côté", "f-s ft-ok") + T(210, 130, "(crypto.getRandomValues dans un navigateur)", "f-s");
      else s += T(210, 110, "3 sorties → 2 inconnues (a, c) → toute la suite", "f-s");
      return { cap: x.r_fix ? "Avec une source imprévisible, la même méthode ne prédit rien." : "Trois jetons consécutifs permettent de retrouver a et c, donc de prédire le prochain jeton.", svg: SVG(150, "État d'un générateur prévisible", s) };
    },
  };

  GAMES.cryptomisuse = {
    id: "cryptomisuse", order: 27, title: "L'Atelier des Erreurs", pageTitle: "Crypto Misuse Quest", subtitle: "aventure textuelle · erreurs d'usage de la cryptographie",
    blurb: "Casse puis répare sept systèmes « chiffrés » défectueux : nonce réutilisé, ECB, MAC absent, comparaison lente, aléa prévisible.",
    concept: "Cryptographie appliquée : les erreurs d'usage classiques",
    start: "atelier", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      x.seed = 4443; x.toks = []; x.obs = []; x.lstate = LSEED; x.cnt = 0; x.k1 = "_".repeat(32); x.k2 = "_".repeat(32);
    },
    refig(name) { fig(name); },
    figAlias: { xor: ["nonce", "flux"], ecb: ["blocs", "motif"], mac: ["malleabilite", "auth"], temps: ["chrono", "timing"], lcg: ["aleas", "generateur"] },
    help: "Spécifiques : `xor 1 2` · `glisser ‹mot›` · `intercepter` · `modifier ‹pos› ‹ancien› ‹nouveau›` · `inscrire ‹nom›` · `presenter ‹n›` · `coller ‹n.b›...` · `tenter ‹mac›` · `balayer ‹préfixe›` · `observer` · `retrouver` · `predire` · `soumettre ‹jeton›` · `fouiller ‹objet›` · `dechiffrer ‹objet› ‹clé›` · `casser carnet` · `periode` · `frequences ‹n›` · `deviner ‹clé›` · `reparer ‹défaut›` · `construire ‹boîte›`",
    verbs: {
      xor: { words: ["xor", "xorer"], run: ctx => { if (needQuest()) xorCmd(ctx); } },
      slide: { words: ["glisser", "crib"], run: ctx => { if (needQuest()) slide(ctx); } },
      intercept: { words: ["intercepter"], run: ctx => { if (needQuest()) intercept(ctx); } },
      modify: { words: ["modifier", "alterer", "inverser"], run: ctx => { if (needQuest()) modify(ctx); } },
      issue: { words: ["inscrire", "enregistrer"], run: ctx => { if (needQuest()) issueCmd(ctx); } },
      present: { words: ["presenter"], run: ctx => { if (needQuest()) presentCmd(ctx); } },
      paste: { words: ["coller", "assembler", "forger"], run: ctx => { if (needQuest()) pasteCmd(ctx); } },
      tryMac: { words: ["tenter"], run: ctx => { if (needQuest()) timeCmd(ctx); } },
      sweep: { words: ["balayer", "mesurer", "chronometrer"], run: ctx => { if (needQuest()) sweepCmd(ctx); } },
      observe: { words: ["observer"], run: ctx => { if (needQuest()) observe(ctx); } },
      recover: { words: ["retrouver", "remonter"], run: ctx => { if (needQuest()) recoverCmd(ctx); } },
      predict: { words: ["predire", "prevoir"], run: ctx => { if (needQuest()) predictCmd(ctx); } },
      submit: { words: ["soumettre"], run: ctx => { if (needQuest()) submitCmd(ctx); } },
      search: { words: ["fouiller", "strings"], run: ctx => { if (needQuest()) searchCmd(ctx); } },
      decrypt: { words: ["dechiffrer", "decrypter", "ouvrir"], run: ctx => { if (needQuest()) decryptCmd(ctx); } },
      crack: { words: ["casser", "craquer"], run: ctx => { if (needQuest()) crackCmd(ctx); } },
      period: { words: ["periode", "longueur"], run: ctx => { if (needQuest()) periodCmd(ctx); } },
      freq: { words: ["frequences", "frequence", "colonnes"], run: ctx => { if (needQuest()) freqCmd(ctx); } },
      guess: { words: ["deviner"], run: ctx => { if (needQuest()) guessCmd(ctx); } },
      repair: { words: ["reparer", "corriger", "securiser", "patcher"], run: ctx => { if (needQuest()) repairCmd(ctx); } },
      build: { words: ["construire", "assembler systeme"], run: ctx => { if (needQuest()) buildCmd(ctx); } },
    },
    intro() {
      out("L'Atelier des Erreurs", "title");
      out("Gontran, cryptographe de Port-443, est célèbre pour deux choses : il n'a jamais écrit une primitive cryptographique entière, et il n'a jamais utilisé correctement celles des autres. Son atelier est rempli de systèmes « inviolables ». Maître Ada t'y envoie avec un contrat d'audit signé : casser chaque système (en simulation, sur des données fictives), puis le réparer.", "");
    },
  };
})();
