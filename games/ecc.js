"use strict";
/* La Courbe de Port-443 : cryptographie sur courbes elliptiques, à la main sur de petits corps.
   Courbe jouet : y² = x³ + 2x + 2 sur F17, G = (5, 1), ordre 19 (18 points + l'infini).
   Courbe moyenne : y² = x³ + 2x + 40 sur F1000003, G = (2, 463086), ordre 999023 (premier).
   Tout est déterministe (aucun hasard) : le test rejoue toujours la même partie. */
(function () {
  const F = () => f();

  /* ---------- arithmétique de courbe (entiers < 2^53, donc p < 9×10^7) ---------- */
  function mk(p, a, b) {
    const md = v => ((v % p) + p) % p;
    const mm = (u, v) => (u * v) % p;
    const inv = v => {
      v = md(v);
      let r0 = p, r1 = v, t0 = 0, t1 = 1;
      while (r1) { const q = Math.floor(r0 / r1); [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; }
      return r0 === 1 ? md(t0) : null;
    };
    const rhs = x => md(mm(mm(x, x), x) + a * x + b);
    const on = P => !P || (P[0] >= 0 && P[0] < p && P[1] >= 0 && P[1] < p && mm(P[1], P[1]) === rhs(P[0]));
    const neg = P => P ? [P[0], md(-P[1])] : null;
    // addition avec le détail du calcul ; null = point à l'infini O
    function add(P, Q) {
      if (!P) return { R: Q, kind: "neutre" };
      if (!Q) return { R: P, kind: "neutre" };
      let lam, num, den, kind;
      if (P[0] === Q[0]) {
        if (md(P[1] + Q[1]) === 0) return { R: null, kind: "inverse" };
        num = md(3 * mm(P[0], P[0]) + a); den = md(2 * P[1]); kind = "double";
      } else { num = md(Q[1] - P[1]); den = md(Q[0] - P[0]); kind = "chord"; }
      lam = mm(num, inv(den));
      const x3 = md(mm(lam, lam) - P[0] - Q[0]);
      const y3 = md(mm(lam, md(P[0] - x3)) - P[1]);
      return { R: [x3, y3], kind, lam, num, den, den1: inv(den) };
    }
    // multiplication scalaire par doublements et additions (de gauche à droite), avec la trace
    function mul(k, P) {
      if (k === 0 || !P) return { R: null, steps: [], D: 0, A: 0, bits: "0" };
      const bits = k.toString(2);
      let R = P, m = 1, D = 0, A = 0; const steps = [];
      for (let i = 1; i < bits.length; i++) {
        R = add(R, R).R; m *= 2; D++;
        const st = { bit: bits[i], d: R, dm: m };
        if (bits[i] === "1") { R = add(R, P).R; m++; A++; st.a = R; st.am = m; }
        steps.push(st);
      }
      return { R, steps, D, A, bits };
    }
    return { p, a, b, md, mm, inv, rhs, on, neg, add, mul };
  }
  const CA = mk(17, 2, 2), G1 = [5, 1], N1 = 19;
  const CB = mk(1000003, 2, 40), GB = [2, 463086], NB = 999023;
  const KB = 842317;                         // secret de la grande courbe (le jeu le connaît, le joueur le cherche)
  const D1 = 7, QPUB = CA.mul(D1, G1).R;     // clé de signature : d = 7, Q = (0, 6)
  const KQ = 13, QDL = CA.mul(KQ, G1).R;     // logarithme à trouver sur la courbe jouet : (16, 4)
  const DH = { a: 6, b: 11 };
  DH.A = CA.mul(DH.a, G1).R; DH.B = CA.mul(DH.b, G1).R; DH.S = CA.mul(DH.a, DH.B).R;
  let QBIG = null;                           // Q = KB·G sur la grande courbe, calculé au premier besoin
  const bigQ = () => QBIG || (QBIG = CB.mul(KB, GB).R);

  const pt = P => P ? `(${P[0]}, ${P[1]})` : "O";
  const nums = txt => (txt.match(/-?\d+/g) || []).map(Number);
  const nm = (v, n) => ((v % n) + n) % n;
  const ZH = m => parseInt(sha256(m).slice(0, 8), 16) % N1;       // « hachage jouet » : 32 premiers bits mod n
  const SQ = new Set(); for (let y = 0; y < 17; y++) SQ.add(y * y % 17);
  const rootsOf = v => { const r = []; for (let y = 0; y < 17; y++) if (y * y % 17 === v) r.push(y); return r; };
  const POINTS = []; for (let xx = 0; xx < 17; xx++) rootsOf(CA.rhs(xx)).forEach(yy => POINTS.push([xx, yy]));

  // les deux signatures « du serveur » qui ont réutilisé le même nonce
  const K0 = 9, M1 = "virement 10 pieces", M2 = "virement 90 pieces";
  function ecdsaSign(k, m) {
    const R = CA.mul(k, G1).R, r = R[0] % N1, z = ZH(m);
    const s = nm(modpow(k, N1 - 2, N1) * (z + r * D1), N1);
    return { R, r, z, s, k, m };
  }
  const INT = { s1: ecdsaSign(K0, M1), s2: ecdsaSign(K0, M2) };

  const notes = {
    courbe: ["Une courbe elliptique sur un corps fini", "Une courbe elliptique est l'ensemble des points (x, y) vérifiant y² = x³ + ax + b, plus un point à l'infini noté O. Sur un corps fini F_p, x et y sont des restes modulo p : la courbe devient un nuage de points. Ici, y² = x³ + 2x + 2 modulo 17 compte 18 points, plus O : 19 en tout (le théorème de Hasse borne ce nombre : p + 1 ± 2√p). Il faut aussi que 4a³ + 27b² ≠ 0 (mod p), sinon la courbe est « singulière » et n'a plus la bonne structure."],
    addition: ["L'addition de points", "On définit P + Q : la droite passant par P et Q recoupe la courbe en un troisième point, et P + Q est son symétrique (x, −y). Formules : λ = (y2 − y1)/(x2 − x1), x3 = λ² − x1 − x2, y3 = λ(x1 − x3) − y1 ; pour un doublement, λ = (3x1² + a)/(2y1). Diviser, c'est multiplier par l'inverse modulaire (d^(p−2) mod p). L'opposé de (x, y) est (x, −y), et P + (−P) = O, qui joue le rôle de zéro. Ces points forment un groupe : la géométrie sert de décor, c'est l'algèbre qui compte."],
    scalaire: ["La multiplication scalaire kP", "kP = P + P + … + P (k fois). On ne l'additionne pas k fois : on double et on ajoute selon les bits de k (« double-and-add »). Pour un k de 256 bits, environ 255 doublements et 128 additions suffisent : à peu près 400 opérations, contre 10^77 pour la méthode naïve. Ici, 19·G = O : le plus petit k tel que kG = O s'appelle l'ordre de G, et kG ne dépend que de k mod 19."],
    dlog: ["Le logarithme discret elliptique", "Étant donnés G et Q = kG, retrouver k. Calculer kG est rapide, retrouver k n'a aucun raccourci connu en général sur une bonne courbe : les meilleures méthodes génériques (comme rho de Pollard) coûtent environ √n opérations. Sur la courbe jouet (19 points) ou la courbe moyenne (10^6 points), la force brute est instantanée. Sur une courbe d'ordre n ≈ 2^256, il faut ≈ 2^128 opérations : hors de portée. C'est cette asymétrie qui fait la sécurité de toute la cryptographie sur courbes."],
    ecdh: ["Échange de clés ECDH", "Alice choisit a, publie A = aG ; Bob choisit b, publie B = bG. Alice calcule aB, Bob calcule bA : c'est le même point S = abG. Ève voit G, A et B, mais pour obtenir S elle doit résoudre un logarithme discret. On dérive ensuite une clé symétrique du point S (par une fonction de hachage). Attention : ECDH seul n'authentifie personne : Mallory peut se placer au milieu. En pratique, on signe les messages du protocole (TLS), et on utilise des clés éphémères pour la confidentialité persistante."],
    tailles: ["Tailles de clé à sécurité équivalente", "Pour 128 bits de sécurité, il faut environ 256 bits en courbe elliptique et 3072 bits en RSA (NIST SP 800-57) : douze fois plus. À 256 bits de sécurité, c'est 512 bits contre 15360 bits. Les clés, les signatures (64 octets en ECDSA P-256 contre 384 pour RSA-3072) et les échanges réseau sont plus petits ; signer et générer une clé sont bien plus rapides. En revanche, vérifier une signature RSA (avec e = 65537) peut être plus rapide qu'en ECDSA. Un ordinateur quantique assez grand casserait aussi les courbes elliptiques (algorithme de Shor)."],
    ecdsa: ["La signature ECDSA", "Clé privée d, clé publique Q = dG, ordre n. Pour signer un message de hachage z, on tire un nonce k secret, on calcule R = kG, r = x(R) mod n, puis s = k⁻¹(z + r·d) mod n. La signature est (r, s). Pour vérifier, on calcule w = s⁻¹, u1 = z·w, u2 = r·w et le point u1·G + u2·Q : son abscisse mod n doit valoir r. Changer un seul caractère du message change z, et la vérification échoue."],
    nonce: ["Le nonce ne doit jamais être réutilisé", "Si deux signatures utilisent le même k, elles ont le même r, et s1 − s2 = k⁻¹(z1 − z2) donne k = (z1 − z2)/(s1 − s2) mod n, puis d = (s1·k − z1)/r mod n : la clé privée sort d'un simple calcul. Ce n'est pas théorique : la clé de signature de la PlayStation 3 (2010) et des portefeuilles Bitcoin sur Android (2013) ont ainsi été exposées. Même un nonce partiellement prévisible suffit à retrouver la clé. Remèdes : nonce déterministe dérivé de la clé privée et du message (RFC 6979, Ed25519), et bon générateur aléatoire."],
    standard: ["Courbes standard, jamais maison", "Utilise des courbes standardisées, analysées par de nombreux cryptographes : X25519 (échange de clés, 32 octets, conçue pour être difficile à mal implémenter), Ed25519 (signatures à nonce déterministe), P-256 (NIST, partout dans TLS et les passeports), secp256k1 (Bitcoin). Une courbe maison peut être singulière, avoir un ordre « lisse » ou un cofacteur dangereux, sans que ça se voie. Il faut aussi valider chaque point reçu : un point hors de la courbe, accepté sans contrôle, fait travailler le calcul sur une autre courbe et peut faire fuiter la clé privée (attaque par courbe invalide). Et on n'écrit pas ses propres routines : on utilise une bibliothèque éprouvée."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Sur son bureau, un parchemin porte un seul mot, souligné trois fois : « petit »." },
    rivest: { npc: true, names: ["rivest", "dame rivest", "forgeronne"], label: "Dame Rivest", desc: () => "Dame Rivest, forgeronne de clés, qui a troqué sa clé à molette contre un compas et une règle. Elle présente la nouvelle courbe de la Guilde." },
    grille: { names: ["grille", "courbe", "carte", "damier"], label: "la grille de la courbe", vis: () => S.room === "atelier",
      desc: () => F().counted ? "Une grille de 17 × 17 cases, où chaque point de la courbe est marqué d'un clou. (`schema courbe` pour la voir.)" : "Une grande grille de 17 × 17 cases, vide : x en abscisse, y en ordonnée, de 0 à 16. La courbe y² = x³ + 2x + 2 (mod 17) doit y être clouée point par point : `tester ‹x›` évalue x³ + 2x + 2 pour une valeur de x, `lister` clouera tout." },
    parchemin: { names: ["parchemin", "recette", "formules", "defi"], label: "le parchemin des formules", vis: () => S.room === "atelier", onExamine() { F().sawRecipe = true; },
      desc: () => {
        const x = F();
        let s = "Courbe : y² = x³ + 2x + 2 modulo 17. Point de départ G = (5, 1).\nAddition (x1 ≠ x2) : λ = (y2 − y1)/(x2 − x1), x3 = λ² − x1 − x2, y3 = λ(x1 − x3) − y1. Doublement : λ = (3·x1² + a)/(2·y1) avec a = 2, puis mêmes x3 et y3. Opposé : −(x, y) = (x, −y). P + (−P) = O.\nDiviser par d modulo 17, c'est multiplier par d^15 modulo 17 : `calc ‹d›^15 mod 17`. Attention au boulier : écris des parenthèses, par exemple `calc (3*25+2) mod 17`, et pour une soustraction ajoute 17 pour rester positif : `calc (1-9+17) mod 17`. Quand tu as (x3, y3), envoie `verifier ‹x3› ‹y3›`.";
        if (!x.addDone) s += "\nDÉFI 1 : additionne P = (5, 1) et Q = (9, 16).";
        else if (!x.dblDone) s += "\nDÉFI 2 : double T = (3, 1) (calcule T + T avec la tangente).";
        else s += "\nDéfis réussis. L'additionneur accepte toutes les additions : `ajouter ‹x1› ‹y1› ‹x2› ‹y2›`. Et `multiplier ‹k›` calcule kG par doublements et additions.";
        return s;
      } },
    additionneur: { names: ["additionneur", "machine", "mecanisme"], label: "l'additionneur de points", vis: () => S.room === "atelier" && F().dblDone,
      desc: () => "Un mécanisme de cuivre, réglé sur la courbe y² = x³ + 2x + 2 (mod 17). `ajouter ‹x1› ‹y1› ‹x2› ‹y2›` montre toutes les étapes d'une addition ; `multiplier ‹k›` calcule kG ; `multiplier ‹k› ‹x› ‹y›` multiplie un autre point de la courbe." },
    mallory: { npc: true, names: ["mallory", "attaquante"], label: "Mallory", vis: () => ["tour", "scriptorium", "halle"].includes(S.room),
      desc: () => "Mallory, boulier en bandoulière, qui lorgne sur les clés de tout le monde. Audit autorisé : tout est simulé." },
    alice: { npc: true, names: ["alice"], label: "Alice", vis: () => S.room === "tour" || S.room === "scriptorium", desc: () => "Alice, qui échange des messages secrets avec Bob. Elle a un secret a et signe ses virements." },
    bob: { npc: true, names: ["bob"], label: "Bob", vis: () => S.room === "tour" || S.room === "halle", desc: () => "Bob, trésorier de la Guilde. Il aime les messages courts et les factures plus courtes encore." },
    eve: { npc: true, names: ["eve", "espionne"], label: "Ève", vis: () => S.room === "tour", desc: () => "Ève, qui écoute tout ce qui passe sur le réseau de Port-443. Elle voit les points publics, jamais les secrets." },
    ardoise: { names: ["ardoise", "tableau noir", "defi"], label: "l'ardoise du logarithme", vis: () => S.room === "tour",
      desc: () => `L'ardoise de la tour. Courbe jouet : G = ${pt(G1)}, Q = ${pt(QDL)} (Q = k·G, k inconnu). Grande courbe (p = 1000003, y² = x³ + 2x + 40, ordre premier ${NB}) : G = ${pt(GB)}, Q = ${pt(bigQ())}. Commandes : \`multiplier ‹k› grande\` (sens facile), \`chercher\` puis \`chercher grande\` (force brute), \`echanger\` (ECDH d'Alice et Bob), \`espionner\` (Ève).` },
    pupitre: { names: ["pupitre", "registre", "signatures"], label: "le pupitre des signatures", vis: () => S.room === "scriptorium",
      desc: () => `Au pupitre, le scribe signe avec la courbe jouet (n = ${N1}, G = ${pt(G1)}). Clé publique d'Alice : Q = ${pt(QPUB)} (sa clé privée d reste dans sa poche). Le « hachage » est SHA-256, 32 premiers bits lus comme un nombre, modulo ${N1}. \`signer ‹k› ‹message›\` signe avec le nonce k (de 1 à 18). \`verifier ‹r› ‹s›\` vérifie la dernière signature ; \`verifier ‹r› ‹s› ‹autre message›\` la teste contre un autre texte. \`intercepter\` montre ce que Mallory a capté.` },
    balance: { names: ["balance", "comptoir", "tailles", "grille des tailles"], label: "la balance des clés", vis: () => S.room === "halle",
      desc: () => "Une balance à deux plateaux : d'un côté une clé RSA, de l'autre une clé de courbe elliptique. `niveau ‹bits›` choisit une sécurité (80, 112, 128, 192 ou 256) et pèse les deux clés." },
    etal: { names: ["etal", "vitrine", "courbes"], label: "l'étal des courbes", vis: () => S.room === "halle",
      desc: () => "Dans la vitrine : des courbes standard (X25519, P-256) sous verre, et un étal de Mallory où traînent des « courbes maison ». `auditer ‹p› ‹a› ‹b›` contrôle une courbe y² = x³ + ax + b modulo p (p premier jusqu'à 2000000). Mallory propose sa courbe : p = 17, a = 14, b = 2. `valider ‹x› ‹y›` contrôle un point reçu sur la courbe jouet." },
  };

  const rooms = {
    place: { name: "La place de la Guilde", short: "Place", alias: ["place", "guilde"], ents: ["ada"], exits: { nord: "atelier", est: "tour", ouest: "scriptorium", sud: "halle" },
      desc: () => "Le cœur de Port-443. Au nord, l'atelier de la Courbe. À l'est, la tour du Logarithme. À l'ouest, le scriptorium des signatures. Au sud, la halle des Tailles." },
    atelier: { name: "L'atelier de la Courbe", short: "Atelier", alias: ["atelier", "courbe"], ents: ["rivest", "grille", "parchemin", "additionneur"], exits: { sud: "place" },
      desc: () => "Un atelier d'arithmétique : une grande grille, des clous, un compas. Dame Rivest y présente la courbe de la Guilde." },
    tour: { name: "La tour du Logarithme", short: "Tour", alias: ["tour", "logarithme"], ents: ["mallory", "alice", "bob", "eve", "ardoise"], exits: { ouest: "place" },
      desc: () => "Une tour d'ardoises où l'on essaie de remonter de kG à k. Mallory et son boulier y traînent ; Alice, Bob et Ève aussi, car on y échange des clés." },
    scriptorium: { name: "Le scriptorium des signatures", short: "Scriptorium", alias: ["scriptorium", "signatures"], ents: ["alice", "mallory", "pupitre"], exits: { est: "place" },
      desc: () => "Une salle silencieuse où l'on signe les virements de la Guilde. Un pupitre, une plume, et Mallory, qui guette les doublons." },
    halle: { name: "La halle des Tailles", short: "Halle", alias: ["halle", "tailles"], ents: ["bob", "mallory", "balance", "etal"], exits: { nord: "place" },
      desc: () => "Une halle de marché où l'on pèse les clés et où l'on choisit des courbes : une balance, une vitrine de courbes sérieuses et l'étal douteux de Mallory." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if ((x.tx || []).length < 3) return "test";
    if (!x.listed) return "list";
    if (!x.counted) return "count";
    if (!x.addDone) return "add";
    if (!x.dblDone) return "dbl";
    if (!x.infDone) return "inf";
    if (!x.mulDone) return "mul";
    if (!x.orderDone) return "ordre";
    if (!x.easyDone) return "easy";
    if (!x.dlog1) return "dlog1";
    if (!x.dlog2) return "dlog2";
    if (!x.bitsDone) return "bits";
    if (!x.dh) return "dh1";
    if (!x.dhOk) return "dh2";
    if (!x.eveDone) return "eve";
    if (!x.sig) return "sig1";
    if (!x.sigOk) return "sig2";
    if (!x.tamper) return "sig3";
    if (!x.intercepted) return "icpt";
    if (!x.kOk) return "k";
    if (!x.dOk) return "d";
    if (!x.lvl128) return "size1";
    if (!x.sizeOk) return "size2";
    if (!x.auditSing) return "audit1";
    if (!x.auditGood) return "audit2";
    if (!x.validated) return "valid";
    if (!x.end) return "end";
    return "fin";
  };
  const addTask = () => ({ P: [5, 1], Q: [9, 16] });
  const hints = {
    quest: () => ["Maître Ada t'attend sur la place.", "`parler ada`"],
    test: () => ["Va à l'atelier (nord de la place) et évalue x³ + 2x + 2 pour trois valeurs de x. Un point existe si le résultat est un carré modulo 17.", "`aller nord`, puis `tester 5`, `tester 1`, `tester 2` (ou d'autres valeurs de 0 à 16)."],
    list: () => ["Fais maintenant l'inventaire complet de la courbe : toutes les valeurs de x d'un coup.", "`lister`"],
    count: () => ["Compte les points listés (une ligne par valeur de x, avec ses y). N'oublie pas qu'il existe un point de plus, qui n'est dans aucune case.", "18 points dans la liste, plus le point à l'infini O : `dire 19`."],
    add: () => ["Additionne P = (5, 1) et Q = (9, 16) avec les formules du parchemin. D'abord λ = (y2 − y1)/(x2 − x1) modulo 17 : l'inverse de (x2 − x1) se calcule avec une puissance.", "Dénominateur 9 − 5 = 4, son inverse : `calc 4^15 mod 17` (= 13). λ = `calc 15*13 mod 17`. Puis x3 = λ² − 5 − 9, y3 = λ(5 − x3) − 1, tous modulo 17. Réponds par `verifier ‹x3› ‹y3›`."],
    dbl: () => ["Double T = (3, 1) : λ = (3·3² + 2)/(2·1) modulo 17, puis mêmes formules pour x3 et y3 avec x1 = x2 = 3.", "Numérateur `calc (3*3*3+2) mod 17` (= 12), dénominateur 2, inverse `calc 2^15 mod 17` (= 9). Puis `verifier ‹x3› ‹y3›`."],
    inf: () => ["Rivest veut que tu additionnes un point et son opposé. L'opposé de (x, y) est (x, −y) : l'additionneur est maintenant à ta disposition.", "L'opposé de (5, 1) est (5, 16) : `ajouter 5 1 5 16`."],
    mul: () => ["Calcule un multiple de G avec l'additionneur : il double et ajoute selon les bits de k.", "`multiplier 13`"],
    ordre: () => ["Continue à multiplier G : à quel k retombe-t-on sur le point à l'infini ? (Le nombre de points de la courbe est la réponse.)", "`multiplier 19`"],
    easy: () => ["Va à la tour (est de la place) et teste la grande courbe : multiplier est facile, même avec un grand k.", "`aller est` (depuis la place), `multiplier 777777 grande`."],
    dlog1: () => ["Dans l'autre sens : retrouve k à partir de Q sur la courbe jouet, en essayant 1G, 2G, 3G…", "`chercher`"],
    dlog2: () => ["Même chose sur la grande courbe, qui compte environ un million de points.", "`chercher grande`"],
    bits: () => ["Sur une courbe de 256 bits, le meilleur algorithme générique coûte environ la racine carrée de l'ordre. Combien de bits d'effort cela fait-il ? Tu as `calc`.", "La racine carrée de 2^256 est 2^128 : `dire 128`."],
    dh1: () => ["Alice et Bob veulent se mettre d'accord sur un secret en public. Lance l'échange.", "`echanger`"],
    dh2: () => ["Tu joues Alice : multiplie le point publié par Bob par ton secret a, puis envoie le résultat.", `\`multiplier ${DH.a} ${DH.B[0]} ${DH.B[1]}\` puis \`verifier ‹x› ‹y›\`.`],
    eve: () => ["Ève a vu A et B. Sur une courbe aussi petite, peut-elle retrouver le secret ?", "`espionner`"],
    sig1: () => ["Le scriptorium est à l'ouest de la place. Signe un message avec un nonce de ton choix (de 1 à 18).", "`aller ouest` (depuis la place), puis `signer 5 facture 40 pieces`."],
    sig2: () => ["Vérifie la signature avec la clé publique, comme le fera Bob.", "`verifier ‹r› ‹s›` avec les deux nombres de ta signature."],
    sig3: () => ["Une signature doit échouer si le message est modifié. Teste.", "`verifier ‹r› ‹s› facture 140 pieces` (avec les r et s de ta signature)."],
    icpt: () => ["Mallory a capté deux signatures du serveur de Bob. Regarde-les de près.", "`intercepter`"],
    k: () => {
      const a = INT.s1, b = INT.s2, ds = nm(a.s - b.s, N1), dz = nm(a.z - b.z, N1);
      return ["Les deux signatures ont le même r, donc le même nonce k. Soustrais : s1 − s2 = k⁻¹(z1 − z2), donc k = (z1 − z2)/(s1 − s2) modulo 19.", `Δz = ${dz}, Δs = ${ds}. Inverse de Δs : \`calc ${ds}^17 mod 19\`, puis \`calc ${dz}*‹inverse› mod 19\`. Réponds \`dire ‹k›\`.`];
    },
    d: () => {
      const a = INT.s1;
      return ["Maintenant que k est connu : s1 = k⁻¹(z1 + r·d), donc d = (s1·k − z1)/r modulo 19.", `\`calc ${a.s}*${K0} mod 19\`, soustrais z1 = ${a.z} (ajoute 19 si besoin), multiplie par l'inverse de r = ${a.r} (\`calc ${a.r}^17 mod 19\`), modulo 19. Puis \`dire ‹d›\`.`];
    },
    size1: () => ["La halle des Tailles est au sud de la place. Pèse les clés pour 128 bits de sécurité.", "`aller sud`, puis `niveau 128`."],
    size2: () => ["Combien de fois la clé RSA est-elle plus grande que la clé de courbe à 128 bits ?", "3072 / 256 : `calc 3072/256`, puis `dire 12`."],
    audit1: () => ["Mallory propose sa courbe maison (p = 17, a = 14, b = 2). Audite-la avant de lui faire confiance.", "`auditer 17 14 2`"],
    audit2: () => ["Compare avec une courbe sérieuse : audite la courbe de l'atelier.", "`auditer 17 2 2` (ou la grande : `auditer 1000003 2 40`)."],
    valid: () => ["Un client envoie un point (3, 4) comme clé publique. Un serveur sérieux le valide avant de s'en servir.", "`valider 3 4`"],
    end: () => ["Tu as tout vu. Retourne voir Maître Ada.", "`aller nord`, `aller sud` si besoin, puis `parler ada`."],
    fin: () => ["Aventure terminée. Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "La Guilde trouve que nos clés RSA sont lourdes : des nombres de 600 chiffres, des certificats qui pèsent, des serveurs qui ahanent. Dame Rivest propose mieux : des clés bien plus petites pour la même sécurité. Le secret s'appelle courbe elliptique.");
          say("Maître Ada", "Tu vas la fabriquer à la main, sur un tout petit corps (modulo 17), puis voir pourquoi le même principe, avec des nombres de 256 bits, tient la route. Commence par l'atelier, au nord. Tu auras ton `calc`.");
          out("`aller nord`", "sys");
        } else if (x.end) say("Maître Ada", "La Guilde passe aux courbes standard. Et elle a banni les courbes maison et les nonces réutilisés.");
        else if (objective() === "end") ending();
        else say("Maître Ada", "Tu es en route. `indice` si tu bloques.");
        break;
      case "rivest": {
        const o = objective();
        if (o === "quest") say("Dame Rivest", "Va d'abord voir Maître Ada, elle t'expliquera.");
        else if (o === "test" || o === "list" || o === "count") say("Dame Rivest", "Une courbe elliptique, ce sont les points (x, y) tels que y² = x³ + 2x + 2. Sur le corps à 17 éléments, x et y sont des restes modulo 17 : la courbe devient un nuage de points sur ma grille. À toi de les trouver : `tester ‹x›` calcule x³ + 2x + 2 ; si le résultat est un carré modulo 17, il y a un ou deux points. Puis `lister`, et compte.");
        else if (o === "add") say("Dame Rivest", "Le plus beau : on peut additionner deux points. On trace la droite qui passe par P et Q, elle recoupe la courbe en un troisième point, et P + Q est son symétrique par rapport à l'axe des x. Sans dessin, ce sont des formules (regarde le parchemin). Additionne P = (5, 1) et Q = (9, 16), puis `verifier ‹x3› ‹y3›`.");
        else if (o === "dbl") say("Dame Rivest", "Bien. Maintenant le cas spécial : additionner un point avec lui-même. La droite devient la tangente. Double T = (3, 1).");
        else if (o === "inf") say("Dame Rivest", "Dernier cas : P + (−P). Les deux points sont sur la même verticale : la droite ne recoupe plus la courbe. On convient alors que le résultat est le point à l'infini O, qui joue le rôle de zéro. Mon additionneur est à toi : essaie avec (5, 1) et son opposé (5, 16).");
        else if (o === "mul") say("Dame Rivest", "On sait additionner : on sait donc multiplier. kP, c'est P ajouté k fois, mais on ne l'additionne pas k fois : on double, et on ajoute quand le bit de k vaut 1. Essaie `multiplier ‹k›` (par exemple 13) et regarde les étapes.");
        else if (o === "ordre") say("Dame Rivest", "Continue de multiplier G : les multiples tournent en rond. À quel k retrouve-t-on le point à l'infini ? Ce nombre est l'ordre du point.");
        else say("Dame Rivest", "La suite est à la tour du Logarithme, à l'est de la place : on y regarde pourquoi remonter de kG à k est dur.");
        break;
      }
      case "alice":
        if (S.room === "tour") {
          if (!x.bitsDone) say("Alice", "Quand Mallory aura fini ses démonstrations, Bob et moi voudrions nous mettre d'accord sur un secret, en public. `echanger`.");
          else if (!x.dh) say("Alice", "Je suis prête : `echanger`. Mon secret a est dans ma poche, mais tu joues mon rôle.");
          else if (!x.dhOk) say("Alice", `Bob m'a envoyé B = ${pt(DH.B)}. À moi de calculer a·B. Fais-le avec \`multiplier ${DH.a} ${DH.B[0]} ${DH.B[1]}\`, puis \`verifier ‹x› ‹y›\`.`);
          else say("Alice", "Nous avons notre secret commun. Reste Ève : `espionner`.");
        } else if (!x.sig) say("Alice", "Je dois signer un virement à Bob. Signe-le avec un nonce de ton choix : `signer ‹k› ‹message›`, par exemple `signer 5 facture 40 pieces`.");
        else if (!x.sigOk) say("Alice", "Voilà ma signature. Vérifie-la : `verifier ‹r› ‹s›`.");
        else if (!x.dOk) say("Alice", "Mon serveur signe des milliers de virements par jour. Mallory dit qu'il y a un défaut. Je n'y crois pas.");
        else say("Alice", "Mon serveur utilise maintenant un nonce déterministe. Merci.");
        break;
      case "bob":
        if (S.room === "tour") say("Bob", "Je publie B = bG et je garde b. Alice fait de même. Le secret commun, c'est abG.");
        else say("Bob", "Mon serveur reçoit des clés publiques de partout. Si je ne vérifie pas qu'elles sont bien sur la courbe, je prends des risques. Voyons ça à l'étal.");
        break;
      case "eve":
        if (!x.dhOk) say("Ève", "J'écoute tout. Dès qu'Alice et Bob auront échangé leurs points, je les noterai.");
        else say("Ève", "Je ne vois que A et B. Pour trouver abG, il me faut a ou b : `espionner` si tu veux me voir essayer.");
        break;
      case "mallory":
        if (S.room === "tour") say("Mallory", "La force brute, c'est ma spécialité : j'essaie 1G, 2G, 3G… jusqu'à tomber sur Q. `chercher` sur la courbe jouet, `chercher grande` sur la moyenne.");
        else if (S.room === "scriptorium") say("Mallory", x.intercepted ? "Tu as vu : même r dans les deux signatures. C'est la signature du nonce réutilisé. À toi de jouer : retrouve k, puis d." : "Je surveille ce serveur depuis un moment. Quand tu auras signé et vérifié, je te montrerai ce que j'ai capté : `intercepter`.");
        else say("Mallory", "Ma courbe maison est toute neuve : p = 17, a = 14, b = 2. Elle est plus rapide que celles de la vitrine. Audite-la si tu l'oses : `auditer 17 14 2`.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- atelier : points, addition ---------- */
  function need(room, msg) { if (S.room !== room) { out(msg, "sys"); return false; } return true; }
  function testX(c) {
    const x = F();
    if (!need("atelier", "Ce calcul se fait à l'atelier (nord de la place).")) return;
    const n = nums(c.rawArg)[0];
    if (n === undefined || n < 0 || n > 16) { out("Une valeur de x entre 0 et 16 : `tester 5`.", "err"); return; }
    const v = CA.rhs(n), ys = rootsOf(v);
    x.tx = x.tx || []; if (!x.tx.includes(n)) x.tx.push(n);
    out(`x = ${n} : x³ + 2x + 2 = ${n * n * n} + ${2 * n} + 2 = ${n * n * n + 2 * n + 2} ≡ **${v}** (mod 17).`, "ok");
    if (ys.length === 2) out(`${v} est un carré modulo 17 : ${ys[0]}² ≡ ${ys[1]}² ≡ ${v}. Deux points : **(${n}, ${ys[0]})** et **(${n}, ${ys[1]})**.`, "ok");
    else if (ys.length === 1) out(`${v} est un carré (y = ${ys[0]}, racine double). Un seul point : (${n}, ${ys[0]}).`, "ok");
    else out(`${v} n'est le carré d'aucun nombre modulo 17 (les carrés sont ${[...SQ].sort((a, b) => a - b).join(", ")}). Aucun point pour x = ${n}.`, "err");
    if (x.tx.length === 3) out("Tu as le principe. `lister` fait le tour de toutes les valeurs de x.", "sys");
  }
  function listAll() {
    const x = F();
    if (!need("atelier", "La grille est à l'atelier (nord de la place).")) return;
    if ((x.tx || []).length < 3) { out("Teste d'abord à la main au moins trois valeurs de x : `tester ‹x›`.", "sys"); return; }
    const lines = [];
    for (let xx = 0; xx < 17; xx++) {
      const v = CA.rhs(xx), ys = rootsOf(v);
      lines.push(`x = ${String(xx).padStart(2)} : x³+2x+2 ≡ ${String(v).padStart(2)}  ${ys.length ? "y = " + ys.join(" ou ") : "(pas un carré)"}`);
    }
    code(lines.join("\n"));
    x.listed = true;
    out(`Les clous sont posés : ${POINTS.length} points. Combien la courbe en compte-t-elle au total ? \`dire ‹nombre›\` (pense au point à l'infini).`, "ok");
  }
  function markPt(P, label) {
    const x = F(); x.marks = x.marks || [];
    if (P && !x.marks.some(m => m.p[0] === P[0] && m.p[1] === P[1])) x.marks.push({ p: P, l: label });
    if (x.marks.length > 6) x.marks.shift();
  }
  function deriv(P, Q, d) {
    const L = [];
    if (d.kind === "chord") {
      L.push(`λ = (${Q[1]} − ${P[1]}) / (${Q[0]} − ${P[0]}) = ${d.num} / ${d.den} = ${d.num} × ${d.den1} = ${d.lam} (mod 17)`);
    } else {
      L.push(`λ = (3·${P[0]}² + ${CA.a}) / (2·${P[1]}) = ${d.num} / ${d.den} = ${d.num} × ${d.den1} = ${d.lam} (mod 17)`);
    }
    L.push(`x3 = λ² − x1 − x2 = ${d.lam * d.lam} − ${P[0]} − ${Q[0]} ≡ ${d.R[0]}`);
    L.push(`y3 = λ(x1 − x3) − y1 = ${d.lam}·(${P[0]} − ${d.R[0]}) − ${P[1]} ≡ ${d.R[1]}`);
    return L.join("\n");
  }
  function lastAdd(P, Q, d) { F().lastAdd = { P, Q, R: d.R, lam: d.lam, kind: d.kind }; }
  function checkAtelier(c) {
    const x = F();
    const t = norm(c.rawArg);
    const nn = nums(c.rawArg);
    if (!x.addDone || !x.dblDone) {
      const isAdd = !x.addDone;
      const P = isAdd ? addTask().P : [3, 1], Q = isAdd ? addTask().Q : [3, 1];
      const d = CA.add(P, Q), want = d.R;
      if (nn.length < 2) { out("Donne le point : `verifier ‹x3› ‹y3›`.", "err"); return; }
      const g = [nn[0], nn[1]];
      if (g[0] === want[0] && g[1] === want[1]) {
        out(isAdd ? `Exact : P + Q = ${pt(want)}.` : `Exact : 2T = ${pt(want)}.`, "ok");
        code(deriv(P, Q, d));
        out(`Le point ${pt(want)} est bien sur la courbe (${want[1]}² = ${want[1] * want[1]} ≡ ${CA.mm(want[1], want[1])}, et x³ + 2x + 2 ≡ ${CA.rhs(want[0])}). L'addition de deux points de la courbe donne toujours un point de la courbe : c'est ce qui en fait un groupe.`, "ok");
        lastAdd(P, Q, d); markPt(P, isAdd ? "P" : "T"); markPt(Q, isAdd ? "Q" : "T"); markPt(want, isAdd ? "P+Q" : "2T");
        if (isAdd) { x.addDone = true; fig("addition"); out("Passons au doublement : `examiner parchemin` pour voir le défi 2.", "sys"); }
        else { x.dblDone = true; out("Maintenant tu sais tout faire sauf un cas : P + (−P). Dame Rivest te confie son additionneur : `parler rivest`.", "sys"); }
        return;
      }
      x.bad = (x.bad || 0) + 1;
      if (!CA.on(g)) {
        out(`Le point ${pt(g)} n'est pas sur la courbe : y² = ${CA.mm(g[1], g[1])} mais x³ + 2x + 2 = ${CA.rhs(g[0])} (mod 17). Une erreur s'est glissée dans λ, dans x3 ou dans y3.`, "err");
      } else if (g[0] === want[0] && g[1] === CA.md(-want[1])) {
        out("Bon x, mais le mauvais signe pour y : la droite recoupe la courbe en un point, et le résultat est son symétrique (x, −y). Tu as sans doute oublié de retourner le point, ou calculé y3 sans le − y1.", "err");
      } else out(`${pt(g)} est sur la courbe, mais ce n'est pas ${isAdd ? "P + Q" : "2T"}. Recalcule λ avec soin.`, "err");
      if (x.bad >= 3) { out(`Coup de pouce : λ = ${d.lam}. Reprends à partir de là : x3 = λ² − x1 − x2, y3 = λ(x1 − x3) − y1 (mod 17).`, "sys"); }
      return;
    }
    out("Tu as réussi les deux défis. Pour une addition quelconque : `ajouter ‹x1› ‹y1› ‹x2› ‹y2›`.", "sys");
    void t;
  }
  function addCmd(c) {
    const x = F();
    if (!need("atelier", "L'additionneur est à l'atelier (nord de la place).")) return;
    if (!x.dblDone) { out("Réussis d'abord les deux défis à la main : `examiner parchemin`.", "sys"); return; }
    const nn = nums(c.rawArg);
    if (nn.length < 4) { out("Donne deux points : `ajouter 5 1 5 16`.", "err"); return; }
    const P = [nn[0], nn[1]], Q = [nn[2], nn[3]];
    for (const [Z, nme] of [[P, "premier"], [Q, "second"]]) if (!CA.on(Z)) { out(`Le ${nme} point ${pt(Z)} n'est pas sur la courbe : l'additionneur refuse (la courbe, c'est y² = x³ + 2x + 2 modulo 17).`, "err"); return; }
    const d = CA.add(P, Q);
    if (d.kind === "inverse") {
      out(`${pt(P)} + ${pt(Q)} : même abscisse, ordonnées opposées (${P[1]} + ${Q[1]} ≡ 0 mod 17). La droite est verticale et ne recoupe plus la courbe : le résultat est le point à l'infini **O**.`, "ok");
      F().lastAdd = { P, Q, R: null, lam: null, kind: "inverse" };
      if (!x.infDone) { x.infDone = true; note("addition"); fig("addition"); out("Dame Rivest : « O joue le rôle du zéro : P + O = P, et P + (−P) = O. Les points de la courbe forment un groupe. Prochaine étape : les multiples. »", "sys"); }
      return;
    }
    if (d.kind === "neutre") { out("Ça ne sert à rien : P + O = P.", "sys"); return; }
    out(`${d.kind === "double" ? "Doublement" : "Addition"} : ${pt(P)} + ${pt(Q)} = **${pt(d.R)}**.`, "ok");
    code(deriv(P, Q, d));
    lastAdd(P, Q, d);
    if (!x.infDone) out(`Essaie le cas particulier : \`ajouter ${G1[0]} ${G1[1]} ${G1[0]} ${CA.md(-G1[1])}\`.`, "sys");
  }

  /* ---------- multiplication scalaire ---------- */
  function mulText(k, P, r, C, fmtP) {
    const L = [`k = ${k} = ${r.bits} en binaire`, `R = P = ${fmtP(P)}`];
    r.steps.forEach(s => L.push(`bit ${s.bit} : doubler -> ${s.dm}P = ${fmtP(s.d)}` + (s.a !== undefined ? ` ; ajouter P -> ${s.am}P = ${fmtP(s.a)}` : "")));
    return L;
  }
  function mulCmd(c) {
    const x = F();
    if (S.room !== "atelier" && S.room !== "tour") { out("Les multiplications se font à l'atelier (nord de la place) ou à la tour (est).", "sys"); return; }
    if (S.room === "atelier" && !x.dblDone) { out("Réussis d'abord les deux défis d'addition (`examiner parchemin`).", "sys"); return; }
    if (S.room === "atelier" && !x.infDone) { out("Fais d'abord l'essai de P + (−P) avec `ajouter`.", "sys"); return; }
    const t = norm(c.rawArg), nn = nums(c.rawArg);
    const big = /grande|grand|moyenne|gros/.test(t);
    if (!nn.length || nn[0] < 0) { out("`multiplier ‹k›` (par exemple `multiplier 13`), ou `multiplier ‹k› ‹x› ‹y›` pour un autre point, ou `multiplier ‹k› grande` à la tour.", "err"); return; }
    const k = nn[0];
    if (big && S.room !== "tour") { out("La grande courbe est à la tour (est de la place).", "sys"); return; }
    const C = big ? CB : CA;
    let P = big ? GB : G1;
    if (!big && nn.length >= 3) {
      P = [nn[1], nn[2]];
      if (!CA.on(P) || !P) { out(`Le point ${pt(P)} n'est pas sur la courbe jouet.`, "err"); return; }
    }
    if (k > 1e9) { out("Reste raisonnable : k jusqu'à un milliard.", "err"); return; }
    if (k === 0) { out("0·P = O, par convention.", "sys"); return; }
    const r = C.mul(k, P);
    const ptxt = Z => Z ? `(${Z[0]}, ${Z[1]})` : "O";
    const lines = mulText(k, P, r, C, ptxt);
    code(lines.length > 26 ? lines.slice(0, 24).concat([`… (${lines.length - 24} lignes de plus)`]).join("\n") : lines.join("\n"));
    out(`${k}·${ptxt(P)} = **${ptxt(r.R)}**. Coût : ${r.D} doublement${r.D > 1 ? "s" : ""} + ${r.A} addition${r.A > 1 ? "s" : ""} = **${r.D + r.A} opérations**, au lieu de ${k - 1} additions en répétant P.`, "ok");
    if (big) {
      out(`Pour un k de 256 bits : environ 255 doublements + 128 additions, soit moins de 400 opérations. Sens facile : kP se calcule en un clin d'œil, même pour un k gigantesque.`, "sys");
      if (!x.easyDone) { x.easyDone = true; out("Maintenant le sens inverse : `chercher` (courbe jouet), puis `chercher grande`.", "sys"); }
      return;
    }
    x.lastMul = { k, P, R: r.R, steps: r.steps, D: r.D, A: r.A, bits: r.bits };
    if (k >= 2 && S.room === "atelier" && !x.mulDone) { x.mulDone = true; fig("kp"); out("Les bits de k pilotent tout : un doublement par bit, une addition par bit à 1. `schema kp` pour le résumé.", "sys"); }
    if (k % N1 === 0 && !r.R) {
      out(`${N1}·${ptxt(P)} = O : les multiples tournent en rond. Le plus petit k tel que kP = O s'appelle l'ordre de P : ici ${N1}, qui est aussi le nombre de points de la courbe. Du coup kP ne dépend que de k mod ${N1} (20·P = P, 21·P = 2P…).`, "ok");
      if (S.room === "atelier" && !x.orderDone) { x.orderDone = true; note("scalaire"); out("Dame Rivest te renvoie vers la tour du Logarithme : à l'est de la place.", "sys"); }
    } else if (k > N1 && S.room === "atelier") out(`(Rappel : ${N1}·P = O, donc ${k}·P = ${k % N1}·P.)`, "sys");
  }

  /* ---------- tour : logarithme discret, ECDH ---------- */
  function searchCmd(c) {
    const x = F();
    if (!need("tour", "La force brute se pratique à la tour (est de la place).")) return;
    const big = /grande|grand|moyenne|gros/.test(norm(c.rawArg));
    if (!big) {
      if (!x.easyDone) { out("Teste d'abord le sens facile : `multiplier 777777 grande`.", "sys"); return; }
      const L = []; let R = null, found = 0;
      for (let k = 1; k <= N1; k++) {
        R = CA.add(R, G1).R;
        const hit = R && R[0] === QDL[0] && R[1] === QDL[1];
        L.push(`k = ${String(k).padStart(2)} : kG = ${pt(R)}${hit ? "  <- Q !" : ""}`);
        if (hit) { found = k; break; }
      }
      code(L.join("\n"));
      out(`Q = ${pt(QDL)} = **${found}·G**, trouvé en ${found} additions. Avec 19 points, c'est instantané.`, "ok");
      x.dlog1 = true; out("Même chose sur la grande courbe : `chercher grande`.", "sys");
      return;
    }
    if (!x.dlog1) { out("Commence par la courbe jouet : `chercher`.", "sys"); return; }
    const Q = bigQ();
    const t0 = performance.now(); let R = null, k = 0;
    for (k = 1; k <= NB; k++) { R = CB.add(R, GB).R; if (R && R[0] === Q[0] && R[1] === Q[1]) break; }
    const ms = Math.max(1, Math.round(performance.now() - t0));
    out(`Q = ${pt(Q)} = **${k}·G**, trouvé après ${k} additions en ${ms} ms. Sur un million de points, la force brute passe encore.`, "ok");
    x.dlog2 = true;
    const rate = Math.max(1, k * 1000 / ms), lg = Math.log10(rate);
    const yrs = e => Math.round(e * Math.log10(2) - lg - Math.log10(3.156e7));
    out(`À ce rythme (${rate >= 1e6 ? (rate / 1e6).toFixed(1) + " million" : Math.round(rate)} d'additions par seconde), une courbe d'ordre 2^256 demanderait par force brute environ 10^${yrs(256)} années. Avec le meilleur algorithme générique (rho de Pollard, ≈ √n = 2^128 opérations) : environ 10^${yrs(128)} années. L'univers a 1,4 × 10^10 ans. Chaque bit de plus doublerait l'effort de la force brute : c'est la différence entre un million de points et 2^256.`, "sys");
    out("Question : combien de bits d'effort (puissance de 2) représente le meilleur algorithme générique contre une courbe de 256 bits ? `dire ‹nombre›`.", "sys");
  }
  function sayCmd(txt, c) {
    const x = F();
    const arg = (c && c.rawArg) || txt || "";
    const n = nums(arg)[0];
    if (S.room === "atelier" && x.listed && !x.counted) {
      if (n === undefined) { out("Un nombre : `dire 19`.", "err"); return; }
      if (n === POINTS.length + 1) {
        x.counted = true; markPt(G1, "G");
        out(`${POINTS.length} points avec des coordonnées, plus le point à l'infini O : **${n}** éléments. (Le théorème de Hasse prévoyait 17 + 1 ± 2√17, c'est-à-dire entre 10 et 26 : 19 est dans la fourchette.) Et 19 est premier : on verra que cela simplifie tout.`, "ok");
        note("courbe"); fig("courbe");
        out("Prochaine étape : additionner des points. `examiner parchemin`, puis `parler rivest`.", "sys");
      } else if (n === POINTS.length) out(`${n} est le nombre de points affines (avec des coordonnées). Il en manque un, qui n'est dans aucune case : le point à l'infini O.`, "err");
      else out(`Recompte les lignes de la liste : chaque ligne avec deux y vaut deux points, une ligne avec un seul y vaut un point. (${n} n'est pas le bon total.)`, "err");
      return;
    }
    if (S.room === "tour" && x.dlog2 && !x.bitsDone) {
      if (n === undefined) { out("Un nombre de bits : `dire 128`.", "err"); return; }
      if (n === 128) {
        x.bitsDone = true;
        out("128 bits : √(2^256) = 2^128. Voilà pourquoi une courbe de 256 bits est dite « de sécurité 128 bits » : la moitié, à cause de l'attaque générique en racine carrée.", "ok");
        out("Rappel : 2^128 ≈ 3,4 × 10^38 opérations, hors de portée de toutes les machines de la planète.", "sys");
        note("dlog");
        out("Alice et Bob veulent maintenant se mettre d'accord sur un secret commun : `echanger`.", "sys");
      } else if (n === 256) out("256 serait la force brute naïve sur 2^256 points. Mais l'algorithme de Pollard rho fait mieux : il coûte environ la racine carrée de l'ordre. Quelle puissance de 2 est la racine carrée de 2^256 ?", "err");
      else out(`Non : la racine carrée de 2^256 est 2^(256/2). Calcule 256/2 : \`calc 256/2\`.`, "err");
      return;
    }
    if (S.room === "scriptorium" && x.intercepted && !x.kOk) {
      if (n === undefined) { out("Un nombre : `dire ‹k›`.", "err"); return; }
      const a = INT.s1, b = INT.s2, ds = nm(a.s - b.s, N1), dz = nm(a.z - b.z, N1);
      if (nm(n * ds, N1) === dz && n % N1 !== 0) {
        x.kOk = true;
        out(`k = ${n} : ${n} × ${ds} ≡ ${nm(n * ds, N1)} ≡ ${dz} (mod ${N1}). Contrôle : kG = ${pt(CA.mul(n, G1).R)}, dont l'abscisse mod ${N1} vaut ${CA.mul(n, G1).R[0] % N1} = r. C'est bien le nonce.`, "ok");
        out(`Il reste la clé : d = (s1·k − z1)/r mod ${N1}. \`dire ‹d›\`.`, "sys");
      } else out(`Test : ${n} × ${ds} ≡ ${nm(n * ds, N1)} (mod ${N1}), et il faudrait Δz = ${dz}. Ce n'est pas k. (k = Δz / Δs : multiplie Δz par l'inverse de Δs.)`, "err");
      return;
    }
    if (S.room === "scriptorium" && x.kOk && !x.dOk) {
      if (n === undefined) { out("Un nombre : `dire ‹d›`.", "err"); return; }
      const a = INT.s1;
      if (n >= 1 && n < N1 && CA.mul(n, G1).R && pt(CA.mul(n, G1).R) === pt(QPUB)) {
        x.dOk = true;
        out(`d = ${n} : ${n}·G = ${pt(CA.mul(n, G1).R)} = Q, la clé publique d'Alice. **Tu as retrouvé sa clé privée avec deux signatures et un peu d'arithmétique modulaire.** Mallory peut maintenant signer n'importe quel virement à sa place.`, "err");
        say("Mallory", "Un seul nonce réutilisé et la clé tombe. Pas besoin de casser la courbe.");
        note("nonce");
        out("Remèdes : nonce déterministe (RFC 6979, Ed25519), ou excellent générateur aléatoire. Direction la halle des Tailles : retour à la place (`aller est`) puis `aller sud`.", "sys");
      } else out(`Test : ${n}·G = ${pt(CA.mul(n % N1 || N1, G1).R)}, ce n'est pas la clé publique Q = ${pt(QPUB)}. Recalcule : d = (s1·k − z1) / r avec s1 = ${a.s}, k = ${K0}, z1 = ${a.z}, r = ${a.r} (mod ${N1}).`, "err");
      return;
    }
    if (S.room === "halle" && x.lvl128 && !x.sizeOk) {
      if (n === undefined) { out("Un nombre : `dire 12`.", "err"); return; }
      if (n === 12) { x.sizeOk = true; out("3072 / 256 = 12 : à 128 bits de sécurité, la clé RSA est douze fois plus grande que la clé de courbe elliptique.", "ok"); note("tailles"); fig("tailles"); out("Reste à voir les bons et mauvais usages : `examiner etal`.", "sys"); }
      else out(`Non : 3072 / 256 = ${3072 / 256}. Le rapport est entier.`, "err");
      return;
    }
    out(arg ? "Personne ne réagit." : "Dire quoi ?", "sys");
  }
  function echanger() {
    const x = F();
    if (!need("tour", "L'échange de clés se joue à la tour (est de la place).")) return;
    if (!x.bitsDone) { out("Termine d'abord la leçon du logarithme (`indice`).", "sys"); return; }
    if (x.dh) { out(`L'échange est déjà lancé : Bob a publié B = ${pt(DH.B)}. À toi de calculer a·B : \`multiplier ${DH.a} ${DH.B[0]} ${DH.B[1]}\`, puis \`verifier ‹x› ‹y›\`.`, "sys"); return; }
    x.dh = true;
    out("Alice et Bob s'accordent publiquement sur la courbe jouet et sur G = (5, 1). Puis chacun tire un secret :", "sys");
    code(`Alice : secret a = ${DH.a}, publie A = a·G = ${pt(DH.A)}\nBob   : secret b = ${DH.b}, publie B = b·G = ${pt(DH.B)}   (Ève voit A et B)`);
    out(`Tu joues Alice : tu connais a = ${DH.a} et tu as reçu B = ${pt(DH.B)}. Calcule le secret commun S = a·B avec \`multiplier ${DH.a} ${DH.B[0]} ${DH.B[1]}\`, puis \`verifier ‹x› ‹y›\`.`, "ok");
  }
  function checkTour(c) {
    const x = F();
    if (!x.dh) { out("Il n'y a rien à vérifier : `echanger` lance l'échange.", "sys"); return; }
    if (x.dhOk) { out("Le secret commun est déjà établi. `espionner`.", "sys"); return; }
    const nn = nums(c.rawArg);
    if (nn.length < 2) { out("Donne le point : `verifier ‹x› ‹y›`.", "err"); return; }
    const g = [nn[0], nn[1]];
    if (g[0] === DH.S[0] && g[1] === DH.S[1]) {
      x.dhOk = true;
      const bobS = CA.mul(DH.b, DH.A).R;
      out(`Alice : a·B = ${DH.a}·${pt(DH.B)} = **${pt(DH.S)}**.`, "ok");
      out(`Bob, de son côté : b·A = ${DH.b}·${pt(DH.A)} = ${pt(bobS)}. Même point, parce que a(bG) = (ab)G = b(aG).`, "ok");
      const key = sha256(String(DH.S[0])).slice(0, 16);
      out(`Ils dérivent une clé commune en hachant l'abscisse : SHA-256("${DH.S[0]}") → ${key}… (jamais le point brut).`, "sys");
      fig("ecdh");
      out("Ève a tout vu passer, sauf a et b. Peut-elle retrouver S ? `espionner`.", "sys");
    } else if (!CA.on(g)) out(`${pt(g)} n'est pas sur la courbe : tu t'es trompé en calculant.`, "err");
    else {
      x.dhBad = (x.dhBad || 0) + 1;
      out(`Ce n'est pas a·B. Refais \`multiplier ${DH.a} ${DH.B[0]} ${DH.B[1]}\` et recopie le résultat.`, "err");
    }
  }
  function spy() {
    const x = F();
    if (!need("tour", "Ève écoute à la tour (est de la place).")) return;
    if (!x.dhOk) { out("Ève n'a encore rien à voir : termine l'échange.", "sys"); return; }
    out("Ève a G, A et B. Elle essaie de retrouver a en testant 1G, 2G, 3G…", "sys");
    const L = []; let R = null, a = 0;
    for (let k = 1; k <= N1; k++) { R = CA.add(R, G1).R; L.push(`k = ${k} : kG = ${pt(R)}${R && R[0] === DH.A[0] && R[1] === DH.A[1] ? "  <- A !" : ""}`); if (R && R[0] === DH.A[0] && R[1] === DH.A[1]) { a = k; break; } }
    code(L.join("\n"));
    out(`Elle trouve a = ${a}, puis calcule a·B = ${pt(CA.mul(a, DH.B).R)} : **le secret commun**, en ${a} essais. Sur 19 points, l'échange ne protège rien.`, "err");
    out("Avec une courbe de 256 bits (X25519, P-256), retrouver a coûterait ≈ 2^128 opérations : impossible. Aucune méthode connue ne permet de calculer abG à partir de aG et bG sans résoudre (au moins en pratique) un logarithme discret.", "ok");
    out("Il reste un piège : ECDH seul n'authentifie personne. Mallory, placée entre Alice et Bob, ferait deux échanges séparés. C'est pourquoi on signe (ECDSA, Ed25519) : voir le scriptorium.", "sys");
    if (!x.eveDone) { x.eveDone = true; note("ecdh"); out("Direction le scriptorium : retour à la place (`aller ouest`) puis `aller ouest`.", "sys"); }
  }

  /* ---------- scriptorium : ECDSA ---------- */
  function signCmd(c) {
    const x = F();
    if (!need("scriptorium", "On signe au scriptorium (ouest de la place).")) return;
    const m = c.rawArg.match(/^\s*(\d+)\s*(.*)$/);
    if (!m || !m[2].trim()) { out("`signer ‹k› ‹message›` : k est le nonce (1 à 18), par exemple `signer 5 facture 40 pieces`.", "err"); return; }
    const k = parseInt(m[1], 10), msg = m[2].trim();
    if (k < 1 || k >= N1) { out(`Le nonce k doit être entre 1 et ${N1 - 1}.`, "err"); return; }
    const R = CA.mul(k, G1).R, r = R[0] % N1, z = ZH(msg);
    const s = nm(modpow(k, N1 - 2, N1) * (z + r * D1), N1);
    if (r === 0 || s === 0) { out(`Avec k = ${k} : r = ${r}, s = ${s}. Un des deux est nul : la signature est refusée. Recommence avec un autre nonce (c'est un des inconvénients de n = 19).`, "err"); return; }
    x.sig = { k, m: msg, z, r, s };
    out(`Signature de « ${msg} » avec le nonce k = ${k} :`, "ok");
    code(`1. R = k·G = ${k}·${pt(G1)} = ${pt(R)} ; r = x(R) mod ${N1} = ${r}\n2. z = SHA-256(message), 32 premiers bits mod ${N1} = ${z}\n3. s = k⁻¹ · (z + r·d) mod ${N1} = ${s}   (d reste secret dans la machine)`);
    out(`Signature : **(r, s) = (${r}, ${s})**. Le nonce k reste secret et ne doit servir qu'une seule fois. Vérifie : \`verifier ${r} ${s}\`.`, "ok");
    x.sigOk = false;
  }
  function checkScript(c) {
    const x = F();
    const m = c.rawArg.match(/^\s*(\d+)[\s,]+(\d+)\s*(.*)$/);
    if (!m) { out("`verifier ‹r› ‹s›` (ou `verifier ‹r› ‹s› ‹autre message›`).", "err"); return; }
    if (!x.sig) { out("Signe d'abord un message : `signer ‹k› ‹message›`.", "sys"); return; }
    const r = +m[1], s = +m[2], msg = m[3].trim() || x.sig.m;
    if (!(r >= 1 && r < N1 && s >= 1 && s < N1)) { out(`r et s doivent être entre 1 et ${N1 - 1}.`, "err"); return; }
    const z = ZH(msg), w = modpow(s, N1 - 2, N1), u1 = z * w % N1, u2 = r * w % N1;
    const A1 = CA.mul(u1, G1).R, A2 = CA.mul(u2, QPUB).R, X = CA.add(A1, A2).R;
    const v = X ? X[0] % N1 : -1;
    code(`message : « ${msg} » -> z = ${z}\nw = s⁻¹ = ${w} (mod ${N1})\nu1 = z·w = ${u1} ; u2 = r·w = ${u2}\nX = u1·G + u2·Q = ${pt(A1)} + ${pt(A2)} = ${pt(X)}\nv = x(X) mod ${N1} = ${v}`);
    if (v === r) {
      out(`v = r : signature **valide** pour « ${msg} ».`, "ok");
      if (msg === x.sig.m) {
        if (!x.sigOk) { x.sigOk = true; out("Seul le détenteur de d a pu produire ce (r, s). Teste maintenant la sensibilité : change le message (`verifier ‹r› ‹s› facture 140 pieces`).", "sys"); }
      } else out("(Attention : n = 19 est si petit qu'une fausse signature passe 1 fois sur 19 par hasard. Avec n de 256 bits, c'est 2^−256. Essaie un autre texte.)", "sys");
    } else {
      out(`v = ${v} ≠ r = ${r} : signature **rejetée**.`, "err");
      if (msg !== x.sig.m || r !== x.sig.r || s !== x.sig.s) {
        if (msg !== x.sig.m && x.sigOk && r === x.sig.r && s === x.sig.s && !x.tamper) {
          x.tamper = true; note("ecdsa");
          out("Un seul caractère de différence et le hachage change : la signature ne couvre que le message d'origine. C'est l'intégrité.", "ok");
          out("Mais attention à un détail : le nonce k de cette signature était un secret à usage unique. Que se passe-t-il s'il sert deux fois ? Mallory a capté quelque chose : `intercepter`.", "sys");
        }
      }
    }
  }
  function intercept() {
    const x = F();
    if (!need("scriptorium", "Mallory guette au scriptorium (ouest de la place).")) return;
    if (!x.tamper) { say("Mallory", "Pas encore. Signe, vérifie, et teste une modification : après, je te montrerai."); return; }
    const a = INT.s1, b = INT.s2;
    out("Mallory a capté deux signatures du serveur de Bob (même clé que celle d'Alice, Q = " + pt(QPUB) + ") :", "sys");
    code(`signature 1 : « ${a.m} » -> z1 = ${a.z}, r = ${a.r}, s1 = ${a.s}\nsignature 2 : « ${b.m} » -> z2 = ${b.z}, r = ${b.r}, s2 = ${b.s}`);
    const ds = nm(a.s - b.s, N1), dz = nm(a.z - b.z, N1);
    out(`Les deux r sont identiques (${a.r}) : R = kG est le même, donc k aussi. Alors s1 − s2 = k⁻¹(z1 − z2) (mod ${N1}), c'est-à-dire ${ds} ≡ k⁻¹ × ${dz}. Retrouve k = ${dz} / ${ds} (mod ${N1}) : l'inverse de ${ds} est \`calc ${ds}^17 mod 19\`. Puis \`dire ‹k›\`.`, "ok");
    x.intercepted = true;
  }

  /* ---------- halle : tailles, audit ---------- */
  const LEVELS = { 80: [1024, 160], 112: [2048, 224], 128: [3072, 256], 192: [7680, 384], 256: [15360, 512] };
  function levelCmd(c) {
    const x = F();
    if (!need("halle", "La balance est dans la halle des Tailles (sud de la place).")) return;
    const n = nums(c.rawArg)[0];
    if (!LEVELS[n]) { out("Niveaux de sécurité : 80, 112, 128, 192 ou 256 bits. Par exemple `niveau 128`.", "err"); return; }
    const [rsa, ecc] = LEVELS[n];
    x.lvl = n;
    out(`Pour ${n} bits de sécurité (NIST SP 800-57) : RSA ${rsa} bits contre courbe elliptique ${ecc} bits, soit un rapport de ${(rsa / ecc).toFixed(rsa / ecc % 1 ? 1 : 0).replace(".", ",")}.`, "ok");
    if (n === 128) {
      code("                  RSA-3072     ECC (P-256, X25519)\nclé publique      384 octets   32 à 65 octets\nsignature         384 octets   64 octets (ECDSA, Ed25519)\nclé secrète       près de 2 Ko 32 octets");
      out("Vitesse (ordres de grandeur, selon le processeur) : générer une clé et signer sont des dizaines de fois plus rapides en courbe elliptique ; vérifier une signature RSA (e = 65537) est en revanche plus rapide qu'en ECDSA. Pour une poignée de main TLS, c'est surtout la bande passante économisée (certificats, échange de clé) qui pèse.", "sys");
      if (!x.lvl128) { x.lvl128 = true; out("Question : à 128 bits de sécurité, combien de fois la clé RSA est-elle plus grande que la clé de courbe ? `calc 3072/256` puis `dire ‹nombre›`.", "sys"); }
    } else if (n === 256) out("À 256 bits de sécurité, RSA exige 15360 bits : des clés de près de 2 Ko, des calculs très lents. Voilà pourquoi RSA devient impraticable quand la sécurité monte, alors que les courbes suivent presque linéairement.", "sys");
  }
  function isPrimeBig(n) { if (n < 2) return false; for (let i = 2; i * i <= n; i++) if (n % i === 0) return false; return true; }
  function factorize(n) { const f = []; for (let d = 2; d * d <= n; d++) while (n % d === 0) { f.push(d); n /= d; } if (n > 1) f.push(n); return f; }
  function auditCmd(c) {
    const x = F();
    if (!need("halle", "L'étal est dans la halle des Tailles (sud de la place).")) return;
    const nn = nums(c.rawArg);
    if (nn.length < 3) { out("`auditer ‹p› ‹a› ‹b›` : par exemple `auditer 17 14 2` (courbe y² = x³ + ax + b modulo p).", "err"); return; }
    const [p, a0, b0] = nn;
    if (p < 5 || p > 2000000 || !isPrimeBig(p)) { out("p doit être un nombre premier entre 5 et 2000000 (pour que l'audit tienne dans le jeu).", "err"); return; }
    const a = nm(a0, p), b = nm(b0, p);
    const mm = (u, v) => (u * v) % p;
    const disc = nm(4 * mm(mm(a, a), a) + 27 * mm(b, b), p);
    out(`Courbe y² = x³ + ${a}x + ${b} modulo ${p}. Discriminant : 4a³ + 27b² ≡ **${disc}** (mod ${p}).`, "sys");
    if (disc === 0) {
      out("Discriminant nul : la courbe est SINGULIÈRE (elle a un point où elle se recoupe ou une pointe). Les points ne forment plus un groupe de la bonne famille, et le logarithme discret se ramène à quelque chose de très simple (une simple division dans F_p ou F_p²). Une courbe maison singulière ne protège rien.", "err");
      if (!x.auditSing) { x.auditSing = true; say("Mallory", "Ah, tiens… Je l'ai trouvée sur un forum. Personne ne l'avait vérifiée."); out("Audite maintenant une courbe sérieuse : `auditer 17 2 2`.", "sys"); }
      return;
    }
    const sq = new Uint8Array(p);
    for (let y = 0; y < p; y++) sq[mm(y, y)]++;
    let N = 1;
    for (let xx = 0; xx < p; xx++) { const r = nm(mm(mm(xx, xx), xx) + a * xx + b, p); N += sq[r]; }
    const fac = factorize(N), big = fac[fac.length - 1], h = N / big;
    const hasse = Math.floor(2 * Math.sqrt(p));
    out(`Nombre de points (par énumération) : N = **${N}** (Hasse : entre ${p + 1 - hasse} et ${p + 1 + hasse}). Décomposition : ${fac.join(" × ")}. Plus grand facteur premier : ${big}, cofacteur ${h}.`, "sys");
    let verdict = "ok";
    if (N === p) { verdict = "bad"; out("N = p : courbe « anormale » (anomalous) : une attaque, celle de Smart, résout le logarithme discret en temps linéaire. À proscrire.", "err"); }
    else if (h > 8) { verdict = "bad"; out(`Ordre lisse : l'effort du meilleur logarithme générique dépend du plus grand facteur premier (${big}), pas de N. Avec le cofacteur ${h}, la méthode de Pohlig-Hellman cuit chaque petit facteur à part : la courbe est bien plus faible qu'elle n'en a l'air.`, "err"); }
    else if (h === 1) out(`N est premier : le groupe entier est un bon sous-groupe d'ordre ${N}. L'attaque générique coûte environ √${N} ≈ ${Math.round(Math.sqrt(N))} opérations.`, "ok");
    else out(`Cofacteur ${h} (petit, comme les courbes standard Curve25519 de cofacteur 8) : acceptable à condition de travailler dans le sous-groupe d'ordre ${big}.`, "ok");
    if (p < 1e9) out(`Mais p = ${p} reste minuscule : un ordre de ${N} se casse en une fraction de seconde (tu l'as vu à la tour). Une vraie courbe a un p de 256 bits.`, "sys");
    if (verdict === "ok" && !x.auditGood) { x.auditGood = true; out("Retiens les trois contrôles : discriminant ≠ 0, ordre (quasi) premier, et p assez grand. Les courbes standard ont toutes été auditées pour cela, et pour d'autres propriétés (résistance aux attaques par canaux cachés, absence de constantes suspectes). Un bon réflexe : ne jamais fabriquer sa courbe. Dernier point : `valider 3 4`.", "sys"); }
  }
  function validCmd(c) {
    const x = F();
    if (!need("halle", "Le serveur de Bob est à la halle (sud de la place).")) return;
    const nn = nums(c.rawArg);
    if (nn.length < 2) { out("`valider ‹x› ‹y›` : contrôle une clé publique reçue (courbe jouet).", "err"); return; }
    const P = [nn[0], nn[1]];
    if (P[0] < 0 || P[0] > 16 || P[1] < 0 || P[1] > 16) { out("Coordonnées entre 0 et 16 pour la courbe jouet.", "err"); return; }
    if (CA.on(P)) {
      out(`${pt(P)} : y² = ${CA.mm(P[1], P[1])} et x³ + 2x + 2 = ${CA.rhs(P[0])}. Sur la courbe. Contrôle de sous-groupe : ${N1}·P = ${pt(CA.mul(N1, P).R)}. **Point valide.**`, "ok");
      return;
    }
    out(`${pt(P)} : y² = ${CA.mm(P[1], P[1])} mais x³ + 2x + 2 = ${CA.rhs(P[0])}. **Hors de la courbe.**`, "err");
    // le point vit sur y² = x³ + 2x + b' : les formules d'addition n'utilisent pas b
    const bAlt = CA.md(CA.mm(P[1], P[1]) - (CA.rhs(P[0]) - 2));
    const alt = mk(17, 2, bAlt);
    let m = 0, R = P;
    for (let i = 1; i <= 40; i++) { R = i === 1 ? P : alt.add(R, P).R; if (!R) { m = i; break; } }
    const disc = nm(4 * 8 + 27 * bAlt * bAlt, 17);
    out(`Il est sur la courbe voisine y² = x³ + 2x + ${bAlt}${disc === 0 ? " (singulière)" : ""}. Les formules d'addition n'utilisent pas b : un serveur qui multiplie ce point par sa clé privée k sans le contrôler calcule en réalité sur cette autre courbe${m ? `, où P est d'ordre ${m}. La réponse ne dépend alors que de k mod ${m}` : ""}.`, "sys");
    out("En envoyant plusieurs points d'ordres faibles et différents, un attaquant recoupe les restes de k (théorème des restes chinois) et reconstruit la clé privée : c'est l'attaque par courbe invalide. Défense : contrôler chaque point reçu (équation et sous-groupe), ou utiliser X25519, conçue pour que toute entrée de 32 octets soit sûre. (Simulation sur p = 17 : rien d'opérationnel, seulement le mécanisme.)", "ok");
    if (!x.validated) { x.validated = true; note("standard"); out("Tu as vu les deux mauvais usages : courbe maison et point non vérifié. Retourne voir Maître Ada (`aller nord`, `parler ada`).", "sys"); }
  }

  function checkCmd(c) {
    const nn = nums(c.rawArg);
    if (!nn.length) { const id = resolve(c.target); if (id) { if (ents[id].onExamine) ents[id].onExamine(); out(ents[id].desc()); } return; }
    if (S.room === "atelier") return checkAtelier(c);
    if (S.room === "tour") return checkTour(c);
    if (S.room === "scriptorium") return checkScript(c);
    out("Il n'y a rien à vérifier ici : la vérification se fait à l'atelier, à la tour ou au scriptorium.", "sys");
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Tu as construit une courbe, additionné des points, multiplié, échangé des clés, signé et vu comment les attaquer. La Guilde adopte X25519 pour les échanges et Ed25519 pour les signatures. Pas de courbe maison, pas de nonce réutilisé, et tous les points reçus sont contrôlés.");
    say("Dame Rivest", "Mes clés sont douze fois plus petites que celles de la banque pour la même sécurité. Le prochain défi : l'ordinateur quantique, qui casserait aussi celles-ci.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La grille et ses clous = la courbe sur un corps fini.** Les points (x, y) qui vérifient y² = x³ + 2x + 2 modulo 17, plus le point à l'infini. En vrai, la courbe est définie modulo un premier de 256 bits (P-256 : 2^256 − 2^224 + 2^192 + 2^96 − 1) ou 255 bits (Curve25519 : 2^255 − 19).");
    out("**L'additionneur = la loi de groupe.** Sécante et tangente, formules avec inverse modulaire. Le point à l'infini est le zéro, l'opposé de (x, y) est (x, −y).");
    out("**Multiplier par les bits = double-and-add.** kP se calcule avec environ 1,5 × (nombre de bits de k) opérations. Les bibliothèques utilisent en plus des exécutions à temps constant pour ne pas fuiter k par les temps de calcul.");
    out("**La tour du Logarithme.** Retrouver k à partir de G et kG : le logarithme discret elliptique. Pas d'attaque générique meilleure que √n (rho de Pollard), alors que pour RSA ou Diffie-Hellman classique il existe des attaques sous-exponentielles, d'où les clés plus longues.");
    out("**Alice, Bob et Ève = ECDH.** Chacun publie aG et bG, et abG est le secret commun. Il faut en plus authentifier l'échange, sinon Mallory s'interpose.");
    out("**Le scriptorium = ECDSA.** Signature (r, s) avec un nonce k secret et unique. Réutiliser k révèle la clé privée par deux équations linéaires, ce qui est arrivé en vrai (PlayStation 3, portefeuilles Bitcoin Android).");
    out("**La halle = tailles et bons usages.** 256 bits de courbe valent 3072 bits de RSA (128 bits de sécurité). X25519, Ed25519, P-256 plutôt que des courbes maison, et contrôle des points reçus.");
    out("**Les simplifications du jeu.** (1) Des corps de 17 et 1000003 éléments : une vraie courbe a un p de 256 bits et un ordre premier d'environ 2^256. (2) Les calculs sont faits en coordonnées affines avec des inverses ; les bibliothèques utilisent des coordonnées projectives ou de Montgomery pour éviter les inversions. (3) Le hachage de l'ECDSA est réduit modulo 19 : en vrai, on prend les bits de gauche du hachage, et on rejette les nonces qui donnent r ou s nuls. (4) La courbe de X25519 n'est pas sous forme de Weierstrass ; on a présenté le principe avec la forme y² = x³ + ax + b. (5) Les attaques décrites (courbe invalide, nonce réutilisé) sont montrées sur un exemple jouet pour en comprendre le mécanisme. (6) Un ordinateur quantique assez grand casserait aussi la cryptographie sur courbes (algorithme de Shor) : c'est la raison d'être de la cryptographie post-quantique.");
    out("Rappel utile : **utilise des courbes standard et une bibliothèque éprouvée ; ne réutilise jamais un nonce ECDSA, et contrôle chaque point reçu.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    courbe: () => {
      const x = F(), X0 = 38, Y0 = 346, C = 20;
      const px = v => X0 + v * C, py = v => Y0 - v * C;
      let s = "";
      for (let i = 0; i < 17; i++) for (let j = 0; j < 17; j++) s += `<circle cx="${px(i)}" cy="${py(j)}" r="1.3" fill="var(--dim)" opacity=".45"/>`;
      for (const v of [0, 4, 8, 12, 16]) s += T(px(v), Y0 + 18, String(v), "f-s") + T(X0 - 14, py(v) + 4, String(v), "f-s");
      s += LN(X0 - 6, Y0 + 6, X0 + 16 * C + 6, Y0 + 6) + LN(X0 - 6, Y0 + 6, X0 - 6, py(16) - 6);
      POINTS.forEach(P => { s += `<circle cx="${px(P[0])}" cy="${py(P[1])}" r="5" fill="var(--npc)"/>`; });
      (x.marks || []).forEach(m => {
        s += `<circle cx="${px(m.p[0])}" cy="${py(m.p[1])}" r="7.5" fill="none" stroke="${m.l === "G" ? "var(--you)" : "var(--ok)"}" stroke-width="2.2"/>`;
        s += T(px(m.p[0]) + 10, py(m.p[1]) - 8, m.l, (m.l === "G" ? "ft-priv" : "ft-ok") + " f-b f-s", "start");
      });
      s += T(210, 14, "y² = x³ + 2x + 2 (mod 17)", "f-b");
      s += T(210, 392, "bleu : points de la courbe · orange : G · vert : points calculés", "f-s");
      return { cap: `La courbe y² = x³ + 2x + 2 modulo 17 : ${POINTS.length} points, plus le point à l'infini (non dessiné). Ce n'est pas une jolie courbe : un nuage, où l'on retrouve pourtant une symétrie (x, y) et (x, −y).`, svg: SVG(404, "Points de la courbe elliptique modulo 17", s) };
    },
    addition: () => {
      const x = F(), la = x.lastAdd;
      // courbe réelle y² = x³ − x + 1 : illustration continue de la règle de la sécante
      const f3 = u => u * u * u - u + 1, sx = u => 62 + (u + 1.5) * 66, sy = v => 130 - v * 34;
      let up = [], lo = [];
      for (let u = -1.3247; u <= 2.4; u += 0.04) { const v = Math.sqrt(Math.max(0, f3(u))); up.push(`${sx(u).toFixed(1)},${sy(v).toFixed(1)}`); lo.push(`${sx(u).toFixed(1)},${sy(-v).toFixed(1)}`); }
      const P = [-1, 1], Q = [2, -Math.sqrt(7)], lam = (Q[1] - P[1]) / (Q[0] - P[0]);
      const x3 = lam * lam - P[0] - Q[0], yl = u => P[1] + lam * (u - P[0]), T3 = [x3, yl(x3)], Rr = [x3, -T3[1]];
      let s = `<polyline points="${up.concat(lo.reverse()).join(" ")}" class="f-ln" fill="none"/>`;
      s += `<line x1="${sx(-1.35)}" y1="${sy(yl(-1.35))}" x2="${sx(2.2)}" y2="${sy(yl(2.2))}" class="f-ln f-pub"/>`;
      s += `<line x1="${sx(x3)}" y1="${sy(T3[1])}" x2="${sx(x3)}" y2="${sy(Rr[1])}" class="f-ln f-dash"/>`;
      const dot = (p, col, hollow) => `<circle cx="${sx(p[0]).toFixed(1)}" cy="${sy(p[1]).toFixed(1)}" r="5.5" ${hollow ? `fill="var(--bg)" stroke="${col}" stroke-width="2"` : `fill="${col}"`}/>`;
      s += dot(P, "var(--npc)") + dot(Q, "var(--npc)") + dot(T3, "var(--bad)", true) + dot(Rr, "var(--ok)");
      s += T(sx(P[0]) - 8, sy(P[1]) - 9, "P", "ft-pub f-b", "end") + T(sx(Q[0]) + 9, sy(Q[1]) + 16, "Q", "ft-pub f-b", "start") + T(sx(x3) + 9, sy(T3[1]) + 4, "−(P+Q)", "ft-bad f-s", "start") + T(sx(x3) + 9, sy(Rr[1]) + 4, "P+Q", "ft-ok f-b", "start");
      s += T(210, 14, "illustration sur les réels : y² = x³ − x + 1", "f-s");
      s += T(210, 272, "1. la droite par P et Q recoupe la courbe en un 3e point", "f-s");
      s += T(210, 288, "2. P + Q est son symétrique par rapport à l'axe des x", "f-s");
      let l1, l2;
      if (la && la.kind === "inverse") { l1 = `Ton calcul (mod 17) : ${pt(la.P)} + ${pt(la.Q)} = O`; l2 = "droite verticale : le résultat est le point à l'infini"; }
      else if (la) { l1 = `Ton calcul (mod 17) : ${pt(la.P)} + ${pt(la.Q)} = ${pt(la.R)}`; l2 = `λ = ${la.lam} (${la.kind === "double" ? "tangente" : "sécante"}), formules du parchemin`; }
      else { l1 = "Sur le petit corps (mod 17), mêmes formules"; l2 = "avec des restes et des inverses modulaires"; }
      s += R(40, 300, 340, 46, "f-ok") + T(210, 320, l1, "f-b") + T(210, 338, l2, "f-s");
      return { cap: "La règle de la sécante, dessinée sur les réels : la géométrie guide l'intuition. Sur un corps fini il n'y a plus de dessin continu, mais exactement les mêmes formules.", svg: SVG(360, "Addition de deux points d'une courbe elliptique", s) };
    },
    kp: () => {
      const m = F().lastMul;
      if (!m) return { cap: "Aucune multiplication effectuée.", svg: SVG(60, "kP", T(210, 34, "Fais d'abord `multiplier ‹k›`.", "f-s")) };
      const rows = m.steps.slice(0, 11);
      let s = T(210, 18, `k = ${m.k} = ${m.bits}₂`, "f-b") + T(210, 36, `départ : R = P = ${pt(m.P)}`, "f-s");
      rows.forEach((st, i) => {
        const y = 62 + i * 22;
        s += R(8, y - 14, 404, 20, st.a !== undefined ? "f-ok" : "") + T(14, y, `bit ${st.bit}`, "f-b f-s", "start") + T(60, y, `doubler : ${st.dm}P = ${pt(st.d)}`, "f-s", "start") + (st.a !== undefined ? T(244, y, `+P : ${st.am}P = ${pt(st.a)}`, "ft-ok f-s", "start") : "");
      });
      const yb = 62 + rows.length * 22 + 14;
      if (m.steps.length > rows.length) s += T(210, yb - 4, "…", "f-s");
      s += T(210, yb + 16, `résultat : ${m.k}·P = ${pt(m.R)}`, "f-b") + T(210, yb + 36, `${m.D} doublements + ${m.A} additions = ${m.D + m.A} opérations`, "f-s") + T(210, yb + 52, "(256 bits : ≈ 255 + 128 opérations)", "f-s");
      return { cap: "Multiplication scalaire par doubler-ajouter : on lit les bits de k de gauche à droite. À chaque bit on double, et si le bit vaut 1 on ajoute P.", svg: SVG(yb + 64, "Multiplication scalaire", s) };
    },
    ecdh: () => {
      const s = T(68, 22, "Alice", "f-b ft-priv") + T(352, 22, "Bob", "f-b ft-pub") +
        R(8, 30, 130, 78, "f-priv") + T(73, 52, `a = ${DH.a} (secret)`, "ft-priv f-s") + T(73, 72, "A = a·G", "f-s") + T(73, 90, pt(DH.A), "f-b") +
        R(282, 30, 130, 78, "f-pub") + T(347, 52, `b = ${DH.b} (secret)`, "ft-pub f-s") + T(347, 72, "B = b·G", "f-s") + T(347, 90, pt(DH.B), "f-b") +
        AR(138, 58, 282, 58) + T(210, 52, "A", "f-s") + AR(282, 92, 138, 92) + T(210, 86, "B", "f-s") +
        R(30, 130, 360, 62, "f-ok") + T(210, 150, "Secret commun S = a·B = b·A", "f-b") + T(210, 170, `S = ${pt(DH.S)}`, "ft-ok f-b") + T(210, 186, "clé = SHA-256(abscisse de S)", "f-s") +
        R(70, 212, 280, 62, "f-bad") + T(210, 232, "Ève voit G, A et B", "ft-bad f-b") + T(210, 250, "il lui faudrait a ou b :", "f-s") + T(210, 266, "un logarithme discret", "f-s");
      return { cap: "ECDH : chacun combine son secret avec le point public de l'autre, et obtient le même point. Ève, qui ne voit que les points publics, devrait résoudre un logarithme discret.", svg: SVG(288, "Échange de clés ECDH", s) };
    },
    tailles: () => {
      const x = F();
      let s = T(210, 16, "Taille de clé à sécurité équivalente (échelle linéaire)", "f-b f-s");
      Object.keys(LEVELS).forEach((k, i) => {
        const [rsa, ecc] = LEVELS[k], y = 34 + i * 54, sel = +k === x.lvl;
        s += (sel ? R(2, y - 6, 416, 50, "f-priv") : "") + T(10, y + 20, `${k} bits`, "f-b f-s", "start");
        s += `<rect x="70" y="${y}" width="${Math.max(3, rsa / 15360 * 262).toFixed(1)}" height="16" rx="3" fill="var(--bad)"/>` + T(70 + Math.max(3, rsa / 15360 * 262) + 6, y + 12, `RSA ${rsa}`, "f-s", "start");
        s += `<rect x="70" y="${y + 21}" width="${Math.max(3, ecc / 15360 * 262).toFixed(1)}" height="16" rx="3" fill="var(--ok)"/>` + T(70 + Math.max(3, ecc / 15360 * 262) + 6, y + 33, `ECC ${ecc}`, "f-s", "start");
      });
      return { cap: "Pour la même sécurité, une clé de courbe elliptique est bien plus petite qu'une clé RSA, et l'écart se creuse quand la sécurité augmente (128 bits : 256 contre 3072).", svg: SVG(310, "Comparaison des tailles de clé RSA et ECC", s) };
    },
  };

  GAMES.ecc = {
    id: "ecc", order: 43, title: "La Courbe de Port-443", pageTitle: "ECC Quest", subtitle: "aventure textuelle · courbes elliptiques",
    blurb: "Construis une courbe elliptique modulo 17, additionne des points, échange des clés et signe, puis vois pourquoi 256 bits suffisent.",
    concept: "Cryptographie sur courbes elliptiques",
    start: "place", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    gate(dest) {
      const x = F();
      const need = {
        atelier: [x.quest, "Maître Ada t'attend : `parler ada`."],
        tour: [x.orderDone, "La tour n'ouvre qu'après l'atelier : additions, multiples, et l'ordre du point (`indice`)."],
        scriptorium: [x.eveDone, "Le scriptorium ouvre quand la tour est terminée (échange de clés et Ève : `indice`)."],
        halle: [x.dOk, "La halle ouvre quand le scriptorium est terminé (nonce réutilisé : `indice`)."],
      }[dest];
      if (need && !need[0]) { out(need[1], "sys"); return true; }
      return false;
    },
    refig(name) { fig(name); },
    figAlias: { courbe: ["points", "grille", "nuage"], addition: ["somme", "secante", "tangente"], kp: ["multiplication", "scalaire", "double", "multiplier"], ecdh: ["echange", "diffie", "secret"], tailles: ["taille", "cle", "rsa"] },
    help: "Spécifiques : `tester ‹x›` · `lister` · `ajouter ‹x1› ‹y1› ‹x2› ‹y2›` · `multiplier ‹k› [‹x› ‹y›|grande]` · `verifier ‹x› ‹y›` · `chercher [grande]` · `echanger` · `espionner` · `signer ‹k› ‹message›` · `verifier ‹r› ‹s› [message]` · `intercepter` · `niveau ‹bits›` · `auditer ‹p› ‹a› ‹b›` · `valider ‹x› ‹y›` · `dire ‹nombre›`. Boulier : mets des parenthèses, `calc (3*25+2) mod 17`.",
    verbs: {
      testX: { words: ["tester", "evaluer", "essayer"], run: testX },
      listAll: { words: ["lister", "enumerer", "inventorier"], run: listAll },
      addCmd: { words: ["ajouter", "additionner", "sommer"], run: addCmd },
      mulCmd: { words: ["multiplier", "multiplie"], run: mulCmd },
      check: { words: ["verifier", "controler"], run: checkCmd },
      search: { words: ["chercher", "forcer", "bruteforce"], run: searchCmd },
      echanger: { words: ["echanger", "negocier"], run: echanger },
      spy: { words: ["espionner", "ecouter"], run: spy },
      sign: { words: ["signer", "signature"], run: signCmd },
      intercept: { words: ["intercepter", "capter"], run: intercept },
      level: { words: ["niveau", "peser"], run: levelCmd },
      audit: { words: ["auditer", "audit"], run: auditCmd },
      valid: { words: ["valider", "validation"], run: validCmd },
    },
    say: sayCmd,
    intro() {
      out("La Courbe de Port-443", "title");
      out("La Guilde de Port-443 trouve ses clés RSA trop lourdes : des nombres de 600 chiffres, des certificats volumineux, des serveurs essoufflés. Dame Rivest présente une idée plus économe : la courbe elliptique. Mêmes promesses de sécurité, des clés douze fois plus petites. Maître Ada te confie la mission de la fabriquer à la main, sur un tout petit corps, avant de voir comment on s'en sert et comment on la casse (audit autorisé : tout est simulé sur des données fictives).", "");
      out("Tu disposes d'une calculatrice de poche : `calc 4^15 mod 17`, `calc (3*25+2) mod 17`. Mets des parenthèses autour des sommes avant `mod`.", "sys");
    },
  };
})();
