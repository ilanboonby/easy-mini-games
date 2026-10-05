"use strict";
/* Le Grand Livre de Port-443 : blockchain, chaînage, Merkle, preuve de travail, consensus. SHA-256 réel. */
(function () {
  const F = () => f();
  const ZERO = "0".repeat(64);
  const NAMES = ["alice", "bob", "eve", "mallory", "ada"];
  const MTX = ["alice>bob:5", "bob>eve:3", "eve>alice:2", "alice>ada:4", "bob>mallory:1", "ada>bob:6", "mallory>eve:2", "eve>bob:1"];
  const GEN = ["cite>alice:50", "cite>bob:30", "cite>mallory:10", "cite>eve:20"];
  const sh = (h, n) => h.slice(0, n || 8) + "…";
  const clone = o => JSON.parse(JSON.stringify(o));
  const nums = s => (String(s).match(/\d+(?:[.,]\d+)?/g) || []).map(t => parseFloat(t.replace(",", ".")));
  const fN = n => Math.round(n).toLocaleString("fr-FR");
  const pct = p => p >= 0.9999 ? "100 %" : p < 1e-6 ? "moins de 0,0001 %" : (p * 100).toFixed(p < 0.01 ? 4 : 2).replace(".", ",") + " %";
  const room = () => S.room;

  /* ---------- blocs, Merkle, preuve de travail (tout en SHA-256 réel) ---------- */
  function levels(txs) {
    const lv = [txs.map(sha256)];
    while (lv[lv.length - 1].length > 1) {
      const cur = lv[lv.length - 1].slice();
      if (cur.length % 2) cur.push(cur[cur.length - 1]); // nombre impair : on duplique le dernier
      const nx = []; for (let i = 0; i < cur.length; i += 2) nx.push(sha256(cur[i] + cur[i + 1]));
      lv.push(nx);
    }
    return lv;
  }
  const merkle = txs => { const lv = levels(txs); return lv[lv.length - 1][0]; };
  function proofOf(txs, idx) {
    const lv = levels(txs), pr = [];
    for (let l = 0; l < lv.length - 1; l++) {
      const cur = lv[l].slice(); if (cur.length % 2) cur.push(cur[cur.length - 1]);
      pr.push({ h: cur[idx ^ 1], side: idx % 2 === 0 ? "droite" : "gauche" }); idx >>= 1;
    }
    return pr;
  }
  const hdr = b => `${b.i}|${b.prev}|${merkle(b.txs)}|${b.nonce}`;
  const bh = b => sha256(hdr(b));
  function pow(i, prev, txs, d, max) {
    const pre = `${i}|${prev}|${merkle(txs)}|`, z = "0".repeat(d), t0 = performance.now();
    let n = 0, h;
    for (; ; n++) { h = sha256(pre + n); if (h.startsWith(z)) break; if (n >= max) return null; }
    return { nonce: n, hash: h, tries: n + 1, ms: Math.max(1, Math.round(performance.now() - t0)), pre };
  }
  function balances(ch) {
    const b = {};
    ch.forEach(bl => bl.txs.forEach(t => {
      const m = t.match(/^(\w+)>(\w+):(\d+)$/); if (!m) return;
      if (m[1] !== "cite") b[m[1]] = (b[m[1]] || 0) - Number(m[3]);
      b[m[2]] = (b[m[2]] || 0) + Number(m[3]);
    }));
    return b;
  }
  const linkOk = (ch, j) => j === 0 || ch[j].prev === bh(ch[j - 1]);
  const validChain = ch => ch.every((b, j) => linkOk(ch, j));
  const work = br => br.reduce((s, b) => s + Math.pow(16, b.d || 0), 0);

  const memo = {};
  function honest5(d) {
    if (memo[d]) return memo[d];
    const T5 = [GEN, ["alice>bob:5", "bob>eve:3"], ["eve>alice:2", "alice>ada:4"], ["ada>bob:6", "bob>mallory:1"], ["mallory>eve:2", "eve>bob:1"]];
    const ch = []; let prev = ZERO, tr = 0, ms = 0;
    T5.forEach((t, i) => {
      const b = { i, prev, txs: t, nonce: 0, d: i ? d : 0 };
      if (i) { const r = pow(i, prev, t, d, 8e6); b.nonce = r.nonce; tr += r.tries; ms += r.ms; }
      ch.push(b); prev = bh(b);
    });
    return (memo[d] = { ch, tries: tr / 4, ms: ms / 4 });
  }
  function forkBase() {
    if (memo.fork) return clone(memo.fork);
    const mk = (i, prev, txs) => { const r = pow(i, prev, txs, 2, 1e6); return { i, prev, txs, nonce: r.nonce, d: 2 }; };
    const g = { i: 0, prev: ZERO, txs: GEN, nonce: 0, d: 0 };
    const b1 = mk(1, bh(g), ["alice>bob:5"]), b2 = mk(2, bh(b1), ["bob>eve:3"]);
    memo.fork = { trunk: [g, b1, b2], A: [mk(3, bh(b2), ["mallory>eve:10"])], B: [mk(3, bh(b2), ["mallory>bob:10"])], win: null };
    return clone(memo.fork);
  }
  /* probabilité qu'un attaquant (part q de la puissance) rattrape son retard de z blocs */
  function pSuccess(q, z) {
    if (q >= 0.5 || z <= 0) return 1;
    const p = 1 - q; let nb = Math.pow(p, z), s = 0, cum = 0;
    for (let k = 0; k < z; k++) { cum += nb; s += nb * Math.pow(q / p, z - k); nb = nb * q * (k + z) / (k + 1); }
    return s + (1 - cum);
  }
  const POL_Q = 0.3, POL_MAX = 0.01;
  const polMin = () => { let z = 1; while (pSuccess(POL_Q, z) >= POL_MAX) z++; return z; };

  /* ---------- carnet ---------- */
  const notes = {
    double: ["La double dépense", "Une donnée numérique se copie à l'infini : sans arbitre, on peut dépenser deux fois les mêmes pièces auprès de deux commerçants qui ne se parlent pas. Une banque centrale tranche. Sans elle, il faut un grand livre commun à tous, avec un ordre unique des opérations : le second paiement est alors refusé, car le solde est déjà vide."],
    chaine: ["Le chaînage par hachage", "Chaque bloc contient l'empreinte du bloc précédent. Modifier une vieille transaction change l'empreinte de son bloc, ce qui casse le lien du suivant ; le réparer change l'empreinte du suivant, et ainsi de suite jusqu'à la tête de chaîne, que tout le monde connaît. La falsification se voit donc, mais refaire les calculs ne coûte rien : il faut y ajouter un coût."],
    merkle: ["L'arbre de Merkle", "Les transactions d'un bloc sont hachées deux à deux, puis les empreintes de nouveau deux à deux, jusqu'à une seule : la racine, inscrite dans l'en-tête du bloc. Changer une transaction change la racine. Prouver qu'une transaction est dans un bloc ne demande que log2(n) empreintes (3 pour 8 transactions, 20 pour un million), pas le bloc entier."],
    pow: ["La preuve de travail et la difficulté", "Pour proposer un bloc, il faut trouver un nonce tel que l'empreinte de l'en-tête commence par n zéros (simplification : en vrai, l'empreinte doit être inférieure à une cible). Il n'y a pas de raccourci : on essaie. Chaque zéro hexadécimal de plus multiplie le travail moyen par 16. Trouver coûte cher, vérifier coûte une seule empreinte. Le réseau ajuste la difficulté pour garder un rythme de bloc stable."],
    reecriture: ["Le coût de réécriture", "Falsifier le bloc k oblige à re-miner le bloc k et tous les suivants, pendant que le réseau honnête continue d'allonger la chaîne. Plus le bloc est ancien, plus la falsification coûte (nombre de blocs × 16^difficulté essais) et plus l'attaquant est en retard. C'est ce coût, pas un secret, qui rend l'historique pratiquement immuable."],
    consensus: ["Le consensus et les fourches", "Deux blocs valides trouvés en même temps créent une fourche : deux versions provisoires de l'histoire. Chaque nœud retient la chaîne qui représente le plus de travail cumulé (la « plus longue », quand la difficulté est constante), et bascule dès qu'une branche prend l'avantage. Les transactions de la branche perdante redeviennent en attente, voire invalides : on attend donc plusieurs confirmations."],
    cinquante: ["L'attaque des 51 % et les confirmations", "Un attaquant avec une part q < 50 % de la puissance a une probabilité de rattraper z blocs de retard qui chute vite avec z (environ (q/(1-q))^z). Avec plus de 50 %, il finit toujours par y arriver. Il peut alors réécrire ses propres paiements récents et censurer, mais pas voler les coins des autres (il lui manque leurs clés) ni faire accepter des blocs invalides. D'où les confirmations : plus l'attaquant est puissant, plus il en faut."],
    energie: ["Énergie et preuve d'enjeu", "La preuve de travail transforme de l'électricité en sécurité : le réseau Bitcoin consomme de l'ordre de la centaine de TWh par an. La preuve d'enjeu remplace le travail par un capital bloqué : des validateurs mettent des fonds en gage, sont tirés au sort proportionnellement à leur mise et perdent une partie du gage s'ils trichent (« slashing »). Elle consomme environ 99 % d'énergie en moins, avec d'autres compromis (concentration du capital, règles plus complexes)."],
    limites: ["Ce que la blockchain ne garantit pas", "Elle garantit l'ordre et l'intégrité de ce qui a été inscrit, pas sa vérité : une donnée fausse saisie reste fausse à jamais (« garbage in, garbage out »). Une clé privée volée permet des transactions parfaitement valides. Un contrat mal écrit s'exécute fidèlement, bug compris, et ne se corrige pas. Et si une partie de confiance existe déjà, une base de données ordinaire est souvent plus simple, moins chère et plus rapide."],
  };

  /* ---------- entités et lieux ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle t'a confié l'audit du projet de grand livre commun de la cité." },
    bob: { npc: true, names: ["bob", "marchand", "tomates"], label: "Bob, marchand de tomates", desc: () => "Bob, marchand de tomates, qui tient un petit carnet de comptes à lui, sur son étal." },
    boulangere: { npc: true, names: ["boulangere", "dame farine", "pain", "farine"], label: "Dame Farine, la boulangère", desc: () => "Dame Farine, la boulangère, qui tient elle aussi son propre carnet de comptes, sans rien savoir de celui de Bob." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, 10 écus numériques en poche, dans le rôle de la mauvaise cliente que l'audit autorisé lui a confié." },
    eve: { npc: true, names: ["eve"], label: "Ève, la greffière", desc: () => "Ève, la greffière. Elle écoute tout, et surtout elle garde chez elle une copie du grand livre." },
    livre: { names: ["livre", "grand livre", "registre", "chaine"], label: "le Grand Livre", onExamine() { const x = F(); code(chainText(x.chain)); },
      desc: () => `Le Grand Livre : ${F().chain.length} bloc(s). Chaque bloc porte l'empreinte du précédent. Commandes : \`ajouter ‹de› ‹vers› ‹montant›\`, \`modifier ‹n° de bloc› ‹nouveau montant›\`, \`auditer\`, \`recalculer\`.` },
    mur: { names: ["mur", "transactions", "tableau", "liste"], label: "le mur des 8 transactions", onExamine() { code(F().mtx.map((t, i) => `t${i + 1}  ${t}`).join("\n")); },
      desc: () => "Les 8 transactions d'un bloc, affichées sur le mur. `batir` calcule l'arbre, `modifier ‹n°› ‹montant›` falsifie l'une d'elles, `prouver ‹n°›` et `controler` vérifient une inclusion." },
    arbre: { names: ["arbre", "arbre de merkle", "merkle", "racine"], label: "l'arbre de Merkle", desc: () => "Un arbre dessiné à la craie : en bas les empreintes des transactions, en haut une seule, la racine. `batir` pour le construire." },
    enclume: { names: ["enclume", "forge", "marteau"], label: "l'enclume du mineur", desc: () => "Une enclume où l'on frappe, nonce après nonce, un en-tête de bloc jusqu'à ce que son empreinte commence par assez de zéros. `miner ‹1 à 4›` choisit la difficulté ; `reecrire ‹bloc› [difficulté]` tente de falsifier un vieux bloc." },
    carte: { names: ["carte", "balise", "tableau de fourche"], label: "la carte des nœuds", desc: () => "Une carte des tours de la cité : chaque tour garde sa copie du livre et suit la chaîne la plus lourde qu'elle connaît. `fourche`, `etendre ‹a|b›`, `comparer`, `estimer ‹part %› ‹confirmations›`, `simuler`, `exiger ‹n›`." },
    validateur: { npc: true, names: ["validateur", "veilleur", "gardien"], label: "le Validateur", desc: () => "Le Validateur, qui garde un coffre-fort de mise en gage et n'a pas l'air de transpirer." },
    dossiers: { names: ["dossiers", "dossier", "cas", "pupitre"], label: "les trois dossiers du Conseil", desc: () => "Trois dossiers : `tester saisie`, `tester cle`, `tester contrat`. Plus `energie` pour la facture d'électricité." },
  };

  const rooms = {
    place: { name: "La place du marché", short: "Place", alias: ["place", "marche"], ents: ["ada", "bob", "boulangere", "mallory"], exits: { nord: "greffe", est: "halle", ouest: "forge", sud: "tour" },
      desc: () => "Plus de banque centrale à Port-443 : les étals tiennent chacun leur carnet. Au nord, le greffe du Grand Livre. À l'est, la halle des Empreintes. À l'ouest, la forge des mineurs. Au sud, la tour de guet." },
    greffe: { name: "Le greffe du Grand Livre", short: "Greffe", alias: ["greffe", "livre"], ents: ["eve", "livre"], exits: { sud: "place" },
      desc: () => "Un pupitre massif porte le Grand Livre, relié à la chaîne. Ève en garde une copie dans la pièce voisine et vérifie tout ce qui arrive." },
    halle: { name: "La halle des Empreintes", short: "Halle", alias: ["halle", "empreintes"], ents: ["mur", "arbre"], exits: { ouest: "place" },
      desc: () => "Une halle où l'on résume des piles de transactions en une seule empreinte. Huit transactions sont affichées sur le mur, un arbre à la craie couvre la cloison." },
    forge: { name: "La forge des mineurs", short: "Forge", alias: ["forge", "mineurs"], ents: ["enclume"], exits: { est: "place" },
      desc: () => "Une forge où l'on ne bat pas le fer : on cherche. Les mineurs frappent des en-têtes de blocs à la chaîne, nonce après nonce, et leurs ardoises sont couvertes d'essais ratés." },
    tour: { name: "La tour de guet", short: "Tour", alias: ["tour", "guet"], ents: ["carte"], exits: { nord: "place", est: "conseil" },
      desc: () => "Du haut de la tour, on voit toutes les autres tours de la cité qui se font des signaux. Au pied de l'escalier, une carte des nœuds. À l'est, la salle du Conseil." },
    conseil: { name: "La salle du Conseil", short: "Conseil", alias: ["conseil"], ents: ["validateur", "dossiers"], exits: { ouest: "tour" },
      desc: () => "La salle où le Conseil décide si le Grand Livre mérite sa place. Un Validateur y garde une mise en gage ; trois dossiers sont posés sur le pupitre." },
  };

  /* ---------- aides d'affichage ---------- */
  function chainText(ch) {
    return ch.map((b, j) => `bloc ${b.i} │ hash ${sh(bh(b), 12)}\n       │ prev ${j ? sh(b.prev, 12) : "(genèse)"}  racine ${sh(merkle(b.txs), 6)}\n       │ ${b.txs.join("  ")}`).join("\n");
  }
  function check6() {
    const x = F();
    if (x.s6 || !(x.fk && x.fk.win && x.cmpw && x.estN && x.pol && x.est51)) return;
    x.s6 = true; note("cinquante");
    say("Maître Ada", "Le consensus tient tant que personne ne contrôle plus de la moitié de la puissance. Il reste à voir ce que la blockchain NE garantit PAS : la salle du Conseil, à l'est de la tour.");
  }
  function check7() {
    const x = F();
    if (x.s7 || !(x.energy && x.pos && x.tests.saisie && x.tests.cle && x.tests.contrat)) return;
    x.s7 = true;
    say("Maître Ada", "Tu as tout ce qu'il te faut. Viens me faire ton rapport sur la place.");
  }

  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.s1) { if (!(x.pay1.bob && x.pay1.boul)) return "pay1"; if (!x.shared) return "share"; return "pay2"; }
    if (!x.s2) { if (x.chain.length < 4) return "add"; if (!x.mod) return "mod"; if (!x.aud) return "aud"; return "recalc"; }
    if (!x.s3) { if (!x.built) return "build"; if (!x.tam) return "tam"; if (!x.pf) return "prove"; return "ctrl"; }
    if (!x.s4) return "mine";
    if (!x.s5) return "rew";
    if (!x.s6) { if (!x.fk) return "fork"; if (!x.fk.win) return "ext"; if (!x.cmpw) return "cmp"; if (!x.estN) return "est"; if (!x.pol) return "pol"; return "est51"; }
    if (!x.s7) { if (!x.energy) return "energy"; if (!(x.tests.saisie && x.tests.cle && x.tests.contrat)) return "tests"; return "pos"; }
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend sur la place du marché.", "`parler ada`"],
    pay1: () => ["Sur la place, fais payer Mallory auprès des deux commerçants, avec les mêmes 10 écus.", "`payer bob` puis `payer boulangere`."],
    share: () => ["Chacun a vérifié dans son carnet privé. Il faut un registre unique, partagé par tous.", "`ouvrir livre`"],
    pay2: () => ["Rejoue les deux paiements, maintenant que tout le monde consulte le même livre.", "`payer bob` puis `payer boulangere`."],
    add: () => ["Au greffe (nord de la place), construis la chaîne : il faut au moins 3 blocs en plus de la genèse. Les soldes de départ : alice 50, bob 30, mallory 10, eve 20.", "`aller nord`, puis `ajouter alice bob 5`, `ajouter bob eve 3`, `ajouter eve alice 2`."],
    mod: () => ["Falsifie le montant d'une ancienne transaction (pas du dernier bloc).", "`modifier 1 500`"],
    aud: () => ["Fais contrôler la chaîne : les empreintes sont recalculées une à une.", "`auditer`"],
    recalc: () => ["Mallory peut-elle cacher sa falsification ? Répare les liens en cascade.", "`recalculer`"],
    build: () => ["À la halle (est de la place), construis l'arbre de Merkle des 8 transactions.", "`aller sud`, `aller est`, `batir`."],
    tam: () => ["Falsifie une transaction du mur et regarde la racine.", "`modifier 3 99`"],
    prove: () => ["Bob ne connaît que la racine. Produis la preuve d'inclusion de la transaction n° 6.", "`prouver 6`"],
    ctrl: () => ["Bob recalcule la racine à partir de la transaction et de la preuve. (Si le mur a été falsifié, un premier contrôle échoue : refais alors `prouver 6`.)", "`controler 6`"],
    mine: () => ["À la forge (ouest de la place), mine des blocs à au moins 3 difficultés différentes et compare les essais et le temps.", "`aller sud`, `aller ouest`, puis `miner 1`, `miner 2`, `miner 3` (et `miner 4`, plus long)."],
    rew: () => ["Falsifie un vieux bloc d'une chaîne minée de 5 blocs : essaie le bloc 4, puis le bloc 1, et compare le coût.", "`reecrire 4`, puis `reecrire 1` (option : `reecrire 1 2` pour choisir la difficulté)."],
    fork: () => ["À la tour de guet (sud de la place), provoque une fourche.", "`aller est`, `aller sud`, puis `fourche`."],
    ext: () => ["Deux blocs valides existent. Fais miner la suite d'une des deux branches.", "`etendre a` (ou `etendre b`)"],
    cmp: () => ["Sur quoi les nœuds comparent-ils vraiment deux chaînes ?", "`comparer`"],
    est: () => ["Estime la probabilité de réussite d'un attaquant : part de puissance en % puis nombre de confirmations.", "`estimer 10 6` puis `estimer 30 6`."],
    pol: () => ["Le marchand d'immobilier craint un attaquant à 30 %. Cherche avec `estimer 30 ‹n›` le nombre de confirmations pour passer sous 1 % de risque, puis impose-le.", "`estimer 30 10`, `estimer 30 20`… puis `exiger ‹n›`."],
    est51: () => ["Et si l'attaquant dépasse la moitié de la puissance ?", "`estimer 51 6`"],
    energy: () => ["Au Conseil (est de la tour), mesure la facture d'électricité du réseau à partir de la vitesse de ton navigateur.", "`aller est`, puis `energie`."],
    tests: () => ["Instruis les trois dossiers : ce que la chaîne ne garantit pas.", "`tester saisie`, `tester cle`, `tester contrat`."],
    pos: () => ["Interroge le Validateur sur l'alternative à la preuve de travail.", "`parler validateur`"],
    end: () => ["Fais ton rapport à Maître Ada, sur la place.", "`aller ouest`, `aller nord`, puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "La banque centrale de Port-443 a fermé. Il reste des commerçants, des carnets de comptes… et Mallory. La cité veut un grand livre que tous tiennent ensemble et que personne ne puisse falsifier sans que tout le monde le voie. Mon rôle : t'en faire comprendre le fonctionnement en le reconstruisant. Audit autorisé, données fictives : tout se passe sur nos tables.");
          say("Maître Ada", "Commence par le problème de départ : Mallory dispose de 10 écus numériques. Sur la place, fais-la payer chez Bob et chez Dame Farine, et regarde ce que valent leurs carnets privés.");
          out("`payer bob` puis `payer boulangere`.", "sys");
        } else if (x.end) say("Maître Ada", "Le Grand Livre est en service. Merci pour l'audit !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "Ce n'est pas fini. " + hints[objective()]()[0] + " (`indice` pour la commande exacte.)");
        break;
      case "bob":
        if (!x.s1) say("Bob", "Mes tomates, mon carnet. Quand quelqu'un me paie, je regarde si je lui ai déjà vu de l'argent dans MON carnet. Je ne sais rien de ce que Dame Farine a écrit dans le sien.");
        else say("Bob", "Je ne livre plus rien sans avoir lu le Grand Livre, et j'attends quelques confirmations pour les grosses commandes.");
        break;
      case "boulangere":
        if (!x.s1) say("Dame Farine", "Mon pain, mon carnet. Je fais confiance à ce qui est écrit dedans, point.");
        else say("Dame Farine", "Un seul livre pour tout le monde : mon carnet privé a pris sa retraite.");
        break;
      case "mallory":
        if (!x.s1) say("Mallory", "Dix écus, c'est dix écus. Si personne ne compare les carnets, ils valent le double.");
        else if (!x.s5) say("Mallory", "Je réécrirai l'histoire, tu verras. Il suffit de recalculer des empreintes, non ?");
        else say("Mallory", "Pour réécrire le passé, il me faudrait plus de puissance de calcul que tout le reste de la cité réuni. Tant pis. Je me rabats sur les clés.");
        break;
      case "eve":
        if (!x.s2) say("Ève", "Je garde une copie de la chaîne. Ce que je regarde en premier : la tête, l'empreinte du dernier bloc. Si elle diffère de la mienne, je sais que quelqu'un a touché au passé.");
        else say("Ève", "Quand la copie de chacun contredit la tienne, ta version est rejetée. C'est la force du nombre.");
        break;
      case "validateur":
        if (!x.energy) { say("Validateur", "Reviens après avoir mesuré la facture d'électricité de la forge : tu comprendras pourquoi on m'a installé."); break; }
        say("Validateur", "Je suis l'alternative à la forge. Au lieu de brûler de l'électricité, je mets une somme en gage dans ce coffre. Le protocole tire au sort le validateur du prochain bloc, avec une probabilité proportionnelle à ma mise. Si je signe deux blocs contradictoires ou un bloc invalide, on détruit une partie de mon gage (le « slashing »).");
        say("Validateur", "Résultat : une sécurité économique plutôt que thermique, environ 99 % d'énergie en moins (l'Ethereum l'a fait en 2022). En contrepartie : le pouvoir suit le capital (les plus gros gages pèsent plus), et les règles sont plus complexes que « la chaîne la plus lourde gagne ».");
        if (!x.pos) { x.pos = true; check7(); }
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- étape 1 : double dépense ---------- */
  function payCmd(c) {
    const x = F();
    if (room() !== "place") { out("Les paiements se font sur la place du marché.", "sys"); return; }
    if (!x.quest) { say("Maître Ada", "Viens d'abord me parler."); return; }
    const t = norm(c.rawArg), who = /bob|tomate|march/.test(t) ? "bob" : /boulang|pain|farine|dame/.test(t) ? "boul" : null;
    if (!who) { out("Payer qui ? `payer bob` ou `payer boulangere`.", "err"); return; }
    const nom = who === "bob" ? "Bob" : "Dame Farine";
    if (x.s1) { out("Les commerçants ne se fient plus qu'au Grand Livre : cette étape est terminée.", "sys"); return; }
    if (!x.shared) {
      if (x.pay1[who]) { out(`Mallory a déjà payé ${nom}.`, "sys"); return; }
      x.pay1[who] = true;
      say(nom, "Je regarde mon carnet… Mallory a 10 écus ? Rien ne contredit ça chez moi. Marché conclu, voici ma marchandise.");
      out(`Mallory remet ses 10 écus à ${nom}. Les écus numériques se copient : elle les a encore tous.`, "sys");
      if (x.pay1.bob && x.pay1.boul) {
        out("Mallory a acheté pour 20 écus de marchandise avec 10 écus. Chaque commerçant a pourtant vérifié correctement SON carnet : aucun n'a pu voir l'autre paiement.", "err");
        note("double");
        say("Maître Ada", "Voilà la double dépense. Dans le monde du papier, la monnaie ne se copie pas ; dans le monde numérique, tout se copie, et une banque centrale arbitre. Nous n'en avons plus : il faut un registre commun que tout le monde consulte avant d'accepter, et dont l'ordre des opérations est unique. Ouvre-le : `ouvrir livre`.");
      }
    } else {
      x.pay2 = x.pay2 || {};
      if (x.pay2[who]) { out(`Mallory a déjà payé ${nom} (via le livre).`, "sys"); return; }
      const first = !x.pay2.bob && !x.pay2.boul;
      x.pay2[who] = true;
      if (first) {
        say(nom, "Je consulte le Grand Livre commun : Mallory, 10 écus. Je note « mallory>" + (who === "bob" ? "bob" : "boulangere") + ":10 » et j'attends qu'il soit confirmé.");
        out("Le paiement est inscrit dans le Grand Livre : le solde de Mallory passe à 0 pour TOUT LE MONDE.", "ok");
      } else {
        say(nom, "Je consulte le Grand Livre : Mallory a 0 écu depuis son premier paiement. Refusé !");
        out("La double dépense échoue : il n'existe qu'une seule version du solde, et les opérations sont ordonnées.", "ok");
        x.s1 = true;
        say("Maître Ada", "Parfait. Mais qui garantit que ce livre n'est pas retouché après coup ? Va au greffe (nord) : construis une chaîne de blocs et tente de la falsifier.");
      }
    }
  }
  function openBook(c) {
    const x = F();
    if (!/livre|registre/.test(norm(c.rawArg))) { out("Ouvrir quoi ? `ouvrir livre`", "err"); return; }
    if (x.shared) { out("Le Grand Livre est déjà ouvert à tous.", "sys"); return; }
    if (!(x.pay1.bob && x.pay1.boul)) { say("Maître Ada", "Constate d'abord le problème : fais payer Mallory auprès de Bob et de Dame Farine."); return; }
    x.shared = true; x.pay2 = {};
    out("Un grand livre unique est ouvert sur la place : tous les commerçants y lisent les soldes et y inscrivent les paiements. Mallory retrouve ses 10 écus pour un nouvel essai.", "ok");
    out("Rejoue : `payer bob` puis `payer boulangere`.", "sys");
  }

  /* ---------- étape 2 : chaînage ---------- */
  function addCmd(c) {
    const x = F();
    if (room() !== "greffe") { out("Le Grand Livre est au greffe (nord de la place).", "sys"); return; }
    if (!x.s1) { say("Maître Ada", "Montre-moi d'abord pourquoi un livre partagé est nécessaire (sur la place)."); return; }
    const toks = norm(c.rawArg).split(" ").filter(t => NAMES.includes(t) || /^\d+$/.test(t));
    if (toks.length !== 3 || !/^\d+$/.test(toks[2]) || NAMES.indexOf(toks[0]) < 0 || NAMES.indexOf(toks[1]) < 0) { out("Format : `ajouter ‹de› ‹vers› ‹montant›`, par exemple `ajouter alice bob 5`. Noms : alice, bob, eve, mallory, ada.", "err"); return; }
    const [a, b] = toks, n = parseInt(toks[2], 10);
    if (a === b || n < 1 || n > 999) { out("Il faut deux personnes différentes et un montant entre 1 et 999.", "err"); return; }
    const bal = balances(x.chain)[a] || 0;
    if (bal < n) { out(`Refusé : ${a} n'a que ${bal} écu(s) dans le livre. La double dépense est impossible puisque chacun voit le même solde.`, "err"); return; }
    const last = x.chain[x.chain.length - 1];
    const blk = { i: x.chain.length, prev: bh(last), txs: [`${a}>${b}:${n}`], nonce: 0 };
    x.chain.push(blk); x.pub = clone(x.chain); x.mod = null;
    out(`Nouveau bloc n° ${blk.i} : « ${blk.txs[0]} ». Il contient l'empreinte du bloc précédent :`, "ok");
    code(`prev = ${bh(last)}\nhash = ${bh(blk)}`);
    if (x.chain.length === 4) out("Trois blocs : tu peux maintenant tenter de falsifier le passé. `modifier ‹n° de bloc› ‹nouveau montant›`", "sys");
  }
  function modifyCmd(c) {
    const x = F(), v = nums(c.rawArg);
    if (room() === "halle") { modifyWall(v); return; }
    if (room() !== "greffe") { out("On modifie le Grand Livre au greffe, ou le mur à la halle.", "sys"); return; }
    if (!x.s1) { say("Maître Ada", "Pas encore : l'étape précédente d'abord."); return; }
    if (x.chain.length < 4) { out("Ajoute d'abord au moins 3 blocs : `ajouter alice bob 5`…", "sys"); return; }
    if (v.length < 2 || !Number.isInteger(v[0]) || !Number.isInteger(v[1])) { out("`modifier ‹n° de bloc› ‹nouveau montant›` (ex. `modifier 1 500`).", "err"); return; }
    const n = v[0];
    if (n < 1 || n > x.chain.length - 2) { out(`Choisis un bloc entre 1 et ${x.chain.length - 2} : un bloc ancien, qui a des suivants (la tête de chaîne est surveillée par tout le monde).`, "err"); return; }
    if (x.mod) { out("Un bloc est déjà falsifié : `auditer` ou `recalculer`.", "sys"); return; }
    const b = x.chain[n], old = b.txs[0];
    b.txs[0] = old.replace(/:\d+$/, ":" + v[1]);
    x.mod = n;
    out(`Dans le bloc ${n}, « ${old} » devient « ${b.txs[0]} ». Rien ne l'a empêché : c'est de l'encre. Mais l'empreinte du bloc a changé… \`auditer\` pour voir qui s'en aperçoit.`, "ok");
  }
  function auditCmd() {
    const x = F();
    if (room() !== "greffe") { out("L'audit se fait au greffe, devant le Grand Livre.", "sys"); return; }
    const ch = x.chain, lines = [];
    let bad = 0, first = -1;
    ch.forEach((b, j) => {
      const ok = linkOk(ch, j);
      if (!ok) { bad++; if (first < 0) first = j; }
      lines.push(`bloc ${b.i}  hash ${sh(bh(b))}  prev ${j ? sh(b.prev) : "—"}  ${j === 0 ? "genèse" : ok ? "lien ✓" : "lien ✗ : prev ≠ hash du bloc " + (j - 1) + " recalculé"}`);
    });
    const tip = bh(ch[ch.length - 1]), pt = bh(x.pub[x.pub.length - 1]), same = tip === pt;
    lines.push(`tête recalculée ${sh(tip)}  copie publique d'Ève ${sh(pt)}  ${same ? "✓" : "✗ DIFFÉRENTE"}`);
    out("L'audit recalcule chaque empreinte et vérifie chaque lien :", "sys");
    code(lines.join("\n"));
    if (!bad && same) { out(x.mod ? "Tout est cohérent (rien de falsifié)." : "Tout est cohérent. Falsifie un ancien bloc (`modifier 1 500`) pour voir la différence.", "ok"); return; }
    if (bad) out(`Fraude détectée : le lien casse au bloc ${first}. Le bloc ${first - 1} a changé, donc son empreinte aussi, mais le bloc ${first} contient toujours l'ancienne : un seul octet modifié dans le passé se voit tout de suite.`, "err");
    if (x.mod && !x.aud) { x.aud = true; x.snap = clone(ch); note("chaine"); fig("chaine", x.snap); out("Mallory peut-elle cacher sa falsification en corrigeant les liens ? Essaie : `recalculer`.", "sys"); }
  }
  function relink() {
    const x = F(), ch = x.chain;
    if (room() !== "greffe") { out("Cela se fait au greffe.", "sys"); return; }
    if (!x.mod) { out("Il n'y a rien à raccorder : aucun bloc n'a été falsifié.", "sys"); return; }
    if (!x.aud) { out("Fais d'abord `auditer` pour constater ce que ta falsification casse.", "sys"); return; }
    const t0 = performance.now(), lines = [];
    for (let j = x.mod + 1; j < ch.length; j++) {
      const old = ch[j].prev; ch[j].prev = bh(ch[j - 1]);
      lines.push(`bloc ${j} : prev ${sh(old)} → ${sh(ch[j].prev)}   donc son hash devient ${sh(bh(ch[j]))}`);
    }
    const ms = Math.max(1, Math.round(performance.now() - t0));
    out("Mallory corrige les liens en cascade : chaque réparation change l'empreinte du bloc suivant, qu'il faut donc réparer à son tour :", "sys");
    code(lines.join("\n"));
    out(`En ${ms} ms, la chaîne est de nouveau cohérente de bout en bout. Mais la tête a changé : ${sh(bh(ch[ch.length - 1]))} au lieu de ${sh(bh(x.pub[x.pub.length - 1]))}.`, "err");
    say("Ève", "Ma copie dit autre chose, et celle de tous les voisins aussi. Ta chaîne est rejetée, je restaure la vraie.");
    x.chain = clone(x.pub); x.mod = null; x.s2 = true; x.recalc = true;
    out("Le livre honnête est restauré. Mais le problème est réel : refaire ces calculs ne coûte RIEN, quelques millisecondes. Si falsifier coûtait très cher, la vigilance d'Ève ne serait plus le dernier rempart.", "sys");
    say("Maître Ada", "Il faut rendre l'écriture d'un bloc coûteuse. Mais avant, une question d'efficacité : comment résumer des centaines de transactions et en prouver une seule ? Halle des Empreintes, à l'est de la place.");
  }

  /* ---------- étape 3 : Merkle ---------- */
  function buildCmd() {
    const x = F();
    if (room() !== "halle") { out("L'arbre se construit à la halle (est de la place).", "sys"); return; }
    if (!x.s2) { say("Maître Ada", "Finis d'abord l'étape du chaînage, au greffe."); return; }
    const lv = levels(x.mtx), L = [];
    L.push("feuilles : empreinte de chaque transaction");
    x.mtx.forEach((t, i) => L.push(`  t${i + 1} ${t.padEnd(14)} ${sh(lv[0][i])}`));
    for (let l = 1; l < lv.length; l++) L.push(`niveau ${l} : ${lv[l].length} empreinte(s) = sha256(gauche + droite)\n  ` + lv[l].map(h => sh(h, 6)).join("  "));
    const root = lv[lv.length - 1][0];
    L.push("racine : " + root);
    out("Tu construis l'arbre de Merkle des 8 transactions (SHA-256 réel) :", "sys");
    code(L.join("\n"));
    if (!x.mroot) x.mroot = root;
    out(root === x.mroot ? "Cette racine unique, 64 caractères, est inscrite dans l'en-tête du bloc : elle « contient » toutes les transactions." : "Attention : cette racine diffère de celle publiée dans l'en-tête du bloc, car le mur a été falsifié.", root === x.mroot ? "ok" : "err");
    x.built = true; fig("merkle", null);
    if (!x.tam) out("Que se passe-t-il si Mallory change une transaction ? `modifier 3 99`", "sys");
  }
  function modifyWall(v) {
    const x = F();
    if (!x.built) { out("Construis d'abord l'arbre : `batir`.", "sys"); return; }
    if (v.length < 2 || !Number.isInteger(v[0]) || !Number.isInteger(v[1]) || v[0] < 1 || v[0] > 8) { out("`modifier ‹n° de 1 à 8› ‹montant›` (ex. `modifier 3 99`).", "err"); return; }
    const before = levels(x.mtx), n = v[0] - 1;
    x.mtx[n] = x.mtx[n].replace(/:\d+$/, ":" + v[1]);
    const after = levels(x.mtx);
    let diff = 0, tot = 0; after.forEach((lvl, l) => lvl.forEach((h, i) => { tot++; if (h !== before[l][i]) diff++; }));
    x.tam = true; x.pf = null;
    out(`Mallory change t${v[0]} en « ${x.mtx[n]} ».`, "sys");
    code(`racine publiée   ${sh(x.mroot, 16)}\nracine recalculée ${sh(after[after.length - 1][0], 16)}   ✗`);
    out(`${diff} empreintes sur ${tot} ont changé : la feuille et ses ancêtres, jusqu'à la racine. Un seul octet modifié, une racine entièrement différente : comparer la racine suffit à détecter n'importe quelle altération.`, "err");
  }
  function proveCmd(c) {
    const x = F(), v = nums(c.rawArg);
    if (room() !== "halle") { out("La preuve se prépare à la halle.", "sys"); return; }
    if (!x.built) { out("Construis d'abord l'arbre : `batir`.", "sys"); return; }
    if (!(v.length && Number.isInteger(v[0]) && v[0] >= 1 && v[0] <= 8)) { out("`prouver ‹n° de 1 à 8›` (ex. `prouver 6`).", "err"); return; }
    const n = v[0], pr = proofOf(x.mtx, n - 1);
    x.pf = { n, tx: x.mtx[n - 1], proof: pr };
    out(`Preuve que t${n} (« ${x.mtx[n - 1]} ») est dans le bloc : ${pr.length} empreintes seulement, au lieu des 8 transactions.`, "sys");
    code(pr.map((p, i) => `${i + 1}. voisin à ${p.side} : ${sh(p.h, 16)}`).join("\n"));
    out("Bob, client léger, ne connaît que la racine de l'en-tête. Il peut recalculer le chemin : `controler " + n + "`. (Tu peux aussi tester une fausse affirmation : `controler " + n + " 90`.)", "sys");
    fig("merkle", n - 1);
  }
  function controlCmd(c) {
    const x = F(), v = nums(c.rawArg);
    if (room() !== "halle") { out("Le contrôle se fait à la halle.", "sys"); return; }
    if (!x.pf) { out("Il faut une preuve : `prouver ‹n°›`.", "sys"); return; }
    const pf = x.pf;
    if (v.length && v[0] !== pf.n && v.length === 1 && v[0] <= 8) { out(`La preuve en main concerne t${pf.n}.`, "err"); return; }
    let claim = pf.tx;
    const amount = v.length >= 2 ? v[1] : (v.length === 1 && v[0] > 8 ? v[0] : null);
    if (amount !== null) claim = pf.tx.replace(/:\d+$/, ":" + amount);
    let h = sha256(claim); const L = [`h0 = sha256("${claim}") = ${sh(h, 10)}`];
    pf.proof.forEach((p, i) => { h = p.side === "droite" ? sha256(h + p.h) : sha256(p.h + h); L.push(`h${i + 1} = sha256(${p.side === "droite" ? "h" + i + " + voisin" : "voisin + h" + i}) = ${sh(h, 10)}`); });
    out("Bob recalcule le chemin jusqu'à la racine :", "sys"); code(L.join("\n") + `\nrecalculée ${sh(h, 14)}   publiée ${sh(x.mroot, 14)}`);
    if (h === x.mroot) {
      out(`Les racines concordent : t${pf.n} fait bien partie du bloc, avec ${pf.proof.length} empreintes au lieu de 8. Pour 1 000 000 de transactions, il en faudrait 20.`, "ok");
      x.s3 = true; note("merkle"); fig("merkle", pf.n - 1);
      say("Maître Ada", "Voilà de quoi résumer un bloc entier en 64 caractères et prouver n'importe quelle transaction à peu de frais. Reste à rendre l'écriture d'un bloc coûteuse : la forge des mineurs, à l'ouest de la place.");
    } else if (amount !== null) {
      out("Racines différentes : le montant annoncé n'est pas celui du bloc. Une fausse affirmation ne passe pas, même avec une vraie preuve.", "err"); x.ctrlBad = true;
    } else {
      out("Racines différentes : cette preuve ne correspond plus à l'en-tête publié, car le mur a été falsifié. Ève remet le mur en état. Refais `prouver " + pf.n + "` puis `controler`.", "err");
      x.mtx = MTX.slice(); x.pf = null;
    }
  }

  /* ---------- étape 4 : preuve de travail ---------- */
  function mineCmd(c) {
    const x = F(), d = nums(c.rawArg)[0];
    if (room() === "tour") { out("Ici on ne mine que les branches de la fourche : `etendre a` ou `etendre b`.", "sys"); return; }
    if (room() !== "forge") { out("On mine à la forge (ouest de la place).", "sys"); return; }
    if (!x.s3) { say("Maître Ada", "L'arbre de Merkle d'abord : tu en auras besoin pour l'en-tête."); return; }
    if (![1, 2, 3, 4].includes(d)) { out("Choisis une difficulté de 1 à 4 : `miner 3` (nombre de zéros hexadécimaux exigés au début de l'empreinte).", "err"); return; }
    const i = x.chain.length + (x.mineN || 0); x.mineN = (x.mineN || 0) + 1;
    const prev = bh(x.chain[x.chain.length - 1]), txs = ["alice>bob:5", "bob>eve:3"];
    out(`Bloc candidat n° ${i}, racine de Merkle ${sh(merkle(txs))}, difficulté ${d} : l'empreinte doit commencer par ${"0".repeat(d)}.` + (d === 4 ? " (Quelques secondes de calcul.)" : ""), "sys");
    const r = pow(i, prev, txs, d, 6e6);
    if (!r) { out("Aucun nonce trouvé dans la limite d'essais. Réessaie.", "err"); return; }
    const L = []; for (let k = 0; k < Math.min(3, r.tries - 1); k++) L.push(`nonce ${k} → ${sha256(r.pre + k).slice(0, 20)}…  ✗`);
    if (r.tries > 4) L.push("   … " + fN(r.tries - 4) + " essais ratés …");
    if (r.tries > 3) L.push(`nonce ${r.nonce - 1} → ${sha256(r.pre + (r.nonce - 1)).slice(0, 20)}…  ✗`);
    L.push(`nonce ${r.nonce} → ${r.hash.slice(0, 20)}…  ✓`);
    code(L.join("\n"));
    const rate = Math.round(r.tries / (r.ms / 1000));
    out(`Trouvé : nonce = ${fN(r.nonce)} en ${fN(r.tries)} essais, ${fN(r.ms)} ms (≈ ${fN(rate)} empreintes/s dans ton navigateur). Pour le vérifier, une seule empreinte suffit.`, "ok");
    out(`Espérance : 16^${d} = ${fN(Math.pow(16, d))} essais en moyenne. (Tu peux avoir de la chance ou pas : chaque essai est un tirage indépendant.)`, "sys");
    x.rate = Math.max(x.rate || 0, rate);
    const s = x.stats[d] || { runs: 0, tries: 0, ms: 0 }; s.runs++; s.tries += r.tries; s.ms += r.ms; x.stats[d] = s;
    x.lastMine = { pre: r.pre, d, nonce: r.nonce };
    const keys = Object.keys(x.stats).map(Number).sort();
    code("difficulté  essais attendus  essais mesurés (moy.)  temps cumulé\n" + keys.map(k => `${String(k).padEnd(11)} ${fN(Math.pow(16, k)).padEnd(16)} ${fN(x.stats[k].tries / x.stats[k].runs).padEnd(22)} ${fN(x.stats[k].ms)} ms`).join("\n"));
    if (keys.length >= 3 && !x.s4) {
      x.s4 = true; note("pow"); fig("nonce", x.lastMine);
      out("Chaque zéro de plus multiplie le travail moyen par 16, alors que la vérification reste à 1 empreinte. Trouver coûte, vérifier est gratuit.", "ok");
      say("Maître Ada", "Maintenant, tente de réécrire l'histoire : `reecrire ‹n° de bloc›` sur une chaîne de 5 blocs minés.");
    } else if (!x.s4) out("Essaie une autre difficulté (au moins 3 différentes) pour comparer le coût.", "sys");
  }

  /* ---------- étape 5 : réécrire l'histoire ---------- */
  function rewriteCmd(c) {
    const x = F(), v = nums(c.rawArg);
    if (room() !== "forge") { out("La réécriture se tente à la forge.", "sys"); return; }
    if (!x.s4) { say("Maître Ada", "Maîtrise d'abord la preuve de travail : `miner ‹1 à 4›` à trois difficultés."); return; }
    const n = v[0], d = v.length > 1 ? v[1] : 3;
    if (!Number.isInteger(n) || n < 1 || n > 4 || ![1, 2, 3, 4].includes(d)) { out("`reecrire ‹bloc de 1 à 4› [difficulté de 1 à 4]` (ex. `reecrire 2`). La chaîne a 5 blocs : 0 à 4.", "err"); return; }
    if (d === 4) out("Difficulté 4 sur plusieurs blocs : jusqu'à une vingtaine de secondes de calcul…", "sys");
    const H = honest5(d), ch = clone(H.ch), k = 5 - n;
    out(`La chaîne honnête de 5 blocs a été minée à la difficulté ${d} (≈ ${fN(H.tries)} essais, ${fN(H.ms)} ms par bloc en moyenne). Mallory veut changer la transaction du bloc ${n} :`, "sys");
    ch[n].txs[0] = ch[n].txs[0].replace(/:\d+$/, ":500");
    const L = [`bloc ${n} : « ${ch[n].txs[0]} » : son empreinte ne commence plus par ${"0".repeat(d)} → à re-miner`];
    let tot = 0, ms = 0;
    for (let j = n; j < 5; j++) {
      ch[j].prev = bh(ch[j - 1]);
      const r = pow(j, ch[j].prev, ch[j].txs, d, 8e6); ch[j].nonce = r.nonce; tot += r.tries; ms += r.ms;
      L.push(`bloc ${j} re-miné : nonce ${fN(r.nonce)}, ${fN(r.tries)} essais, ${fN(r.ms)} ms`);
    }
    code(L.join("\n"));
    out(`Pour réécrire le bloc ${n} il a fallu re-miner ${k} bloc${k > 1 ? "s" : ""} : ${fN(tot)} essais, ${fN(ms)} ms, contre ${fN(H.tries)} essais pour un seul bloc honnête. Estimation : ${k} × 16^${d} = ${fN(k * Math.pow(16, d))} essais.`, "err");
    const q = 0.1;
    out(`Et ce n'est que la moitié du problème : pendant ce temps, le réseau honnête continue d'allonger la chaîne. Avec ${q * 100} % de la puissance, Mallory met ${k / q} durées de bloc pour refaire ${k} bloc${k > 1 ? "s" : ""}, durant lesquels les honnêtes en ajoutent ${Math.round(k / q * (1 - q))} de plus : elle ne rattrape jamais. Sur le vrai réseau Bitcoin, un bloc demande de l'ordre de 10^23 essais.`, "sys");
    x.rewN = x.rewN || []; if (!x.rewN.includes(n)) x.rewN.push(n);
    if (x.rewN.length < 2) { out("Compare avec un autre bloc : plus il est ancien, plus c'est cher (`reecrire 4` contre `reecrire 1`).", "sys"); return; }
    if (!x.s5) {
      x.s5 = true; note("reecriture");
      say("Maître Ada", "Le passé n'est pas inviolable par magie : il est protégé par la somme de travail accumulée dessus. Maintenant, que se passe-t-il quand deux mineurs trouvent un bloc en même temps ? À la tour de guet, au sud de la place.");
    }
  }

  /* ---------- étape 6 : consensus ---------- */
  function forkCmd() {
    const x = F();
    if (room() !== "tour") { out("La fourche se provoque à la tour de guet (sud de la place).", "sys"); return; }
    if (!x.s5) { say("Maître Ada", "D'abord le coût de réécriture, à la forge."); return; }
    if (x.fk) { out("La fourche est déjà là : `etendre a` ou `etendre b`, `comparer`.", "sys"); return; }
    x.fk = forkBase();
    out("Mallory diffuse en même temps, aux deux bouts de la cité, deux transactions contradictoires pour les mêmes 10 écus. Deux mineurs trouvent chacun un bloc valide à quelques secondes d'écart :", "sys");
    code(fkText(x.fk));
    out("Les deux blocs respectent toutes les règles et pèsent autant : les tours du nord suivent A, celles du sud suivent B. Deux versions de l'histoire coexistent, provisoirement.", "err");
    fig("fourche", x.fk);
    out("Fais miner la suite d'une branche : `etendre a` ou `etendre b`.", "sys");
  }
  function fkText(fk) {
    const t = fk.trunk[fk.trunk.length - 1];
    return `tronc commun jusqu'au bloc ${t.i} (hash ${sh(bh(t), 10)})\n` + ["A", "B"].map(k => fk[k].map(b => `branche ${k}  bloc ${b.i}  hash ${sh(bh(b), 10)}  ${b.txs.join(" ")}`).join("\n")).join("\n");
  }
  function extendCmd(c) {
    const x = F(), w = norm(c.rawArg).split(" ")[0];
    if (room() !== "tour") { out("Cela se passe à la tour de guet.", "sys"); return; }
    if (!x.fk) { out("Pas de fourche pour l'instant : `fourche`.", "sys"); return; }
    if (x.fk.win) { out("La fourche est déjà tranchée : seule la branche gagnante continue.", "sys"); return; }
    if (w !== "a" && w !== "b") { out("Quelle branche ? `etendre a` ou `etendre b`.", "err"); return; }
    const K = w.toUpperCase(), br = x.fk[K], last = br[br.length - 1], i = last.i + 1;
    const txs = [K === "A" ? "alice>ada:1" : "eve>ada:1"];
    const r = pow(i, bh(last), txs, 2, 1e6);
    br.push({ i, prev: bh(last), txs, nonce: r.nonce, d: 2 });
    out(`Un mineur de la branche ${K} trouve le bloc ${i} (${fN(r.tries)} essais) :`, "ok");
    const wa = work(x.fk.A), wb = work(x.fk.B);
    code(`branche A : ${x.fk.A.length} bloc(s), travail ≈ ${fN(wa)}\nbranche B : ${x.fk.B.length} bloc(s), travail ≈ ${fN(wb)}`);
    if (wa === wb) { out("Égalité de nouveau : toujours deux versions.", "sys"); fig("fourche", x.fk); return; }
    x.fk.win = wa > wb ? "A" : "B"; const L = x.fk.win === "A" ? "B" : "A";
    const kept = x.fk[x.fk.win][0].txs[0], lost = x.fk[L][0].txs[0];
    out(`La branche ${x.fk.win} pèse plus de travail : tous les nœuds basculent dessus. Les blocs de ${L} deviennent orphelins.`, "ok");
    out(`« ${kept} » est confirmée. « ${lost} » est annulée : les 10 écus de Mallory sont déjà dépensés, sa transaction ne sera jamais valide. Si le marchand avait livré après une seule confirmation (un bloc), il vient de perdre sa marchandise : c'est pourquoi on attend plusieurs blocs.`, "err");
    note("consensus"); fig("fourche", x.fk);
    out("Mais sur quoi les nœuds comparent-ils vraiment ? `comparer`", "sys");
  }
  function compareCmd() {
    const x = F();
    if (room() !== "tour") { out("La comparaison se fait à la tour de guet.", "sys"); return; }
    if (!x.s5) { say("Maître Ada", "D'abord le coût de réécriture."); return; }
    const L = [];
    if (x.fk) L.push(`fourche  A : ${x.fk.A.length} bloc(s), travail ${fN(work(x.fk.A))}   B : ${x.fk.B.length} bloc(s), travail ${fN(work(x.fk.B))}`);
    L.push(`chaîne X : 6 blocs faciles (difficulté 1) → 6 × 16 = ${fN(6 * 16)} essais de travail`);
    L.push(`chaîne Y : 3 blocs (difficulté 3)        → 3 × 4 096 = ${fN(3 * 4096)} essais de travail`);
    code(L.join("\n"));
    out("La règle n'est pas « la plus longue » au sens strict, mais « celle qui représente le plus de travail cumulé » (somme des difficultés). X est plus longue, Y est plus lourde : Y fait foi. Quand la difficulté est constante, les deux notions coïncident.", "ok");
    x.cmpw = true; check6();
  }
  function estimateCmd(c) {
    const x = F(), v = nums(c.rawArg);
    if (room() !== "tour") { out("Les calculs de risque se font à la tour de guet.", "sys"); return; }
    if (!x.s5) { say("Maître Ada", "D'abord le coût de réécriture."); return; }
    if (!x.fk || !x.fk.win) { say("Maître Ada", "Tranche d'abord la fourche (`fourche`, `etendre a`)."); return; }
    if (v.length < 2 || !(v[0] > 0 && v[0] < 100) || !Number.isInteger(v[1]) || v[1] < 0 || v[1] > 60) { out("`estimer ‹part de puissance en %› ‹confirmations›` (ex. `estimer 30 6`).", "err"); return; }
    const q = v[0] / 100, z = v[1], p = pSuccess(q, z);
    x.estN = (x.estN || 0) + 1; x.lastEst = { q, z, p };
    if (q >= 0.5) {
      out(`Avec ${v[0]} % de la puissance, l'attaquant produit en moyenne plus de blocs que tous les honnêtes réunis : il rattrape n'importe quel retard avec une probabilité de ${pct(p)}, quel que soit le nombre de confirmations. Seul le temps nécessaire change.`, "err");
      x.est51 = true;
      out("Il peut alors annuler ses propres paiements récents (double dépense) et censurer des transactions. Il ne peut pas dépenser les coins des autres (il lui manque leurs clés) ni faire accepter un bloc invalide : les nœuds le rejetteraient.", "sys");
    } else {
      const row = [1, 2, 3, 6, 12, 24].map(n => `${String(n).padStart(2)} confirmation(s) : ${pct(pSuccess(q, n))}`);
      out(`Part d'attaquant ${v[0]} %, ${z} confirmation(s) : probabilité de réussite ≈ ${pct(p)}.`, p < 0.01 ? "ok" : "err");
      code(`pour une part de ${v[0]} % :\n` + row.join("\n"));
    }
    if (x.estN === 1) fig("attaque", x.lastEst);
    check6();
  }
  function simulateCmd(c) {
    const x = F(), v = nums(c.rawArg);
    if (room() !== "tour") { out("Les simulations se font à la tour de guet.", "sys"); return; }
    if (!x.fk || !x.fk.win) { out("Tranche d'abord la fourche.", "sys"); return; }
    if (v.length < 2 || !(v[0] > 0 && v[0] < 50) || !Number.isInteger(v[1]) || v[1] < 1 || v[1] > 40) { out("`simuler ‹part < 50 %› ‹confirmations›` (ex. `simuler 30 6`).", "err"); return; }
    const q = v[0] / 100, z = v[1], N = 5000; let win = 0;
    for (let t = 0; t < N; t++) {
      let hon = 0, att = 0;
      while (hon < z) { if (Math.random() < q) att++; else hon++; }
      let def = z - att, st = 0;
      while (def > 0 && def < 60 && st < 4000) { def += Math.random() < q ? -1 : 1; st++; }
      if (def <= 0) win++;
    }
    out(`${fN(N)} courses simulées (un tirage au sort par bloc trouvé) : l'attaquant a réussi ${fN(win)} fois, soit ${pct(win / N)}. Calcul exact : ${pct(pSuccess(q, z))}.`, "ok");
  }
  function requireCmd(c) {
    const x = F(), v = nums(c.rawArg);
    if (room() !== "tour") { out("Les règles du marché se fixent à la tour de guet.", "sys"); return; }
    if (!x.fk || !x.fk.win) { out("Tranche d'abord la fourche et estime quelques risques.", "sys"); return; }
    if (!x.estN) { out("Estime d'abord quelques risques : `estimer 30 6`.", "sys"); return; }
    if (!(v.length && Number.isInteger(v[0]) && v[0] >= 1 && v[0] <= 60)) { out("`exiger ‹nombre de confirmations›` (ex. `exiger 12`).", "err"); return; }
    const z = v[0], p = pSuccess(POL_Q, z);
    if (x.pol) { out("Le marchand a déjà sa règle.", "sys"); return; }
    if (p >= POL_MAX) { out(`Avec ${z} confirmations, un attaquant à 30 % réussit encore ${pct(p)} du temps : au-dessus des 1 % tolérés. Cherche avec \`estimer 30 ‹n›\`.`, "err"); return; }
    x.pol = true;
    out(`${z} confirmations : un attaquant à 30 % ne réussit que ${pct(p)} du temps, sous les 1 % tolérés. Règle adoptée.`, "ok");
    if (z > polMin() + 8) out(`C'est plus prudent que nécessaire (${polMin()} suffisent) : chaque confirmation coûte du temps (10 minutes sur Bitcoin).`, "sys");
    else out(`(Minimum possible : ${polMin()} confirmations.) Sur Bitcoin, une confirmation dure environ 10 minutes : sécurité et délai se compensent.`, "sys");
    check6();
  }

  /* ---------- étape 7 : les limites ---------- */
  function energyCmd() {
    const x = F();
    if (room() !== "conseil") { out("La facture d'électricité se présente au Conseil (est de la tour).", "sys"); return; }
    if (!x.s6) { say("Maître Ada", "Termine d'abord l'étape du consensus."); return; }
    const t0 = performance.now(); let h = "x"; for (let i = 0; i < 20000; i++) h = sha256(h);
    const ms = Math.max(1, performance.now() - t0), rate = 20000 / (ms / 1000), NET = 6e20, J = 2e-11;
    const W = NET * J, TWh = W * 8760 / 1e12;
    out(`Ton navigateur hache à ≈ ${fN(rate)} empreintes/s. Le réseau Bitcoin : de l'ordre de ${NET.toExponential(0).replace("e+", " × 10^")} empreintes/s (ordre de grandeur 2024-2025).`, "sys");
    code(`Il faudrait environ ${(NET / rate).toExponential(1).replace(".", ",").replace("e+", " × 10^")} navigateurs comme le tien.\nAvec ≈ ${J.toExponential(0).replace("e-", " × 10^-")} J par empreinte (machines spécialisées) :\n  puissance ≈ ${(W / 1e9).toFixed(0)} GW  →  ≈ ${TWh.toFixed(0)} TWh par an`);
    out("Cette énergie est le prix de la sécurité : plus elle est élevée, plus réécrire l'histoire coûte cher. Le réseau ne traite pourtant que quelques transactions par seconde (de l'ordre de 5 à 7 sur la couche de base). Le Validateur propose une alternative : `parler validateur`.", "sys");
    x.energy = true; note("energie"); check7();
  }
  function testCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (room() !== "conseil") { out("Les dossiers sont au Conseil (est de la tour).", "sys"); return; }
    if (!x.s6) { say("Maître Ada", "Termine d'abord l'étape du consensus."); return; }
    if (/saisie|donnee|bob|certificat/.test(t)) {
      const ch = clone(x.chain), last = ch[ch.length - 1];
      ch.push({ i: ch.length, prev: bh(last), txs: ["certificat:bob:100kg-tomates-bio"], nonce: 0 });
      out("Bob inscrit sur la chaîne un certificat « 100 kg de tomates bio ». En réalité : 12 kg, pas bio.", "sys");
      code(`audit de la chaîne : ${ch.length} blocs, liens ${validChain(ch) ? "✓ tous valides" : "✗"}\nbloc ${ch.length - 1} : ${ch[ch.length - 1].txs[0]}  hash ${sh(bh(ch[ch.length - 1]))}`);
      out("La chaîne est parfaitement valide : elle prouve que cette déclaration a été faite, à cette date, et qu'elle n'a pas été modifiée. Pas qu'elle est vraie. Un mensonge saisi reste un mensonge, immuable. (Les données du monde réel entrent par des « oracles », qui sont des points de confiance.)", "err");
      x.tests.saisie = true;
    } else if (/cle|clef|signature|vol/.test(t)) {
      const bal = Math.max(1, balances(x.chain).alice || 10), tx = `alice>mallory:${bal}`, sig = sha256("cle privee d'alice|" + tx);
      out("Mallory a hameçonné la clé privée d'Alice et signe un transfert de tous ses écus vers elle.", "sys");
      code(`transaction : ${tx}\nsignature   : ${sig.slice(0, 32)}…\nle réseau vérifie la signature : ✓ valide (c'est bien la clé d'Alice)\nsolde suffisant : ✓   ordre : ✓   →  transaction acceptée`);
      out("Pour la blockchain, c'est Alice qui a payé : posséder la clé, c'est avoir le droit. Aucun guichet pour contester, et après quelques confirmations, la transaction est irréversible. La protection des clés (matériel dédié, multi-signature, sauvegardes) reste l'affaire des utilisateurs.", "err");
      x.tests.cle = true;
    } else if (/contrat|code|coffre|dao/.test(t)) {
      const run = fixed => {
        const pool = { total: 100 }, bal = { mallory: 10, alice: 50, bob: 40 }, log = []; let depth = 0;
        const retirer = w => {
          const a = bal[w]; if (!a || pool.total < a) return;
          if (fixed) bal[w] = 0;
          pool.total -= a; log.push(`${w} retire ${a}  (reste ${pool.total} dans le coffre)`);
          if (w === "mallory" && !fixed && depth < 20) { depth++; retirer(w); }
          bal[w] = 0;
        };
        retirer("mallory"); return { log, pool: pool.total };
      };
      const a = run(false), b = run(true);
      out("Le Conseil a déployé un coffre commun de 100 écus (alice 50, bob 40, mallory 10). La fonction « retirer » envoie l'argent PUIS met le solde à 0. Mallory, dont le portefeuille se rappelle lui-même à la réception, retire encore et encore avant la mise à jour :", "sys");
      code("version avec bug :\n  " + a.log.join("\n  ") + `\n  → coffre : ${a.pool} écu(s). Mallory a retiré ${100 - a.pool} écus avec 10 déposés.\nversion corrigée (solde remis à 0 AVANT d'envoyer) :\n  ` + b.log.join("\n  ") + `\n  → coffre : ${b.pool} écus.`);
      out("La blockchain a exécuté le code fidèlement, bug compris, et ne permet pas de le corriger après coup : « le code fait loi ». C'est le scénario de The DAO (2016), où des millions d'ether ont été siphonnés par ce type de défaut. D'où les audits, les tests et les contrats minuscules.", "err");
      x.tests.contrat = true;
    } else { out("Quel dossier ? `tester saisie`, `tester cle` ou `tester contrat`.", "err"); return; }
    if (x.tests.saisie && x.tests.cle && x.tests.contrat && !x.noteLim) { x.noteLim = true; note("limites"); }
    check7();
  }

  /* ---------- épilogue et bilan ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Voici ce que tu as vu. Un grand livre que tous tiennent ensemble : l'ordre des opérations est unique, donc la double dépense meurt. Des blocs chaînés par leurs empreintes : toute retouche du passé se voit. Un arbre de Merkle pour tenir un bloc en 64 caractères et prouver une transaction avec quelques empreintes. Une preuve de travail pour que l'écriture coûte. Et la règle de la chaîne la plus lourde pour que la cité s'accorde sans arbitre.");
    say("Maître Ada", "Mais retiens la limite : la blockchain protège l'histoire, pas la vérité des données, ni les clés, ni le code. Utilise-la quand il n'y a vraiment personne à qui faire confiance, et une base de données ordinaire le reste du temps. Mallory continuera à chercher le maillon faible : il se trouve rarement dans les empreintes.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le carnet de chaque marchand = une base de données non partagée.** Chacun vérifie correctement SES données, mais personne ne voit l'ensemble : la double dépense est possible. Le **Grand Livre = le registre distribué** : tout le monde en détient une copie et les opérations y ont un ordre unique.");
    out("**Les blocs chaînés = le chaînage par hachage.** L'en-tête de chaque bloc contient l'empreinte (SHA-256) du bloc précédent. Modifier un ancien bloc change son empreinte et casse tous les liens suivants jusqu'à la tête de chaîne. **La copie d'Ève = un nœud complet** qui revérifie tout et compare la tête.");
    out("**L'arbre de Merkle (la halle).** Les transactions sont hachées deux à deux jusqu'à une racine unique, placée dans l'en-tête. Une preuve d'inclusion ne demande que log2(n) empreintes : c'est ce qui permet aux clients légers (portefeuilles mobiles) de vérifier un paiement sans télécharger le bloc.");
    out("**La forge = les mineurs et la preuve de travail.** Chercher un nonce tel que l'empreinte soit sous un seuil est le seul moyen d'écrire un bloc ; chaque zéro hexadécimal supplémentaire multiplie le travail par 16 ; vérifier ne demande qu'un hachage. Le coût de réécriture d'un bloc est (nombre de blocs à refaire) × (travail par bloc), face à un réseau qui continue d'avancer.");
    out("**La tour de guet = le réseau de nœuds et le consensus.** Chaque nœud retient la chaîne représentant le plus de travail cumulé, et les blocs de la branche perdante deviennent orphelins (le Bitcoin attend en général 6 confirmations). Le calcul du jeu suit le modèle de la « course » de Nakamoto : un attaquant de part q doit rattraper z blocs ; sa probabilité est de l'ordre de (q/(1-q))^z si q < 50 %, et 100 % au-delà. L'attaque des 51 % permet de réécrire ses propres paiements récents et de censurer, pas de voler les clés des autres.");
    out("**Le Validateur = la preuve d'enjeu (proof of stake).** Un capital mis en gage remplace l'électricité : on est tiré au sort selon sa mise et on risque d'en perdre une partie en cas de triche. Ethereum y est passé en 2022 et a réduit sa consommation de plus de 99 %. **Les trois dossiers** montrent ce qu'aucun consensus ne répare : une donnée fausse saisie, une clé privée volée, un contrat mal écrit.");
    out("**Les simplifications du jeu.** (1) Les transactions sont de simples lignes « de>vers:montant », sans signatures (en vrai : signatures à clé publique, ECDSA ou EdDSA, modèle UTXO ou comptes, frais, récompense du mineur). (2) Le seuil de difficulté est « n zéros hexadécimaux » ; Bitcoin compare l'empreinte (double SHA-256 d'un en-tête de 80 octets) à une cible fine, et recalibre la difficulté toutes les 2 016 blocs pour viser 10 minutes par bloc. (3) L'arbre de Merkle concatène les empreintes en texte hexadécimal et non en octets bruts. (4) Le consensus est réduit à « le plus de travail », sans propagation réseau, latence ni mempool ; la probabilité de rattrapage est un modèle simplifié (attaquant secret, un seul compte à rebours). (5) Les chiffres d'énergie et de puissance du réseau sont des ordres de grandeur variables dans le temps. (6) La preuve d'enjeu n'est que résumée (tirage, slashing), sans ses attaques ni ses finalités.");
    out("Rappel utile : **une blockchain prouve l'ordre et l'intégrité de ce qui y a été inscrit, pas que c'était vrai, ni que celui qui a signé était légitime. Sa sécurité vient du coût de réécrire l'histoire, et chaque confirmation supplémentaire la renforce.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    chaine: snap => {
      const ch = snap || F().chain;
      const st = ch.map((b, j) => ({ b, h: bh(b), ok: linkOk(ch, j) }));
      const view = st.slice(-4);
      let s = "";
      view.forEach((e, k) => {
        const x0 = 5 + k * 106, cl = e.ok ? "f-ok" : "f-bad", ft = e.ok ? "ft-ok" : "ft-bad";
        s += R(x0, 12, 92, 112, cl) + T(x0 + 46, 30, "Bloc " + e.b.i, "f-b") + T(x0 + 46, 50, "prev " + (e.b.i ? e.b.prev.slice(0, 6) : "000000"), "f-s") +
          T(x0 + 46, 68, "racine " + merkle(e.b.txs).slice(0, 6), "f-s") + T(x0 + 46, 86, "nonce " + e.b.nonce, "f-s") + T(x0 + 46, 108, "hash " + e.h.slice(0, 6), "f-s " + ft);
        if (k < view.length - 1) s += AR(x0 + 92, 68, x0 + 106, 68, view[k + 1].ok ? "f-ok" : "f-bad");
      });
      const broken = st.filter(e => !e.ok).length;
      s += T(210, 150, broken ? "✗ le lien rompu se voit dès le bloc suivant la retouche" : "✓ chaque prev est l'empreinte du bloc précédent", broken ? "ft-bad f-b" : "ft-ok f-b");
      s += T(210, 170, "changer un bloc change son hash, donc le prev du suivant, etc.", "f-s");
      return { cap: "Chaque bloc contient l'empreinte du précédent. Vert : lien cohérent ; rouge : lien rompu après une falsification.", svg: SVG(184, "Chaîne de blocs et empreintes", s) };
    },
    merkle: sel => {
      const lv = levels(MTX), cx = i => 30 + i * 52, Y = [170, 118, 66, 14];
      const pos = lv.map((l, k) => l.map((_, i) => k === 0 ? cx(i) : (pos0(k - 1, 2 * i) + pos0(k - 1, 2 * i + 1)) / 2));
      function pos0(k, i) { return k === 0 ? cx(i) : (pos0(k - 1, 2 * i) + pos0(k - 1, 2 * i + 1)) / 2; }
      const path = new Set(), sib = new Set();
      if (sel !== null && sel !== undefined) { let i = sel; for (let l = 0; l < lv.length; l++) { path.add(l + ":" + i); if (l < lv.length - 1) sib.add(l + ":" + (i ^ 1)); i >>= 1; } }
      let s = "";
      for (let l = 0; l < lv.length - 1; l++) lv[l].forEach((_, i) => { s += LN(pos[l][i], Y[l], pos[l + 1][i >> 1], Y[l + 1] + 30); });
      lv.forEach((arr, l) => arr.forEach((h, i) => {
        const key = l + ":" + i, cl = path.has(key) ? "f-pub" : sib.has(key) ? "f-ok" : (l === lv.length - 1 ? "f-priv" : "");
        s += R(pos[l][i] - 24, Y[l], 48, 30, cl) + T(pos[l][i], Y[l] + 19, h.slice(0, 4), "f-s");
      }));
      MTX.forEach((_, i) => { s += T(cx(i), 220, "t" + (i + 1), "f-s"); });
      s += T(8, 22, "racine", "f-b ft-priv", "start");
      if (path.size) s += T(210, 244, "bleu : chemin · vert : empreintes de la preuve", "f-s");
      else s += T(210, 244, "8 transactions, 3 niveaux, 1 racine", "f-s");
      return { cap: "Arbre de Merkle des 8 transactions (4 premiers caractères de chaque empreinte). Pour prouver une transaction, on ne donne que les voisins (en vert) le long de son chemin.", svg: SVG(252, "Arbre de Merkle", s) };
    },
    nonce: m => {
      let s = "";
      const stats = F().stats || {};
      if (m) {
        const start = Math.max(0, m.nonce - 3);
        for (let k = start; k <= m.nonce; k++) {
          const ok = k === m.nonce, y = 22 + (k - start) * 20;
          s += T(10, y, "nonce " + k, "f-s", "start") + T(104, y, sha256(m.pre + k).slice(0, 24) + "…", "f-s " + (ok ? "ft-ok f-b" : "ft-bad"), "start") + T(408, y, ok ? "✓" : "✗", "f-b " + (ok ? "ft-ok" : "ft-bad"), "end");
        }
        s += T(210, 112, `difficulté ${m.d} : l'empreinte doit commencer par ${m.d} zéro${m.d > 1 ? "s" : ""}`, "f-b");
      }
      s += T(10, 142, "travail moyen par bloc", "f-b", "start");
      for (let d = 1; d <= 4; d++) {
        const y = 154 + (d - 1) * 22, s1 = stats[d];
        s += T(10, y + 13, "difficulté " + d, "f-s", "start") + `<rect x="100" y="${y}" width="${40 * d + 20}" height="16" rx="3" fill="var(--${d < 3 ? "ok" : "bad"})" opacity=".8"/>` +
          T(100 + 40 * d + 28, y + 13, "≈ " + fN(Math.pow(16, d)) + (s1 ? " · mesuré " + fN(s1.tries / s1.runs) : " essais"), "f-s", "start");
      }
      s += T(210, 262, "chaque zéro de plus : ×16 (échelle logarithmique)", "f-s");
      return { cap: "Recherche de nonce : on essaie 0, 1, 2… jusqu'à une empreinte qui commence par assez de zéros. Les barres montrent le coût moyen par difficulté et, si tu l'as mesuré, le nombre d'essais de ta partie.", svg: SVG(274, "Recherche de nonce", s) };
    },
    fourche: fk => {
      fk = fk || { trunk: [0, 1, 2].map(i => ({ i })), A: [{ i: 3 }], B: [{ i: 3 }], win: null };
      let s = T(80, 52, "tronc commun", "f-s");
      fk.trunk.forEach((b, k) => { const x0 = 10 + k * 50; s += R(x0, 60, 40, 28) + T(x0 + 20, 78, "#" + b.i, "f-s"); if (k < fk.trunk.length - 1) s += AR(x0 + 40, 74, x0 + 50, 74); });
      const end = 10 + (fk.trunk.length - 1) * 50 + 40;
      ["A", "B"].forEach((K, r) => {
        const y = r ? 124 : 24, br = fk[K], lost = fk.win && fk.win !== K, cl = fk.win ? (lost ? "f-bad f-dash" : "f-ok") : "f-pub";
        s += AR(end, 74, 170, y + 14, lost ? "f-bad" : "") + T(170, y - 4, `chaîne ${K}` + (lost ? " : orphelins" : fk.win ? " : gagnante" : ""), "f-s " + (lost ? "ft-bad" : fk.win ? "ft-ok" : ""), "start");
        br.forEach((b, k) => { const x0 = 170 + k * 56; s += R(x0, y, 44, 28, cl) + T(x0 + 22, y + 18, "#" + b.i, "f-s"); if (k < br.length - 1) s += AR(x0 + 44, y + 14, x0 + 56, y + 14); });
        s += T(170, y + 46, `${br.length} bloc(s), travail ≈ ${fN(br.reduce((t, b) => t + Math.pow(16, b.d || 2), 0))}`, "f-s", "start");
      });
      s += T(210, 192, fk.win ? "les nœuds suivent la chaîne la plus lourde" : "deux blocs valides : deux histoires", "f-b");
      return { cap: "Une fourche : deux blocs valides au même rang. Dès qu'une branche s'allonge, elle pèse plus de travail, tous les nœuds la suivent et les blocs de l'autre deviennent orphelins.", svg: SVG(206, "Fourche et chaîne la plus lourde", s) };
    },
    attaque: est => {
      const X0 = 50, X1 = 400, Y0 = 20, Y1 = 150, zs = 12, px = z => X0 + (X1 - X0) * z / zs, py = p => Y1 - (Y1 - Y0) * p;
      let s = LN(X0, Y1, X1, Y1) + LN(X0, Y0, X0, Y1);
      [0, 0.5, 1].forEach(p => { s += T(44, py(p) + 4, Math.round(p * 100) + "%", "f-s", "end"); });
      [0, 3, 6, 9, 12].forEach(z => { s += T(px(z), Y1 + 16, String(z), "f-s"); });
      s += T(225, Y1 + 34, "confirmations (blocs d'avance des honnêtes)", "f-s");
      [[0.1, "f-ok", "10 %"], [0.3, "f-pub", "30 %"], [0.45, "f-bad", "45 %"]].forEach(([q, cl, lab], k) => {
        let pts = ""; for (let z = 0; z <= zs; z++) pts += `${px(z).toFixed(1)},${py(pSuccess(q, z)).toFixed(1)} `;
        s += `<polyline points="${pts}" fill="none" class="f-ln ${cl}"/>` + LN(240 + k * 62, 8, 252 + k * 62, 8, cl) + T(256 + k * 62, 11, lab, "f-s", "start");
      });
      if (est && est.q < 0.5 && est.z <= zs) s += `<circle cx="${px(est.z)}" cy="${py(est.p)}" r="4" fill="var(--bad)"/>`;
      if (est && est.q >= 0.5) s += T(225, 72, "au-delà de 50 % : 100 % pour toute valeur de z", "ft-bad f-b");
      else s += T(300, 118, "sous 50 %, chute exponentielle", "f-s");
      return { cap: "Probabilité de succès d'un attaquant en fonction de sa part de puissance et du nombre de confirmations attendues (modèle simplifié). Le point rouge est ta dernière estimation.", svg: SVG(206, "Probabilité d'une attaque selon les confirmations", s) };
    },
  };

  GAMES.chain = {
    id: "chain", order: 19, title: "Le Grand Livre de Port-443", pageTitle: "Chain Quest", subtitle: "aventure textuelle · blockchain et preuve de travail",
    blurb: "Sans banque centrale, construis un grand livre infalsifiable : chaînage, arbre de Merkle, minage, consensus.",
    concept: "Blockchain, preuve de travail",
    start: "place", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      x.chain = [{ i: 0, prev: ZERO, txs: GEN, nonce: 0 }]; x.pub = clone(x.chain);
      x.pay1 = {}; x.stats = {}; x.rewN = []; x.mtx = MTX.slice(); x.mroot = merkle(MTX); x.tests = {};
    },
    refig(name) {
      const x = F();
      fig(name, name === "chaine" ? (x.snap || x.chain) : name === "merkle" ? (x.pf ? x.pf.n - 1 : null) : name === "nonce" ? x.lastMine : name === "fourche" ? x.fk : name === "attaque" ? x.lastEst : undefined);
    },
    figAlias: { chaine: ["chainage", "blocs", "hash"], merkle: ["arbre", "racine"], nonce: ["pow", "preuve", "minage", "travail"], fourche: ["consensus", "fork", "longue"], attaque: ["51", "probabilite", "confirmations"] },
    help: "Spécifiques : `payer ‹bob|boulangere›` · `ouvrir livre` · `ajouter ‹de› ‹vers› ‹montant›` · `modifier ‹n°› ‹montant›` · `auditer` · `recalculer` · `batir` · `prouver ‹n°›` · `controler` · `miner ‹1-4›` · `reecrire ‹bloc›` · `fourche` · `etendre ‹a|b›` · `comparer` · `estimer ‹%› ‹n›` · `simuler ‹%› ‹n›` · `exiger ‹n›` · `energie` · `tester ‹saisie|cle|contrat›`",
    verbs: {
      pay: { words: ["payer", "verser", "acheter"], run: payCmd },
      open: { words: ["ouvrir", "instituer"], run: openBook },
      add: { words: ["ajouter", "inscrire", "enregistrer"], run: addCmd },
      modify: { words: ["modifier", "falsifier", "truquer"], run: modifyCmd },
      audit: { words: ["auditer"], run: auditCmd },
      relink: { words: ["recalculer", "reparer", "raccorder"], run: relink },
      build: { words: ["batir", "edifier"], run: buildCmd },
      prove: { words: ["prouver", "preuve"], run: proveCmd },
      control: { words: ["controler", "valider"], run: controlCmd },
      mine: { words: ["miner", "extraire"], run: mineCmd },
      rewrite: { words: ["reecrire", "refaire"], run: rewriteCmd },
      fork: { words: ["fourche", "bifurquer"], run: forkCmd },
      extend: { words: ["etendre", "prolonger"], run: extendCmd },
      compare: { words: ["comparer", "peser"], run: compareCmd },
      estimate: { words: ["estimer", "evaluer", "proba"], run: estimateCmd },
      simulate: { words: ["simuler"], run: simulateCmd },
      require: { words: ["exiger", "imposer", "fixer"], run: requireCmd },
      energy: { words: ["energie", "consommation"], run: energyCmd },
      test: { words: ["tester", "essayer"], run: testCmd },
    },
    intro() {
      out("Le Grand Livre de Port-443", "title");
      out("La banque centrale de Port-443 a fermé. Plus personne pour dire qui possède quoi : chaque commerçant tient son carnet, et Mallory rôde avec ses 10 écus numériques. La cité veut un grand livre que tous tiennent ensemble, et que personne ne puisse falsifier sans que tout le monde le voie.\nMaître Ada te charge d'auditer ce projet (audit autorisé, données fictives) en le reconstruisant pas à pas, avec du vrai SHA-256 : chaînage des blocs, arbre de Merkle, minage, consensus et attaques.", "");
    },
  };
})();
