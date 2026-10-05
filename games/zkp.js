"use strict";
/* La Caverne de Port-443 : preuves à divulgation nulle de connaissance.
   Caverne d'Ali Baba jouable, simulateur, vrai protocole de Schnorr (p = 23, q = 11, g = 2), Fiat-Shamir avec SHA-256 réel. */
(function () {
  const F = () => f();
  const P = 23, Q = 11, GEN = 2, X = 7;           // g = 2 est d'ordre 11 modulo 23 (2^11 = 2048 = 89 x 23 + 1)
  const Y = modpow(GEN, X, P);                     // clé publique d'Alice : 13
  const pw = (b, e) => modpow(b, e, P);
  const ymul = (c) => pw(Y, c);

  /* ---------- hasard reproductible (graine fixe : le jeu rejoue toujours le même déroulé) ---------- */
  function rnd() {
    const x = F();
    x.seed = (x.seed + 0x6D2B79F5) >>> 0;
    let t = x.seed;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  const rint = (a, b) => a + Math.floor(rnd() * (b - a + 1));
  const hc = (t, ctx) => parseInt(sha256(`${GEN},${Y},${t}` + (ctx ? "," + ctx : "")).slice(0, 8), 16) % Q;
  const pct = n => { const v = 100 / Math.pow(2, n); return String(+v.toPrecision(3)).replace(".", ",") + " %"; };
  const sideName = s => s === "G" ? "gauche" : "droite";
  function parseSide(txt) {
    const t = norm(txt || "").split(" ");
    for (const w of t) { if (w === "g" || w === "gauche") return "G"; if (w === "d" || w === "droite") return "D"; }
    return null;
  }
  const nums = txt => (txt.match(/-?\d+/g) || []).map(Number);

  const notes = {
    preuve: ["Prouver qu'on sait, sans dire quoi", "Une preuve de connaissance convainc un vérificateur que le prouveur connaît un secret (ici, un mot de passe), sans que le secret soit transmis. Ce n'est pas du chiffrement : on ne cache pas un message, on cache la raison pour laquelle l'affirmation est vraie."],
    proba: ["Chaque tour divise la chance de tricher par deux", "Dans la caverne, une tricheuse qui ne connaît pas le mot devine le bon côté une fois sur deux. Après n tours réussis, elle n'a passé que dans 1 cas sur 2^n : 1/2, 1/4, 1/8… 1/1024 après 10 tours. On ne prouve jamais « à 100 % » : on rend la triche aussi improbable que voulu (une preuve probabiliste)."],
    proprietes: ["Complétude, solidité, divulgation nulle", "Trois propriétés définissent une preuve à divulgation nulle. Complétude : si l'affirmation est vraie et que les deux jouent honnêtement, le vérificateur accepte. Solidité : si elle est fausse, aucun tricheur n'est accepté, sauf avec une probabilité négligeable. Divulgation nulle : le vérificateur n'apprend rien d'autre que « c'est vrai », rien qui l'aide à refaire la preuve pour un tiers."],
    simulateur: ["L'argument du simulateur", "Pour montrer que rien ne fuit, on prouve qu'on peut fabriquer, sans connaître le secret, une transcription indiscernable d'une vraie (le « simulateur » connaît à l'avance les défis, donc il s'arrange pour toujours y répondre). Conséquence : un film d'une preuve ne prouve rien à un tiers. Il n'est convaincant que pour celui qui a lancé les défis au hasard, en direct."],
    schnorr: ["Le protocole de Schnorr", "Paramètres publics : p = 23, q = 11 (q divise p−1), g = 2 d'ordre q. Secret x, clé publique y = g^x mod p. Trois messages : engagement t = g^r mod p (r aléatoire), défi c choisi par le vérificateur (de 0 à q−1), réponse s = r + c·x mod q. Vérification : g^s ≡ t · y^c (mod p). Une tricheuse qui ne connaît pas x ne peut répondre correctement qu'à un seul défi, qu'elle devrait deviner à l'avance : 1 chance sur q. Avec un q de 256 bits, c'est 1 chance sur 2^256."],
    aleas: ["Un aléa neuf à chaque preuve", "Si le même r sert pour deux défis différents c1 et c2, on obtient s1 − s2 ≡ (c1 − c2)·x (mod q) : r disparaît et x se calcule. Un observateur qui capte les deux preuves retrouve le secret. D'où la règle : r doit être aléatoire, secret et jamais réutilisé (ou dérivé de façon déterministe du secret et du message, comme Ed25519). Des clés ont ainsi fuité dans la vraie vie, par exemple avec les signatures ECDSA de la PlayStation 3, qui réutilisaient leur nonce."],
    fiatshamir: ["Fiat-Shamir : supprimer l'interaction", "On remplace le vérificateur par une fonction de hachage : c = H(g, y, t). Alice envoie (t, s) d'un seul coup, et chacun peut vérifier seul. Comme t est figé avant que c existe, elle ne peut plus choisir t après avoir vu c. Il faut un espace de défis immense : avec q = 11, Mallory « broie » un faux en une dizaine d'essais. Il faut aussi hacher toute la déclaration (g, y, t, contexte) : en oublier une partie ouvre des attaques réelles."],
    usages: ["À quoi ça sert", "Authentification sans mot de passe stocké : le serveur ne garde que y (c'est le principe des clés SSH et des signatures Schnorr/Ed25519), et un contexte unique dans le hachage empêche de rejouer une preuve capturée. Preuve d'âge ou de solvabilité : on prouve « majeur », « solde ≥ seuil » sans livrer la date de naissance ou le solde. Confidentialité des transactions (Zcash) et zk-rollups : une seule preuve de quelques centaines d'octets atteste qu'un lot de milliers de transactions a été exécuté correctement."],
    limites: ["Les limites", "Paramètres de confiance : certaines preuves (zk-SNARK comme Groth16) exigent une cérémonie de configuration dont le secret doit être détruit ; d'autres (zk-STARK) s'en passent mais produisent de plus grosses preuves. Coût : prouver est bien plus lent que vérifier. Implémentation : l'erreur la plus fréquente n'est pas mathématique (aléa réutilisé, déclaration mal hachée, circuit qui oublie une contrainte). Et une preuve ne dit que ce qu'on a formalisé : si l'énoncé est mal posé, elle prouve la mauvaise chose."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle tient un parchemin où elle a écrit trois mots : « complétude, solidité, discrétion »." },
    alice: { npc: true, names: ["alice", "prouveuse"], label: "Alice", vis: () => S.room !== "cabine" && S.room !== "place", desc: () => "Alice, la prouveuse. Elle affirme connaître le mot qui ouvre la porte magique, et ne veut le dire à personne." },
    bob: { npc: true, names: ["bob", "verificateur"], label: "Bob", vis: () => S.room === "cabine" || S.room === "halle" || S.room === "place" || S.room === "atelier", desc: () => "Bob, le vérificateur. Il paiera pour le mot si Alice prouve qu'elle le connaît, mais il est méfiant, comme il se doit." },
    eve: { npc: true, names: ["eve", "espionne"], label: "Ève", vis: () => S.room === "cabine" || S.room === "halle" || S.room === "atelier", desc: () => "Ève, qui écoute tout ce qui se dit et se filme à Port-443. Elle ne triche pas : elle regarde, et enregistre." },
    mallory: { npc: true, names: ["mallory", "tricheuse", "alice voilee"], label: "Mallory, la tricheuse", vis: () => ["caverne", "atelier", "scriptorium"].includes(S.room), desc: () => "Mallory, voilée pour ressembler à Alice. Elle ne connaît pas le mot (ni le secret x) : elle tente sa chance. Audit autorisé, tout est simulé." },
    porte: { names: ["porte", "porte magique"], label: "la porte magique", vis: () => S.room === "caverne", desc: () => "Au fond de la caverne en anneau, une porte magique barre le passage entre le côté gauche et le côté droit. Elle ne s'ouvre qu'à celui qui prononce le mot." },
    anneau: { names: ["anneau", "tunnels", "caverne", "tunnel", "plan"], label: "", vis: () => S.room === "caverne", desc: () => "Un anneau : on entre par une seule ouverture, puis le couloir se sépare en un côté gauche et un côté droit, qui se rejoignent au fond, fermés par la porte. Bob attend à l'entrée : il ne voit pas dans quel côté Alice s'engage. `demander gauche` ou `demander droite` : tu choisis par où elle doit ressortir. `schema caverne` après ton premier succès." },
    film: { names: ["film", "bobine", "camera", "projecteur"], label: "le film d'Ève", vis: () => S.room === "cabine", desc: () => F().film ? "Le film d'Ève : les " + F().film.length + " derniers tours d'Alice, avec les défis de Bob. `scenario ‹G D G D D G›` : tu écris un scénario de 6 tours pour Mallory, qui n'a pas le mot." : "Une caméra et une bobine vides : Ève n'a rien filmé pour l'instant. Fais d'abord ta preuve dans la caverne." },
    ardoise: { names: ["ardoise", "parametres", "tableau"], label: "l'ardoise des paramètres", vis: () => S.room === "atelier", onExamine() { F().sawParams = true; },
      desc: () => `Paramètres publics gravés : p = ${P}, q = ${Q}, g = ${GEN}. Vérifie avec \`calc ${GEN}^${Q} mod ${P}\` : tu dois trouver 1 (g est d'ordre q). Clé publique d'Alice : y = ${Y} (= g^x mod p, x est secret). Protocole : t = g^r mod p, défi c de 0 à ${Q - 1}, s = r + c·x mod q, vérification g^s ≡ t · y^c (mod p). Commandes : \`prouver\`, \`defi ‹c›\`, \`verifier ‹a› ‹b›\` (a = g^s mod p, b = t·y^c mod p), \`convoquer alice|mallory\`.` },
    scribe: { names: ["scribe", "sceau", "machine", "hachoir"], label: "le Scribe-hachoir", vis: () => S.room === "scriptorium", desc: () => `Le Scribe-hachoir calcule le défi de Fiat-Shamir : c = SHA-256("g,y,t"), les 8 premiers chiffres hexadécimaux lus comme un nombre, modulo ${Q}. \`hacher ‹texte›\` (par exemple \`hacher ${GEN},${Y},‹t›\`). Alice affiche sa preuve avec \`prouver\`, \`verifier ‹a› ‹b›\` la contrôle, \`forger\` laisse Mallory tricher.` },
    guichet: { names: ["guichet", "serveur", "base"], label: "le guichet de connexion", vis: () => S.room === "halle", desc: () => `Le serveur du guichet ne stocke pas de mot de passe : seulement la clé publique d'Alice, y = ${Y}. \`connecter\` lance une connexion d'Alice par preuve non interactive, \`rejouer\` laisse Ève rejouer la preuve captée.` },
    comptoir: { names: ["comptoir", "videur", "taverne"], label: "le comptoir du videur", vis: () => S.room === "halle", desc: () => "Le comptoir du videur : on n'y sert que les majeurs. `presenter carte` montre la carte d'identité, `presenter preuve` fait une preuve d'âge." },
    stand: { names: ["stand", "rollup", "rouleau", "lots"], label: "le stand des rouleaux", vis: () => S.room === "halle", desc: () => "Le stand des rouleaux : un coursier y regroupe des transactions pour les valider d'un coup. `grouper ‹n›` regroupe n transactions (2 à 5000) sous une seule preuve." },
  };

  const rooms = {
    place: { name: "La place de la Guilde", short: "Place", alias: ["place", "guilde"], ents: ["ada", "bob"], exits: { nord: "caverne", est: "cabine", ouest: "atelier", sud: "halle" },
      desc: () => "Le cœur de Port-443. Au nord, l'entrée de la caverne en anneau. À l'est, la cabine d'Ève. À l'ouest, l'atelier des calculs. Au sud, la halle des usages." },
    caverne: { name: "La caverne en anneau", short: "Caverne", alias: ["caverne", "anneau"], ents: ["alice", "mallory", "porte", "anneau"], exits: { sud: "place" },
      desc: () => "Une caverne en forme d'anneau, avec une seule entrée. Au fond, une porte magique relie les deux côtés. Tu joues le vérificateur : tu attends à l'entrée, sans rien voir, et tu cries le côté par lequel tu veux voir ressortir la prouveuse. Alice est là ; Mallory aussi, voilée." },
    cabine: { name: "La cabine d'Ève", short: "Cabine", alias: ["cabine", "eve"], ents: ["eve", "bob", "film"], exits: { ouest: "place" },
      desc: () => "Une cabine de projection tapissée de bobines. Ève y garde tout ce qu'elle a filmé. Bob est venu regarder." },
    atelier: { name: "L'atelier des calculs", short: "Atelier", alias: ["atelier", "calculs"], ents: ["alice", "mallory", "bob", "eve", "ardoise"], exits: { est: "place", nord: "scriptorium" },
      desc: () => "Un atelier d'arithmétique : une ardoise couverte de paramètres, un boulier (`calc`), des chiffres partout. C'est ici que l'on joue le vrai protocole, avec de petits nombres. Au nord, le scriptorium. Ève s'est glissée sous la grande table." },
    scriptorium: { name: "Le scriptorium", short: "Scriptorium", alias: ["scriptorium", "scribe"], ents: ["alice", "mallory", "scribe"], exits: { sud: "atelier" },
      desc: () => "Une salle silencieuse : un Scribe-hachoir y transforme n'importe quel texte en empreinte. Ici, plus de Bob au guichet : le hachage joue le rôle du vérificateur." },
    halle: { name: "La halle des usages", short: "Halle", alias: ["halle", "usages"], ents: ["alice", "bob", "eve", "guichet", "comptoir", "stand"], exits: { nord: "place" },
      desc: () => "Une halle de marché où l'on essaie ce que valent ces preuves dans la vraie vie : un guichet de connexion, le comptoir d'un videur, un stand de regroupement de transactions." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.hOk) return "c1";
    if (!x.caught) return "c2";
    if (!x.proba) return "proba";
    if (!x.props) return "props";
    if (!x.film2) return "cab1";
    if (!x.guessed) return "cab2";
    if (!x.sawParams) return "a0";
    if (!x.schnorrOk) return "a1";
    if (!x.mCaught) return "a2";
    if (!x.pair) return "a3";
    if (!x.rev) return "a4";
    if (!x.fs) return "f1";
    if (!x.hashedT) return "f2";
    if (!x.fsOk) return "f3";
    if (!x.forged) return "f4";
    if (!x.login) return "u1";
    if (!x.replayFail) return "u2";
    if (!x.ageCard || !x.ageProof) return "u3";
    if (!x.rollup) return "u4";
    if (!x.end) return "end";
    return "fin";
  };
  const sesHint = () => {
    const s = F().ses;
    if (!s || s.done) return ["Lance une preuve : Alice annonce son engagement t.", "`convoquer alice` puis `prouver`."];
    if (s.c == null) return ["Tu as reçu t. Choisis un défi c entre 0 et 10.", "`defi 4` (n'importe quel c entre 0 et 10)."];
    return [`Calcule avec \`calc\` les deux côtés de l'égalité g^s = t · y^c, puis envoie-les.`, `\`calc ${GEN}^${s.s} mod ${P}\` et \`calc ${s.t}*${Y}^${s.c} mod ${P}\` (le produit se fait en deux temps si besoin : \`calc ${Y}^${s.c} mod ${P}\` puis multiplier par ${s.t} modulo ${P}), puis \`verifier ‹a› ‹b›\`.`];
  };
  const hints = {
    quest: () => ["Maître Ada t'attend sur la place.", "`parler ada`"],
    c1: () => ["Va à la caverne (nord de la place) et demande à Alice de ressortir par un côté de ton choix, plusieurs fois de suite.", "`aller nord`, puis répète `demander gauche` et `demander droite` (alterne) jusqu'à 6 tours réussis."],
    c2: () => ["Mallory ne connaît pas le mot. Convoque-la, et teste-la tour après tour jusqu'à la démasquer.", "`convoquer mallory` puis `demander gauche` / `demander droite`, plusieurs fois."],
    proba: () => ["Alice te pose une question : combien de tours pour passer sous une chance sur mille ? Tu as `calc 2^‹n›`.", "`calc 2^10` donne 1024. Réponds avec `dire 10`."],
    props: () => ["Maître Ada a sûrement quelque chose à t'expliquer.", "`aller sud` puis `parler ada`."],
    cab1: () => ["Va voir Ève dans sa cabine (est de la place) : elle a filmé ta preuve. Mallory peut-elle en fabriquer un faux ?", "`aller est`, `examiner film`, puis `scenario G D G D D G` (6 tours)."],
    cab2: () => ["Deux films sont projetés : l'un est la vraie preuve, l'autre le faux. Devine, puis lis la réponse.", "`dire 1` ou `dire 2`."],
    a0: () => ["L'atelier est à l'ouest de la place. Commence par lire l'ardoise.", "`aller sud`/`aller est` jusqu'à la place, `aller ouest`, `examiner ardoise`."],
    a1: () => F().ses && !F().ses.done ? sesHint() : ["Joue un tour de Schnorr complet avec Alice : engagement, défi, réponse, puis vérifie toi-même avec `calc`.", "`convoquer alice`, `prouver`, `defi 4`, puis `verifier ‹a› ‹b›`."],
    a2: () => ["Convoque Mallory (qui ne connaît pas x) et essaie de la prendre en défaut avec des défis différents.", "`convoquer mallory`, `prouver`, `defi 3` (relance avec un autre défi jusqu'à la démasquer)."],
    a3: () => F().ses && F().ses.replay && !F().ses.done ? ["Alice a rejoué le même t. Envoie un défi différent de l'ancien.", `\`defi ‹c›\` avec c différent de ${F().last.c}.`] : ["Alice a un défaut : son générateur d'aléa se coince. Fais-lui rejouer son dernier tirage, puis donne un défi différent.", "`rejouer`, puis `defi ‹c›` (différent du précédent)."],
    a4: () => { const p = F().pair; return ["Deux équations, une seule inconnue : x se calcule. Cherche x tel que (c1−c2)·x ≡ s1−s2 (mod 11), en testant avec `calc`.", `\`calc ${((p.c1 - p.c2) % Q + Q) % Q}*‹x› mod ${Q}\` doit donner ${((p.s1 - p.s2) % Q + Q) % Q}. Puis \`dire ‹x›\`.`]; },
    f1: () => ["Le scriptorium est au nord de l'atelier. Alice y affiche une preuve sans personne en face.", "`aller nord`, `convoquer alice`, `prouver`."],
    f2: () => { const t = F().fs.t; return ["Le défi est calculé par le hachage de « g,y,t ». Utilise le Scribe-hachoir pour retrouver c.", `\`hacher ${GEN},${Y},${t}\``]; },
    f3: () => { const s = F().fs; return ["Vérifie la preuve comme dans l'atelier, avec le défi trouvé par le hachage.", `\`calc ${GEN}^${s.s} mod ${P}\`, \`calc ${s.t}*${Y}^${s.c} mod ${P}\` (en deux temps), puis \`verifier ‹a› ‹b›\`.`]; },
    f4: () => ["Laisse Mallory essayer de tricher contre ce hachage à 11 défis possibles.", "`forger`"],
    u1: () => ["La halle est au sud de la place. Essaie la connexion sans mot de passe.", "`aller sud` (depuis la place), `connecter`."],
    u2: () => ["Ève a capté la preuve : voyons si elle peut la rejouer.", "`rejouer`"],
    u3: () => ["Compare ce que révèle une carte d'identité et ce que révèle une preuve d'âge.", "`presenter carte` puis `presenter preuve`."],
    u4: () => ["Au stand, regroupe un grand nombre de transactions et regarde la taille de la preuve.", "`grouper 1000`"],
    end: () => ["Retourne voir Maître Ada pour conclure.", "`aller nord`, `parler ada`"],
    fin: () => ["Aventure terminée. Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Alice prétend connaître le mot qui ouvre la porte magique, au fond de la caverne en anneau. Bob l'achèterait, mais comment savoir qu'elle ne bluffe pas, sans qu'elle lui dise le mot ? Et il y a Ève, qui écoute tout : si le mot passe par sa bouche, il est perdu.");
          say("Maître Ada", "Il existe une réponse : une preuve à divulgation nulle de connaissance. Tu vas jouer le vérificateur. Commence par la caverne, au nord.");
          out("`aller nord`", "sys");
        } else if (x.proba && !x.props) {
          x.props = true;
          say("Maître Ada", "Retiens ces trois propriétés. La complétude : si Alice connaît vraiment le mot, elle réussit à tous les coups, tu l'as vu. La solidité : si elle ne le connaît pas, elle ne passe qu'avec une probabilité qui s'écrase d'un tour à l'autre. Et la divulgation nulle : toi, Bob, tu n'apprends rien d'autre que « elle sait ».");
          say("Maître Ada", "Cette dernière est la plus surprenante. Pour la comprendre, va voir Ève dans sa cabine, à l'est : elle a filmé ta preuve.");
          note("proprietes");
        } else if (x.end) say("Maître Ada", "Bob a payé. Alice a gardé son mot. Ève est repartie les mains vides.");
        else if (objective() === "end") ending();
        else say("Maître Ada", "Tu es en route. `indice` si tu bloques.");
        break;
      case "alice":
        if (S.room === "caverne") {
          if (x.hOk && x.caught && !x.proba) say("Alice", "Combien de tours faut-il pour que Mallory ait moins d'une chance sur mille de passer ? Calcule avec `calc 2^‹n›` et réponds `dire ‹n›`.");
          else if (!x.hOk) say("Alice", "Je connais le mot. Je ne le dirai à personne. Demande-moi de ressortir par le côté que tu veux (`demander gauche`, `demander droite`), autant de fois que tu voudras. Pour voir comment Mallory s'en sortirait, `convoquer mallory`.");
          else say("Alice", "Autant de tours que tu veux : je ressors toujours du bon côté, et tu n'apprends toujours rien du mot.");
        } else if (S.room === "atelier") say("Alice", `Mon secret est x, ma clé publique est y = ${Y}. Je ne dis rien d'autre. \`prouver\` pour commencer.`);
        else if (S.room === "scriptorium") say("Alice", "Ici, personne ne me pose de défi : c'est le hachage de ce que j'annonce qui le fixe. `prouver`.");
        else say("Alice", "On essaie mes preuves dans la vraie vie ?");
        break;
      case "bob":
        if (S.room === "cabine") say("Bob", "Ce film me montre Alice qui ressort du bon côté six fois de suite. Mais je n'y étais pas : qui me dit qu'il n'est pas truqué ?");
        else if (S.room === "halle") say("Bob", "Au comptoir, je ne demande pas ta date de naissance : je demande « majeur ou pas ». Pourquoi devrais-je tout voir ?");
        else say("Bob", "Je veux être sûr qu'Alice connaît le mot. Mais je ne veux pas qu'elle me le dise.");
        break;
      case "eve":
        if (S.room === "cabine") {
          if (!x.hOk) say("Ève", "Je n'ai encore rien filmé. Quand tu auras joué une série de tours avec Alice, reviens.");
          else say("Ève", "J'ai tout filmé, les défis de Bob et les sorties d'Alice. Je vais montrer ça à tout le monde : « voilà la preuve qu'Alice connaît le mot ». `examiner film` ; `scenario ‹G D G D D G›` si tu veux voir Mallory essayer d'en faire autant.");
        } else if (S.room === "atelier") say("Ève", "Je note tout ce qui circule : t, c, s. Les chiffres publics, je les ai déjà.");
        else say("Ève", "J'ai capté la preuve de connexion. Le serveur ne me dira pas que je ne peux pas la rejouer.");
        break;
      case "mallory":
        if (S.room === "caverne") say("Mallory", "Je n'ai pas le mot. Mais la caverne a deux côtés : une chance sur deux à chaque tour. `convoquer mallory` pour que je joue la prouveuse.");
        else if (S.room === "atelier") say("Mallory", `Je ne connais pas x, juste y = ${Y}. Je prépare un engagement t pour UN défi que j'espère deviner, et je croise les doigts.`);
        else say("Mallory", "Si le défi est calculé à partir de mon propre engagement, je peux essayer des engagements jusqu'à ce que ça tombe juste. Tout dépend de la taille de q.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- caverne ---------- */
  function convoke(c) {
    const x = F();
    if (!["caverne", "atelier", "scriptorium"].includes(S.room)) { out("Personne à convoquer ici.", "sys"); return; }
    const t = norm(c.rawArg);
    const who = /mallory|tricheuse/.test(t) ? "mallory" : /alice|prouveuse/.test(t) ? "alice" : null;
    if (!who) { out("Qui ? `convoquer alice` ou `convoquer mallory`.", "err"); return; }
    if (S.room === "scriptorium" && who === "mallory") { out("Ici, Alice prouve (`prouver`). Mallory pourra tricher avec `forger` une fois la preuve vérifiée.", "sys"); return; }
    x.who = who; x.streak = 0;
    if (x.ses && !x.ses.done) x.ses = null;
    out(who === "alice" ? "Alice s'avance. Elle connaît le mot." : "Mallory s'avance, voilée. Elle ne connaît pas le mot : elle jouera sur la chance.", "ok");
  }
  function maybeAsk() {
    const x = F();
    if (x.hOk && x.caught && !x.proba && !x.asked) { x.asked = true; say("Alice", "Combien de tours faut-il pour que Mallory ait moins d'une chance sur mille de passer ? Calcule avec `calc 2^‹n›` et réponds `dire ‹n›`."); }
  }
  function ask(c) {
    const x = F();
    if (S.room !== "caverne") { out("Les tours se jouent dans la caverne (nord de la place).", "sys"); return; }
    const call = parseSide(c.rawArg);
    if (!call) { out("Quel côté ? `demander gauche` ou `demander droite`.", "err"); return; }
    const entered = rnd() < 0.5 ? "G" : "D";
    x.rounds = (x.rounds || 0) + 1;
    if (x.who === "alice") {
      x.streak++; x.best = Math.max(x.best || 0, x.streak);
      x.hist.push(call);
      out(`Tour ${x.streak} : tu cries « ${sideName(call)} ». Alice ressort par la ${sideName(call)}.`, "ok");
      out(`Tu ne sais pas de quel côté elle est entrée (si c'était l'autre, elle a dit le mot et franchi la porte). Une tricheuse aurait passé ${x.streak === 1 ? "ce tour" : "ces " + x.streak + " tours"} avec une probabilité de 1/${Math.pow(2, x.streak)} (${pct(x.streak)}).`, "sys");
      if (x.streak >= 6 && !x.hOk) {
        x.hOk = true; x.film = x.hist.slice(-6);
        out("Six tours sans faute : complétude vérifiée (Alice honnête réussit toujours), et pourtant tu ne sais toujours pas le mot.", "ok");
        note("preuve"); fig("caverne");
        if (x.caught) maybeAsk(); else out("Maintenant, voyons ce que vaut la même épreuve pour une tricheuse : `convoquer mallory` puis `demander ...`.", "sys");
      }
    } else if (entered === call) {
      x.streak++; x.best = Math.max(x.best || 0, x.streak);
      out(`Tour ${x.streak} : tu cries « ${sideName(call)} ». Mallory ressort par la ${sideName(call)}. Elle a eu de la chance (elle était entrée de ce côté).`, "err");
      out(`Une chance sur deux à chaque tour : ${x.streak === 1 ? "ce tour" : "ces " + x.streak + " tours de suite"}, probabilité 1/${Math.pow(2, x.streak)} (${pct(x.streak)}). Continue !`, "sys");
    } else {
      const n = x.streak + 1;
      out(`Tour ${n} : tu cries « ${sideName(call)} ». Mallory était entrée par la ${sideName(entered)} : la porte la bloque, elle ne connaît pas le mot. Elle bredouille. Démasquée !`, "ok");
      out(x.streak ? `Elle avait passé ${x.streak} tour${x.streak > 1 ? "s" : ""}, ce qui arrive 1 fois sur ${Math.pow(2, x.streak)}. Plus tu demandes de tours, plus ça devient rare.` : "Elle n'avait aucune chance de passer à coup sûr : à chaque tour, une chance sur deux de se faire prendre. Plus tu demandes de tours, plus elle passe rarement.", "sys");
      x.caught = true; x.streak = 0;
      maybeAsk();
    }
  }

  function sayCmd(txt, c) {
    const x = F();
    const arg = (c && c.rawArg) || txt || "";
    const n = nums(arg)[0];
    if (S.room === "caverne" && x.hOk && x.caught && !x.proba) {
      if (n === undefined) { say("Alice", "Un nombre de tours, par exemple `dire 5`."); return; }
      if (n === 10) { x.proba = true; say("Alice", "Dix tours : 2^10 = 1024, soit moins d'une chance sur mille. Et vingt tours : plus d'un million."); out("À chaque tour, la probabilité de tricher est divisée par deux : 2^-n.", "ok"); note("proba"); fig("proba"); out("Maître Ada voudrait te voir (`aller sud`, `parler ada`).", "sys"); }
      else if (n < 10) say("Alice", `2^${n} = ${Math.pow(2, n)} : 1 chance sur ${Math.pow(2, n)}, c'est encore plus d'une sur mille. Il faut plus de tours.`);
      else say("Alice", `Ça suffit, mais c'est plus que nécessaire. Cherche le plus petit n : 2^9 = 512 (trop peu), 2^10 = 1024.`);
      return;
    }
    if (S.room === "cabine" && x.cmp && !x.guessed) {
      if (n !== 1 && n !== 2) { say("Ève", "Quel film est le vrai ? `dire 1` ou `dire 2`."); return; }
      x.guessed = true;
      const win = n === x.cmp.real;
      out(win ? `Bonne réponse : le vrai film était le n° ${x.cmp.real}. Mais c'était de la chance, pas de la lecture.` : `Raté : le vrai film était le n° ${x.cmp.real}. Tu n'avais aucun moyen de le savoir.`, win ? "ok" : "err");
      out("Les deux films ont exactement la même forme : des défis, des sorties, toujours « sortie = défi ». Mallory, qui ne connaît pas le mot, a monté le sien en sachant à l'avance les défis : elle s'est placée du bon côté à chaque fois. Ève peut projeter n'importe lequel : il ne prouve rien à Bob, qui n'a pas lancé les défis lui-même.", "ok");
      say("Bob", "Je ne vois aucune différence : ce film ne vaut rien pour moi. Je ne croirais Alice qu'en lui posant mes propres défis, au hasard, en direct.");
      out("Et c'est ça, la divulgation nulle : tout ce que tu as vu, tu aurais pu le fabriquer toi-même sans le secret. Donc tu n'as rien appris.", "ok");
      note("simulateur"); fig("simulateur");
      out("Prochaine étape : l'atelier des calculs, à l'ouest de la place, pour le vrai protocole.", "sys");
      return;
    }
    if (S.room === "atelier" && x.pair && !x.rev) {
      if (n === undefined) { out("Un nombre : `dire ‹x›`.", "err"); return; }
      const p = x.pair;
      if (n === X) {
        x.rev = true;
        out(`x = ${n} : on vérifie g^x = ${GEN}^${n} mod ${P} = ${pw(GEN, n)} = y. C'est bien le secret d'Alice, retrouvé par Ève à partir de deux preuves publiques.`, "err");
        say("Alice", "Mon secret… Ma preuve ne valait plus rien dès que j'ai réutilisé r.");
        out("Un r réutilisé et le secret est perdu : r doit être neuf à chaque preuve (ou dérivé de façon sûre).", "ok");
        note("aleas");
        out("Direction le scriptorium (`aller nord`) : comment se passer de Bob ?", "sys");
      } else {
        out(`Test : ${((p.c1 - p.c2) % Q + Q) % Q} × ${n} mod ${Q} = ${(((p.c1 - p.c2) % Q + Q) % Q) * n % Q}, et il faudrait ${((p.s1 - p.s2) % Q + Q) % Q} (c'est s1−s2 mod ${Q}). Ce n'est pas x. Essaie un autre candidat avec \`calc\`.`, "err");
      }
      return;
    }
    out(arg ? "Personne ne réagit." : "Dire quoi ?", "sys");
  }

  /* ---------- cabine : simulateur ---------- */
  const filmText = arr => arr.map((s, i) => `tour ${i + 1} : défi ${sideName(s).padEnd(7)} -> sortie ${sideName(s)}`).join("\n");
  function script(c) {
    const x = F();
    if (S.room !== "cabine") { out("Le montage se fait dans la cabine d'Ève (est de la place).", "sys"); return; }
    if (!x.film) { out("Il n'y a pas encore de film : fais d'abord ta preuve dans la caverne.", "err"); return; }
    let t = norm(c.rawArg).split(" ").filter(Boolean);
    if (t.length === 1 && /^[gd]+$/.test(t[0])) t = t[0].split("");
    const arr = t.map(w => parseSide(w)).filter(Boolean);
    if (arr.length !== 6 || arr.length !== t.length) { out("Écris un scénario de 6 tours, avec G ou D : `scenario G D G D D G`.", "err"); return; }
    x.film2 = arr;
    x.cmp = { real: rnd() < 0.5 ? 1 : 2 }; x.guessed = false;
    out("Mallory, qui n'a pas le mot, lit ton scénario à l'avance : à chaque tour elle entre directement du côté que tu vas crier. Elle ressort donc toujours bien, sans jamais ouvrir la porte. Ève projette les deux films dans un ordre qu'elle mélange :", "sys");
    const a = x.cmp.real === 1 ? x.film : arr, b = x.cmp.real === 1 ? arr : x.film;
    out("Film 1", "title"); code(filmText(a));
    out("Film 2", "title"); code(filmText(b));
    out("L'un est la vraie preuve d'Alice (tes propres défis), l'autre est le faux de Mallory. Lequel est le vrai ? `dire 1` ou `dire 2`.", "sys");
  }

  /* ---------- atelier : Schnorr ---------- */
  function convFail(txt) { out(txt, "err"); }
  function prove(c) {
    const x = F();
    if (S.room === "scriptorium") return fsProve();
    if (S.room !== "atelier") { out(S.room === "halle" ? "Ici, c'est `connecter` qui lance la preuve." : "Le protocole se joue à l'atelier (ouest de la place).", "sys"); return; }
    if (!x.sawParams) { out("Regarde d'abord l'ardoise : `examiner ardoise`.", "sys"); return; }
    if (x.ses && !x.ses.done) { out(x.ses.c == null ? "Tu as déjà son engagement t. Envoie ton défi : `defi ‹c›`." : "Termine d'abord ce tour : `verifier ‹a› ‹b›`.", "sys"); return; }
    if (x.who === "mallory") {
      const cg = rint(0, Q - 1), sg = rint(0, Q - 1);
      const t = (pw(GEN, sg) * pw(Y, (Q - cg) % Q)) % P;
      x.ses = { who: "mallory", t, cg, sg, c: null, s: null, done: false };
      out(`Mallory annonce son engagement : t = **${t}**.`, "ok");
      out("Elle ne connaît pas x. Comment a-t-elle fabriqué ce t ? Tu le verras.", "sys");
    } else {
      const r = rint(1, Q - 1), t = pw(GEN, r);
      x.ses = { who: "alice", r, t, c: null, s: null, done: false };
      out(`Alice choisit un r secret et annonce son engagement : t = g^r mod p = **${t}**. (Elle ne dit pas r.)`, "ok");
    }
    out(`Envoie ton défi (un nombre de 0 à ${Q - 1}) : \`defi ‹c›\`.`, "sys");
  }
  function challenge(c) {
    const x = F();
    if (S.room === "scriptorium") { out("Ici, personne ne lance de défi : c'est le hachage qui joue Bob (`hacher`).", "sys"); return; }
    if (S.room !== "atelier") { out("Les défis se lancent à l'atelier (ouest de la place).", "sys"); return; }
    const s = x.ses;
    if (!s || s.done) { out("Il faut d'abord un engagement : `prouver`.", "err"); return; }
    if (s.c != null) { out("Ce tour a déjà son défi. `verifier ‹a› ‹b›`, ou relance une preuve avec `prouver`.", "sys"); return; }
    const n = nums(c.rawArg)[0];
    if (n === undefined || n < 0 || n > Q - 1) { out(`Le défi est un nombre de 0 à ${Q - 1} : \`defi 4\`.`, "err"); return; }
    if (s.replay && n === x.last.c) { out(`C'est le même défi que la première fois (${n}) : la même réponse, donc rien de neuf. Choisis-en un autre.`, "err"); return; }
    s.c = n;
    if (s.who === "alice") {
      s.s = (s.r + n * X) % Q;
      out(`Alice répond avec s = r + c·x mod q = **${s.s}**.`, "ok");
      if (s.replay) {
        x.pair = { t: s.t, c1: x.last.c, s1: x.last.s, c2: n, s2: s.s }; s.done = true;
        const dS = ((x.last.s - s.s) % Q + Q) % Q, dC = ((x.last.c - n) % Q + Q) % Q;
        out("Ève, sous la table, a noté deux preuves qui partagent le même t :", "sys");
        code(`preuve 1 : t = ${s.t}, c1 = ${x.last.c}, s1 = ${x.last.s}\npreuve 2 : t = ${s.t}, c2 = ${n}, s2 = ${s.s}`);
        out(`Soustrais : s1 − s2 ≡ (c1 − c2)·x (mod ${Q}). r a disparu ! Ici : ${dS} ≡ ${dC}·x (mod ${Q}). Retrouve x avec \`calc ${dC}*‹x› mod ${Q}\` (essaie des valeurs), puis \`dire ‹x›\`.`, "ok");
        return;
      }
      out(`Vérifie comme Bob : g^s ≡ t · y^c (mod p) ? Calcule g^s mod p avec \`calc ${GEN}^${s.s} mod ${P}\`, puis t · y^c mod p (\`calc ${Y}^${n} mod ${P}\`, multiplie par ${s.t}, réduis modulo ${P}). Puis \`verifier ‹a› ‹b›\`.`, "sys");
    } else if (n === s.cg) {
      s.s = s.sg;
      out(`Mallory répond s = **${s.s}**. (Elle avait deviné le défi !)`, "err");
      out("Vérifie comme Bob : `calc` les deux côtés, puis `verifier ‹a› ‹b›`.", "sys");
    } else {
      s.done = true; x.mCaught = true;
      out(`Mallory bredouille : elle n'a pas de réponse. Son engagement t = ${s.t} avait été fabriqué pour le défi ${s.cg} (en choisissant s = ${s.sg} puis t = g^s · y^−${s.cg}), pas pour ${n}. Sans x, elle ne sait répondre qu'à UN seul défi, qu'elle devait deviner avant de t'annoncer t : 1 chance sur ${Q}.`, "ok");
      out(`Mais si tu avais demandé ${s.cg}, elle passait : Bob n'aurait rien vu. C'est la solidité de Schnorr : un défi de 0 à ${Q - 1}, soit 1/${Q} d'erreur, à répéter (ou à agrandir : avec q de 256 bits, 1 chance sur 2^256).`, "sys");
      out("Autre point : elle n'a jamais eu besoin de r ni de x pour fabriquer cette paire (t, s) quand le défi est connu d'avance : c'est le simulateur de Schnorr.", "sys");
    }
  }
  function badv(msg) { const x = F(); x.badv = (x.badv || 0) + 1; return x.badv; }
  function check(c) {
    const x = F();
    const nn = nums(c.rawArg);
    if (!nn.length) { const id = resolve(c.target); if (id) { if (G_ents()[id].onExamine) G_ents()[id].onExamine(); out(G_ents()[id].desc()); } return; }
    if (S.room === "scriptorium") {
      const s = x.fs;
      if (!s) { out("Il n'y a pas de preuve affichée : `prouver` (Alice).", "sys"); return; }
      if (!x.hashedT) { out("Tu ne connais pas encore le défi c : le Scribe le calcule. `hacher ‹g,y,t›`.", "sys"); return; }
      return verifyCore(nn, s.t, s.c, s.s, "fs");
    }
    if (S.room !== "atelier") { out("La vérification se fait à l'atelier ou au scriptorium.", "sys"); return; }
    const s = x.ses;
    if (!s || s.s == null || s.done) { out("Aucune réponse à vérifier : `prouver`, puis `defi ‹c›`.", "sys"); return; }
    verifyCore(nn, s.t, s.c, s.s, "ses");
  }
  const G_ents = () => ents;
  function verifyCore(nn, t, c, s, kind) {
    const x = F();
    if (nn.length < 2) { out("Donne les deux nombres : `verifier ‹g^s mod p› ‹t·y^c mod p›`.", "err"); return; }
    const L = pw(GEN, s), Rr = (t * ymul(c)) % P;
    if (nn[0] !== L || nn[1] !== Rr) {
      const k = badv();
      const ws = [];
      if (nn[0] !== L) ws.push(`g^s mod p (${GEN}^${s} mod ${P})`);
      if (nn[1] !== Rr) ws.push(`t · y^c mod p (${t} · ${Y}^${c} mod ${P})`);
      out(`Ton calcul de ${ws.join(" et de ")} ne tombe pas juste. Recalcule avec \`calc\`${k >= 3 ? ` (pour t'aider : ${nn[0] !== L ? "g^s mod p = " + L : ""}${nn[0] !== L && nn[1] !== Rr ? " ; " : ""}${nn[1] !== Rr ? "t · y^c mod p = " + Rr : ""})` : ""}.`, "err");
      return;
    }
    const ses = x.ses;
    out(`g^s mod p = ${GEN}^${s} mod ${P} = ${L} ; t · y^c mod p = ${t} · ${Y}^${c} mod ${P} = ${Rr}.`, "ok");
    out(`Les deux côtés sont égaux : la preuve est **acceptée**. (Pourquoi : g^s = g^(r + c·x) = g^r · (g^x)^c = t · y^c.)`, "ok");
    if (kind === "fs") {
      if (!x.fsOk) { x.fsOk = true; out("Alice t'a convaincu sans aucune interaction : n'importe qui peut refaire ce calcul.", "ok"); fig("fiatshamir"); out("Reste une question : et si Mallory essayait de tricher contre le hachage ? `forger`.", "sys"); }
      return;
    }
    ses.done = true;
    if (ses.who === "alice") {
      x.last = { r: ses.r, t: ses.t, c: ses.c, s: ses.s };
      if (!x.schnorrOk) { x.schnorrOk = true; note("schnorr"); fig("schnorr"); out("Tu as vu t, c, s, les nombres publics, et tu n'as rien appris sur x. (Pourtant, Alice a répondu juste : elle connaît x.) Et Mallory ? `convoquer mallory`.", "ok"); }
    } else {
      out(`Bob accepte, à tort : Mallory a eu de la chance (1 sur ${Q}, elle avait deviné ton défi). Relance un tour (\`prouver\`, \`defi ‹c›\`) avec un autre défi.`, "err");
    }
  }
  function replay() {
    const x = F();
    if (S.room === "halle") {
      if (!x.login) { out("Connecte d'abord Alice : `connecter`.", "sys"); return; }
      if (x.replayFail) { out("Ève a déjà essayé : sans succès.", "sys"); return; }
      const lg = x.login;
      let sid = 2, c2 = hc(lg.t, "session-" + sid);
      while (c2 === lg.c) { sid++; c2 = hc(lg.t, "session-" + sid); }
      const L = pw(GEN, lg.s), Rr = (lg.t * ymul(c2)) % P;
      out(`Ève ouvre une nouvelle session (session-${sid}) et rejoue la preuve captée : t = ${lg.t}, s = ${lg.s}.`, "sys");
      out(`Le serveur calcule le défi de CETTE session : c = H(g,y,t,session-${sid}) mod ${Q} = ${c2} (la preuve valait pour c = ${lg.c}). g^s mod p = ${L} ; t · y^c mod p = ${Rr}. Différents : **connexion refusée**.`, "ok");
      out(`Parce que le contexte de la session est inclus dans le hachage, une preuve ne vaut que pour une session. (Avec q = ${Q}, un rejeu passerait 1 fois sur ${Q} ; avec un vrai q, jamais en pratique.)`, "sys");
      x.replayFail = true; checkUsages();
      return;
    }
    if (S.room !== "atelier") { out("Il n'y a rien à rejouer ici.", "sys"); return; }
    if (!x.schnorrOk || !x.mCaught) { out("Pas encore : termine d'abord un tour d'Alice et démasque Mallory.", "sys"); return; }
    x.who = "alice";
    x.ses = { who: "alice", r: x.last.r, t: x.last.t, c: null, s: null, done: false, replay: true };
    out(`Alice, épuisée, relance une preuve. Défaut : son générateur d'aléa est coincé, elle ressort le même r qu'avant. Son engagement : t = **${x.ses.t}**, exactement le même que tout à l'heure (${x.last.t}).`, "err");
    out(`Choisis un défi DIFFÉRENT de ${x.last.c} : \`defi ‹c›\`.`, "sys");
  }

  /* ---------- scriptorium : Fiat-Shamir ---------- */
  function fsProve() {
    const x = F();
    if (x.fs) { out("La preuve d'Alice est déjà affichée. Utilise `hacher`, puis `verifier`.", "sys"); return; }
    let r, t, c;
    do { r = rint(1, Q - 1); t = pw(GEN, r); c = hc(t); } while (c === 0);
    const s = (r + c * X) % Q;
    x.fs = { r, t, c, s };
    out(`Alice calcule en silence : t = g^r mod p, puis c = H(g, y, t) mod q, puis s = r + c·x mod q. Elle n'affiche que la preuve : **(t, s) = (${t}, ${s})**.`, "ok");
    out("Tu ne connais pas c : à toi de le recalculer comme le ferait n'importe quel vérificateur. `hacher ‹g,y,t›`.", "sys");
  }
  function hashCmd(c) {
    const x = F();
    if (S.room !== "scriptorium") { out("Le Scribe-hachoir est au scriptorium (nord de l'atelier).", "sys"); return; }
    const text = c.rawArg;
    if (!text) { out("Que hacher ? `hacher 2,13,‹t›`.", "err"); return; }
    const h = sha256(text), v = parseInt(h.slice(0, 8), 16);
    code(`SHA-256("${text}")\n= ${h}`);
    out(`8 premiers chiffres : 0x${h.slice(0, 8)} = ${v} ; ${v} mod ${Q} = **${v % Q}**.`, "ok");
    if (x.fs && text.replace(/\s/g, "") === `${GEN},${Y},${x.fs.t}`) {
      x.hashedT = true;
      out(`C'est le défi de la preuve d'Alice : c = ${x.fs.c}. Comme t est figé avant le hachage, Alice ne pouvait pas choisir t après avoir vu c. Vérifie la preuve : \`verifier ‹a› ‹b›\`.`, "ok");
    } else if (x.fs) out(`Ce n'est pas l'entrée du défi d'Alice. Le défi se calcule sur « g,y,t » avec ses valeurs : g = ${GEN}, y = ${Y}, t = ${x.fs.t}. (L'avalanche : une virgule ou un chiffre de plus et tout change.)`, "sys");
    else out("Pas de preuve à contrôler pour l'instant : `prouver`.", "sys");
  }
  function forge() {
    const x = F();
    if (S.room !== "scriptorium") { out("La forgerie se joue au scriptorium.", "sys"); return; }
    if (!x.fsOk) { out("Vérifie d'abord la preuve d'Alice (`verifier ‹a› ‹b›`).", "sys"); return; }
    if (x.forged) { out(`Mallory a déjà forgé un faux en ${x.forged} essais.`, "sys"); return; }
    out("Mallory ne connaît pas x. Elle choisit un défi espéré c' et un s' au hasard, calcule t = g^s' · y^−c', puis hache pour voir si le défi tombe sur c' :", "sys");
    let n = 0, found = null;
    const shown = [];
    while (!found && n < 5000) {
      n++;
      const cp = rint(0, Q - 1), sp = rint(0, Q - 1);
      const t = (pw(GEN, sp) * pw(Y, (Q - cp) % Q)) % P;
      const ch = hc(t);
      if (shown.length < 4) shown.push(`essai ${n} : c' = ${cp}, s' = ${sp}, t = ${t}, H mod ${Q} = ${ch}${ch === cp ? "  <- gagné" : ""}`);
      if (ch === cp) found = { cp, sp, t };
    }
    code(shown.join("\n") + (n > shown.length ? `\n… (${n} essais en tout)` : ""));
    if (!found) { out("Rien trouvé cette fois (malchance) : relance.", "sys"); return; }
    x.forged = n; x.forgedProof = found;
    const L = pw(GEN, found.sp), Rr = (found.t * ymul(found.cp)) % P;
    out(`Mallory sort un faux : (t, s) = (${found.t}, ${found.sp}), en seulement **${n} essais**. Vérification : g^s mod p = ${L} ; t · y^c mod p = ${Rr}. Le vérificateur accepte, et elle n'a jamais connu x.`, "err");
    out(`Le défi ne prend que ${Q} valeurs : une dizaine d'essais suffit. Voilà pourquoi q doit être énorme : avec q de 256 bits, il faudrait environ 2^256 essais, soit un nombre à 77 chiffres. Il faut aussi hacher toute la déclaration (g, y, t, et le contexte).`, "ok");
    note("fiatshamir"); fig("fiatshamir");
    out("Direction la halle des usages : retour à l'atelier (`aller sud`), la place (`aller est`) puis `aller sud`.", "sys");
  }

  /* ---------- halle : usages ---------- */
  function connect() {
    const x = F();
    if (S.room !== "halle") { out("Le guichet est dans la halle (sud de la place).", "sys"); return; }
    if (x.login) { out("Alice est déjà connectée. `rejouer` laisse Ève tenter son rejeu.", "sys"); return; }
    let r, t, c;
    do { r = rint(1, Q - 1); t = pw(GEN, r); c = hc(t, "session-1"); } while (c === 0);
    const s = (r + c * X) % Q;
    x.login = { t, c, s };
    out("Alice se connecte. Le serveur ne contient aucun mot de passe :", "sys");
    code(`compte alice : y = ${Y}\n(aucun secret stocké)`);
    out(`Alice envoie la preuve (t, s) = (${t}, ${s}), produite avec c = H(g,y,t,session-1) mod ${Q} = ${c}. Le serveur recalcule c, vérifie g^s = t · y^c : **accepté**.`, "ok");
    out("Si Mallory vole la base du serveur, elle n'y trouve que y : ce n'est pas un secret. Et Ève a capté (t, s) : peut-elle s'en servir ? `rejouer`.", "sys");
  }
  function present(c) {
    const x = F();
    if (S.room !== "halle") { out("Le comptoir du videur est dans la halle (sud de la place).", "sys"); return; }
    const t = norm(c.rawArg);
    if (/carte|identite/.test(t)) {
      x.ageCard = true;
      out("Tu présentes ta carte d'identité (données fictives) :", "sys");
      code("nom       : Alice Martin\nné(e) le  : 14/03/2001\nadresse   : 12 quai des Hachures, Port-443\nn° carte  : 7741-PC-2203");
      out("Le videur apprend tout, alors qu'il voulait une seule information : majeur ou non. Et il peut copier la carte.", "err");
    } else if (/preuve|age|zk/.test(t)) {
      x.ageProof = true;
      out("Tu présentes une preuve d'âge à divulgation nulle (le jeu simule ce que verrait Bob) :", "sys");
      code("majeur (>= 18 ans) : OUI\npreuve              : " + sha256("preuve-age-demo").slice(0, 32) + "...\n(nom, date, adresse : rien)");
      out("Le vérificateur apprend « majeur : oui » et rien d'autre. Derrière : une attestation signée (« né avant telle date ») et une preuve que tu en possèdes une, sans la montrer. Même idée pour « solde ≥ seuil ».", "ok");
    } else { out("Que présenter ? `presenter carte` ou `presenter preuve`.", "err"); return; }
    checkUsages();
  }
  function group(c) {
    const x = F();
    if (S.room !== "halle") { out("Le stand est dans la halle (sud de la place).", "sys"); return; }
    const n = nums(c.rawArg)[0];
    if (n === undefined || n < 2 || n > 5000) { out("Combien de transactions ? `grouper 1000` (de 2 à 5000).", "err"); return; }
    const naive = n * 100, rollup = 300 + 32;
    out(`${n} transactions regroupées :`, "sys");
    code(`sans preuve : ${n} x 100 octets = ${naive} octets à publier et à rejouer\navec preuve : un état (32 octets) + une preuve (~300 octets) = ${rollup} octets\nrapport    : environ x${Math.round(naive / rollup * 10) / 10}`);
    out("Le vérificateur ne refait pas les calculs : il contrôle la preuve (rapide, de coût presque constant). Mais le prouveur, lui, doit travailler beaucoup plus que pour exécuter les transactions simplement. (Ordres de grandeur illustratifs.)", "ok");
    x.rollup = true; checkUsages();
  }
  function checkUsages() {
    const x = F();
    if (x.usages || !(x.login && x.replayFail && x.ageCard && x.ageProof && x.rollup)) return;
    x.usages = true; note("usages");
    out("Authentification, preuve d'âge, rollups : trois usages d'une même idée. Retourne voir Maître Ada.", "sys");
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Alice a prouvé à Bob qu'elle connaît le mot : tour après tour, défi après défi, sans le prononcer. Bob a payé. Ève a un film sans valeur et des chiffres qui ne disent rien. Mallory a compris qu'on ne triche pas contre un défi qu'on ne peut pas prévoir.");
    say("Maître Ada", "N'oublie pas les limites : une configuration de confiance à protéger, des preuves coûteuses à produire, et surtout des implémentations qui se trompent là où on ne les attend pas.");
    note("limites");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La caverne en anneau et la porte magique = le problème de la « caverne d'Ali Baba » (Quisquater et al., 1989).** Le mot est le secret ; le côté demandé est le défi ; le côté de sortie est la réponse. À chaque tour, une tricheuse a une chance sur deux : après n tours, 2^-n.");
    out("**Alice, Bob, Ève = prouveur, vérificateur, observateur.** Complétude : Alice honnête passe toujours. Solidité : Mallory ne passe qu'avec probabilité 2^-n. Divulgation nulle : le vérificateur n'apprend rien, et Ève, qui regarde, non plus.");
    out("**Le film d'Ève = la transcription.** Mallory a pu monter un film indiscernable en connaissant les défis à l'avance : c'est l'argument du simulateur. Il montre que la transcription ne contient pas le secret, et qu'elle ne convainc que celui qui a posé les défis en direct.");
    out(`**L'atelier = le protocole de Schnorr.** p = ${P}, q = ${Q}, g = ${GEN}, y = g^x mod p. Engagement t = g^r, défi c, réponse s = r + c·x mod q, vérification g^s ≡ t · y^c (mod p). Mallory ne peut préparer sa réponse que pour un défi deviné (1/q). Deux réponses avec le même r donnent x : r doit être neuf.`);
    out("**Le scriptorium = Fiat-Shamir.** Le défi devient c = H(g, y, t), avec un vrai SHA-256. La preuve est un simple couple (t, s), vérifiable par tous, sans interaction. La sécurité repose sur un espace de défis immense et un hachage de toute la déclaration.");
    out("**La halle = les usages.** Connexion par preuve de connaissance d'un secret (le serveur ne stocke que y, le contexte de session empêche le rejeu), preuves d'âge ou de solvabilité sans divulguer la donnée, zk-rollups (une preuve courte atteste un lot de transactions).");
    out("**Les simplifications du jeu.** (1) Des nombres minuscules (p = 23) : un vrai groupe compte 256 bits, et q = 11 n'offre aucune sécurité. (2) Le hasard du jeu est reproductible (graine fixe), ce qui rend la partie rejouable, pas sûre. (3) Schnorr n'est à divulgation nulle que face à un vérificateur honnête ; avec Fiat-Shamir, la sécurité est prouvée dans le « modèle de l'oracle aléatoire ». (4) Les preuves d'âge, de solvabilité et les rollups reposent sur des systèmes plus complexes (zk-SNARK, zk-STARK, signatures anonymes) : les tailles et les coûts donnés ne sont que des ordres de grandeur. (5) Les cas d'usage supposent des clés, des attestations et des circuits bien conçus, que le jeu ne montre pas.");
    out("Rappel utile : **une preuve à divulgation nulle ne prouve pas qu'un secret existe : elle prouve qu'on le connaît, sans le dire, avec une probabilité d'erreur aussi petite qu'on veut, à condition de l'aléa neuf, d'un espace de défis énorme et d'une implémentation soignée.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    caverne: () => {
      const x = F(), n = x.streak || x.best || 0;
      return {
        cap: "La caverne : une seule entrée, deux côtés, une porte au fond. Bob crie un côté ; seule Alice, qui sait le mot, peut toujours ressortir par celui-là.",
        svg: SVG(270, "Plan de la caverne en anneau",
          `<rect x="95" y="45" width="230" height="130" rx="46" class="f-box f-pub"/><rect x="143" y="87" width="134" height="46" rx="16" class="f-box"/>` +
          LN(210, 45, 210, 87, "f-bad") + `<rect x="203" y="45" width="14" height="42" fill="var(--bad)"/>` + T(210, 34, "porte magique", "f-s ft-bad") +
          T(119, 112, "G", "f-b ft-pub") + T(301, 112, "D", "f-b ft-pub") + T(84, 112, "gauche", "f-s", "end") + T(336, 112, "droite", "f-s", "start") +
          `<path d="M210,175 L119,160 L119,66 L210,66" class="f-ln f-dash"/>` +
          AR(210, 232, 210, 177, "f-pub") + T(210, 247, "entrée : Bob attend ici", "f-s") +
          T(210, 148, "Ève écoute", "f-s ft-bad") +
          T(8, 264, n ? `${n} tour${n > 1 ? "s" : ""} de suite : une tricheuse passe avec une probabilité de 1/${Math.pow(2, n)}` : "aucun tour joué pour l'instant", "f-s", "start"))
      };
    },
    proba: () => {
      const x = F(), cur = x.best || 0;
      let b = "";
      for (let i = 1; i <= 10; i++) {
        const h = Math.max(0.6, 130 * Math.pow(2, 1 - i)), xx = 20 + (i - 1) * 39;
        b += `<rect x="${xx}" y="${168 - h}" width="28" height="${h}" rx="3" fill="var(--${i <= cur ? "ok" : "bad"})"/>` + T(xx + 14, 184, String(i), "f-s");
        if ([1, 2, 3, 5, 10].includes(i)) b += T(xx + 14, 168 - h - 5, "1/" + Math.pow(2, i), "f-s");
      }
      return {
        cap: "Chance qu'une tricheuse passe n tours de suite : 1/2^n. Elle s'effondre : dix tours suffisent à passer sous une chance sur mille.",
        svg: SVG(222, "Probabilité de triche selon le nombre de tours",
          T(210, 16, "probabilité de triche après n tours", "f-b") + b + LN(14, 168, 410, 168) + T(210, 205, "n (nombre de tours réussis)", "f-s") + T(8, 220, cur ? `en vert : tes ${cur} tours réussis` : "", "f-s", "start"))
      };
    },
    simulateur: () => {
      const x = F();
      const real = x.film || ["G", "D", "G", "D", "D", "G"], fake = x.film2 || ["D", "G", "D", "G", "G", "D"];
      const col = (arr, x0, cl) => arr.map((s, i) => T(x0, 66 + i * 17, `${i + 1} : défi ${s} -> sortie ${s}`, cl + " f-s", "start")).join("");
      return {
        cap: "Deux films de la même forme : l'un est une vraie preuve, l'autre est monté par Mallory qui connaissait les défis à l'avance. On ne peut pas les distinguer : un film ne prouve rien à un tiers.",
        svg: SVG(190, "Film réel et film simulé",
          R(8, 22, 196, 118, "f-ok") + T(106, 42, "film réel (Alice sait)", "f-b ft-ok") + col(real, 22, "") +
          R(216, 22, 196, 118, "f-bad") + T(314, 42, "film monté (Mallory)", "f-b ft-bad") + col(fake, 230, "") +
          T(210, 166, "même forme, mêmes statistiques : indiscernables", "f-b") + T(210, 182, "Mallory ne connaît pas le mot", "f-s"))
      };
    },
    schnorr: () => {
      const x = F(), l = x.last;
      return {
        cap: "Schnorr en trois messages : engagement, défi, réponse. Bob vérifie g^s = t · y^c sans jamais voir x ni r.",
        svg: SVG(250, "Protocole de Schnorr",
          R(8, 28, 124, 170, "f-priv") + T(70, 46, "Alice", "f-b ft-priv") + T(70, 66, "secret x", "f-s") + T(70, 82, "r aléatoire", "f-s") +
          R(288, 28, 124, 170, "f-pub") + T(350, 46, "Bob", "f-b ft-pub") + T(350, 66, "choisit c", "f-s") + T(350, 82, "vérifie :", "f-s") + T(350, 98, "g^s = t·y^c", "f-s") +
          T(210, 64, "t = g^r mod p", "f-s") + AR(136, 70, 284, 70) + T(210, 100, l ? `t = ${l.t}` : "1. engagement", "f-s ft-priv") +
          T(210, 118, "défi c", "f-s") + AR(284, 124, 136, 124) + T(210, 144, l ? `c = ${l.c}` : "2. défi", "f-s ft-pub") +
          T(210, 162, "s = r + c·x mod q", "f-s") + AR(136, 168, 284, 168) + T(210, 188, l ? `s = ${l.s}` : "3. réponse", "f-s ft-priv") +
          T(210, 222, `p = ${P}, q = ${Q}, g = ${GEN}, y = g^x = ${Y}`, "f-s") + T(210, 240, "public : p, q, g, y, t, c, s", "f-s"))
      };
    },
    fiatshamir: () => {
      const x = F(), s = x.fs;
      return {
        cap: "Fiat-Shamir : le défi est c = H(g, y, t). Alice envoie un seul message (t, s) que tout le monde peut vérifier. Avec q = 11, un faux se broie en une dizaine d'essais ; avec q de 256 bits, c'est hors de portée.",
        svg: SVG(250, "Preuve non interactive Fiat-Shamir",
          R(8, 28, 190, 120, "f-priv") + T(103, 46, "Alice", "f-b ft-priv") + T(103, 66, "t = g^r mod p", "f-s") + T(103, 82, "c = H(g, y, t) mod q", "f-s") + T(103, 98, "s = r + c·x mod q", "f-s") +
          T(103, 124, s ? `t = ${s.t}, c = ${s.c}, s = ${s.s}` : "(à calculer)", "f-s ft-priv") +
          R(262, 28, 150, 120, "f-pub") + T(337, 46, "Bob (n'importe qui)", "f-b ft-pub") + T(337, 66, "recalcule c", "f-s") + T(337, 82, "= H(g, y, t)", "f-s") + T(337, 98, "g^s = t·y^c ?", "f-s") +
          AR(198, 88, 260, 88) + T(229, 80, "(t, s)", "f-s") +
          R(8, 170, 404, 62, x.forged ? "f-bad" : "") + T(210, 190, x.forged ? `Mallory forge un faux en ${x.forged} essais (q = ${Q})` : "Pas de Bob au guichet : le hachage joue son rôle", x.forged ? "f-b ft-bad" : "f-b") +
          T(210, 208, "avec q de 256 bits : environ 2^256 essais", "f-s") + T(210, 224, "hacher aussi g, y et le contexte de session", "f-s"))
      };
    },
  };

  GAMES.zkp = {
    id: "zkp", order: 20, title: "La Caverne de Port-443", pageTitle: "ZKP Quest", subtitle: "aventure textuelle · preuves à divulgation nulle de connaissance",
    blurb: "Prouve que tu connais un secret sans le dévoiler : la caverne d'Ali Baba, puis un vrai protocole de Schnorr.",
    concept: "Preuves à divulgation nulle de connaissance (zero-knowledge)",
    start: "place", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.seed = 443; x.who = "alice"; x.streak = 0; x.best = 0; x.hist = []; },
    gate(dest) {
      const x = F();
      const need = { caverne: [x.quest, "Maître Ada t'attend : `parler ada`."], cabine: [x.props, "Pas encore : Maître Ada veut d'abord te parler (`parler ada`) et tu dois avoir vu la probabilité de triche."],
        atelier: [x.guessed, "L'atelier n'ouvre qu'une fois le film d'Ève examiné (`aller est` depuis la place)."], scriptorium: [x.rev, "Le scriptorium est fermé : achève d'abord l'atelier (Schnorr, réutilisation de r)."],
        halle: [x.forged, "La halle des usages ouvre quand le scriptorium est terminé (`forger`)."] }[dest];
      if (need && !need[0]) { out(need[1], "sys"); return true; }
      return false;
    },
    refig(name) { fig(name); },
    figAlias: { caverne: ["grotte", "anneau", "plan"], proba: ["probabilite", "triche", "tours"], simulateur: ["film", "simulation"], schnorr: ["protocole", "trois"], fiatshamir: ["fiat", "shamir", "hachage", "hash"] },
    help: "Spécifiques : `demander gauche|droite` · `convoquer alice|mallory` · `scenario ‹G D G D D G›` · `prouver` · `defi ‹c›` · `verifier ‹a› ‹b›` · `rejouer` · `hacher ‹texte›` · `forger` · `connecter` · `presenter carte|preuve` · `grouper ‹n›` · `dire ‹nombre›`",
    verbs: {
      ask: { words: ["demander", "exiger", "crier"], run: ask },
      convoke: { words: ["convoquer", "appeler"], run: convoke },
      script: { words: ["scenario", "scripter", "ecrire"], run: script },
      prove: { words: ["prouver", "engager"], run: prove },
      challenge: { words: ["defi", "defier", "challenge"], run: challenge },
      check: { words: ["verifier"], run: check },
      replay: { words: ["rejouer", "rejeu"], run: replay },
      hash: { words: ["hacher", "hasher"], run: hashCmd },
      forge: { words: ["forger", "broyer", "tricher"], run: forge },
      connect: { words: ["connecter", "connexion"], run: connect },
      present: { words: ["presenter", "montrer"], run: present },
      group: { words: ["grouper", "regrouper"], run: group },
    },
    say: sayCmd,
    intro() {
      out("La Caverne de Port-443", "title");
      out("Au fond d'une caverne en anneau de Port-443 se trouve une porte magique, qui ne s'ouvre qu'à celui qui connaît le mot. Alice affirme le connaître. Bob veut bien l'acheter, mais veut d'abord être sûr qu'elle ne bluffe pas, et Alice ne veut le dire ni à Bob ni à Ève, qui écoute et filme tout ce qui se passe. Maître Ada te confie le rôle de Bob : comment se convaincre sans que le secret ne circule ? Audit autorisé : tout est simulé sur des données fictives.", "");
      out("Tu disposes d'une calculatrice de poche : `calc 2^10`, `calc 5*7 mod 11`.", "sys");
    },
  };
})();
