"use strict";
/* L'Apothicaire des Empreintes : hachage, sel, tables arc-en-ciel et hachage lent. SHA-256 réel. */
(function () {
  const F = () => f();
  const ITER = 5000;
  const USERS = [["alice", "azerty"], ["bob", "soleil"], ["carla", "soleil"], ["dave", "port443"], ["erin", "x7#Kp!2vQz9$"]];
  const LIST = ["azerty", "soleil", "port443", "password", "123456", "qwerty", "bonjour", "motdepasse", "doudou", "football", "letmein", "admin"];
  const TABLE = new Map(LIST.map(w => [sha256(w), w])); // table précalculée (« arc-en-ciel »)

  function stretch(s) { let h = sha256(s); for (let i = 1; i < ITER; i++) h = sha256(h + s); return h; }
  const saltOf = u => sha256("sel:" + u).slice(0, 8);
  function H(pw, user) {
    const x = F(), s = (x.salt ? saltOf(user) : "") + pw;
    return x.slow ? stretch(s) : sha256(s);
  }
  function rebuild() { const x = F(); x.db = {}; USERS.forEach(([u, pw]) => x.db[u] = H(pw, u)); }
  const short = h => h.slice(0, 14) + "…";
  const dbText = () => {
    const x = F();
    return USERS.map(([u]) => `${u.padEnd(6)} ${x.salt ? saltOf(u) + "$" : ""}${short(x.db[u])}`).join("\n");
  };

  const notes = {
    empreinte: ["Une empreinte (hachage)", "Une fonction de hachage transforme n'importe quel texte en une empreinte de taille fixe (64 caractères hexadécimaux pour SHA-256). Le même texte donne toujours la même empreinte, et on ne peut pas remonter de l'empreinte au texte."],
    avalanche: ["L'effet avalanche", "Modifier un seul caractère change complètement l'empreinte (environ la moitié des bits). Impossible de deviner « à peu près » le texte en regardant une empreinte proche."],
    doublons: ["Mêmes mots de passe, mêmes empreintes", "Sans sel, deux comptes avec le même mot de passe ont la même empreinte : une fuite révèle qui réutilise quoi, et casser un compte en casse tous ses jumeaux."],
    arc: ["Tables précalculées (arc-en-ciel)", "Un attaquant calcule à l'avance les empreintes des mots de passe courants, puis n'a plus qu'à chercher chaque empreinte volée dans sa table : instantané, pour tous les comptes à la fois."],
    sel: ["Le sel", "Un sel est une valeur aléatoire propre à chaque compte, ajoutée au mot de passe avant le hachage et stockée en clair. Les tables précalculées deviennent inutilisables, et deux mots de passe identiques donnent des empreintes différentes."],
    lent: ["Hacher lentement", "SHA-256 est conçu pour être rapide : des milliards d'essais par seconde sur un GPU. Pour les mots de passe, on utilise des fonctions volontairement lentes ou gourmandes en mémoire (Argon2, bcrypt, scrypt, PBKDF2) pour multiplier le coût de chaque essai."],
    entropie: ["La force d'un mot de passe", "Aucun hachage ne sauve un mot de passe courant. Ce qui compte : la longueur et l'imprévisibilité. Une phrase de passe longue, ou un mot de passe aléatoire géré par un gestionnaire, résiste même à une fuite."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, qui supervise l'analyse de la fuite." },
    apothicaire: { npc: true, names: ["apothicaire", "pharmacien"], label: "l'Apothicaire", desc: () => "L'Apothicaire, aux lunettes embuées, qui fabrique des empreintes uniques de toute substance qu'on lui apporte." },
    machine: { names: ["machine", "alambic", "appareil"], label: "l'alambic à empreintes", desc: () => "Un alambic de cuivre : tu y verses n'importe quel texte avec `hacher ‹texte›` et il en sort une empreinte SHA-256, de 64 caractères hexadécimaux." },
    livre: { names: ["livre", "base", "registre", "mots de passe", "fuite"], label: "le Livre des mots de passe volé", vis: () => S.room === "voute",
      desc: () => { F().saw = true; return "Le Livre volé à la Bibliothèque (extrait) :\n" + dbText() + "\n\n`craquer ‹nom›` pour chercher une empreinte dans la table de Mallory, `attaquer ‹nom›` pour la deviner mot à mot."; } },
    table: { names: ["table", "table precalculee", "arc en ciel"], label: "la table de Mallory", vis: () => S.room === "voute",
      desc: () => `La table de Mallory : ${LIST.length} mots de passe courants dont l'empreinte est calculée à l'avance (azerty, soleil, port443…). Chercher une empreinte dedans est instantané.` },
    grimoire: { names: ["grimoire", "procedes", "recettes"], label: "le grimoire des procédés", vis: () => S.room === "officine",
      desc: () => `Le grimoire de l'Apothicaire. Procédés de conservation des mots de passe :\n  · \`activer sel\` : ${F().salt ? "ACTIVÉ" : "désactivé"}\n  · \`activer lent\` : ${F().slow ? "ACTIVÉ (" + ITER + " itérations)" : "désactivé"}` },
    moulin: { names: ["moulin", "meule"], label: "le moulin lent", vis: () => S.room === "moulin",
      desc: () => "Un moulin à eau dont la roue tourne lentement, volontairement. Chaque tour de roue représente une itération du hachage." },
  };

  const rooms = {
    officine: { name: "L'officine de l'Apothicaire", short: "Officine", alias: ["officine"], ents: ["ada", "apothicaire", "grimoire"], exits: { nord: "labo", est: "voute", ouest: "moulin" },
      desc: () => "Fioles, balances et alambics. L'Apothicaire fait fonctionner une maison sérieuse : toute substance qu'il reçoit, il en tire une empreinte. Au nord, le laboratoire. À l'est, la voûte où est exposé le Livre volé. À l'ouest, le moulin lent." },
    labo: { name: "Le laboratoire d'empreintes", short: "Laboratoire", alias: ["labo", "laboratoire"], ents: ["machine"], exits: { sud: "officine" },
      desc: () => "Un alambic de cuivre au centre de la pièce. On y verse un texte, on en tire une empreinte." },
    voute: { name: "La voûte de la fuite", short: "Voûte", alias: ["voute", "fuite"], ents: ["livre", "table"], exits: { ouest: "officine" },
      desc: () => "Une voûte sombre où Maître Ada a fait afficher, sous scellés, le Livre des mots de passe que Mallory a volé à la Bibliothèque. Une table de pierre porte la table de Mallory." },
    moulin: { name: "Le moulin lent", short: "Moulin", alias: ["moulin"], ents: ["moulin"], exits: { est: "officine" },
      desc: () => "Une roue énorme qui tourne très lentement. Ici, rien n'est rapide, et c'est le but." },
  };

  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.det) return "det";
    if (!x.aval) return "aval";
    if (!x.saw) return "saw";
    if (Object.keys(x.cracked || {}).length < 3) return "crack";
    if (!x.salt) return "salt";
    if (!x.atkSalted) return "atk1";
    if (!x.slow) return "slow";
    if (!x.atkSlow) return "atk2";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend à l'officine.", "`parler ada`"],
    det: () => ["Va au laboratoire (nord) et fais deux fois l'empreinte du même texte. Que remarques-tu ?", "`aller nord`, `hacher bonjour`, `hacher bonjour`."],
    aval: () => ["Compare deux textes presque identiques : une seule lettre de différence.", "`hacher bonjour` puis `hacher Bonjour`."],
    saw: () => ["Direction la voûte (est de l'officine) pour examiner le Livre volé.", "`aller sud`, `aller est`, `examiner livre`."],
    crack: () => ["Cherche les empreintes du Livre dans la table de Mallory. Essaie plusieurs comptes.", "`craquer alice`, `craquer bob`, `craquer carla`…"],
    salt: () => ["Des empreintes sans sel se retrouvent par une simple recherche. L'Apothicaire peut changer de procédé.", "`aller ouest`, `activer sel` (à l'officine)."],
    atk1: () => ["Retourne à la voûte et vois si Mallory s'en sort toujours (la table ne marche plus, mais un dictionnaire ?).", "`aller est`, `craquer alice`, puis `attaquer alice`."],
    slow: () => ["Mallory essaie mot à mot : c'est encore rapide. Rends chaque essai plus coûteux.", "`aller ouest`, `activer lent` (à l'officine)."],
    atk2: () => ["Rejoue une attaque par dictionnaire et compare le temps.", "`aller est`, `attaquer alice` puis `attaquer erin`."],
    end: () => ["Rends compte à l'Apothicaire ou à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Mallory a volé le Livre des mots de passe de la Bibliothèque. Les mots de passe n'y sont pas écrits en clair : seulement leur empreinte. Mais elle les a quand même presque tous retrouvés. Ton rôle : comprendre ce qu'est une empreinte, voir comment on les casse, puis proposer un meilleur stockage.");
          say("Maître Ada", "Commence par le laboratoire, au nord : l'alambic de l'Apothicaire fabrique des empreintes. C'est du vrai SHA-256.");
          out("`aller nord` puis `hacher ‹texte›`.", "sys");
        } else if (x.end) say("Maître Ada", "La Bibliothèque a adopté le nouveau procédé. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'analyse n'est pas finie. `indice` si tu bloques.");
        break;
      case "apothicaire":
        if (!x.salt && Object.keys(x.cracked || {}).length >= 3) say("Apothicaire", "Trois comptes tombés en une seconde ? L'empreinte seule ne suffit pas : ajoute un sel, une valeur aléatoire propre à chaque compte, avant de hacher. `activer sel`.");
        else if (x.salt && !x.slow) say("Apothicaire", "Le sel a tué les tables précalculées, mais Mallory peut encore essayer les mots courants un par un, très vite. Ralentissons chaque essai : `activer lent`.");
        else say("Apothicaire", "Une empreinte, c'est comme une empreinte digitale : unique, de taille fixe, impossible à remonter. Mais si l'on te demande « et si on essayait tous les doigts possibles ? », le secret est la lenteur.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  const diffHex = (a, b) => { let n = 0; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) n++; return n; };
  function hashCmd(c) {
    const x = F();
    if (S.room !== "labo") { out("L'alambic est au laboratoire (nord de l'officine).", "sys"); return; }
    const text = c.rawArg;
    if (!text) { out("Que veux-tu hacher ? `hacher ‹texte›`", "err"); return; }
    const h = sha256(text);
    out("L'alambic distille :", "sys");
    code(`SHA-256("${text}")\n= ${h}`);
    x.hist = x.hist || [];
    const prev = x.hist.find(t => t === text);
    if (prev !== undefined) {
      if (!x.det) { x.det = true; out("Même texte, même empreinte : c'est déterministe. C'est ce qui permet de vérifier un mot de passe sans le stocker.", "ok"); note("empreinte"); fig("empreinte"); }
      else out("Même texte, même empreinte.", "sys");
    }
    for (const t of x.hist) {
      if (t === text) continue;
      const close = (t.length === text.length && [...t].filter((ch, i) => ch !== text[i]).length === 1) || t.toLowerCase() === text.toLowerCase();
      if (close) {
        const d = diffHex(sha256(t), h);
        out(`Rapproche-la de celle de « ${t} » : ${d} caractères sur 64 sont différents (≈ la moitié). Un seul caractère change tout.`, "ok");
        if (!x.aval) { x.aval = true; note("avalanche"); fig("avalanche", [t, text]); }
        break;
      }
    }
    if (!x.hist.includes(text)) x.hist.push(text);
    out(`(Taille de l'empreinte : toujours ${h.length} caractères, que le texte fasse 1 lettre ou 1 million.)`, "sys");
  }

  function crackCmd(c) {
    const x = F();
    if (S.room !== "voute") { out("La table de Mallory est dans la voûte (est de l'officine).", "sys"); return; }
    const u = norm(c.target).split(" ")[0];
    const user = USERS.find(([n]) => n === u);
    if (!user) { out("Quel compte ? alice, bob, carla, dave ou erin : `craquer alice`", "err"); return; }
    x.cracked = x.cracked || {}; x.seenPw = x.seenPw || {};
    const h = x.db[u];
    if (x.salt) {
      out(`L'empreinte de ${u} est préfixée d'un sel (${saltOf(u)}) : elle ne figure dans aucune table précalculée. La recherche ne donne rien.`, "err");
      if (!x.noteArc2) { x.noteArc2 = true; fig("sel"); }
      return;
    }
    const pw = TABLE.get(h);
    if (pw) {
      x.cracked[u] = pw;
      out(`${u} : l'empreinte est dans la table. Mot de passe : **${pw}** (recherche instantanée).`, "err");
      const twins = USERS.filter(([n]) => n !== u && x.db[n] === h).map(([n]) => n);
      if (twins.length) { out(`Même empreinte que ${twins.join(", ")} : ${twins.length > 1 ? "ils ont" : "il/elle a"} le même mot de passe ! Un seul calcul casse tous les jumeaux.`, "err"); note("doublons"); }
      if (Object.keys(x.cracked).length >= 3) { note("arc"); if (!x.shownArc) { x.shownArc = true; fig("arc"); } }
    } else out(`${u} : l'empreinte n'est pas dans la table. (Ce mot de passe n'est pas un mot courant : bon signe.)`, "ok");
  }

  function attackCmd(c) {
    const x = F();
    if (S.room !== "voute") { out("L'attaque se joue dans la voûte (est de l'officine).", "sys"); return; }
    const u = norm(c.target).split(" ")[0];
    const user = USERS.find(([n]) => n === u);
    if (!user) { out("Quel compte ? `attaquer alice`", "err"); return; }
    const target = x.db[u];
    out(`Mallory essaie son dictionnaire (${LIST.length} mots courants) sur ${u}, en recalculant ${x.slow ? "le hachage lent" : "SHA-256"}${x.salt ? " avec le sel du compte" : ""} pour chaque mot :`, "sys");
    const t0 = performance.now(); let tries = 0, found = null;
    for (const w of LIST) { tries++; if (H(w, u) === target) { found = w; break; } }
    const ms = Math.max(1, Math.round(performance.now() - t0));
    if (found) out(`Trouvé en ${tries} essai${tries > 1 ? "s" : ""} (${ms} ms) : « ${found} ».`, "err");
    else out(`${tries} essais (${ms} ms) : aucun mot du dictionnaire ne correspond. Mot de passe non courant.`, "ok");
    const nb = x.slow ? 3 : 300, b0 = performance.now();
    for (let i = 0; i < nb; i++) H("essai" + i, u);
    const per = Math.round(nb / Math.max(0.001, (performance.now() - b0) / 1000));
    out(`Rythme mesuré dans ton navigateur : environ ${per.toLocaleString("fr-FR")} essais par seconde.`, "sys");
    if (x.slow) { x.atkSlow = true; note("lent"); note("entropie"); fig("cout"); x.lastMs = ms; }
    else if (x.salt) { x.atkSalted = true; note("sel"); out("Le sel a arrêté la table précalculée, mais pas l'essai mot par mot : chaque essai reste très rapide. (Un GPU en fait des milliards par seconde.)", "err"); }
    else if (!found) note("entropie");
  }

  function activate(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "officine") { out("Les procédés se règlent à l'officine.", "sys"); return; }
    if (/sel/.test(t)) {
      if (Object.keys(x.cracked || {}).length < 3) { say("Apothicaire", "Pas encore : voyons d'abord comment Mallory a retrouvé les mots de passe (voûte)."); return; }
      if (x.salt) { out("Déjà activé.", "sys"); return; }
      x.salt = true; rebuild();
      out("L'Apothicaire attribue à chaque compte un sel aléatoire, le colle devant le mot de passe, et refait toutes les empreintes. Les sels sont stockés en clair à côté.", "ok");
      code(dbText());
      out("Remarque : bob et carla n'ont plus la même empreinte, bien qu'ils aient le même mot de passe.", "ok"); note("sel"); fig("sel");
    } else if (/lent|lente|argon|bcrypt/.test(t)) {
      if (!x.atkSalted) { say("Apothicaire", "Vérifions d'abord ce que le sel seul empêche, et ce qu'il n'empêche pas : essaie `attaquer alice` à la voûte."); return; }
      if (x.slow) { out("Déjà activé.", "sys"); return; }
      x.slow = true; rebuild();
      out(`Chaque empreinte est maintenant le résultat de ${ITER} hachages successifs. (En vrai : Argon2, bcrypt ou scrypt, calibrés pour durer ~100 ms par essai.)`, "ok");
      say("Apothicaire", "Pour toi, un essai prend un instant. Pour Mallory, qui doit en faire des milliards, c'est une éternité. Rejoue ton attaque à la voûte.");
    } else out("Quel procédé ? `activer sel` ou `activer lent`.", "err");
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "La Bibliothèque stocke désormais des empreintes salées et lentes. Même si Mallory vole à nouveau le Livre, elle ne retrouvera que les mots de passe les plus faibles, et pas en une seconde. Et n'oublie pas : le meilleur procédé ne rattrape pas « azerty ».");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**L'alambic = une fonction de hachage (ici SHA-256, réelle).** Entrée de taille quelconque, sortie de taille fixe, déterministe, à sens unique, et avec effet avalanche. Pour vérifier un mot de passe, on hache ce que l'utilisateur tape et on compare à l'empreinte stockée : le mot de passe n'est jamais conservé.");
    out("**Le Livre volé = une base de données qui fuit.** Les fuites sont inévitables à long terme : la question est ce que l'attaquant peut en tirer.");
    out("**La table de Mallory = tables précalculées (rainbow tables).** Elle fait un calcul unique pour tous les comptes. Les vraies sont énormes, mais le principe est le même : on a calculé à l'avance les empreintes des mots de passe courants.");
    out("**Le sel.** Une valeur aléatoire unique par compte, ajoutée avant le hachage et stockée à côté de l'empreinte. Il détruit les tables précalculées et sépare les jumeaux. Il n'a pas besoin d'être secret.");
    out("**Le moulin lent = Argon2, bcrypt, scrypt, PBKDF2.** Elles répètent le calcul (et parfois exigent de la mémoire) pour rendre chaque essai coûteux. Un hachage rapide (MD5, SHA-1, SHA-256 seul) est une MAUVAISE idée pour des mots de passe : un GPU en fait des milliards par seconde. Ici : 5 000 tours de SHA-256 ; en vrai, calibre pour environ 100 ms.");
    out("**Les simplifications du jeu.** (1) Le dictionnaire ne compte que 12 mots. (2) Le « hachage lent » est une simple répétition de SHA-256 (PBKDF2 en est une version mieux conçue). (3) Il manque le poivre (un secret côté serveur, hors de la base), l'authentification multifacteur et la détection des mots de passe déjà fuités. (4) Les empreintes de fichiers ou de signatures n'ont pas les mêmes contraintes : là, un hachage rapide est voulu.");
    out("Rappel utile : **on ne stocke jamais un mot de passe : on stocke une empreinte salée, lente, d'un mot de passe long.**", "ok");
  }

  const figs = {
    empreinte: () => ({
      cap: "Une empreinte est toujours de la même taille et ne se remonte pas. Deux textes presque identiques donnent des empreintes sans rapport.",
      svg: SVG(210, "Fonction de hachage",
        R(8, 20, 120, 46) + T(68, 40, "texte", "f-b") + T(68, 57, "de toute taille", "f-s") + AR(128, 43, 162, 43) +
        R(162, 20, 96, 46, "f-pub") + T(210, 40, "SHA-256", "f-b ft-pub") + T(210, 57, "sens unique", "f-s") + AR(258, 43, 292, 43) +
        R(292, 20, 120, 46) + T(352, 40, "empreinte", "f-b") + T(352, 57, "64 caractères hex", "f-s") +
        `<path d="M352,70 C352,100 68,100 68,70" fill="none" class="f-ln f-bad f-dash"/>` + T(210, 108, "✗ impossible de remonter", "ft-bad f-s") +
        T(8, 140, "bonjour →", "f-s", "start") + T(88, 140, sha256("bonjour").slice(0, 28) + "…", "ft-ok f-s", "start") +
        T(8, 160, "Bonjour →", "f-s", "start") + T(88, 160, sha256("Bonjour").slice(0, 28) + "…", "ft-priv f-s", "start") +
        T(8, 192, "une majuscule de plus : rien en commun", "f-s", "start"))
    }),
    avalanche: (pair) => {
      const a = sha256(pair[0]), b = sha256(pair[1]);
      let marks = "";
      for (let i = 0; i < 32; i++) marks += `<rect x="${8 + i * 12.6}" y="64" width="10" height="14" rx="2" fill="${a[i] === b[i] ? "var(--line)" : "var(--bad)"}"/>`;
      return {
        cap: "Chaque case est un caractère de l'empreinte (32 premiers) : en rouge, ceux qui changent quand on modifie une seule lettre.",
        svg: SVG(130, "Effet avalanche",
          T(8, 18, `« ${pair[0]} » → ${a.slice(0, 32)}`, "f-s", "start") + T(8, 40, `« ${pair[1]} » → ${b.slice(0, 32)}`, "f-s", "start") + marks +
          T(210, 108, `${diffHex(a, b)} caractères sur 64 sont différents`, "ft-bad f-b"))
      };
    },
    arc: () => ({
      cap: "Avec la table précalculée de Mallory, chaque empreinte volée se retrouve par simple recherche, pour tous les comptes à la fois.",
      svg: SVG(210, "Table arc-en-ciel",
        R(8, 20, 120, 120) + T(68, 40, "Livre volé", "f-b") + T(68, 62, "alice 5d4a…", "f-s") + T(68, 78, "bob 9f2c…", "f-s") + T(68, 94, "carla 9f2c…", "f-s") + T(68, 110, "dave a6b1…", "f-s") +
        AR(128, 80, 160, 80, "f-bad") + R(160, 20, 110, 120, "f-bad") + T(215, 40, "table Mallory", "f-b ft-bad") + T(215, 62, "azerty ↔ 5d4a…", "f-s") + T(215, 78, "soleil ↔ 9f2c…", "f-s") + T(215, 94, "port443 ↔ a6b1…", "f-s") + T(215, 110, "… 12 mots", "f-s") +
        AR(270, 80, 302, 80, "f-bad") + R(302, 20, 110, 120) + T(357, 40, "résultat", "f-b") + T(357, 62, "alice : azerty", "ft-bad f-s") + T(357, 78, "bob : soleil", "ft-bad f-s") + T(357, 94, "carla : soleil", "ft-bad f-s") + T(357, 110, "dave : port443", "ft-bad f-s") +
        T(210, 172, "un seul calcul à l'avance : tous les comptes tombent", "ft-bad"))
    }),
    sel: () => {
      const a = sha256("soleil").slice(0, 12), b = sha256(saltOf("bob") + "soleil").slice(0, 12), c = sha256(saltOf("carla") + "soleil").slice(0, 12);
      return {
        cap: "Sans sel, bob et carla (même mot de passe) ont la même empreinte. Avec un sel propre à chacun, tout diffère : la table précalculée est inutile.",
        svg: SVG(190, "Effet du sel",
          T(8, 18, "Sans sel", "f-b", "start") + R(8, 26, 200, 56, "f-bad") + T(18, 46, "bob   : " + a + "…", "ft-bad f-s", "start") + T(18, 66, "carla : " + a + "…", "ft-bad f-s", "start") + T(310, 58, "identiques", "ft-bad f-b") +
          T(8, 104, "Avec sel (sel + mot de passe)", "f-b", "start") + R(8, 112, 260, 56, "f-ok") + T(18, 132, `bob   : ${saltOf("bob")}$${b}…`, "ft-ok f-s", "start") + T(18, 152, `carla : ${saltOf("carla")}$${c}…`, "ft-ok f-s", "start") + T(340, 144, "différentes", "ft-ok f-b"))
      };
    },
    cout: () => ({
      cap: "Pour un mot de passe de 8 lettres minuscules (26^8 ≈ 2×10^11 possibilités) : quelques secondes avec un hachage rapide sur GPU, des mois avec un hachage lent. L'échelle est logarithmique.",
      svg: SVG(190, "Coût d'une attaque selon le hachage",
        T(8, 20, "SHA-256 simple (≈ 10^10 essais/s)", "f-s", "start") + R(8, 28, 400, 16) + `<rect x="8" y="28" width="60" height="16" rx="3" fill="var(--bad)"/>` + T(76, 41, "≈ 21 secondes", "ft-bad f-s", "start") +
        T(8, 76, "Hachage lent (≈ 10^4 essais/s)", "f-s", "start") + R(8, 84, 400, 16) + `<rect x="8" y="84" width="330" height="16" rx="3" fill="var(--ok)"/>` + T(346, 97, "≈ 8 mois", "ft-ok f-s", "start") +
        T(8, 132, "Avec en plus un mot de passe de 16 caractères aléatoires :", "f-s", "start") + R(8, 140, 400, 16) + `<rect x="8" y="140" width="400" height="16" rx="3" fill="var(--ok)"/>` + T(400, 153, "hors de portée ▶▶", "f-b", "end") +
        T(8, 182, `Dans ce jeu, ton navigateur a mesuré le même rapport : ×${ITER}.`, "f-s", "start"))
    }),
  };

  GAMES.hash = {
    id: "hash", order: 6, title: "L'Apothicaire des Empreintes", pageTitle: "Hash Quest", subtitle: "aventure textuelle · hachage et mots de passe",
    blurb: "Analyse la fuite du Livre des mots de passe avec du vrai SHA-256, puis stocke-les correctement.",
    concept: "Hachage, sel, mots de passe",
    start: "officine", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.hist = []; x.cracked = {}; rebuild(); },
    refig(name) { fig(name, name === "avalanche" ? ((F().hist || []).slice(-2).length === 2 ? F().hist.slice(-2) : ["bonjour", "Bonjour"]) : undefined); },
    figAlias: { empreinte: ["hachage", "sha"], avalanche: ["effet"], arc: ["table", "rainbow"], sel: ["salt"], cout: ["temps", "lent"] },
    help: "Spécifiques : `hacher ‹texte›` · `craquer ‹nom›` · `attaquer ‹nom›` · `activer sel` · `activer lent`",
    verbs: {
      hash: { words: ["hacher", "hasher", "empreinte"], run: hashCmd },
      crack: { words: ["craquer", "chercher", "retrouver"], run: crackCmd },
      attack: { words: ["attaquer", "essayer", "deviner"], run: attackCmd },
      activate: { words: ["activer", "adopter"], run: activate },
    },
    intro() {
      out("L'Apothicaire des Empreintes", "title");
      out("Mallory a volé le Livre des mots de passe de la Bibliothèque de Port-443. Les mots de passe n'y sont pas écrits en clair, seulement leurs empreintes… et pourtant elle les connaît presque tous. Maître Ada te confie l'analyse de la fuite, avec l'aide de l'Apothicaire, dont l'alambic produit de vraies empreintes SHA-256.", "");
    },
  };
})();
