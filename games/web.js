"use strict";
/* Les Archives de Port-443 : injection SQL et XSS, dans un bac à sable simulé.
   Contexte : audit autorisé de nos propres Archives (mandat écrit). */
(function () {
  const F = () => f();
  const DB = [{ nom: "admin", mdp: "Zx9!kq" }, { nom: "alice", mdp: "hunter2" }, { nom: "bob", mdp: "azerty" }];
  const DANGER = /<\s*script|<\s*img[^>]*onerror|<\s*svg[^>]*onload|\bon\w+\s*=|javascript:/i;

  const notes = {
    inj: ["Injection : mélanger code et données", "Quand une requête est fabriquée en collant du texte venu de l'utilisateur, ce texte peut contenir du code SQL. L'application ne distingue plus ce qu'a écrit le développeur de ce qu'a tapé l'attaquant."],
    taut: ["Tautologie et commentaire", "Deux classiques : une condition toujours vraie (' OR '1'='1) ou un commentaire (--) qui supprime la suite de la requête, par exemple le test du mot de passe."],
    prep: ["Requêtes préparées", "On envoie à la base le modèle de la requête (avec des ?) puis les valeurs séparément. Les valeurs ne sont jamais interprétées comme du code. C'est LA défense contre l'injection SQL."],
    xss: ["XSS (Cross-Site Scripting)", "Si un site affiche tel quel un texte fourni par un utilisateur, un attaquant y glisse du JavaScript. Dans le XSS stocké, le code s'exécute dans le navigateur de chaque visiteur : vol de cookie de session, actions en son nom."],
    esc: ["Échappement en sortie", "Avant d'afficher une donnée dans du HTML, on remplace < > & \" ' par leurs équivalents (&lt; &gt;…). Le navigateur les affiche comme du texte au lieu de les exécuter. Les frameworks modernes le font par défaut."],
    depth: ["Défense en profondeur", "Aucune protection n'est suffisante seule : requêtes préparées, échappement, compte SQL aux droits minimaux, cookie HttpOnly (illisible par JavaScript), en-tête Content-Security-Policy, messages d'erreur neutres, mots de passe hachés (jamais en clair)."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada",
      desc: () => "Maître Ada, doyenne de la Guilde. Elle est ici en tant que commanditaire de l'audit." },
    mandat: { names: ["mandat", "autorisation"], label: "ton mandat d'audit",
      desc: () => "« Mandat d'audit : l'apprenti·e est autorisé·e à tester la sécurité des Archives de Port-443, aux dates et sur le périmètre convenus. Signé : Maître Ada. » Tester un système sans autorisation est illégal : ce document fait toute la différence." },
    borne: { names: ["borne", "terminal", "formulaire", "guichet"], label: "la borne de connexion",
      desc: () => "La borne affiche deux champs : **utilisateur** et **mdp**. Remplis-les avec `saisir utilisateur ‹texte›` et `saisir mdp ‹texte›`, puis `valider`. Elle fabrique la requête SQL en collant ce que tu tapes : tu verras laquelle." },
    greffier: { npc: true, names: ["greffier", "archiviste"], label: "le Greffier",
      desc: () => "Le Greffier surveille la borne sans comprendre ce qui se passe derrière l'écran." },
    livre: { names: ["livre", "livre d or", "registre"], label: "le Livre d'or",
      desc: () => {
        const m = F().msgs || [];
        if (!m.length) return "Le Livre d'or des Archives : les visiteurs y laissent un mot. Pour l'instant il est vide. `ecrire ‹message›` pour y inscrire quelque chose.";
        return "Le Livre d'or, tel qu'affiché par le navigateur :\n" + m.map(x => "  • " + render(x)).join("\n");
      } },
    lovelace: { npc: true, names: ["lovelace", "dame lovelace", "ingenieure"], label: "Dame Lovelace, ingénieure",
      desc: () => "Dame Lovelace, ingénieure en chef des Archives : tablier, clés à molette, un clavier à manivelle." },
    code: { names: ["code", "programme", "serveur"], label: "le code du serveur",
      desc: () => "Le code du serveur (`examiner code sql` ou `examiner code html` pour le détail)." },
    leviers: { names: ["levier", "leviers", "panneau"], label: "deux leviers",
      desc: () => `Deux leviers :\n  · \`activer requetes preparees\` : ${F().prep ? "ACTIVÉ" : "désactivé"}\n  · \`activer echappement\` : ${F().esc ? "ACTIVÉ" : "désactivé"}` },
  };

  const rooms = {
    hall: { name: "Le hall des Archives", short: "Hall", alias: ["hall", "archives"], ents: ["ada", "mandat"], exits: { est: "guichet", nord: "livre", sud: "machines" },
      desc: () => "Un hall de pierre où s'alignent les registres de Port-443 : comptes, courriers, dettes. À l'est, la borne de connexion. Au nord, la salle du Livre d'or. Au sud, la salle des machines." },
    guichet: { name: "Le guichet de connexion", short: "Guichet", alias: ["guichet", "borne"], ents: ["borne", "greffier"], exits: { ouest: "hall" },
      desc: () => "Une borne à écran vert permet aux agents d'accéder aux registres. Elle demande un nom et un mot de passe. Sa base de comptes contient admin, alice et bob." },
    livre: { name: "La salle du Livre d'or", short: "Livre d'or", alias: ["livre", "or"], ents: ["livre"], exits: { sud: "hall" },
      desc: () => "Un pupitre où trône le Livre d'or numérique : tout ce qu'on y écrit est affiché à chaque visiteur qui ouvre la page, y compris à Maître Ada, qui le consulte chaque jour avec son compte d'administratrice." },
    machines: { name: "La salle des machines", short: "Machines", alias: ["machines", "salle"], ents: ["lovelace", "code", "leviers"], exits: { nord: "hall" },
      desc: () => "Des armoires de cuivre, des câbles, le ronronnement des serveurs. Dame Lovelace règle les paramètres de sécurité depuis deux leviers." },
  };

  /* ---------- mini-moteur SQL ---------- */
  function tokenize(s) {
    const t = []; let i = 0;
    while (i < s.length) {
      const c = s[i];
      if (/\s/.test(c)) { i++; continue; }
      if (s.startsWith("--", i) || c === "#") break;
      if (s.startsWith("/*", i)) { const j = s.indexOf("*/", i + 2); if (j < 0) throw new Error("commentaire non terminé"); i = j + 2; continue; }
      if (c === "'") {
        let j = i + 1, v = "";
        for (;;) {
          if (j >= s.length) throw new Error("chaîne de caractères non terminée");
          if (s[j] === "'") { if (s[j + 1] === "'") { v += "'"; j += 2; continue; } break; }
          v += s[j++];
        }
        t.push({ t: "str", v }); i = j + 1; continue;
      }
      if (/\d/.test(c)) { let j = i; while (/\d/.test(s[j] || "")) j++; t.push({ t: "num", v: +s.slice(i, j) }); i = j; continue; }
      if (/[A-Za-z_]/.test(c)) { let j = i; while (/\w/.test(s[j] || "")) j++; const w = s.slice(i, j), u = w.toUpperCase(); t.push(["AND", "OR", "NOT", "LIKE"].includes(u) ? { t: "kw", v: u } : { t: "id", v: w }); i = j; continue; }
      const two = s.slice(i, i + 2);
      if (["<>", "!=", "<=", ">="].includes(two)) { t.push({ t: "op", v: two }); i += 2; continue; }
      if ("=<>()".includes(c)) { t.push({ t: "op", v: c }); i++; continue; }
      if (c === ";") { t.push({ t: "semi", v: ";" }); break; }
      throw new Error(`caractère inattendu « ${c} »`);
    }
    return t;
  }
  const truthy = v => v === true || (typeof v === "number" && v !== 0);
  function evalWhere(tokens, row) {
    let p = 0;
    const peek = () => tokens[p], eat = () => tokens[p++];
    const isKw = w => peek() && peek().t === "kw" && peek().v === w;
    function prim() {
      const k = eat();
      if (!k) throw new Error("expression incomplète");
      if (k.t === "str" || k.t === "num") return k.v;
      if (k.t === "id") { if (!(k.v in row)) throw new Error(`colonne inconnue « ${k.v} »`); return row[k.v]; }
      if (k.t === "op" && k.v === "(") { const v = orE(); const c = eat(); if (!c || c.v !== ")") throw new Error("parenthèse fermante manquante"); return v; }
      throw new Error(`erreur de syntaxe près de « ${k.v} »`);
    }
    function cmp() {
      const l = prim(), k = peek();
      if (k && k.t === "op" && ["=", "<>", "!=", "<", ">", "<=", ">="].includes(k.v)) {
        eat(); const r = prim();
        switch (k.v) { case "=": return l == r; case "<>": case "!=": return l != r; case "<": return l < r; case ">": return l > r; case "<=": return l <= r; default: return l >= r; }
      }
      if (isKw("LIKE")) { eat(); const r = prim(); return new RegExp("^" + String(r).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, ".*").replace(/_/g, ".") + "$", "i").test(String(l)); }
      return l;
    }
    function notE() { if (isKw("NOT")) { eat(); return !truthy(notE()); } return cmp(); }
    function andE() { let v = notE(); while (isKw("AND")) { eat(); const r = notE(); v = truthy(v) && truthy(r); } return v; }
    function orE() { let v = andE(); while (isKw("OR")) { eat(); const r = andE(); v = truthy(v) || truthy(r); } return v; }
    const v = orE();
    if (p < tokens.length && tokens[p].t !== "semi") throw new Error(`erreur de syntaxe près de « ${tokens[p].v} »`);
    return truthy(v);
  }
  function runLogin(user, pass) {
    const x = F();
    if (x.prep) {
      const rows = DB.filter(r => r.nom === user && r.mdp === pass);
      return { shown: "SELECT * FROM comptes WHERE nom = ? AND mdp = ?\n  paramètres : [" + JSON.stringify(user) + ", " + JSON.stringify(pass) + "]", rows, legit: rows.length > 0 };
    }
    const q = `SELECT * FROM comptes WHERE nom='${user}' AND mdp='${pass}'`;
    const where = q.slice(q.indexOf("WHERE") + 5);
    try {
      const toks = tokenize(where);
      const rows = DB.filter(r => evalWhere(toks, r));
      const legit = DB.some(r => r.nom === user && r.mdp === pass);
      return { shown: q, rows, legit, stacked: toks.some(t => t.t === "semi") };
    } catch (e) { return { shown: q, error: e.message }; }
  }
  function render(m) {
    const x = F();
    if (x.esc) return m.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") + "   (affiché comme du texte)";
    return DANGER.test(m) ? m + "   ← le navigateur EXÉCUTE ce code" : m;
  }

  /* ---------- objectifs ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.sawQuery) return "see";
    if (!x.sqli) return "sqli";
    if (!x.prep) return "prep";
    if (!x.sqlBlocked) return "retest";
    if (!x.msgs || !x.msgs.length) return "write";
    if (!x.xss) return "xss";
    if (!x.esc) return "esc";
    if (!x.xssBlocked) return "xretest";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada est dans le hall.", "`parler ada`"],
    see: () => ["Commence par une connexion ordinaire à la borne (est du hall) pour voir comment la requête est fabriquée.", "`aller est`, `saisir utilisateur alice`, `saisir mdp test`, `valider`"],
    sqli: () => ["Le texte que tu tapes est collé dans la requête. Que se passe-t-il si tu y mets une apostrophe ? Et si tu mets en commentaire la suite ?", "`saisir utilisateur admin'--` puis `valider` (autre piste : `saisir utilisateur alice` et `saisir mdp ' OR '1'='1`)."],
    prep: () => ["Ça marche… donc c'est à corriger. Dame Lovelace règle la sécurité dans la salle des machines (sud du hall).", "`aller ouest`, `aller sud`, `examiner code sql`, puis `activer requetes preparees`."],
    retest: () => ["Retourne à la borne rejouer la même attaque : elle doit échouer.", "`aller nord`, `aller est`, `valider` (les champs sont encore remplis)."],
    write: () => ["Passons au Livre d'or (nord du hall). Ce qu'on y écrit est affiché à tout le monde.", "`aller nord` puis `ecrire Bravo pour ces archives !` (texte inoffensif d'abord)."],
    xss: () => ["Un message peut contenir du HTML. Que se passe-t-il si c'est un script ? Écris-en un, puis laisse Ada ouvrir la page.", "`ecrire <script>vol(document.cookie)</script>` puis `attendre`."],
    esc: () => ["L'attaque marche : corrige l'affichage. Les leviers sont dans la salle des machines.", "`activer echappement` (salle des machines : hall puis sud)."],
    xretest: () => ["Rejoue l'attaque pour vérifier : le message piégé doit être affiché comme du simple texte.", "`aller nord`, `attendre` (le message est déjà dans le livre)."],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; give("mandat");
          say("Maître Ada", "Mallory a volé des comptes des Archives sans forcer aucune porte. Elle parle à nos machines, et nos machines l'écoutent. J'ai besoin que tu comprennes comment : tu vas attaquer NOS Archives, avec ce mandat écrit, pour qu'on les corrige.");
          say("Maître Ada", "Deux endroits à tester : la borne de connexion (est) et le Livre d'or (nord). Puis tu iras voir Dame Lovelace, au sud, pour tout corriger. Tout ce que tu fais ici est simulé, mais le principe est réel : on teste uniquement ce qu'on a le droit de tester.");
          out("Tu as reçu un mandat d'audit (`examiner mandat`).", "sys");
        } else if (x.end) say("Maître Ada", "Les Archives sont enfin à l'épreuve de Mallory. Merci.");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas terminé. `indice` si tu bloques.");
        break;
      case "greffier":
        say("Le Greffier", "Moi, je tape ce qu'on me dit de taper, et la borne fait le reste. Des gens bizarres essaient parfois des apostrophes, je ne comprends pas pourquoi.");
        break;
      case "lovelace":
        if (!x.sqli && !x.xss) say("Dame Lovelace", "Pour l'instant tout semble fonctionner. Reviens quand tu auras trouvé une faille : je ne corrige que ce qu'on m'a prouvé cassé.");
        else say("Dame Lovelace", `Mes deux leviers : « requêtes préparées » (état : ${x.prep ? "activé" : "désactivé"}) et « échappement » (état : ${x.esc ? "activé" : "désactivé"}). Regarde le code avec \`examiner code sql\` ou \`examiner code html\` avant de tirer dessus.`);
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function typeCmd(c) {
    const m = c.rawArg.match(/^(utilisateur|user|nom|mdp|mot de passe|motdepasse|password)\s+(.*)$/i);
    if (S.room !== "guichet") { out("Il n'y a pas de formulaire à remplir ici.", "sys"); return; }
    if (!m) { out("Quel champ ? `saisir utilisateur ‹texte›` ou `saisir mdp ‹texte›`.", "err"); return; }
    const field = /^(utilisateur|user|nom)$/i.test(m[1]) ? "user" : "pass";
    F()[field] = m[2];
    out(`Champ ${field === "user" ? "utilisateur" : "mdp"} : « ${m[2]} »`, "ok");
  }
  function submit() {
    const x = F();
    if (S.room !== "guichet") { out("Il n'y a rien à valider ici.", "sys"); return; }
    if (x.user == null || x.pass == null) { out("Remplis d'abord les deux champs : `saisir utilisateur ‹texte›` et `saisir mdp ‹texte›`.", "err"); return; }
    const r = runLogin(x.user, x.pass);
    out("Requête exécutée par le serveur :", "sys"); code(r.shown);
    x.sawQuery = true;
    const looksInj = /'|--|#|\/\*|;/.test(x.user + x.pass);
    if (r.error) {
      out(`Erreur SQL : ${r.error}.`, "err");
      out("L'apostrophe a cassé la requête : ton texte a été interprété comme du SQL. (Afficher ce genre de message à l'utilisateur est une fuite d'information supplémentaire.)", "sys");
      note("inj"); return;
    }
    if (r.stacked) out("(Le pilote n'exécute qu'une seule requête : les requêtes empilées après « ; » sont ignorées ici. Certains pilotes les acceptent : un DROP TABLE serait alors exécuté.)", "sys");
    if (!r.rows.length) {
      out("Lignes renvoyées : 0. **Accès refusé : identifiants invalides.**", "err");
      if (x.prep && looksInj) {
        x.sqlBlocked = true;
        out(`Avec les requêtes préparées, ton texte est traité comme une DONNÉE : aucun compte ne s'appelle « ${x.user} », et le mot de passe n'est pas « ${x.pass} ». L'attaque échoue.`, "ok");
        note("prep"); fig("prepare");
      }
      return;
    }
    out(`Lignes renvoyées : ${r.rows.length} (${r.rows.map(z => z.nom).join(", ")}). **Connecté en tant que ${r.rows[0].nom}.**`, r.legit ? "ok" : "err");
    if (!r.legit) {
      x.sqli = true;
      out("Tu es entré·e sans connaître le mot de passe : la partie « mdp » de la requête a été neutralisée par ton texte.", "err");
      note("inj"); note("taut"); fig("sqli");
    } else out("(Connexion légitime. Pour tester une faille, essaie un nom avec une apostrophe.)", "sys");
  }
  function write(c) {
    const x = F();
    if (S.room !== "livre") { out("On écrit dans le Livre d'or, au nord du hall.", "sys"); return; }
    if (!c.rawArg.trim()) { out("Que veux-tu écrire ? `ecrire ‹message›`", "err"); return; }
    x.msgs = x.msgs || []; x.msgs.push(c.rawArg);
    out(`Message ajouté au Livre d'or : « ${c.rawArg} »`, "ok");
    out("Maître Ada consulte le Livre d'or chaque jour. `attendre` pour qu'elle l'ouvre.", "sys");
  }
  function wait() {
    const x = F();
    if (S.room !== "livre") { out("Rien à attendre ici.", "sys"); return; }
    const bad = (x.msgs || []).filter(m => DANGER.test(m));
    if (!(x.msgs || []).length) { out("Le livre est vide, Ada ne verra rien. Écris un message d'abord.", "sys"); return; }
    out("Maître Ada ouvre la page du Livre d'or avec son compte d'administratrice…", "sys");
    if (!bad.length) { out("Elle sourit, lit tes messages et referme la page. Rien d'anormal.", "sys"); return; }
    if (!x.esc) {
      x.xss = true;
      out(`Le navigateur d'Ada trouve ${bad[0].length > 40 ? bad[0].slice(0, 40) + "…" : bad[0]} dans la page et l'EXÉCUTE, comme si le site l'avait écrit lui-même.`, "err");
      code("document.cookie  →  « session=ada-7f3c91 »\nenvoi vers mallory.example/collect?c=session%3Dada-7f3c91");
      out("Le cookie de session d'Ada vient d'être envoyé à l'attaquant : en le copiant, elle peut agir en tant qu'administratrice sans mot de passe.", "err");
      note("xss"); fig("xss");
    } else {
      x.xssBlocked = true;
      out("La page affiche le message comme du simple texte, sans l'exécuter :", "ok");
      code(bad[0].replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"));
      out("Le navigateur ne voit plus de balise : seulement des caractères à afficher. Le cookie reste en sécurité.", "ok");
      note("esc"); fig("escape");
    }
  }
  function activate(c) {
    const x = F();
    if (S.room !== "machines") { out("Les leviers sont dans la salle des machines.", "sys"); return; }
    const t = norm(c.rawArg);
    if (/prepar|requete|sql/.test(t)) {
      if (x.prep) { out("Déjà activé.", "sys"); return; }
      x.prep = true; out("Clac. La borne n'assemble plus la requête avec du texte : elle envoie le modèle à la base, puis les valeurs séparément.", "ok");
      say("Dame Lovelace", "Retourne rejouer ton attaque à la borne : tu verras la différence.");
      fig("prepare");
    } else if (/echapp|html|affichage/.test(t)) {
      if (x.esc) { out("Déjà activé.", "sys"); return; }
      x.esc = true; out("Clac. Le Livre d'or remplace désormais < > & par leurs équivalents (&lt; &gt; &amp;) avant d'afficher quoi que ce soit.", "ok");
      say("Dame Lovelace", "Rejoue l'attaque : fais ouvrir le livre par Ada.");
    } else out("Quel levier ? `activer requetes preparees` ou `activer echappement`.", "err");
  }
  const codeEnt = ents.code;
  codeEnt.onExamine = function () { /* le détail est dans desc selon la commande */ };
  codeEnt.desc = () => "Précise : `examiner code sql` ou `examiner code html`.";
  ents.codesql = { names: ["code sql", "sql", "requete", "requetes"], label: "", vis: () => S.room === "machines",
    desc: () => F().prep
      ? "Code actuel (corrigé) :\n  requete = \"SELECT * FROM comptes WHERE nom = ? AND mdp = ?\"\n  executer(requete, [nom, mdp])\nLe modèle et les valeurs voyagent séparément."
      : "Code actuel (vulnérable) :\n  requete = \"SELECT * FROM comptes WHERE nom='\" + nom + \"' AND mdp='\" + mdp + \"'\"\n  executer(requete)\nLe texte de l'utilisateur est collé dans la requête." };
  ents.codehtml = { names: ["code html", "html", "page", "affichage"], label: "", vis: () => S.room === "machines",
    desc: () => F().esc
      ? "Code actuel (corrigé) :\n  page = \"<li>\" + echapper(message) + \"</li>\""
      : "Code actuel (vulnérable) :\n  page = \"<li>\" + message + \"</li>\"\nLe message de l'utilisateur est inséré tel quel dans la page." };
  rooms.machines.ents.push("codesql", "codehtml");

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Tu as volé un compte sans mot de passe, puis volé la session d'une administratrice, avec un simple texte. Et tu as aussi montré comment tout corriger : trois lignes de code, qui séparent enfin les données du code. Voilà ce qu'est un audit.");
    note("depth"); debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La borne et le Greffier = une application web et sa base de données.** Le Greffier tape ce qu'on lui dit sans comprendre : comme une application qui colle ton texte dans une requête SQL. Une apostrophe y devient la fin d'un texte et le début de code.");
    out("**admin'-- et ' OR '1'='1 = injection SQL.** Le premier commente la suite de la requête (le mot de passe n'est plus testé), le second rend la condition toujours vraie. Le même principe permet de lire d'autres tables (UNION), ou de modifier et détruire des données si le compte SQL a trop de droits.");
    out("**Le levier « requêtes préparées ».** La requête est envoyée avec des emplacements (?), puis les valeurs séparément : la base sait qu'elles sont des données, jamais du code. C'est la défense à utiliser par défaut. Un filtre qui retire les apostrophes est fragile et contournable.");
    out("**Le Livre d'or et Ada = XSS stocké.** Le message d'un visiteur est enregistré, puis affiché à tous. Si le navigateur le prend pour du HTML, le script s'exécute avec les droits de la victime : vol de cookie de session, actions à sa place, faux formulaires.");
    out("**Le levier « échappement ».** Avant d'insérer une donnée dans du HTML, on remplace < par &lt;, etc. Le navigateur affiche alors le texte au lieu de l'exécuter. Les frameworks (React, Vue…) le font automatiquement, sauf si on le contourne explicitement.");
    out("**Les simplifications du jeu.** (1) Le mini-moteur SQL du jeu ne gère que des conditions (AND, OR, NOT, comparaisons, LIKE). (2) La requête pour la connexion est volontairement naïve : en vrai le mot de passe est comparé à un hachage salé, jamais en clair (voir le jeu sur le hachage). (3) Il manque d'autres défenses : cookie HttpOnly et SameSite, en-tête Content-Security-Policy, compte SQL aux droits minimaux. (4) Tout ceci est simulé : n'attaque jamais un système sans autorisation écrite.");
    out("Rappel utile : **ne jamais construire du code (SQL, HTML, commande) en collant du texte non fiable : séparer les données du code.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    sqli: () => ({
      cap: "Le texte tapé (en rouge) ferme la chaîne, puis le commentaire -- supprime la vérification du mot de passe : la requête ne teste plus que le nom.",
      svg: SVG(180, "Injection SQL avec un commentaire",
        T(8, 18, "Ce que le développeur imaginait", "f-s", "start") + R(8, 26, 404, 34) + T(18, 48, "WHERE nom='alice' AND mdp='…'", "", "start") +
        T(8, 88, "Ce que l'attaquant fait envoyer (utilisateur = admin'--)", "f-s", "start") + R(8, 96, 404, 34, "f-bad") +
        T(18, 118, "WHERE nom='", "", "start") + `<text x="102" y="118" class="f-t ft-bad f-b">admin'--</text>` + `<text x="170" y="118" class="f-t f-s" text-decoration="line-through">' AND mdp='…'</text>` +
        T(412, 150, "↑ après -- tout est ignoré : plus de test du mot de passe", "ft-bad f-s", "end") +
        T(8, 172, "résultat : nom = 'admin'  →  connecté en admin", "ft-bad", "start"))
    }),
    prepare: () => ({
      cap: "Requête préparée : le modèle et les valeurs arrivent séparément. La base ne mélange jamais les deux, donc le texte de l'attaquant reste une simple donnée.",
      svg: SVG(190, "Requête préparée",
        R(8, 20, 190, 50) + T(103, 40, "modèle de requête", "f-b") + T(103, 58, "nom = ?  AND  mdp = ?", "ft-ok f-s") +
        R(8, 100, 190, 50, "f-bad") + T(103, 120, "données", "f-b") + T(103, 138, "admin'--", "ft-bad f-s") +
        AR(198, 45, 260, 80) + AR(198, 125, 260, 100) +
        R(262, 60, 150, 60) + T(337, 84, "base de données", "f-b") + T(337, 104, "compare comme valeurs", "f-s") +
        T(210, 178, "aucun compte nommé « admin'-- » : refusé ✔", "ft-ok"))
    }),
    xss: () => ({
      cap: "XSS stocké : le script est enregistré par le serveur, puis servi à chaque visiteur. Il s'exécute dans le navigateur d'Ada, avec ses droits.",
      svg: SVG(230, "Scénario de XSS stocké",
        R(8, 20, 100, 50, "f-bad") + T(58, 40, "Mallory", "f-b ft-bad") + T(58, 58, "poste <script>", "f-s") +
        R(160, 20, 100, 50) + T(210, 40, "Livre d'or", "f-b") + T(210, 58, "stocké tel quel", "f-s") +
        R(312, 20, 100, 50) + T(362, 40, "Ada", "f-b") + T(362, 58, "ouvre la page", "f-s") +
        AR(108, 45, 160, 45, "f-bad") + T(134, 36, "1", "f-s") + AR(260, 45, 312, 45) + T(286, 36, "2", "f-s") +
        R(312, 110, 100, 50, "f-bad") + T(362, 130, "script exécuté", "ft-bad f-b") + T(362, 148, "lit le cookie", "f-s") +
        AR(362, 70, 362, 110, "f-bad") + T(376, 94, "3", "f-s", "start") +
        AR(312, 135, 108, 195, "f-bad") + T(210, 160, "4 : cookie envoyé à Mallory", "ft-bad f-s") +
        R(8, 175, 100, 40, "f-bad") + T(58, 200, "session d'Ada", "ft-bad f-s"))
    }),
    escape: () => ({
      cap: "Avec l'échappement, < devient &lt; : le navigateur affiche les caractères au lieu d'interpréter une balise.",
      svg: SVG(170, "Échappement HTML",
        T(8, 18, "Sans échappement", "f-s", "start") + R(8, 26, 404, 34, "f-bad") + T(18, 48, "&lt;script&gt;vol()&lt;/script&gt;  →  le navigateur l'exécute", "ft-bad", "start") +
        T(8, 90, "Avec échappement", "f-s", "start") + R(8, 98, 404, 34, "f-ok") + T(18, 120, "&amp;lt;script&amp;gt;vol()&amp;lt;/script&amp;gt;  →  du texte", "ft-ok", "start") +
        T(8, 158, "Règle : &lt; → &amp;lt;   &gt; → &amp;gt;   &amp; → &amp;amp;", "f-s", "start"))
    }),
  };

  GAMES.web = {
    id: "web", order: 3, title: "Les Archives de Port-443", pageTitle: "Web Quest", subtitle: "aventure textuelle · injections SQL et XSS",
    blurb: "Audite les Archives avec un mandat : vole un compte sans mot de passe, puis corrige tout.",
    concept: "Injection SQL, XSS",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    refig(name) { fig(name); },
    figAlias: { sqli: ["injection", "sql"], prepare: ["requete", "preparee"], xss: ["script", "livre"], escape: ["echappement", "html"] },
    help: "Spécifiques : `saisir utilisateur|mdp ‹texte›` · `valider` · `ecrire ‹message›` · `attendre` · `activer requetes preparees|echappement` · `examiner code sql|html`",
    verbs: {
      type: { words: ["saisir", "taper", "remplir"], run: typeCmd },
      submit: { words: ["valider", "connecter", "envoyer"], run: submit },
      write: { words: ["ecrire", "poster", "publier"], run: write },
      wait: { words: ["attendre", "patienter"], run: wait },
      activate: { words: ["activer", "tirer", "basculer"], run: activate },
    },
    intro() {
      out("Les Archives de Port-443", "title");
      out("Les Archives de Port-443 conservent tous les comptes de la ville. Depuis quelques semaines, Mallory y vole des données sans jamais forcer une porte ni casser un mot de passe.\nMaître Ada t'engage pour un **audit de sécurité autorisé** : tu vas attaquer les Archives, avec un mandat écrit, pour comprendre comment elles se font piéger, puis les faire corriger. Tout est simulé dans le jeu.", "");
    },
  };
})();
