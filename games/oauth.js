"use strict";
/* Le Palais des Passeports : OAuth 2.0 (code d'autorisation) et JWT. */
(function () {
  const F = () => f();
  const REDIR = "https://biblio.port443/callback";
  const EVIL = "https://evil.example/callback";
  const WEAK = "passeport";
  const STRONG = "q9X!f4Lw-Zk2#TrN7vB0";
  const WORDS = ["123456", "password", "secret", "azerty", "admin", "letmein", "port443", "passeport", "qwerty"];
  const rnd = () => Math.random().toString(16).slice(2, 10);
  const sigOf = (d, k) => b64u(sha256(k + "|" + d).slice(0, 32));
  const secret = () => F().secFix ? STRONG : WEAK;
  function mkToken(payload, key, alg) {
    const h = b64u(JSON.stringify({ alg, typ: "JWT" })), p = b64u(JSON.stringify(payload));
    return h + "." + p + "." + (alg === "none" ? "" : sigOf(h + "." + p, key));
  }
  function parseToken(t) {
    const [h, p, s] = String(t).split(".");
    try { return { h, p, s: s || "", head: JSON.parse(unb64u(h)), body: JSON.parse(unb64u(p)) }; } catch (e) { return null; }
  }
  // Le serveur de ressources : renvoie {ok, why}
  function apiCheck(token) {
    const x = F(), t = parseToken(token);
    if (!t) return { ok: false, why: "jeton illisible" };
    if (!x.sigFix) return { ok: true, why: "le serveur ne vérifie pas la signature : il fait confiance au contenu", role: t.body.role };
    if (t.head.alg !== "HS256") return { ok: false, why: `algorithme « ${t.head.alg} » refusé : seul HS256 est accepté` };
    if (t.s !== sigOf(t.h + "." + t.p, secret())) return { ok: false, why: "signature invalide : ce jeton n'a pas été émis par le Passeport" };
    return { ok: true, why: "signature valide", role: t.body.role };
  }
  const payload = (role) => ({ iss: "passeport.port443", sub: "alice", aud: "contacts", scope: "contacts.lecture", role, exp: 1791200000 });

  const notes = {
    deleg: ["Déléguer sans donner son mot de passe", "OAuth 2.0 permet à un service (le client) d'accéder à une partie de tes données chez un autre (le serveur de ressources) sans connaître ton mot de passe. C'est la clé de voiturier : elle ouvre la portière et démarre, mais pas le coffre, et on peut la retirer."],
    code: ["Pourquoi un code, puis un jeton ?", "Le serveur d'autorisation renvoie d'abord un code à usage unique, via le navigateur (visible, donc peu fiable). Le client l'échange ensuite directement avec le serveur, en s'authentifiant : le jeton d'accès ne transite jamais par le navigateur."],
    scope: ["Les portées (scopes) et le consentement", "L'utilisateur voit ce que le client demande (ici contacts.lecture) et l'accepte sur la page du serveur d'autorisation. Le jeton ne donne que cette permission, pour un temps limité."],
    jwt: ["Le JWT : trois parties en base64", "Un JWT est header.payload.signature, chaque partie encodée en base64url. Base64 n'est PAS du chiffrement : n'importe qui lit le contenu. La signature garantit que le contenu n'a pas été modifié et vient de l'émetteur."],
    redirect: ["redirect_uri : correspondance exacte", "Le serveur doit refuser tout redirect_uri qui n'est pas exactement celui enregistré pour le client. Sinon un lien piégé envoie le code d'autorisation chez l'attaquant."],
    state: ["Le paramètre state contre le CSRF", "Le client génère une valeur aléatoire, la lie à la session de l'utilisateur et exige de la retrouver au retour. Sans cela, un attaquant peut faire terminer à la victime un flux commencé avec SON compte."],
    alg: ["Toujours vérifier la signature et l'algorithme", "Un serveur qui accepte alg: none (ou qui ne vérifie pas la signature) laisse n'importe qui fabriquer un jeton. On fixe la liste des algorithmes acceptés côté serveur, jamais d'après l'en-tête."],
    secret: ["Secret fort ou clés asymétriques", "Avec HS256, le secret partagé doit être long et aléatoire : un mot courant est retrouvé par essais hors ligne à partir d'un seul jeton. Avec RS256 (RSA) ou ES256, seul l'émetteur détient la clé privée, les autres vérifient avec la publique."],
    oidc: ["OAuth et OpenID Connect", "OAuth 2.0 sert à autoriser l'accès à des ressources. OpenID Connect ajoute une couche d'authentification : un id_token (un JWT) qui dit QUI s'est connecté. « Se connecter avec… » utilise OpenID Connect."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, mandatée par le Palais pour auditer le système de jetons." },
    bibliothecaire: { npc: true, names: ["bibliothecaire", "client", "bibliotheque"], label: "le Bibliothécaire (application cliente)", desc: () => "Le Bibliothécaire, serviable, qui voudrait importer les contacts d'Alice dans le catalogue de la Bibliothèque. C'est l'application CLIENT." },
    chambellan: { npc: true, names: ["chambellan", "passeport", "serveur"], label: "le Chambellan du Passeport (serveur d'autorisation)", desc: () => "Le Chambellan du Passeport : perruque poudrée, registre des clients autorisés. Il décide qui reçoit quoi, après consentement. C'est le SERVEUR D'AUTORISATION." },
    archiviste: { npc: true, names: ["archiviste", "contacts", "api"], label: "l'Archiviste des contacts (serveur de ressources)", desc: () => "L'Archiviste garde les contacts d'Alice. Il ne délivre rien sans jeton valide. C'est le SERVEUR DE RESSOURCES (l'API)." },
    registre: { names: ["registre", "clients"], label: "le registre des clients", desc: () => `Le registre du Chambellan : client « biblio », redirect_uri enregistré : ${REDIR}, portées autorisées : contacts.lecture. Réglage actuel : ${F().redFix ? "redirect_uri vérifié à l'identique" : "redirect_uri non contrôlé (tout est accepté)"}.` },
    pupitre: { names: ["pupitre", "essai", "attaques"], label: "le pupitre d'essai", desc: () => "Le pupitre d'essai te permet de rejouer les attaques de Mallory contre les défenses actuelles, en simulation :\n  `attaquer redirect` · `attaquer csrf` · `attaquer none` · `attaquer secret`\nElles sont disponibles dès que tu as parcouru le flux normal." },
    lien: { names: ["lien", "url", "adresse", "lien autorisation"], label: "le lien d'autorisation", desc: () => `Le lien d'autorisation :\n  ${authUrl(REDIR)}` },
    code: { names: ["code", "code autorisation"], label: "le code d'autorisation", desc: () => `Le code d'autorisation : **${F().code}**. À usage unique, valable quelques secondes.` },
    jeton: { names: ["jeton", "token", "jwt"], label: "le jeton d'accès (JWT)", desc: () => `Le jeton d'accès :\n${F().token}\n(\`decoder jeton\` pour lire son contenu)` },
  };
  function authUrl(redir) {
    return `https://passeport.port443/authorize?response_type=code&client_id=biblio&redirect_uri=${redir}&scope=contacts.lecture&state=${F().state}`;
  }

  const rooms = {
    cour: { name: "La cour du Palais des Passeports", short: "Cour", alias: ["cour", "palais"], ents: ["ada"], exits: { nord: "guichet", est: "bibliotheque", ouest: "bureau", sud: "essai" },
      desc: () => "Une cour pavée entre quatre bâtiments. Au nord, le guichet du Passeport. À l'est, la Bibliothèque. À l'ouest, le Bureau des contacts. Au sud, une salle d'essai fermée par une grille." },
    bibliotheque: { name: "La Bibliothèque", short: "Bibliothèque", alias: ["bibliotheque", "biblio"], ents: ["bibliothecaire"], exits: { ouest: "cour" },
      desc: () => "Rayonnages, odeur de papier. Le Bibliothécaire voudrait importer les contacts d'Alice depuis le Palais, mais il ne doit surtout pas connaître son mot de passe du Palais." },
    guichet: { name: "Le guichet du Passeport", short: "Guichet", alias: ["guichet", "passeport"], ents: ["chambellan", "registre"], exits: { sud: "cour" },
      desc: () => "Un comptoir de marbre. Le Chambellan reçoit les demandes d'autorisation et délivre les codes. Un registre indique les clients enregistrés et leurs adresses de retour." },
    bureau: { name: "Le Bureau des contacts", short: "Bureau", alias: ["bureau", "contacts"], ents: ["archiviste"], exits: { est: "cour" },
      desc: () => "Une salle d'archives où chaque tiroir porte un nom. L'Archiviste n'ouvre un tiroir qu'à la présentation d'un jeton." },
    essai: { name: "La salle d'essai", short: "Salle d'essai", alias: ["essai", "salle"], ents: ["pupitre"], exits: { nord: "cour" },
      desc: () => "Un pupitre à manivelle devant une grille de fer. Ici, tu joues le rôle de Mallory contre les défenses actuelles du Palais, en simulation, pour comprendre ce qu'il faut corriger." },
  };

  const VULNS = [["red", "redirect"], ["csrf", "csrf"], ["none", "none"], ["sec", "secret"]];
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.asked) return "ask";
    if (!x.presented) return "present";
    if (!x.consent) return "consent";
    if (!x.token) return "callback";
    if (!x.apiOk) return "api";
    for (const [k] of VULNS) {
      if (!x[k + "Att"]) return k + "_att";
      if (!x[k + "Fix"]) return k + "_fix";
      if (!x[k + "Blk"]) return k + "_blk";
    }
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada attend dans la cour.", "`parler ada`"],
    ask: () => ["Le flux commence à la Bibliothèque (est de la cour) : c'est elle qui veut accéder aux contacts.", "`aller est`, puis `demander acces`."],
    present: () => ["Alice doit aller sur la page du Passeport (nord de la cour) avec le lien d'autorisation.", "`aller ouest`, `aller nord`, puis `presenter lien`."],
    consent: () => ["Le Chambellan attend la décision d'Alice : c'est elle qui consent, pas le client.", "`accepter`"],
    callback: () => ["Le code doit retourner à la Bibliothèque, qui l'échangera contre un jeton.", "`aller sud`, `aller est`, puis `donner code a bibliothecaire`."],
    api: () => ["Il reste à utiliser le jeton chez le serveur de ressources : le Bureau des contacts (ouest de la cour).", "`aller ouest`, puis `presenter jeton` (tu peux aussi `decoder jeton`)."],
    red_att: () => ["Tu connais le flux normal. Tu as maintenant accès à la salle d'essai (sud de la cour) pour rejouer les attaques. Commence par le lien piégé.", "`aller est`, `aller sud`, puis `attaquer redirect`."],
    red_fix: () => ["Le Chambellan accepte n'importe quelle adresse de retour. À corriger côté serveur d'autorisation (guichet).", "`aller nord` (cour), `aller nord` (guichet), puis `configurer redirect`."],
    red_blk: () => ["Rejoue l'attaque pour vérifier le correctif.", "`aller sud`, `aller sud`, puis `attaquer redirect`."],
    csrf_att: () => ["Deuxième faiblesse : le retour du code vers la Bibliothèque. Rejoue l'attaque CSRF dans la salle d'essai.", "`attaquer csrf`"],
    csrf_fix: () => ["La faille est dans l'application cliente : à corriger à la Bibliothèque.", "`aller nord`, `aller est`, puis `configurer state`."],
    csrf_blk: () => ["Rejoue l'attaque CSRF en salle d'essai.", "`aller ouest`, `aller sud`, `attaquer csrf`."],
    none_att: () => ["Passons au jeton. Peut-on en fabriquer un sans connaître le secret ? Salle d'essai.", "`attaquer none`"],
    none_fix: () => ["Le serveur de ressources fait confiance au contenu du jeton : à corriger au Bureau des contacts.", "`aller nord`, `aller ouest`, puis `configurer signature`."],
    none_blk: () => ["Rejoue l'attaque `none`.", "`aller est`, `aller sud`, `attaquer none`."],
    sec_att: () => ["La signature est vérifiée. Mais le secret est-il solide ? Tente de le deviner en salle d'essai.", "`attaquer secret`"],
    sec_fix: () => ["Un secret trop court se retrouve : changer le secret côté émetteur et vérificateur.", "`aller nord`, `aller ouest`, puis `configurer secret`."],
    sec_blk: () => ["Rejoue l'attaque sur le secret.", "`aller est`, `aller sud`, `attaquer secret`."],
    end: () => ["Rends compte à Maître Ada.", "`aller nord`, puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Alice veut que la Bibliothèque importe ses contacts du Palais. Mais elle ne donnera jamais son mot de passe du Palais à la Bibliothèque : si celle-ci était piratée, tout serait perdu. Le Palais a donc inventé le Passeport : une clé de voiturier. Elle ouvre la portière et démarre la voiture, pas le coffre, et on peut la retirer.");
          say("Maître Ada", "Quatre acteurs : Alice (propriétaire des données), la Bibliothèque (le client), le Passeport (le serveur d'autorisation) et le Bureau des contacts (le serveur de ressources). Parcours d'abord le flux normal, puis tu rejoueras, en simulation, les attaques de Mallory pour corriger chaque faille.");
          note("deleg"); out("Commence à la Bibliothèque (`aller est`).", "sys");
        } else if (x.end) say("Maître Ada", "Le Passeport est maintenant solide. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "Le travail n'est pas terminé. `indice` si tu bloques.");
        break;
      case "bibliothecaire":
        if (!x.quest) say("Bibliothécaire", "Bonjour ! Maître Ada voudrait vous voir avant que nous commencions.");
        else if (!x.asked) say("Bibliothécaire", "Je veux importer les contacts d'Alice, mais sans jamais voir son mot de passe. Je vais la renvoyer vers le Passeport avec ma demande. `demander acces`.");
        else if (!x.token) say("Bibliothécaire", "J'attends le code d'autorisation : rapporte-le moi (`donner code a bibliothecaire`).");
        else say("Bibliothécaire", `J'ai mon jeton d'accès. Il ne vaut que pour « contacts.lecture » et pour quelques minutes.${x.stateCheck ? " Et je vérifie maintenant le state à chaque retour." : ""}`);
        break;
      case "chambellan":
        if (!x.asked) say("Chambellan", "Je n'ai reçu aucune demande d'autorisation. Quand un client m'en envoie une, je demande à la personne concernée si elle consent, puis je lui délivre un code.");
        else if (!x.consent) say("Chambellan", "Présente-moi le lien d'autorisation (`presenter lien`). Je vérifierai le client et l'adresse de retour.");
        else say("Chambellan", `Mon contrôle de l'adresse de retour : ${x.redFix ? "elle doit être EXACTEMENT celle du registre" : "je ne regarde pas vraiment, je renvoie le code là où on me le demande"}.`);
        break;
      case "archiviste":
        say("Archiviste", `Je ne garde aucun registre de jetons : je vérifie la signature de chacun. ${x.sigFix ? "Algorithme imposé : HS256 uniquement." : "Je crois que je lis simplement leur contenu."} ${x.secFix ? "Mon secret est désormais long et aléatoire." : ""}`);
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function ask() {
    const x = F();
    if (S.room !== "bibliotheque") { out("Il faut faire la demande à la Bibliothèque (est de la cour).", "sys"); return; }
    if (!x.quest) { say("Bibliothécaire", "Allez voir Maître Ada d'abord."); return; }
    if (x.asked) { out("Tu as déjà le lien d'autorisation.", "sys"); return; }
    x.asked = true; x.state = rnd(); give("lien");
    say("Bibliothécaire", "Je ne vais pas demander son mot de passe à Alice. Je la renvoie vers le Passeport avec cette adresse, qui dit qui je suis, ce que je veux, où renvoyer la réponse, et un état aléatoire de ma session :");
    code(authUrl(REDIR).replace(/&/g, "\n  &").replace("?", "\n  ?"));
    out("Tu prends le lien d'autorisation. Alice, elle, va devoir l'ouvrir au guichet du Passeport (nord de la cour).", "sys");
  }
  function present(c) {
    const x = F();
    const id = resolve(c.target, e => !e.npc && !e.card); if (!id) return;
    if (!S.inv.includes(id)) { out("Tu ne l'as pas sur toi.", "err"); return; }
    if (id === "lien") {
      if (S.room !== "guichet") { out("Le lien d'autorisation se présente au guichet du Passeport (nord de la cour).", "sys"); return; }
      if (x.consent) { out("Alice a déjà consenti : le code est émis.", "sys"); return; }
      say("Chambellan", `Client « biblio », portée « contacts.lecture », adresse de retour enregistrée. Ceci est une demande d'accès aux contacts d'Alice. Alice, te connectes-tu avec TON mot de passe du Palais (que seul moi connais) et acceptes-tu ? Tu joues Alice : \`accepter\` ou \`refuser\`.`);
      x.presented = true;
    } else if (id === "jeton") {
      if (S.room !== "bureau") { out("Le jeton se présente à l'Archiviste, au Bureau des contacts (ouest de la cour).", "sys"); return; }
      const r = apiCheck(x.token);
      if (r.ok) {
        x.apiOk = true;
        say("Archiviste", "Jeton reçu, signature valide, portée contacts.lecture : voici les contacts d'Alice.");
        code("[ Bob, Carla, Dave, Éloïse ]");
        out("Tout le flux a fonctionné sans que la Bibliothèque ne voie jamais le mot de passe d'Alice.", "ok");
        note("code"); fig("flux");
      } else say("Archiviste", "Refusé : " + r.why + ".");
    } else out("Ça ne se présente à personne ici.", "sys");
  }
  function consent(c) {
    const x = F();
    if (S.room !== "guichet" || !x.presented) { out("Il n'y a rien à accepter pour l'instant.", "sys"); return; }
    if (x.consent) { out("Déjà fait.", "sys"); return; }
    if (c.k === "refuse") { say("Chambellan", "Très bien. Aucun code ne sera émis. (Mais il faut un code pour continuer : `accepter`.)"); return; }
    x.consent = true; x.codeGot = true; x.code = rnd() + rnd(); give("code");
    out("Alice saisit son mot de passe, sur la page du Passeport (pas dans la Bibliothèque), et accepte la portée demandée.", "ok");
    say("Chambellan", "Voici un code d'autorisation, à usage unique, et le state d'origine que je te rends tel quel :");
    code(`${REDIR}?code=${x.code}&state=${x.state}`);
    out("Tu prends le code. Il doit retourner à la Bibliothèque.", "sys"); note("scope");
  }
  function giveFn(item, who) {
    const x = F();
    if (item === "code" && who === "bibliothecaire") {
      if (S.room !== "bibliotheque") return false;
      if (x.token) { out("Déjà échangé.", "sys"); return; }
      out("Le Bibliothécaire vérifie que le state reçu est bien celui de la session d'Alice : identique. Puis, directement avec le Passeport (sans passer par le navigateur), il échange :", "sys");
      code(`POST /token\n  grant_type=authorization_code\n  code=${x.code}\n  client_id=biblio\n  client_secret=••••••••`);
      x.token = mkToken(payload("lecteur"), secret(), "HS256"); give("jeton"); drop("code");
      say("Passeport", "Code valide, client authentifié. Voici un jeton d'accès, valable dix minutes :");
      code(x.token);
      out("Tu prends le jeton. `decoder jeton` te montre ce qu'il contient.", "sys"); note("jwt"); fig("jwt");
      return;
    }
    if (item === "jeton" && who === "archiviste") { present({ target: "jeton" }); return; }
    if (item === "lien" && who === "chambellan") { present({ target: "lien" }); return; }
    return false;
  }
  function decodeCmd(c) {
    const x = F();
    const raw = c.rawArg.trim();
    const tok = /^[\w-]+\.[\w-]+\.[\w-]*$/.test(raw) ? raw : x.token;
    if (!tok) { out("Tu n'as pas de jeton à décoder.", "err"); return; }
    const t = parseToken(tok);
    if (!t) { out("Ce n'est pas un JWT lisible.", "err"); return; }
    out("Décodage du jeton (n'importe qui peut le faire : base64 n'est pas du chiffrement) :", "sys");
    code("header  = " + JSON.stringify(t.head) + "\npayload = " + JSON.stringify(t.body) + "\nsignature = " + (t.s || "(vide)"));
    out("La signature, elle, ne se calcule qu'avec le secret : on ne peut pas la refaire sans lui.", "sys");
    note("jwt");
  }
  function attack(c) {
    const x = F();
    if (S.room !== "essai") { out("Les attaques se rejouent à la salle d'essai (sud de la cour).", "sys"); return; }
    if (!x.apiOk) { out("Parcours d'abord le flux normal, jusqu'aux contacts d'Alice.", "sys"); return; }
    const t = norm(c.rawArg);
    if (/redirect|lien|code/.test(t)) {
      const evil = authUrl(EVIL);
      out("Mallory envoie à Alice un lien presque identique, avec son adresse de retour :", "sys"); code(evil);
      if (!x.redFix) {
        x.redAtt = true;
        out("Le Chambellan ne contrôle pas l'adresse de retour. Alice se connecte et accepte, et le code part chez Mallory :", "err");
        code(`${EVIL}?code=${rnd() + rnd()}&state=${x.state}`);
        out("Mallory échange le code contre un jeton et lit les contacts d'Alice.", "err"); note("redirect"); fig("redir", false);
      } else {
        x.redBlk = true;
        say("Chambellan", "redirect_uri « " + EVIL + " » n'est pas l'adresse enregistrée pour ce client. Demande refusée, aucun code émis.");
        out("L'attaque échoue : le code ne peut partir qu'à l'adresse enregistrée.", "ok"); note("redirect"); fig("redir", true);
      }
    } else if (/csrf|state/.test(t)) {
      out("Mallory démarre un flux avec SON compte, s'arrête avant le retour, et envoie à Alice le lien de retour contenant le code de Mallory :", "sys");
      code(`${REDIR}?code=CODE_DE_MALLORY&state=${rnd()}`);
      if (!x.stateCheck) {
        x.csrfAtt = true;
        out("La Bibliothèque ne compare pas le state : elle échange ce code et lie le compte de MALLORY à la session d'Alice. Tout ce qu'Alice importera ensuite ira dans le catalogue de Mallory.", "err"); note("state");
      } else {
        x.csrfBlk = true;
        say("Bibliothécaire", "Ce state ne correspond à aucune demande lancée depuis cette session. Je rejette le retour.");
        out("L'attaque échoue : sans le state de la session d'Alice, le retour est refusé.", "ok"); note("state");
      }
    } else if (/none|alg/.test(t)) {
      const forged = mkToken(payload("admin"), "", "none");
      out("Mallory fabrique un jeton sans signature, en s'attribuant le rôle admin :", "sys"); code(forged);
      const r = apiCheck(forged);
      if (r.ok) { x.noneAtt = true; out(`L'Archiviste l'accepte (${r.why}). Mallory est admin sur tous les tiroirs.`, "err"); note("alg"); fig("forge", false); }
      else { x.noneBlk = true; say("Archiviste", "Refusé : " + r.why + "."); out("L'attaque échoue.", "ok"); note("alg"); fig("forge", true); }
    } else if (/secret|devine|force/.test(t)) {
      if (!x.sigFix) { out("Inutile de chercher le secret : le serveur ne vérifie même pas la signature. Corrige d'abord ça (Bureau des contacts, `configurer signature`).", "sys"); return; }
      out("Mallory prend un vrai jeton (visible dans le navigateur d'Alice) et teste des secrets courants hors ligne :", "sys");
      const t0 = F().token, tt = parseToken(t0);
      let found = null, n = 0;
      for (const w of WORDS) { n++; if (sigOf(tt.h + "." + tt.p, w) === tt.s) { found = w; break; } }
      if (found) {
        x.secAtt = true;
        out(`Essai ${n} : le secret est « ${found} » ! Avec lui, Mallory signe un faux jeton valide, rôle admin :`, "err");
        code(mkToken(payload("admin"), found, "HS256"));
        out("L'Archiviste l'accepte : la signature est bonne. (Et Mallory n'a eu qu'à lire un jeton, hors ligne, sans jamais déclencher d'alarme.)", "err"); note("secret");
      } else {
        x.secBlk = true;
        out(`${WORDS.length} secrets testés, aucun ne correspond. Il faudrait énumérer ${"≈ 10^36"} combinaisons : hors de portée.`, "ok");
        note("secret");
      }
    } else out("Quelle attaque ? `attaquer redirect` · `attaquer csrf` · `attaquer none` · `attaquer secret`", "err");
  }
  function configure(c) {
    const x = F();
    const t = norm(c.rawArg);
    if (/redirect/.test(t)) {
      if (S.room !== "guichet") { out("Ce réglage appartient au Passeport : va au guichet (nord de la cour).", "sys"); return; }
      if (!x.redAtt) { out("Rien à corriger pour l'instant. Rejoue d'abord l'attaque en salle d'essai pour la comprendre.", "sys"); return; }
      x.redFix = true; out("Le Chambellan compare désormais redirect_uri, caractère par caractère, à l'adresse du registre.", "ok");
    } else if (/state/.test(t)) {
      if (S.room !== "bibliotheque") { out("Ce réglage appartient à l'application cliente : va à la Bibliothèque (est de la cour).", "sys"); return; }
      if (!x.csrfAtt) { out("Rien à corriger pour l'instant : rejoue d'abord l'attaque CSRF.", "sys"); return; }
      x.stateCheck = true; x.csrfFix = true; out("La Bibliothèque lie un state aléatoire à chaque session et le contrôle au retour.", "ok");
    } else if (/signature|alg/.test(t)) {
      if (S.room !== "bureau") { out("Ce réglage appartient au serveur de ressources : va au Bureau des contacts (ouest de la cour).", "sys"); return; }
      if (!x.noneAtt) { out("Rien à corriger pour l'instant : rejoue d'abord l'attaque `none`.", "sys"); return; }
      x.sigFix = true; x.noneFix = true; out("L'Archiviste vérifie maintenant la signature avec son secret, et n'accepte que l'algorithme HS256, quelle que soit la valeur de l'en-tête du jeton.", "ok");
    } else if (/secret/.test(t)) {
      if (S.room !== "bureau") { out("Le secret se change au Bureau des contacts (ouest de la cour) : l'émetteur et le vérificateur le partagent.", "sys"); return; }
      if (!x.secAtt) { out("Rien à corriger pour l'instant : rejoue d'abord l'attaque sur le secret.", "sys"); return; }
      x.secFix = true; out("Nouveau secret : 20 caractères aléatoires. Les jetons déjà émis sont invalidés ; Alice devra refaire le flux, la Bibliothèque reçoit un nouveau jeton automatiquement.", "ok");
      x.token = mkToken(payload("lecteur"), secret(), "HS256");
    } else out("Quel réglage ? `configurer redirect` (guichet) · `configurer state` (Bibliothèque) · `configurer signature` · `configurer secret` (Bureau)", "err");
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Tu as parcouru le flux, puis tu l'as attaqué quatre fois pour mieux le défendre : adresse de retour piégée, CSRF sur le retour, jeton sans signature, secret trop faible. Chaque acteur a son rôle de sécurité : le Passeport contrôle l'adresse, la Bibliothèque le state, l'Archiviste la signature.");
    note("oidc"); debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La clé de voiturier = un jeton d'accès OAuth.** Il ouvre seulement ce que tu as autorisé (la portée, le scope), pour un temps limité, et se révoque sans changer ton mot de passe.");
    out("**Les quatre personnages = les quatre rôles d'OAuth 2.0.** Alice est le propriétaire de ressource, la Bibliothèque le client, le Chambellan le serveur d'autorisation (ex. Google, Microsoft), l'Archiviste le serveur de ressources (l'API).");
    out("**Le lien, le code, puis le jeton = le flux « Authorization Code ».** Le navigateur ne voit passer que le code, à usage unique. Le jeton est échangé en direct entre client et serveur d'autorisation. Aujourd'hui, on y ajoute PKCE, qui protège même les applications sans secret (mobiles, sites en JavaScript).");
    out("**Le state et le redirect_uri.** Deux protections du flux : le state contre le CSRF, la comparaison exacte du redirect_uri contre le vol de code.");
    out("**Le JWT.** Trois parties (en-tête, contenu, signature) en base64url. C'est lisible par tous : n'y mets jamais de secret. Le serveur de ressources vérifie la signature, l'émetteur (iss), le destinataire (aud) et la date d'expiration (exp).");
    out("**alg: none et secret faible.** Deux erreurs classiques : accepter l'algorithme annoncé par le jeton lui-même, et utiliser un secret HS256 devinable. Avec des clés asymétriques (RS256, ES256), le serveur de ressources n'a jamais besoin du secret de l'émetteur.");
    out("**Les simplifications du jeu.** (1) La signature utilise un hachage maison simplifié, pas un vrai HMAC-SHA256. (2) Le flux n'inclut ni PKCE, ni jeton de rafraîchissement, ni expiration réellement contrôlée. (3) OAuth 2.0 seul n'authentifie pas l'utilisateur : « Se connecter avec… » repose sur OpenID Connect (id_token). (4) Les attaques sont simulées et reposent sur des erreurs de configuration, pas sur des failles du protocole.");
    out("Rappel utile : **OAuth délègue un accès limité ; la sécurité dépend de chaque acteur qui contrôle son maillon.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    flux: () => {
      const L = [[50, "Alice"], [160, "Biblio"], [270, "Passeport"], [375, "Contacts"]];
      const row = (y, x1, x2, n, label, c) => AR(x1, y, x2, y, c) + T((x1 + x2) / 2, y - 6, n + " " + label, "f-s");
      return {
        cap: "Le flux « code d'autorisation » : Alice s'authentifie chez le Passeport, jamais chez la Bibliothèque ; le code transite par le navigateur, le jeton non.",
        svg: SVG(330, "Flux OAuth 2.0 code d'autorisation",
          L.map(([x, n]) => R(x - 40, 6, 80, 24) + T(x, 22, n, "f-b") + LN(x, 30, x, 322, "f-dash")).join("") +
          row(62, 50, 160, 1, "importer") + row(98, 160, 270, 2, "demande+state", "f-pub") + row(134, 50, 270, 3, "login+accord", "f-pub") +
          row(170, 270, 160, 4, "code+state", "f-pub") + row(206, 160, 270, 5, "code+secret") + row(242, 270, 160, 6, "jeton", "f-pub") + row(290, 160, 375, 7, "jeton → données"))
      };
    },
    jwt: () => {
      const t = parseToken(F().token) || { h: "eyJhbGciOi…", p: "eyJpc3MiOi…", s: "x9f…" };
      const cut = s => s.length > 11 ? s.slice(0, 10) + "…" : s;
      return {
        cap: "Un JWT, c'est trois morceaux séparés par des points. Les deux premiers se lisent par tous (base64 n'est pas du chiffrement) ; le troisième prouve l'authenticité.",
        svg: SVG(220, "Structure d'un JWT",
          R(8, 20, 120, 40, "f-pub") + T(68, 45, cut(t.h), "ft-pub") + T(134, 45, ".", "f-b") +
          R(140, 20, 130, 40, "f-ok") + T(205, 45, cut(t.p), "ft-ok") + T(276, 45, ".", "f-b") +
          R(282, 20, 130, 40, "f-priv") + T(347, 45, cut(t.s), "ft-priv") +
          T(68, 80, "en-tête", "f-b") + T(68, 97, '{"alg":"HS256"}', "f-s") +
          T(205, 80, "contenu (payload)", "f-b") + T(205, 97, '{"sub":"alice",', "f-s") + T(205, 111, '"scope":"lecture"}', "f-s") +
          T(347, 80, "signature", "f-b") + T(347, 97, "HMAC(secret, 1+2)", "f-s") +
          R(8, 135, 404, 70, "f-bad") + T(210, 158, "Attention : lire le contenu ne demande aucun secret.", "ft-bad") + T(210, 176, "Seule la signature interdit de le modifier.", "") + T(210, 194, "Ne mets jamais de mot de passe dans un jeton.", "f-s"))
      };
    },
    redir: (blocked) => ({
      cap: blocked ? "Le serveur compare redirect_uri à l'adresse enregistrée : le lien piégé est refusé, aucun code n'est émis."
        : "Le serveur renvoie le code à l'adresse fournie dans le lien : Mallory le reçoit et prend la place de la Bibliothèque.",
      svg: SVG(210, "Vol de code par redirect_uri",
        R(8, 30, 90, 46) + T(53, 56, "Alice", "f-b") + R(165, 30, 90, 46) + T(210, 50, "Passeport", "f-b") + T(210, 66, blocked ? "contrôle exact" : "accepte tout", blocked ? "ft-ok f-s" : "ft-bad f-s") +
        AR(98, 53, 165, 53, "f-bad") + T(132, 44, "lien piégé", "ft-bad f-s") +
        (blocked ? R(322, 30, 90, 46, "f-ok") + T(367, 56, "refusé ✔", "ft-ok f-b") + AR(255, 53, 322, 53, "f-dash f-ln")
          : R(322, 30, 90, 46, "f-bad") + T(367, 50, "Mallory", "ft-bad f-b") + T(367, 66, "reçoit le code", "f-s") + AR(255, 53, 322, 53, "f-bad")) +
        T(8, 110, "redirect_uri enregistré :", "f-s", "start") + T(8, 126, REDIR, "ft-ok", "start") +
        T(8, 152, "redirect_uri du lien piégé :", "f-s", "start") + T(8, 168, EVIL, "ft-bad", "start") +
        T(8, 198, blocked ? "différents → refus" : "non comparés → code envoyé à Mallory", blocked ? "ft-ok" : "ft-bad", "start"))
    }),
    forge: (blocked) => ({
      cap: blocked ? "Le serveur n'accepte que HS256 et recalcule la signature : le jeton forgé est rejeté."
        : "Avec alg: none, le jeton n'a pas de signature. Un serveur qui n'en vérifie aucune l'accepte, même s'il est fabriqué par Mallory.",
      svg: SVG(210, "Jeton forgé avec alg none",
        R(8, 16, 190, 90, "f-ok") + T(103, 36, "jeton légitime", "f-b ft-ok") + T(103, 56, '{"alg":"HS256"}', "f-s") + T(103, 72, '{"role":"lecteur"}', "f-s") + T(103, 92, "signature : valide", "ft-ok f-s") +
        R(222, 16, 190, 90, "f-bad") + T(317, 36, "jeton forgé", "f-b ft-bad") + T(317, 56, '{"alg":"none"}', "f-s") + T(317, 72, '{"role":"admin"}', "f-s") + T(317, 92, "signature : (vide)", "ft-bad f-s") +
        AR(317, 106, 317, 140, blocked ? "f-dash f-ln" : "f-bad") +
        R(222, 140, 190, 54, blocked ? "f-ok" : "f-bad") + T(317, 162, blocked ? "refusé ✔" : "accepté ✘", blocked ? "f-b ft-ok" : "f-b ft-bad") + T(317, 180, blocked ? "signature vérifiée" : "pas de vérification", "f-s"))
    }),
  };

  GAMES.oauth = {
    id: "oauth", order: 4, title: "Le Palais des Passeports", pageTitle: "OAuth Quest", subtitle: "aventure textuelle · OAuth 2.0 et JWT",
    blurb: "Fais circuler une clé de voiturier entre quatre acteurs, puis rejoue quatre attaques pour les corriger.",
    concept: "OAuth 2.0, OpenID Connect, JWT",
    start: "cour", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, give: giveFn, isEnd: () => !!F().end,
    refig(name) { fig(name, name === "redir" ? !!F().redBlk : name === "forge" ? !!F().noneBlk : undefined); },
    figAlias: { flux: ["oauth", "code"], jwt: ["jeton", "token"], redir: ["redirect", "lien"], forge: ["none", "alg"] },
    gate(dest) { if (dest === "essai" && !F().apiOk) { out("La grille de la salle d'essai est fermée à clé. Maître Ada l'ouvrira quand tu auras parcouru le flux normal.", "err"); return true; } return false; },
    help: "Spécifiques : `demander acces` · `presenter lien|jeton` · `accepter` · `donner code a bibliothecaire` · `decoder jeton` · `attaquer redirect|csrf|none|secret` · `configurer redirect|state|signature|secret`",
    verbs: {
      ask: { words: ["demander", "requerir"], run: ask },
      present: { words: ["presenter", "soumettre", "montrer"], run: present },
      accept: { words: ["accepter", "autoriser", "consentir"], run: consent },
      refuse: { words: ["refuser"], run: consent },
      decode: { words: ["decoder", "decode", "lire jeton"], run: decodeCmd },
      attack: { words: ["attaquer", "tester", "simuler", "rejouer"], run: attack },
      config: { words: ["configurer", "regler", "corriger"], run: configure },
    },
    intro() {
      out("Le Palais des Passeports", "title");
      out("Alice voudrait que la Bibliothèque importe ses contacts du Palais, sans donner son mot de passe à la Bibliothèque. Le Palais a inventé pour cela le Passeport : une clé de voiturier numérique, limitée et révocable. Tu vas parcourir le flux, puis rejouer en simulation les attaques de Mallory contre chaque maillon, pour les faire corriger.", "");
    },
  };
})();
