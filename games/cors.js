"use strict";
/* Le Quartier des Douanes : same-origin policy, CORS et CSRF. */
(function () {
  const F = () => f();
  const BANK = "https://banque.port443";
  const APP = "https://appli.port443";
  const EVIL = "https://promo.evil.example";
  const BLOG = "https://blog.banque.port443";
  const PAIRS = [
    [BANK, BANK + "/compte?id=7", true, "Seuls le schéma, l'hôte et le port comptent. Le chemin (/compte) et les paramètres ne changent pas l'origine."],
    [BANK, "http://banque.port443", false, "Le schéma diffère : https contre http. Origines différentes."],
    [BANK, "https://api.banque.port443", false, "L'hôte diffère : api.banque.port443 n'est pas banque.port443, même si c'est un sous-domaine. Origines différentes."],
    [BANK, BANK + ":8443", false, "Le port diffère : 443 (implicite pour https) contre 8443. Origines différentes."],
    [BANK + ":443", BANK, true, "Le port 443 est le port par défaut d'https : écrit ou non, c'est la même origine."],
  ];

  const notes = {
    sop: ["La politique de même origine (SOP)", "Une origine, c'est schéma + hôte + port. Une page ne peut lire (via JavaScript) les réponses que d'une même origine. Cela empêche un site quelconque de lire ta messagerie, ouverte dans un autre onglet."],
    cors: ["CORS : un assouplissement décidé par le serveur", "Un serveur peut autoriser un autre site à lire ses réponses avec l'en-tête Access-Control-Allow-Origin. C'est le navigateur qui applique la règle : le serveur la déclare."],
    wild: ["Le joker * et les cookies ne vont pas ensemble", "Avec * n'importe quel site peut lire la réponse : acceptable pour des données publiques. Pour des données privées (requêtes avec cookies), il faut une origine précise ET Access-Control-Allow-Credentials: true. Le navigateur refuse la combinaison * + credentials."],
    preflight: ["La requête préliminaire (preflight)", "Pour les requêtes « non simples » (PUT, JSON, en-têtes personnalisés), le navigateur envoie d'abord une requête OPTIONS pour demander la permission. La réponse doit autoriser méthode, en-têtes et origine."],
    csrf: ["CSRF : le navigateur joint les cookies tout seul", "Un site piégé peut faire envoyer à ton navigateur une requête vers ta banque, avec ton cookie de session. Il n'a pas besoin de lire la réponse : l'action est déjà faite. CORS ne l'empêche pas."],
    samesite: ["Le cookie SameSite", "SameSite=Lax (défaut des navigateurs modernes) interdit d'envoyer le cookie dans une requête POST venue d'un autre site. C'est la première défense. Mais un site « same-site » (un sous-domaine compromis) passe encore."],
    token: ["Jeton CSRF et contrôle de l'Origin", "Un jeton secret imprévisible, inclus dans chaque formulaire légitime, ou la vérification de l'en-tête Origin, bloquent même une requête venue d'un sous-domaine. Le jeton marche grâce à la SOP : le site piégé ne peut pas lire la page de la banque pour le copier."],
    depth: ["Combiner les défenses", "SOP, CORS bien réglé, SameSite, jeton CSRF, contrôle de l'Origin : chacun couvre un cas que les autres laissent passer. Et ne jamais mettre * ni refléter n'importe quelle Origin sur une API privée."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, qui supervise les douanes de Port-443." },
    capitaine: { npc: true, names: ["capitaine", "douanier", "navigateur"], label: "le Capitaine des douanes (le navigateur)", desc: () => "Le Capitaine, au képi impeccable : il représente le NAVIGATEUR. Il décide, pour chaque page, ce qui a le droit de traverser la frontière." },
    greffier: { npc: true, names: ["greffier", "serveur", "douanier serveur"], label: "le Greffier de l'API (le serveur)", desc: () => "Le Greffier de l'API de la banque. Il tamponne les réponses avec des en-têtes. Le navigateur lira ces tampons pour décider." },
    banquier: { npc: true, names: ["banquier", "banque"], label: "le Banquier", desc: () => "Le Banquier de la banque.port443. Alice est connectée : son cookie de session est dans son navigateur." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, dont la page « Promo gratuite » est en réalité piégée." },
    reglages: { names: ["reglages", "en tete", "tampons", "headers", "panneau"], label: "le panneau de réglages", vis: () => S.room === "douane",
      desc: () => `Réglages de l'API de la banque :\n  Access-Control-Allow-Origin      : ${F().acao || "(aucun)"}\n  Access-Control-Allow-Credentials : ${F().acac || "(aucun)"}\n\`definir origine ‹valeur›\` · \`definir credentials true|false\`\nPuis tester : \`envoyer ‹origine› ‹chemin›\`. Chemins : /taux (public), /solde (privé, avec cookie).\nOrigines : ${APP} (appli d'Alice), ${EVIL} (site piégé).` },
    defenses: { names: ["defenses", "coffre", "securite"], label: "le tableau des défenses", vis: () => S.room === "guichet",
      desc: () => { const x = F(); return `Défenses de la banque contre les requêtes forgées :\n  samesite (cookie SameSite=Lax) : ${x.samesite ? "ACTIVÉ" : "désactivé"}\n  token (jeton CSRF dans les formulaires) : ${x.token ? "ACTIVÉ" : "désactivé"}\n  origin (contrôle de l'en-tête Origin) : ${x.originCheck ? "ACTIVÉ" : "désactivé"}\n\`defendre samesite|token|origin\``; } },
  };

  const rooms = {
    poste: { name: "Le poste-frontière", short: "Poste", alias: ["poste", "frontiere"], ents: ["ada", "capitaine"], exits: { nord: "douane", est: "guichet", sud: "piege", ouest: "blog" },
      desc: () => "Au carrefour de cinq quartiers, le poste-frontière du Capitaine. Au nord, la douane de l'API. À l'est, le guichet de la banque. Au sud, la page « Promo gratuite ». À l'ouest, le blog de la banque." },
    douane: { name: "La douane de l'API", short: "Douane", alias: ["douane", "api"], ents: ["greffier", "reglages"], exits: { sud: "poste" },
      desc: () => "Un comptoir où le Greffier tamponne chaque réponse de l'API de la banque avec des en-têtes. Le Capitaine ne laissera la page d'un autre site lire une réponse que si les tampons l'y autorisent." },
    guichet: { name: "Le guichet de la banque", short: "Guichet", alias: ["guichet", "banque"], ents: ["banquier", "defenses"], exits: { ouest: "poste" },
      desc: () => "Le guichet de banque.port443. Alice est connectée : son navigateur détient un cookie de session, que la banque reconnaît à chaque requête, y compris les virements (POST /virement)." },
    piege: { name: "La page « Promo gratuite »", short: "Promo gratuite", alias: ["piege", "promo"], ents: ["mallory"], exits: { nord: "poste" },
      desc: () => "Une page criarde : « GAGNEZ UN VOYAGE ! ». Derrière le bouton se cache un formulaire invisible qui, au clic, envoie un virement vers la banque. Tu peux jouer Alice qui clique : `cliquer`." },
    blog: { name: "Le blog de la banque", short: "Blog", alias: ["blog"], ents: [], exits: { est: "poste" },
      desc: () => "blog.banque.port443 : un blog de la banque, hébergé sur un sous-domaine, dont un commentaire a été piégé (une faille XSS). Il est « du même site » que la banque, mais ce n'est pas la même origine. `cliquer` pour jouer Alice qui lit le commentaire." },
  };

  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if ((x.sop || 0) < PAIRS.length) return "sop";
    if (!x.pubOk) return "pub";
    if (!x.privOk) return "priv";
    if (!x.evilBlk) return "evil";
    if (!x.csrfAtt) return "csrf";
    if (!x.samesite) return "samesite";
    if (!x.piegeBlk) return "blk1";
    if (!x.blogAtt) return "blog";
    if (!x.token && !x.originCheck) return "tok";
    if (!x.blogBlk) return "blk2";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada est au poste-frontière.", "`parler ada`"],
    sop: () => ["Réponds aux questions du Capitaine : les deux adresses ont-elles la même origine ? (schéma + hôte + port)", "`parler capitaine`, puis `dire meme` ou `dire different`."],
    pub: () => ["À la douane (nord), règle l'API pour que l'appli d'Alice puisse lire des données publiques (/taux), puis teste.", "`aller nord`, `definir origine *`, `envoyer https://appli.port443 /taux`."],
    priv: () => ["Pour les données privées (avec cookie), il faut une origine précise et l'autorisation d'envoyer les identifiants.", `\`definir origine ${APP}\`, \`definir credentials true\`, \`envoyer ${APP} /solde\`.`],
    evil: () => ["Vérifie que le site piégé ne peut PAS lire le solde d'Alice.", `\`envoyer ${EVIL} /solde\``],
    csrf: () => ["Mallory ne veut pas lire : elle veut agir. Joue Alice sur la page piégée (sud du poste).", "`aller sud`, `aller sud`, `cliquer`."],
    samesite: () => ["Le CORS n'a rien arrêté. Il faut agir côté cookie : à la banque (est du poste).", "`aller nord`, `aller est`, `defendre samesite`."],
    blk1: () => ["Rejoue l'attaque pour voir si la parade tient.", "`aller ouest`, `aller sud`, `cliquer`."],
    blog: () => ["Mallory a un plan B : un commentaire piégé sur le blog de la banque, qui est « du même site ».", "`aller nord`, `aller ouest`, `cliquer`."],
    tok: () => ["SameSite ne suffit pas contre un sous-domaine. Ajoute un jeton CSRF ou le contrôle de l'Origin à la banque.", "`aller est`, `aller est`, `defendre token`."],
    blk2: () => ["Retourne au blog piégé vérifier.", "`aller ouest`, `aller ouest`, `cliquer`."],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  function pairText(i) { const p = PAIRS[i]; return `Paire ${i + 1}/${PAIRS.length} :\n  A = ${p[0]}\n  B = ${p[1]}\nMême origine ? \`dire meme\` ou \`dire different\`.`; }
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; x.sop = 0;
          say("Maître Ada", "Alice utilise son appli (appli.port443) pour consulter son solde à la banque (api.banque.port443). Et un jour, de l'argent a disparu après un clic sur une pub. Pour comprendre, il faut connaître les règles du navigateur : la politique de même origine, CORS, et ce qu'elles ne couvrent PAS.");
          say("Maître Ada", "Le Capitaine des douanes représente le navigateur. Va le voir : il te posera cinq questions.");
        } else if (x.end) say("Maître Ada", "Les douanes de Port-443 sont à jour. Bon travail !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas terminé. `indice` si tu bloques.");
        break;
      case "capitaine":
        if (!x.quest) say("Capitaine", "Maître Ada voudrait vous voir d'abord.");
        else if ((x.sop || 0) < PAIRS.length) {
          if (!x.sop) say("Capitaine", "Une origine, c'est la combinaison d'un schéma (https), d'un hôte (banque.port443) et d'un port (443). Je ne laisse une page lire les réponses d'une autre que si les deux ont la même origine. À toi de juger les paires que je te présente.");
          out(pairText(x.sop || 0), "sys");
        } else say("Capitaine", "Tu connais la règle. Les pages ne lisent librement que leur propre origine. Sauf si le serveur le leur autorise explicitement : c'est CORS.");
        break;
      case "greffier":
        say("Greffier", "Par défaut, je ne tamponne rien : le Capitaine empêchera toute page d'une autre origine de lire mes réponses. Pour autoriser une origine, je pose un tampon Access-Control-Allow-Origin. Pour que les cookies soient pris en compte, j'ajoute Access-Control-Allow-Credentials. Règle-moi avec `definir`.");
        break;
      case "banquier":
        say("Banquier", "Je reçois des requêtes avec le cookie de session d'Alice. Je ne sais pas, moi, si c'est elle qui a cliqué ou une page piégée : je vois juste le cookie. Que puis-je vérifier de plus ? `defendre ...`.");
        break;
      case "mallory":
        say("Mallory", "Bonjour ! Un voyage gratuit, ça vous tente ? Il suffit de cliquer. (`cliquer`)");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  function sayCmd(txt) {
    const x = F();
    if (S.room !== "poste" || !x.quest || (x.sop || 0) >= PAIRS.length) { out(txt ? "Personne ne réagit." : "Dire quoi ?", "sys"); return; }
    const same = /^(meme|identique|oui|same)/.test(txt), diff = /^(different|differente|non|diff)/.test(txt);
    if (!same && !diff) { out("Réponds par `dire meme` ou `dire different`.", "err"); return; }
    const p = PAIRS[x.sop];
    if (same === p[2]) {
      out(`Exact. ${p[3]}`, "ok"); x.sop++;
      if (x.sop >= PAIRS.length) { say("Capitaine", "Cinq sur cinq. Retiens : seule l'origine compte, pas le chemin."); note("sop"); fig("origine"); }
      else out(pairText(x.sop), "sys");
    } else { say("Capitaine", "Non. " + p[3]); out(pairText(x.sop), "sys"); }
  }

  function define(c) {
    const x = F();
    if (S.room !== "douane") { out("Les réglages sont à la douane de l'API (nord du poste).", "sys"); return; }
    const m = c.rawArg.match(/^(origine|origin|credentials|identifiants)\s+(\S+)$/i);
    if (!m) { out("`definir origine ‹valeur›` ou `definir credentials true|false`", "err"); return; }
    if (/^orig/i.test(m[1])) { x.acao = m[2]; out(`Access-Control-Allow-Origin : ${m[2]}`, "ok"); }
    else { x.acac = m[2].toLowerCase() === "true" ? "true" : "false"; out(`Access-Control-Allow-Credentials : ${x.acac}`, "ok"); }
  }
  function decide(origin, path) {
    const x = F();
    if (path === "/taux") {
      if (x.acao === "*" || x.acao === origin) return { ok: true, why: "origine autorisée pour une lecture publique (sans cookies)" };
      return { ok: false, why: x.acao ? `l'en-tête autorise « ${x.acao} », pas « ${origin} »` : "aucun en-tête Access-Control-Allow-Origin dans la réponse" };
    }
    if (!x.acao) return { ok: false, why: "aucun en-tête Access-Control-Allow-Origin dans la réponse" };
    if (x.acao === "*") return { ok: false, why: "le navigateur refuse « * » pour une requête avec cookies : il faut une origine précise", wild: true };
    if (x.acao !== origin) return { ok: false, why: `l'en-tête autorise « ${x.acao} », pas « ${origin} »` };
    if (x.acac !== "true") return { ok: false, why: "il manque Access-Control-Allow-Credentials: true pour lire une réponse à une requête avec cookies" };
    return { ok: true, why: "origine exacte + credentials autorisés" };
  }
  function send(c) {
    const x = F();
    if (S.room !== "douane") { out("Les tests se font à la douane de l'API (nord du poste).", "sys"); return; }
    const parts = c.rawArg.trim().split(/\s+/);
    const origin = parts[0], path = parts[1];
    if (!origin || !/^https?:\/\//.test(origin) || !["/taux", "/solde"].includes(path)) { out(`\`envoyer ‹origine› ‹chemin›\`, par exemple : envoyer ${APP} /taux  (chemins : /taux, /solde)`, "err"); return; }
    const r = decide(origin, path), cred = path === "/solde";
    out(`Une page de ${origin} appelle GET ${path}${cred ? " avec les cookies d'Alice" : ""} :`, "sys");
    code(`Requête  : Origin: ${origin}${cred ? "\n           Cookie: session=…" : ""}\nRéponse  : Access-Control-Allow-Origin: ${x.acao || "(absent)"}${cred ? "\n           Access-Control-Allow-Credentials: " + (x.acac || "(absent)") : ""}`);
    if (r.ok) {
      out(`Le Capitaine laisse la page LIRE la réponse : ${r.why}.`, "ok");
      if (path === "/taux") { x.pubOk = true; note("cors"); fig("cors", false); }
      else if (origin === APP) { x.privOk = true; note("wild"); note("preflight"); fig("cors", false); }
    } else {
      out(`Le Capitaine empêche la page de LIRE la réponse : ${r.why}.`, "err");
      out("(La requête a bien été envoyée au serveur : seul l'accès à la réponse est bloqué.)", "sys");
      if (r.wild) { note("wild"); }
      if (cred && origin === EVIL && x.acao === APP && x.acac === "true") { x.evilBlk = true; note("cors"); fig("cors", true); }
    }
  }

  function bankPost(origin, sameSite) {
    const x = F();
    const cookie = !x.samesite || sameSite;
    code(`POST ${BANK}/virement  (to=mallory, montant=500)\nOrigin: ${origin}\nCookie: ${cookie ? "session=…" : "(non envoyé : SameSite=Lax)"}\nCSRF-token: ${x.token ? "(absent)" : "(non exigé)"}`);
    if (!cookie) return { ok: false, why: "le navigateur n'a pas joint le cookie : requête POST venue d'un autre site, interdit par SameSite=Lax" };
    if (x.token) return { ok: false, why: "jeton CSRF manquant : le site piégé ne peut pas lire la page de la banque (SOP) pour le copier" };
    if (x.originCheck && origin !== BANK) return { ok: false, why: `en-tête Origin « ${origin} » différent de la banque : la requête est rejetée` };
    return { ok: true };
  }
  function click() {
    const x = F();
    if (S.room !== "piege" && S.room !== "blog") { out("Il n'y a rien sur quoi cliquer ici.", "sys"); return; }
    if (!x.privOk || !x.evilBlk) { out("Termine d'abord le réglage de CORS à la douane : tu verras ainsi que CORS ne suffit pas.", "sys"); return; }
    const blog = S.room === "blog";
    out(blog ? "Alice lit un commentaire piégé sur le blog de la banque. Un script, injecté par une faille XSS, envoie une requête à la banque :" : "Alice, connectée à sa banque dans un autre onglet, clique sur « GAGNEZ UN VOYAGE ». Le formulaire invisible se soumet :", "sys");
    const r = bankPost(blog ? BLOG : EVIL, blog);
    if (r.ok) {
      out("**500 pièces d'or virées vers Mallory.** La banque a vu une requête avec un cookie valide d'Alice et l'a crue.", "err");
      if (blog) { x.blogAtt = true; out("SameSite n'a rien changé : le blog est « du même site » que la banque, donc le cookie part. Il faut vérifier que la requête vient bien de la banque elle-même.", "err"); }
      else {
        x.csrfAtt = true; note("csrf"); fig("csrf", false);
        out("Pourtant CORS est parfaitement réglé ! C'est que CORS limite la LECTURE des réponses ; ici Mallory n'a pas besoin de lire : l'action est déjà faite. Il faut protéger la banque autrement (`defendre ...` au guichet).", "err");
      }
    } else {
      out("Virement refusé : " + r.why + ".", "ok");
      if (blog) { x.blogBlk = true; note("token"); fig("defenses"); } else { x.piegeBlk = true; note("samesite"); fig("csrf", true); }
    }
  }
  function defend(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "guichet") { out("Les défenses se règlent au guichet de la banque (est du poste).", "sys"); return; }
    if (/same/.test(t)) {
      if (!x.csrfAtt) { out("Rien à corriger pour l'instant : rejoue d'abord l'attaque (page « Promo gratuite »).", "sys"); return; }
      if (x.samesite) { out("Déjà activé.", "sys"); return; }
      x.samesite = true; out("Le cookie de session est désormais SameSite=Lax : il ne part plus dans une requête POST venue d'un autre site.", "ok");
    } else if (/token|jeton|csrf/.test(t)) {
      if (!x.blogAtt) { out("Rien à corriger pour l'instant : rejoue d'abord l'attaque depuis le blog.", "sys"); return; }
      if (x.token) { out("Déjà activé.", "sys"); return; }
      x.token = true; out("Chaque formulaire légitime contient maintenant un jeton aléatoire lié à la session ; la banque rejette tout POST sans ce jeton.", "ok");
    } else if (/origin/.test(t)) {
      if (!x.blogAtt) { out("Rien à corriger pour l'instant : rejoue d'abord l'attaque depuis le blog.", "sys"); return; }
      if (x.originCheck) { out("Déjà activé.", "sys"); return; }
      x.originCheck = true; out("La banque vérifie désormais l'en-tête Origin de chaque POST : seule sa propre origine est acceptée.", "ok");
    } else out("Quelle défense ? `defendre samesite` · `defendre token` · `defendre origin`", "err");
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Tu as vu que le navigateur protège la lecture (SOP, CORS), pas l'envoi : un site piégé peut toujours faire partir une requête avec les cookies de la victime. Les défenses doivent donc être côté serveur : SameSite, jeton CSRF, contrôle de l'Origin.");
    note("depth"); debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le poste-frontière et le Capitaine = la politique de même origine du navigateur.** Une origine (schéma + hôte + port) est comme un pays : une page n'y lit que ce qui vient de chez elle. C'est ce qui empêche un onglet quelconque de lire ta messagerie dans un autre.");
    out("**Les tampons du Greffier = les en-têtes CORS.** Le serveur indique quelles origines peuvent lire ses réponses. Une API publique peut mettre *. Une API qui utilise des cookies doit nommer l'origine exacte (jamais refléter n'importe quelle Origin) et ajouter Allow-Credentials. Le préflight (OPTIONS) vérifie en amont les méthodes et en-têtes non simples.");
    out("**« La requête est partie, seule la lecture est bloquée. »** C'est le point le plus mal compris : CORS ne protège pas le serveur. Le navigateur envoie la requête, il refuse seulement de montrer la réponse au script de l'autre site.");
    out("**La page « Promo gratuite » = CSRF (Cross-Site Request Forgery).** Les cookies sont joints automatiquement par le navigateur, quel que soit le site qui déclenche la requête. Un formulaire caché peut donc agir en ton nom. Pas besoin de lire la réponse.");
    out("**SameSite, jeton CSRF, contrôle de l'Origin.** SameSite=Lax bloque l'envoi du cookie dans les POST inter-sites. Le jeton CSRF (secret aléatoire par session) et le contrôle de l'Origin couvrent aussi les cas « same-site » (sous-domaine compromis, XSS). Un XSS sur le site lui-même, lui, contourne tout cela : voir le jeu sur les injections.");
    out("**Les simplifications du jeu.** (1) Les requêtes sont simulées et l'API n'a qu'un seul réglage CORS pour tous les chemins. (2) Les en-têtes Vary: Origin, Access-Control-Allow-Methods/Headers et Max-Age ne sont pas détaillés. (3) Le blog « same-site » illustre le cas limite de SameSite, mais les navigateurs gèrent aussi des listes de suffixes publics et des cookies Strict. (4) Les attaques sont simulées : ne teste que ce qui t'appartient.");
    out("Rappel utile : **le navigateur contrôle qui lit ; seul le serveur peut contrôler qui agit.**", "ok");
  }

  const figs = {
    origine: () => ({
      cap: "L'origine, c'est le schéma, l'hôte et le port. Le chemin et les paramètres ne comptent pas.",
      svg: SVG(150, "Anatomie d'une origine",
        R(8, 30, 70, 38, "f-pub") + T(43, 54, "https://", "ft-pub f-b") + R(82, 30, 170, 38, "f-pub") + T(167, 54, "api.banque.port443", "ft-pub f-b") + R(256, 30, 50, 38, "f-pub") + T(281, 54, ":443", "ft-pub f-b") +
        R(310, 30, 102, 38) + T(361, 54, "/solde?id=7", "f-b") +
        `<path d="M8,76 H306" class="f-ln f-pub"/>` + T(157, 98, "origine = schéma + hôte + port", "ft-pub") +
        T(43, 126, "schéma", "f-s") + T(167, 126, "hôte", "f-s") + T(281, 126, "port", "f-s") + T(361, 126, "ignoré", "f-s"))
    }),
    cors: (blocked) => ({
      cap: blocked ? "Le serveur n'autorise pas l'origine du site piégé : le navigateur refuse de montrer la réponse au script (la requête, elle, est partie)."
        : "Le serveur répond avec Access-Control-Allow-Origin : le navigateur laisse le script lire la réponse.",
      svg: SVG(210, "Fonctionnement de CORS",
        R(8, 20, 130, 50) + T(73, 40, blocked ? "site piégé" : "appli d'Alice", "f-b") + T(73, 58, blocked ? "promo.evil.example" : "appli.port443", "f-s") +
        R(282, 20, 130, 50) + T(347, 40, "API banque", "f-b") + T(347, 58, "api.banque.port443", "f-s") +
        AR(138, 36, 282, 36) + T(210, 30, "requête + Origin", "f-s") + AR(282, 56, 138, 56, blocked ? "f-bad" : "f-pub") + T(210, 76, "réponse + tampon CORS", "f-s") +
        R(8, 110, 404, 80, blocked ? "f-bad" : "f-ok") +
        T(210, 134, blocked ? "Allow-Origin : appli.port443  ≠  promo.evil.example" : "Allow-Origin : appli.port443  =  origine de la page", blocked ? "ft-bad" : "ft-ok") +
        T(210, 158, blocked ? "✘ le navigateur CACHE la réponse au script" : "✔ le navigateur MONTRE la réponse au script", blocked ? "ft-bad f-b" : "ft-ok f-b") +
        T(210, 178, "(c'est le navigateur qui applique la règle)", "f-s"))
    }),
    csrf: (blocked) => ({
      cap: blocked ? "La banque ne reçoit plus le cookie (ou refuse la requête sans jeton) : le virement forgé échoue."
        : "Le navigateur joint le cookie à toute requête vers la banque, même déclenchée par un autre site. Mallory n'a pas besoin de lire la réponse.",
      svg: SVG(230, "Attaque CSRF",
        R(8, 20, 100, 50) + T(58, 40, "Alice", "f-b") + T(58, 58, "cookie banque", "f-s") +
        R(160, 20, 100, 50, "f-bad") + T(210, 40, "page piégée", "f-b ft-bad") + T(210, 58, "form. caché", "f-s") +
        R(312, 20, 100, 50) + T(362, 40, "Banque", "f-b") + T(362, 58, "/virement", "f-s") +
        AR(108, 45, 160, 45) + T(134, 36, "clic", "f-s") + AR(260, 45, 312, 45, "f-bad") + T(286, 36, "POST", "f-s") +
        AR(362, 70, 362, 120, blocked ? "f-dash f-ln" : "f-bad") +
        R(222, 120, 190, 52, blocked ? "f-ok" : "f-bad") + T(317, 142, blocked ? "refusé ✔" : "500 pièces virées ✘", blocked ? "ft-ok f-b" : "ft-bad f-b") + T(317, 160, blocked ? "pas de cookie / pas de jeton" : "cookie joint automatiquement", "f-s") +
        T(210, 206, blocked ? "la banque contrôle de qui vient la requête" : "CORS n'intervient pas : rien à lire", "f-s"))
    }),
    defenses: () => ({
      cap: "Chaque défense couvre un cas que les autres laissent passer. Combiner est la règle.",
      svg: SVG(210, "Défenses contre le CSRF",
        T(8, 20, "défense", "f-b", "start") + T(230, 20, "site piégé", "f-b", "start") + T(330, 20, "sous-domaine", "f-b", "start") +
        LN(8, 28, 412, 28) +
        T(8, 56, "SameSite=Lax", "", "start") + T(260, 56, "✔", "ft-ok f-b") + T(360, 56, "✘", "ft-bad f-b") +
        T(8, 92, "jeton CSRF", "", "start") + T(260, 92, "✔", "ft-ok f-b") + T(360, 92, "✔", "ft-ok f-b") +
        T(8, 128, "contrôle de l'Origin", "", "start") + T(260, 128, "✔", "ft-ok f-b") + T(360, 128, "✔", "ft-ok f-b") +
        T(8, 164, "CORS seul", "", "start") + T(260, 164, "✘", "ft-bad f-b") + T(360, 164, "✘", "ft-bad f-b") +
        T(210, 198, "SameSite d'abord, puis jeton ou Origin en plus", "f-s"))
    }),
  };

  GAMES.cors = {
    id: "cors", order: 7, title: "Le Quartier des Douanes", pageTitle: "CORS Quest", subtitle: "aventure textuelle · SOP, CORS et CSRF",
    blurb: "Joue le navigateur à la frontière, règle les en-têtes CORS, puis découvre ce que CORS ne protège pas.",
    concept: "Same-Origin Policy, CORS, CSRF",
    start: "poste", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, say: sayCmd, debrief, isEnd: () => !!F().end,
    refig(name) { fig(name, name === "cors" ? !!F().evilBlk && !F().pubFirst : name === "csrf" ? !!F().piegeBlk : undefined); },
    figAlias: { origine: ["origin", "url"], cors: ["en tete", "headers"], csrf: ["cookie", "piege"], defenses: ["samesite", "token"] },
    help: "Spécifiques : `dire meme|different` · `definir origine|credentials ‹valeur›` · `envoyer ‹origine› ‹chemin›` · `cliquer` · `defendre samesite|token|origin`",
    verbs: {
      define: { words: ["definir", "header", "entete"], run: define },
      send: { words: ["envoyer", "tester", "requete"], run: send },
      click: { words: ["cliquer", "visiter", "ouvrir"], run: click },
      defend: { words: ["defendre", "proteger", "securiser"], run: defend },
    },
    intro() {
      out("Le Quartier des Douanes", "title");
      out("Alice consulte son solde depuis une appli web, connectée à sa banque. Un jour, de l'argent disparaît après un clic sur une publicité. Personne n'a volé son mot de passe, ni forcé aucun serveur : le navigateur, qui joint les cookies tout seul, a fait ce qu'on lui demandait.\nMaître Ada t'envoie au poste-frontière de Port-443 pour comprendre les règles du navigateur (même origine, CORS), et surtout ce qu'elles ne protègent pas.", "");
    },
  };
})();
