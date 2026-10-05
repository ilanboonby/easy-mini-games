"use strict";
/* La Citadelle des Tickets : Kerberos (AS, TGS, tickets, authentificateurs). */
(function () {
  const F = () => f();
  const LIST = ["port443", "password", "azerty", "123456", "motdepasse", "citadelle", "soleil", "bonjour", "qwerty", "letmein", "admin", "passeport"];
  const strong = pw => pw.length >= 12 && !LIST.includes(pw.toLowerCase());
  const bad = pw => !strong(pw);

  const notes = {
    sso: ["Pourquoi Kerberos ?", "Dans un réseau d'entreprise, on veut s'authentifier une fois le matin, puis accéder à plusieurs services (fichiers, messagerie…) sans retaper son mot de passe, et sans que chaque service connaisse ce mot de passe. Kerberos fait cela avec des tickets."],
    kdc: ["Le KDC : un tiers de confiance", "Le centre de distribution de clés (KDC) connaît la clé secrète de chaque utilisateur et de chaque service. Il comporte deux parties : le serveur d'authentification (AS) et le serveur de tickets (TGS)."],
    pwkey: ["Le mot de passe ne voyage jamais", "Le mot de passe sert à dériver une clé sur ta machine. Le KDC renvoie une réponse que seule cette clé peut ouvrir : si tu l'ouvres, c'est que tu connais le mot de passe. Rien de secret n'est envoyé."],
    tgt: ["Le TGT : ton « passe de la journée »", "Le Ticket-Granting Ticket est scellé avec la clé du KDC : tu ne peux pas le lire ni le modifier, mais tu le présentes au TGS pour obtenir d'autres tickets, sans retaper ton mot de passe. Il vient avec une clé de session pour toi."],
    tgs: ["Le ticket de service", "Pour accéder à un service, tu demandes au TGS un ticket scellé avec la clé du service (que tu ne peux pas lire). Le TGS te donne aussi une clé de session entre toi et ce service."],
    auth: ["L'authentificateur", "À chaque présentation d'un ticket, tu joins un authentificateur : ton nom et l'heure, scellés avec la clé de session. Il prouve que tu possèdes la clé de session et que la demande est fraîche."],
    clock: ["L'horloge : tolérance de 5 minutes", "Les horodatages sont vérifiés : si ton horloge dérive de plus de 5 minutes par rapport à celle du serveur, la demande est refusée. C'est pourquoi tout un domaine Kerberos doit être synchronisé (NTP)."],
    mutual: ["Authentification mutuelle", "Le service prouve aussi son identité : il renvoie l'heure de ton authentificateur (+1), scellée avec la clé de session. Seul un vrai service, qui a pu ouvrir le ticket, connaît cette clé."],
    offline: ["Deviner le mot de passe hors ligne", "Un attaquant qui capture la réponse du KDC peut essayer des mots de passe à volonté, hors ligne, sans alerter personne. Seuls un mot de passe long et aléatoire (ou une phrase de passe) résistent."],
    replay: ["Le rejeu", "Rejouer un message capturé échoue : l'authentificateur est daté et vérifié (fenêtre de 5 minutes, cache anti-rejeu), et sans la clé de session on ne peut pas en fabriquer un neuf. Le ticket seul ne suffit pas."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, qui a arraché un contrat d'audit à la Citadelle." },
    cerbere: { npc: true, names: ["cerbere", "kdc", "chien", "gardien porte"], label: "Cerbère, le chien à trois têtes (KDC)", desc: () => "Cerbère, un molosse à trois têtes qui garde la porte. C'est le centre de distribution de clés : il connaît la clé secrète de chacun et de chaque service. Une tête reçoit les connexions (AS), une autre délivre les tickets (TGS)." },
    scribe: { npc: true, names: ["scribe", "tgs", "greffier"], label: "le Scribe des tickets (TGS)", desc: () => "Le Scribe des tickets est la deuxième tête de Cerbère : il délivre un ticket pour un service à qui présente un TGT valide." },
    gardien: { npc: true, names: ["gardien", "grenier", "service"], label: "le Gardien du Grenier (service)", desc: () => "Le Gardien du Grenier, qui conserve les registres de la Citadelle. Il n'ouvre qu'à qui présente un ticket scellé avec SA clé." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, qui capte tout ce qui circule dans la taverne : tous les messages de la Citadelle passent par ici." },
    mdp: { names: ["mot de passe", "mdp", "password"], label: "ton mot de passe", desc: () => `Ton mot de passe : « ${F().pw} ». Il ne sera JAMAIS envoyé sur le réseau : on s'en sert seulement pour dériver une clé, sur ta machine.` },
    tgt: { names: ["tgt", "ticket tgt", "passe"], label: "ton TGT (scellé)", desc: () => "Un TGT : un coffret scellé avec la clé de Cerbère. Tu ne peux pas l'ouvrir. Il prouve au TGS que Cerbère t'a déjà authentifié." },
    enveloppe: { names: ["enveloppe", "enveloppe 1", "reponse"], label: "une enveloppe scellée avec ta clé", desc: () => "Une enveloppe scellée avec la clé dérivée de ton mot de passe. Elle contient ta clé de session K1 : `utiliser mot de passe sur enveloppe`." },
    cle1: { names: ["cle 1", "cle1", "k1", "cle de session 1"], label: "la clé de session K1", desc: () => "La clé de session K1, partagée entre toi et le TGS : elle scelle tes authentificateurs auprès du TGS." },
    auth: { names: ["authentificateur", "authenticator"], label: "ton authentificateur", desc: () => { const a = F().authObj; return a ? `Ton authentificateur : « alice, ${a.t} », scellé avec la clé ${a.k}.` : "Pas d'authentificateur pour l'instant."; } },
    ticket: { names: ["ticket", "ticket grenier", "ticket de service"], label: "le ticket du Grenier (scellé)", desc: () => "Le ticket pour le Grenier : scellé avec la clé du Grenier, donc illisible pour toi. Le Gardien saura l'ouvrir." },
    enveloppe2: { names: ["enveloppe 2", "enveloppe2", "reponse 2"], label: "une enveloppe scellée avec K1", desc: () => "Une enveloppe scellée avec K1. Elle contient K2, ta clé de session avec le Grenier : `utiliser cle 1 sur enveloppe 2`." },
    cle2: { names: ["cle 2", "cle2", "k2", "cle de session 2"], label: "la clé de session K2", desc: () => "K2, la clé de session partagée entre toi et le Grenier." },
    horloge: { names: ["horloge", "montre"], label: "", vis: () => true, desc: () => clockText() },
  };
  function clockText() { return F().clockOK ? "Ta montre : 14:00. L'horloge de la Citadelle : 14:00. Synchronisées." : "Ta montre : 14:12. L'horloge de la Citadelle : 14:00. Écart : 12 minutes."; }

  const rooms = {
    cour: { name: "La cour de la Citadelle", short: "Cour", alias: ["cour", "citadelle"], ents: ["ada", "horloge"], exits: { nord: "porte", est: "tickets", ouest: "grenier", sud: "taverne" },
      desc: () => "Une grande cour entourée de remparts. Au nord, la porte gardée par Cerbère. À l'est, la salle des tickets. À l'ouest, le Grenier où l'on range les registres. Au sud, la taverne, où tout le monde parle trop fort." },
    porte: { name: "La porte de la Citadelle", short: "Porte", alias: ["porte"], ents: ["cerbere"], exits: { sud: "cour" },
      desc: () => "Une lourde porte, un chien à trois têtes assis devant. Cerbère connaît chaque habitant·e par sa clé secrète, et chaque service par la sienne." },
    tickets: { name: "La salle des tickets", short: "Tickets", alias: ["tickets", "ticket"], ents: ["scribe"], exits: { ouest: "cour" },
      desc: () => "Une salle de pupitres. Le Scribe y délivre des tickets, un par service, à qui présente un passe de la journée valide." },
    grenier: { name: "Le Grenier", short: "Grenier", alias: ["grenier"], ents: ["gardien"], exits: { est: "cour" },
      desc: () => "Un grenier immense, des registres jusqu'au plafond. Le Gardien ne laisse entrer que les porteurs de ticket valide." },
    taverne: { name: "La taverne du Dragon", short: "Taverne", alias: ["taverne"], ents: ["mallory"], exits: { nord: "cour" },
      desc: () => "Bruyante et enfumée. Tous les messages de la Citadelle transitent par là. Mallory, au fond, écoute tout et prend des notes." },
  };

  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.asTgt) return "tgt";
    if (!S.inv.includes("cle1") && !x.tgsDone) return "open1";
    if (!x.tgsDone) return x.authObj && x.authObj.k === "K1" ? "tgs" : "auth1";
    if (!S.inv.includes("cle2") && !x.service) return "open2";
    if (!x.service) return x.authObj && x.authObj.k === "K2" ? "present" : "auth2";
    if (!x.crackAtt) return "crack";
    if (!x.pwFix) return "pw";
    if (!x.crackBlk) return "crack2";
    if (!x.replay) return "replay";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend dans la cour.", "`parler ada`"],
    tgt: () => ["Pour commencer, tu t'annonces à Cerbère (nord de la cour), la tête qui authentifie.", "`aller nord`, puis `demander tgt`."],
    open1: () => ["Cerbère t'a donné une enveloppe scellée avec ta clé. Seul ton mot de passe l'ouvre.", "`utiliser mot de passe sur enveloppe`"],
    auth1: () => ["Pour obtenir un ticket de service, il faut le TGT et un authentificateur scellé avec K1, à la salle des tickets (est de la cour).", "`aller sud`, `aller est`, `fabriquer authentificateur`."],
    tgs: () => ["Demande maintenant le ticket du Grenier au Scribe. Si l'heure ne va pas, corrige-la.", "`demander ticket grenier` (si l'horloge est fausse : `synchroniser`, puis `fabriquer authentificateur` à nouveau)."],
    open2: () => ["Le Scribe t'a donné une enveloppe scellée avec K1. Ouvre-la avec la clé que tu as.", "`utiliser cle 1 sur enveloppe 2`"],
    auth2: () => ["Va au Grenier (ouest de la cour) avec le ticket, et fabrique un authentificateur scellé avec K2.", "`aller ouest` (depuis la cour), puis `fabriquer authentificateur`."],
    present: () => ["Présente le ticket et l'authentificateur au Gardien.", "`presenter ticket`"],
    crack: () => ["Tout fonctionne. Va à la taverne (sud de la cour) : Mallory a tout écouté. Voyons si ton mot de passe tient face à elle.", "`aller sud`, `ecouter`, puis `attaquer mdp`."],
    pw: () => ["Ton mot de passe est trop faible. Va le changer auprès de Cerbère (nord de la cour) : choisis une phrase de passe d'au moins 12 caractères qui n'est pas un mot courant.", "`aller nord`, `aller nord`, puis `changer mdp ‹ta phrase de passe›` (ex. changer mdp le chien a trois tetes)."],
    crack2: () => ["Retourne voir si Mallory y arrive encore.", "`aller sud`, `aller sud`, puis `attaquer mdp`."],
    replay: () => ["Dernière tentative de Mallory : rejouer un message que tu as envoyé au Grenier.", "`rejouer`"],
    end: () => ["Rends compte à Maître Ada.", "`aller nord`, puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; x.pw = "port443"; give("mdp");
          say("Maître Ada", "Bienvenue à la Citadelle. Chaque matin, des centaines d'employé·e·s accèdent à une dizaine de services : le Grenier, la Forge, la Chancellerie. Taper un mot de passe devant chacun serait infernal, et chaque service connaîtrait ce mot de passe. La Citadelle utilise donc Kerberos : on s'identifie UNE fois auprès de Cerbère, qui distribue des tickets.");
          say("Maître Ada", "Ton rôle : obtenir un accès au Grenier en suivant la procédure, puis voir ce que Mallory peut en faire. Voici ton mot de passe : « port443 ». Les clés se dérivent de lui, et il ne doit jamais circuler.");
          note("sso"); out("Commence par Cerbère (`aller nord`).", "sys");
        } else if (x.end) say("Maître Ada", "La Citadelle est plus solide. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "Ce n'est pas fini. `indice` si tu bloques.");
        break;
      case "cerbere":
        if (!x.asTgt) say("Cerbère", "Je suis le KDC. Une tête me parle, c'est moi qui authentifie : demande-moi un TGT : `demander tgt`.");
        else say("Cerbère", "Tu as ton TGT. Pour obtenir un ticket pour un service, va voir mon autre tête, le Scribe, à la salle des tickets.");
        break;
      case "scribe":
        if (!x.asTgt) say("Scribe", "Il me faut un TGT. Passe d'abord voir Cerbère.");
        else say("Scribe", "Je délivre un ticket par service. Présente-moi ton TGT avec un authentificateur frais, scellé avec ta clé de session K1 : `fabriquer authentificateur` puis `demander ticket grenier`.");
        break;
      case "gardien":
        say("Gardien", "Je n'ouvre qu'à qui me présente un ticket scellé avec MA clé, accompagné d'un authentificateur frais scellé avec la clé de session que nous partageons. `presenter ticket`.");
        break;
      case "mallory":
        if (!x.service) say("Mallory", "Je ne fais que passer. Reviens quand tu auras un accès : j'aime regarder les gens s'authentifier.");
        else say("Mallory", "J'ai tout entendu passer : la réponse de Cerbère, ton authentificateur, ton ticket. Je ne peux rien lire directement, tout est scellé. `ecouter` pour voir ce que j'ai capté, `attaquer mdp` pour que j'essaie, `rejouer` pour que je tente ma chance au Grenier.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function ask(c) {
    const x = F(), t = norm(c.target);
    if (/tgt|passe/.test(t)) {
      if (S.room !== "porte") { out("Le TGT se demande à Cerbère (nord de la cour).", "sys"); return; }
      if (!x.quest) { out("Va d'abord voir Maître Ada.", "sys"); return; }
      x.asTgt = true; x.pwAtAS = x.pw; give("tgt"); give("enveloppe");
      say("Toi → Cerbère", "Je suis alice. Voici l'heure, scellée avec ma clé dérivée de mon mot de passe (preuve que je le connais). Je ne l'envoie pas.");
      say("Cerbère", "Je connais la clé d'Alice : je sais ouvrir ça. Voici deux choses : un TGT scellé avec MA clé (tu ne peux pas le lire), et une enveloppe scellée avec TA clé qui contient ta clé de session K1.");
      out("Tu reçois un TGT et une enveloppe. L'enveloppe ne s'ouvre qu'avec ton mot de passe.", "ok"); note("pwkey"); fig("flux");
    } else if (/ticket|grenier/.test(t)) {
      if (S.room !== "tickets") { out("Les tickets se demandent au Scribe (salle des tickets, est de la cour).", "sys"); return; }
      if (!S.inv.includes("tgt") || !S.inv.includes("cle1")) { say("Scribe", "Il me faut ton TGT, et tu dois avoir ouvert l'enveloppe de Cerbère pour détenir K1."); return; }
      if (!x.authObj || x.authObj.k !== "K1") { say("Scribe", "Pas d'authentificateur scellé avec K1. `fabriquer authentificateur`."); return; }
      if (x.authObj.t !== "14:00") {
        say("Scribe", `Authentificateur daté de ${x.authObj.t}, mon horloge indique 14:00 : écart de 12 minutes, la tolérance est de 5. Refusé : je ne peux pas distinguer une demande fraîche d'un message rejoué.`);
        out("Ton horloge est décalée. `synchroniser`, puis refais ton authentificateur.", "err"); note("clock"); fig("horloge", false); return;
      }
      x.tgsDone = true; give("ticket"); give("enveloppe2"); drop("auth"); x.authObj = null;
      say("Scribe", "TGT valide (je sais l'ouvrir : il est scellé avec ma clé), authentificateur frais et cohérent. Voici le ticket du Grenier, scellé avec la clé du Grenier, et une enveloppe scellée avec K1 qui contient la clé de session K2.");
      out("Tu reçois le ticket et une enveloppe. Ouvre-la avec K1 : `utiliser cle 1 sur enveloppe 2`.", "ok"); note("tgs"); note("auth"); fig("tickets");
    } else out("Que demander ? `demander tgt` (Cerbère) ou `demander ticket grenier` (Scribe).", "err");
  }
  function make() {
    const x = F();
    let k = null;
    if (S.room === "tickets") k = S.inv.includes("cle1") ? "K1" : null;
    else if (S.room === "grenier") k = S.inv.includes("cle2") ? "K2" : null;
    else { out("Un authentificateur se fabrique juste avant de le présenter : à la salle des tickets (clé K1) ou au Grenier (clé K2).", "sys"); return; }
    if (!k) { out(`Tu n'as pas la clé de session nécessaire (${S.room === "tickets" ? "K1" : "K2"}).`, "err"); return; }
    x.authObj = { k, t: x.clockOK ? "14:00" : "14:12" }; give("auth");
    out(`Tu écris « alice, ${x.authObj.t} » (l'heure de TA montre) et tu le scelles avec ${k}.`, "ok");
  }
  function sync() {
    const x = F();
    if (x.clockOK) { out("Ta montre est déjà à l'heure.", "sys"); return; }
    x.clockOK = true; x.authObj = null; drop("auth");
    out("Tu remets ta montre à 14:00, l'heure de la Citadelle. Ton ancien authentificateur est périmé : refais-le.", "ok"); note("clock"); fig("horloge", true);
  }
  function present(c) {
    const x = F();
    if (S.room !== "grenier") { out("Le ticket se présente au Gardien du Grenier (ouest de la cour).", "sys"); return; }
    if (!S.inv.includes("ticket")) { say("Gardien", "Pas de ticket, pas d'entrée."); return; }
    if (!x.authObj || x.authObj.k !== "K2") { say("Gardien", "Il me faut aussi un authentificateur frais scellé avec K2 : `fabriquer authentificateur`."); return; }
    if (x.authObj.t !== "14:00") { say("Gardien", "Ton authentificateur est daté de 14:12 : refusé. `synchroniser`, puis refais-le."); return; }
    x.service = true; drop("auth");
    say("Gardien", "Ticket ouvert avec ma clé : il vient bien de Cerbère, il est pour moi et ton nom est alice. L'authentificateur est scellé avec K2, la clé de session qu'il contient, et son heure est fraîche. Entre.");
    say("Gardien → toi", "Et voici la preuve que je suis le vrai Grenier : « 14:01 », scellé avec K2. Seul un service qui sait ouvrir le ticket connaît K2.");
    out("Tu vérifies : c'est bien l'heure de ton authentificateur, +1. Le service est authentique.", "ok");
    out("Tu es dans le Grenier. Tout le parcours a fonctionné sans que ton mot de passe ne circule.", "ok"); note("mutual"); fig("flux");
  }
  function listen() {
    if (S.room !== "taverne") { out("Il y a de quoi écouter à la taverne (sud de la cour).", "sys"); return; }
    if (!F().service) { say("Mallory", "Il ne s'est encore rien passé d'intéressant."); return; }
    out("Mallory te montre ses notes : ce qu'elle a capté dans la taverne.", "sys");
    code("AS-REQ   : alice, horodatage chiffré\nAS-REP   : [TGT scellé]  [enveloppe scellée avec la clé d'alice]\nTGS-REQ  : [TGT]  [authentificateur K1]\nTGS-REP  : [ticket Grenier]  [enveloppe K1]\nAP-REQ   : [ticket]  [authentificateur K2]\nAP-REP   : [14:01 scellé K2]");
    out("Tout est scellé. Mais l'enveloppe de l'AS-REP est scellée avec une clé dérivée de TON mot de passe : Mallory peut essayer des mots de passe hors ligne jusqu'à ce que ça s'ouvre. `attaquer mdp`.", "sys");
  }
  function attack(c) {
    const x = F();
    if (S.room !== "taverne") { out("Mallory est à la taverne (sud de la cour).", "sys"); return; }
    if (!x.service) { say("Mallory", "Je n'ai encore rien capté."); return; }
    if (!/mdp|mot|password|devin/.test(norm(c.rawArg))) { out("Quelle attaque ? `attaquer mdp`. (Pour le rejeu : `rejouer`.)", "err"); return; }
    out("Mallory prend l'enveloppe de l'AS-REP et dérive une clé pour chaque mot de passe courant de son dictionnaire, hors ligne :", "sys");
    const hit = LIST.indexOf(x.pw.toLowerCase());
    if (bad(x.pw) && (hit >= 0 || x.pw.length <= 8 || LIST.some(w => x.pw.toLowerCase().includes(w)))) {
      const n = hit >= 0 ? hit + 1 : LIST.length + 7;
      x.crackAtt = true;
      out(`Essai ${n} : l'enveloppe s'ouvre. Ton mot de passe est « ${x.pw} ». Mallory a la clé, donc K1, et peut demander des tickets à ta place !`, "err");
      note("offline"); fig("offline", false);
      out("Mallory ne t'a même pas laissé de trace : elle n'a jamais touché la Citadelle. Il faut changer de mot de passe : Cerbère, au nord.", "err");
    } else if (!x.crackAtt) {
      out("Ton mot de passe est déjà assez fort : sa liste ne contient pas la solution. (Pour comprendre l'attaque, remets d'abord un mot de passe faible avec `recommencer`, ou continue.)", "sys");
    } else {
      x.crackBlk = true;
      out(`${LIST.length} mots de passe testés, puis ${"10 000 000"} variantes : rien. Avec une phrase de passe de plus de 12 caractères, ce serait des siècles.`, "ok");
      note("offline"); fig("offline", true);
    }
  }
  function changePw(c) {
    const x = F();
    if (S.room !== "porte") { out("Le mot de passe se change auprès de Cerbère (nord de la cour).", "sys"); return; }
    const m = c.rawArg.match(/^(?:mdp|mot de passe|password)\s+(.+)$/i);
    if (!m) { out("`changer mdp ‹ta phrase de passe›`", "err"); return; }
    if (!x.crackAtt) { say("Cerbère", "Ton mot de passe a-t-il déjà été compromis ? Tu n'as pas de raison d'en changer pour l'instant."); return; }
    if (bad(m[1])) { say("Cerbère", "Trop faible : il faut au moins 12 caractères, et pas un mot courant. Une phrase de passe fait très bien l'affaire."); return; }
    x.pw = m[1]; x.pwFix = true;
    say("Cerbère", "C'est noté : ta clé est dérivée de la nouvelle phrase. Les anciennes captures de Mallory ne servent plus à rien.");
  }
  function replay() {
    const x = F();
    if (S.room !== "taverne") { out("Mallory est à la taverne (sud de la cour).", "sys"); return; }
    if (!x.service) { say("Mallory", "Je n'ai rien à rejouer."); return; }
    if (!x.crackBlk) { say("Mallory", "J'ai mieux à faire : d'abord, mon dictionnaire (`attaquer mdp`)."); return; }
    out("Mallory se rend au Grenier avec le ticket et l'authentificateur capturés (daté 14:00), et les présente au Gardien quelques minutes plus tard :", "sys");
    x.replay = true;
    say("Gardien", "Ce ticket est valide. Mais cet authentificateur, je l'ai déjà vu passer : refusé. Et sans K2 tu ne peux pas en fabriquer un neuf.");
    out("Le ticket seul ne suffit pas : l'authentificateur est à usage unique (daté, mémorisé), et Mallory n'a pas la clé de session pour en forger un.", "ok");
    note("replay"); fig("tickets");
  }
  function useFn(key) {
    const x = F();
    if (key === "enveloppe+mdp") {
      if (x.pw !== x.pwAtAS) { out("Ce mot de passe n'est plus celui avec lequel la réponse a été scellée.", "err"); return; }
      drop("enveloppe"); give("cle1");
      out("Tu dérives ta clé du mot de passe (en local) et tu ouvres l'enveloppe : dedans, la clé de session **K1**. Si tu avais tapé un autre mot de passe, la clé aurait été différente et l'enveloppe serait restée illisible.", "ok"); note("kdc"); note("tgt");
      return;
    }
    if (key === "cle1+enveloppe2") {
      drop("enveloppe2"); give("cle2");
      out("Tu ouvres l'enveloppe avec K1 : dedans, la clé de session **K2**, partagée entre toi et le Grenier.", "ok");
      return;
    }
    return false;
  }
  function timeCmd() { out(clockText(), "sys"); }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Tu as obtenu l'accès au Grenier sans que ton mot de passe ne traverse la Citadelle, tu as mis en évidence la faiblesse du mot de passe lui-même, et vu pourquoi le rejeu échoue. Voilà Kerberos : un tiers de confiance, des clés de session et des tickets.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La Citadelle = un domaine Kerberos (par exemple Active Directory).** **Cerbère = le KDC**, avec ses deux « têtes » : l'AS (Authentication Server), qui authentifie, et le TGS (Ticket-Granting Server), qui délivre les tickets. Le nom Kerberos vient de Cerbère, le chien à trois têtes (client, KDC, service).");
    out("**Les enveloppes scellées = le chiffrement symétrique.** Chaque clé est connue de deux parties seulement : toi et le KDC (clé dérivée de ton mot de passe), le KDC et le service (clé du service), toi et le TGS (K1), toi et le service (K2). Le KDC les connaît toutes : s'il est compromis, tout l'est (d'où la protection du compte krbtgt).");
    out("**Le TGT et le ticket de service.** Ils sont scellés avec une clé que TU ne connais pas : tu les transportes sans pouvoir les lire ni les modifier. Ils contiennent ton identité, une durée de validité et la clé de session.");
    out("**L'authentificateur et l'horloge.** Ton nom et l'heure, scellés avec la clé de session : il prouve que tu détiens la clé et que la demande est fraîche. D'où la tolérance de 5 minutes et la synchronisation horaire (NTP) obligatoire.");
    out("**Mallory et ses attaques.** (1) Deviner le mot de passe hors ligne à partir de la réponse du KDC (AS-REP roasting, ou capture du trafic) : la parade est une phrase de passe longue. (2) Le rejeu : inefficace grâce aux horodatages et au cache anti-rejeu. Elle n'a jamais besoin de casser le chiffrement lui-même.");
    out("**Les simplifications du jeu.** (1) Les clés sont des objets : en vrai ce sont des clés AES et les messages contiennent d'autres champs (durée de vie, adresses, PAC). (2) La pré-authentification est résumée en une phrase. (3) On n'a pas vu la délégation, la renégociation, ni les attaques qui visent les services (Kerberoasting) ou la clé du KDC (golden ticket). (4) En vrai, le TGT dure environ 10 heures.");
    out("Rappel utile : **ton mot de passe ne voyage jamais ; ce qui circule, ce sont des tickets que seuls les bons destinataires savent lire.**", "ok");
  }

  const figs = {
    flux: () => {
      const L = [[55, "Toi"], [210, "KDC"], [365, "Grenier"]];
      const row = (y, x1, x2, n, label, c) => AR(x1, y, x2, y, c) + T((x1 + x2) / 2, y - 6, n + " " + label, "f-s");
      return {
        cap: "Kerberos en six messages : l'AS authentifie (1-2), le TGS délivre le ticket (3-4), puis le service vérifie et se prouve à son tour (5-6). Ton mot de passe ne sort jamais.",
        svg: SVG(310, "Flux Kerberos",
          L.map(([x, n]) => R(x - 36, 6, 72, 24) + T(x, 22, n, "f-b") + LN(x, 30, x, 302, "f-dash")).join("") +
          row(64, 55, 210, 1, "AS-REQ : alice") + row(100, 210, 55, 2, "TGT + clé K1", "f-pub") +
          row(148, 55, 210, 3, "TGT + authentif.") + row(184, 210, 55, 4, "ticket + K2", "f-pub") +
          row(232, 55, 365, 5, "ticket + authentificateur") + row(272, 365, 55, 6, "heure+1 (mutuel)", "f-pub") +
          T(210, 128, "──── plus de mot de passe ────", "f-s"))
      };
    },
    tickets: () => ({
      cap: "Chaque élément est scellé avec une clé précise. Tu transportes le TGT et le ticket sans pouvoir les lire : seuls le KDC et le service les ouvrent.",
      svg: SVG(230, "Qui peut lire quoi",
        R(8, 10, 195, 48, "f-bad") + T(105, 30, "TGT", "f-b") + T(105, 47, "scellé : clé du KDC", "f-s ft-bad") +
        R(217, 10, 195, 48, "f-bad") + T(315, 30, "ticket Grenier", "f-b") + T(315, 47, "scellé : clé du Grenier", "f-s ft-bad") +
        R(8, 80, 195, 48, "f-pub") + T(105, 100, "enveloppe K1", "f-b") + T(105, 117, "scellée : ta clé (mdp)", "f-s ft-pub") +
        R(217, 80, 195, 48, "f-pub") + T(315, 100, "enveloppe K2", "f-b") + T(315, 117, "scellée : K1", "f-s ft-pub") +
        R(8, 150, 404, 64, "f-ok") + T(210, 172, "authentificateur : « alice, heure »", "f-b") + T(210, 192, "scellé : K1 (TGS) ou K2 (service)", "f-s ft-ok") + T(210, 207, "à usage unique : pas rejouable", "f-s"))
    }),
    horloge: (ok) => ({
      cap: ok ? "Montre synchronisée : l'écart est dans la tolérance, la demande est acceptée."
        : "Ta montre avance de 12 minutes : au-delà de la tolérance de 5 minutes, le serveur refuse l'authentificateur.",
      svg: SVG(150, "Dérive d'horloge",
        LN(20, 70, 400, 70) + T(20, 56, "heure", "f-s", "start") +
        `<rect x="150" y="58" width="60" height="24" rx="4" fill="var(--ok)" opacity=".25"/>` + T(180, 100, "tolérance ±5 min", "ft-ok f-s") +
        LN(180, 52, 180, 88, "f-ok") + T(180, 44, "Citadelle 14:00", "f-s") +
        (ok ? LN(180, 52, 180, 88, "f-ok") + T(180, 124, "ta montre : 14:00 ✔", "ft-ok f-b")
          : LN(330, 52, 330, 88, "f-bad") + T(330, 44, "ta montre 14:12", "ft-bad f-s") + AR(180, 70, 330, 70, "f-bad") + T(255, 124, "écart 12 min > 5 → refusé", "ft-bad f-b")))
    }),
    offline: (strongPw) => ({
      cap: strongPw ? "Contre une phrase de passe longue, la liste de Mallory ne contient jamais la solution : l'énumération est hors de portée."
        : "Mallory teste hors ligne des mots de passe courants sur la réponse capturée. Un mot de passe faible tombe en quelques essais, sans alerte.",
      svg: SVG(180, "Devinette hors ligne",
        R(8, 20, 110, 50, "f-bad") + T(63, 40, "dictionnaire", "f-b") + T(63, 58, "port443, azerty…", "f-s") +
        AR(118, 45, 160, 45) + R(160, 20, 110, 50) + T(215, 40, "dériver une clé", "f-b") + T(215, 58, "pour chaque mot", "f-s") +
        AR(270, 45, 312, 45) + R(312, 20, 100, 50) + T(362, 40, "ouvrir", "f-b") + T(362, 58, "l'enveloppe ?", "f-s") +
        T(210, 110, strongPw ? "aucune clé ne marche : phrase de passe longue" : "une clé marche : mot de passe retrouvé", strongPw ? "ft-ok f-b" : "ft-bad f-b") +
        T(210, 134, strongPw ? "(il faudrait ≈ 10^30 essais)" : "(en quelques essais)", "f-s") +
        T(210, 164, "Tout se passe hors ligne : le KDC ne voit rien.", "f-s"))
    }),
  };

  GAMES.kerberos = {
    id: "kerberos", order: 5, title: "La Citadelle des Tickets", pageTitle: "Kerberos Quest", subtitle: "aventure textuelle · Kerberos",
    blurb: "Obtiens un accès au Grenier sans que ton mot de passe ne circule : TGT, tickets, authentificateurs.",
    concept: "Kerberos, tickets, SSO",
    start: "cour", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, use: useFn, isEnd: () => !!F().end,
    refig(name) { fig(name, name === "horloge" ? !!F().clockOK : name === "offline" ? !!F().crackBlk : undefined); },
    figAlias: { flux: ["kerberos", "messages"], tickets: ["tgt", "cles"], horloge: ["heure", "temps"], offline: ["mdp", "mallory"] },
    help: "Spécifiques : `demander tgt|ticket grenier` · `fabriquer authentificateur` · `synchroniser` · `heure` · `presenter ticket` · `ecouter` · `attaquer mdp` · `changer mdp ‹phrase›` · `rejouer`",
    verbs: {
      ask: { words: ["demander", "requerir"], run: ask },
      make: { words: ["fabriquer", "construire", "ecrire", "creer"], run: make },
      sync: { words: ["synchroniser", "regler", "sync"], run: sync },
      time: { words: ["heure", "horloge", "montre"], run: timeCmd },
      present: { words: ["presenter", "montrer", "soumettre"], run: present },
      listen: { words: ["ecouter", "capturer"], run: listen },
      attack: { words: ["attaquer", "deviner", "casser"], run: attack },
      changepw: { words: ["changer", "modifier"], run: changePw },
      replay: { words: ["rejouer", "rejeu"], run: replay },
    },
    intro() {
      out("La Citadelle des Tickets", "title");
      out("La Citadelle de Port-443 abrite dix services : le Grenier, la Forge, la Chancellerie… Taper un mot de passe devant chacun serait infernal, et chacun connaîtrait ce mot de passe. À la porte, un chien à trois têtes, Cerbère, distribue donc des tickets : on s'identifie une seule fois, puis on circule.\nMaître Ada t'engage pour parcourir la procédure, puis observer ce que Mallory, qui écoute tout dans la taverne, peut en faire.", "");
    },
  };
})();
