"use strict";
/* Le Standard Téléphonique : ingénierie sociale, vishing, procédures de vérification.
   Tout est vu du côté de la personne qui REÇOIT l'appel et doit résister. Aucune donnée réelle. */
(function () {
  const F = () => {
    const x = f();
    if (!x.res) Object.assign(x, { res: {}, found: {}, fl: [], leaks: [], procs: [], pol: [], n: 0, l3: {}, nrep: 0, trust: 0, s: {}, cur: null, pend: null, last: null });
    return x;
  };
  const SCN = ["s1", "s3", "s2", "s4", "s5", "s6"];
  const PHONE = ["s1", "s2", "s3", "s6"];
  const has = (t, re) => re.test(t);
  const bar = n => "▮".repeat(n) + "▯".repeat(5 - n);
  const SECRET = "port443-otp-secret";
  const otpOf = (mt, ben, win) => String(parseInt(sha256([SECRET, mt, ben, win].join("|")).slice(0, 8), 16) % 1000000).padStart(6, "0");
  const WIN = 47182;

  const notes = {
    pourquoi: ["Pourquoi l'ingénierie sociale marche", "Au lieu de forcer une machine, on influence une personne. Aucune faille logicielle n'est nécessaire : on exploite des réflexes utiles au quotidien (obéir à une autorité, rendre service, ne pas déranger, faire comme les autres). Ces attaques suivent presque toujours quatre phases : renseignement, prétexte, pression, action. La parade n'est pas de soupçonner tout le monde, mais d'avoir des procédures qui ne dépendent pas de ton humeur ni de ton flair du moment."],
    autorite: ["Autorité et urgence", "Un titre (support technique, direction, banque) et un délai très court forment le duo classique : l'autorité dit « obéis », l'urgence dit « ne réfléchis pas, ne vérifie pas ». Une urgence est donc un signal d'alerte, jamais une raison de sauter une étape. Aucun service légitime n'a besoin de ton mot de passe : le support peut réinitialiser un compte sans le connaître."],
    collecte: ["La collecte progressive d'informations", "Chaque question paraît anodine : qui est responsable de quoi, quel logiciel, quels horaires. Mises bout à bout, les réponses forment un dossier qui rend l'attaque suivante crédible (noms, outils, moments où personne ne vérifie). Ici, la sympathie et le petit service rendu d'abord (réciprocité) font le travail. Parade : ne confirmer aucune information interne à quelqu'un dont l'identité n'est pas vérifiée, et signaler les appels trop curieux."],
    dirigeant: ["L'usurpation de dirigeant (fraude au président)", "Un faux dirigeant, souvent « à l'étranger », demande un virement urgent et confidentiel en contournant les circuits habituels. Le numéro affiché à l'écran peut être falsifié ; une voix peut être imitée. Parades : validation par deux personnes pour tout virement, quel que soit le rang du demandeur ; confirmation par un canal indépendant (rappel sur le numéro connu) ; l'exigence de secret est elle-même un signal d'alerte."],
    tailgating: ["Le talonnage (tailgating)", "Franchir une porte sécurisée derrière quelqu'un qui vient de badger : la politesse et la preuve sociale (« tout le monde le fait ») font le travail. Parades : un badge par personne, on propose poliment l'accueil, les visiteurs sont enregistrés et accompagnés. Refuser est bien plus facile quand c'est la règle de l'organisation, et non ton jugement personnel."],
    usb: ["Les supports USB « trouvés »", "Une clé abandonnée est un appât : une étiquette tentante exploite la curiosité. Brancher un support inconnu peut exécuter du code sur ton poste, depuis l'intérieur du réseau. On ne la branche pas : on la remet à la sécurité, qui l'analyse sur un poste isolé. Bloquer l'exécution automatique et filtrer les ports USB réduit le risque, sans remplacer le réflexe."],
    otp: ["Les codes à usage unique", "Un code reçu par SMS prouve que TOI tu autorises quelque chose. Il ne se communique jamais à un tiers, même à un « conseiller ». Un bon SMS indique ce que le code autorise (montant, bénéficiaire) : lis-le en entier. Aucune banque, aucun support, aucun collègue ne demande ce code : règle simple, sans exception. Les clés de sécurité matérielles (FIDO2) vont plus loin : il n'y a rien à lire à voix haute."],
    rappel: ["Vérifier : le rappel et la question non devinable", "(1) On raccroche et on rappelle sur un numéro de l'annuaire, jamais celui que donne l'appelant. (2) Une question de vérification convenue d'avance, non devinable (pas une date de naissance ni un nom lisible sur un réseau social). (3) La règle « jamais de mot de passe ni de code par téléphone ». (4) Les opérations sensibles se valident à deux. Ces procédures marchent parce qu'elles ne demandent pas de deviner qui ment."],
    culture: ["La culture du signalement sans blâme", "Tout le monde peut se faire avoir un jour. La seule chose à éviter est de se taire. Si signaler fait honte ou est puni, on se tait et l'attaquant gagne des jours. Si signaler est remercié, l'alerte arrive en minutes : la banque peut rappeler un virement, la sécurité isole un poste. Les attaques déjouées se signalent aussi : elles protègent les collègues suivants."],
  };

  const LEV = {
    autorite: ["Autorité", "on obéit à un titre, un rôle, un uniforme"],
    urgence: ["Urgence", "un délai très court empêche de vérifier"],
    rarete: ["Rareté", "une occasion ou une information exclusive, qui ne reviendra pas"],
    reciprocite: ["Réciprocité", "on rend un service à qui nous en a rendu un"],
    sympathie: ["Sympathie", "on aide plus volontiers quelqu'un d'aimable ou de proche"],
    preuve: ["Preuve sociale", "« tout le monde le fait », donc on s'aligne"],
    curiosite: ["Curiosité", "l'envie de savoir ce qu'il y a derrière le secret"],
  };
  const SHORTLEV = { autorite: "on obéit à un titre ou un rôle", urgence: "pas le temps de vérifier", rarete: "occasion exclusive et brève", reciprocite: "on rend un service reçu", sympathie: "on aide qui nous plaît", preuve: "« tout le monde le fait »" };
  const levKey = t => has(t, /autor/) ? "autorite" : has(t, /urgen|press|vite|delai/) ? "urgence" : has(t, /rare|exclusi|penur/) ? "rarete" : has(t, /reciproc|dette|service rendu/) ? "reciprocite" : has(t, /sympath|aimab|charme|gentil/) ? "sympathie" : has(t, /preuve|social|conform|tout le monde/) ? "preuve" : has(t, /curio/) ? "curiosite" : null;

  /* ---------- données des épisodes ---------- */
  const SC = {
    s1: {
      name: "Le technicien pressé", note: "autorite", levers: ["autorite", "urgence"],
      clues: { autorite: "« Kévin du support informatique », « le directeur m'attend » : un titre technique et un nom de chef.", urgence: "« verrouillé dans dix minutes », « plus que quelques minutes » : le temps qu'on t'enlève.", preuve: "« tous tes collègues l'ont déjà fait » : tu serais la seule à résister." },
      phases: [["Un nom de service, un prénom, du jargon", "technique : de quoi sonner « officiel »."], ["Prétexte : une alerte virus sur ton compte,", "un « support » qui vient t'aider."], ["Pression : verrouillage dans dix minutes,", "« tous tes collègues l'ont déjà fait »."], ["Action : te faire dicter ton mot de passe.", "Il ouvrirait tout ce que tu peux ouvrir."]],
      press: [["Kévin", "Allez, il reste huit minutes, après le compte est verrouillé et c'est moi qui devrai expliquer pourquoi au directeur !"], ["Kévin", "Écoute, je n'ai pas que ça à faire. Tous tes collègues l'ont fait sans histoires. Tu veux être celle qui bloque tout l'étage ?"], ["Kévin", "Dernier avertissement : cinq minutes. Ton mot de passe, vite."]],
      rep: { win: "Léa diffuse un message : « Un faux support téléphone et réclame des mots de passe. Ne donnez rien, renvoyez-nous l'appel. » Les collègues suivants seront prévenus.", lose: "Léa fait réinitialiser ton mot de passe, coupe les sessions ouvertes et vérifie le journal : l'attaquant n'a eu que quelques minutes. Elle ne te reproche rien." },
      intro() {
        out("Le standard sonne. Écran : « poste externe, numéro masqué ». Tu décroches.", "sys");
        say("Voix pressée (« Kévin »)", "Bonjour, Kévin du support informatique ! J'ai une alerte rouge sur ton compte : un virus s'y propage et le système va le verrouiller dans dix minutes. Je dois resynchroniser ton accès tout de suite : donne-moi ton mot de passe, je m'en occupe. Tous tes collègues de l'étage sont déjà passés par là, tu es la dernière. Le directeur m'attend, je n'ai pas deux minutes !");
        out("Que fais-tu ? (`demander ‹nom|ticket|question›`, `verifier ‹support›`, `transferer ‹service›`, `donner ‹information›`, `refuser`, `escalader`)", "sys");
        out("(Tu peux aussi `examiner annuaire` ou `examiner classeur` sans raccrocher.)", "sys");
      },
      h(k, t) {
        switch (k) {
          case "give":
            if (has(t, /mot de passe|mdp|password|passe|identifiant|login/)) {
              say("Kévin", "Parfait, c'est reçu ! Je resynchronise… voilà, c'est fait. Tu peux raccrocher, merci !");
              out("Tu as dicté ton mot de passe. Clic : il a raccroché.", "err");
              out("Simulation : journal d'accès de la Guilde (fictif)", "sys");
              code("14:07  connexion  compte « standard »   origine : adresse jamais vue\n14:09  lecture    messagerie partagée (3 boîtes)\n14:12  export     annuaire du personnel");
              out("Rien n'a été « resynchronisé » : il n'y avait ni virus, ni verrouillage. Ton accès sert désormais à quelqu'un d'autre. Si tu signales vite (`escalader`), Léa peut encore limiter les dégâts.", "err");
              F().leaks.push("Mot de passe du compte du standard (épisode 1)");
              finish("s1", "lose", 3);
            } else { say("Kévin", "Non, ce n'est pas ça qu'il me faut : ton mot de passe, vite !"); press("s1"); }
            break;
          case "ask":
            if (has(t, /nom|matricule|ticket|numero|identite|prenom|equipe|badge/)) {
              say("Kévin", "Kévin Marchand, matricule 4471, ticket INC-20931, équipe infrastructure. Tu vois, c'est du sérieux, maintenant le mot de passe !");
              out("Il a répondu du tac au tac. Mais rien de tout cela n'est vérifiable par toi, au téléphone : un nom, un matricule, un numéro de ticket se devinent, se trouvent en ligne ou s'inventent. Une réponse fluide n'est pas une preuve.", "sys");
              bump(1); press("s1");
            } else if (has(t, /question|secret|convenu|code|verification|mot de service/)) {
              say("Kévin", "Euh… cette question-là, je ne l'ai pas sous la main. On n'a vraiment pas le temps pour des chinoiseries !");
              out("Un vrai technicien sait où trouver la question de vérification, ou accepte que tu rappelles. Il esquive : c'est un signal d'alerte.", "ok");
              bump(-2); press("s1");
            } else out("Demander quoi ? `demander nom`, `demander ticket`, `demander question`.", "err");
            break;
          case "verify":
            if (has(t, /support|kevin|technicien|appelant|service|informatique|ticket|it/)) {
              callback("le support informatique", "poste 204", [["Vrai support", "Kévin Marchand ? Il n'y a personne de ce nom chez nous, et le ticket INC-20931 n'existe pas. On ne demande jamais un mot de passe, à personne. Raccroche et signale-le à la sécurité."]]);
              out("Pendant ce temps, l'appelant est tombé sur ta messagerie d'attente. Il a raccroché.", "ok");
              finish("s1", "win", 1);
            } else out("Vérifier qui ? `verifier support` (rappel sur le numéro de l'annuaire).", "err");
            break;
          case "transfer":
            if (has(t, /securite|lea|support|informatique/)) {
              out("Tu dis « je vous passe un collègue qui va s'occuper de votre dossier » et tu transfères vers la sécurité (poste 211).", "sys");
              say("Léa", "Sécurité, bonjour. Qui est à l'appareil ?"); out("Clic : « Kévin » a raccroché.", "ok");
              finish("s1", "win", 2, true);
            } else if (has(t, /compta|bob|accueil|ada|rh/)) out("Passer l'appel à quelqu'un qui n'est pas prévenu, c'est lui refiler le piège. Un appel suspect va à la sécurité : `transferer securite`.", "err");
            else out("Transférer vers quel service ? (`securite`, `support`, `compta`, `accueil`)", "err");
            break;
          case "refuse":
            out("Tu dis calmement : « Je ne communique jamais mon mot de passe par téléphone. »", "sys");
            say("Kévin", "Tu prends un gros risque ! Je note ton refus, c'est toi qui seras responsable si on perd les données !");
            out("Tu restes ferme. Il raccroche. C'est bien : la règle a tenu. Mais tu n'as ni vérifié qui c'était, ni prévenu personne : il va rappeler quelqu'un d'autre. (`escalader` répare cela.)", "ok");
            finish("s1", "win", 2);
            break;
          case "yes": say("Kévin", "Super ! Alors vas-y, ton mot de passe, je note."); out("(Si tu veux vraiment le donner : `donner mot de passe`. Sinon, réfléchis.)", "sys"); bump(1); break;
          case "hello": say("Kévin", "Oui, oui, bonjour ! Alors, ton mot de passe ?"); break;
          case "escalate": escIn("s1", "Tu envoies discrètement un message à Léa (« appel suspect, faux support, mot de passe demandé ») pendant qu'il continue de parler.", "win", 2); break;
          default: out("Il attend toujours ton mot de passe.", "sys");
        }
      },
    },

    s3: {
      name: "L'appel sympathique", note: "collecte", levers: ["sympathie", "reciprocite"],
      clues: { sympathie: "Ton chaleureux, compliments (« vous êtes si aimable »), tutoiement doux : on a envie de lui faire plaisir.", reciprocite: "« Je vous dépanne gratuitement, vous pouvez bien m'aider à votre tour » : un petit service rendu d'abord, une dette ensuite.", preuve: "« Tout le monde m'a répondu sans problème »." },
      phases: [["Un prestataire plausible, un ton chaleureux,", "un petit service rendu d'abord."], ["Prétexte : envoyer une facture, mettre à", "jour un pilote d'impression."], ["Pression douce : sympathie, dette de service", "(« je vous ai dépannée, non ? »)."], ["Action : trois réponses anodines, bout à bout :", "organigramme, outils, horaires."]],
      press: [], rep: { win: "Léa consigne : « Appel de reconnaissance, prestataire fictif, trois questions ». Elle prévient l'accueil et la compta : si Camille rappelle, personne ne répondra.", lose: "Léa note exactement ce qui a été dit, pour que l'équipe sache ce que l'appelante sait déjà. Rien n'est effaçable, mais on peut s'y préparer : les noms et horaires fuités seront surveillés." },
      intro() {
        out("Le standard sonne. Écran : « numéro de société inconnu ». Tu décroches.", "sys");
        say("Camille", "Bonjour ! Camille, de PrintoPort, on s'occupe de l'entretien de vos imprimantes. Oh, mais quelle voix aimable, ça fait plaisir ! Écoutez, j'ai vu à distance que l'imprimante de l'étage bourre : je vous la remets d'aplomb en deux minutes, gratuitement, juste pour vous rendre service.");
        out("Elle « dépanne » quelque chose que tu n'avais pas signalé, mais c'est tout de même sympathique. Puis, avec naturel :", "sys");
        F().s.r = 1; ask3();
      },
      h(k, t) {
        const x = F(), s = x.s, r = s.r;
        const keys = [/organigramme|responsable|chef|achats|nom|equipe/, /logiciel|messagerie|outil|compta|version|systeme/, /horaire|absence|heure|ferm|directeur|semaine/];
        switch (k) {
          case "give": case "yes": {
            const word = k === "yes" ? ["organigramme", "logiciel", "horaires"][r - 1] : t;
            if (!has(word, keys[r - 1])) {
              if (keys.some(re => has(word, re))) out("Elle ne te demande pas cela pour l'instant. Réponds à sa question, ou refuse-la.", "sys");
              else out("Donner quoi ? Ce qu'elle demande : `donner " + ["organigramme", "logiciel", "horaires"][r - 1] + "`.", "sys");
              return;
            }
            const L = [["org", "Mme Roux dirige les achats ; elle dépend de M. Valmont, le directeur", "organigramme (Mme Roux aux achats, sous M. Valmont)"], ["log", "la compta tourne sur ComptaPort 7", "logiciel de compta (ComptaPort 7)"], ["hor", "le standard ferme le vendredi à 16 h et M. Valmont est absent la semaine prochaine", "horaires et absence du directeur"]][r - 1];
            x.l3[L[0]] = true; x.leaks.push(L[2].charAt(0).toUpperCase() + L[2].slice(1) + " (épisode 2)");
            out("Tu réponds de bonne foi : " + L[1] + ".", "sys");
            say("Camille", ["Merci mille fois, vous êtes un amour ! Ça m'évite des mails dans tous les sens.", "Parfait, ça colle avec ma liste. Vous êtes vraiment efficace, on n'a pas toujours cette chance !", "Génial, merci. Voilà, votre imprimante est réparée, et on ne s'est pas trop ennuyées, hein ?"][r - 1]);
            out("Rien de grave en apparence. C'est tout le principe : chaque réponse est inoffensive seule.", "sys");
            bump(1);
            s.r++;
            if (s.r > 3) { out("Elle remercie, raccroche, ravie. Trois réponses banales : tu viens de lui donner un organigramme, un outil et un calendrier.", "err"); finish("s3", "lose", 3); } else ask3();
            break;
          }
          case "ask":
            if (has(t, /pourquoi|contrat|preuve|reference|bon de commande|qui|societe/)) {
              say("Camille", "Oh, ne soyez pas méfiante, voyons ! Je viens de vous dépanner gratuitement, et tout le monde a répondu sans problème. C'est juste pour envoyer la facture au bon endroit.");
              out("Voilà la réciprocité à l'œuvre : « je t'ai aidée, aide-moi ». Une demande légitime peut passer par l'accueil ou par le contrat. Tu peux le proposer : `refuser`, ou vérifier : `verifier camille`.", "sys"); bump(1);
            } else out("Demander quoi ? `demander pourquoi`, `demander contrat`.", "err");
            break;
          case "verify":
            if (has(t, /camille|printoport|prestataire|societe|imprimante|appelante|reprographie/)) {
              callback("PrintoPort (contrat)", "0 800 00 00 18", [["PrintoPort", "Camille ? Pas dans nos équipes de Port-443. Et nous ne dépannons jamais à distance une imprimante sans ticket ouvert par vous. Vous avez bien fait de rappeler."]]);
              out("Camille est tombée sur ta messagerie d'attente. Elle n'a pas rappelé.", "ok");
              finish("s3", Object.keys(x.l3).length ? "partial" : "win", 1);
            } else out("Vérifier qui ? `verifier camille` (rappel sur le numéro du contrat, dans l'annuaire).", "err");
            break;
          case "refuse": case "transfer":
            if (k === "transfer" && !has(t, /accueil|securite|lea/)) { out("Pour un appel qui collecte des informations, le bon destinataire est l'accueil ou la sécurité : `transferer accueil`.", "err"); return; }
            say("Toi", "Je préfère que vous passiez par l'accueil avec une demande écrite : nous ne donnons pas d'informations internes par téléphone.");
            say("Camille", "Oh… très bien, comme vous voulez. (Le ton s'est refroidi.) Bonne journée.");
            out(Object.keys(x.l3).length ? "Tu t'arrêtes à temps, mais une partie du dossier est déjà partie." : "Tu as coupé court dès la première question : rien n'a fuité. Dire non à quelqu'un d'aimable coûte, d'où l'intérêt d'une règle écrite.", Object.keys(x.l3).length ? "sys" : "ok");
            finish("s3", Object.keys(x.l3).length ? "partial" : "win", 2);
            break;
          case "hello": say("Camille", "Bonjour bonjour ! Alors, je reprends ma question."); ask3(); break;
          case "escalate": escIn("s3", "Tu glisses un mot à Léa pendant que Camille enchaîne les compliments : « appel curieux, prestataire inconnu ».", Object.keys(x.l3).length ? "partial" : "win", 2); break;
          default: out("Elle attend ta réponse.", "sys");
        }
      },
    },

    s2: {
      name: "Le directeur à l'étranger", note: "dirigeant", levers: ["autorite", "urgence", "rarete"],
      clues: { autorite: "« C'est M. Valmont » puis « c'est un ordre » : le plus haut de la hiérarchie.", urgence: "« Avant 17 h, c'est maintenant ou jamais » : le temps de vérifier t'est refusé.", rarete: "Un rachat « unique », « strictement confidentiel », dont tu serais l'une des seules informées : l'exclusivité flatte et isole." },
      phases: [["Noms et horaires pris dans des sources", "ouvertes ou dans de précédentes collectes."], ["Prétexte : un rachat confidentiel à l'étranger,", "ligne mauvaise, numéro inhabituel."], ["Pression : fenêtre à 17 h, secret absolu,", "« je compte sur toi, c'est un ordre »."], ["Action : lancer un virement de 48 000 écus,", "hors procédure, vers un compte inconnu."]],
      press: [["Valmont", "Tu perds du temps, la fenêtre se ferme ! Tu veux que je dise au conseil que le rachat a échoué à cause de toi ?"], ["Valmont", "Je suis ton directeur. Il n'y a pas de procédure qui tienne : fais ce que je te dis, et pas un mot à personne."], ["Valmont", "Dernière fois : le virement. Maintenant."]],
      rep: { win: "Léa et Bob consignent l'incident : le vrai M. Valmont est prévenu par son canal habituel. Toute demande de virement « exceptionnelle » sera désormais rappelée.", lose: "Léa appelle la banque immédiatement : une demande de rappel de fonds est lancée dans l'heure. Rien n'est garanti, mais passé 48 heures, les fonds ont déjà été dispersés. Chaque heure compte." },
      intro() {
        const x = F(), l = x.l3;
        out("Le standard sonne. Écran : numéro inhabituel, indicatif lointain. Tu décroches.", "sys");
        let t = "Allô ? C'est Armand Valmont. Je t'appelle de Tokyo, la ligne est mauvaise, ne coupe pas. Je suis en pleine négociation de rachat : c'est strictement confidentiel, personne ne doit être au courant, pas même Bob. Il me faut un virement de 48 000 écus vers le compte de Kaizen-Holdings, avant 17 h, c'est maintenant ou jamais. Tu es la seule en qui j'ai confiance. Je régulariserai les papiers demain.";
        if (l.org) t += " Dis à Mme Roux des achats de ne pas s'inquiéter, elle est au courant.";
        if (l.hor) t += " Je suis absent toute la semaine prochaine de toute façon, et le standard ferme vendredi à 16 h : fais-le tout de suite, ne dérange pas la compta.";
        say("Voix grave (« Armand Valmont »)", t);
        let k = 1 + (l.org ? 1 : 0) + (l.hor ? 1 : 0);
        x.trust = Math.min(5, k);
        if (l.org || l.hor) out("Il connaît le nom de Mme Roux" + (l.hor ? " et le calendrier de la Guilde" : "") + ". Tu te souviens : c'est toi, tout à l'heure, qui as donné ces détails à « Camille ». Ils te rassurent, et c'est exactement leur rôle : voici l'effet d'une collecte d'informations réussie.", "err");
        out("Confiance accordée à ton interlocuteur : " + bar(x.trust) + " (" + x.trust + "/5)", "sys");
        out("Que fais-tu ? (`demander ‹question|pourquoi|justificatif›`, `verifier ‹directeur›`, `transferer ‹compta›`, `donner ‹virement›`, `refuser`, `escalader`)", "sys");
      },
      h(k, t) {
        switch (k) {
          case "give":
            if (has(t, /virement|paiement|ordre|accord|iban|argent|fonds|execut|valid/)) {
              say("Valmont", "Excellent. Je savais que je pouvais compter sur toi. Surtout, pas un mot à personne.");
              out("Tu lances le virement depuis le portail de paiement, sous ta seule signature : aucune seconde validation n'est demandée, car « c'est le directeur ».", "err");
              out("Simulation (fictive) : relevé de la Guilde", "sys");
              code("16:41  VIREMENT  48 000,00 écus  vers  Kaizen-Holdings (compte ouvert il y a 6 jours)\n16:44  DÉPART     fonds transférés vers 2 comptes à l'étranger\nLendemain  M. Valmont (de retour de Lyon) : « Je n'ai appelé personne. »");
              out("Il n'y a jamais eu de rachat. Plus les fonds partent loin, moins on peut les récupérer : `escalader` tout de suite pour que la banque tente un rappel.", "err");
              F().leaks.push("Virement de 48 000 écus exécuté sur ordre téléphonique (épisode 3)");
              finish("s2", "lose", 3);
            } else { say("Valmont", "Le virement ! De quoi parles-tu d'autre ? Fais-le."); press("s2"); }
            break;
          case "ask":
            if (has(t, /question|secret|convenu|code|verification|mot de/)) {
              say("Valmont", "Tu doutes de MOI ? Je suis à l'autre bout du monde, je n'ai pas le temps pour tes devinettes !");
              out("Le vrai M. Valmont a un mot convenu avec la sécurité. Un dirigeant légitime accepte la vérification : il s'énerve plutôt que de répondre, mauvais signe.", "ok"); bump(-2); press("s2");
            } else if (has(t, /pourquoi|compta|bob|procedure|validation|deux|secret/)) {
              say("Valmont", "Parce que ça doit rester entre nous. Les procédures, c'est pour le quotidien : ici c'est exceptionnel.");
              out("Plus l'exception est « exceptionnelle », plus elle doit passer par la procédure. Exiger le secret et l'isolement est la signature de cette fraude.", "ok"); bump(1); press("s2");
            } else if (has(t, /justificatif|facture|ecrit|mail|bon de commande|contrat|papier/)) {
              say("Valmont", "Je te l'envoie plus tard, je t'ai dit que je régulariserais demain !");
              out("Pas de justificatif, pas de bon de commande : c'est précisément ce que la procédure de validation à deux aurait exigé.", "ok"); bump(-1); press("s2");
            } else out("Demander quoi ? `demander question`, `demander pourquoi`, `demander justificatif`.", "err");
            break;
          case "verify":
            if (has(t, /directeur|valmont|armand|appelant|patron|dirigeant/)) {
              callback("le portable professionnel de M. Valmont", "06 00 00 00 12 (fictif)", [["M. Valmont (le vrai)", "Allô ? Je suis à Lyon, en plein conseil d'administration. Tokyo ? Un rachat ? Je n'ai appelé personne. Ne fais rien, préviens la sécurité. Merci d'avoir rappelé !"]]);
              out("Le numéro affiché sur ton écran ne prouvait rien : un numéro se falsifie. Le faux directeur, lui, a raccroché.", "ok");
              finish("s2", "win", 1);
            } else out("Vérifier qui ? `verifier directeur` (rappel sur son numéro de l'annuaire).", "err");
            break;
          case "transfer":
            if (has(t, /compta|bob/)) {
              out("Tu dis « je vous passe la comptabilité » et tu transfères vers Bob (poste 230).", "sys");
              say("Bob", "Bob, comptabilité. 48 000 écus, sans bon de commande, sans seconde validation, sur ordre téléphonique ? Je ne fais rien sans double validation. Je rappelle M. Valmont sur son numéro connu et je préviens la sécurité.");
              out("Clic : le faux directeur a raccroché. Bob applique la règle des deux personnes : un virement hors norme ne part jamais sur une seule voix.", "ok");
              finish("s2", "win", 2, true);
            } else if (has(t, /securite|lea|ada/)) {
              out("Tu transfères à la sécurité (poste 211). Léa prend l'appel, le faux directeur raccroche.", "ok"); finish("s2", "win", 2, true);
            } else out("Transférer vers quel service ? (`compta`, `securite`)", "err");
            break;
          case "refuse":
            out("Tu dis : « Monsieur, je ne peux pas lancer un virement hors procédure, même sur votre ordre. »", "sys");
            say("Valmont", "Tu es renvoyée si ça échoue ! Je l'écrirai dans ton dossier !");
            out("Tu restes ferme. Il raccroche. Bien joué : mais tu n'as ni vérifié ni prévenu : la tentative recommencera sur un autre poste. (`escalader` répare cela.)", "ok");
            finish("s2", "win", 2);
            break;
          case "yes": say("Valmont", "Alors vas-y, lance le virement."); out("(`donner virement` pour le lancer. Mais d'abord, n'y a-t-il pas une procédure ?)", "sys"); bump(1); break;
          case "hello": say("Valmont", "Oui, oui, tu m'entends ? Le virement, vite."); break;
          case "escalate": escIn("s2", "Tu appuies sur le bouton « deuxième personne » : Maître Ada vient s'asseoir à côté de toi. Elle te chuchote : « Raccroche, on rappelle ensemble sur son numéro connu. »", "win", 2); break;
          default: out("Il attend le virement.", "sys");
        }
      },
    },

    s4: {
      name: "La visiteuse au badge oublié", note: "tailgating", levers: ["sympathie", "preuve"],
      clues: { sympathie: "Sourire, bras chargés, plaisanterie : comment refuser à quelqu'un d'aussi charmant et débordé ?", preuve: "Deux collègues passent sans rien dire et l'un lance « laisse, elle est déjà venue » : tout le monde fait pareil, donc ce doit être normal.", urgence: "« Je suis en retard pour la réunion de la direction » : on te presse de ne pas poser de question." },
      phases: [["Repérage de l'heure d'affluence et des", "habitudes (porte tenue par politesse)."], ["Prétexte : bras chargés, badge « au fond", "du sac », réunion avec la direction."], ["Pression : retard, sourire, « ça se fait", "toujours ici », deux collègues passent."], ["Action : franchir la porte sans badge, donc", "sans trace dans le journal des accès."]],
      press: [], rep: { win: "Léa ajoute l'incident au registre et renforce le rappel affiché à la porte : un badge par personne. Elle te remercie : « Le plus dur, c'est de dire non à quelqu'un d'aimable. »", lose: "Léa consulte les caméras et le journal d'accès : une seule entrée enregistrée pour deux personnes. Elle fait inspecter les bureaux de l'étage. Elle ne te reproche rien : la porte s'est ouverte parce que la règle n'était pas assez claire." },
      intro() {
        out("Tu t'approches de la porte sécurisée. Une femme élégante arrive derrière toi, les bras chargés de dossiers, un gobelet de café en équilibre.", "sys");
        say("Visiteuse", "Oh là là, quelle matinée ! Mon badge est au fond de mon sac, je ne peux pas le sortir sans tout lâcher. Tu peux me tenir la porte, s'il te plaît ? Je suis déjà en retard pour la réunion avec la direction !");
        out("Derrière elle, deux employés franchissent le portique sans s'arrêter. L'un lance, en riant : « Laisse, elle est déjà venue. »", "sys");
        out("Que fais-tu ? (`demander ‹badge|nom›`, `verifier ‹reunion›`, `transferer ‹accueil›`, `repondre oui`, `refuser`, `escalader`)", "sys");
      },
      h(k, t) {
        switch (k) {
          case "give": case "yes":
            if (k === "yes" || has(t, /porte|acces|passage|entree|ouvrir|tenir|laisser|badge/)) {
              out("Tu retiens la porte avec le pied. Elle te sourit, passe sans scanner quoi que ce soit : « Merci, tu me sauves ! »", "err");
              out("Simulation (fictive) : journal d'accès", "sys");
              code("09:12  badge Alice   porte principale   ENTRÉE (1 personne enregistrée)\n09:12  (aucun badge)    porte principale   2 passages détectés par la caméra\n09:12 à 09:40  personne inconnue circule dans le couloir des bureaux");
              out("Pendant vingt-huit minutes, quelqu'un circule dans les bureaux sans qu'aucun badge n'y soit associé : on ne saura pas qui c'était, ni ce qu'elle a vu ou photographié.", "err");
              F().leaks.push("Accès physique sans badge accordé à une inconnue (épisode 4)");
              finish("s4", "lose", 3);
            } else out("Donner quoi ? Elle ne te demande qu'une chose : la porte.", "sys");
            break;
          case "ask":
            if (has(t, /badge|nom|qui|identite|invitation|reunion|pass/)) {
              say("Visiteuse", "Mon badge ? Au fond du sac, je te dis ! Je suis du cabinet de conseil, réunion de la direction à 15 h, avec M. Valmont. Tiens, je m'appelle Laurence Marchal.");
              out("Ses réponses sont fluides et plausibles. Mais un badge oublié se règle à l'accueil, pas en tenant une porte : tu ne peux toujours rien vérifier.", "sys"); bump(1);
            } else out("Demander quoi ? `demander badge`, `demander nom`.", "err");
            break;
          case "verify":
            if (has(t, /reunion|direction|visiteuse|valmont|secretariat|femme|invitation|rendez/)) {
              callback("le secrétariat de direction", "poste 201", [["Secrétariat", "Une réunion à 15 h avec un cabinet de conseil ? Non, rien dans l'agenda de M. Valmont, et aucun visiteur annoncé. Envoyez-la à l'accueil, nous descendons si besoin."]]);
              out("La visiteuse sourit moins : « Bon, je vais à l'accueil. » Elle a compris que le jeu était fini.", "ok");
              finish("s4", "win", 1);
            } else out("Vérifier quoi ? `verifier reunion` (rappel du secrétariat, poste 201).", "err");
            break;
          case "transfer":
            if (has(t, /accueil|securite|lea|reception/)) {
              out("Tu lui dis : « Venez, je vous accompagne à l'accueil, ils s'occupent des visiteurs. » Tu laisses la porte se refermer.", "ok");
              say("Visiteuse", "Oh, pas la peine, je repasserai plus tard, finalement…");
              out("Elle s'en va. Tu as appliqué la règle sans soupçonner personne : l'accueil enregistre les visiteurs, appelle la personne attendue et leur remet un badge temporaire.", "ok");
              finish("s4", "win", 2, true);
            } else out("Transférer vers l'accueil : `transferer accueil`.", "err");
            break;
          case "refuse":
            say("Toi", "Désolée : un badge par personne, ici, pour tout le monde. L'accueil est juste là, ils vous arrangeront ça en une minute.");
            say("Visiteuse", "Quelle rigidité ! Les autres ne font pas tant de manières…");
            out("Tu tiens bon, avec le sourire. Elle hausse les épaules et s'éloigne vers l'accueil, ou vers la sortie. Dire non à quelqu'un d'aimable coûte : c'est pour cela que la règle doit être celle de l'organisation. Tu n'as pourtant prévenu personne (`escalader`).", "ok");
            finish("s4", "win", 2);
            break;
          case "hello": say("Visiteuse", "Alors, tu me tiens la porte ?"); break;
          case "escalate": escIn("s4", "Tu appelles Léa : « une inconnue sans badge devant la porte principale ». Léa descend et escorte la visiteuse à l'accueil.", "win", 2); break;
          default: out("Elle attend, les bras chargés.", "sys");
        }
      },
    },

    s5: {
      name: "La clé USB trouvée", note: "usb", levers: ["rarete", "curiosite"],
      clues: { rarete: "« SALAIRES 2026, CONFIDENTIEL » : une information exclusive, que presque personne ne devrait voir : l'appât.", curiosite: "L'envie de « juste jeter un œil » : personne ne regarderait une clé anodine.", sympathie: "Le post-it poli, « merci de la rapporter à Mme Colin », t'invite à jouer le bon samaritain." },
      phases: [["Choix du lieu : devant l'entrée, là où les", "employés passent chaque matin."], ["Prétexte : une clé « perdue », avec un post-it", "qui demande de la rapporter à la RH."], ["Pression : la curiosité. Étiquette « SALAIRES", "2026 CONFIDENTIEL » : irrésistible."], ["Action : la brancher sur un poste du réseau :", "du code s'exécute depuis l'intérieur."]],
      press: [], rep: { win: "Léa met la clé dans un sachet, note l'heure et le lieu, et regarde les caméras de l'entrée : quelqu'un l'a bien déposée à 07 h 50. Elle informe les autres de ne brancher aucune clé trouvée.", lose: "Léa isole immédiatement le poste du réseau et lance une analyse. Plus le poste est coupé tôt, moins il a le temps de faire quoi que ce soit : ton signalement rapide change tout." },
      intro() { out("Ça traîne par terre, près de la porte d'entrée : tu pourrais l'examiner, la prendre, la brancher, la rendre, la jeter…", "sys"); out("(`examiner cle`, `prendre cle`, `brancher cle`, `donner cle a ‹personne›`, `verifier ‹rh›`, `jeter cle`, `escalader`)", "sys"); },
      h(k, t, c) {
        const x = F();
        switch (k) {
          case "plug": {
            if (!S.inv.includes("cle")) { out("Tu n'as pas la clé sur toi : `prendre cle`.", "sys"); return; }
            if (S.room === "securite") {
              out("Tu approches la clé du poste isolé de la sécurité.", "sys");
              say("Léa", "Hep ! Même ici, pas toi, pas comme ça. Je m'en occupe avec le sas d'analyse.");
              labAnalyse(); finish("s5", "win", 2, true); return;
            }
            if (S.room === "hall") { out("Il n'y a pas de poste dans le hall. (Et c'est bien : réfléchis avant d'aller en chercher un.)", "sys"); return; }
            out("Tu branches la clé sur le poste (relié au réseau de la Guilde).", "err");
            out("Simulation (fictive) : l'écran affiche un document « Salaires_2026.pdf ». L'icône est celle d'un PDF, mais l'extension masquée cache « .exe » : c'est un programme déguisé.", "err");
            code("11:03  poste STANDARD   périphérique USB détecté\n11:03  poste STANDARD   Salaires_2026.pdf (en réalité .exe) lancé\n11:03  poste STANDARD   connexion sortante vers 198.51.100.20 (serveur inconnu)");
            out("Le programme contacte un serveur externe : l'attaquant a maintenant un pied à l'intérieur du réseau. `escalader` tout de suite : un poste isolé tôt fait toute la différence.", "err");
            drop("cle"); x.usbGone = true; x.leaks.push("Clé USB inconnue branchée sur un poste du réseau (épisode 5)");
            finish("s5", "lose", 3);
            break;
          }
          case "give": {
            if (!S.inv.includes("cle")) { out("Tu n'as pas la clé sur toi : `prendre cle`.", "sys"); return; }
            if (has(t, /lea|securite|analyste/)) {
              if (S.room !== "securite") { out("Léa est au bureau de la sécurité (ouest du standard) : va l'y retrouver, ou fais-la venir avec `escalader`.", "sys"); return; }
              say("Léa", "Bonne décision. Je la prends avec un sachet.");
              labAnalyse(); finish("s5", "win", 2, true);
            } else if (has(t, /ada|maitre/)) out("Maître Ada te renvoie vers la sécurité : « Ce n'est pas moi qui analyse les clés. Léa a un poste isolé pour ça. »", "sys");
            else out("À qui ? Remets-la à Léa, de la sécurité : `donner cle a lea`.", "err");
            break;
          }
          case "verify":
            if (has(t, /rh|colin|etiquette|proprietaire|post it/)) {
              callback("les RH (Mme Colin)", "poste 215", [["Mme Colin", "Une clé avec les salaires 2026 ? Je n'ai rien perdu, et ces données ne sortent jamais du serveur RH. Ne la branchez surtout pas : apportez-la à la sécurité."]]);
              out("La RH n'a rien perdu : l'étiquette est un appât. Il te reste à la remettre à la sécurité, sans la brancher.", "ok");
            } else out("Vérifier quoi ? `verifier rh` (rappel sur le poste de Mme Colin).", "err");
            break;
          case "toss":
            out("Tu jettes la clé à la corbeille de l'accueil. Problème réglé ? Pas vraiment : n'importe qui peut la repêcher, et la sécurité ne saura jamais que quelqu'un dépose des clés piégées devant l'entrée. Tu as détruit l'indice.", "sys");
            drop("cle"); x.usbGone = true;
            finish("s5", "partial", 2);
            break;
          case "yes": out("Tu hésites… Un coup d'œil ne coûte rien, non ? Précisément ce que l'étiquette est conçue pour te faire penser. Réfléchis : que dit la procédure ?", "sys"); break;
          case "refuse": out("Tu ne la branches pas : bon réflexe. Mais la laisser traîner n'arrange rien : quelqu'un d'autre la ramassera. Remets-la à la sécurité : `prendre cle`, puis `donner cle a lea`.", "sys"); break;
          case "escalate": {
            out("Tu appelles Léa (poste 211) : « une clé étiquetée SALAIRES devant l'entrée, je n'y ai pas touché ». Elle arrive avec un sachet.", "sys");
            say("Léa", "Merci, ne la branche surtout pas ! Je l'analyse sur le poste isolé.");
            drop("cle"); labAnalyse(); finish("s5", "win", 2, true);
            break;
          }
          default: out("Que veux-tu faire de la clé ?", "sys");
        }
      },
    },

    s6: {
      name: "La banque et le code SMS", note: "otp", levers: ["autorite", "urgence"],
      clues: { autorite: "« Service antifraude de la Banque du Port » : une institution à laquelle on fait confiance.", urgence: "« Dernière fenêtre avant le débit » : il faut agir avant d'avoir le temps de relire le SMS." },
      phases: [["Nom de la banque, montant crédible, parfois", "des détails glanés ailleurs (logiciels)."], ["Prétexte : « service antifraude », paiement", "suspect à annuler, SMS de confirmation."], ["Pression : « dernière fenêtre avant le débit »,", "voix calme, assurance professionnelle."], ["Action : te faire lire à voix haute un code qui,", "en vérité, AUTORISE le virement."]],
      press: [["Conseiller", "Je vois que le SMS est arrivé : lisez-moi le code, la fenêtre d'annulation se ferme dans trois minutes."], ["Conseiller", "C'est un code d'annulation, tout à fait normal, je vous l'ai dit : il me faut les six chiffres."], ["Conseiller", "Madame, dans deux minutes le paiement part, et ce sera votre responsabilité."]],
      rep: { win: "Léa alerte la banque : un virement vers « Atelier Nova » était en attente d'autorisation ; il est annulé. La banque confirme qu'elle n'appelle jamais pour demander un code.", lose: "Léa appelle la banque en urgence : le virement de 1 249 écus est contesté, un rappel de fonds est lancé. Les petits montants sont parfois récupérés si l'on agit dans l'heure. Bob renouvelle les accès du compte." },
      intro() {
        const x = F(), l = x.l3;
        out("Le standard sonne. Écran : « 0 800 00 00 77 » : le numéro affiché ressemble à celui de la Banque du Port. Tu décroches. (Un numéro affiché n'est qu'une étiquette : il se falsifie.)", "sys");
        let t = "Bonjour, service antifraude de la Banque du Port. Nous avons détecté un paiement suspect de 1 249 écus à « Atelier Nova » sur le compte de la Guilde : il sera débité dans quelques minutes.";
        if (l.log) t += " Il vient de votre outil ComptaPort, d'après nos systèmes.";
        if (l.org) t += " Je parle bien à l'équipe de Mme Roux ?";
        t += " Pour l'annuler, je déclenche un code par SMS sur votre portable : dès que vous le recevez, lisez-le-moi à voix haute pour confirmer l'annulation. Vite, c'est la dernière fenêtre avant le débit.";
        say("Voix calme (« conseiller de la banque »)", t);
        x.trust = (l.log ? 1 : 0) + (l.org ? 1 : 0);
        if (x.trust) out("Il cite " + (l.log ? "le nom de ton logiciel" : "le nom de Mme Roux") + (l.log && l.org ? " et celui de Mme Roux" : "") + ". Ce sont des détails que tu as donnés à « Camille » : ils t'inspirent confiance, et c'est leur but.", "err");
        x.otp = otpOf("1249", "Atelier Nova", WIN); x.smsRead = false; give("sms");
        out("Ton portable vibre : un SMS vient d'arriver. (`examiner sms`)", "sys");
        out("Confiance accordée à ton interlocuteur : " + bar(x.trust) + " (" + x.trust + "/5)", "sys");
        out("Que fais-tu ? (`examiner sms`, `demander ‹pourquoi|nom›`, `verifier ‹banque›`, `transferer ‹securite›`, `donner ‹code›`, `refuser`, `escalader`)", "sys");
      },
      h(k, t) {
        switch (k) {
          case "give":
            if (has(t, /code|sms|chiffre|otp|six|numero|message/)) {
              say("Conseiller", "Merci. Voilà, c'est annulé ! Bonne journée.");
              out("Tu as lu les six chiffres à voix haute. Clic : il a raccroché.", "err");
              out("Simulation (fictive) : le portail de la banque", "sys");
              code("11:21  validation  code " + F().otp + " saisi sur le portail (valide pour CE virement)\n11:21  VIREMENT    1 249,00 écus  vers  Atelier Nova  AUTORISÉ\n11:22  (le code d'« annulation » était le code d'autorisation)");
              out("Le SMS disait « AUTORISER » : tu venais de signer le virement par téléphone. Si tu ne l'avais pas lu en entier, c'est parce qu'on t'a pressé de ne pas le faire. `escalader` vite : la banque peut tenter un rappel de fonds.", "err");
              F().leaks.push("Code à usage unique lu à voix haute : virement de 1 249 écus autorisé (épisode 6)");
              drop("sms"); finish("s6", "lose", 3);
            } else { say("Conseiller", "Le code reçu par SMS, madame, les six chiffres."); press("s6"); }
            break;
          case "ask":
            if (has(t, /pourquoi|autoriser|sms|annul|code|message/)) {
              if (!F().smsRead) { out("Tu n'as pas encore lu le SMS en entier. `examiner sms`.", "sys"); return; }
              say("Conseiller", "C'est la formulation technique du système, ne vous en occupez pas : c'est automatique. Le code, vite !");
              out("Tu lui fais remarquer que le SMS dit AUTORISER. Il esquive au lieu de répondre : c'est un signal d'alerte majeur.", "ok"); bump(-2); press("s6");
            } else if (has(t, /nom|identite|conseiller|matricule|agence/)) {
              say("Conseiller", "Thomas Girard, conseiller 8812, cellule antifraude. Vous voulez que je vous l'épelle ?");
              out("Un nom et un numéro de conseiller se déclarent : rien de vérifiable.", "sys"); bump(1); press("s6");
            } else out("Demander quoi ? `demander pourquoi` (le SMS dit autoriser), `demander nom`.", "err");
            break;
          case "verify":
            if (has(t, /banque|conseiller|appelant|antifraude|numero|carte/)) {
              callback("la Banque du Port (numéro au dos de la carte)", "0 800 00 00 77, saisi à la main", [["Vraie banque", "Aucune alerte antifraude n'a été émise. En revanche, un virement de 1 249 écus vers Atelier Nova attend une autorisation par code SMS : n'autorisez surtout pas, nous le bloquons. Et nous n'appelons jamais pour demander un code."]]);
              out("Le faux conseiller n'a plus de ligne. Le virement en attente est annulé.", "ok");
              drop("sms"); finish("s6", "win", 1);
            } else out("Vérifier qui ? `verifier banque` (rappel sur le numéro du dos de la carte).", "err");
            break;
          case "transfer":
            if (has(t, /securite|lea|banque/)) {
              out("Tu transfères l'appel à la sécurité : « mon interlocuteur veut mon code SMS ».", "sys"); say("Léa", "Léa, sécurité. Monsieur ? Vous voulez un code ? Raccrochez, je vous rappelle."); out("Clic : l'appelant a raccroché. Tu ne lui as pas donné le code.", "ok");
              drop("sms"); finish("s6", "win", 2, true);
            } else out("Transférer vers la sécurité : `transferer securite`.", "err");
            break;
          case "refuse":
            say("Toi", "Je ne communique jamais un code reçu par SMS, à personne, par téléphone.");
            say("Conseiller", "Alors le paiement partira, et ce sera votre responsabilité !");
            out("Tu raccroches. Sans ton code, le virement ne peut pas être autorisé : il expire. Tu as bien résisté, mais sans rappel ni signalement, la banque ne sait pas qu'on a essayé de t'avoir.", "ok");
            drop("sms"); finish("s6", "win", 2);
            break;
          case "yes": out("Tu hésites… As-tu lu le SMS ? (`examiner sms`) Que dit-il ?", "sys"); bump(1); break;
          case "hello": say("Conseiller", "Oui, vous avez reçu le SMS ? Les six chiffres, s'il vous plaît."); break;
          case "escalate": escIn("s6", "Tu fais signe à Léa en lui montrant l'écran du portable : « il veut mon code ». Elle prend le combiné et demande à l'appelant de s'identifier.", "win", 2); break;
          default: out("Il attend le code.", "sys");
        }
      },
    },
  };

  /* ---------- mécanique commune ---------- */
  function bump(n) {
    const x = F(); x.trust = Math.max(0, Math.min(5, (x.trust || 0) + n));
    out("Confiance accordée à ton interlocuteur : " + bar(x.trust) + " (" + x.trust + "/5)", "sys");
    if (x.trust >= 4) out("Tu sens que tu es à deux doigts de céder. C'est précisément l'effet recherché : arrête-toi et passe par la procédure (`verifier`, `refuser` ou `escalader`).", "err");
  }
  function press(id) {
    const x = F(), P = SC[id].press; x.s.n = (x.s.n || 0) + 1;
    if (!P.length) return;
    if (x.s.n > P.length + 1) {
      out("L'interlocuteur finit par perdre patience et raccroche : « Bon, tant pis. » Tu n'as rien cédé, mais tu n'as pas vraiment fait de vérification non plus.", "sys");
      if (id === "s6") drop("sms");
      finish(id, "win", 2); return;
    }
    const p = P[Math.min(x.s.n - 1, P.length - 1)]; say(p[0], p[1]);
  }
  function callback(who, num, lines) {
    const x = F();
    out("Tu dis calmement : « Je vous rappelle. » et tu raccroches. Tu cherches " + who + " dans l'annuaire (" + num + ") et tu composes CE numéro-là, pas un numéro donné par l'appelant.", "sys");
    lines.forEach(l => say(l[0], l[1]));
    x.trust = 0; x.procs.push("Rappel sur numéro connu : " + who + " (" + SC[x.cur].name.toLowerCase() + ")");
    note("rappel"); if (!S.figs.includes("rappel")) fig("rappel");
  }
  function escIn(id, text, r, ph) { out(text, "sys"); finish(id, r, ph, true); }
  function labAnalyse() {
    const x = F();
    out("Léa branche la clé sur le poste isolé de la sécurité (aucun réseau, aucun accès à rien). Son rapport :", "sys");
    code("Salaires_2026.pdf    : en réalité un exécutable (.exe) à l'icône de PDF\nComportement         : tente de joindre un serveur externe à l'ouverture\nVerdict              : clé piégée, déposée volontairement devant l'entrée\nDégâts               : aucun (analysée hors réseau)");
    out("Tu l'as remise sans la brancher : la procédure a fonctionné. Léa a de quoi retrouver l'origine de la clé.", "ok");
    drop("cle"); x.usbGone = true;
  }
  function finish(id, r, ph, rep) {
    const x = F();
    const raw = ph; ph = raw + 1;
    x.res[id] = { r, ph, rep: false }; x.last = id; x.pend = id; x.cur = null; x.trust = 0; x.found[id] = []; x.s = {};
    out(r === "win" ? "Résultat : ✔ attaque arrêtée." : r === "partial" ? "Résultat : ~ attaque arrêtée en partie." : "Résultat : ✗ l'attaque aboutit (simulé).", r === "win" ? "ok" : r === "partial" ? "sys" : "err");
    if (r !== "lose" && raw !== 1) x.procs.push("Résistance : " + SC[id].name.toLowerCase() + " (refus, transfert ou signalement)");
    if (rep) doReport(id, true);
    if (id === "s1") note("pourquoi");
    out("Fin de l'épisode. Décortique-le : `analyser`, puis `identifier ‹levier›` pour nommer les leviers psychologiques. (`leviers` liste les noms possibles.)", "sys");
  }
  function doReport(id, inline) {
    const x = F(), r = x.res[id]; if (r.rep) return;
    r.rep = true; x.nrep++;
    out(inline ? "Signalement fait en même temps :" : "Tu appelles Léa (poste 211) pour signaler l'épisode « " + SC[id].name + " ».", "sys");
    say("Léa", "Merci d'avoir signalé : c'est exactement ce qu'il fallait faire, et personne ne te le reprochera.");
    out(SC[id].rep[r.r === "lose" ? "lose" : "win"], r.r === "lose" ? "sys" : "ok");
  }
  function report() {
    const x = F();
    let id = null;
    for (let i = SCN.length - 1; i >= 0; i--) if (x.res[SCN[i]] && !x.res[SCN[i]].rep) { id = SCN[i]; break; }
    if (!id) { out(Object.keys(x.res).length ? "Tout ce qui s'est passé a déjà été signalé. Continue ainsi." : "Tu n'as rien à signaler pour l'instant.", "sys"); return; }
    doReport(id, false);
  }

  function begin(id) {
    const x = F(); x.cur = id; x.s = { n: 0 }; x.trust = x.trust || 0;
    if (!["s2", "s6"].includes(id)) x.trust = 0;
    SC[id].intro();
    if (!["s2", "s6"].includes(id)) { /* pas de jauge au départ */ }
  }
  function ask3() {
    const r = F().s.r, w = ["Pour envoyer la facture de maintenance au bon endroit : c'est qui, la responsable des achats chez vous, et elle dépend de qui ?", "Et pour le pilote d'impression : vous êtes toujours sur quel logiciel de comptabilité ? Je veux être sûre de la bonne version.", "Dernière chose, pour planifier l'intervention : vous fermez à quelle heure le vendredi ? Et M. Valmont est là la semaine prochaine ?"];
    say("Camille", w[r - 1]);
    out("(Ce qu'elle demande : " + ["l'organigramme", "le nom de ton logiciel", "tes horaires et une absence"][r - 1] + ". `donner " + ["organigramme", "logiciel", "horaires"][r - 1] + "`, `demander ‹pourquoi›`, `verifier camille`, `refuser`, `escalader`.)", "sys");
  }

  const idle = k => {
    const x = F();
    if (k === "escalate") { report(); return; }
    if (x.pend) out("Plus rien en cours. Termine ton analyse : `analyser`, puis `identifier ‹levier›`.", "sys");
    else out("Aucun appel ni visiteur en cours. " + (PHONE.includes(SCN[x.n]) ? "Le standard va sonner : `decrocher`." : x.n < 6 ? "Quelque chose t'attend dans le hall." : ""), "sys");
  };
  function act(k, t, c) {
    const x = F();
    if (!x.quest) { out("Parle d'abord à Maître Ada.", "sys"); return; }
    if (!x.cur) { idle(k); return; }
    SC[x.cur].h(k, t, c);
  }

  /* ---------- entités et lieux ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada", vis: () => F().n < 6, desc: () => "Maître Ada, doyenne de la Guilde, l'œil tranquille derrière ses lunettes. Elle tient la Guilde depuis trente ans et déteste qu'on dise « c'est la faute de l'utilisateur »." },
    ada2: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, derrière son bureau." },
    eve: { npc: true, names: ["eve", "oreille", "enregistrement"], label: "Ève, la voix des enregistrements", vis: () => true, desc: () => "Ève, qui « écoute » tout ce qui passe sur les lignes de la Guilde, avec l'accord de chacun, pour la formation. Elle sait rejouer les appels." },
    standard: { names: ["standard", "combine", "ligne", "appareil", "telephone"], label: "le standard", desc: () => { const x = F(); return x.cur ? "Le combiné est contre ton oreille : l'appelant est toujours en ligne." : PHONE.includes(SCN[x.n]) && !x.pend ? "Un voyant rouge clignote : `decrocher`." : "Un grand tableau de fiches et de voyants. Pour l'instant, rien ne clignote."; } },
    ordinateur: { names: ["ordinateur", "poste", "pc", "ecran"], label: "le poste du standard", desc: () => "Le poste du standard, relié au réseau de la Guilde : il donne accès à la messagerie, à l'annuaire du personnel et au portail de paiement." },
    annuaire: { names: ["annuaire", "repertoire", "numeros"], label: "l'annuaire interne", onExamine() { F().sawDir = true; },
      desc: () => "Annuaire interne : numéros vérifiés, ceux avec lesquels on RAPPELLE (jamais ceux que donne un appelant) :\n  · Support informatique ........ poste 204\n  · Sécurité (Léa) .............. poste 211\n  · Comptabilité (Bob) .......... poste 230\n  · Secrétariat de direction .... poste 201\n  · RH (Mme Colin) .............. poste 215\n  · Direction : M. Valmont ...... portable pro 06 00 00 00 12 (fictif)\n  · PrintoPort (contrat) ........ 0 800 00 00 18 (fictif)\n  · Banque du Port .............. numéro au dos de la carte : 0 800 00 00 77 (fictif)\nChaque service et chaque dirigeant a aussi un « mot convenu » connu de la sécurité, jamais écrit ici." },
    classeur: { names: ["classeur", "procedures", "procedure", "reflexes"], label: "le classeur des procédures", onExamine() { F().sawProc = true; },
      desc: () => "Le classeur des procédures, aux pages écornées. Cinq réflexes en couverture :\n  1. Urgence + autorité + demande inhabituelle : on ralentit, c'est le signal d'alerte.\n  2. On raccroche et on RAPPELLE sur un numéro de l'annuaire, jamais celui de l'appelant.\n  3. Jamais de mot de passe ni de code à usage unique par téléphone, à personne.\n  4. Un virement ne part jamais sur une seule voix : validation à deux personnes.\n  5. On signale, tout de suite, sans honte : ce qui s'est passé comme ce qui a failli." },
    sms: { names: ["sms", "portable", "message", "code"], label: "ton portable (SMS reçu)", vis: () => S.inv.includes("sms"), onExamine() { F().smsRead = true; if (!S.figs.includes("otp")) fig("otp"); },
      desc: () => { const x = F(); return "Banque du Port : le code " + (x.otp || "000000") + " AUTORISE le virement de 1 249,00 écus vers Atelier Nova. Valable 60 s. Ne le communiquez JAMAIS, même à un conseiller de la banque.\n\nLe code n'est pas un mot de passe qu'on retient : il est calculé à partir du secret de la banque, du montant, du bénéficiaire et de l'instant. Pour 1,00 écu vers un autre bénéficiaire, avec le même secret et le même instant, ce serait " + otpOf("1", "Autre", WIN) + ". `schema otp` montre la différence entre ce que dit l'appelant et ce que dit le SMS."; } },
    porte: { names: ["porte", "porte securisee", "lecteur", "badge", "portique"], label: "la porte sécurisée", desc: () => "Une porte vitrée à lecteur de badge. Chaque badge passé laisse une ligne dans le journal des accès. Un badge, une personne : c'est écrit sur l'affiche, juste à côté." },
    visiteuse: { npc: true, names: ["visiteuse", "femme", "inconnue", "laurence"], label: "une femme aux bras chargés", vis: () => SCN[F().n] === "s4" && !F().res.s4, desc: () => "Une femme élégante, un gobelet de café en équilibre sur une pile de dossiers, un sourire désarmant." },
    cle: { names: ["cle usb", "usb", "cle", "support"], label: "une clé USB par terre", take: true, vis: () => SCN[F().n] === "s5" && !F().usbGone,
      onExamine() { const x = F(); if (SCN[x.n] === "s5" && !x.cur && !x.res.s5) begin("s5"); },
      desc: () => "Une clé USB gris métal, étiquette manuscrite : « SALAIRES 2026, CONFIDENTIEL ». Un post-it : « Si trouvée, merci de la rapporter à Mme Colin, RH ». Rien ne dit à qui elle appartient." },
    bob: { npc: true, names: ["bob", "comptable"], label: "Bob, le comptable", desc: () => "Bob, comptable de la Guilde, un peu voûté sur ses colonnes de chiffres, toujours poli, toujours pressé." },
    registre: { names: ["registre", "virements", "portail", "cahier"], label: "le registre des virements", desc: () => "Le registre des virements : chaque ligne porte deux paraphes (la personne qui prépare, celle qui valide). Un virement à une seule signature est refusé par le portail, sauf « exception » : un mot qui fait frémir Bob." },
    lea: { npc: true, names: ["lea", "analyste", "securite"], label: "Léa, analyste sécurité", desc: () => "Léa, analyste sécurité de la Guilde. Calme, précise, elle remercie systématiquement quand on lui signale quelque chose." },
    posteisole: { names: ["poste isole", "sas", "isole", "poste jetable", "analyse"], label: "le poste isolé", desc: () => "Un vieux poste sans aucun câble réseau : c'est ici que la sécurité ouvre les supports suspects, sans risque pour la Guilde." },
    signalements: { names: ["signalements", "cahier des signalements", "registre signalements", "tableau signalements"], label: "le cahier des signalements", desc: () => { const x = F(); return "Le cahier des signalements : une ligne par alerte, avec ce mot en couverture : « Merci d'avoir signalé ». " + (x.nrep ? `Tu y as déjà ${x.nrep} entrée${x.nrep > 1 ? "s" : ""}.` : "Il est vide pour l'instant."); } },
    tableau: { names: ["tableau", "politique", "regles", "panneau"], label: "le tableau de la politique", desc: () => { const x = F(); return x.pol.length ? "Politique en cours : " + x.pol.map(r => RULES[r].short).join(" · ") + "." : "Le tableau est vide. `politique` pour voir les douze règles proposées."; } },
  };

  const rooms = {
    standard: { name: "Le standard de la Guilde", short: "Standard", alias: ["standard", "accueil"], ents: ["ada", "standard", "ordinateur", "annuaire", "classeur"], exits: { sud: "hall", est: "compta", ouest: "securite", nord: "bureau" },
      desc: () => { const x = F(); return "Un grand tableau de fiches et de voyants, un combiné et un casque. Ici aboutissent tous les appels destinés à la Guilde, un jour de forte activité : tout le monde veut quelque chose, tout de suite. Au sud, le hall d'entrée ; à l'est la comptabilité ; à l'ouest la sécurité ; au nord le bureau de Maître Ada." + (x.cur && x.cur !== "s5" ? "\nTu es en ligne." : ""); } },
    hall: { name: "Le hall d'entrée", short: "Hall", alias: ["hall", "entree"], ents: ["porte", "visiteuse", "cle"], exits: { nord: "standard" },
      desc: () => "Le hall de la Guilde, avec sa porte vitrée à lecteur de badge qui sépare l'entrée du couloir des bureaux. Un panneau rappelle : « un badge, une personne ». L'accueil est tout près." },
    compta: { name: "Le bureau de la comptabilité", short: "Compta", alias: ["compta", "comptabilite"], ents: ["bob", "registre"], exits: { ouest: "standard" },
      desc: () => "Des colonnes de chiffres, des classeurs, un portail de paiement toujours ouvert. Ici, l'argent ne sort pas sans deux paraphes." },
    securite: { name: "Le bureau de la sécurité", short: "Sécurité", alias: ["securite"], ents: ["lea", "posteisole", "signalements"], exits: { est: "standard" },
      desc: () => "Un petit bureau aux écrans sobres. Un poste sans câble réseau sur une table à part. Au mur, une affiche : « Signaler n'est pas avouer une faute. »" },
    bureau: { name: "Le bureau de Maître Ada", short: "Bureau d'Ada", alias: ["bureau", "ada"], ents: ["ada2", "eve", "tableau"], exits: { sud: "standard" },
      desc: () => "Un bureau encombré de livres et de tasses. Un tableau accueille la politique de vérification de la Guilde. Ève, installée à un petit pupitre, a branché ses enregistrements : elle peut rejouer les appels de la journée." },
  };

  /* ---------- objectif et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (x.cur) return "act_" + x.cur;
    if (x.pend) return "analyse";
    if (x.n < 6) return "next_" + SCN[x.n];
    if (!x.polOK) return S.room === "bureau" ? "pol" : "toada";
    if (!x.bobDone) return "bob";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend au standard.", "`parler ada`"],
    next_s1: () => ["Le standard sonne.", "`decrocher`"],
    next_s3: () => ["Le standard sonne de nouveau.", "`decrocher`"],
    next_s2: () => ["Le standard sonne de nouveau.", "`decrocher`"],
    next_s6: () => ["Le standard sonne de nouveau.", "`decrocher`"],
    next_s4: () => ["Quelque chose se passe dans le hall d'entrée, au sud du standard.", "`aller sud`, puis `parler visiteuse`."],
    next_s5: () => ["Devant l'entrée, quelque chose traîne par terre : va voir.", "`aller sud`, puis `examiner cle`."],
    act_s1: () => ["Un inconnu te demande ton mot de passe sous pression. Quelle procédure peux-tu suivre sans te laisser bousculer ? L'annuaire contient les numéros de rappel.", "`verifier support` (rappel sur le numéro connu) ; ou `transferer securite` ; ou `refuser`. `demander question` pour voir comment il réagit."],
    act_s3: () => ["Chaque demande paraît anodine, mais regarde-les ensemble. Une procédure existe pour une personne qu'on ne connaît pas.", "`verifier camille` (rappel sur le numéro du contrat), `refuser` ou `transferer accueil`. Ne donne que ce que tu ferais devant n'importe quel inconnu."],
    act_s2: () => ["Un dirigeant exige un virement urgent, secret et hors procédure. Qui peut confirmer sa demande ?", "`verifier directeur` (rappel sur son portable de l'annuaire), ou `transferer compta` pour la double validation, ou `escalader`."],
    act_s4: () => ["Elle est sympathique, pressée, et les autres passent déjà. Que dit la règle de la porte ?", "`transferer accueil`, `refuser` ou `verifier reunion` (secrétariat). Ne tiens pas la porte."],
    act_s5: () => ["Une clé inconnue est un appât, et sa curiosité est ton ennemie. Ni la brancher, ni la jeter : qui sait l'analyser sans risque ?", "`prendre cle`, `aller ouest`, `donner cle a lea` (ou `escalader` depuis n'importe où)."],
    act_s6: () => ["Lis le SMS en entier avant de dire quoi que ce soit. Que dit-il vraiment ?", "`examiner sms`, puis `verifier banque` (rappel sur le numéro de la carte), `refuser` ou `transferer securite`."],
    analyse: () => {
      const x = F(), id = x.pend, L = SC[id].levers.filter(l => !(x.found[id] || []).includes(l));
      return ["Décortique l'épisode (`analyser`), puis nomme les leviers psychologiques à l'œuvre : `leviers` donne la liste.", "`analyser`, puis " + L.map(l => "`identifier " + LEV[l][0].toLowerCase() + "`").join(", ") + "."];
    },
    toada: () => ["Tous les épisodes sont digérés : Maître Ada t'attend dans son bureau.", "`aller nord` (depuis le standard)"],
    pol: () => ["Choisis au plus six règles parmi douze, puis teste-les contre les six épisodes. Les règles « dures » ne dépendent pas de ton jugement du moment.", "`politique`, `adopter ‹n›`, `retirer ‹n›`, `tester politique`. Chaque épisode doit être arrêté."],
    bob: () => ["Bob a quelque chose à te dire à la comptabilité.", "`aller sud`, `aller est`, `parler bob`, puis `remercier bob` ou `sanctionner bob`."],
    end: () => ["Rends compte à Maître Ada.", "Vers le bureau d'Ada : `aller ouest`, `aller nord`, puis `parler ada`."],
    fin: () => ["Journée terminée ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- parler ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada": case "ada2":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Bienvenue au standard, Alice. Aujourd'hui, la Guilde est sens dessus dessous : appels, visiteurs, courriels, tout le monde veut quelque chose tout de suite. Ton travail : tenir le standard, et rester toi-même quand on te presse.");
          say("Maître Ada", "Tu as deux alliés : l'annuaire interne (les numéros pour rappeler) et le classeur des procédures. Quand une demande te met mal à l'aise, c'est le bon moment pour t'en servir : la procédure existe pour que tu n'aies pas à décider seule, sous pression, si quelqu'un ment. Et personne ne te reprochera de signaler quoi que ce soit.");
          out("Tout se passe dans les locaux de la Guilde, sur des données fictives. Commence par `examiner annuaire` et `examiner classeur`, puis `decrocher` quand le standard sonnera.", "sys");
        } else if (id === "ada" && x.n < 6) say("Maître Ada", x.cur ? "Ne me regarde pas : tu es en ligne, occupe-toi de ton appelant." : x.pend ? "Digère ce qui vient de se passer : `analyser`, puis `identifier ‹levier›`." : "Le standard et le hall sont à toi. `indice` si tu bloques.");
        else if (!x.polOK) {
          say("Maître Ada", "Tu as tenu le standard toute la journée. Maintenant, on en fait une règle pour tout le monde : écris la politique de vérification de la Guilde. Six règles au plus, choisies parmi douze (certaines sont excellentes, d'autres sont des pièges). Ève rejouera chaque appel de la journée contre ta politique. `politique`, `adopter ‹n›`, `tester politique`.");
        } else if (!x.bobDone) say("Maître Ada", "Bob est passé me voir, il voulait te parler. Va le retrouver à la compta : il a quelque chose à dire, et la manière dont tu réagiras comptera plus que toutes les règles.");
        else if (!x.end) ending();
        else say("Maître Ada", "La Guilde est plus prudente, et surtout plus sereine. Merci !");
        break;
      case "eve":
        if (!x.polOK) say("Ève", "J'ai enregistré les six appels de ta journée (avec l'accord de la Guilde, pour l'audit). Dès que ta politique est prête, `tester politique` : je les rejoue contre elle, un par un.");
        else say("Ève", "Tout est rejoué. Je continue d'écouter : c'est mon rôle, et celui de tes règles est de rendre mon écoute inutile à qui voudrait en profiter.");
        break;
      case "visiteuse":
        if (SCN[x.n] === "s4" && !x.cur) begin("s4");
        else say("Visiteuse", "Alors, tu me tiens cette porte ?");
        break;
      case "bob":
        if (!x.polOK) say("Bob", "Ici, tout virement de plus de 1 000 écus a deux paraphes : le mien et celui d'une autre personne. Même pour le directeur. Surtout pour le directeur : c'est lui que les fraudeurs imitent le plus volontiers.");
        else if (!x.bobState) {
          x.bobState = 1;
          say("Bob", "Alice… je dois te dire quelque chose. Hier, un monsieur de « la banque » m'a appelé pour annuler un prélèvement suspect. J'ai lu à voix haute le code reçu par SMS. Il y avait un montant dans le SMS, je ne l'ai pas lu. Ce matin, j'ai compris. J'ai honte. Je n'ai rien dit hier soir. Je préférais que tu l'apprennes de moi.");
          out("Bob attend ta réaction. Deux manières de répondre : `remercier bob`, ou `sanctionner bob`.", "sys");
        } else if (x.bobState < 3) say("Bob", "Alors ? Qu'est-ce que tu comptes faire de ce que je t'ai dit ? (`remercier bob` ou `sanctionner bob`)");
        else say("Bob", "Merci de m'avoir écouté. Je signalerai vite, la prochaine fois : même pour un doute.");
        break;
      case "lea":
        if (x.cur === "s5" && S.inv.includes("cle")) say("Léa", "Tu as une clé trouvée ? Ne la branche pas, donne-la-moi : `donner cle a lea`.");
        else say("Léa", "Je reçois tous les signalements. Les plus utiles viennent de gens qui ont failli se faire avoir : on apprend plus d'un échec évité que d'un succès. `escalader` pour me signaler quelque chose.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function pick() {
    const x = F();
    if (!x.quest) { out("Parle d'abord à Maître Ada.", "sys"); return; }
    if (S.room !== "standard") { out("Le standard est dans la pièce centrale de la Guilde.", "sys"); return; }
    if (x.cur) { out("Tu es déjà en ligne.", "sys"); return; }
    if (x.pend) { out("Le dernier épisode n'est pas digéré : `analyser`, puis `identifier ‹levier›`.", "sys"); return; }
    const id = SCN[x.n];
    if (!id) { out("Plus d'appel pour l'instant. Va voir Maître Ada, dans son bureau.", "sys"); return; }
    if (!PHONE.includes(id)) { out("Le standard reste silencieux. Mais tu entends du bruit dans le hall (`aller sud`).", "sys"); return; }
    begin(id);
  }
  function giveCmd(c) {
    const t = norm(c.rawArg);
    if (!t) { out("Donner quoi ? Par exemple `donner mot de passe`, `donner virement`, `donner organigramme`, `donner code`, `donner cle a lea`.", "err"); return; }
    if (has(t, /\b(cle|usb)\b/)) {
      const x = F();
      if (!x.cur && SCN[x.n] === "s5" && S.inv.includes("cle") && !x.res.s5) begin("s5");
      act("give", t, c);
      return;
    }
    act("give", t, c);
  }
  function plugCmd() {
    const x = F();
    if (!x.cur && SCN[x.n] === "s5" && S.inv.includes("cle") && !x.res.s5) begin("s5");
    if (!x.cur) { out("Il n'y a rien à brancher pour l'instant.", "sys"); return; }
    if (x.cur !== "s5") { out("Rien à brancher en ce moment.", "sys"); return; }
    SC.s5.h("plug", "", {});
  }
  function analyse() {
    const x = F();
    if (!x.pend) { out(x.cur ? "Finis d'abord l'appel en cours." : "Rien à analyser pour l'instant.", "sys"); return; }
    const id = x.pend, S0 = SC[id], r = x.res[id];
    out("Anatomie de l'épisode : " + S0.name, "title");
    out(r.r === "lose" ? "L'attaque a franchi les quatre phases et abouti à l'action demandée." : "Tu as coupé l'attaque à la phase " + r.ph + " sur 4 (" + ["", "renseignement", "prétexte", "pression", "action"][r.ph] + "), avant l'action finale.", r.r === "lose" ? "err" : "ok");
    fig("anatomie", id);
    out("Quels leviers psychologiques ont été actionnés ? Il y en a " + S0.levers.length + " à retrouver : `identifier ‹levier›` (`leviers` donne la liste).", "sys");
  }
  function leviers() {
    out("Leviers possibles : " + Object.keys(LEV).map(k => "**" + LEV[k][0] + "** (" + LEV[k][1] + ")").join(" · ") + ".", "sys");
  }
  function identify(c) {
    const x = F(), t = norm(c.rawArg);
    if (!x.pend) { out(x.cur ? "Finis d'abord l'appel : tu analyseras ensuite." : "Aucun épisode à analyser pour l'instant.", "sys"); return; }
    if (!t) { leviers(); return; }
    const key = levKey(t);
    if (!key) { out("Je ne connais pas ce levier. `leviers` donne la liste.", "err"); return; }
    const id = x.pend, S0 = SC[id], fnd = x.found[id] || (x.found[id] = []);
    if (fnd.includes(key)) { out("Déjà identifié.", "sys"); return; }
    if (!S0.clues[key]) { out("✗ Pas ici : **" + LEV[key][0] + "** (" + LEV[key][1] + "). Relis l'épisode : ce levier n'y apparaît pas. Il t'en manque " + (S0.levers.length - fnd.filter(k => S0.levers.includes(k)).length) + ".", "err"); return; }
    fnd.push(key); if (!x.fl.includes(key)) x.fl.push(key);
    out("✔ **" + LEV[key][0] + "** : " + S0.clues[key], "ok");
    if (!S.figs.includes("leviers")) fig("leviers");
    if (S0.levers.every(l => fnd.includes(l))) {
      x.pend = null; x.n++; note(S0.note);
      out("Épisode digéré. Tu peux aussi `escalader` si tu n'as pas encore signalé ce qui s'est passé.", "sys");
      if (x.n >= 6) out("Tous les épisodes sont digérés. Maître Ada t'attend dans son bureau (au nord du standard).", "title");
      else out(PHONE.includes(SCN[x.n]) ? "Le standard va bientôt sonner : `decrocher`." : "Quelque chose se passe dans le hall : `aller sud`.", "sys");
    } else out("Il t'en reste " + S0.levers.filter(l => !fnd.includes(l)).length + " à retrouver.", "sys");
  }
  function status() {
    const x = F();
    out("Situation de la journée", "title");
    out("Épisodes : " + SCN.map(id => { const r = x.res[id]; return SC[id].name + " : " + (r ? (r.r === "win" ? "✔ arrêté" : r.r === "partial" ? "~ partiel" : "✗ aboutit") + (r.rep ? " (signalé)" : "") : "pas encore"); }).join(" · "), "sys");
    out("Informations divulguées : " + (x.leaks.length ? x.leaks.join(" ; ") : "aucune") + ".", x.leaks.length ? "err" : "ok");
    out("Procédures suivies : " + (x.procs.length ? x.procs.join(" ; ") : "aucune pour l'instant") + ".", "sys");
    out("Signalements : " + x.nrep + ".", "sys");
    if (x.cur) out("Confiance accordée à l'interlocuteur en ligne : " + bar(x.trust) + " (" + x.trust + "/5).", "sys");
  }

  /* ---------- politique ---------- */
  const ORDER = ["r9", "r1", "r10", "r5", "r12", "r3", "r7", "r11", "r6", "r4", "r8", "r2"];
  const RULES = {
    r1: { short: "Rappel numéro connu", kind: "soft", txt: "Avant toute action demandée par téléphone, on raccroche et on rappelle un numéro de l'annuaire, jamais celui que donne l'appelant.",
      stops: { s1: "Tu raccroches et rappelles le support (poste 204) : ni Kévin ni ticket. Arrêté avant l'action.", s2: "Rappel sur le portable de M. Valmont de l'annuaire : il est en réunion à Lyon. Arrêté.", s6: "Rappel au numéro du dos de la carte : aucune alerte, le virement en attente est bloqué. Arrêté." } },
    r2: { short: "Question convenue", kind: "soft", txt: "Une question de vérification convenue d'avance, non devinable, valide l'identité de quiconque se réclame d'un service ou d'un dirigeant de la Guilde.",
      stops: { s1: "Le faux « support » ne connaît pas le mot convenu avec le service : il esquive. Arrêté.", s2: "Le faux directeur ne connaît pas le mot convenu : il s'énerve, sans répondre. Arrêté." } },
    r3: { short: "Jamais mdp ni code", kind: "hard", txt: "Jamais de mot de passe ni de code à usage unique par téléphone, à personne, quelle que soit la raison.",
      stops: { s1: "Aucun mot de passe par téléphone : la règle ne se discute pas, même sous « urgence ». Tu n'as pas à juger. Arrêté.", s6: "Aucun code à usage unique par téléphone : tu ne lis pas le SMS à voix haute. Arrêté." } },
    r4: { short: "Virement à deux", kind: "hard", txt: "Tout virement exige deux validations indépendantes et un justificatif : aucun ordre téléphonique ne suffit, quel que soit le rang du demandeur.",
      stops: { s2: "Le virement exige deux paraphes et un bon de commande : l'ordre téléphonique ne suffit pas. Arrêté." } },
    r5: { short: "Un badge, une personne", kind: "hard", txt: "Porte sécurisée : un badge par personne, on ne tient jamais la porte ; les visiteurs passent par l'accueil et sont accompagnés.",
      stops: { s4: "Un badge par personne : porte non tenue, visiteuse envoyée à l'accueil. Arrêté." } },
    r6: { short: "USB inconnue : sécurité", kind: "hard", txt: "Une clé USB ou un support inconnu ne se branche jamais : on le remet à la sécurité, qui l'analyse sur un poste isolé.",
      stops: { s5: "Clé inconnue : jamais branchée, remise à Léa, analysée sur le poste isolé. Arrêté." } },
    r7: { short: "Rien à un inconnu", kind: "soft", txt: "Aucune information interne (organigramme, logiciels, horaires) n'est confirmée à un interlocuteur non vérifié ; en cas de doute, on propose l'accueil ou un rappel.",
      stops: { s3: "Aucune information interne à une inconnue : tu proposes l'accueil dès la première question. La collecte s'arrête. Arrêté." } },
    r8: { short: "Signalement sans blâme", kind: "detect", txt: "Tout appel ou fait suspect se signale immédiatement à la sécurité, sans honte et sans sanction.", stops: {} },
    r9: { short: "Mots de passe /30 jours", kind: "none", txt: "Les mots de passe sont changés tous les trente jours.", stops: {} },
    r10: { short: "Connaît nos noms = fiable", kind: "bad", txt: "Un appelant qui connaît des noms ou des projets internes est présumé légitime.", stops: {} },
    r11: { short: "Numéro affiché = fiable", kind: "bad", txt: "Un appel dont le numéro s'affiche comme interne ou connu est digne de confiance.", stops: {} },
    r12: { short: "Formation annuelle", kind: "weak", txt: "Une session de sensibilisation obligatoire, une fois par an.", stops: {} },
  };
  const FAIL = { s1: "Kévin obtient le mot de passe : compte compromis.", s2: "Le virement de 48 000 écus part vers un compte inconnu.", s3: "Les trois informations anodines partent : dossier de reconnaissance complet.", s4: "La visiteuse passe sans badge, sans trace.", s5: "La clé est branchée sur un poste du réseau.", s6: "Le code est lu à voix haute : le virement est autorisé." };
  function evalScn(id, pol) {
    const bad10 = pol.includes("r10") && ["s1", "s2", "s3", "s6"].includes(id), bad11 = pol.includes("r11") && ["s1", "s2", "s6"].includes(id);
    const eff = [], blocked = [];
    pol.forEach(r => {
      const R = RULES[r]; if (!R.stops[id]) return;
      if (R.kind === "soft" && (bad10 || (bad11 && (r === "r1" || r === "r2")))) blocked.push(r); else eff.push(r);
    });
    const weak = pol.some(r => ["detect", "weak"].includes(RULES[r].kind));
    return { st: eff.length ? "stop" : weak ? "limit" : "fail", eff, blocked };
  }
  function polList() {
    const x = F();
    out("La politique de vérification : douze règles possibles, six au plus", "title");
    ORDER.forEach((r, i) => out((x.pol.includes(r) ? "[x] " : "[ ] ") + (i + 1) + ". " + RULES[r].txt, x.pol.includes(r) ? "ok" : ""));
    out(`Règles retenues : ${x.pol.length}/6. \`adopter ‹n›\`, \`retirer ‹n›\`, \`tester politique\`.`, "sys");
  }
  function adopt(c) {
    const x = F();
    if (S.room !== "bureau") { out("La politique s'écrit dans le bureau de Maître Ada.", "sys"); return; }
    if (x.n < 6) { out("Pas encore : il reste des épisodes à vivre.", "sys"); return; }
    const n = parseInt(norm(c.rawArg), 10);
    if (!(n >= 1 && n <= 12)) { out("Quelle règle ? `adopter ‹n›` avec n de 1 à 12 (`politique` donne la liste).", "err"); return; }
    const r = ORDER[n - 1];
    if (x.pol.includes(r)) { out("Déjà retenue.", "sys"); return; }
    if (x.pol.length >= 6) { out("Six règles au plus : une politique que personne ne retient n'est pas appliquée. `retirer ‹n›` d'abord.", "err"); return; }
    x.pol.push(r); out("Retenue : « " + RULES[r].short + " » (" + x.pol.length + "/6).", "ok");
  }
  function unadopt(c) {
    const x = F();
    const n = parseInt(norm(c.rawArg), 10), r = ORDER[n - 1];
    if (!r || !x.pol.includes(r)) { out("Cette règle n'est pas retenue. `retirer ‹n›`", "err"); return; }
    x.pol = x.pol.filter(i => i !== r); out("Retirée : « " + RULES[r].short + " » (" + x.pol.length + "/6).", "ok");
  }
  function testPol() {
    const x = F();
    if (S.room !== "bureau") { out("Le test se fait devant Ève, dans le bureau de Maître Ada.", "sys"); return; }
    if (x.n < 6) { out("Pas encore : il reste des épisodes à vivre.", "sys"); return; }
    if (!x.pol.length) { out("Ta politique est vide : `adopter ‹n›` d'abord.", "err"); return; }
    say("Ève", "Je rejoue les six appels de ta journée contre ta politique, un par un.");
    let ok = 0;
    SCN.forEach(id => {
      const e = evalScn(id, x.pol), R = SC[id];
      if (e.st === "stop") {
        ok++;
        out("✔ **" + R.name + "** : arrêté" + (e.eff.length > 1 ? " (" + e.eff.length + " couches : " + e.eff.map(r => RULES[r].short).join(", ") + ")" : "") + ".  " + RULES[e.eff[0]].stops[id], "ok");
      } else if (e.st === "limit") out("~ **" + R.name + "** : pas empêché, mais détecté plus vite grâce à tes règles de signalement ou de formation : dégâts limités. " + FAIL[id] + (e.blocked.length ? "  (« " + e.blocked.map(r => RULES[r].short).join(", ") + " » existait, mais a été neutralisée par une règle qui donne confiance trop facilement.)" : ""), "sys");
      else {
        out("✗ **" + R.name + "** : l'attaque aboutit. " + FAIL[id] + (e.blocked.length ? "  Tes règles « " + e.blocked.map(r => RULES[r].short).join(", ") + " » existaient, mais ont été neutralisées par une règle qui donne confiance trop facilement." : ""), "err");
      }
    });
    const notes0 = x.pol.filter(r => ["none", "bad", "weak", "detect"].includes(RULES[r].kind));
    notes0.forEach(r => out({ r9: "À propos de « Mots de passe /30 jours » : n'arrête aucun des six : le faux technicien obtient le mot de passe actuel, quel qu'il soit.", r10: "À propos de « Connaît nos noms = fiable » : dangereuse. L'épisode 2 l'a montré : qui connaît tes noms a justement fait ses devoirs. Elle neutralise tes règles de vérification.", r11: "À propos de « Numéro affiché = fiable » : un numéro s'affiche à volonté. Elle neutralise le rappel et la question convenue.", r12: "À propos de « Formation annuelle » : utile pour la culture, mais elle ne bloque aucun des six appels à elle seule.", r8: "À propos de « Signalement sans blâme » : n'arrête rien, mais accélère la détection et limite les dégâts." }[r], "sys"));
    fig("matrice");
    if (ok === 6) {
      if (!x.polOK) {
        x.polOK = true;
        out("Les six épisodes sont arrêtés ! Ève : « Aucune des six attaques ne passe. »", "title");
        say("Maître Ada", "Voilà une politique qui tient sous pression : les règles « dures » n'attendent pas que tu devines qui ment. Maintenant, va voir Bob, à la compta : il t'attend.");
      } else out("Les six épisodes sont arrêtés.", "ok");
    } else out("Politique insuffisante : " + (6 - ok) + " épisode" + (6 - ok > 1 ? "s" : "") + " passe" + (6 - ok > 1 ? "nt" : "") + ". Une règle qui dépend de ton jugement se contourne sous pression ; cherche les règles « dures » qui couvrent chaque cas. `retirer`, `adopter`, puis `tester politique`.", "sys");
  }

  /* ---------- culture du signalement ---------- */
  function thank() {
    const x = F();
    if (S.room !== "compta") { out("Bob est à la comptabilité (est du standard).", "sys"); return; }
    if (!x.polOK || !x.bobState) { out("Parle d'abord à Bob.", "sys"); return; }
    if (x.bobDone) { out("Tu l'as déjà remercié.", "sys"); return; }
    say("Toi", "Merci de me l'avoir dit, Bob. Tu as bien fait. Ça aurait pu arriver à n'importe qui. Regardons ensemble ce qu'on peut encore faire.");
    say("Bob", "Je… merci. J'avais tellement peur d'être renvoyé.");
    out("Tu appelles Léa. Simulation : deux scénarios, selon le moment où l'alerte arrive.", "sys");
    code("Alerte dans les 20 minutes (grâce à Bob) :\n  banque prévenue, virement contesté, accès renouvelés,\n  chance réelle de récupérer les fonds.\nAlerte à J+3 (si Bob s'était tu) :\n  fonds dispersés, accès abusés pendant trois jours,\n  d'autres collègues appelés avant qu'on le sache.");
    out("Évolution des signalements par mois dans deux Guildes fictives (ordres de grandeur illustratifs) :", "sys");
    code("Mois                       1    2    3    4\nGuilde du reproche        12    5    2    1   (on se tait, on découvre tard)\nGuilde du merci           12   15   21   26   (on signale, on corrige tôt)");
    x.bobState = 3; x.bobDone = true; note("culture");
    say("Maître Ada", "Voilà la règle la plus précieuse de la Guilde : on remercie ceux qui signalent, même quand ils se sont fait avoir. Retrouve-moi dans mon bureau.");
  }
  function blame() {
    const x = F();
    if (S.room !== "compta") { out("Bob est à la comptabilité (est du standard).", "sys"); return; }
    if (!x.polOK || !x.bobState) { out("Parle d'abord à Bob.", "sys"); return; }
    if (x.bobDone) { out("Bob a déjà été remercié : ce serait une drôle de façon de le remercier.", "sys"); return; }
    x.bobState = 2;
    say("Toi", "Tu as lu un code à un inconnu ? C'est une faute grave, Bob. Cela sera consigné dans ton dossier.");
    say("Bob", "…Je comprends. (Il baisse les yeux.) Je ne le referai plus. Je ne vous dirai plus rien non plus, j'imagine.");
    out("Simulation : la Guilde du reproche. Dans les mois suivants, le nombre de signalements s'effondre, pas celui des attaques :", "err");
    code("Mois                       1    2    3    4\nSignalements              12    5    2    1\nAttaques réussies          1    2    4    7   (découvertes tard, par la banque ou un client)");
    out("Quand signaler fait honte ou est puni, on se tait : et l'attaquant, lui, gagne des jours. Maître Ada soupire : « Essaie autrement. » (`remercier bob`)", "err");
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Je dois te l'avouer : toute la journée était un audit autorisé. Les appelants, la visiteuse, la clé étaient l'équipe de Mallory, mandatée par la Guilde pour éprouver notre standard. Ève a tout enregistré avec l'accord de chacun. Aucune donnée réelle n'a été touchée : tout cela se passait sur des comptes et des numéros fictifs.");
    say("Maître Ada", "Les vrais fraudeurs, eux, ne préviennent pas, et ne s'arrêtent pas à un premier « non » : ils rappellent, ou essaient quelqu'un d'autre. Alors la Guilde a une politique, des habitudes et une culture : on vérifie, on rappelle, on signale, on remercie.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le standard = le point d'entrée humain de toute organisation** (accueil, support, standard, secrétariat). Les attaques d'ingénierie sociale visent les personnes parce que ce sont elles qui détiennent les accès, et que les contourner est plus simple que de contourner une machine. Tout se déroule en quatre phases : renseignement, prétexte, pression, action.");
    out("**Les six épisodes, décodés.** (1) Le faux technicien = hameçonnage vocal (vishing) du « support » : autorité + urgence pour obtenir un mot de passe. (2) L'appel sympathique = reconnaissance par prétexte (pretexting) : de petites informations anodines, mises bout à bout, préparent d'autres attaques ; il joue sur la sympathie et la réciprocité. (3) Le faux directeur = fraude au président (BEC, usurpation de dirigeant) : autorité, urgence, secret. (4) La visiteuse = talonnage (tailgating) : sympathie et preuve sociale contre un contrôle d'accès physique. (5) La clé = appât USB (baiting) : la curiosité et la rareté (« confidentiel »). (6) Le conseiller de banque = vishing + contournement d'un code à usage unique : on te fait donner toi-même l'autorisation.");
    out("**Les leviers psychologiques** (inspirés des principes d'influence étudiés en psychologie sociale, notamment par Cialdini) : autorité, réciprocité, sympathie, preuve sociale, rareté. L'urgence, très présente dans les attaques, s'y ajoute : elle empêche de réfléchir. Les connaître ne te rend pas immunisé : ils fonctionnent même quand on les connaît. C'est pourquoi les parades sont des procédures et non du flair.");
    out("**Les parades = des contrôles qui ne reposent pas sur ton jugement.** Le rappel sur un numéro de l'annuaire = vérification par un canal indépendant (« hors bande »). La question convenue = un secret partagé qu'on ne peut pas deviner. « Jamais de mot de passe ni de code par téléphone » = une règle sans exception, donc sans négociation possible. La validation à deux personnes = le principe des quatre yeux (séparation des tâches). Léa et le cahier des signalements = la détection et la réponse à incident. La politique complète = la défense en profondeur : plusieurs couches, car n'importe laquelle peut céder.");
    out("**L'analogie des « règles dures » et « souples ».** Les règles qui ne dépendent pas d'un jugement (pas de mot de passe par téléphone, deux paraphes, un badge par personne) résistent mieux à la pression que celles qui demandent d'évaluer qui ment. Et les mauvaises règles (« il connaît nos noms donc il est fiable », « le numéro affiché est connu donc il est fiable ») sont pires que pas de règle : elles transforment les renseignements recueillis par l'attaquant en laissez-passer.");
    out("**La culture du signalement sans blâme.** Une organisation où l'on remercie ceux qui signalent apprend plus vite qu'une qui punit. C'est ce qui permet de rappeler un virement à temps, d'isoler un poste, de prévenir les collègues d'un appel suspect.");
    out("**Les simplifications du jeu.** (1) Les interlocuteurs suivent un scénario ; dans la réalité, ils improvisent, écoutent, s'adaptent à ta voix, et mêlent les leviers sans les nommer. (2) Le numéro affiché peut être falsifié et la voix imitée par des outils de clonage vocal : aucun des deux n'est simulé ici. (3) Le rappel suppose que la ligne soit bien coupée (certaines lignes restent ouvertes si l'autre ne raccroche pas : on patiente ou on appelle d'un autre poste) et que l'annuaire soit à jour. (4) Le code à usage unique est calculé ici par un hachage simple de quatre éléments ; en vrai, il suit des normes (TOTP, authentification forte liant le montant et le bénéficiaire). (5) Les conséquences sont écourtées et simplifiées : un rappel de fonds réel n'est jamais garanti. (6) La politique comporte douze règles à choisir ; une vraie politique demande aussi de la formation continue, des exercices réguliers (simulations d'hameçonnage), des contrôles techniques (authentification résistante à l'hameçonnage comme les clés FIDO2, filtrage des ports USB, journaux d'accès) et la participation de la direction. (7) Les exercices d'ingénierie sociale ne se font jamais sans autorisation écrite : ici, tout est fictif et consenti.");
    out("Rappel utile : **urgence + autorité + demande qui contourne la procédure = on raccroche, on rappelle sur un numéro connu, on signale. Et on remercie celui qui signale.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    anatomie: id => {
      const S0 = id && SC[id] ? SC[id] : null, r = S0 && F().res[id];
      const names = ["1 Renseignement", "2 Prétexte", "3 Pression", "4 Action"];
      const rows = names.map((n, i) => {
        const y = 8 + i * 62, cut = r && r.ph === i + 1, past = r && r.r !== "lose" && i + 1 > r.ph;
        const cls = cut ? (r.r === "lose" ? "f-bad" : "f-ok") : past ? "" : "f-pub";
        const l = S0 ? S0.phases[i].map((z, k) => k ? z : z.replace(/^(Prétexte|Pression douce|Pression|Action)\s*:\s*/, "").replace(/^./, m => m.toUpperCase())) : [["Qui est la cible ? Quels noms, quels outils,", "quels horaires ? (sources ouvertes, collecte)"], ["Une histoire plausible : support, banque, direction,", "prestataire, visiteur, livreur."], ["Urgence, autorité, sympathie, secret : tout pour", "empêcher de vérifier."], ["Ce qu'on veut : un mot de passe, un code, de", "l'argent, une porte ouverte, un poste branché."]][i];
        return R(6, y, 118, 52, cls) + T(65, y + 31, n, "f-b f-s") + T(134, y + 22, l[0], "f-s", "start") + T(134, y + 40, l[1], "f-s", "start") + (i < 3 ? AR(65, y + 52, 65, y + 62, "f-ln") : "") + (cut ? T(414, y + 10, r.r === "lose" ? "abouti" : "coupé ici", "f-s " + (r.r === "lose" ? "ft-bad" : "ft-ok"), "end") : "");
      }).join("");
      return {
        cap: S0 ? "Anatomie de l'épisode « " + S0.name + " » : l'attaque doit franchir quatre phases. " + (r && r.r === "lose" ? "Ici, elle a atteint l'action." : "Tu l'as coupée avant l'action : plus tôt on vérifie, moins elle avance.") : "Une attaque d'ingénierie sociale suit presque toujours ces quatre phases. On peut l'arrêter à n'importe laquelle, et plus tôt vaut mieux.",
        svg: SVG(262, "Les quatre phases d'un appel d'ingénierie sociale", rows),
      };
    },
    leviers: () => {
      const found = F().fl, keys = ["autorite", "urgence", "rarete", "reciprocite", "sympathie", "preuve"];
      const boxes = keys.map((k, i) => {
        const col = i % 2, row = Math.floor(i / 2), x = 6 + col * 208, y = 8 + row * 66, ok = found.includes(k);
        return R(x, y, 200, 58, ok ? "f-ok" : "f-pub") + T(x + 100, y + 22, (ok ? "✔ " : "") + LEV[k][0], "f-b " + (ok ? "ft-ok" : "ft-pub")) + T(x + 100, y + 42, SHORTLEV[k], "f-s");
      }).join("");
      return {
        cap: "Les six leviers psychologiques : en vert, ceux que tu as identifiés dans les appels. Une demande qui en cumule plusieurs (autorité + urgence, par exemple) est un signal d'alerte. (La curiosité sert d'appât pour les supports USB.)",
        svg: SVG(224, "Leviers psychologiques", boxes + T(210, 216, "à retenir : plusieurs leviers à la fois = on ralentit", "f-s")),
      };
    },
    rappel: () => ({
      cap: "La procédure de rappel : on raccroche, on cherche le numéro dans l'annuaire (jamais celui que l'appelant a donné) et on rappelle. Si l'appelant était un imposteur, la vraie personne ne sait rien.",
      svg: SVG(250, "Procédure de rappel",
        R(6, 10, 120, 44, "f-bad") + T(66, 30, "Appelant", "f-b ft-bad") + T(66, 46, "numéro affiché ?", "f-s") +
        R(150, 10, 110, 44) + T(205, 30, "Toi", "f-b") + T(205, 46, "au standard", "f-s") +
        R(284, 10, 130, 44, "f-pub") + T(349, 30, "Annuaire", "f-b ft-pub") + T(349, 46, "numéros vérifiés", "f-s") +
        AR(126, 32, 150, 32, "f-bad") + T(138, 70, "1. demande pressante", "f-s ft-bad") +
        AR(260, 32, 284, 32, "f-pub") + T(272, 70, "2. tu raccroches", "f-s ft-pub") +
        R(150, 108, 110, 44, "f-ok") + T(205, 128, "Vraie personne", "f-b ft-ok") + T(205, 144, "numéro connu", "f-s") +
        AR(205, 54, 205, 108, "f-ok") + T(214, 86, "3. TU rappelles", "f-s ft-ok", "start") +
        R(10, 180, 180, 54, "f-ok") + T(100, 200, "confirme : on agit", "f-b ft-ok") + T(100, 218, "(et on le consigne)", "f-s") +
        R(230, 180, 180, 54, "f-bad") + T(320, 200, "ne sait rien : imposteur", "f-b ft-bad") + T(320, 218, "(on signale tout de suite)", "f-s") +
        AR(205, 152, 100, 180, "f-ok") + AR(205, 152, 320, 180, "f-bad")),
    }),
    otp: () => {
      const x = F(), code0 = x.otp || otpOf("1249", "Atelier Nova", WIN);
      return {
        cap: "Ce que dit l'appelant (« annulation ») ne correspond pas à ce que dit le SMS (« AUTORISER »). Le code est lié au montant et au bénéficiaire : le lire à un tiers, c'est signer à sa place.",
        svg: SVG(240, "Appelant contre SMS",
          R(6, 10, 200, 80, "f-bad") + T(106, 30, "Ce que dit l'appelant", "f-b ft-bad") + T(106, 52, "« lisez-moi le code", "f-s") + T(106, 68, "pour ANNULER le paiement »", "f-s") +
          R(214, 10, 200, 80, "f-ok") + T(314, 30, "Ce que dit le SMS", "f-b ft-ok") + T(314, 52, "code " + code0 + " pour AUTORISER", "f-s") + T(314, 68, "1 249 écus vers Atelier Nova", "f-s") +
          T(210, 118, "code = 6 chiffres de f(secret, montant, bénéficiaire, instant)", "f-s") +
          T(210, 138, "autre montant ou autre bénéficiaire : tout autre code", "f-s") +
          R(60, 156, 300, 64, "f-pub") + T(210, 178, "Règle simple, sans exception :", "f-b ft-pub") + T(210, 198, "un code ne se lit jamais à un tiers.", "f-s") + T(210, 212, "Ni banque, ni support, ni collègue.", "f-s")),
      };
    },
    matrice: () => {
      const x = F(), pol = x.pol, cols = SCN.map((id, i) => ({ id, label: ["S1", "S3", "S2", "S4", "S5", "S6"][i] })).sort((a, b) => a.label.localeCompare(b.label));
      const X0 = 168, DX = 40, rows = pol.length || 1, H = 56 + rows * 24 + 46;
      let b = T(6, 18, "règle", "f-b f-s", "start");
      cols.forEach((c, i) => b += T(X0 + i * DX + 18, 18, c.label, "f-b f-s"));
      b += LN(6, 26, 414, 26);
      if (!pol.length) b += T(210, 58, "Aucune règle adoptée pour l'instant", "f-s");
      pol.forEach((r, j) => {
        const y = 46 + j * 24;
        b += T(6, y, RULES[r].short, "f-s", "start");
        cols.forEach((c, i) => {
          const e = evalScn(c.id, pol), cx = X0 + i * DX + 18;
          if (RULES[r].stops[c.id]) b += T(cx, y, e.eff.includes(r) ? "✔" : "✗", "f-b " + (e.eff.includes(r) ? "ft-ok" : "ft-bad"));
          else if (["detect", "weak"].includes(RULES[r].kind)) b += T(cx, y, "~", "f-s");
          else if (RULES[r].kind === "bad" && ((r === "r10" && ["s1", "s2", "s3", "s6"].includes(c.id)) || (r === "r11" && ["s1", "s2", "s6"].includes(c.id)))) b += T(cx, y, "⚠", "f-b ft-bad");
        });
      });
      const yy = 46 + rows * 24 + 8;
      b += LN(6, yy - 14, 414, yy - 14) + T(6, yy + 6, "résultat", "f-b f-s", "start");
      cols.forEach((c, i) => { const e = evalScn(c.id, pol), cx = X0 + i * DX + 18; b += T(cx, yy + 6, pol.length ? (e.st === "stop" ? "✔" : e.st === "limit" ? "~" : "✗") : "?", "f-b " + (e.st === "stop" ? "ft-ok" : e.st === "limit" ? "" : "ft-bad")); });
      b += T(210, yy + 30, "✔ arrête · ~ limite · ✗ échoue · ⚠ aggrave", "f-s");
      return { cap: "Matrice règles × épisodes : S1 technicien, S2 directeur, S3 collecte, S4 visiteuse, S5 clé USB, S6 code SMS. Un ✔ en bas signifie qu'au moins une règle efficace arrête l'épisode.", svg: SVG(H, "Matrice politique par scénario", b) };
    },
  };

  GAMES.social = {
    id: "social", order: 23, title: "Le Standard Téléphonique", pageTitle: "Social Quest", subtitle: "aventure textuelle · ingénierie sociale",
    blurb: "Tiens le standard de la Guilde un jour de forte activité : faux support, faux directeur, visiteuse sans badge, clé USB, code SMS.",
    concept: "Ingénierie sociale, vishing, procédures de vérification",
    start: "standard", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { F(); },
    gate(dest) {
      const x = F();
      if (x.cur && x.cur !== "s5") { out("Tu ne peux pas quitter la scène : " + (x.cur === "s4" ? "la visiteuse est devant toi, bras chargés." : "l'appelant est toujours en ligne.") + " Réponds, vérifie, refuse ou escalade.", "err"); return true; }
      if (dest === "bureau" && x.n < 6) { out("Maître Ada est occupée. Ta place est au standard : il reste des choses à vivre aujourd'hui.", "sys"); return true; }
      return false;
    },
    refig(name) { fig(name, name === "anatomie" ? (F().pend || F().last || undefined) : undefined); },
    figAlias: { anatomie: ["phases", "appel", "anatomie"], leviers: ["psychologie", "influence"], rappel: ["procedure", "verification", "callback"], otp: ["code", "sms"], matrice: ["politique", "regles"] },
    help: "Spécifiques : `decrocher` · `repondre ‹oui|non›` · `demander ‹nom|question|pourquoi›` · `verifier ‹identité›` (rappel) · `transferer ‹service›` · `donner ‹information›` · `refuser` · `escalader` (signaler) · `brancher cle` · `analyser` · `identifier ‹levier›` · `leviers` · `etat` · `politique` · `adopter ‹n›` · `retirer ‹n›` · `tester politique` · `remercier bob`",
    verbs: {
      pick: { words: ["decrocher"], run: pick },
      answer: { words: ["repondre", "acquiescer"], run(c) { const t = norm(c.rawArg); if (!t) { out("Répondre quoi ? Par exemple `repondre oui` ou `repondre non`.", "err"); return; } act(has(t, /^(non|jamais|pas question|certainement pas)/) ? "refuse" : has(t, /^(oui|ok|d accord|bien sur|entendu|volontiers|je veux bien|avec plaisir)/) ? "yes" : has(t, /^(bonjour|bonsoir|allo|salut)/) ? "hello" : "other", t, c); } },
      ask: { words: ["demander", "exiger", "interroger", "questionner"], run(c) { const t = norm(c.rawArg); if (!t) { out("Demander quoi ? `demander nom`, `demander question`, `demander pourquoi`…", "err"); return; } act("ask", t, c); } },
      verify: { words: ["verifier", "rappeler", "controler", "authentifier"], run(c) { const t = norm(c.rawArg); if (!F().cur && has(t, /annuaire|classeur|procedure|numero/)) { out(ents[has(t, /annuaire|numero/) ? "annuaire" : "classeur"].desc(), ""); return; } if (!t) { out("Vérifier quoi ? `verifier support`, `verifier directeur`, `verifier banque`…", "err"); return; } act("verify", t, c); } },
      transfer: { words: ["transferer", "passer", "rediriger", "orienter", "escorter"], run(c) { const t = norm(c.rawArg); if (!t) { out("Transférer vers quel service ? `transferer securite`, `transferer accueil`, `transferer compta`…", "err"); return; } act("transfer", t, c); } },
      give: { words: ["communiquer", "reveler", "epeler", "dicter", "executer", "virer"], run: giveCmd },
      refuse: { words: ["refuser", "raccrocher", "decliner", "ignorer"], run(c) { act("refuse", norm(c.rawArg), c); } },
      escalate: { words: ["escalader", "signaler", "alerter", "prevenir", "reporter"], run(c) { const x = F(); if (!x.quest) { out("Parle d'abord à Maître Ada.", "sys"); return; } act("escalate", norm(c.rawArg), c); } },
      plug: { words: ["brancher", "inserer", "connecter", "ouvrir cle"], run: plugCmd },
      toss: { words: ["jeter", "abandonner"], run(c) { const x = F(); if (x.cur === "s5" && S.inv.includes("cle")) act("toss", "", c); else out("Rien à jeter.", "sys"); } },
      analyse: { words: ["analyser", "decortiquer", "decomposer"], run: analyse },
      identify: { words: ["identifier", "reconnaitre", "nommer"], run: identify },
      levers: { words: ["leviers", "levier"], run: leviers },
      status: { words: ["etat", "situation", "statut", "bilan jour"], run: status },
      policy: { words: ["politique", "regles", "regle"], run: polList },
      adopt: { words: ["adopter", "ajouter", "retenir", "choisir"], run: adopt },
      unadopt: { words: ["retirer", "enlever", "supprimer"], run: unadopt },
      test: { words: ["tester", "rejouer", "evaluer"], run: testPol },
      thank: { words: ["remercier", "feliciter", "rassurer"], run: thank },
      blame: { words: ["sanctionner", "punir", "reprocher", "blamer"], run: blame },
    },
    say(txt, c) { const t = norm(c.rawArg); if (!t) { out("Dire quoi ?", "sys"); return; } act(has(t, /^(non|jamais)/) ? "refuse" : has(t, /^(oui|ok|d accord)/) ? "yes" : "other", t, c); },
    use(key, a, b) {
      const o = a === "cle" ? b : b === "cle" ? a : null;
      if (o === "ordinateur" || o === "posteisole") { plugCmd(); return; }
      return false;
    },
    intro() {
      out("Le Standard Téléphonique", "title");
      out("Un jour de forte activité à la Guilde de Port-443. Tu es Alice, au standard : tout le monde appelle, passe, demande, et tout est urgent. Maître Ada est derrière toi, Bob à la comptabilité, Léa à la sécurité, Ève écoute les lignes pour la formation.\nTu n'as qu'une seule consigne : reste toi-même, même sous pression. Chaque demande te mettra à l'épreuve ; les procédures de la Guilde sont là pour que tu n'aies pas à deviner, seule, qui dit vrai.", "");
    },
  };
})();
