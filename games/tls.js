"use strict";
const P = 23, G_ = 5, B_SECRET = 15, B_PUB = modpow(G_, B_SECRET, P); // 19 : valeur publique de Hellman
const TODAY = "5 octobre 2026";
const NOTES = {
  asym: ["Clé publique, clé privée", "Chaque personne a une paire de clés. La publique se distribue (cadenas ouvert) : on s'en sert pour CHIFFRER à son attention. La privée reste secrète : elle seule DÉCHIFFRE."],
  sig: ["Signature", "Signer = appliquer sa clé privée. Tout le monde peut vérifier avec la clé publique, personne d'autre ne peut produire la signature. Elle prouve l'auteur et que le contenu n'a pas changé."],
  sym: ["Clé de session symétrique", "Le chiffrement asymétrique est lent. TLS s'en sert pour s'entendre sur une petite clé symétrique commune (type AES), rapide, qui chiffre ensuite toute la conversation."],
  dh: ["Diffie-Hellman", "Chacun garde un nombre secret et publie g^secret mod p. En combinant la valeur de l'autre avec son propre secret, les deux obtiennent le même résultat : (g^a)^b = (g^b)^a. L'espion voit p, g, A, B mais retrouver a ou b (logarithme discret) est infaisable avec de grands nombres."],
  pfs: ["Confidentialité persistante", "Les secrets Diffie-Hellman sont éphémères : jetés après la session. Voler la clé du serveur plus tard ne permet pas de relire les anciennes conversations enregistrées."],
  cert: ["Certificat et chaîne de confiance", "Un certificat lie une clé publique à un nom, signé par une autorité (CA). Le navigateur vérifie : 1) le nom correspond au site, 2) les dates sont valides, 3) la chaîne de signatures remonte à une autorité racine qu'il connaît. Un certificat auto-signé ne prouve rien."],
  mitm: ["Homme du milieu", "Sans authentification, chiffrer ne suffit pas : un attaquant peut établir une connexion chiffrée avec chaque côté et tout relire. Les certificats servent à s'assurer de QUI se trouve de l'autre côté."],
  hs: ["Le handshake TLS 1.3", "ClientHello (suites + sa moitié Diffie-Hellman) → ServerHello (choix + sa moitié) → Certificate + CertificateVerify (identité) → Finished serveur → Finished client (intégrité de tout l'échange) → données chiffrées."]
};
/* ============ Entités ============ */
// vis: visible ou non ; npc: personnage ; take: ramassable ; label: libellé dans la liste "Tu vois"
const ENT = {
  /* objets d'inventaire */
  lettre: { names: ["lettre", "lettre alice", "pli", "enveloppe"], label: "la lettre d'Alice",
    desc: () => f().sealed
      ? "La lettre d'Alice, fermée avec le cadenas de la banque. Seule la clé privée de la banque peut l'ouvrir. Adressée à : **banque-du-port**."
      : "La lettre d'Alice : « À l'attention de banque-du-port. Merci de virer 4 200 pièces d'or vers le compte de Bob. » Elle n'est pas protégée : n'importe qui peut la lire en chemin." },
  bordereau: { names: ["bordereau", "recu", "accuse"], label: "le bordereau",
    desc: () => f().signed
      ? "Le bordereau de livraison, portant ta signature. N'importe qui peut la vérifier avec ton empreinte publique, personne ne peut la falsifier."
      : "Un bordereau de livraison vierge. La banque voudra savoir qui livre : il faut le signer." },
  sceau: { names: ["sceau", "sceau personnel", "tampon", "cle privee"], label: "ton sceau personnel",
    desc: () => "Ton sceau personnel : ta **clé privée**. Il ne quitte jamais ta poche. Appliqué sur un document, il laisse une marque que lui seul peut produire, mais que tout le monde peut vérifier." },
  cadcour: { names: ["cadenas courrier", "mon cadenas", "cadenas personnel"], label: "ton cadenas ouvert",
    desc: () => "Ton cadenas ouvert : ta **clé publique**. Tu peux en distribuer autant que tu veux : il sert à chiffrer à ton intention. Rien à signer avec." },
  cle: { names: ["cle de session", "cle session", "cle", "cle legere"], label: "la clé de session",
    desc: () => `Une petite clé de cuivre gravée du nombre **${f().secretVal}**, la **clé de session** que toi et la banque partagerez. Légère, symétrique : la même clé ferme et ouvre.` },

  /* Guilde */
  ada: { npc: true, names: ["ada", "maitre ada", "doyenne", "mentor"], label: "Maître Ada, doyenne de la Guilde",
    desc: () => "Maître Ada, doyenne de la Guilde, des lunettes sur le front et des piles de lettres en équilibre sur le comptoir. Elle a vu passer tous les types de messages, et tous les types de tricheurs." },

  /* Place */
  panneau: { names: ["panneau", "affichage"], label: "un panneau",
    desc: () => "Le panneau indique : **Guilde** (ouest) · **Atelier de Dame Rivest** (nord) · **Bureau des Sceaux** (est, et la **Banque du Port** juste derrière) · **Café Wi-Fi Gratuit** (sud)." },
  fontaine: { names: ["fontaine"], label: "", desc: () => "Une fontaine où les courriers se retrouvent. Rien d'utile, sauf que tout le monde peut voir tout le monde y parler." },

  /* Atelier */
  rivest: { npc: true, names: ["rivest", "dame rivest", "serruriere"], label: "Dame Rivest, serrurière",
    desc: () => "Dame Rivest, serrurière, des mains tachées d'huile et un trousseau énorme à la ceinture. Elle ne parle que de clés." },
  annuaire: { names: ["annuaire"], label: "l'annuaire public", desc: () => "Un immense annuaire mural : chaque habitant·e y a épinglé son cadenas ouvert, étiqueté à son nom. Celui de la **banque-du-port** est là, au milieu." },
  cadbanque: { take: true, names: ["cadenas banque", "cadenas public", "cadenas banque du port"], label: "le cadenas ouvert de la banque",
    desc: () => "Le cadenas ouvert de la banque : sa **clé publique**. N'importe qui peut le prendre et s'en servir pour fermer un message destiné à la banque. Seule la banque, avec sa clé privée, saura l'ouvrir." },

  /* Tour */
  peintres: { npc: true, names: ["peintres", "peintre", "hellman", "diffie"], label: "Diffie et Hellman, les peintres",
    desc: () => "Diffie, volubile, et Hellman, méthodique, ont inventé un tour de passe-passe pour s'accorder sur un secret devant tout le monde." },
  corbeau: { npc: true, names: ["eve", "corbeau", "oiseau"], label: "Ève, le corbeau",
    desc: () => "Un corbeau au regard vif. C'est Ève. Elle répète à voix haute tout ce qu'elle entend." },
  tableau: { names: ["tableau", "mur", "chiffres"], label: "un tableau noirci de chiffres",
    desc: () => `Écrit à la craie, en gros :  **p = ${P}**  et  **g = ${G_}**. Ces deux nombres sont publics.\nDessous, la règle : « Chacun choisit un secret. On publie g^secret mod p. On combine la valeur de l'autre avec son secret. »\nTu as un boulier de poche : \`calc ${G_}^3 mod ${P}\` calcule 5 puissance 3 modulo 23.` },
  coffre: { names: ["coffre", "coffre fort"], label: "un coffre de fer",
    desc: () => f().key ? "Le coffre est ouvert et vide : tu as pris la clé de session." : "Un coffre de fer à serrure à chiffres. Il s'ouvre quand on énonce le **secret commun** (`dire ‹nombre›`). Qui n'a pas participé à l'échange ne peut pas le connaître." },

  /* Bureau */
  capitaine: { npc: true, names: ["capitaine", "chaine", "capitaine chaine"], label: "le Capitaine Chaîne",
    desc: () => "Le Capitaine Chaîne : raide, moustache impeccable, un sceau d'argent au revers. Il ne croit que ce qui est signé par quelqu'un de confiance, lui-même signé par quelqu'un de confiance…" },
  registre: { names: ["registre", "autorites", "livre"], label: "le registre des autorités de confiance",
    desc: () => `Le registre des **autorités de confiance** de ton navigateur... pardon, de ta Guilde :\n  1. Chancellerie Royale\n  2. Guilde des Notaires\nTout ce qui n'y remonte pas, par une chaîne de signatures, n'est pas fiable.\nDate du jour : ${TODAY}.` },
  rouge: { cour: "rouge", names: ["courrier rouge", "rouge", "certificat rouge"], label: "le courrier rouge", desc: () => certText("rouge") },
  vert: { cour: "vert", names: ["courrier vert", "vert", "certificat vert"], label: "le courrier vert", desc: () => certText("vert") },
  bleu: { cour: "bleu", names: ["courrier bleu", "bleu", "certificat bleu"], label: "le courrier bleu", desc: () => certText("bleu") },
  jaune: { cour: "jaune", names: ["courrier jaune", "jaune", "certificat jaune"], label: "le courrier jaune", desc: () => certText("jaune") },

  /* Café */
  mallory: { npc: true, names: ["mallory", "silhouette", "capuche", "inconnu", "faux courrier", "courrier encapuchonne"], label: "une silhouette encapuchonnée",
    desc: () => f().malloryDone ? "Mallory a disparu par la porte de service." : "Une silhouette encapuchonnée, sac de courrier en bandoulière. Elle sourit trop." },
  cadmal: { vis: () => f().malloryOffer && !f().malloryDone, names: ["cadenas mallory", "cadenas tendu", "nouveau cadenas", "cadenas silhouette"], label: "le cadenas qu'elle te tend",
    desc: () => "Un cadenas ouvert, flambant neuf. « La clé de la banque a changé, celui de l'annuaire est périmé », dit la silhouette. Mais qui a fabriqué ce cadenas ?" },
  certmal: { vis: () => f().certShown && !f().malloryDone, names: ["certificat", "certificat mallory", "parchemin"], label: "son certificat",
    desc: () => `Le certificat de la silhouette :\n  Délivré à    : banque-du-port\n  Émetteur     : « Autorité du Café Wi-Fi »\n  Chaîne       : Autorité du Café Wi-Fi (auto-déclarée), aucune autorité de ton registre\n  Valide du 1 sept. 2026 au 1 sept. 2027\nNom ✔  Dates ✔  Chaîne ✘` },
  comptoir: { names: ["comptoir", "bar", "wifi", "enseigne"], label: "", desc: () => "« WI-FI GRATUIT. Aucun mot de passe. » Gratuit… et tout le monde peut écouter." },

  /* Banque */
  vault: { npc: true, names: ["vault", "madame vault", "banquiere", "guichet"], label: "Madame Vault, banquière",
    desc: () => "Madame Vault, banquière, droite comme une règle. Le coffre-fort de la banque est derrière elle. Elle ne fait confiance qu'à ce qui est correctement protocolé." },
  table: { names: ["table", "cartes", "protocole"], label: "la table du protocole (six cartes)",
    desc: () => {
      const cards = CARDS.map(c => `  ${S.table.includes(c.n) ? "[posée]" : "[     ]"} ${c.title}`).join("\n");
      return `Six cartes à poser dans l'ordre d'une vraie conversation sécurisée (\`poser hello client\` par exemple) :\n${cards}`;
    } },
};
const CARDS = [
  { n: 1, id: "c1", title: "hello-client", names: ["hello client", "client hello", "clienthello", "carte 1"],
    explain: "**ClientHello** : « Bonjour, voici les suites de chiffrement que je connais, et ma moitié d'échange Diffie-Hellman. » Le client parle en premier.",
    wrong: "Quelqu'un doit bien ouvrir la conversation, et ce n'est pas le serveur : c'est le client qui se présente en premier." },
  { n: 2, id: "c2", title: "hello-serveur", names: ["hello serveur", "server hello", "serverhello", "carte 2"],
    explain: "**ServerHello** : « Je choisis cette suite, et voici ma moitié Diffie-Hellman. » Dès cet instant, les deux côtés peuvent calculer le secret commun, et tout ce qui suit est chiffré.",
    wrong: "Le serveur répond au client avant de montrer quoi que ce soit d'autre : il choisit la suite et donne sa moitié du secret." },
  { n: 3, id: "c3", title: "certificat", names: ["certificat", "certificate", "carte 3"],
    explain: "**Certificate + CertificateVerify** : le serveur présente son certificat et prouve, par une signature de la conversation, qu'il détient la clé privée correspondante.",
    wrong: "Le secret commun existe, mais avec qui ? Le serveur doit maintenant prouver son identité." },
  { n: 4, id: "c4", title: "fin-serveur", names: ["fin serveur", "finished serveur", "serveur finished", "carte 4"],
    explain: "**Finished (serveur)** : un condensé de tout l'échange, calculé avec les clés. Si quelqu'un a modifié un message en route, il ne tombera pas juste.",
    wrong: "Avant les données, le serveur confirme que tout l'échange est intact : un condensé de ce qui a été dit." },
  { n: 5, id: "c5", title: "fin-client", names: ["fin client", "finished client", "client finished", "carte 5"],
    explain: "**Finished (client)** : le client fait la même vérification de son côté. Les deux parties sont d'accord sur l'historique de l'échange.",
    wrong: "Le client confirme à son tour l'intégrité de l'échange, avant d'envoyer quoi que ce soit." },
  { n: 6, id: "c6", title: "données", names: ["donnees", "donnees chiffrees", "application data", "carte 6"],
    explain: "**Données applicatives** : enfin, le vrai message, chiffré en symétrique avec la clé de session. Rapide et solide.",
    wrong: "Les données ne partent qu'une fois tout le reste en place, en toute fin." },
];
CARDS.forEach(c => { ENT[c.id] = { card: c, names: c.names, label: "", desc: () => c.explain }; });

const COURIERS = {
  rouge: { to: "banque-du-port", issuer: "Sous-Chancellerie du Port ← Chancellerie Royale (dans ton registre)", from: "1 sept. 2026", until: "1 déc. 2026", ok: true,
    why: "Nom exact, dates en cours, et la chaîne Sous-Chancellerie → Chancellerie Royale aboutit à une autorité de ton registre. Les trois contrôles passent." },
  vert: { to: "banque-du-port", issuer: "banque-du-port (auto-signé)", from: "1 janv. 2026", until: "1 janv. 2036", ok: false,
    why: "**Auto-signé** : le courrier vert s'est certifié lui-même. N'importe qui peut en fabriquer autant : aucune autorité n'a vérifié son identité." },
  bleu: { to: "banque-du-port", issuer: "Chancellerie Royale (dans ton registre)", from: "1 janv. 2024", until: "1 avr. 2025", ok: false,
    why: "**Expiré** : valable jusqu'au 1 avril 2025. Les dates limitent la durée pendant laquelle une clé volée reste exploitable." },
  jaune: { to: "banque-du-p0rt", issuer: "Sous-Chancellerie du Port ← Chancellerie Royale (dans ton registre)", from: "1 sept. 2026", until: "1 déc. 2026", ok: false,
    why: "**Mauvais nom** : « banque-du-p0rt » avec un zéro. Le certificat est valide, mais pour un autre site. Une imitation du nom ne vaut rien." }
};
function certText(c) {
  const x = COURIERS[c];
  return `Le courrier ${c} prétend représenter la banque. Son certificat :\n  Délivré à    : ${x.to}\n  Chaîne       : ${x.issuer}\n  Valide du ${x.from} au ${x.until}\nÀ toi de vérifier les trois points : nom, dates, chaîne.`;
}

/* ============ Lieux ============ */
const ROOMS = {
  guilde: { name: "La Guilde des Courriers", alias: ["guilde"], ents: ["ada"], exits: { est: "place" },
    desc: () => "Une salle basse aux murs couverts de cartes de routes. Des sacoches pendent aux crochets, des tampons s'alignent sur une étagère. Maître Ada trie du courrier derrière son comptoir. Dehors, la Place du Port." },
  place: { name: "La Place du Port", alias: ["place", "port"], ents: ["panneau", "fontaine"], exits: { ouest: "guilde", nord: "atelier", est: "bureau", sud: "cafe" },
    desc: () => "Toutes les routes de Port-443 passent ici. Des courriers pressés se croisent autour d'une fontaine. Un panneau indique les directions." },
  atelier: { name: "L'Atelier de Dame Rivest", alias: ["atelier", "serrurier", "serrurerie"], ents: ["rivest", "annuaire", "cadbanque"], exits: { sud: "place", nord: "tour" },
    desc: () => "Des centaines de cadenas ouverts pendent aux murs, étiquetés au nom de chacun·e. Sur un grand annuaire public, les habitant·e·s ont épinglé le leur. Dame Rivest polit une clé. Un escalier en colimaçon monte vers la Tour des Peintres (nord)." },
  tour: { name: "La Tour des Peintres", alias: ["tour", "peintres"], ents: ["peintres", "corbeau", "tableau", "coffre"], exits: { sud: "atelier" },
    desc: () => "Au sommet de l'escalier, un atelier baigné de lumière. Diffie et Hellman discutent près d'un coffre de fer. Un tableau noirci de chiffres couvre un mur. Sur le rebord de la fenêtre, un corbeau écoute tout." },
  bureau: { name: "Le Bureau des Sceaux", alias: ["bureau", "sceaux"], ents: ["capitaine", "registre", "rouge", "vert", "bleu", "jaune"], exits: { ouest: "place", est: "banque" },
    desc: () => "Un hall solennel. Le Capitaine Chaîne contrôle l'identité de toute personne qui prétend représenter une institution. Un registre liste les autorités de confiance. Quatre courriers (rouge, vert, bleu, jaune) attendent, chacun avec un parchemin : tous disent venir de la banque. À l'est, la porte de la Banque du Port." },
  cafe: { name: "Le café « Wi-Fi Gratuit »", alias: ["cafe", "wifi"], ents: ["mallory", "cadmal", "certmal", "comptoir"], exits: { nord: "place" },
    desc: () => "Un café bondé, enseigne criarde : WI-FI GRATUIT, ICI TOUS LES CHEMINS PASSENT. Les courriers font halte, posent leurs sacoches, et ne remarquent pas qui les observe. Une silhouette encapuchonnée te fait signe depuis le fond." },
  banque: { name: "La Banque du Port", alias: ["banque"], ents: ["vault", "table", "c1", "c2", "c3", "c4", "c5", "c6"], exits: { ouest: "bureau" },
    desc: () => "Un hall de marbre, silencieux. Derrière le guichet, Madame Vault. Sur une table, six cartes sont étalées, face visible. Une bonne conversation sécurisée suit un protocole précis." },
};


/* ============ Objectif en cours (pour les indices) ============ */
function objective() {
  const F = f();
  if (!F.quest) return "quest";
  if (!F.sealed) return "seal";
  if (!F.signed) return "sign";
  if (!F.key) return S.a == null ? "key0" : !F.sentA ? "key1" : "key2";
  if (!F.certOK) return "cert";
  if (!F.malloryDone) return "mallory";
  if (!F.protocol) return "protocol";
  if (!F.end) return "deliver";
  return "end";
}
const HINTS = {
  quest: () => ["Commence par parler à la doyenne de la Guilde.", "`parler ada`"],
  seal: () => ["La lettre d'Alice n'est pas protégée. L'Atelier de Dame Rivest (nord de la Place) tient les cadenas publics.", "À l'Atelier : `prendre cadenas banque` puis `utiliser lettre sur cadenas banque`. (De la Guilde : `aller est`, puis `aller nord`.)"],
  sign: () => ["La banque voudra savoir qui livre. Que peut-on faire d'une clé privée ?", "À l'Atelier : `utiliser sceau sur bordereau`."],
  key0: () => ["Chiffrer coûte cher : il faut une clé légère commune. Les peintres, au nord de l'Atelier, savent en fabriquer une en public.", "À la Tour : `parler peintres`, puis choisis un secret, par exemple `secret 6`."],
  key1: () => ["Calcule ta valeur publique avec le boulier, puis donne-la à Hellman.", `\`calc ${G_}^${S.a} mod ${P}\` puis \`dire ‹résultat›\`.`],
  key2: () => ["Hellman t'a donné sa valeur publique B. Combine-la avec TON secret, comme lui combinera la tienne avec le sien.", `\`calc ${B_PUB}^${S.a} mod ${P}\` puis \`dire ‹résultat›\` devant le coffre.`],
  cert: () => ["Le Bureau des Sceaux (est de la Place) t'apprendra à vérifier une identité. Trois contrôles : nom, dates, chaîne.", "`examiner rouge`, `examiner vert`, etc. Puis `accepter ‹couleur›` pour celui qui passe les trois contrôles."],
  mallory: () => ["Tu sais chiffrer, signer, partager une clé, vérifier un certificat. Le café Wi-Fi, au sud de la Place, est le point de passage de Mallory.", "`parler silhouette`, `demander certificat`, puis `accuser mallory` si le certificat est suspect."],
  protocol: () => ["Le café est sûr. La banque (est du Bureau des Sceaux) a un rituel d'accueil : les cartes sont sur la table.", "`examiner table`, puis `poser hello client` et les suivantes dans l'ordre d'une vraie conversation TLS."],
  deliver: () => ["Il ne reste plus qu'à remettre le courrier.", "`donner lettre a vault` puis `donner bordereau a vault`."],
  end: () => ["La mission est terminée ! Relis ton carnet.", "`carnet`"],
};

/* ============ Dialogues ============ */
function talk(id) {
  const F = f();
  switch (id) {
    case "ada":
      if (!F.quest) {
        F.quest = true; ["lettre", "bordereau", "sceau", "cadcour"].forEach(give);
        say("Maître Ada", "Te voilà. Écoute bien. Alice, une commerçante, doit envoyer cette lettre à la banque-du-port : un ordre de virement. Mais la route passe par le café Wi-Fi, et depuis une semaine quelqu'un lit nos lettres, parfois les modifie. Ce quelqu'un s'appelle Mallory.");
        say("Maître Ada", "Voici ton équipement : la lettre d'Alice, un bordereau de livraison, ton sceau personnel et ton cadenas ouvert. Avant de partir, trois leçons : l'Atelier de Dame Rivest (nord de la Place), la Tour des Peintres (au-dessus), le Bureau des Sceaux (est de la Place). Puis le café, puis la banque.");
        out("Tape `inventaire` pour voir ce que tu portes, `aide` pour la liste des commandes, `indice` si tu bloques.", "sys");
      } else if (F.end) say("Maître Ada", "Alice a reçu son virement, Mallory est en cavale, et tu sais maintenant ce que fait vraiment le petit cadenas de ton navigateur. Je suis fière de toi.");
      else {
        const k = objective();
        const m = { seal: "Commence par l'Atelier : cette lettre est lisible par tout le monde.", sign: "Il te reste à signer ton bordereau chez Dame Rivest.", key0: "Les peintres de la Tour t'attendent.", key1: "Les peintres de la Tour t'attendent.", key2: "Les peintres de la Tour t'attendent.", cert: "Passe au Bureau des Sceaux : il faut savoir reconnaître un vrai certificat.", mallory: "Tu es prêt pour le café Wi-Fi. Garde les yeux ouverts et ne donne ta confiance à personne sans preuve.", protocol: "Mallory est neutralisée. La banque a rouvert : à toi de jouer le protocole.", deliver: "Remets ta lettre et ton bordereau à Madame Vault." }[k];
        say("Maître Ada", m || "Alors, cette mission ?");
      }
      break;

    case "rivest":
      if (!F.sealed) say("Dame Rivest", "Une lettre confidentielle pour la banque ? Facile : on n'a pas besoin de se rencontrer avant. Chacun possède une paire de clés. Le cadenas OUVERT, c'est la clé publique : tout le monde peut en avoir. La clé qui l'ouvre, la privée, ne quitte jamais son propriétaire. Pour écrire à la banque, ferme ta lettre avec LE CADENAS DE LA BANQUE. Il est dans l'annuaire.");
      else if (!F.signed) say("Dame Rivest", "Bien. Maintenant, la banque doit savoir QUI livre. Un cadenas ouvert est public : n'importe qui en fabrique un. Une signature, c'est l'inverse : tu appliques ta clé PRIVÉE, et tout le monde peut vérifier avec ta clé publique. Signe ton bordereau avec ton sceau.");
      else {
        say("Dame Rivest", "Parfait. Chiffrer, signer : tu as les deux. Un dernier point : mes cadenas sont lourds. Pour une longue conversation, on utilise une petite clé légère, la MÊME des deux côtés, qu'on appelle clé symétrique. Le problème : comment la partager sans que quelqu'un la voie passer ?");
        say("Dame Rivest", "Monte voir les peintres, au nord. Ils ont une réponse étonnante.");
        note("sym");
      }
      break;

    case "peintres": {
      if (F.key) { say("Diffie", "Le coffre est ouvert, tu as ta clé. Et une chose importante : on jette nos secrets a et b dès la fin de la session. Si un jour quelqu'un vole nos coffres, il ne retrouvera rien des anciennes conversations."); note("pfs"); break; }
      if (S.a == null) {
        say("Hellman", `Bienvenue. Voici le problème : tu veux t'entendre sur un secret avec la banque, mais Ève, ce corbeau, répète tout ce qui se dit. Le tableau donne deux nombres publics : p = ${P} et g = ${G_}.`);
        say("Diffie", `Choisis un nombre secret entre 2 et 21 et garde-le pour toi : \`secret ‹2-21›\`, par exemple \`secret 6\`. Ensuite, calcule ta valeur publique : g puissance ton secret, modulo p, au boulier. Pour 6 : \`calc ${G_}^6 mod ${P}\`.`);
      } else if (!F.sentA) {
        say("Hellman", `Ton secret est ${S.a}. Calcule ta valeur publique avec \`calc ${G_}^${S.a} mod ${P}\`, puis annonce-la : \`dire ‹résultat›\`. Cette valeur, tout le monde peut l'entendre, même Ève.`);
      } else {
        say("Hellman", `De mon côté, j'ai fait pareil avec mon secret (que je garde) : ma valeur publique est ${B_PUB}. À toi de la combiner avec TON secret : ${B_PUB} puissance ${S.a}, modulo ${P}. Moi, je combine la tienne avec le mien : on tombera sur le même nombre, par magie des puissances.`);
        say("Diffie", "Quand tu l'as, dis-le au coffre : `dire ‹nombre›`. S'il s'ouvre, tu partages un secret avec nous. Ève, elle, n'a que nos deux valeurs publiques.");
      }
      break;
    }

    case "corbeau": {
      const A = S.a == null ? null : modpow(G_, S.a, P);
      if (A == null) say("Ève", "Croa ! J'écoute. Pour l'instant, je n'ai entendu que p = 23 et g = 5. Rien de secret.");
      else say("Ève", `Croa ! J'ai entendu : p = ${P}, g = ${G_}, A = ${A}${F.sentA ? `, B = ${B_PUB}` : ""}. Avec p = 23 je trouverais ton secret en essayant les 22 exposants possibles : fais-le toi-même au boulier si tu veux. Mais avec un p de 2 000 bits, il n'y a pas assez d'années dans l'univers. Je ne peux pas deviner le secret commun. Croa.`);
      break;
    }

    case "capitaine":
      if (F.certOK) say("Capitaine Chaîne", "Le courrier rouge est authentique : sa chaîne Sous-Chancellerie → Chancellerie Royale remonte jusqu'à une racine connue. Chaque maillon signe le suivant. C'est ça, une chaîne de confiance. Et si un maillon est révoqué, tout ce qui en dépend l'est aussi.");
      else say("Capitaine Chaîne", "Quatre courriers disent venir de la banque, un seul dit vrai. Contrôle trois choses sur chaque certificat. UN : le nom est celui du destinataire de la lettre, banque-du-port, à la lettre près. DEUX : la date du jour (5 octobre 2026) est entre les deux dates de validité. TROIS : la chaîne de signatures aboutit à une autorité de mon registre. Examine-les (`examiner rouge`...) et accepte le bon : `accepter ‹couleur›`.");
      break;

    case "mallory":
      if (F.malloryDone) { say("Mallory", "Tu n'entendras plus parler de moi... jusqu'à la prochaine faille."); break; }
      if (!F.malloryOffer) {
        F.malloryOffer = true;
        say("Silhouette", "Salut courrier ! Je suis le courrier officiel de la banque. Inutile de te taper la route : donne-moi ta lettre. Ah, et un détail : la banque a changé de clé, l'ancien cadenas de l'annuaire est périmé. Voici le nouveau, scelle ta lettre avec celui-là, c'est le bon.");
        out("La silhouette te tend un cadenas ouvert. Réfléchis : que sais-tu de cette personne ? Tu peux lui demander des preuves : `demander certificat`.", "sys");
      } else if (!F.certShown) say("Silhouette", "Alors, tu te décides ? Mon cadenas, c'est celui de la banque, fais-moi confiance.");
      else say("Silhouette", "Mon certificat est en règle : nom, dates, tout y est. Allez, scelle.");
      break;

    case "vault":
      if (F.end) say("Madame Vault", "Un plaisir de traiter avec un courrier qui connaît les règles.");
      else if (!F.protocol) say("Madame Vault", "Bonjour. Ici, on ne sort rien d'une sacoche avant d'avoir établi une connexion sécurisée dans les règles de l'art. Les six étapes sont sur la table, dans le désordre : pose-les dans l'ordre. Les cartes se jouent avec `poser ‹carte›`.");
      else say("Madame Vault", "La connexion est établie. Remets-moi ta lettre et ton bordereau.");
      break;

    default: out("Il ne répond pas.", "sys");
  }
}


function useFn(key, a, b) {
  const F = f();
  switch (key) {
    case "cadbanque+lettre":
      if (!S.inv.includes("cadbanque")) { give("cadbanque"); out("(Tu prends d'abord le cadenas.)", "sys"); }
      if (F.sealed) { out("La lettre est déjà scellée avec ce cadenas.", "sys"); return; }
      F.sealed = true;
      out("Clac. Tu fermes la lettre avec le cadenas ouvert de la banque. Maintenant, seule la banque, avec sa clé privée, pourra l'ouvrir : pas toi, pas Mallory, personne d'autre.", "ok");
      note("asym"); fig("chiffrement"); break;
    case "cadcour+lettre":
      out("Tu fermes la lettre avec ton propre cadenas… et tu réalises que seul TOI pourrais l'ouvrir. La banque n'y a pas accès. On chiffre avec la clé publique du DESTINATAIRE. Tu rouvres la lettre.", "err"); break;
    case "bordereau+sceau":
      if (F.signed) { out("Le bordereau est déjà signé.", "sys"); return; }
      F.signed = true;
      out("Tu presses ton sceau sur le bordereau. Une empreinte unique apparaît : seule ta clé privée peut la produire, mais n'importe qui peut la vérifier avec ton empreinte publique, affichée à l'annuaire de la Guilde.", "ok");
      note("sig"); fig("signature"); break;
    case "bordereau+cadbanque": case "bordereau+cadcour":
      out("Un cadenas ouvert est public : n'importe qui peut en fabriquer un. Il ne prouve pas qui tu es. Pour signer, il faut ta clé PRIVÉE, c'est-à-dire ton sceau.", "err"); break;
    case "lettre+sceau":
      out("Le sceau, c'est pour signer, et signer ne cache rien : tout le monde pourrait toujours lire la lettre. Pour la protéger, il faut chiffrer avec le cadenas du destinataire.", "err"); break;
    case "cadmal+lettre":
      if (!F.malloryOffer || F.malloryDone) { out("Rien ne se passe.", "sys"); return; }
      failMitm("Tu fermes la lettre avec le cadenas de la silhouette."); break;
    default: return false;
  }
}

function failMitm(intro) {
  const F = f();
  F.sealed = false; F.malloryOffer = true; F.mitm = (F.mitm || 0) + 1;
  out(intro, "err");
  say("Mallory", "Merci ! (elle rabat sa capuche en arrière) Ce cadenas, c'est moi qui l'ai fabriqué, et c'est MA clé privée qui l'ouvre. Je vais lire ta lettre, la refermer avec le vrai cadenas de la banque, et la lui faire parvenir. Ni Alice ni la banque ne verront jamais rien.");
  out("C'est l'attaque de l'homme du milieu : la lettre était bien chiffrée, mais pour la mauvaise personne. Ada te rend une nouvelle lettre. Retourne à l'Atelier la sceller avec le VRAI cadenas, puis reviens avec de meilleures questions : exige un certificat.", "err");
  note("mitm"); fig("mitm", false);
}


function secretCmd(rest) {
  const n = parseInt(rest.find(t => /^\d+$/.test(t)), 10);
  if (S.room !== "tour") { out("Tu n'as personne ici avec qui partager un secret.", "sys"); return; }
  if (f().key) { out("Tu as déjà ta clé de session.", "sys"); return; }
  if (!(n >= 2 && n <= 21)) { out("Choisis un nombre entre 2 et 21 : `secret 6`", "err"); return; }
  S.a = n; f().sentA = false;
  out(`Tu choisis ton secret : **${n}**. Tu ne le diras à personne. (Si tu veux en changer, refais \`secret ‹nombre›\`.)`, "ok");
  out(`Prochaine étape : calcule ta valeur publique, \`calc ${G_}^${n} mod ${P}\`, puis annonce-la avec \`dire ‹résultat›\`.`, "sys");
}

function numberSaid(n) {
  const F = f();
  if (S.room !== "tour") { out("Personne ne réagit.", "sys"); return; }
  if (F.key) { out("Le coffre est déjà ouvert.", "sys"); return; }
  if (S.a == null) { out("Tu n'as pas encore choisi de secret. (`secret ‹2-21›`)", "err"); return; }
  const A = modpow(G_, S.a, P);
  if (!F.sentA) {
    if (n === A) {
      F.sentA = true;
      say("Hellman", `${A} : c'est bien ${G_}^${S.a} mod ${P}. Ève l'a entendu, tant pis, ça ne l'avance à rien. Voici ma valeur publique : **${B_PUB}**.`);
      out(`Combine-la avec TON secret : \`calc ${B_PUB}^${S.a} mod ${P}\`, puis dis le résultat au coffre : \`dire ‹résultat›\`.`, "sys");
      note("dh"); fig("echange", { ...dhArgs(), S: null });
    } else say("Hellman", `Non, ce n'est pas ${G_}^${S.a} mod ${P}. Recalcule : \`calc ${G_}^${S.a} mod ${P}\`.`);
    return;
  }
  const secret = modpow(B_PUB, S.a, P);
  if (n === secret) {
    F.key = true; F.secretVal = secret; give("cle");
    out(`Clic. Le coffre s'ouvre. Hellman, de son côté, a calculé ${A}^${B_SECRET} mod ${P} = ${secret} : le même nombre, sans que ce nombre n'ait jamais circulé. Ève, elle, n'a entendu que ${A} et ${B_PUB}.`, "ok");
    out("À l'intérieur : une petite clé de cuivre. C'est la **clé de session**, légère et symétrique. Tu la gardes.", "ok");
    note("pfs"); note("dh"); fig("echange", dhArgs());
  } else if (n === A || n === B_PUB) say("Diffie", "Ça, c'est une valeur publique : Ève la connaît. Le secret commun, c'est la valeur de l'autre combinée avec TON secret.");
  else say("Diffie", `Pas tout à fait. Essaie : \`calc ${B_PUB}^${S.a} mod ${P}\`.`);
}

function sayCmd(txt) {
  if (/^\d+$/.test(txt)) { numberSaid(parseInt(txt, 10)); return; }
  out(txt ? `Tu dis « ${txt} ». Personne ne réagit.` : "Dire quoi ?", "sys");
}

function giveCmd(rest) {
  const F = f();
  if (!rest.length) { out("Donner quoi à qui ? (`donner ‹objet› a ‹personne›`)", "err"); return; }
  if (/^\d+$/.test(rest[0])) { if (S.room === "tour") numberSaid(parseInt(rest[0], 10)); else out("Personne ne réagit.", "sys"); return; }
  const [a, b] = splitArgs(rest);
  const item = resolve(a, e => !e.npc); if (!item) return;
  if (!S.inv.includes(item)) { out("Tu ne l'as pas sur toi.", "err"); return; }
  const who = resolve(b || "", e => e.npc); if (!who) return;
  if (who === "vault") {
    if (S.room !== "banque") return;
    if (!F.protocol) { say("Madame Vault", "Pas de précipitation : le protocole d'accueil d'abord. Les cartes sont sur la table."); return; }
    if (item === "lettre") {
      if (!F.sealed) { say("Madame Vault", "Cette lettre n'est pas scellée : elle a voyagé à découvert. Je ne la prends pas."); return; }
      F.gaveLetter = true; S.inv = S.inv.filter(x => x !== "lettre");
      out("Madame Vault ouvre la lettre avec la clé privée de la banque. Elle seule pouvait le faire.", "ok");
    } else if (item === "bordereau") {
      if (!F.signed) { say("Madame Vault", "Ce bordereau n'est pas signé : comment saurais-je qui me livre ?"); return; }
      F.gaveSlip = true; S.inv = S.inv.filter(x => x !== "bordereau");
      out("Madame Vault vérifie la signature avec ton empreinte publique de l'annuaire de la Guilde. Elle est authentique.", "ok");
    } else { say("Madame Vault", "Je n'ai que faire de cela."); return; }
    if (F.gaveLetter && F.gaveSlip) ending();
    return;
  }
  if (who === "mallory") { out("Tu ne remets pas ta lettre à quelqu'un dont tu n'as pas vérifié l'identité.", "err"); return; }
  say(ENT[who].names[0], "Merci, mais je n'en ai pas besoin.");
}

function ending() {
  const F = f(); F.end = true;
  out("Épilogue", "title");
  out("Madame Vault exécute l'ordre d'Alice : 4 200 pièces d'or, vers le compte de Bob. Personne n'a pu lire la lettre en chemin, personne ne l'a modifiée, et la banque sait précisément qui l'a livrée.", "ok");
  say("Maître Ada", "À ton retour, je t'ai préparé un thé. Tu sais maintenant ce que fait vraiment le petit cadenas dans la barre d'adresse : un échange de clés (Diffie-Hellman), un certificat vérifié (la chaîne de confiance), et un chiffrement symétrique rapide pour tout le reste. Et que sans l'identité, le chiffrement ne protège pas.");
  note("hs");
  debrief();
  out("FIN. Tape `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, ou `recommencer` pour rejouer. D'autres aventures arrivent à Port-443 (voir ROADMAP.md).", "title");
}


function debrief() {
  out("Comment ça marche vraiment : les analogies décodées", "title");
  out("**Port-443 = Internet.** 443 est le numéro de port d'HTTPS. Les **courriers** sont tes données qui voyagent de routeur en routeur. Une **sacoche ouverte** : n'importe quel équipement sur le chemin (Wi-Fi public, box, fournisseur) peut lire un message qui n'est pas chiffré.");
  out("**Le cadenas ouvert et la clé privée = cryptographie asymétrique.** Le cadenas, c'est la clé publique, que tout le monde peut prendre. Le fermer, c'est chiffrer. Seule la clé privée, que le propriétaire ne montre jamais, rouvre. En vrai (RSA, courbes elliptiques), on ne chiffre pas un message avec un cadenas physique : ce sont des calculs mathématiques faciles dans un sens, infaisables dans l'autre.");
  out("**Le sceau et le bordereau = signature numérique.** Appliquer le sceau, c'est signer avec sa clé privée. N'importe qui vérifie avec la clé publique. Limite de l'image : une vraie signature dépend du contenu (via un hachage), alors qu'un tampon se copie sur un autre document. Dans HTTPS, c'est le serveur qui signe pour prouver son identité. Le client s'authentifie en général autrement (mot de passe dans le canal chiffré).");
  out("**La clé de cuivre = clé de session symétrique.** La même clé ferme et ouvre, comme dans AES. Elle est des centaines de fois plus rapide que les cadenas : c'est elle qui chiffre vraiment la page, l'image, le mot de passe. Les clés asymétriques ne servent qu'à la mettre en place.");
  out("**Les peintres et le corbeau = Diffie-Hellman.** On a pris des nombres au lieu de couleurs : chacun publie g^secret mod p, combine la valeur de l'autre avec son secret, et les deux trouvent le même nombre. **Ève** est l'espion passif : elle voit p, g, A et B, mais retrouver le secret est le problème du logarithme discret. Ici p = 23 (trop petit, tu l'as vu) ; en vrai ce sont des courbes elliptiques (X25519) de 256 bits. Limite : en vrai personne n'« annonce » le secret au coffre, les deux côtés dérivent leurs clés de session en silence. Jeter les secrets après la session, c'est la **confidentialité persistante**.");
  out("**Le Capitaine, le registre, la Chancellerie = certificats et autorités.** Le Capitaine est ton navigateur. Le registre est son **magasin de certificats racine**. La Chancellerie Royale est une autorité racine, la Sous-Chancellerie une autorité **intermédiaire**. Les trois contrôles sont ceux du navigateur : le nom (le courrier jaune imitait « p0rt »), les dates (le bleu avait expiré), la chaîne (le vert s'était signé lui-même). Dans la vraie vie s'ajoute la vérification de révocation.");
  out("**Le café Wi-Fi et Mallory = attaque de l'homme du milieu.** Un Wi-Fi public, ou un réseau piraté, laisse un attaquant se placer entre toi et le site. Son faux cadenas est une fausse clé publique : la lettre est bien chiffrée, mais pour lui. Ce qui l'arrête, c'est le certificat. Dans ton navigateur, c'est l'écran « Votre connexion n'est pas privée » : si on clique sur « continuer quand même », on accepte le faux cadenas.");
  out("**La banque et les six cartes = le handshake TLS 1.3.** Madame Vault est le serveur. Dans l'ordre : ClientHello, ServerHello (à partir de là les deux ont le secret et chiffrent), Certificate + CertificateVerify, Finished du serveur, Finished du client (chacun confirme l'historique de l'échange, ce qui détecte toute modification), puis les données applicatives. Ce rituel prend environ un aller-retour sur le réseau.");
  out("**Les simplifications du jeu.** (1) La lettre « scellée avec le cadenas de la banque » est l'ancien fonctionnement : TLS 1.3 n'envoie pas la clé de session chiffrée avec la clé publique du serveur, elle passe par Diffie-Hellman. Le cadenas sert ici à illustrer « chiffrer pour quelqu'un ». (2) Les leçons sont rangées par quartier pour être compréhensibles. Dans une vraie connexion, tout se passe en quelques millisecondes et dans un autre ordre. (3) Les noms de ville et de personnages, eux, sont des clins d'œil : Rivest (RSA), Diffie et Hellman, Ève (eavesdropper), Mallory (malicious), Alice et Bob.");
  out("Rappel utile : **chiffrer + échanger une clé + vérifier l'identité** : il faut les trois. Sans le dernier, tu parles en secret… peut-être avec l'attaquant.", "ok");
}

function putCmd(txt) {
  if (S.room !== "banque") { out("Il n'y a rien à poser ici.", "sys"); return; }
  const F = f();
  const id = resolve(txt, e => e.card); if (!id) return;
  const c = ENT[id].card;
  if (F.protocol) { out("Le protocole est déjà établi.", "sys"); return; }
  if (S.table.includes(c.n)) { out("Cette carte est déjà sur la table.", "sys"); return; }
  if (c.n !== S.table.length + 1) { say("Madame Vault", "Pas dans cet ordre. " + c.wrong); out(`(Tu as posé ${S.table.length} carte${S.table.length > 1 ? "s" : ""} sur 6. Prochaine étape : réfléchis à ce qui vient logiquement après.)`, "sys"); return; }
  if (c.n === 3 && !F.certOK) { say("Madame Vault", "Voici mon certificat. Mais as-tu appris à en vérifier un ? Le Capitaine Chaîne te l'enseigne au Bureau des Sceaux."); return; }
  if (c.n === 6 && !F.key) { say("Madame Vault", "Tu n'as pas de clé de session pour chiffrer les données. Les peintres de la Tour en fabriquent."); return; }
  S.table.push(c.n);
  out(`Tu poses **${c.title}** (${c.n}/6).`, "ok");
  out(c.explain, "sys");
  if (S.table.length === 6) {
    F.protocol = true; note("hs"); fig("handshake");
    say("Madame Vault", "Conversation établie : identité vérifiée, historique confirmé, données chiffrées. Voilà ce que j'appelle une poignée de main. Maintenant, remets-moi ta lettre (`donner lettre a vault`) et ton bordereau (`donner bordereau a vault`).");
  }
}

function askCmd(rest) {
  const [a, b] = splitArgs(rest);
  const wantCert = a.includes("certificat");
  if (S.room === "cafe" && !f().malloryDone) {
    if (!wantCert) { out("Que veux-tu demander ? (essaie `demander certificat`)", "sys"); return; }
    if (!f().malloryOffer) { out("Parle d'abord à la silhouette.", "sys"); return; }
    f().certShown = true;
    say("Silhouette", "Mon certificat ? Bien sûr, le voici.");
    out(ENT.certmal.desc());
    out("Examine-le attentivement. Si tu le juges douteux : `accuser mallory`. Si tu lui fais confiance : `accepter certificat`.", "sys");
    return;
  }
  if (S.room === "bureau" && (a.includes("chaine") || wantCert)) { talk("capitaine"); return; }
  out("Personne ne répond à ça.", "sys");
}

function acceptCmd(txt) {
  const F = f();
  if (S.room === "bureau") {
    const id = resolve(txt, e => e.cour); if (!id) return;
    const c = ENT[id].cour, x = COURIERS[c];
    if (F.certOK) { out("Le Capitaine a déjà validé un certificat. Le sceau « vérifié » est posé.", "sys"); return; }
    if (x.ok) {
      F.certOK = true;
      out(`« Exact », dit le Capitaine en tamponnant le parchemin du courrier ${c}. ${x.why}`, "ok");
      note("cert"); fig("chaine");
    } else say("Capitaine Chaîne", "Non. " + x.why.replace(/\*\*/g, "") + " Regarde mieux : trois contrôles, nom, dates, chaîne.");
    return;
  }
  if (S.room === "cafe" && !F.malloryDone && F.certShown) {
    failMitm("Tu acceptes le certificat et le cadenas qui va avec, puis tu scelles ta lettre.");
    return;
  }
  out("Il n'y a rien à accepter ici.", "sys");
}

function refuseCmd(txt) {
  const F = f();
  if (S.room === "bureau") {
    const id = resolve(txt, e => e.cour); if (!id) return;
    const x = COURIERS[ENT[id].cour];
    if (x.ok) say("Capitaine Chaîne", "Ce certificat-là est pourtant en règle. Contrôle encore : nom, dates, chaîne.");
    else out(`« Bien vu. » ${x.why}`, "ok");
    return;
  }
  if (S.room === "cafe" && !F.malloryDone) { accuseCmd(txt); return; }
  out("Il n'y a rien à refuser ici.", "sys");
}

function accuseCmd(txt) {
  const F = f();
  if (S.room !== "cafe" || F.malloryDone) { out("Accuser qui ? Personne ne mérite ça ici.", "sys"); return; }
  if (!F.malloryOffer) { out("Parle d'abord à la silhouette.", "sys"); return; }
  if (!F.certShown) { say("Silhouette", "M'accuser ? De quoi ? Sur quelle preuve ? Demande-moi plutôt mon certificat, si tu y tiens."); return; }
  F.malloryDone = true;
  out("Tu refuses le certificat : son émetteur, l'« Autorité du Café Wi-Fi », ne figure dans aucun registre, et ne s'appuie sur aucune chaîne. Un cadenas fabriqué par la personne même qui veut te surveiller ne prouve rien.", "ok");
  say("Mallory", "(elle rabat sa capuche) Bravo. J'ai lu des dizaines de lettres comme ça : il suffit qu'on me prenne mon cadenas pour celui de la banque. Si tu t'étais contenté de partager un secret avec moi, j'en aurais partagé un autre avec la banque, et j'aurais tout relayé en lisant chaque mot. C'est le certificat qui m'arrête.");
  out("Mallory file par la porte de service. Les vigiles de la banque, prévenus, rouvrent les portes.", "ok");
  note("mitm"); fig("mitm", true);
}



const FIGS = {
  chiffrement: () => ({
    cap: "Alice ferme sa lettre avec le cadenas PUBLIC de la banque. Mallory a beau l'intercepter, seule la clé PRIVÉE de la banque l'ouvre.",
    svg: SVG(190, "Alice chiffre avec la clé publique de la banque, la banque déchiffre avec sa clé privée",
      R(8, 62, 84, 52) + T(50, 84, "Alice", "f-b") + T(50, 102, "lettre claire", "f-s") +
      AR(92, 88, 150, 88) + LOCK(162, 82, "f-pub") + T(174, 60, "cadenas public", "ft-pub") + T(174, 46, "de la banque", "ft-pub") +
      AR(198, 88, 326, 88) + T(262, 78, "lettre chiffrée", "") + T(250, 112, "Mallory : illisible", "ft-bad") +
      R(326, 62, 86, 52) + T(369, 84, "Banque", "f-b") + T(369, 102, "lettre claire", "f-s") +
      KEY(296, 150, "f-priv") + T(330, 154, "clé privée", "ft-priv", "start") + T(412, 172, "seule elle ouvre", "f-s", "end"))
  }),
  signature: () => ({
    cap: "Tu signes avec ton sceau (clé privée). La banque vérifie avec ton empreinte publique : elle sait que c'est toi et que le bordereau n'a pas changé.",
    svg: SVG(200, "Signature avec la clé privée, vérification avec la clé publique",
      R(8, 50, 84, 56) + T(50, 74, "Toi", "f-b") + T(50, 92, "(courrier)", "f-s") +
      KEY(24, 132, "f-priv") + T(8, 164, "sceau = clé privée", "ft-priv", "start") +
      AR(92, 78, 150, 78) + R(150, 40, 110, 76) + T(205, 72, "bordereau", "") + T(205, 90, "+ signature", "ft-priv") +
      AR(260, 78, 326, 78) + R(326, 50, 86, 56) + T(369, 74, "Banque", "f-b") + T(369, 92, "vérifie", "f-s") +
      KEY(300, 132, "f-pub") + T(412, 164, "empreinte publique", "ft-pub", "end") + T(412, 184, "✔ signature authentique", "ft-ok", "end"))
  }),
  echange: (x) => {
    const a = x.a, A = x.A, B = x.B, S = x.S == null ? "?" : x.S;
    return {
      cap: "Diffie-Hellman : chacun garde un secret (en orange) et n'envoie que sa valeur publique (en bleu). Ève voit les valeurs publiques, jamais les secrets, et les deux côtés retombent sur le même nombre.",
      svg: SVG(250, "Échange de clés Diffie-Hellman",
        R(8, 14, 130, 150) + T(73, 34, "Toi (Alice)", "f-b") + T(73, 60, "secret a = " + a, "ft-priv") + T(73, 77, "(jamais dit)", "f-s") +
        T(73, 112, "A = 5^" + a + " mod 23", "ft-pub") + T(73, 130, "= " + A, "ft-pub f-b") +
        R(282, 14, 130, 150) + T(347, 34, "Hellman", "f-b") + T(347, 60, "secret b = ?", "ft-priv") + T(347, 77, "(jamais dit)", "f-s") +
        T(347, 112, "B = 5^b mod 23", "ft-pub") + T(347, 130, "= " + B, "ft-pub f-b") +
        T(210, 36, "publics :", "f-s") + T(210, 52, "p = 23   g = 5", "") +
        AR(138, 96, 282, 96, "f-pub") + T(210, 90, "A = " + A, "ft-pub") + AR(282, 144, 138, 144, "f-pub") + T(210, 138, "B = " + B, "ft-pub") +
        R(120, 178, 180, 46, "f-bad") + T(210, 196, "Ève entend seulement", "ft-bad") + T(210, 213, "p, g, " + A + " et " + B, "ft-bad") +
        T(73, 192, "B^a mod 23", "") + T(73, 210, "= " + S, "ft-ok f-b") + T(347, 192, "A^b mod 23", "") + T(347, 210, "= " + S, "ft-ok f-b") +
        T(210, 244, "même secret commun des deux côtés", "f-s"))
    };
  },
  chaine: () => ({
    cap: "Chaque maillon est signé par celui du dessus. Le navigateur remonte jusqu'à une autorité racine qu'il connaît déjà (son registre).",
    svg: SVG(232, "Chaîne de confiance d'un certificat",
      R(8, 12, 250, 50, "f-ok") + T(133, 34, "Chancellerie Royale", "f-b") + T(133, 51, "racine : dans ton registre", "f-s") +
      AR(133, 62, 133, 90) + T(150, 80, "signe", "f-s", "start") +
      R(8, 90, 250, 50) + T(133, 112, "Sous-Chancellerie du Port", "f-b") + T(133, 129, "autorité intermédiaire", "f-s") +
      AR(133, 140, 133, 168) + T(150, 158, "signe", "f-s", "start") +
      R(8, 168, 250, 50, "f-pub") + T(133, 190, "banque-du-port", "f-b") + T(133, 207, "certificat : nom + clé publique + dates", "f-s") +
      R(280, 12, 132, 206) + T(346, 36, "Le navigateur", "f-b") + T(346, 53, "vérifie :", "f-s") +
      T(292, 90, "1. le nom", "", "start") + T(400, 90, "✔", "ft-ok", "end") +
      T(292, 118, "2. les dates", "", "start") + T(400, 118, "✔", "ft-ok", "end") +
      T(292, 146, "3. la chaîne", "", "start") + T(400, 146, "✔", "ft-ok", "end") +
      T(346, 194, "→ confiance", "ft-ok f-b"))
  }),
  mitm: (blocked) => ({
    cap: blocked
      ? "Le certificat de Mallory ne remonte à aucune autorité connue : la connexion est refusée avant que la lettre parte."
      : "Mallory fait un échange chiffré avec Alice ET un autre avec la banque. Tout est « sécurisé »… mais elle lit tout au milieu.",
    svg: SVG(250, "Attaque de l'homme du milieu",
      R(8, 84, 76, 50) + T(46, 114, "Alice", "f-b") + R(172, 84, 76, 50, "f-bad") + T(210, 114, "Mallory", "f-b ft-bad") + R(336, 84, 76, 50) + T(374, 114, "Banque", "f-b") +
      AR(84, 102, 172, 102, blocked ? "f-bad" : "f-pub", true) + AR(248, 102, 336, 102, blocked ? "f-dash f-ln" : "f-pub", true) +
      LOCK(116, 54, blocked ? "f-priv" : "f-pub") + T(128, 40, "cadenas de Mallory", blocked ? "ft-bad" : "ft-pub") +
      LOCK(280, 54, "f-pub") + T(292, 40, "cadenas banque", "ft-pub") +
      (blocked ? `<text x="128" y="132" text-anchor="middle" class="f-t ft-bad" style="font-size:22px;font-weight:700">✗</text>` : "") +
      T(210, 156, "lit tout en clair", "ft-bad") + T(210, 172, blocked ? "(bloquée)" : "puis rechiffre", "f-s") +
      T(210, 206, blocked ? "Certificat refusé : aucune autorité" : "Alice croit parler à la banque :", blocked ? "ft-ok" : "ft-bad") +
      T(210, 224, blocked ? "du registre n'a signé ce cadenas." : "le cadenas s'affiche, mais c'est le mauvais.", blocked ? "ft-ok" : "ft-bad"))
  }),
  handshake: () => {
    const row = (y, dir, n, title, sub, enc) => {
      const c = enc ? "f-pub" : "";
      const a = dir === ">" ? AR(70, y, 350, y, c) : dir === "<" ? AR(350, y, 70, y, c) : AR(70, y, 350, y, c, true);
      return a + T(210, y - 17, n + ". " + title, "f-b") + T(210, y - 5, sub, "f-s");
    };
    return {
      cap: "Le client parle en premier. Dès le ServerHello, les deux côtés ont le secret et tout est chiffré (en bleu). Les Finished confirment que personne n'a rien modifié.",
      svg: SVG(340, "Handshake TLS 1.3",
        R(20, 6, 100, 26) + T(70, 24, "Client", "f-b") + R(300, 6, 100, 26) + T(350, 24, "Serveur", "f-b") +
        `<line x1="70" y1="32" x2="70" y2="332" class="f-ln f-dash"/><line x1="350" y1="32" x2="350" y2="332" class="f-ln f-dash"/>` +
        row(66, ">", 1, "ClientHello", "suites acceptées + sa moitié DH", false) +
        row(104, "<", 2, "ServerHello", "suite choisie + sa moitié DH", false) +
        `<line x1="20" y1="124" x2="400" y2="124" class="f-ln f-pub f-dash"/>` + T(210, 120, "", "") + T(400, 138, "chiffré à partir d'ici", "ft-pub f-s", "end") +
        row(168, "<", 3, "Certificate + Verify", "identité + signature", true) +
        row(208, "<", 4, "Finished", "résumé de tout l'échange", true) +
        row(248, ">", 5, "Finished", "idem côté client", true) +
        row(296, "x", 6, "Données applicatives", "chiffrées avec la clé de session", true))
    };
  }
};
const FIG_ALIAS = { chiffrement: ["chiffrement", "cadenas", "asymetrique", "cles"], signature: ["signature", "sceau"], echange: ["echange", "diffie", "hellman", "dh", "peintres"], chaine: ["chaine", "certificat", "confiance"], mitm: ["mitm", "mallory", "homme"], handshake: ["handshake", "poignee", "protocole"] };


function dhArgs() { const a = S.a || 6; return { a, A: modpow(G_, a, P), B: B_PUB, S: f().key ? f().secretVal : null }; }

/* ============ Branchement sur le moteur ============ */
function tlsGate(dest) {
  const F = f();
  if (dest === "cafe" && !F.malloryDone) {
    const missing = [];
    if (!F.sealed) missing.push("ta lettre n'est pas scellée");
    if (!F.signed) missing.push("ton bordereau n'est pas signé");
    if (!F.key) missing.push("tu n'as pas de clé de session");
    if (!F.certOK) missing.push("tu ne sais pas encore vérifier un certificat");
    if (missing.length) {
      say("Maître Ada", `(elle te rattrape par la manche) Pas dans cet état ! ${missing.join(", ")}. Le café est le territoire de Mallory : on n'y entre pas à découvert.`);
      return true;
    }
  }
  if (dest === "banque" && !F.malloryDone) {
    out("Un vigile barre la porte : « La banque est fermée. Une personne malveillante rôde sur la route, on ne reçoit plus personne tant qu'elle n'est pas neutralisée. » Elle traîne sans doute au café Wi-Fi.", "err");
    return true;
  }
  return false;
}

GAMES.tls = {
  id: "tls", order: 1, title: "Le Courrier de Port-443", pageTitle: "TLS Quest", subtitle: "aventure textuelle · TLS",
  blurb: "Livre une lettre confidentielle à la banque malgré Mallory. Clés, certificats, handshake.",
  concept: "TLS, certificats, HTTPS",
  start: "guilde", firstCommand: "parler ada", setup() { S.table = []; },
  ents: ENT, rooms: ROOMS, notes: NOTES, hints: HINTS, figs: FIGS, refig(name) { if (name === "echange") fig(name, dhArgs()); else if (name === "mitm") fig(name, !!f().malloryDone); else fig(name); },
  figAlias: { chiffrement: ["cadenas", "asymetrique", "cles"], signature: ["sceau"], echange: ["diffie", "hellman", "dh", "peintres"], chaine: ["certificat", "confiance"], mitm: ["mallory", "homme"], handshake: ["poignee", "protocole"] },
  objective, talk, gate: tlsGate, use: useFn, say: txt => sayCmd(txt), debrief, isEnd: () => !!f().end,
  help: "Spécifiques : `demander certificat` · `accepter` / `refuser` / `accuser` · `poser ‹carte›` · `secret ‹nombre›`",
  verbs: {
    secret: { words: ["secret", "choisir"], run: c => secretCmd(c.rest) },
    put: { words: ["poser", "placer", "mettre"], run: c => putCmd(c.target) },
    ask: { words: ["demander", "reclamer", "exiger"], run: c => askCmd(c.rest) },
    accept: { words: ["accepter", "valider", "approuver"], run: c => acceptCmd(c.target) },
    refuse: { words: ["refuser", "rejeter"], run: c => refuseCmd(c.target) },
    accuse: { words: ["accuser", "denoncer", "demasquer", "arreter"], run: c => accuseCmd(c.target) },
    give: { run: c => giveCmd(c.rest) },
  },
  intro() {
    out("Le Courrier de Port-443", "title");
    out("Port-443 est une cité marchande où se croisent toutes les routes. Ici, les messages voyagent à pied, dans la sacoche de courriers comme toi. Et n'importe qui peut ouvrir une sacoche sur le chemin.\nOn vient de t'admettre à la Guilde des Courriers. Première mission : acheminer la lettre confidentielle d'une commerçante jusqu'à sa banque, sans que personne, jamais, ne puisse la lire ni la modifier. Une certaine Mallory rôde.", "");
    out("Tu joues en tapant des commandes (ou en cliquant sur celles en orange). `aide` liste tout, `indice` te débloque.", "sys");
  },
};
Object.entries({ guilde: "Guilde", place: "Place du Port", atelier: "Atelier", tour: "Tour des Peintres", bureau: "Bureau des Sceaux", cafe: "Café Wi-Fi", banque: "Banque" }).forEach(([k, v]) => ROOMS[k].short = v);
