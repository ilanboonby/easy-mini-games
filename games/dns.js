"use strict";
/* L'Annuaire de Port-443 : DNS (résolution itérative, cache/TTL), empoisonnement de cache, DNSSEC, DoH/DoT. */
(function () {
  const F = () => f();
  const NAME = "banque.port443", WWW = "www.banque.port443", IP = "10.4.4.20", FAKE = "10.6.6.6";
  const TTL = 300, FAKE_TTL = 86400, FLOOD = 1000, ID_SPACE = 65536, PORTS = 64512, RACE_MS = 50;
  const CAP = 100000;

  /* ---------- petite cryptographie de jeu : RSA jouet (clés de ~29 bits), hachage SHA-256 réel ---------- */
  const E = 65537n;
  function inv(a, m) { let [r0, r1, s0, s1] = [BigInt(a), BigInt(m), 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return ((s0 % BigInt(m)) + BigInt(m)) % BigInt(m); }
  function genKey(p, q) { const n = p * q; const d = Number(inv(E, BigInt(p - 1) * BigInt(q - 1))); return { n, e: Number(E), d }; }
  const KEYS = { root: genKey(20011, 20021), tld: genKey(20023, 20029), bank: genKey(20047, 20051), mal: genKey(20063, 20071) };
  const ZNAME = { root: ".", tld: "port443.", bank: "banque.port443.", mal: "banque.port443." };
  const hv = s => parseInt(sha256(s).slice(0, 6), 16); // empreinte de 24 bits (< n)
  const keyStr = z => KEYS[z].n + ":" + KEYS[z].e;
  const digest = z => sha256("DS|" + ZNAME[z] + "|" + keyStr(z)).slice(0, 16);
  const sign = (z, data) => modpow(hv(data), KEYS[z].d, KEYS[z].n);
  const unsign = (z, sig) => modpow(sig, KEYS[z].e, KEYS[z].n);
  const ANCHOR = digest("root");
  const dsData = z => "DS|" + ZNAME[z] + "|" + digest(z);
  const aData = ip => "A|" + NAME + ".|" + ip + "|" + TTL;

  /* ---------- simulation de l'empoisonnement ---------- */
  function rnd() {
    const x = F();
    let t = x.seed = (x.seed + 0x6D2B79F5) | 0;
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  const idSpace = () => F().cfg.txid === "alea" ? ID_SPACE : 1;
  const portSpace = () => F().cfg.port === "alea" ? PORTS : 1;
  const pRace = () => Math.min(1, FLOOD / (idSpace() * portSpace()));
  const fr = s => String(s).replace(".", ",");
  const fmtP = p => p >= 0.9999 ? "100 %" : fr(p >= 0.01 ? (p * 100).toFixed(2) + " %" : (p * 100).toPrecision(2) + " %");
  const num = n => Math.round(n).toLocaleString("fr-FR");
  function fmtD(s) {
    if (s < 1) return "moins d'une seconde";
    if (s < 90) return Math.round(s) + " secondes";
    if (s < 5400) return Math.round(s / 60) + " minutes";
    if (s < 129600) return fr((s / 3600).toFixed(1)) + " heures";
    return fr((s / 86400).toFixed(1)) + " jours";
  }
  const poisoned = () => { const c = F().cache; return !!(c.A && c.A.fake); };

  const notes = {
    hier: ["La hiérarchie du DNS", "Le DNS est un annuaire distribué : personne ne détient tout. La racine (« . ») sait quels serveurs gèrent chaque domaine de premier niveau (TLD, ici .port443) ; le serveur du TLD sait qui gère chaque domaine (banque.port443) ; le serveur faisant autorité de ce domaine détient la réponse finale. Un résolveur descend cette hiérarchie, de renvoi en renvoi (résolution itérative), et ne reçoit la vraie réponse qu'à la fin."],
    types: ["Les types d'enregistrements", "A : un nom → une adresse IPv4 (AAAA pour IPv6). NS : quels serveurs font autorité pour une zone. CNAME : un nom est l'alias d'un autre nom (il faut alors résoudre la cible). Chaque enregistrement porte un TTL, sa durée de validité en secondes. Il existe aussi MX (courrier), TXT (texte libre), etc. Une réponse peut être vide mais valide : le nom existe, pas ce type."],
    cache: ["Le cache et le TTL", "Un résolveur garde chaque réponse en mémoire pendant son TTL : tant qu'il n'a pas expiré, la même question reçoit une réponse immédiate, sans interroger personne. Un TTL long soulage les serveurs et accélère tout ; un TTL court permet de changer une adresse vite. Corollaire : une fausse réponse mise en cache est servie à tout le monde, jusqu'à son expiration."],
    poison: ["L'empoisonnement de cache", "Le DNS classique répond en clair, sans signature. Un attaquant qui fait poser une question au résolveur peut inonder celui-ci de fausses réponses avant la vraie : la première qui paraît correcte est acceptée et mise en cache, avec le TTL choisi par l'attaquant. Tous les clients du résolveur sont alors redirigés vers sa fausse adresse."],
    txid: ["Identifiant de transaction et port source", "Pour accepter une réponse, le résolveur vérifie qu'elle vient du bon serveur, répond à la bonne question et reprend l'identifiant de transaction de 16 bits (65 536 valeurs) de la requête, envoyée depuis un port source. Si l'identifiant est prévisible, l'attaque est immédiate. Même aléatoire, 16 bits se devinent à force de courses (c'est l'attaque de Kaminsky, 2008). Ajouter un port source aléatoire (~16 bits de plus) multiplie le travail par environ 64 000. C'est une rustine, pas une garantie."],
    dnssec: ["DNSSEC : la chaîne de confiance", "DNSSEC signe les enregistrements : un RRSIG est une signature de l'ensemble de réponses, vérifiable avec la clé publique de la zone (DNSKEY). Cette clé est elle-même garantie par le parent : il publie un DS (empreinte de la clé enfant) et le signe. On remonte ainsi jusqu'à la racine, dont la clé est l'ancre de confiance installée d'avance dans le résolveur. Une réponse forgée n'a pas de signature valide : elle est rejetée (SERVFAIL), même si l'attaquant a gagné la course."],
    doh: ["DNS en clair, DoT et DoH", "Le DNS classique circule en clair (UDP/TCP 53) : quiconque est sur le chemin voit quels noms tu demandes. DNS over TLS (DoT, port 853) et DNS over HTTPS (DoH, port 443) enveloppent les requêtes dans TLS entre toi et le résolveur : le réseau ne voit plus que des octets chiffrés vers le résolveur."],
    limites: ["Les limites de DNSSEC et de DoH", "DNSSEC authentifie les réponses (origine et intégrité) mais ne chiffre rien : les noms demandés restent lisibles. DoH/DoT chiffrent le trajet mais n'authentifient pas le contenu de la réponse, et le résolveur voit tout. Après la résolution, l'adresse IP contactée (et souvent le nom, dans le SNI de TLS) trahit encore le site visité. Les deux sont complémentaires, ni l'un ni l'autre ne suffit seul."],
    iter: ["Résolveur récursif et résolution itérative", "Ton appareil pose la question à un résolveur récursif, qui fait tout le travail à sa place : il interroge la racine, le TLD, puis le serveur faisant autorité, en suivant les renvois (c'est l'itération). Il garde le résultat en cache pour tous ses clients, d'où l'importance de le protéger."],
  };

  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, venue avec une pile de contrats d'audit signés. Tout ce que tu fais ici est simulé, et autorisé." },
    horloge: { names: ["horloge", "pendule", "sablier"], label: "l'horloge de l'annuaire", desc: () => "L'horloge de l'annuaire : t = " + F().t + " secondes depuis ton arrivée. Elle avance quand tu `attendre ‹secondes›`." },
    commis: { npc: true, names: ["commis", "resolveur", "resolveur local", "facteur en chef"], label: "le Commis du résolveur local", desc: () => "Le Commis du résolveur local : un petit homme derrière un comptoir, un registre ouvert devant lui (le cache). C'est lui qui répond à tous les habitants de Port-443. Il ne sait que ce qu'on lui a déjà appris." },
    cache: { names: ["cache", "registre"], label: "le registre du cache", desc: () => cacheText() },
    racine: { npc: true, names: ["racine", "serveur racine", "archiviste", "archiviste racine"], label: "l'Archiviste de la Racine", desc: () => "L'Archiviste de la Racine, perché sur une échelle roulante. Il ne connaît aucune adresse de banque, mais il sait qui gère chaque domaine de premier niveau, comme .port443." },
    tld: { npc: true, names: ["tld", "scribe", "scribe du tld", "serveur tld", "port443"], label: "le Scribe du TLD .port443", desc: () => "Le Scribe du TLD .port443 : il tient le registre de tous les domaines enregistrés sous .port443, et sait qui fait autorité pour chacun." },
    autorite: { npc: true, names: ["autorite", "notaire", "serveur", "ns1", "serveur faisant autorite"], label: "le Notaire de banque.port443 (faisant autorité)", desc: () => "Le Notaire de banque.port443, serveur faisant autorité : lui seul détient la vérité sur ce domaine. Il ne renvoie personne ailleurs : il répond." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", desc: () => "Mallory, adossée au mur, un paquet de faux courriers sous le bras. Elle dit qu'elle est « en audit autorisé », et ça se voit à son sourire." },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, assise sur un tonneau, une oreille collée à la canalisation par où passent les requêtes. Elle n'altère rien : elle regarde, elle écoute." },
    reponse: { take: true, names: ["reponse", "reponse du notaire", "enregistrement"], label: "la réponse du Notaire", desc: () => "Un parchemin : « " + NAME + ". " + TTL + " IN A " + IP + " ». À rapporter au Commis : `donner reponse au commis`." },
    dossier: { names: ["dossier", "preuves", "dossier de preuves"], label: "ton dossier de preuves DNSSEC", desc: () => kitText() },
    fausse: { names: ["fausse reponse", "faux", "reponse forgee", "forgerie"], label: "la fausse réponse de Mallory", desc: () => "Une réponse forgée : « " + NAME + ". A " + FAKE + " », avec une signature que Mallory a fabriquée. `verifier fausse reponse` au bureau du Commis pour la tester." },
  };

  function cacheText() {
    const x = F(), c = x.cache.A;
    if (!c) return "Le registre du cache est vide : le Commis n'a rien en mémoire.";
    const left = c.exp - x.t;
    return "Le registre du cache :\n  " + NAME + ". A " + c.val + "   TTL restant : " + left + " s sur " + c.ttl + " s" + (c.fake ? "\n  (cette entrée a été posée par Mallory !)" : "");
  }
  function kitText() {
    const x = F(), k = x.kit || {};
    return "Ton dossier de preuves DNSSEC :\n  racine : " + (k.root ? "DNSKEY(.) et DS(port443.) + signature, récupérés" : "à récupérer") + "\n  TLD    : " + (k.tld ? "DNSKEY(port443.) et DS(banque.port443.) + signature, récupérés" : "à récupérer") + "\n  banque : " + (k.auth ? "DNSKEY(banque.port443.) et A + signature, récupérés" : "à récupérer") + "\nVérifications faites : " + (["anchor", "tld", "bank", "rep"].filter(s => (x.v || {})[s]).length) + "/4.";
  }

  const rooms = {
    hall: { name: "Le hall de l'Annuaire", short: "Hall", alias: ["hall", "annuaire"], ents: ["ada", "horloge"], exits: { nord: "resolveur", est: "racine", ouest: "tld", sud: "ruelle" },
      desc: () => "Un grand hall tapissé de casiers : l'Annuaire de Port-443, où l'on trouve l'adresse de n'importe quel nom. Tu es le facteur : tu dois remettre un pli à « banque.port443 », mais tu ne connais pas son adresse. Au nord, le bureau du résolveur local. À l'est, la Tour de la Racine. À l'ouest, le Pavillon du TLD .port443. Au sud, une ruelle où l'on entend des murmures." },
    resolveur: { name: "Le bureau du résolveur local", short: "Résolveur", alias: ["resolveur", "bureau", "commis"], ents: ["commis", "cache"], exits: { sud: "hall" },
      desc: () => "Un comptoir, un registre, une file d'habitants qui posent tous la même sorte de question. Le Commis note chaque réponse apprise pour ne pas la redemander. C'est ici que tu configures le résolveur : `configurer` (sans rien) montre ses réglages." },
    racine: { name: "La Tour de la Racine", short: "Racine", alias: ["racine", "tour"], ents: ["racine"], exits: { ouest: "hall" },
      desc: () => "Une tour étroite, des étagères jusqu'au plafond. Treize bureaux identiques (les « serveurs racine ») répondent ici à toutes les questions de la planète. Tous les chemins commencent en haut de cette tour." },
    tld: { name: "Le Pavillon du TLD .port443", short: "TLD .port443", alias: ["tld", "pavillon", "port443"], ents: ["tld"], exits: { est: "hall", ouest: "autorite" },
      desc: () => "Un pavillon de verre où sont rangées les fiches de tous les domaines en .port443. À l'ouest, l'étude du Notaire qui fait autorité sur banque.port443." },
    autorite: { name: "L'étude du Notaire de banque.port443", short: "Étude du Notaire", alias: ["autorite", "etude", "notaire", "banque"], ents: ["autorite"], exits: { est: "tld" },
      desc: () => "Une étude calme, des dossiers soigneusement classés. Le Notaire tient la zone de banque.port443 : c'est la source de vérité de ce domaine." },
    ruelle: { name: "La ruelle des murmures", short: "Ruelle", alias: ["ruelle"], ents: ["mallory", "eve"], exits: { nord: "hall" },
      desc: () => "Une ruelle étroite où l'on voit passer la canalisation des requêtes. Mallory y flâne, Ève s'y tient en observation." },
  };

  /* ---------- objectifs et indices ---------- */
  const typesDone = () => { const s = F().seenT || {}; return s.A && s.NS && s.CNAME; };
  const kitDone = () => { const k = F().kit || {}; return k.root && k.tld && k.auth; };
  const objective = () => {
    const x = F(), v = x.v || {};
    if (!x.quest) return "quest";
    if (!x.root) return "root";
    if (!x.tld) return "tld";
    if (!x.auth) return "auth";
    if (!typesDone()) return "types";
    if (!x.delivered) return "deliver";
    if (!x.hitCache) return "hit";
    if (!x.expired) return "expire";
    if (!x.hit1) return "hit1";
    if (!x.sawFake) return "fake";
    if (!x.hit2) { if (x.cfg.txid !== "alea") return "id"; if (poisoned()) return "clear2"; return "hit2"; }
    if (!x.fail3) { if (x.cfg.port !== "alea") return "port"; if (poisoned()) return "clear3"; return "fail3"; }
    if (!x.signed) return "ada2";
    if (!kitDone()) return "fetch";
    if (!v.anchor) return "v1";
    if (!v.tld) return "v2";
    if (!v.bank) return "v3";
    if (!v.rep) return "v4";
    if (!x.forged) return "forge";
    if (!x.rejected) return "v5";
    if (!x.sawClear) return "eve1";
    if (x.cfg.transport === "clair") return "doh";
    if (!x.sawEnc) return "eve2";
    if (!x.eveTalk) return "eve3";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend dans le hall.", "`parler ada`"],
    root: () => ["Tu cherches l'adresse de banque.port443. Le résolveur (nord) ne la connaît pas encore : il faut descendre la hiérarchie en commençant tout en haut, à la Tour de la Racine (est du hall).", "`aller est`, puis `interroger banque.port443 A`."],
    tld: () => ["La Racine t'a renvoyé vers le serveur du TLD .port443. Il est à l'ouest du hall.", "`aller ouest` (depuis le hall), puis `interroger banque.port443 A`."],
    auth: () => ["Le Scribe du TLD t'a renvoyé vers le serveur qui fait autorité sur banque.port443 : l'étude du Notaire, à l'ouest du pavillon.", "`aller ouest`, puis `interroger banque.port443 A`."],
    types: () => ["Pendant que tu es chez le Notaire, regarde les autres types d'enregistrements : la liste des serveurs de la zone (NS) et l'alias www (CNAME).", "`interroger banque.port443 NS` puis `interroger www.banque.port443 CNAME`."],
    deliver: () => ["Rapporte le parchemin au Commis du résolveur pour qu'il le mémorise (cache).", "Va au bureau du résolveur (hall, puis nord) : `donner reponse au commis`."],
    hit: () => ["Redemande l'adresse au Commis : que remarques-tu ?", "`resoudre banque.port443` (au bureau du résolveur)."],
    expire: () => ["Le TTL est de 300 secondes. Laisse le temps passer pour voir l'entrée expirer.", "`attendre 301`, puis `resoudre banque.port443`."],
    hit1: () => ["Le cache est vide : c'est le moment où Mallory peut tenter sa chance. Elle est dans la ruelle (sud du hall). Le résolveur utilise pour l'instant des identifiants séquentiels et un port fixe.", "`aller sud`, `aller sud`, puis `empoisonner 100` (il suffit qu'elle gagne une fois)."],
    fake: () => ["Mallory a gagné la course. Va voir ce que répond maintenant le Commis.", "`aller nord`, `aller nord`, puis `resoudre banque.port443`."],
    id: () => ["Premier réglage : des identifiants de transaction aléatoires, au lieu de séquentiels. Puis il faut vider le cache empoisonné.", "Au bureau du résolveur : `configurer txid aleatoire`, puis `vider cache`."],
    clear2: () => ["Le cache contient encore la fausse entrée de Mallory.", "`vider cache` (au bureau du résolveur)."],
    hit2: () => ["Retente avec des identifiants aléatoires : 16 bits, est-ce suffisant ? Elle peut recommencer des milliers de courses.", "Dans la ruelle : `empoisonner 5000`."],
    port: () => ["Deuxième réglage : un port source aléatoire en plus de l'identifiant. Puis vide encore le cache.", "Au bureau du résolveur : `configurer port aleatoire`, puis `vider cache`."],
    clear3: () => ["Le cache contient encore une fausse entrée.", "`vider cache` (au bureau du résolveur)."],
    fail3: () => ["Même défi, avec cette fois deux inconnues à deviner. Regarde ce que cela change.", "Dans la ruelle : `empoisonner 100000`."],
    ada2: () => ["Le hasard ralentit Mallory sans rien prouver. Retourne voir Maître Ada pour la suite.", "`aller nord` jusqu'au hall, puis `parler ada`."],
    fetch: () => ["Port-443 signe désormais ses zones. Pour vérifier une réponse, il faut rassembler les clés et les signatures de chaque niveau : un serveur à la fois, du haut vers le bas.", "À la Racine, au TLD puis chez le Notaire : `interroger banque.port443 dnssec`."],
    v1: () => ["Rien n'est vrai tant qu'on n'a pas un point de départ de confiance : la clé de la racine, dont l'empreinte est installée d'avance chez le Commis (l'ancre).", "Au bureau du résolveur : `verifier ancre`."],
    v2: () => ["Étape suivante : la racine garantit la clé du TLD (enregistrement DS signé).", "`verifier port443`"],
    v3: () => ["Le TLD garantit à son tour la clé de banque.port443.", "`verifier banque`"],
    v4: () => ["Dernière marche : la signature de la réponse elle-même (RRSIG sur l'enregistrement A).", "`verifier reponse`"],
    forge: () => ["Et si Mallory gagnait la course malgré tout ? Demande-lui de forger une réponse pour la tester.", "Dans la ruelle : `forger`."],
    v5: () => ["Teste la fausse réponse comme une vraie, au bureau du résolveur.", "`verifier fausse reponse`"],
    eve1: () => ["DNSSEC protège l'authenticité. Mais que voit Ève, dans la ruelle, des requêtes ?", "Dans la ruelle : `ecouter`."],
    doh: () => ["Règle le résolveur pour chiffrer les requêtes dans TLS (DoH ou DoT).", "Au bureau du résolveur : `configurer transport doh`."],
    eve2: () => ["Retourne écouter avec Ève : qu'est-ce qui a changé ?", "Dans la ruelle : `ecouter`."],
    eve3: () => ["Demande à Ève ce qu'elle voit encore malgré tout.", "`parler eve`"],
    end: () => ["Rends compte à Maître Ada.", "`aller nord` (jusqu'au hall), puis `parler ada`."],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Bienvenue à l'Annuaire de Port-443. Tout courrier, toute visite à la banque commence par une question : « quelle est l'adresse de banque.port443 ? ». Personne ne connaît toutes les adresses : l'annuaire est réparti en trois niveaux, la Racine, le TLD .port443, et le serveur propre à chaque domaine.");
          say("Maître Ada", "Ton rôle, facteur : mener toi-même la résolution, voir comment le résolveur local retient les réponses, puis assister, en audit autorisé, à une tentative d'empoisonnement de cache par Mallory. Nous verrons ensuite comment on s'en protège. Tout est simulé.");
          out("Passe par le bureau du résolveur (`aller nord`) et demande-lui l'adresse : `resoudre banque.port443`.", "sys");
        } else if (objective() === "ada2") {
          x.signed = true;
          say("Maître Ada", "Mallory n'a pas gagné cette fois, mais regarde ce que nous avons fait : nous avons ralenti la devinette, rien de plus. Le résolveur n'a toujours aucun moyen de PROUVER qu'une réponse vient bien du Notaire. La vraie parade s'appelle DNSSEC : chaque zone signe ses enregistrements, et chaque niveau garantit la clé du niveau inférieur.");
          say("Maître Ada", "Port-443 vient de signer ses zones. Les clés sont de petites clés RSA jouets, les signatures sont réelles : ce sont de vrais calculs. Va chercher, à chaque niveau, les clés et les signatures : `interroger banque.port443 dnssec`, à la Racine, au TLD, puis chez le Notaire.");
          note("dnssec");
        } else if (objective() === "end") ending();
        else if (x.end) say("Maître Ada", "L'Annuaire est plus sûr. Merci !");
        else say("Maître Ada", "L'audit n'est pas terminé. `indice` si tu bloques.");
        break;
      case "commis":
        say("Commis", "Je réponds aux habitants de Port-443. Si j'ai la réponse en cache, je la donne tout de suite. Sinon, je dois l'apprendre : racine, TLD, serveur faisant autorité. Essaie : `resoudre banque.port443`. Pour voir mes réglages : `configurer`.");
        if (x.signed) out("Rappel : les étapes de vérification DNSSEC se font ici (`verifier ancre`…).", "sys");
        break;
      case "racine":
        say("Archiviste", "Je ne connais pas banque.port443 : je ne connais que les domaines de premier niveau, et qui les gère. Interroge-moi : `interroger banque.port443 A`. Je te renverrai vers le bon serveur.");
        break;
      case "tld":
        say("Scribe", "Je tiens le registre de .port443 : je sais qui fait autorité pour chaque domaine, mais je ne détiens pas les adresses. `interroger banque.port443 A` et je te dirai à qui t'adresser.");
        break;
      case "autorite":
        say("Notaire", "Je fais autorité sur banque.port443 : mes réponses sont la source de vérité. A, NS, CNAME… Demande : `interroger banque.port443 A` ou `interroger www.banque.port443 CNAME`.");
        break;
      case "mallory":
        if (!x.expired) say("Mallory", "Tant que le cache du résolveur est plein, ma fausse réponse ne sert à rien : il ne pose même pas la question. Reviens quand l'entrée aura expiré.");
        else if (!x.hit1) say("Mallory", "L'entrée a expiré ? Parfait. Le résolveur doit poser la question au Notaire, et la vraie réponse mettra environ " + RACE_MS + " ms à revenir. Pendant ce temps, j'inonde le résolveur de " + FLOOD + " fausses réponses, chacune avec un identifiant différent. Si l'une porte le bon identifiant avant la vraie : empoisonné. `empoisonner ‹nombre de courses›`.");
        else say("Mallory", "Chaque « course », c'est une question forcée au résolveur et " + FLOOD + " fausses réponses envoyées pendant " + RACE_MS + " ms. `empoisonner ‹n›` simule n courses. " + (x.rejected ? "Pour DNSSEC : `forger`." : (x.signed && x.v && x.v.rep) ? "Et si on testait une réponse forgée contre DNSSEC ? `forger`." : "Les réglages du résolveur sont chez le Commis : `configurer`."));
        break;
      case "eve":
        if (!x.sawEnc) say("Ève", "Je ne fais que regarder. `ecouter` te montre ce qui passe sur la canalisation du résolveur" + (x.rejected ? "." : ", mais ça ne devient intéressant qu'une fois la réponse authentifiée."));
        else if (!x.eveTalk) {
          x.eveTalk = true;
          say("Ève", "Le nom que tu demandes n'est plus lisible pour moi. Mais je vois toujours qui parle à qui, quand, et la taille des messages. Ton résolveur, lui, voit tout, et il décide à qui il répond. Quand tu te connectes ensuite à la banque, l'adresse IP et souvent le nom (dans le SNI de TLS) sont encore visibles. Et rappelle-toi : DoH chiffre le trajet, mais c'est DNSSEC qui prouve que la réponse est authentique. Les deux se complètent.");
          note("limites"); fig("prive");
        } else say("Ève", "Je n'ai rien de plus à ajouter. Va voir Maître Ada.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- requêtes DNS ---------- */
  const TYPES = ["A", "AAAA", "NS", "CNAME", "MX", "TXT", "DNSKEY", "DS", "RRSIG", "DNSSEC"];
  function parseQ(raw) {
    const toks = raw.toLowerCase().split(/\s+/).filter(Boolean);
    let type = toks.find(t => TYPES.includes(t.toUpperCase()));
    let name = toks.find(t => t !== type && /port443|banque|^www/.test(t));
    if (name) { name = name.replace(/\.$/, ""); if (name === "banque" || name === "www.banque") name += ".port443"; }
    return { name, type: type ? type.toUpperCase() : "A" };
  }
  const known = n => n === NAME || n === WWW;
  function query(c) {
    const x = F(), room = S.room;
    if (!["racine", "tld", "autorite"].includes(room)) { out("On n'interroge un serveur qu'en face de lui : la Racine (est du hall), le TLD (ouest), ou le Notaire. Le Commis, lui, se consulte avec `resoudre`.", "sys"); return; }
    if (!x.quest) { out("Va d'abord voir Maître Ada.", "sys"); return; }
    const q = parseQ(c.rawArg);
    if (!q.name) { out("Quel nom ? `interroger banque.port443 A` (types : A, NS, CNAME, DNSSEC…)", "err"); return; }
    if (room === "tld" && !x.root) { say("Scribe", "Je ne devrais pas répondre à qui ne sait pas comment il est arrivé ici. Un résolveur commence toujours par la Racine, qui lui indique le TLD : va d'abord la voir."); return; }
    if (room === "autorite" && !x.tld) { say("Notaire", "Comment as-tu trouvé mon étude ? Un résolveur apprend qui fait autorité en demandant au serveur du TLD. Passe d'abord par la Racine puis le pavillon."); return; }
    const head = ";; QUESTION  : " + q.name + ". IN " + q.type;
    if (q.type === "DNSSEC" || q.type === "DNSKEY" || q.type === "DS" || q.type === "RRSIG") { dnssecQuery(room, q, head); return; }
    if (!known(q.name) && q.name !== "port443") {
      out("Le serveur ne connaît pas ce nom.", "sys");
      code(head + "\n;; STATUT     : NXDOMAIN (le nom n'existe pas)");
      return;
    }
    if (room === "racine") {
      out("L'Archiviste feuillette ses fiches et répond :", "sys");
      code(head + "\n;; RÉPONSE    : (aucune)   [drapeau aa absent : je ne fais pas autorité]\n;; AUTORITÉ   : port443.            172800  IN  NS  a.nic.port443.\n;; ADDITIONNEL: a.nic.port443.      172800  IN  A   10.0.0.53   (« glue »)");
      say("Archiviste", "Je ne sais pas, mais voici qui gère .port443 : le serveur a.nic.port443, à l'adresse 10.0.0.53. Va le voir : c'est un renvoi (referral).");
      out("Une réponse de renvoi : la Racine ne répond pas à ta question, elle te dit à qui la poser.", "ok");
      if (!x.root) { x.root = true; note("hier"); note("iter"); fig("hier"); }
    } else if (room === "tld") {
      out("Le Scribe consulte son registre :", "sys");
      code(head + "\n;; RÉPONSE    : (aucune)   [aa absent]\n;; AUTORITÉ   : banque.port443.    172800  IN  NS  ns1.banque.port443.\n;; ADDITIONNEL: ns1.banque.port443. 172800  IN  A   10.4.4.1   (« glue »)");
      say("Scribe", "banque.port443 est enregistré. C'est ns1.banque.port443, à l'adresse 10.4.4.1, qui fait autorité. Le « glue » est nécessaire : sinon, pour trouver ns1.banque.port443 il faudrait déjà connaître l'adresse… de banque.port443 !");
      out("Nouveau renvoi : il ne reste qu'un niveau.", "ok");
      if (!x.tld) { x.tld = true; fig("hier"); }
    } else authQuery(q, head);
  }
  function authQuery(q, head) {
    const x = F(); x.seenT = x.seenT || {};
    const hdr = ";; drapeaux   : aa (réponse faisant autorité)\n" + head;
    if (q.name === "port443") { code(hdr + "\n;; STATUT     : REFUSED (je ne gère pas la zone port443.)"); return; }
    if (q.type === "A" && q.name === NAME) {
      x.ans = { val: IP, ttl: TTL }; give("reponse"); x.auth = true;
      out("Le Notaire ouvre son dossier et te remet un parchemin :", "sys");
      code(hdr + "\n;; RÉPONSE    : " + NAME + ".   " + TTL + "  IN  A  " + IP);
      out("Tu as l'adresse ! Le TTL (" + TTL + " secondes) dit combien de temps on peut la garder en mémoire. Tu portes le parchemin : rapporte-le au Commis pour qu'il la retienne.", "ok");
      x.seenT.A = true; fig("hier");
    } else if (q.type === "NS" && q.name === NAME) {
      code(hdr + "\n;; RÉPONSE    : " + NAME + ".   3600  IN  NS  ns1.banque.port443.\n;; ADDITIONNEL: ns1.banque.port443.  3600  IN  A   10.4.4.1");
      out("Un enregistrement NS : la liste des serveurs qui font autorité pour la zone.", "ok"); x.seenT.NS = true;
    } else if (q.name === WWW && (q.type === "CNAME" || q.type === "A")) {
      code(hdr + "\n;; RÉPONSE    : " + WWW + ".  600  IN  CNAME  " + NAME + ".\n;;             " + NAME + ".       " + TTL + "  IN  A      " + IP + "   (cible jointe : même zone)");
      out("Un CNAME : www.banque.port443 n'a pas d'adresse propre, c'est un alias de banque.port443. Il faut résoudre la cible. Ici le Notaire a joint l'adresse de la cible, car il fait aussi autorité pour elle ; sinon, le résolveur aurait dû reposer la question. Chaque enregistrement a son propre TTL (600 s pour le CNAME, " + TTL + " s pour l'A).", "ok");
      x.seenT.CNAME = true;
    } else if (q.type === "AAAA" || q.type === "MX" || q.type === "TXT" || q.type === "CNAME") {
      code(hdr + "\n;; STATUT     : NOERROR   ;; RÉPONSE : (vide)");
      out("Réponse vide mais valide (« NODATA ») : le nom existe, il n'a simplement pas d'enregistrement de ce type" + (q.type === "CNAME" ? " : banque.port443 est un nom « canonique », ce n'est l'alias de personne." : "."), "sys");
    } else { code(hdr + "\n;; STATUT     : NXDOMAIN (le nom n'existe pas)"); out("Ce nom n'existe pas dans la zone.", "sys"); }
    if (typesDone() && !x.notedTypes) { x.notedTypes = true; note("types"); }
  }

  function dnssecQuery(room, q, head) {
    const x = F(); x.kit = x.kit || {};
    if (!x.signed) {
      code(head + "\n;; (aucun enregistrement DNSKEY, DS ni RRSIG : la zone n'est pas signée)");
      out("Ces zones ne sont pas encore signées : aucun enregistrement DNSSEC. Les réponses ne sont accompagnées d'aucune preuve.", "sys"); return;
    }
    let body;
    const sh = n => String(n);
    if (room === "racine") {
      const d = dsData("tld");
      body = ";; DNSKEY (zone « . ») : n=" + KEYS.root.n + "  e=" + KEYS.root.e + "\n;; DS     port443.   : empreinte de la clé du TLD = " + digest("tld") + "\n;; RRSIG  du DS      : signé par « . », signature = " + sh(sign("root", d));
      x.kit.root = true;
    } else if (room === "tld") {
      const d = dsData("bank");
      body = ";; DNSKEY (zone « port443. ») : n=" + KEYS.tld.n + "  e=" + KEYS.tld.e + "\n;; DS     banque.port443. : empreinte de la clé de banque = " + digest("bank") + "\n;; RRSIG  du DS            : signé par « port443. », signature = " + sh(sign("tld", d));
      x.kit.tld = true;
    } else {
      body = ";; DNSKEY (zone « banque.port443. ») : n=" + KEYS.bank.n + "  e=" + KEYS.bank.e + "\n;; A      " + NAME + ". " + TTL + " : " + IP + "\n;; RRSIG  de l'A : signé par « banque.port443. », signature = " + sh(sign("bank", aData(IP)));
      x.kit.auth = true;
    }
    give("dossier");
    out("Le serveur joint ses clés et ses signatures :", "sys");
    code(head + "\n" + body);
    out("Ajouté à ton dossier de preuves (`examiner dossier`). Une signature seule ne prouve rien : il faudra la vérifier avec la clé, et la clé avec le niveau du dessus.", "ok");
    if (kitDone() && !x.kitSaid) { x.kitSaid = true; out("Ton dossier est complet : retourne au bureau du résolveur (hall, puis nord) et vérifie la chaîne : `verifier ancre`.", "sys"); }
  }

  /* ---------- résolveur : résolution, cache, TTL, réglages ---------- */
  function resolve1(c) {
    const x = F();
    if (S.room !== "resolveur") { out("Le résolveur local est au nord du hall.", "sys"); return; }
    const q = parseQ(c.rawArg);
    if (!q.name) { out("Quel nom ? `resoudre banque.port443`", "err"); return; }
    if (q.name === WWW) { out("Ce nom est un alias (CNAME) vers " + NAME + " : pour la leçon, résous plutôt `resoudre banque.port443`.", "sys"); return; }
    if (q.name !== NAME) { out("Le Commis ne connaît pas ce nom. (`resoudre banque.port443`)", "sys"); return; }
    const ent = x.cache.A;
    if (ent && ent.exp > x.t) {
      const left = ent.exp - x.t;
      out("Cache : le Commis lit son registre sans lever la tête.", "sys");
      code(";; " + NAME + ". " + left + " (TTL restant)  IN  A  " + ent.val + "\n;; temps de réponse : 0 ms (aucune requête réseau)");
      if (ent.fake) {
        out("L'adresse " + ent.val + " n'est pas celle de la banque ! Tu as devant toi l'adresse de Mallory : toute personne qui demandera au Commis sera envoyée chez elle, et ce pendant " + fmtD(left) + " (TTL choisi par Mallory). Ta lettre, tes identifiants... tout irait chez elle.", "err");
        if (!x.sawFake) { x.sawFake = true; note("poison"); fig("course"); }
      } else {
        out("Réponse immédiate : pas besoin de redescendre la hiérarchie. Le TTL diminue : il reste " + left + " s.", "ok");
        if (!x.hitCache) { x.hitCache = true; note("cache"); fig("cache"); }
      }
      return;
    }
    if (ent) { delete x.cache.A; x.expired = true; out("Le TTL de l'entrée est écoulé : le Commis la raye du registre.", "sys"); }
    out("Cache : le Commis cherche dans son registre… rien.", "sys");
    code(";; " + NAME + ". IN A : MISS (aucune entrée valide)");
    say("Commis", "Je n'ai pas la réponse en mémoire. Normalement, je ferais la tournée moi-même : racine, TLD, serveur faisant autorité. " + (x.auth ? "Tu as la réponse ? `donner reponse au commis`." : "Fais-la toi-même (c'est toi le facteur) et rapporte-moi la réponse : commence par la Tour de la Racine, à l'est du hall."));
  }
  function giveFn(item, who) {
    const x = F();
    if (who === "commis" && item === "reponse") {
      if (S.room !== "resolveur") { out("Le Commis est au bureau du résolveur (nord du hall).", "sys"); return; }
      x.cache.A = { val: IP, exp: x.t + TTL, ttl: TTL }; x.delivered = true; drop("reponse");
      say("Commis", "Merci ! Je note : " + NAME + " = " + IP + ", valable " + TTL + " secondes. Dès maintenant, tous les habitants qui poseront la question recevront la réponse tout de suite.");
      out("Entrée mise en cache. Redemande-lui : `resoudre banque.port443`.", "ok"); return;
    }
    if (who === "commis" && item === "fausse") { say("Commis", "Je ne l'accepte pas comme ça. Utilise `verifier fausse reponse` pour voir ce que fait un résolveur qui valide DNSSEC."); return; }
    return false;
  }
  function useFn(key) {
    if (key === "commis+reponse") { if (giveFn("reponse", "commis") === false) return false; return; }
    return false;
  }
  function wait(c) {
    const x = F();
    const n = parseInt(c.rawArg, 10);
    if (!n || n < 1) { out("Combien de secondes ? `attendre 301`", "err"); return; }
    const d = Math.min(n, 200000);
    x.t += d;
    out("Tu laisses passer " + d + " secondes. Il est maintenant t = " + x.t + " s.", "sys");
    const ent = x.cache.A;
    if (ent && ent.exp <= x.t) {
      delete x.cache.A; x.expired = true;
      out("L'entrée du cache « " + NAME + " A " + ent.val + " » a expiré : le Commis l'a effacée. La prochaine question devra redescendre la hiérarchie.", "ok");
      note("cache"); fig("cache");
    } else if (ent) out("Le cache garde encore l'entrée : TTL restant " + (ent.exp - x.t) + " s.", "sys");
  }
  function clearCache(c) {
    const x = F();
    if (S.room !== "resolveur") { out("Le cache est au bureau du résolveur (nord du hall).", "sys"); return; }
    if (!/cache|registre|tout/.test(norm(c.rawArg))) { out("`vider cache`", "err"); return; }
    if (!x.cache.A) { out("Le cache est déjà vide.", "sys"); return; }
    delete x.cache.A; out("Le Commis rature son registre : toutes les entrées sont effacées (c'est le « flush » du cache).", "ok");
  }
  const TXT = { seq: "séquentiel (prévisible)", alea: "aléatoire", fixe: "fixe (53)", clair: "clair (UDP 53)", doh: "DoH (HTTPS, 443)", dot: "DoT (TLS, 853)" };
  function configShow() {
    const c = F().cfg;
    out("Réglages du résolveur :", "sys");
    code("txid      : " + TXT[c.txid] + "\nport source: " + (c.port === "alea" ? "aléatoire" : TXT.fixe) + "\ntransport  : " + TXT[c.transport] + "\nancre DNSSEC : " + ANCHOR + " (empreinte de la clé racine)");
    out("Modifier : `configurer txid aleatoire` · `configurer port aleatoire` · `configurer transport doh`", "sys");
  }
  function config(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "resolveur") { out("Les réglages du résolveur se font à son bureau (nord du hall).", "sys"); return; }
    if (!t) { configShow(); return; }
    let m;
    if ((m = t.match(/^(txid|id|identifiant)\s+(.+)$/))) {
      const v = /alea|random|hasard/.test(m[2]) ? "alea" : /seq|prev/.test(m[2]) ? "seq" : null;
      if (!v) { out("`configurer txid aleatoire` ou `configurer txid sequentiel`.", "err"); return; }
      x.cfg.txid = v; out("Identifiant de transaction : " + TXT[v] + ".", "ok");
      if (v === "alea") out("Chaque requête reçoit maintenant un identifiant tiré au hasard parmi 65 536 valeurs (16 bits). Pense à `vider cache` si une fausse entrée y traîne.", "sys");
    } else if ((m = t.match(/^port(?: source)?\s+(.+)$/))) {
      const v = /alea|random|hasard/.test(m[1]) ? "alea" : /fixe|53/.test(m[1]) ? "fixe" : null;
      if (!v) { out("`configurer port aleatoire` ou `configurer port fixe`.", "err"); return; }
      x.cfg.port = v; out("Port source : " + (v === "alea" ? "aléatoire (environ 64 000 ports possibles)" : "fixe") + ".", "ok");
    } else if ((m = t.match(/^transport\s+(.+)$/))) {
      const v = /doh|https/.test(m[1]) ? "doh" : /dot|tls/.test(m[1]) ? "dot" : /clair|udp|53/.test(m[1]) ? "clair" : null;
      if (!v) { out("`configurer transport doh` (ou dot, ou clair).", "err"); return; }
      x.cfg.transport = v; out("Transport des requêtes : " + TXT[v] + ".", "ok");
      if (v !== "clair") out("Les requêtes de ton résolveur sont maintenant enveloppées dans TLS. Va voir ce qu'Ève entend : `ecouter` dans la ruelle.", "sys");
    } else { out("Réglage inconnu. `configurer` seul affiche les réglages.", "err"); configShow(); }
  }

  /* ---------- Mallory : la course ---------- */
  function poison(c) {
    const x = F();
    if (S.room !== "ruelle") { out("Mallory est dans la ruelle (sud du hall).", "sys"); return; }
    if (!x.expired) { say("Mallory", "Le cache est encore plein : le résolveur ne pose pas la question, ma fausse réponse n'aurait aucun effet. Il faut qu'il ait expiré (`attendre`)."); return; }
    if (poisoned()) { say("Mallory", "Mon entrée est déjà dans son cache. Le résolveur ne posera plus la question avant " + fmtD(x.cache.A.exp - x.t) + ". À toi de le vider : `vider cache` chez le Commis."); return; }
    if (x.cache.A) { say("Mallory", "Le cache contient une vraie entrée valide : je n'ai pas de course à courir."); return; }
    let n = parseInt(c.rawArg, 10); if (!n || n < 1) n = 1000; if (n > CAP) n = CAP;
    const cfg = x.cfg, p = pRace(), idb = cfg.txid === "alea" ? "alea" : "seq";
    out("Mallory lance " + num(n) + " course" + (n > 1 ? "s" : "") + ". À chaque course : le résolveur interroge le Notaire (identifiant " + (idb === "alea" ? "aléatoire" : "séquentiel") + ", port " + (cfg.port === "alea" ? "aléatoire" : "fixe") + ") ; la vraie réponse met " + RACE_MS + " ms ; Mallory envoie " + FLOOD + " fausses réponses dans ce laps de temps.", "sys");
    code("probabilité de gagner une course = " + FLOOD + " / (" + num(idSpace()) + " identifiants × " + num(portSpace()) + " port" + (portSpace() > 1 ? "s" : "") + ")\n                                 = " + fmtP(p) + "\nespérance : " + (p >= 1 ? "1 course" : "environ " + num(1 / p) + " courses (" + fmtD(1 / p * RACE_MS / 1000) + " au rythme d'une course toutes les " + RACE_MS + " ms)"));
    let hit = 0;
    for (let i = 1; i <= n; i++) if (rnd() < p) { hit = i; break; }
    x.races = (x.races || 0) + (hit || n);
    if (hit) {
      x.cache.A = { val: FAKE, exp: x.t + FAKE_TTL, ttl: FAKE_TTL, fake: true };
      out("Course n° " + num(hit) + " : une des " + FLOOD + " fausses réponses porte le bon identifiant" + (cfg.port === "alea" ? " et arrive sur le bon port" : "") + ", avant la vraie. Le résolveur l'accepte : " + NAME + " = " + FAKE + ", avec un TTL de " + FAKE_TTL + " secondes (un jour entier).", "err");
      out("Temps écoulé : environ " + fmtD(hit * RACE_MS / 1000) + ". Le cache est empoisonné.", "err");
      if (idb === "seq" && cfg.port === "fixe") x.hit1 = true; else if (cfg.port === "fixe") { x.hit2 = true; note("txid"); } else x.lucky = (x.lucky || 0) + 1;
      if (x.hit1) note("poison");
      out("Va voir ce que répond le Commis (`resoudre banque.port443`)" + (x.hit2 ? "" : "."), "sys");
      if (cfg.port === "fixe" && cfg.txid === "alea") out("Identifiants aléatoires, et pourtant Mallory a gagné en " + num(hit) + " courses : 16 bits ne sont pas une protection suffisante contre quelqu'un qui peut forcer des milliers de questions.", "err");
      if (cfg.port === "alea") out("Coup de malchance rare (la probabilité était d'environ " + fmtP(1 - Math.pow(1 - p, n)) + " sur ces " + num(n) + " courses). Vide le cache et réessaie : ce n'est pas un état durable, mais cela montre que la protection est statistique.", "sys");
      fig("course");
    } else {
      out("Après " + num(n) + " courses : aucune fausse réponse n'a deviné à la fois l'identifiant et le port. Le cache est intact.", "ok");
      if (cfg.txid === "alea" && cfg.port === "alea") {
        x.fail3 = true; note("txid");
        out("Avec identifiant ET port aléatoires, Mallory doit deviner ~32 bits : environ " + num(1 / p) + " courses en moyenne, soit " + fmtD(1 / p * RACE_MS / 1000) + " sans pause. Les résolveurs, de plus, repèrent un flot de réponses invalides et le coupent. Le hasard a rendu l'attaque peu rentable.", "ok");
        out("Mais attention : c'est un pari statistique. Rien ne PROUVE que la réponse est authentique.", "sys");
        fig("course");
      } else out("Mallory n'a pas eu de chance cette fois. Avec un identifiant " + (idb === "seq" ? "séquentiel" : "") + ", réessaie avec plus de courses.", "sys");
    }
  }
  function forge() {
    const x = F();
    if (S.room !== "ruelle") { out("Mallory est dans la ruelle (sud du hall).", "sys"); return; }
    if (!(x.v && x.v.rep)) { say("Mallory", "Forger quoi, contre quoi ? Montre-moi d'abord que tu sais vérifier une vraie réponse."); return; }
    if (S.inv.includes("fausse")) { out("Tu as déjà la fausse réponse.", "sys"); return; }
    x.forged = true; give("fausse");
    say("Mallory", "Admettons que j'aie gagné la course : identifiant et port corrects, ma réponse arrive la première. J'ai changé l'adresse en " + FAKE + ". Il me faut une signature qui passe : j'essaie de recopier celle du Notaire, ou de signer avec ma propre clé.");
    out("Tu reçois la fausse réponse. Teste-la au bureau du résolveur : `verifier fausse reponse`.", "ok");
  }

  /* ---------- vérification DNSSEC ---------- */
  function verify(c) {
    const x = F(); x.v = x.v || {};
    if (S.room !== "resolveur") { out("La vérification se fait au bureau du résolveur (nord du hall).", "sys"); return; }
    const t = norm(c.rawArg), v = x.v;
    if (!x.signed) { out("Les zones ne sont pas signées : il n'y a rien à vérifier.", "sys"); return; }
    if (!kitDone()) { out("Ton dossier est incomplet : il manque des clés ou des signatures. `examiner dossier`. (`interroger banque.port443 dnssec` à la Racine, au TLD et chez le Notaire.)", "err"); return; }
    if (/fauss|forg|faux/.test(t)) { verifyFake(); return; }
    const need = (cond, msg) => { if (!cond) { out(msg, "err"); return false; } return true; };
    if (/ancre|racine/.test(t) && !/port443|banque/.test(t)) {
      const d = digest("root");
      out("Le Commis compare l'empreinte de la clé reçue avec l'ancre de confiance installée d'avance :", "sys");
      code("DNSKEY(.)  n=" + KEYS.root.n + " e=" + KEYS.root.e + "\nempreinte calculée   = " + d + "\nancre de confiance   = " + ANCHOR + "\n=> " + (d === ANCHOR ? "identiques" : "DIFFÉRENTES"));
      out("La clé de la racine est authentique : on peut s'y fier, par construction (elle n'est pas validée par un parent, elle est installée avec le logiciel).", "ok");
      if (!v.anchor) { v.anchor = true; fig("chaine"); }
    } else if (/port443|tld/.test(t) && !/banque/.test(t)) {
      if (!need(v.anchor, "Il faut d'abord établir la confiance en la racine : `verifier ancre`.")) return;
      const sg = sign("root", dsData("tld")), back = unsign("root", sg), h = hv(dsData("tld")), ok = back === h;
      out("Étape 2 : la racine garantit-elle la clé du TLD ?", "sys");
      code("signature du DS(port443.)     = " + sg + "\nsignature ^ e mod n (clé racine) = " + back + "\nempreinte du DS (24 bits)        = " + h + "\n=> signature " + (ok ? "VALIDE" : "INVALIDE") + "\nempreinte de la DNSKEY(port443.) = " + digest("tld") + "\nDS publié par la racine          = " + digest("tld") + "\n=> clé du TLD " + (ok ? "garantie par la racine" : "non garantie"));
      out("Le DS est l'empreinte de la clé du TLD ; la racine l'a signé, donc la clé du TLD est de confiance.", "ok");
      if (!v.tld) { v.tld = true; fig("chaine"); }
    } else if (!/rep|enreg/.test(t) && /banque/.test(t)) {
      if (!need(v.tld, "Il faut d'abord valider le TLD : `verifier port443`.")) return;
      const sg = sign("tld", dsData("bank")), back = unsign("tld", sg), h = hv(dsData("bank")), ok = back === h;
      out("Étape 3 : le TLD garantit-il la clé de banque.port443 ?", "sys");
      code("signature du DS(banque.port443.) = " + sg + "\nsignature ^ e mod n (clé du TLD)   = " + back + "\nempreinte du DS (24 bits)          = " + h + "\n=> signature " + (ok ? "VALIDE" : "INVALIDE") + "\nempreinte de la DNSKEY(banque)     = " + digest("bank") + "\nDS publié par le TLD               = " + digest("bank") + "\n=> clé de la banque " + (ok ? "garantie par le TLD" : "non garantie"));
      out("On dispose maintenant d'une clé authentique pour banque.port443 : seule une signature faite avec elle sera acceptée.", "ok");
      if (!v.bank) { v.bank = true; fig("chaine"); }
    } else if (/rep|enreg/.test(t)) {
      if (!need(v.bank, "Il faut d'abord valider la clé de la banque : `verifier banque`.")) return;
      const sg = sign("bank", aData(IP)), back = unsign("bank", sg), h = hv(aData(IP)), ok = back === h;
      out("Étape 4 : la réponse elle-même.", "sys");
      code("A " + NAME + ". " + IP + "   signature = " + sg + "\nsignature ^ e mod n (clé de la banque) = " + back + "\nempreinte de la réponse (24 bits)      = " + h + "\n=> signature " + (ok ? "VALIDE" : "INVALIDE"));
      out("La chaîne est complète : racine (ancre) → TLD → banque → réponse. Cette adresse est authentique : elle vient bien du Notaire, et n'a pas été modifiée en route.", "ok");
      if (!v.rep) { v.rep = true; note("dnssec"); fig("chaine"); out("Maintenant, voyons ce qui se passe avec une fausse réponse : demande-la à Mallory (`forger`, dans la ruelle).", "sys"); }
    } else { out("Quelle étape ? `verifier ancre` · `verifier port443` · `verifier banque` · `verifier reponse` · `verifier fausse reponse`.", "err"); }
  }
  function verifyFake() {
    const x = F();
    if (!S.inv.includes("fausse")) { out("Tu n'as pas de fausse réponse à tester. (`forger`, dans la ruelle.)", "sys"); return; }
    const dat = aData(FAKE), real = sign("bank", aData(IP));
    const back1 = unsign("bank", real), h1 = hv(dat);
    const own = sign("mal", dat), back2 = unsign("mal", own);
    out("Le résolveur reçoit la fausse réponse (identifiant et port corrects : elle a gagné la course). Il l'examine : une signature DNSSEC est exigée.", "sys");
    out("Essai n° 1 de Mallory : recopier la signature du vrai A.", "sys");
    code("A " + NAME + ". " + FAKE + "   signature recopiée = " + real + "\nsignature ^ e mod n (clé de la banque) = " + back1 + "\nempreinte de la fausse réponse         = " + h1 + "\n=> signature INVALIDE (la signature est liée au contenu : adresse modifiée, empreinte différente)");
    out("Essai n° 2 de Mallory : signer avec SA propre clé et la joindre en DNSKEY.", "sys");
    code("signature (clé de Mallory) = " + own + "\nvérifiable avec n=" + KEYS.mal.n + " e=" + KEYS.mal.e + " : " + (back2 === h1 ? "VALIDE" : "INVALIDE") + "\nempreinte de SA DNSKEY      = " + digest("mal") + "\nDS publié par le TLD        = " + digest("bank") + "\n=> cette clé n'est pas garantie par le TLD : CHAÎNE ROMPUE");
    out("SERVFAIL : le résolveur rejette la réponse. Mallory a gagné la course, mais sans la clé privée de la banque elle ne peut pas signer la fausse adresse. L'empoisonnement ne passe plus, quelle que soit la chance de Mallory.", "ok");
    drop("fausse");
    if (!x.rejected) { x.rejected = true; x.validating = true; note("dnssec"); fig("chaine"); out("Le résolveur valide maintenant DNSSEC. Mais Ève, dans la ruelle, voit-elle quelque chose ? (`aller sud`, `aller sud`, `ecouter`)", "sys"); }
  }

  /* ---------- Ève : ce qui circule ---------- */
  function ks(i) { return parseInt(sha256("cle-de-session-TLS|" + i).slice(0, 2), 16); }
  function listen() {
    const x = F();
    if (S.room !== "ruelle") { out("Ève et sa canalisation sont dans la ruelle (sud du hall).", "sys"); return; }
    if (!x.rejected) { say("Ève", "Pour l'instant, il n'y a rien d'intéressant à voir : reviens quand tu auras fini avec Mallory et DNSSEC."); return; }
    const tr = x.cfg.transport;
    out("Ève te tend un casque : voici ce qu'elle capture sur la canalisation du résolveur.", "sys");
    if (tr === "clair") {
      code("UDP  10.0.0.7 -> 10.0.0.2:53   id=0x3a1f   QUESTION : " + NAME + ". A\nUDP  10.0.0.2:53 -> 10.0.0.7   id=0x3a1f   RÉPONSE  : " + NAME + ". A " + IP + "  + RRSIG (signature)");
      out("Ève lit tout : le nom que tu demandes, et la réponse. DNSSEC garantit que la réponse est authentique, mais ne cache rien : la signature est publique, le contenu aussi.", "err");
      if (!x.sawClear) { x.sawClear = true; note("limites"); fig("prive"); }
    } else {
      const plain = "GET /dns-query?name=" + NAME + "&type=A", bytes = Array.from(new TextEncoder().encode(plain)).slice(0, 24);
      const hex = bytes.map((b, i) => (b ^ ks(i)).toString(16).padStart(2, "0")).join(" ");
      code("TCP  10.0.0.7 -> 10.0.0.2:" + (tr === "doh" ? "443" : "853") + "   " + (tr === "doh" ? "TLS (HTTPS)" : "TLS (DoT)") + "   " + (plain.length + 29) + " octets\n  " + hex + " …\nTCP  10.0.0.2:" + (tr === "doh" ? "443" : "853") + " -> 10.0.0.7   TLS   " + (IP.length + 62) + " octets\n  (chiffré : le nom et l'adresse ne sont plus lisibles)");
      out("Ève ne voit plus que des octets illisibles : qui parle à qui, quand, et la taille des messages. Plus le nom demandé. (Chiffrement simulé par un flux dérivé de SHA-256.)", "ok");
      if (!x.sawEnc) { x.sawEnc = true; note("doh"); fig("prive"); out("Parle-lui : `parler eve`.", "sys"); }
    }
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Tu as mené une résolution à la main, vu le cache et son TTL, assisté à un empoisonnement, mesuré ce que valent l'identifiant aléatoire et le port aléatoire, puis construit toi-même la chaîne de confiance DNSSEC. Mallory peut avoir de la chance ou de la ruse : elle ne signera jamais pour la banque. Et Ève ne voit plus les noms. Port-443 recommande : DNSSEC pour l'authenticité, DoH ou DoT pour la confidentialité.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**L'Annuaire et ses trois niveaux = la hiérarchie du DNS.** La Tour de la Racine = les serveurs racine (13 adresses logiques, des centaines de machines) ; le Pavillon = les serveurs d'un TLD (.com, .fr…) ; l'étude du Notaire = le serveur faisant autorité d'un domaine. Le facteur qui descend de renvoi en renvoi, c'est la résolution itérative ; en pratique, c'est un résolveur récursif (celui de ton fournisseur, ou 1.1.1.1, 8.8.8.8…) qui la fait pour toi.");
    out("**Les parchemins = les enregistrements** : A (adresse IPv4, AAAA pour IPv6), NS (serveurs de la zone), CNAME (alias), chacun avec son TTL. Le « glue » règle le piège de l'œuf et de la poule : pour trouver ns1.banque.port443, il faut déjà son adresse.");
    out("**Le registre du Commis = le cache du résolveur.** Le TTL fixe la durée de vie d'une entrée : un TTL court permet de changer vite d'adresse mais multiplie les requêtes ; un TTL long l'inverse. Il a aussi un côté sombre : une fausse entrée, une fois acceptée, est servie à tout le monde pendant son TTL.");
    out("**Mallory et la course = l'empoisonnement de cache.** Elle provoque une requête, puis envoie des réponses forgées plus vite que le vrai serveur. Les seuls secrets protégeant la réponse sont l'identifiant de transaction (16 bits) et le port source : avec des identifiants prévisibles, l'attaque est instantanée ; avec 16 bits aléatoires, il suffit de quelques dizaines de courses (probabilité " + fmtP(FLOOD / ID_SPACE) + " par course avec " + FLOOD + " paquets) ; avec en plus un port aléatoire, environ " + num(ID_SPACE * PORTS / FLOOD) + " courses en moyenne. L'attaque de Kaminsky (2008) force ces courses en demandant des noms inexistants, sans attendre l'expiration du TTL.");
    out("**La chaîne de confiance = DNSSEC.** Chaque zone a une paire de clés. Le parent publie dans un DS l'empreinte de la clé de l'enfant et le signe (RRSIG) : la racine garantit le TLD, le TLD garantit la banque, la banque signe ses réponses. L'ancre de confiance (la clé de la racine) est installée dans le résolveur. Ici, les signatures sont de vrais calculs RSA avec des clés de 29 bits : la vérification est modpow(signature, e, n) comparée à l'empreinte SHA-256 tronquée.");
    out("**Ève et le DoH/DoT.** Le DNS classique est en clair : tout observateur sur le chemin voit les noms. DoT (port 853) et DoH (port 443, mêlé au trafic web) chiffrent le trajet entre toi et le résolveur, mais pas au-delà : le résolveur voit tout, et il interroge ensuite les serveurs faisant autorité souvent en clair.");
    out("**Les simplifications du jeu.** (1) Une seule paire de clés par zone ; en vrai il y a une KSK (qui signe les clés, référencée par le DS) et une ZSK (qui signe les données), des clés de 2048 bits ou des courbes elliptiques, des signatures avec dates de validité, et des enregistrements NSEC/NSEC3 qui prouvent qu'un nom n'existe pas. Ici les clés RSA font 29 bits (cassables en un instant) et l'empreinte est tronquée à 24 bits. (2) L'attaque a pour but de remplacer directement l'enregistrement A ; la vraie attaque de Kaminsky empoisonne les renvois (NS et glue) pour détourner toute la zone. (3) Le jeu fixe 1 000 paquets forgés par course et 50 ms de fenêtre ; les chiffres réels dépendent du réseau, et les résolveurs limitent les réponses invalides. (4) Les défenses non vues : le cookie DNS, la randomisation de la casse (« 0x20 »), la limitation du débit. (5) Le « chiffrement » DoH montré est un flux dérivé de SHA-256, pas du vrai TLS. (6) Une fois DNSSEC en place, il reste à le déployer (beaucoup de zones ne sont pas signées) et à vérifier côté résolveur, pas seulement côté serveur.");
    out("Rappel utile : **le DNS répond sans preuve par défaut : DNSSEC apporte la preuve (authenticité), DoH/DoT le secret (confidentialité), le hasard ne fait que ralentir l'attaque.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    hier: () => {
      const x = F(), box = (y, d, t1, t2) => R(150, y, 262, 56, d ? "f-ok" : "") + T(281, y + 24, t1, "f-b") + T(281, y + 43, t2, "f-s");
      return {
        cap: "Le résolveur descend la hiérarchie : la Racine renvoie vers le TLD, le TLD vers le serveur faisant autorité, qui seul répond. En vert : les niveaux déjà interrogés.",
        svg: SVG(250, "Hiérarchie de résolution DNS",
          R(8, 80, 104, 60, "f-pub") + T(60, 106, "Résolveur", "f-b") + T(60, 124, "(cache, TTL)", "f-s") +
          box(8, x.root, "1. Racine « . »", "→ renvoi : .port443 = a.nic.port443") + AR(112, 100, 150, 38, x.root ? "f-ok" : "f-pub") +
          box(88, x.tld, "2. TLD .port443", "→ renvoi : ns1.banque.port443") + AR(112, 110, 150, 116, x.tld ? "f-ok" : "f-pub") +
          box(168, x.auth, "3. Faisant autorité", x.auth ? "→ réponse : A " + IP : "→ détient la réponse finale") + AR(112, 128, 150, 196, x.auth ? "f-ok" : "f-pub") +
          T(210, 242, "question : banque.port443 ?  réponse finale : " + (x.auth ? IP : "?"), "f-s"))
      };
    },
    cache: () => {
      const x = F(), c = x.cache.A, left = c ? Math.max(0, c.exp - x.t) : 0, fr = c ? left / c.ttl : 0;
      const bad = c && c.fake;
      return {
        cap: c ? "L'entrée du cache diminue à chaque seconde. Tant qu'il reste du TTL : réponse immédiate, aucune requête. À zéro : l'entrée est effacée."
          : "Sans entrée valide, le résolveur doit refaire toute la descente (3 requêtes). Avec une entrée en cache, la réponse est immédiate.",
        svg: SVG(190, "Cache et TTL",
          T(8, 20, "Entrée : " + NAME + " A " + (c ? c.val : "(aucune)"), "f-b", "start") +
          R(8, 34, 404, 24, bad ? "f-bad" : "f-ok") + `<rect x="8" y="34" width="${Math.round(404 * fr)}" height="24" rx="6" fill="var(--${bad ? "bad" : "ok"})" opacity=".3"/>` +
          T(210, 51, c ? "TTL restant : " + left + " s / " + c.ttl + " s" : "cache vide (expirée ou jamais reçue)", "f-b") +
          R(8, 84, 196, 70, "f-bad") + T(106, 106, "sans cache", "f-b") + T(106, 126, "3 requêtes, ≈ 120 ms", "f-s") + T(106, 143, "racine, TLD, autorité", "f-s") +
          R(216, 84, 196, 70, "f-ok") + T(314, 106, "avec cache valide", "f-b") + T(314, 126, "0 requête, ≈ 0 ms", "f-s") + T(314, 143, "tant que le TTL dure", "f-s") +
          T(210, 178, "TTL long : économe mais lent à changer ; TTL court : l'inverse", "f-s"))
      };
    },
    course: () => {
      const x = F(), rows = [["id prévisible + port fixe", 1, "seq", "fixe"], ["id aléatoire + port fixe", FLOOD / ID_SPACE, "alea", "fixe"], ["id aléatoire + port aléatoire", FLOOD / (ID_SPACE * PORTS), "alea", "alea"]];
      const bar = p => Math.max(4, Math.round(260 * (Math.log10(p) + 7) / 7));
      let body = T(8, 18, "Mallory : " + FLOOD + " fausses réponses en ~" + RACE_MS + " ms", "f-s", "start");
      rows.forEach((r, i) => {
        const y = 36 + i * 52, cur = x.cfg.txid === r[2] && x.cfg.port === r[3];
        body += (cur ? R(4, y - 6, 412, 48, "f-pub") : "") + T(12, y + 10, r[0] + (cur ? "  (réglage actuel)" : ""), "f-b", "start") +
          `<rect x="12" y="${y + 18}" width="${bar(r[1])}" height="14" rx="3" fill="var(--${i === 0 ? "bad" : i === 1 ? "bad" : "ok"})" opacity=".55"/>` +
          T(12 + bar(r[1]) + 8, y + 30, fmtP(r[1]) + " par course" + (r[1] < 1 ? " (≈ " + num(1 / r[1]) + " courses)" : ""), "f-s", "start");
      });
      body += T(210, 202, "échelle logarithmique", "f-s");
      return { cap: "Chance de gagner une course selon ce que le résolveur rend imprévisible. L'identifiant seul (16 bits) tombe en quelques dizaines de courses ; avec le port aléatoire il en faut des millions : mais ce n'est qu'un pari statistique.", svg: SVG(214, "Course d'empoisonnement", body) };
    },
    chaine: () => {
      const v = F().v || {}, ok = (b) => b ? "f-ok" : "";
      return {
        cap: "La chaîne de confiance DNSSEC : l'ancre (clé racine) garantit le TLD par un DS signé, le TLD garantit la banque, la banque signe la réponse. En vert : maillons vérifiés.",
        svg: SVG(250, "Chaîne de confiance DNSSEC",
          KEY(24, 30, v.anchor ? "f-ok" : "f-pub") + T(60, 34, "ancre de confiance (installée)", "f-s", "start") + AR(210, 44, 210, 66, ok(v.anchor)) +
          R(8, 66, 124, 56, ok(v.anchor)) + T(70, 90, "racine « . »", "f-b") + T(70, 108, "DNSKEY", "f-s") +
          AR(132, 94, 150, 94, ok(v.tld)) + R(150, 66, 124, 56, ok(v.tld)) + T(212, 90, "port443.", "f-b") + T(212, 108, "DNSKEY", "f-s") +
          AR(274, 94, 292, 94, ok(v.bank)) + R(292, 66, 120, 56, ok(v.bank)) + T(352, 90, "banque.port443.", "f-b") + T(352, 108, "DNSKEY", "f-s") +
          T(141, 140, "DS + RRSIG", "f-s") + T(283, 140, "DS + RRSIG", "f-s") +
          AR(352, 122, 352, 168, ok(v.rep)) + R(210, 168, 202, 54, ok(v.rep)) + T(311, 190, "A " + IP, "f-b") + T(311, 208, "RRSIG : " + (v.rep ? "valide" : "à vérifier"), v.rep ? "f-s ft-ok" : "f-s") +
          R(8, 168, 190, 54, F().rejected ? "f-bad" : "f-dash") + T(103, 190, F().rejected ? "A " + FAKE + " (Mallory)" : "réponse forgée ?", "f-b") + T(103, 208, F().rejected ? "signature fausse : rejetée" : "(pas encore testée)", F().rejected ? "f-s ft-bad" : "f-s"))
      };
    },
    prive: () => {
      const clair = F().cfg.transport === "clair";
      return {
        cap: clair ? "DNS en clair : Ève lit chaque nom demandé. DNSSEC signe les réponses mais ne les cache pas." : "Avec DoH ou DoT : le trajet est chiffré, Ève ne voit plus les noms. DNSSEC ne chiffre rien ; DoH ne prouve pas l'authenticité du contenu : les deux se complètent.",
        svg: SVG(240, "DNS en clair ou chiffré",
          R(8, 40, 90, 50) + T(53, 70, "Toi", "f-b") + R(322, 40, 90, 50, "f-pub") + T(367, 62, "Résolveur", "f-b") + T(367, 78, "(voit tout)", "f-s") +
          AR(98, 65, 322, 65, clair ? "f-bad" : "f-ok", true) + T(210, 56, clair ? "banque.port443 ? (en clair)" : "octets chiffrés (TLS)", clair ? "f-s ft-bad" : "f-s ft-ok") +
          R(120, 108, 180, 44, clair ? "f-bad" : "f-ok") + T(210, 128, "Ève", "f-b") + T(210, 144, clair ? "lit le nom et la réponse" : "voit qui parle, pas quoi", "f-s") + LN(210, 65, 210, 108, "f-dash") +
          T(210, 184, "DNSSEC : authentifie les réponses (ne chiffre rien)", "f-s") +
          T(210, 204, "DoH / DoT : chiffre le trajet (n'authentifie pas)", "f-s") +
          T(210, 226, "Ensuite, l'IP et le SNI trahissent encore le site", "f-s"))
      };
    },
  };

  GAMES.dns = {
    id: "dns", order: 9, title: "L'Annuaire de Port-443", pageTitle: "DNS Quest", subtitle: "aventure textuelle · DNS et DNSSEC",
    blurb: "Mène une résolution DNS, regarde Mallory empoisonner le cache, puis bâtis la chaîne de confiance DNSSEC.",
    concept: "DNS, empoisonnement de cache, DNSSEC",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, give: giveFn, use: useFn, isEnd: () => !!F().end,
    setup() { const x = F(); x.t = 0; x.cache = {}; x.cfg = { txid: "seq", port: "fixe", transport: "clair" }; x.seed = 443; x.seenT = {}; x.kit = {}; x.v = {}; },
    refig(name) { fig(name); },
    figAlias: { hier: ["hierarchie", "resolution", "dns"], cache: ["ttl"], course: ["poison", "empoisonnement", "attaque", "mallory"], chaine: ["dnssec", "confiance", "signature"], prive: ["doh", "dot", "eve", "confidentialite"] },
    help: "Spécifiques : `resoudre banque.port443` · `interroger ‹nom› ‹type›` (A, NS, CNAME, dnssec) · `attendre ‹secondes›` · `configurer ‹txid|port|transport› ‹valeur›` · `vider cache` · `empoisonner ‹courses›` · `forger` · `verifier ‹étape›` · `ecouter`",
    verbs: {
      resolve: { words: ["resoudre", "resolve", "consulter"], run: resolve1 },
      query: { words: ["interroger", "demander", "questionner", "dig", "requete"], run: query },
      wait: { words: ["attendre", "patienter"], run: wait },
      config: { words: ["configurer", "regler", "choisir"], run: config },
      clear: { words: ["vider", "purger", "effacer", "flush"], run: clearCache },
      poison: { words: ["empoisonner", "attaquer", "inonder"], run: poison },
      forge: { words: ["forger", "falsifier"], run: forge },
      verify: { words: ["verifier", "valider", "controler"], run: verify },
      listen: { words: ["ecouter", "capturer", "sniffer"], run: listen },
    },
    intro() {
      out("L'Annuaire de Port-443", "title");
      out("À Port-443, on n'envoie pas un courrier à un nom mais à une adresse. Et personne ne connaît toutes les adresses : il faut consulter l'Annuaire. Tu es le facteur, et tu dois remettre un pli à « banque.port443 ». Maître Ada t'accompagne pour un audit autorisé : comprendre comment on retrouve l'adresse, comment Mallory peut tromper l'Annuaire, et comment s'en protéger. Tout est simulé.", "");
    },
  };
})();
