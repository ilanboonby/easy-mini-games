"use strict";
/* Le Nuage de Port-443 : mauvaises configurations du cloud, IAM, responsabilité partagée.
   Un moteur d'évaluation de politiques IAM jouet (Allow/Deny, jokers, conditions) et un scanner de configuration
   parcourent un compte cloud fictif ; le joueur corrige chaque constat et re-scanne. Tout est simulé. */
(function () {
  const F = () => f();
  const BK = { registres: "registres-guilde", sauvegardes: "sauvegardes-guilde", publications: "publications-guilde", journaux: "journaux-guilde" };
  const PRINC = ["alice", "bob", "deploy-bot", "stagiaire"];
  const PALIAS = { leo: "stagiaire", deploy: "deploy-bot", deploybot: "deploy-bot", bot: "deploy-bot" };
  const BASTION = "10.0.1.0/24", APPNET = "10.0.2.0/24";
  const D14 = [118, 121, 119, 124, 98, 95, 120, 117, 123, 119, 122, 190, 470, 482];
  const MED = (() => { const s = D14.slice().sort((a, b) => a - b); return (s[6] + s[7]) / 2; })();
  const ESC = ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreatePolicyVersion", "iam:CreateAccessKey"];
  // catalogue de capacités pour mesurer l'étendue d'un droit (action, ressource-échantillon)
  const CAT = (() => {
    const L = [];
    for (const a of ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]) for (const b of Object.values(BK)) L.push([a, b + "/exemple.txt"]);
    for (const b of Object.values(BK)) L.push(["s3:ListBucket", b]);
    for (const a of ["ec2:DescribeInstances", "ec2:RunInstances", "ec2:TerminateInstances", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:PutUserPolicy", "cloudtrail:StopLogging", "kms:Decrypt"]) L.push([a, "*"]);
    return L;
  })();
  const LOGS = {
    stagiaire: [["s3:GetObject", "publications-guilde/index.html", 41], ["s3:GetObject", "publications-guilde/actualites.html", 17], ["s3:PutObject", "publications-guilde/actualites.html", 12], ["s3:ListBucket", "publications-guilde", 9], ["ec2:DescribeInstances", "*", 5]],
    bob: [["s3:GetObject", "registres-guilde/2024.csv", 58], ["s3:PutObject", "registres-guilde/2025.csv", 14], ["s3:ListBucket", "registres-guilde", 20]],
    alice: [["s3:GetObject", "registres-guilde/2024.csv", 33], ["s3:GetObject", "sauvegardes-guilde/2025.tar", 2], ["s3:ListBucket", "registres-guilde", 8]],
    "deploy-bot": [["s3:PutObject", "publications-guilde/index.html", 30], ["ec2:DescribeInstances", "*", 30]],
  };
  const LAYERS = [["don", "Données"], ["id", "Identités et accès"], ["cfg", "Configuration du service"], ["app", "Application"], ["os", "Système (OS)"], ["hw", "Matériel et virtualisation"]];
  const MATRIX = { don: "ccc", id: "ccc", cfg: "ccc", app: "ccf", os: "cff", hw: "fff" }; // c = client, f = fournisseur ; colonnes IaaS, PaaS, SaaS
  const SHORT = { id: "Identités, accès", cfg: "Config. du service", hw: "Matériel, virtu." };
  const MODELS = ["IaaS", "PaaS", "SaaS"];
  const QS = [
    ["os", 0, "Ton instance web-1 est une machine virtuelle louée (IaaS). Son système d'exploitation a besoin d'un correctif de sécurité. Qui doit l'appliquer ?"],
    ["os", 1, "Même question en PaaS : tu déposes seulement ton code sur une plateforme managée. Qui maintient et corrige le système qui fait tourner ton application ?"],
    ["cfg", 1, "Le stockage d'objets est un service managé : le fournisseur garantit qu'il fonctionne et que les fichiers ne se perdent pas. Qui décide si un seau est public ou privé ?"],
    ["hw", 0, "Qui garde les portes du centre de données, remplace les disques en panne et alimente les serveurs en électricité ?"],
    ["id", 2, "Tu utilises une messagerie en SaaS. Qui décide qui a un compte, qui a le droit de l'administrer et si le MFA est obligatoire ?"],
  ];
  const cell = (l, m) => MATRIX[l][m] === "c" ? "client" : "fournisseur";

  const notes = {
    partage: ["Le modèle de responsabilité partagée", "Le fournisseur protège LE nuage (bâtiments, matériel, hyperviseur, services managés) ; le client protège CE QU'IL MET DANS le nuage. Plus on monte vers le SaaS, plus le fournisseur gère de couches (système, application) ; mais les données, les identités et la configuration restent toujours chez le client. La plupart des fuites cloud viennent d'une configuration du client, pas d'une faille du fournisseur."],
    iam: ["IAM et moindre privilège", "IAM décide qui peut faire quoi sur quelle ressource. Le moindre privilège donne à chaque identité le minimum nécessaire, et seulement le temps nécessaire. Un droit trop large est dangereux deux fois : par ses usages directs, et parce que certaines actions (iam:AttachUserPolicy, iam:PutUserPolicy, iam:CreatePolicyVersion, iam:CreateAccessKey) permettent de se donner d'autres droits : c'est l'élévation de privilèges. Un outil d'accès généré lit l'historique d'usage (journal) et propose une politique limitée à ce qui a été réellement utilisé ; on la relit avant de l'adopter, car elle ne connaît pas les conditions voulues (MFA, IP) ni les usages rares mais légitimes."],
    refus: ["Refus par défaut et Deny explicite", "Une requête est refusée par défaut (implicit deny) tant qu'aucune politique ne l'autorise. Ensuite : si une instruction Deny correspond, la requête est refusée, quel que soit le nombre de Allow (le Deny explicite l'emporte toujours) ; sinon, si un Allow correspond, elle est autorisée ; sinon, elle reste refusée. Les conditions (MFA présent, adresse source dans une plage) font partie de la correspondance : condition fausse, instruction ignorée. Les jokers (*, ?) élargissent vite : « s3:* sur * » autorise énormément."],
    stockage: ["Stockage d'objets : public, listage, chiffrement", "Un seau public est lisible par tout Internet, sans identifiant. Le listage anonyme est pire : il livre la liste de tous les fichiers à qui sait chercher. Un contenu public voulu (site vitrine) n'a jamais besoin de listage. Le chiffrement au repos protège contre la perte ou le vol du support et satisfait la conformité ; il ne ferme PAS l'accès : le service déchiffre pour toute personne autorisée à lire, y compris « tout le monde » si le seau est public. Le bon réflexe : blocage de l'accès public activé par défaut au niveau du compte."],
    sg: ["Groupes de sécurité", "Un groupe de sécurité est un pare-feu virtuel attaché aux instances : des règles d'entrée par port et par plage d'adresses (notation CIDR : 10.0.1.0/24 = 256 adresses, 0.0.0.0/0 = tout Internet). Ouvrir un port d'administration (SSH 22, bureau à distance 3389) ou de base de données (3306, 5432) à 0.0.0.0/0 est l'erreur la plus classique : des robots balaient en permanence l'Internet entier. On limite à un bastion, un VPN ou un sous-réseau applicatif, et une base de données n'a pas d'adresse publique du tout."],
    secrets: ["Secrets et clés d'accès", "Une clé d'accès est un mot de passe de machine, valable tant qu'on ne la révoque pas. Dangers : une clé ancienne (jamais renouvelée, donc probablement copiée ici ou là), une clé écrite en dur dans le code (les dépôts sont clonés, publiés, indexés), et surtout une clé du compte racine, qui contourne tout. Remèdes : rôles temporaires plutôt que clés longues, renouvellement régulier, secrets rangés dans un gestionnaire de secrets, aucune clé de racine (avec MFA sur le compte racine). Une clé qui a fuité se révoque, même si on l'a retirée du code : l'historique du dépôt la contient encore."],
    journal: ["Journalisation d'audit", "Le journal d'audit enregistre chaque appel d'API : qui (identité, clé), quoi, d'où (adresse IP), quand, avec quel résultat. Sans lui, après un incident on voit des dégâts mais pas l'auteur ni le chemin pris. Bonnes pratiques : activé dans toutes les régions, écrit dans un seau séparé et verrouillé, avec validation d'intégrité pour détecter les altérations, et surveillé : un arrêt de journalisation est lui-même une alerte. On ne peut pas reconstituer a posteriori ce qui n'a pas été enregistré."],
    imds: ["Le service de métadonnées d'instance", "Chaque instance peut interroger une adresse locale spéciale (169.254.169.254) pour lire ses propres métadonnées, dont les identifiants temporaires de son rôle. Avec la version 1, un simple GET suffit : une faille de l'application qui fait émettre des requêtes au serveur (SSRF) peut donc voler le rôle de l'instance. La version 2 exige d'abord un jeton de session obtenu par une requête PUT avec un en-tête dédié, que ces failles ne savent généralement pas produire. On impose la v2, on limite les droits du rôle de l'instance et on réduit la portée du jeton."],
    facture: ["La facture comme signal de compromission", "Un compte volé sert souvent à lancer des calculs coûteux (minage de cryptomonnaie) dans une région inutilisée : la première alerte est parfois la facture. Une alerte de budget compare le coût quotidien à une référence (ici la médiane) : trop sensible, elle crie au loup tous les week-ends ; trop lâche, elle prévient après les dégâts. Le coût dit QUOI et OÙ, le journal d'audit dit QUI. Après avoir révoqué la clé volée, on supprime les ressources malveillantes (sinon elles continuent de coûter), et on interdit les régions inutilisées."],
  };

  /* ---------- utilitaires : CIDR, jokers ---------- */
  function pip(s) { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s); if (!m) return null; const o = m.slice(1).map(Number); if (o.some(v => v > 255)) return null; return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0; }
  function pcidr(s) {
    const m = /^([0-9.]+)(?:\/(\d{1,2}))?$/.exec(s || ""); if (!m) return null;
    const ip = pip(m[1]), bits = m[2] === undefined ? 32 : +m[2]; if (ip === null || bits > 32) return null;
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    return { ip: (ip & mask) >>> 0, bits, mask };
  }
  const inC = (ip, c) => ((ip & c.mask) >>> 0) === c.ip;
  const fip = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const cstr = c => fip(c.ip) + "/" + c.bits;
  const cidrOK = (sgk, need) => {
    const c = pcidr(F().sg[sgk].cidr), n = pcidr(need);
    return !!c && c.bits >= 16 && inC(c.ip, pcidr("10.0.0.0/8")) && n.bits >= c.bits && inC(n.ip, c);
  };
  const gm = (p, s, ci) => {
    const re = new RegExp("^" + p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", ci ? "i" : "");
    return re.test(s);
  };

  /* ---------- moteur d'évaluation IAM (jouet) ---------- */
  const stxt = s => `${s.e} ${s.a.join(",")} sur ${s.r.join(",")}` + ((s.c || []).length ? " si " + s.c.map(c => c[0] === "Bool" ? "MFA" : "IP dans " + c[2]).join(" et ") : "");
  function condOK(c, ctx) {
    if (c[0] === "Bool") return !!ctx.mfa === (c[2] === "true");
    if (c[0] === "IpAddress") { const ip = ctx.ip ? pip(ctx.ip) : null, cd = pcidr(c[2]); return ip !== null && !!cd && inC(ip, cd); }
    return false;
  }
  function evalWith(names, act, res, ctx) {
    const x = F(), tr = []; let allow = false, deny = false;
    for (const pn of names) (x.pol[pn] || []).forEach((s, i) => {
      const am = s.a.some(p => gm(p, act, true)), rm = s.r.some(p => gm(p, res, false));
      const cm = (s.c || []).every(c => condOK(c, ctx));
      const ok = am && rm && cm;
      if (ok && s.e === "Deny") deny = true;
      if (ok && s.e === "Allow") allow = true;
      tr.push({ pn, i: i + 1, e: s.e, txt: stxt(s), ok, why: !am ? "action différente" : !rm ? "autre ressource" : !cm ? "condition non remplie" : "correspond" });
    });
    return { dec: deny ? "explicit" : allow ? "allow" : "implicit", tr, req: { act, res, ctx } };
  }
  const ev = (p, act, res, ctx) => { const r = evalWith(F().att[p] || [], act, res, ctx || {}); r.req.p = p; return r; };
  const okAct = (p, a, r, ctx) => ev(p, a, r, ctx).dec === "allow";
  const granted = names => CAT.filter(([a, r]) => evalWith(names, a, r, {}).dec === "allow").length;
  const decTxt = d => d === "allow" ? "AUTORISÉ" : d === "explicit" ? "REFUSÉ (Deny explicite)" : "REFUSÉ (par défaut : aucun Allow)";

  /* ---------- scanner de configuration ---------- */
  function checks() {
    const x = F(), C = [];
    const add = (id, sev, res, txt, ok, okTxt, layer, grp, vague, fix) => C.push({ id, sev, res, txt, ok, okTxt, layer, grp, vague, fix });
    const pub = Object.keys(x.b).find(k => x.b[k].list);
    add("ST-1", "CRITIQUE", BK.registres, "objets lisibles par tout Internet (accès public)", !x.b.registres.pub, "privé", "cfg", "sto", "Le seau des registres de la Guilde est lisible sans identifiant par n'importe qui. Aux Entrepôts, ferme l'accès public.", "`bloquer registres`");
    add("ST-2", "ÉLEVÉ", pub ? BK[pub] : BK.publications, "listage anonyme : la liste de tous les fichiers est publique", !pub, "pas de listage anonyme", "cfg", "sto", "Un seau peut être public volontairement (site vitrine) sans qu'on doive pouvoir en lister le contenu. Cherche quel seau expose encore son listage, et ne casse pas le site.", "`desactiver listage " + (pub || "publications") + "`");
    add("ST-3", "ÉLEVÉ", BK.registres, "chiffrement au repos absent", x.b.registres.enc, "chiffré au repos", "don", "sto", "Les registres sont stockés en clair sur les disques du fournisseur. Active le chiffrement au repos.", "`chiffrer registres`");
    add("ST-4", "ÉLEVÉ", BK.sauvegardes, "chiffrement au repos absent", x.b.sauvegardes.enc, "chiffré au repos", "don", "sto", "Les sauvegardes aussi sont en clair. Active le chiffrement au repos.", "`chiffrer sauvegardes`");
    add("ST-5", "SERVICE", BK.publications, "le site vitrine n'est plus accessible (public voulu)", x.b.publications.pub, "public voulu (site vitrine)", "cfg", "sto", "Ta correction a coupé le site vitrine, qui est PUBLIC par conception. Rouvre-le (sans listage).", "`ouvrir publications`");
    add("RS-1", "CRITIQUE", "sg-admin", `port 22 (administration) ouvert à ${x.sg.admin.cidr}` + (cidrOK("admin", BASTION) || x.sg.admin.cidr === "0.0.0.0/0" ? "" : " : trop large, ou le bastion est exclu"), cidrOK("admin", BASTION), "22 limité à " + x.sg.admin.cidr, "cfg", "net", "L'administration (SSH, port 22) est ouverte à tout Internet. Limite-la au réseau du bastion d'administration (10.0.1.0/24).", "`restreindre sg-admin 22 10.0.1.0/24`");
    add("RS-2", "CRITIQUE", "sg-base", `port 3306 (base de données) ouvert à ${x.sg.base.cidr}` + (cidrOK("base", APPNET) || x.sg.base.cidr === "0.0.0.0/0" ? "" : " : trop large, ou les serveurs applicatifs sont exclus"), cidrOK("base", APPNET), "3306 limité à " + x.sg.base.cidr, "cfg", "net", "La base de données accepte des connexions de tout Internet. Seuls les serveurs applicatifs (10.0.2.0/24) en ont besoin.", "`restreindre sg-base 3306 10.0.2.0/24`");
    add("RS-3", "SERVICE", "sg-web", "le port 443 du site n'est plus joignable par les visiteurs", x.sg.web.cidr === "0.0.0.0/0", "443 ouvert au public (voulu)", "cfg", "net", "Le site web DOIT rester joignable par tout le monde sur le port 443 : rouvre-le.", "`restreindre sg-web 443 0.0.0.0/0`");
    add("CP-1", "ÉLEVÉ", "base-1", "adresse IP publique sur la machine de la base de données", !x.ins["base-1"].pub, "aucune adresse publique", "cfg", "net", "La machine de la base de données a une adresse IP publique, alors que seuls des serveurs internes lui parlent. Retire-la.", "`isoler base-1`");
    add("CP-2", "ÉLEVÉ", "web-1", "service de métadonnées en version 1 (sans jeton de session)", x.ins["web-1"].v2, "métadonnées v2 (jeton exigé)", "os", "inst", "Le serveur web répond au service de métadonnées sans jeton de session : une faille du site pourrait en voler le rôle. Aux Entrepôts, regarde ce que « voit » un simple GET, puis impose la version 2.", "`exiger jetons web-1` (tu peux d'abord voir `metadonnees web-1`)");
    add("CL-1", "ÉLEVÉ", "clé deploy-bot", `clé d'accès vieille de ${x.k["deploy-bot"].age} jours (plafond 90)`, x.k["deploy-bot"].age <= 90, "clé récente (" + x.k["deploy-bot"].age + " j)", "id", "keys", "La clé de l'outil de déploiement n'a jamais été renouvelée. Au Coffre des clés, renouvelle-la.", "`renouveler deploy-bot`");
    add("CL-2", "CRITIQUE", "clé site-web", x.k["site-web"].hard ? "clé d'accès écrite en clair dans le dépôt de code (visible de tous)" : "ancienne clé encore valide, copiée dans le dépôt", !x.k["site-web"].hard && x.kd, "clé rangée au gestionnaire de secrets", "id", "keys", "Une clé d'accès traîne en clair dans le dépôt de code du site. Renouvelle ET range-la dans le gestionnaire de secrets : la simple rotation laisserait la nouvelle clé dans le code.", "`ranger site-web`");
    add("CL-3", "CRITIQUE", "compte racine", "le compte racine possède une clé d'accès active", x.k.racine.gone, "aucune clé de racine", "id", "keys", "Le compte racine (tous les droits, impossible à restreindre) a une clé d'accès. Une clé de racine ne se renouvelle pas : elle se supprime.", "`revoquer racine`");
    add("JN-1", "ÉLEVÉ", "journal d'audit", "journalisation d'audit désactivée : aucune trace de qui fait quoi", x.trail, "journal actif, validé, dans " + BK.journaux, "cfg", "trail", "Personne ne sait qui a fait quoi dans ce compte : le journal d'audit est éteint. Au Coffre des clés, allume-le.", "`journaliser`");
    add("CP-3", "CRITIQUE", "région ap-sud", `${x.rogue} instances de calcul inconnues, sans étiquette`, x.rogue === 0, "aucune instance inconnue", "cfg", "purge", "Les instances inconnues de la région ap-sud tournent toujours et coûtent chaque jour. Mais d'abord, la clé qui a servi à les lancer doit être invalidée (sinon elles reviennent). Ensuite, au guichet de facturation, supprime-les.", "`purger ap-sud` (au Guichet de facturation, après `ranger site-web`)");
    const esc = PRINC.filter(p => ESC.some(a => okAct(p, a, p)));
    add("IA-1", "CRITIQUE", esc.length ? esc.join(", ") : "identités", "peut se donner d'autres droits (élévation de privilèges)", !esc.length, "aucun chemin d'élévation", "id", "iam", "Un compte peut modifier les droits IAM, donc s'en donner. Aux Habilitations, lis `droits` : qui a `iam:*` ? Remplace ses droits par un accès limité à ce qu'il utilise.", "`generer stagiaire` puis `adopter stagiaire`");
    const bobDel = okAct("bob", "s3:DeleteObject", "registres-guilde/2024.csv"), bobRead = okAct("bob", "s3:GetObject", "registres-guilde/2024.csv");
    add("IA-2", "ÉLEVÉ", "bob", bobDel ? "peut supprimer les registres (s3:* accordé)" : "ne peut plus lire les registres : ta correction est trop large", !bobDel && bobRead, "écriture sans suppression", "id", "iamfix", bobDel ? "Bob a besoin de lire et d'écrire les registres, pas de les supprimer. Sans toucher à ses droits actuels, ajoute une instruction qui interdit la suppression, puis attache-la à Bob." : "Ton refus est trop large : Bob doit toujours pouvoir lire les registres. Détache ta politique et refais-la plus précise.", "`politique ProtegeRegistres refuser s3:DeleteObject registres-guilde/*` puis `attacher ProtegeRegistres bob`");
    const nomfa = PRINC.filter(p => okAct(p, "s3:GetObject", "sauvegardes-guilde/2025.tar"));
    add("IA-3", "ÉLEVÉ", nomfa.length ? nomfa.join(", ") : "sauvegardes", "lit les sauvegardes sans MFA ni réseau interne", !nomfa.length, "sauvegardes protégées par MFA + IP", "id", "iam", "Une identité lit les sauvegardes sans MFA ni réseau interne, car un joker lui donne tout. Le moindre privilège règle aussi ce point.", "`generer stagiaire` puis `adopter stagiaire`");
    return C;
  }
  const grpOpen = g => checks().filter(c => c.grp === g && !c.ok);
  const sevOrd = { CRITIQUE: 0, "ÉLEVÉ": 1, SERVICE: 2 };

  /* ---------- entités et lieux ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle t'a confié, avec mandat écrit, l'audit du compte cloud de Port-443. Tout est simulé : aucune vraie ressource n'est touchée." },
    tableau: { names: ["tableau", "responsabilite", "tableau de responsabilite", "matrice"], label: "le tableau de responsabilité", desc: () => "Un grand tableau : qui est responsable de quoi, selon le modèle de service (IaaS : machines louées ; PaaS : plateforme managée ; SaaS : logiciel clé en main).", onExamine() { out("Qui est responsable ? (fournisseur ou client)", "sys"); code(["Couche                        IaaS         PaaS         SaaS", ...LAYERS.map(([k, n]) => n.padEnd(30) + [0, 1, 2].map(m => cell(k, m).padEnd(13)).join(""))].join("\n")); } },
    console: { names: ["scanner", "console", "console d audit", "scanner de configuration"], label: "le scanner de configuration", desc: () => "Le scanner de configuration de la Guilde parcourt les ressources du compte (seaux, groupes de sécurité, instances, clés, journal, droits) et compare chaque réglage aux bonnes pratiques. `scanner` lance l'analyse ; relance-la après chaque correction." },
    seaux: { names: ["seaux", "seau", "stockage", "buckets"], label: "les seaux de stockage", desc: () => { const x = F(); return "Les seaux du compte (réglages bruts) :\n" + Object.keys(BK).map(k => `  · ${BK[k]} : ${x.b[k].pub ? "PUBLIC" : "privé"}, listage anonyme ${x.b[k].list ? "oui" : "non"}, chiffré ${x.b[k].enc ? "oui" : "non"}`).join("\n") + "\nCommandes : `bloquer ‹seau›` · `ouvrir ‹seau›` · `desactiver listage ‹seau›` · `chiffrer ‹seau›`"; } },
    groupes: { names: ["groupes", "groupe de securite", "groupes de securite", "pare feu", "sg"], label: "les groupes de sécurité", desc: () => { const x = F(); return "Les groupes de sécurité (règles d'entrée) :\n" + Object.keys(x.sg).map(k => `  · sg-${k} : port ${x.sg[k].port} depuis ${x.sg[k].cidr}`).join("\n") + "\nCommande : `restreindre ‹groupe› ‹port› ‹plage CIDR›`, par exemple `restreindre sg-admin 22 10.0.1.0/24`."; } },
    instances: { names: ["instances", "instance", "machines", "serveurs"], label: "les instances", desc: () => { const x = F(); return "Les instances du compte :\n" + Object.keys(x.ins).map(k => `  · ${k} (${k === "web-1" ? "serveur web, groupes sg-web et sg-admin" : "base de données, groupe sg-base"}) : ${x.ins[k].pub ? "adresse IP publique" : "privée seulement"}, métadonnées ${x.ins[k].v2 ? "v2 (jeton exigé)" : "v1 (sans jeton)"}`).join("\n") + "\nCommandes : `isoler ‹instance›` (retire l'IP publique) · `exiger jetons ‹instance›` · `metadonnees ‹instance›`"; } },
    alice: { npc: true, names: ["alice"], label: "Alice (administratrice cloud)", desc: () => "Alice, qui administre le compte cloud de la Guilde. Elle lit les registres et les sauvegardes, avec le MFA et depuis le réseau interne." },
    cles: { names: ["cles", "trousseau", "cle", "coffre de cles"], label: "le trousseau de clés d'accès", desc: () => { const x = F(); return "Le trousseau des clés d'accès du compte :\n" + Object.keys(x.k).map(k => { const c = x.k[k]; return `  · ${k} : ${c.gone ? "supprimée" : "âge " + c.age + " jours" + (c.hard ? ", copiée dans le dépôt de code" : "") + (c.root ? ", clé du compte RACINE" : "")}`; }).join("\n") + "\nCommandes : `renouveler ‹nom›` · `ranger ‹nom›` (au gestionnaire de secrets) · `revoquer ‹nom›`"; } },
    journal: { names: ["journal", "journal d audit", "audit", "trail"], label: "le journal d'audit", desc: () => "Le registre des appels d'API : qui, quoi, d'où, quand, avec quel résultat. Il est " + (F().trail ? "ALLUMÉ : il écrit dans " + BK.journaux + ", avec validation d'intégrité." : "ÉTEINT : rien n'est enregistré.") + " `journaliser` l'allume." },
    droits: { names: ["registre des droits", "registre", "droits", "iam", "console iam"], label: "le registre des droits (IAM)", desc: () => "Le registre des habilitations : identités, politiques, rattachements. Commandes : `droits [‹nom›]` · `evaluer ‹qui› ‹action› ‹ressource› [ip=‹adresse›] [mfa=oui]` · `politique ‹nom› ‹autoriser|refuser› ‹action› ‹ressource›` · `attacher ‹politique› ‹qui›` · `detacher ‹politique› ‹qui›`. Identités : alice, bob, deploy-bot, stagiaire. Les jokers `*` et `?` sont acceptés." },
    historique: { names: ["historique", "usage", "journal d usage", "journaux d usage"], label: "l'historique d'usage (90 jours)", desc: () => "L'historique des appels réellement effectués par chaque identité, tiré du journal d'audit. `generer ‹qui›` s'en sert pour proposer une politique minimale ; `adopter ‹qui›` la met en place." },
    bob: { npc: true, names: ["bob"], label: "Bob (comptable)", desc: () => "Bob, comptable de la Guilde. Il lit et écrit les registres tous les jours. Il n'a jamais supprimé un seul fichier, et il ne veut pas qu'on lui ôte son travail." },
    guichet: { names: ["guichet", "facture", "facturation", "tableau de bord"], label: "le tableau de facturation", desc: () => "Le guichet de la facturation du nuage : coût journalier du compte, en pièces d'or (po). `facture` affiche les 14 derniers jours." },
    alarme: { names: ["alarme", "alerte", "alertes", "budget"], label: "l'alarme de budget", desc: () => "Une cloche reliée au coût journalier. `alerte ‹multiplicateur›` la règle : elle sonne quand le coût d'un jour dépasse ce multiple du coût habituel (la médiane). Ex. `alerte 1.5`." },
  };

  const rooms = {
    parvis: { name: "Le Parvis du Nuage", short: "Parvis", alias: ["parvis", "place"], ents: ["ada", "tableau"], exits: { nord: "console", est: "habilitations", sud: "entrepots", ouest: "coffre" },
      desc: () => "Sur le parvis, des bruissements : la Guilde a déménagé ses registres dans « le Nuage », un vaste entrepôt que gère un fournisseur lointain. Au nord, la salle du scanner. À l'est, le bureau des habilitations. Au sud, les entrepôts. À l'ouest, le coffre des clés." },
    console: { name: "La salle du scanner", short: "Scanner", alias: ["console", "scanner", "salle"], ents: ["console"], exits: { sud: "parvis" },
      desc: () => "Une salle de verre où un scanner parcourt, ressource par ressource, tout le compte cloud et affiche ses constats avec leurs gravités. Tu l'as autorisé par mandat : il ne fait que lire les réglages." },
    entrepots: { name: "Les entrepôts du Nuage", short: "Entrepôts", alias: ["entrepots", "entrepot", "stockage"], ents: ["alice", "seaux", "groupes", "instances"], exits: { nord: "parvis", est: "facturation" },
      desc: () => "Des rayonnages virtuels à perte de vue : les seaux de stockage, les groupes de sécurité (pare-feu virtuels) et les instances (machines louées). Alice y mesure, règle, ferme. À l'est, le guichet de la facturation." },
    coffre: { name: "Le coffre des clés", short: "Coffre", alias: ["coffre", "cles"], ents: ["cles", "journal"], exits: { est: "parvis" },
      desc: () => "Un coffre où pendent les clés d'accès du compte, et, au mur, le registre du journal d'audit. Chaque clé est un mot de passe de machine : ici, on les compte, on les renouvelle, on les révoque." },
    habilitations: { name: "Le bureau des habilitations", short: "Habilitations", alias: ["habilitations", "iam", "bureau"], ents: ["bob", "droits", "historique"], exits: { ouest: "parvis" },
      desc: () => "Le bureau où l'on décide qui peut faire quoi sur quelle ressource. Le registre des droits porte les politiques ; l'historique d'usage en dit long sur ce que chacun utilise vraiment. Bob y attend, un peu inquiet." },
    facturation: { name: "Le guichet de la facturation", short: "Facturation", alias: ["facturation", "guichet", "facture"], ents: ["guichet", "alarme"], exits: { ouest: "entrepots" },
      desc: () => "Un guichet à barreaux de laiton, où des clercs additionnent les dépenses du Nuage à la pièce d'or près. Aujourd'hui, ils ont l'air alarmés." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (x.q < QS.length) return "resp";
    if (!x.fac0) return "facture";
    if (!x.alertOK) return "alerte";
    if (!x.enq) return "enq";
    if (!x.scan0) return "scan0";
    for (const g of ["sto", "net", "inst", "keys", "trail", "purge"]) if (grpOpen(g).length) return g;
    if (!x.evDel) return "iam0";
    if (!x.evImpl) return "impl";
    if (grpOpen("iamfix").length) return "iamfix";
    if (!(x.condFail && x.condOk)) return "cond";
    if (!x.elev) return "elev";
    if (!x.gen) return "gen";
    if (!x.adopted) return "adopt";
    if (!x.elev2) return "elev2";
    if (grpOpen("iam").length) return "iamrest";
    if (!x.scan2) return "scan2";
    if (!x.end) return "end";
    return "fin";
  };
  const firstOf = g => { const c = grpOpen(g)[0]; return c ? [c.vague, c.fix] : ["", ""]; };
  const hints = {
    quest: () => ["Maître Ada t'attend sur le parvis.", "`parler ada`"],
    resp: () => ["Ada te pose une question sur qui est responsable de quoi. Réponds-lui, tu peux relire le tableau du parvis.", "`examiner tableau`, puis `dire client` ou `dire fournisseur`."],
    facture: () => ["La facture a explosé. Va au guichet de la facturation : sud depuis le parvis, puis est.", "`aller sud`, `aller est`, `facture`."],
    alerte: () => ["Une alarme de budget aurait dû sonner. Règle-la : ni trop sensible (fausses alertes), ni trop lâche (trop tard).", "`alerte 1.4` (essaie 1.0, puis 3, pour comparer)."],
    enq: () => ["Cherche d'où vient le surcoût : dans quel service et quelle région ?", "`enqueter`"],
    scan0: () => ["Place au scanner de configuration. Il est au nord du parvis.", "Depuis la facturation : `aller ouest`, `aller nord`, `aller nord`, puis `scanner`."],
    sto: () => firstOf("sto"), net: () => firstOf("net"), inst: () => firstOf("inst"), keys: () => firstOf("keys"), trail: () => firstOf("trail"), purge: () => firstOf("purge"),
    iam0: () => ["Au bureau des habilitations (est du parvis), demande au moteur si Bob peut supprimer un registre. Regarde ce qu'il répond.", "`aller est`, `evaluer bob s3:DeleteObject registres-guilde/2024.csv`"],
    impl: () => ["Teste maintenant une action que personne n'a autorisée : Alice peut-elle écrire dans les registres ?", "`evaluer alice s3:PutObject registres-guilde/2024.csv`"],
    iamfix: () => firstOf("iamfix"),
    cond: () => ["Les sauvegardes sont protégées par des conditions. Teste l'accès d'Alice sans contexte, puis depuis le réseau interne avec MFA.", "`evaluer alice s3:GetObject sauvegardes-guilde/2025.tar`, puis `evaluer alice s3:GetObject sauvegardes-guilde/2025.tar ip=10.0.5.9 mfa=oui`"],
    elev: () => ["Un des comptes a un droit dangereux. Observe, dans le moteur, ce que Mallory ferait avec la clé du stagiaire (simulation).", "`elever stagiaire`"],
    gen: () => ["Plutôt que de deviner les droits du stagiaire, génère-les à partir de ce qu'il a vraiment utilisé.", "`generer stagiaire`"],
    adopt: () => ["Relis la politique proposée, puis adopte-la à la place de ses droits actuels.", "`adopter stagiaire`"],
    elev2: () => ["Rejoue la simulation : le chemin d'élévation est-il fermé ?", "`elever stagiaire`"],
    iamrest: () => firstOf("iam"),
    scan2: () => ["Il ne reste qu'à relancer le scanner pour confirmer que tout est au vert : va au nord du parvis.", "`aller ouest` ou `aller est` jusqu'au parvis, `aller nord`, `scanner`."],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues et quiz ---------- */
  function ask() {
    const q = QS[F().q];
    say("Maître Ada", `Question ${F().q + 1}/${QS.length}. ${q[2]}`);
    out("Réponds : `dire client` ou `dire fournisseur`.", "sys");
  }
  function answer(a) {
    const x = F(), q = QS[x.q], right = cell(q[0], q[1]), L = LAYERS.find(l => l[0] === q[0])[1];
    x.miss = x.miss || 0;
    if (a === right) {
      say("Maître Ada", `Exactement : ${right}. Pour la couche « ${L} » en ${MODELS[q[1]]}, c'est ${right === "client" ? "toi qui en es responsable : le fournisseur te fournit le service, pas la configuration" : "le fournisseur, tu n'as rien à y toucher (et rien à y voir)"}.`);
      x.q++; x.miss = 0;
    } else if (x.miss >= 1) {
      say("Maître Ada", `Non plus : c'est le ${right}. ${right === "client" ? "Dans le nuage, les données, les identités et la configuration te reviennent toujours." : "Ce qui est sous le service que tu consommes appartient au fournisseur."} Passons.`);
      x.q++; x.miss = 0;
    } else {
      x.miss++;
      say("Maître Ada", a ? `Pas tout à fait. Regarde le tableau (\`examiner tableau\`) : à la ligne « ${L} », colonne ${MODELS[q[1]]}, qui s'en charge ? Essaie encore.` : "Réponds par `dire client` ou `dire fournisseur`.");
      return;
    }
    if (x.q < QS.length) ask();
    else {
      say("Maître Ada", "Retiens la règle d'or : le fournisseur sécurise le nuage, TOI tu sécurises ce que tu y mets. Données, identités, configuration : toujours à toi. Or hier, la facture du nuage a été multipliée par quatre, sans que personne n'ait lancé de calcul. Va voir le guichet de la facturation (sud, puis est), puis le scanner.");
      note("partage"); fig("partage");
    }
  }
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Bienvenue. Pour gagner en souplesse, la Guilde a migré ses registres dans « le Nuage ». Ici, plus de murailles à nous : des seaux de stockage, des groupes de sécurité, des clés d'accès, des politiques IAM. Tout se règle par des paramètres, et la moindre erreur de paramètre se paie cher. Tu as mandat pour auditer ce compte et le corriger. Tout ce que tu verras est simulé.");
          say("Maître Ada", "D'abord, une question de fond : dans le nuage, qui est responsable de quoi ?");
          ask();
        } else if (x.q < QS.length) { ask(); }
        else if (objective() === "end") ending();
        else if (x.end) say("Maître Ada", "Le Nuage tient. Merci !");
        else say("Maître Ada", "Ce n'est pas fini. `indice` si tu bloques.");
        break;
      case "alice":
        if (x.scan0 && objective() !== "end") say("Alice", "Chaque réglage que tu corriges ici vaut mieux qu'un incident. Après chaque correction, relance le scanner : il mesure ce qui reste. Et rappelle-toi : un contenu public voulu, comme le site vitrine, ne doit pas être cassé par ton zèle.");
        else say("Alice", "Je gère le compte au jour le jour, mais je n'ai jamais eu le temps de le durcir. Le scanner de la salle du nord fera un bon état des lieux.");
        break;
      case "bob":
        if (x.evDel && !x.condFail) say("Bob", "Moi, je lis et j'écris les registres. Supprimer ? Jamais. Alors si on m'interdit de supprimer, tant mieux : une erreur de clic de moins.");
        else say("Bob", "Je suis comptable. Je lis et j'écris les registres. Je n'ai rien demandé d'autre : si on m'a donné « s3:* », c'est qu'on a voulu aller vite.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- aides de commandes ---------- */
  const need = (room, msg) => { if (S.room !== room) { out(msg, "sys"); return true; } return false; };
  const bkOf = t => { const n = norm(t); return Object.keys(BK).find(k => n.split(" ").some(w => w === k || w === k.replace(/s$/, "") || n.includes(k))); };
  const insOf = t => { const n = norm(t); return n.includes("web") ? "web-1" : n.includes("base") ? "base-1" : null; };
  const who = t => { const n = (t || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, ""); return PRINC.includes(n) ? n : PALIAS[n.replace(/-/g, "")] || null; };
  const keyId = (n, r) => "CLE-" + sha256(n + ":" + r).slice(0, 10).toUpperCase();
  const pad = (s, n) => String(s).padEnd(n);

  /* ---------- scanner ---------- */
  function scanCmd() {
    if (need("console", "Le scanner est dans la salle du nord (`aller nord` depuis le parvis).")) return;
    const x = F(), C = checks(), bad = C.filter(c => !c.ok).sort((a, b) => sevOrd[a.sev] - sevOrd[b.sev]);
    const first = !x.scan0; x.scan0 = true;
    out(`Analyse du compte « guilde-port443 » : ${C.length} contrôles, ${C.length - bad.length} conformes, ${bad.length} constat(s).`, "sys");
    if (bad.length) {
      code(pad("ID", 6) + pad("GRAVITÉ", 10) + pad("RESSOURCE", 20) + "CONSTAT\n" + bad.map(c => pad(c.id, 6) + pad(c.sev, 10) + pad(c.res, 20) + c.txt).join("\n"));
      if (first) out("Chaque constat est un réglage que tu peux corriger. Les ids commencent par ST (stockage), RS (réseau), CP (calcul), CL (clés), JN (journal), IA (identités). Après chaque correction, relance `scanner`.", "sys");
      else out("Il reste du travail : `indice` te dit par où continuer.", "sys");
    } else {
      code(C.map(c => pad(c.id, 6) + pad("OK", 10) + pad(c.res, 20) + c.okTxt).join("\n"));
      out("Aucun constat : tous les contrôles passent. Va rendre compte à Maître Ada.", "ok");
      x.scan2 = true;
    }
    if (first) out("(En vrai, un tel scanner s'appuie sur les API du fournisseur et des référentiels comme CIS Benchmarks.)", "sys");
  }

  /* ---------- stockage ---------- */
  function showSeau() { const x = F(); if (!x.shownSeau) { x.shownSeau = true; fig("seau"); } else out("`schema seau` pour revoir l'avant / après.", "sys"); }
  function blockCmd(c) {
    if (need("entrepots", "Les seaux se règlent aux Entrepôts (sud du parvis).")) return;
    const k = bkOf(c.rawArg), x = F();
    if (!k) { out("Quel seau ? registres, sauvegardes, publications ou journaux : `bloquer registres`", "err"); return; }
    const b = x.b[k];
    if (!b.pub && !b.list) { out(`${BK[k]} n'est déjà ni public ni listable.`, "sys"); return; }
    if (k === "publications") {
      b.pub = false;
      out(`Accès public de ${BK[k]} bloqué. Mais... ce seau héberge le SITE VITRINE de la Guilde : les visiteurs reçoivent désormais une erreur 403. Un contenu public voulu doit rester public ; c'est le LISTAGE qu'il faut couper. Remets-le en ligne avec \`ouvrir publications\`, puis \`desactiver listage publications\`.`, "err");
      return;
    }
    b.pub = false; b.list = false;
    out(`Blocage de l'accès public sur ${BK[k]} : les objets ne sont plus lisibles sans identifiant, et le listage anonyme est coupé.`, "ok");
    note("stockage"); if (k === "registres") showSeau();
  }
  function openCmd(c) {
    if (need("entrepots", "Les seaux se règlent aux Entrepôts (sud du parvis).")) return;
    const k = bkOf(c.rawArg), x = F();
    if (k !== "publications") { out(k ? `Rouvrir ${BK[k]} au public serait une régression : seul le site vitrine (\`publications\`) est public par conception.` : "Quel seau ? `ouvrir publications`", k ? "err" : "err"); return; }
    if (x.b.publications.pub) { out("Le site vitrine est déjà public.", "sys"); return; }
    x.b.publications.pub = true;
    out("Le site vitrine est de nouveau en ligne (lecture publique, listage inchangé)." + (x.b.publications.list ? " Le listage anonyme, lui, est toujours actif : `desactiver listage publications`." : ""), "ok");
  }
  function offCmd(c) {
    if (need("entrepots", "Les seaux se règlent aux Entrepôts (sud du parvis).")) return;
    const x = F(), n = norm(c.rawArg), k = bkOf(c.rawArg);
    if (!/listage|liste|listing/.test(n)) { out("Que désactiver ? `desactiver listage ‹seau›` (ex. `desactiver listage publications`).", "err"); return; }
    if (!k) { out("Quel seau ? `desactiver listage publications`", "err"); return; }
    if (!x.b[k].list) { out(`Le listage anonyme de ${BK[k]} est déjà coupé.`, "sys"); return; }
    x.b[k].list = false;
    out(`Listage anonyme coupé sur ${BK[k]} : on peut toujours lire un fichier dont on connaît le nom, mais plus parcourir la liste de tous les fichiers.${x.b[k].pub ? " Le site reste public, comme voulu." : ""}`, "ok");
    note("stockage");
  }
  function encCmd(c) {
    if (need("entrepots", "Le chiffrement se règle aux Entrepôts (sud du parvis).")) return;
    const k = bkOf(c.rawArg), x = F();
    if (!k) { out("Quel seau ? `chiffrer registres` ou `chiffrer sauvegardes`", "err"); return; }
    if (x.b[k].enc) { out(`${BK[k]} est déjà chiffré au repos.`, "sys"); return; }
    x.b[k].enc = true;
    out(`${BK[k]} est chiffré au repos (AES-256, clé gérée par le service de clés). Les objets sont désormais illisibles sur le support du fournisseur.`, "ok");
    if (x.b[k].pub) out("Mais attention : le seau est toujours PUBLIC. Le service déchiffre à la volée pour toute personne autorisée à lire, donc pour tout le monde. Le chiffrement au repos ne remplace pas le contrôle d'accès : `bloquer " + k + "`.", "err");
    note("stockage"); if (k === "registres") showSeau();
  }

  /* ---------- réseau et instances ---------- */
  function restrictCmd(c) {
    if (need("entrepots", "Les groupes de sécurité se règlent aux Entrepôts (sud du parvis).")) return;
    const x = F(), tk = c.rawArg.split(/\s+/).filter(Boolean);
    if (!tk.length) { out("`restreindre ‹groupe› ‹port› ‹plage›` : ex. `restreindre sg-admin 22 10.0.1.0/24`.", "err"); return; }
    const k = Object.keys(x.sg).find(s => tk[0].toLowerCase().replace(/^sg-?/, "") === s);
    if (!k) { out("Groupe inconnu : « " + tk[0] + " ». Groupes : sg-web, sg-admin, sg-base.", "err"); return; }
    const portT = tk.slice(1).find(t => /^\d+$/.test(t)), cidrT = tk.slice(1).find(t => /\./.test(t));
    if (portT && +portT !== x.sg[k].port) { out(`sg-${k} ne gère que le port ${x.sg[k].port}.`, "err"); return; }
    if (!cidrT) { out("Il manque la plage d'adresses autorisée, en notation CIDR : `restreindre sg-" + k + " " + x.sg[k].port + " 10.0.1.0/24`. (0.0.0.0/0 = tout Internet.)", "err"); return; }
    const cd = pcidr(cidrT);
    if (!cd) { out("Plage invalide : « " + cidrT + " ». Format attendu : adresse/longueur, par exemple 10.0.1.0/24.", "err"); return; }
    x.sg[k].cidr = cstr(cd);
    const n = 2 ** (32 - cd.bits);
    out(`sg-${k} : port ${x.sg[k].port} accepté depuis ${cstr(cd)} (${n.toLocaleString("fr-FR")} adresse${n > 1 ? "s" : ""}).`, "ok");
    if (k === "web") { out(cd.bits === 0 ? "Le site est de nouveau joignable par tous les visiteurs : c'est voulu pour le port 443." : "Attention : le site vitrine n'est plus joignable que depuis cette plage : les visiteurs, eux, viennent de partout. Rétablis `restreindre sg-web 443 0.0.0.0/0`.", cd.bits === 0 ? "sys" : "err"); return; }
    const need2 = pcidr(k === "admin" ? BASTION : APPNET);
    if (cd.bits === 0) out("C'est encore (ou de nouveau) tout Internet : exactement ce qu'on cherche à fermer.", "err");
    else if (cd.bits < 16 || !inC(cd.ip, pcidr("10.0.0.0/8"))) out(`Ce n'est pas assez précis : une plage ${cd.bits < 16 ? "aussi grande qu'un /" + cd.bits + " ne se justifie pas" : "publique n'est pas voulue ici"}. Vise le strict nécessaire : ${cstr(need2)}.`, "err");
    else if (!(need2.bits >= cd.bits && inC(need2.ip, cd))) out(`Trop strict : ${k === "admin" ? "le bastion d'administration (" + cstr(need2) + ") n'y est pas" : "les serveurs applicatifs (" + cstr(need2) + ") n'y sont pas"} : ${k === "admin" ? "plus personne ne pourrait administrer" : "l'application ne joindrait plus sa base"}. Choisis une plage qui les contient.`, "err");
    else { out(k === "admin" ? "Seul le réseau du bastion peut maintenant ouvrir une session d'administration : les robots du monde entier n'y arrivent plus." : "Seuls les serveurs applicatifs parlent maintenant à la base : une base de données ne s'expose jamais à Internet.", "ok"); note("sg"); }
  }
  function isolateCmd(c) {
    if (need("entrepots", "Les instances se règlent aux Entrepôts (sud du parvis).")) return;
    const i = insOf(c.rawArg), x = F();
    if (!i) { out("Quelle instance ? `isoler base-1`", "err"); return; }
    if (!x.ins[i].pub) { out(i + " n'a déjà pas d'adresse publique.", "sys"); return; }
    if (i === "web-1") { out("web-1 est le serveur du site : il a besoin d'être joignable depuis Internet (via sg-web, port 443 seulement). Isole plutôt la base : `isoler base-1`.", "err"); return; }
    x.ins[i].pub = false;
    out(`L'adresse IP publique de ${i} est retirée : la base n'est plus joignable que depuis le réseau privé du Nuage. Même si une règle de groupe de sécurité se trompait un jour, il n'y aurait plus de chemin depuis Internet : c'est de la défense en profondeur.`, "ok");
    note("sg");
  }
  function imdsCmd(c) {
    if (need("entrepots", "Les instances se trouvent aux Entrepôts (sud du parvis).")) return;
    const i = insOf(c.rawArg), x = F();
    if (!i) { out("Quelle instance ? `metadonnees web-1`", "err"); return; }
    out(`Simulation : une faille du site fait émettre au serveur ${i} un simple GET vers l'adresse locale de métadonnées (169.254.169.254), sans autre en-tête.`, "sys");
    x.imdsSeen = true;
    if (x.ins[i].v2) code("HTTP 401 Unauthorized\n(un jeton de session est requis : il faut d'abord obtenir ce jeton par une requête PUT avec un en-tête dédié)");
    else code("HTTP 200 OK\nrole : role-web-1\nAccessKeyId     : ASIA-FICTIVE-0001\nSecretAccessKey : (fictif) 9f3c…\nToken           : (fictif) IQoJ…\nExpiration      : dans 6 heures");
    out(x.ins[i].v2 ? "La v2 arrête ce scénario : un GET aveugle n'obtient rien." : "Les identifiants temporaires du rôle de l'instance sont lisibles par un simple GET : si un attaquant fait émettre cette requête par le site, il emporte les droits du rôle. Impose la v2 : `exiger jetons " + i + "`.", x.ins[i].v2 ? "ok" : "err");
  }
  function requireCmd(c) {
    if (need("entrepots", "Les instances se règlent aux Entrepôts (sud du parvis).")) return;
    const i = insOf(c.rawArg), x = F();
    if (!i) { out("Quelle instance ? `exiger jetons web-1`", "err"); return; }
    if (x.ins[i].v2) { out(i + " exige déjà la version 2 (jeton de session).", "sys"); return; }
    x.ins[i].v2 = true;
    out(`${i} exige maintenant des jetons de session pour le service de métadonnées (v2). Rejoue la requête : \`metadonnees ${i}\`.`, "ok");
    note("imds");
  }

  /* ---------- clés et journal ---------- */
  function keyOf(t) { const n = norm(t); return n.includes("racine") || n.includes("root") ? "racine" : n.includes("site") ? "site-web" : n.includes("deploy") || n.includes("bot") ? "deploy-bot" : null; }
  function rotateCmd(c) {
    if (need("coffre", "Les clés se gèrent au coffre des clés (ouest du parvis).")) return;
    const x = F(), k = keyOf(c.rawArg);
    if (!k) { out("Quelle clé ? deploy-bot, site-web ou racine : `renouveler deploy-bot`", "err"); return; }
    const K = x.k[k];
    if (K.root) { out("Une clé du compte racine ne se renouvelle pas : elle se SUPPRIME. Le compte racine ne devrait avoir aucune clé d'accès. `revoquer racine`", "err"); return; }
    K.age = 0; K.rot++;
    if (k === "site-web") {
      x.kd = true;
      out(`Nouvelle clé ${keyId(k, K.rot)} émise ; l'ancienne est révoquée. ` + (K.hard ? "Mais la nouvelle clé est encore ÉCRITE EN CLAIR dans le dépôt de code : on a seulement déplacé le problème. Range-la dans le gestionnaire de secrets : `ranger site-web`." : ""), K.hard ? "err" : "ok");
    } else out(`Nouvelle clé ${keyId(k, K.rot)} émise pour ${k} ; l'ancienne est désactivée. Âge : 0 jour. (En vrai, mieux vaut un rôle temporaire qu'une clé longue durée.)`, "ok");
    note("secrets");
  }
  function vaultCmd(c) {
    if (need("coffre", "Les clés se gèrent au coffre des clés (ouest du parvis).")) return;
    const x = F(), k = keyOf(c.rawArg);
    if (!k) { out("Quelle clé ranger ? `ranger site-web`", "err"); return; }
    if (k !== "site-web") { out(k === "racine" ? "La clé de racine ne se range pas : elle se supprime (`revoquer racine`)." : "Cette clé n'est pas écrite en clair dans du code : `renouveler " + k + "` suffit.", "err"); return; }
    const K = x.k[k];
    if (!K.hard && x.kd) { out("La clé de site-web est déjà dans le gestionnaire de secrets.", "sys"); return; }
    K.hard = false; K.age = 0; K.rot++; x.kd = true;
    out(`Nouvelle clé ${keyId(k, K.rot)} émise, rangée dans le gestionnaire de secrets (le site la lit au démarrage) ; l'ancienne est RÉVOQUÉE, car elle est restée dans l'historique du dépôt de code, que tout le monde peut cloner. Retirer un secret du code ne suffit jamais : on le fait tourner.`, "ok");
    note("secrets");
  }
  function revokeCmd(c) {
    if (need("coffre", "Les clés se gèrent au coffre des clés (ouest du parvis).")) return;
    const x = F(), k = keyOf(c.rawArg);
    if (!k) { out("Quelle clé ? `revoquer racine`", "err"); return; }
    if (k !== "racine") { out(`Révoquer ${k} sans la remplacer couperait le service qui l'utilise. ${k === "site-web" ? "Utilise `ranger site-web`" : "Utilise `renouveler " + k + "`"} : on remplace puis on invalide l'ancienne.`, "err"); return; }
    if (x.k.racine.gone) { out("La clé de racine est déjà supprimée.", "sys"); return; }
    x.k.racine.gone = true;
    out("Clé d'accès du compte racine supprimée. Aucune activité légitime n'en dépendait. Le compte racine ne sert plus qu'à de rares opérations, avec MFA matériel, sans aucune clé.", "ok");
    note("secrets");
  }
  function trailCmd() {
    if (need("coffre", "Le journal d'audit se règle au coffre des clés (ouest du parvis).")) return;
    const x = F();
    if (x.trail) { out("Le journal d'audit est déjà actif.", "sys"); return; }
    x.trail = true;
    out(`Journal d'audit ALLUMÉ : toutes les régions, écriture dans ${BK.journaux} (privé, chiffré), validation d'intégrité des fichiers. Désormais, chaque appel d'API laisse une ligne : qui, quoi, d'où, quand, résultat.`, "ok");
    code("2026-10-05T09:12:44Z  alice   ListBuckets          10.0.1.14      OK\n2026-10-05T09:12:51Z  bob     GetObject            10.0.5.9       OK\n(exemple de lignes qui seront enregistrées)");
    note("journal");
  }

  /* ---------- IAM ---------- */
  function parseCtx(tk) {
    const ctx = {}; const rest = [];
    tk.forEach(t => { const m = /^(ip|mfa)=(.*)$/i.exec(t); if (!m) { rest.push(t); return; } if (m[1].toLowerCase() === "ip") ctx.ip = m[2]; else ctx.mfa = /^(oui|true|1|yes)$/i.test(m[2]); });
    return { ctx, rest };
  }
  function showEval(r) {
    const x = F(), q = r.req;
    const L = [`Requête : ${q.p} → ${q.act} sur ${q.res}`, `Contexte : ip=${q.ctx.ip || "(absente)"}, mfa=${q.ctx.mfa ? "oui" : "non"}`, ""];
    if (!r.tr.length) L.push("(aucune politique rattachée à cette identité)");
    r.tr.forEach(t => L.push(`${t.ok ? "✔" : "·"} ${t.pn}#${t.i} ${t.txt}  → ${t.why}`));
    L.push("", "Décision : " + decTxt(r.dec));
    code(L.join("\n"));
    if (r.dec === "explicit") { out("Un Deny explicite correspond" + (r.tr.some(t => t.ok && t.e === "Allow") ? " alors qu'un Allow correspond aussi : le Deny l'emporte TOUJOURS." : "."), "ok"); }
    else if (r.dec === "implicit") out(r.tr.some(t => !t.ok && t.why === "condition non remplie") ? "Aucun Allow ne s'applique : une instruction visait bien cette action et cette ressource, mais sa condition n'est pas remplie (MFA absent ou adresse hors plage). Refus par défaut." : "Aucune instruction n'autorise cette requête : refus PAR DÉFAUT. Dans IAM, tout ce qui n'est pas explicitement autorisé est interdit.", "sys");
    else out("Un Allow correspond et aucun Deny ne s'y oppose : requête autorisée.", "sys");
    if (r.dec !== "allow") note("refus"); else if (r.tr.length) note("refus");
    x.lastEval = r;
    if (!x.shownIam) { x.shownIam = true; fig("iam", r); } else out("`schema iam` pour le schéma de cette évaluation.", "sys");
  }
  function evalCmd(c) {
    if (need("habilitations", "Le moteur d'évaluation est au bureau des habilitations (est du parvis).")) return;
    const x = F(), { ctx, rest } = parseCtx(c.rawArg.split(/\s+/).filter(Boolean));
    if (rest.length < 3) { out("`evaluer ‹qui› ‹action› ‹ressource› [ip=‹adresse›] [mfa=oui]` : ex. `evaluer bob s3:DeleteObject registres-guilde/2024.csv`", "err"); return; }
    const p = who(rest[0]);
    if (!p) { out("Identité inconnue : « " + rest[0] + " ». Identités : " + PRINC.join(", ") + ".", "err"); return; }
    if (!/^[a-z0-9-]+:[A-Za-z0-9*?]+$/i.test(rest[1])) { out("Action au format service:Action, par exemple s3:GetObject, ec2:RunInstances, iam:AttachUserPolicy.", "err"); return; }
    if (ctx.ip && pip(ctx.ip) === null) { out("Adresse invalide : « " + ctx.ip + " ». Exemple : ip=10.0.5.9", "err"); return; }
    const r = ev(p, rest[1], rest[2], ctx);
    if (r.dec === "implicit") x.evImpl = true;
    if (p === "bob" && /^s3:deleteobject$/i.test(rest[1]) && /^registres-guilde/.test(rest[2]) && r.dec === "allow") x.evDel = true;
    if (p === "alice" && /^s3:getobject$/i.test(rest[1]) && /^sauvegardes-guilde\//.test(rest[2])) { if (r.dec === "allow") x.condOk = true; else x.condFail = true; }
    showEval(r);
  }
  function polCmd(c) {
    if (need("habilitations", "Les politiques s'écrivent au bureau des habilitations (est du parvis).")) return;
    const x = F(), tk = c.rawArg.split(/\s+/).filter(Boolean);
    if (tk.length < 4) { out("`politique ‹nom› ‹autoriser|refuser› ‹action› ‹ressource›` : ex. `politique ProtegeRegistres refuser s3:DeleteObject registres-guilde/*`", "err"); return; }
    const [name, eff, act, res] = tk, e = /^(autoriser|allow|accorder)$/i.test(eff) ? "Allow" : /^(refuser|deny|interdire)$/i.test(eff) ? "Deny" : null;
    if (!/^[A-Za-z0-9_-]+$/.test(name)) { out("Le nom d'une politique : lettres, chiffres, tirets.", "err"); return; }
    if (!e) { out("L'effet est `autoriser` (Allow) ou `refuser` (Deny).", "err"); return; }
    if (!/^[a-z0-9-]+:[A-Za-z0-9*?]+$/i.test(act)) { out("Action au format service:Action, par exemple s3:DeleteObject (jokers permis : s3:Delete*).", "err"); return; }
    const ex = Object.keys(x.pol).find(k => k.toLowerCase() === name.toLowerCase());
    if (ex && /^(AccesAdministrateur|LectureRegistres|EcritureRegistres|SauvegardesProtegees|DevTout|Deploiement)$/i.test(ex)) { out("« " + ex + " » est une politique existante : choisis un autre nom.", "err"); return; }
    x.pol[ex || name] = [{ e, a: [act], r: [res] }];
    out(`Politique ${ex || name} créée : ${e} ${act} sur ${res}. Elle n'agit sur personne tant qu'elle n'est pas rattachée : \`attacher ${ex || name} ‹qui›\`.`, "ok");
    if (e === "Allow" && /\*/.test(act) && res === "*") out("Attention : « " + act + " sur * » est un joker très large. Le moindre privilège vise plus précis.", "err");
  }
  const pnOf = t => Object.keys(F().pol).find(k => k.toLowerCase() === (t || "").toLowerCase());
  function attachCmd(c, det) {
    if (need("habilitations", "Les rattachements se font au bureau des habilitations (est du parvis).")) return;
    const x = F(), tk = c.rawArg.split(/\s+/).filter(Boolean).filter(t => !/^(a|à|de|sur|au)$/i.test(t));
    const pn = pnOf(tk[0]), p = who(tk[1]);
    if (!pn || !p) { out(`\`${det ? "detacher" : "attacher"} ‹politique› ‹qui›\` : politiques : ${Object.keys(x.pol).join(", ")}. Identités : ${PRINC.join(", ")}.`, "err"); return; }
    const L = x.att[p] || (x.att[p] = []);
    if (det) { if (!L.includes(pn)) { out(`${pn} n'est pas rattachée à ${p}.`, "sys"); return; } x.att[p] = L.filter(n => n !== pn); out(`${pn} détachée de ${p}.`, "ok"); }
    else { if (L.includes(pn)) { out(`${pn} est déjà rattachée à ${p}.`, "sys"); return; } L.push(pn); out(`${pn} rattachée à ${p}.`, "ok"); }
    const r = ev("bob", "s3:DeleteObject", "registres-guilde/2024.csv");
    if (p === "bob") out(`Test rapide pour Bob : supprimer un registre → ${decTxt(r.dec)} ; lire un registre → ${decTxt(ev("bob", "s3:GetObject", "registres-guilde/2024.csv").dec)}.`, "sys");
    if (pn === "AccesAdministrateur" && !det) out("Une politique « Allow * sur * » est un accès administrateur total. À ne donner qu'avec une raison solide.", "err");
  }
  function rightsCmd(c) {
    if (need("habilitations", "Le registre des droits est au bureau des habilitations (est du parvis).")) return;
    const x = F(), t = c.rawArg.trim();
    if (!t) {
      out("Identités et politiques rattachées :", "sys");
      code(PRINC.map(p => `${pad(p, 12)} ${pad((x.att[p] || []).join(", ") || "(aucune)", 40)} ${granted(x.att[p] || [])}/${CAT.length} capacités`).join("\n"));
      out("`droits ‹nom›` détaille une identité ou une politique. Capacités : combinaisons action × ressource du catalogue du jeu.", "sys");
      return;
    }
    const p = who(t), pn = pnOf(t);
    if (p) { out(`Droits de ${p} : ${granted(x.att[p] || [])}/${CAT.length} capacités du catalogue.`, "sys"); code((x.att[p] || []).map(n => n + "\n" + x.pol[n].map((s, i) => `  #${i + 1} ${stxt(s)}`).join("\n")).join("\n") || "(aucune politique)"); }
    else if (pn) code(pn + "\n" + x.pol[pn].map((s, i) => `  #${i + 1} ${stxt(s)}`).join("\n"));
    else out("Inconnu : « " + t + " ». Identités : " + PRINC.join(", ") + " ; politiques : " + Object.keys(x.pol).join(", ") + ".", "err");
  }

  function elevate(p) {
    const x = F(), base = x.att[p] || [], steps = [];
    const run = (names, a, r, label) => { const e = evalWith(names, a, r, {}); steps.push({ txt: label, a, r, dec: e.dec }); return e.dec; };
    let names = base.slice();
    run(names, "s3:GetObject", "publications-guilde/index.html", "Usage normal : lire le site");
    run(names, "cloudtrail:StopLogging", "journal", "Arrêter le journal d'audit");
    const d3 = run(names, "iam:AttachUserPolicy", p, "S'attacher la politique administrateur");
    const esc = d3 === "allow";
    if (esc) {
      names = names.concat("AccesAdministrateur");
      run(names, "cloudtrail:StopLogging", "journal", "Arrêter le journal d'audit (maintenant)");
      run(names, "s3:GetObject", "sauvegardes-guilde/2025.tar", "Lire les sauvegardes (sans MFA ni IP)");
      run(names, "s3:DeleteObject", "registres-guilde/2024.csv", "Supprimer les registres");
    }
    return { p, steps, esc };
  }
  function elevCmd(c) {
    if (need("habilitations", "La simulation se joue au bureau des habilitations (est du parvis).")) return;
    const x = F(), p = who(c.rawArg.trim() || "stagiaire");
    if (!p) { out("Identité inconnue. `elever stagiaire`", "err"); return; }
    if (!(x.evDel && x.evImpl && x.condFail && x.condOk && !grpOpen("iamfix").length)) { say("Bob", "Pas si vite : Ada voudrait d'abord que tu aies fini les évaluations (refus par défaut, Deny explicite, conditions). `indice`."); return; }
    out(`Simulation (moteur jouet, conceptuelle) : Mallory a volé la clé de ${p}. Que peut-elle faire ?`, "sys");
    const r = elevate(p);
    code(r.steps.map((s, i) => `${i + 1}. ${s.a} sur ${s.r}\n   ${s.txt} → ${decTxt(s.dec)}`).join("\n"));
    if (r.esc) {
      out(`${p} possède un droit sur IAM lui-même (iam:AttachUserPolicy via un joker) : en quelques appels, il devient administrateur du compte, arrête le journal et efface les registres. Ce n'est pas un bogue : c'est le droit qui a été accordé, trop large.`, "err");
      if (p === "stagiaire") { x.elev = true; note("iam"); }
    } else {
      out(`Chemin d'élévation FERMÉ : ${p} ne peut pas modifier IAM, l'étape 3 est refusée par défaut. Mallory reste limitée aux droits (étroits) de ce compte.`, "ok");
      if (p === "stagiaire" && x.adopted) x.elev2 = true;
    }
    x.lastElev = r; fig("elevation", r);
  }
  function genPolicy(p) {
    const g = {};
    LOGS[p].forEach(([a, r]) => { const pat = r.includes("/") ? r.split("/")[0] + "/*" : r; (g[pat] = g[pat] || new Set()).add(a); });
    return Object.keys(g).map(pat => ({ e: "Allow", a: [...g[pat]].sort(), r: [pat] }));
  }
  function genCmd(c) {
    if (need("habilitations", "L'historique d'usage est au bureau des habilitations (est du parvis).")) return;
    const x = F(), p = who(c.rawArg.trim());
    if (!p) { out("`generer ‹qui›` : identités : " + PRINC.join(", ") + ". (Commence par `stagiaire`.)", "err"); return; }
    if (!x.elev) { say("Bob", "L'historique d'usage n'est pas encore prêt : Ada veut d'abord que tu aies vu pourquoi un droit trop large est dangereux (`elever stagiaire`)."); return; }
    const used = LOGS[p], st = genPolicy(p), cur = granted(x.att[p] || []);
    out(`Historique de ${p} sur 90 jours (journal d'audit) :`, "sys");
    code(used.map(([a, r, n]) => `${pad(a, 24)} ${pad(r, 36)} ${n} fois`).join("\n"));
    out("Politique minimale générée : uniquement les actions réellement utilisées, sur les ressources touchées, regroupées par motif.", "sys");
    code(st.map((s, i) => `#${i + 1} ${stxt(s)}`).join("\n"));
    const names = ["__tmp"]; const old = x.pol.__tmp; x.pol.__tmp = st; const after = granted(names); if (old) x.pol.__tmp = old; else delete x.pol.__tmp;
    out(`Droits effectifs : ${cur}/${CAT.length} capacités actuellement, ${after}/${CAT.length} avec la politique générée.`, "sys");
    out("Limites : l'historique ne dit pas les conditions voulues (MFA, IP) ni les usages rares mais légitimes (une opération de fin d'année). À relire avant d'adopter.", "sys");
    x.genFor = p;
    if (p === "stagiaire") x.gen = true;
    out("Pour la mettre en place : `adopter " + p + "`.", "sys");
  }
  function adoptCmd(c) {
    if (need("habilitations", "Les politiques s'adoptent au bureau des habilitations (est du parvis).")) return;
    const x = F(), p = who(c.rawArg.trim());
    if (!p) { out("`adopter ‹qui›` : après `generer ‹qui›`.", "err"); return; }
    if (x.genFor !== p) { out(`Génère d'abord la politique de ${p} : \`generer ${p}\`.`, "err"); return; }
    const before = granted(x.att[p] || []);
    x.pol["Genere-" + p] = genPolicy(p); x.att[p] = ["Genere-" + p];
    out(`${p} : ses anciennes politiques sont remplacées par Genere-${p}. Capacités : ${before} → ${granted(x.att[p])} sur ${CAT.length}.`, "ok");
    if (p === "alice") out("Attention : la politique générée ne contient pas les conditions MFA et IP qui protégeaient les sauvegardes : le scanner va le signaler. Un accès généré se relit et se complète.", "err");
    if (p === "stagiaire") x.adopted = true;
    note("iam");
  }

  /* ---------- facturation ---------- */
  const days = () => { const x = F(); return x.rogue === 0 && x.purged ? D14.concat(121) : D14; };
  function billCmd() {
    if (need("facturation", "Le tableau de facturation est au guichet (aux Entrepôts, puis `aller est`).")) return;
    const x = F(), d = days();
    out("Coût journalier du compte (en pièces d'or, po) :", "sys");
    code(d.map((v, i) => `j${String(i + 1).padStart(2)}  ${String(v).padStart(4)}  ${"█".repeat(Math.round(v / 10))}`).join("\n"));
    out(`Médiane : ${MED} po/jour. Les trois derniers jours montent à ${D14[11]}, ${D14[12]} et ${D14[13]} po : jusqu'à quatre fois le coût habituel. ${x.rogue === 0 && x.purged ? "Après nettoyage, le coût redevient normal." : "Personne n'a lancé de calcul. Une alarme de budget aurait dû sonner : `alerte ‹multiplicateur›`."}`, x.rogue === 0 && x.purged ? "ok" : "sys");
    x.fac0 = true;
  }
  function alertCmd(c) {
    if (need("facturation", "L'alarme est au guichet de la facturation (aux Entrepôts, puis `aller est`).")) return;
    const x = F(), m = parseFloat(c.rawArg.replace(",", ".").replace(/^x/i, ""));
    if (!isFinite(m) || m <= 0 || m > 20) { out("Donne un multiplicateur du coût habituel, par exemple `alerte 1.5` (l'alarme sonne quand un jour dépasse 1.5 × la médiane).", "err"); return; }
    const thr = m * MED, flagged = D14.map((v, i) => [i, v]).filter(([i, v]) => v > thr).map(([i]) => i + 1);
    const fp = flagged.filter(j => j <= 11), anomaly = [12, 13, 14], hit = flagged.filter(j => j > 11);
    x.alertMult = m;
    out(`Seuil : ${m} × ${MED} = ${Math.round(thr)} po/jour. Jours en alerte : ${flagged.length ? flagged.map(j => "j" + j).join(", ") : "aucun"}.`, "sys");
    if (fp.length) out(`${fp.length} FAUSSE(S) ALERTE(S) sur des jours normaux (${fp.map(j => "j" + j).join(", ")}) : à ce rythme, on débranche l'alarme au bout d'un mois. Le seuil est trop sensible.`, "err");
    else if (!hit.length) out("L'alarme ne sonne jamais : elle est trop lâche pour servir.", "err");
    else if (hit[0] > 12) { const loss = D14.slice(11, hit[0] - 1).reduce((s, v) => s + v - MED, 0); out(`Aucune fausse alerte, mais l'alarme ne sonne qu'au jour j${hit[0]} : le surcoût déjà payé avant la détection est d'environ ${Math.round(loss)} po. Un seuil plus bas préviendrait plus tôt.`, "err"); }
    else { x.alertOK = true; out("Aucune fausse alerte, et l'alarme sonne dès j12, le premier jour d'activité suspecte : bien réglé. Une alerte sur la dérive du coût est un excellent signal de compromission.", "ok"); note("facture"); }
    fig("facture", x.alertMult);
  }
  function enqCmd() {
    if (need("facturation", "L'enquête se mène au guichet de la facturation (aux Entrepôts, puis `aller est`).")) return;
    const x = F();
    if (!x.alertOK) { out("Règle d'abord l'alarme : `alerte ‹multiplicateur›`.", "sys"); return; }
    out("Ventilation du surcoût des jours j12 à j14, par service et par région :", "sys");
    code(pad("SERVICE", 12) + pad("RÉGION", 10) + pad("SURCOÛT", 14) + "DÉTAIL\n" + pad("calcul", 12) + pad("ap-sud", 10) + pad("+ " + (190 + 470 + 482 - 3 * MED + 0) + " po", 14) + `${x.rogue || 38} instances « calcul intensif », lancées en 2 h à j12, sans étiquette\n` + pad("transfert", 12) + pad("ap-sud", 10) + pad("+ 0 po", 14) + "pas de trafic web associé\n" + pad("autres", 12) + pad("(toutes)", 10) + pad("+ 0 po", 14) + "inchangé");
    out("Tout le surcoût vient d'une région que la Guilde n'utilise pas, avec des machines que personne n'a étiquetées, sans trafic web : la signature d'un minage de cryptomonnaie. Quelqu'un a lancé ces machines avec une identité valide.", "sys");
    if (!x.trail) out("Mais QUI ? La facture dit quoi et où, pas qui. Le journal d'audit est éteint : aucune trace de l'identité, de la clé, ni de l'adresse d'origine. On ne peut pas reconstituer ce qui n'a pas été enregistré. Le scanner dira pourquoi (et ce qu'il faut allumer).", "err");
    else out("Le journal d'audit est allumé depuis ta correction : il ne montre que les événements à venir, pas ceux de j12.", "sys");
    if (x.trail && x.kd) code("2026-10-05T11:03:22Z  site-web(ancienne clé)  RunInstances  198.51.100.77  ÉCHEC  clé révoquée\n2026-10-05T11:03:40Z  site-web(ancienne clé)  RunInstances  198.51.100.77  ÉCHEC  clé révoquée");
    x.enq = true;
  }
  function purgeCmd(c) {
    if (need("facturation", "La purge se lance au guichet de la facturation (aux Entrepôts, puis `aller est`).")) return;
    const x = F();
    if (!/sud/.test(norm(c.rawArg))) { out("Quelle région ? `purger ap-sud`", "err"); return; }
    if (x.rogue === 0) { out("Il n'y a déjà plus rien à supprimer en ap-sud.", "sys"); return; }
    if (!x.kd) { out(`${x.rogue} instances supprimées en ap-sud... et DEUX MINUTES PLUS TARD, ${x.rogue} nouvelles apparaissent : la clé volée (celle du site) est toujours valide, et Mallory relance tout. Supprimer les ressources sans invalider l'identité qui les crée ne sert à rien : invalide d'abord la clé (\`ranger site-web\`, au coffre des clés).`, "err"); return; }
    x.rogue = 0; x.purged = true;
    out("Les 38 instances de ap-sud sont supprimées, et la clé qui les lançait ne fonctionne plus : elles ne reviendront pas. Le coût du lendemain retombe à la normale (`facture`). En plus, on interdit les régions inutilisées par une politique de contrôle du compte.", "ok");
    if (x.trail) { out("Dans le journal d'audit, Mallory a retenté sa chance :", "sys"); code("2026-10-05T11:03:22Z  site-web(ancienne clé)  RunInstances  198.51.100.77  ÉCHEC  clé révoquée"); }
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Le Nuage de Port-443 est enfin à la bonne taille : registres privés et chiffrés, administration limitée au bastion, clés rangées ou supprimées, journal allumé, droits réduits à l'usage réel. Mallory a retenté sa chance avec la clé volée : refus, ligne dans le journal. Mais le nuage change tous les jours : un nouveau seau, un nouveau groupe, et tout est à re-scanner. L'audit n'est pas un événement, c'est une habitude.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le Nuage = un compte chez un fournisseur cloud public.** Seaux = stockage d'objets (type S3) ; groupes de sécurité = pare-feu virtuels attachés aux machines ; instances = machines virtuelles ; le parvis, les entrepôts et le coffre ne sont que des raccourcis pour t'y promener.");
    out("**Le tableau de responsabilité = le modèle de responsabilité partagée.** Le fournisseur sécurise l'infrastructure (matériel, centres de données, hyperviseur, services managés) ; le client sécurise ses données, ses identités, ses accès et la configuration de chaque service. IaaS : tu gères aussi le système et l'application ; PaaS : l'application seulement ; SaaS : surtout les accès et les données. Presque toutes les fuites cloud viennent d'une mauvaise configuration côté client.");
    out("**Le moteur d'évaluation = la logique d'IAM.** Refus par défaut ; un Deny explicite l'emporte sur tous les Allow ; les conditions (MFA, plage d'adresses) font partie de la correspondance ; les jokers élargissent vite. Les vrais moteurs ont en plus des politiques de ressource, des limites de permissions, des politiques d'organisation (SCP) et des rôles qu'on assume.");
    out("**Le scanner = un outil de posture (CSPM) ou des contrôles type CIS Benchmarks.** Il lit les configurations par les API du fournisseur. Les constats ST/RS/CP/CL/JN/IA couvrent les erreurs les plus courantes : seaux publics, administration ouverte à 0.0.0.0/0, clés anciennes ou en dur, absence de chiffrement et de journalisation.");
    out("**Le stagiaire à `iam:*` = l'élévation de privilèges.** Un droit sur IAM lui-même vaut un droit sur tout, car on peut s'attribuer d'autres droits. D'où l'importance des politiques étroites, des limites de permissions et de l'alerte sur les changements IAM. L'accès généré, qui part de l'historique d'usage, est la façon pragmatique de resserrer.");
    out("**Les métadonnées v1 et v2 = IMDS.** La v2 exige un jeton de session ; elle bloque le vol de rôle par les failles du type SSRF les plus courantes.");
    out("**La facture et l'alarme de budget = la détection de dérive de coût.** Des machines lancées dans une région inutilisée font exploser la facture, parfois avant tout autre signal. Le coût dit quoi et où ; le journal dit qui.");
    out("**Les simplifications du jeu.** (1) Un seul compte, peu de ressources, un catalogue d'actions réduit. (2) Le moteur de politiques jouet ne gère ni politiques de ressource, ni limites de permissions, ni SCP, ni rôles assumés, ni les noms de ressources réels (ARN), et seulement deux types de condition. (3) La simulation d'élévation est conceptuelle : les vrais chemins sont plus variés et dépendent du contexte. (4) Le chiffrement au repos réel passe par un service de clés, avec rotation et contrôle d'usage. (5) Les ressources étrangères ou les régions ne sont qu'esquissées. (6) Un vrai audit complète le scanner par une revue d'architecture, de la détection d'anomalies et des exercices de crise.");
    out("Rappel utile : **tout ce que tu mets dans le nuage est à toi : privé par défaut, droits au minimum, secrets hors du code, journal allumé, et un scanner qui repasse en continu.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    partage: () => {
      const x = F(), open = {};
      if (x.scan0) checks().filter(c => !c.ok).forEach(c => open[c.layer] = (open[c.layer] || 0) + 1);
      const cx = [167, 241, 315]; let b = T(386, 16, "constats", "f-b f-s");
      MODELS.forEach((m, i) => b += T(cx[i], 16, m, "f-b"));
      LAYERS.forEach(([k, n], r) => {
        const y = 28 + r * 34;
        b += T(8, y + 18, SHORT[k] || n, "f-s", "start");
        [0, 1, 2].forEach(m => { const c = MATRIX[k][m] === "c"; b += R(cx[m] - 35, y, 70, 28, c ? "f-priv" : "f-ok") + T(cx[m], y + 18, c ? "client" : "cloud", "f-s " + (c ? "ft-priv" : "ft-ok")); });
        b += T(386, y + 18, x.scan0 ? String(open[k] || 0) + " ouvert" + ((open[k] || 0) > 1 ? "s" : "") : "?", "f-s " + (x.scan0 && open[k] ? "ft-bad" : ""));
      });
      b += T(210, 252, "cloud = fournisseur. Données, identités, config : toujours client", "f-s f-b") + T(210, 270, "Le fournisseur sécurise le nuage ; toi, ce que tu y mets", "f-s");
      return { cap: "Qui est responsable de quoi selon le modèle de service. À droite, le nombre de constats ouverts du scanner pour chaque couche : presque tous dans les couches qui restent toujours à ta charge.", svg: SVG(284, "Modèle de responsabilité partagée", b) };
    },
    iam: (r) => {
      const q = r.req, shown = r.tr.slice().sort((a, b) => (b.ok ? 1 : 0) - (a.ok ? 1 : 0)).slice(0, 5);
      let b = T(8, 16, `${q.p} · ${q.act}`, "f-b f-s", "start") + T(8, 32, `sur ${q.res.length > 52 ? q.res.slice(0, 51) + "…" : q.res}`, "f-s", "start");
      const cut = s => s.length > 50 ? s.slice(0, 49) + "…" : s;
      shown.forEach((t, i) => {
        const y = 62 + i * 30, cls = t.ok ? (t.e === "Deny" ? "f-bad" : "f-ok") : "f-dash";
        b += R(8, y - 16, 404, 26, cls) + T(14, y - 1, cut(`${t.pn}#${t.i} ${t.txt}`), "f-s", "start") + T(406, y - 1, t.ok ? "✔" : "✗", "f-s " + (t.ok ? (t.e === "Deny" ? "ft-bad" : "ft-ok") : ""), "end");
      });
      let y = 62 + shown.length * 30;
      if (r.tr.length > 5) { b += T(14, y - 4, `… et ${r.tr.length - 5} autre(s) instruction(s) ne correspondant pas`, "f-s", "start"); y += 18; }
      if (!r.tr.length) { b += T(14, y, "aucune politique rattachée", "f-s", "start"); y += 22; }
      const cls = r.dec === "allow" ? "f-ok" : "f-bad", tcl = r.dec === "allow" ? "ft-ok" : "ft-bad";
      b += R(8, y, 404, 36, cls) + T(210, y + 23, decTxt(r.dec), "f-b " + tcl);
      b += T(210, y + 58, "un Deny gagne ; sinon un Allow ; sinon refus", "f-s");
      return { cap: "Évaluation d'une requête : les instructions qui correspondent sont cochées. Un Deny explicite l'emporte sur tout ; sans Allow, la requête est refusée par défaut.", svg: SVG(y + 72, "Évaluation d'une politique IAM", b) };
    },
    seau: () => {
      const x = F(), cur = x.b.registres, bef = { pub: true, list: true, enc: false };
      const col = (x0, s, t) => {
        const cl = s.pub ? "f-bad" : "f-ok";
        return R(x0, 24, 190, 112, cl) + T(x0 + 95, 44, t, "f-b f-s") + LOCK(x0 + 14, 62, cl) +
          T(x0 + 48, 74, s.pub ? "public" : "privé", "f-s " + (s.pub ? "ft-bad" : "ft-ok"), "start") +
          T(x0 + 14, 104, "listage anonyme : " + (s.list ? "oui" : "non"), "f-s " + (s.list ? "ft-bad" : "ft-ok"), "start") +
          T(x0 + 14, 124, "chiffré au repos : " + (s.enc ? "oui" : "non"), "f-s " + (s.enc ? "ft-ok" : "ft-bad"), "start") +
          R(x0 + 45, 164, 100, 24, s.pub ? "f-bad" : "f-ok") + T(x0 + 95, 180, "Internet anonyme", "f-s") +
          AR(x0 + 95, 164, x0 + 95, 138, s.pub ? "f-bad" : "f-ok f-dash") +
          T(x0 + 95, 208, s.pub ? "lit et liste tout" : "refusé (403)", "f-s f-b " + (s.pub ? "ft-bad" : "ft-ok"));
      };
      return { cap: "Le seau des registres, avant et après. À gauche : ouvert à tout Internet, listable, en clair. À droite : ton état actuel. Le chiffrement seul ne ferme pas l'accès ; c'est le blocage de l'accès public qui le fait.", svg: SVG(222, "Exposition du seau registres-guilde, avant et après", col(8, bef, "AVANT") + col(222, cur, "MAINTENANT")) };
    },
    elevation: (r) => {
      let b = T(210, 16, "Chemin d'élévation de " + r.p, "f-b");
      r.steps.forEach((s, i) => {
        const y = 28 + i * 40, ok = s.dec === "allow", cls = ok ? (i >= 3 || s.a.startsWith("iam:") ? "f-bad" : "f-ok") : "f-ok f-dash";
        b += R(8, y, 404, 32, cls) + T(14, y + 14, `${i + 1}. ${s.txt}`, "f-s f-b", "start") + T(14, y + 27, `${s.a} → ${ok ? "AUTORISÉ" : "refusé"}`, "f-s " + (ok ? (s.a.startsWith("iam:") || i >= 3 ? "ft-bad" : "ft-ok") : "ft-ok"), "start");
        if (i < r.steps.length - 1) b += AR(210, y + 32, 210, y + 40, ok ? "f-bad" : "f-ok");
      });
      const h = 28 + r.steps.length * 40;
      b += T(210, h + 14, r.esc ? "un droit sur IAM = un droit sur tout" : "chemin fermé : pas de droit sur IAM", "f-b " + (r.esc ? "ft-bad" : "ft-ok"));
      return { cap: r.esc ? "Avec iam:* (ou une action IAM équivalente), un compte quelconque se donne l'accès administrateur : il arrête le journal, lit les sauvegardes et supprime les registres." : "Le même scénario avec les droits réduits : l'étape 3 est refusée par défaut, la chaîne s'arrête.", svg: SVG(h + 28, "Chemin d'élévation de privilèges", b) };
    },
    facture: (m) => {
      const x = F(), d = days(), thr = m ? m * MED : null, base = 176, sc = 130 / 500;
      let b = T(8, 14, "coût par jour (po)", "f-s", "start");
      d.forEach((v, i) => { const h = Math.max(2, v * sc), cls = i === 14 ? "f-ok" : v > 1.5 * MED ? "f-bad" : "f-pub"; b += R(14 + i * 26, base - h, 20, h, cls) + T(24 + i * 26, base + 14, "j" + (i + 1), "f-s"); });
      if (thr) { const y = base - thr * sc; b += LN(8, y, 412, y, "f-bad f-dash") + T(8, y - 4, "seuil " + Math.round(thr), "f-s ft-bad", "start"); }
      b += T(210, base + 38, thr ? "rouge : jours au-dessus du seuil" : "règle une alarme pour voir le seuil", "f-s");
      return { cap: "Coût journalier du compte. Les trois derniers jours (rouge) sont ceux d'un abus. Le seuil d'alerte (pointillé) se règle avec la commande alerte : trop bas, il sonne pour rien ; trop haut, il sonne tard.", svg: SVG(base + 50, "Coût journalier et seuil d'alerte", b) };
    },
  };

  GAMES.cloud = {
    id: "cloud", order: 24, title: "Le Nuage de Port-443", pageTitle: "Cloud Quest", subtitle: "aventure textuelle · cloud, IAM, responsabilité partagée",
    blurb: "Audite et corrige le compte cloud de la Guilde : seaux publics, groupes de sécurité ouverts, clés oubliées, droits IAM trop larges.",
    concept: "Mauvaises configurations du cloud, IAM, responsabilité partagée",
    start: "parvis", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      x.q = 0; x.miss = 0;
      x.b = { registres: { pub: true, list: true, enc: false }, sauvegardes: { pub: false, list: false, enc: false }, publications: { pub: true, list: true, enc: true }, journaux: { pub: false, list: false, enc: true } };
      x.sg = { web: { port: 443, cidr: "0.0.0.0/0" }, admin: { port: 22, cidr: "0.0.0.0/0" }, base: { port: 3306, cidr: "0.0.0.0/0" } };
      x.ins = { "web-1": { pub: true, v2: false }, "base-1": { pub: true, v2: true } };
      x.k = { "deploy-bot": { age: 412, hard: false, rot: 0 }, "site-web": { age: 35, hard: true, rot: 0 }, racine: { age: 600, hard: false, rot: 0, root: true, gone: false } };
      x.kd = false; x.trail = false; x.rogue = 38;
      x.pol = {
        LectureRegistres: [{ e: "Allow", a: ["s3:GetObject", "s3:ListBucket"], r: ["registres-guilde", "registres-guilde/*"] }],
        EcritureRegistres: [{ e: "Allow", a: ["s3:*"], r: ["registres-guilde", "registres-guilde/*"] }],
        SauvegardesProtegees: [{ e: "Allow", a: ["s3:GetObject"], r: ["sauvegardes-guilde/*"], c: [["Bool", "aws:MultiFactorAuthPresent", "true"], ["IpAddress", "aws:SourceIp", "10.0.0.0/16"]] }],
        DevTout: [{ e: "Allow", a: ["s3:*", "ec2:*", "iam:*"], r: ["*"] }],
        Deploiement: [{ e: "Allow", a: ["s3:PutObject"], r: ["publications-guilde/*"] }, { e: "Allow", a: ["ec2:DescribeInstances"], r: ["*"] }],
        AccesAdministrateur: [{ e: "Allow", a: ["*"], r: ["*"] }],
      };
      x.att = { alice: ["LectureRegistres", "SauvegardesProtegees"], bob: ["LectureRegistres", "EcritureRegistres"], "deploy-bot": ["Deploiement"], stagiaire: ["DevTout"] };
    },
    refig(name) {
      const x = F();
      if (name === "iam") fig("iam", x.lastEval || ev("bob", "s3:GetObject", "registres-guilde/2024.csv"));
      else if (name === "elevation") fig("elevation", x.lastElev || elevate("stagiaire"));
      else if (name === "facture") fig("facture", x.alertMult);
      else fig(name);
    },
    figAlias: { partage: ["responsabilite", "modele"], iam: ["politique", "evaluation", "droits"], seau: ["stockage", "bucket"], elevation: ["escalade", "privileges", "privilege"], facture: ["facturation", "alerte", "budget"] },
    say(text, ctx) {
      const x = F();
      if (!x.quest || x.q >= QS.length) { out(ctx.rest.length ? "Personne ne réagit." : "Dire quoi ?", "sys"); return; }
      if (S.room !== "parvis") { out("Maître Ada attend ta réponse sur le parvis.", "sys"); return; }
      const t = ctx.rest;
      answer(t.includes("client") ? "client" : t.includes("fournisseur") || t.includes("provider") ? "fournisseur" : t.includes("partage") || t.includes("deux") ? "partage" : "");
    },
    help: "Spécifiques : `scanner` · `bloquer`/`ouvrir`/`chiffrer ‹seau›` · `desactiver listage ‹seau›` · `restreindre ‹groupe› ‹port› ‹CIDR›` · `isoler`/`exiger jetons`/`metadonnees ‹instance›` · `renouveler`/`ranger`/`revoquer ‹clé›` · `journaliser` · `droits` · `evaluer ‹qui› ‹action› ‹ressource›` · `politique` · `attacher`/`detacher` · `elever` · `generer`/`adopter ‹qui›` · `facture` · `alerte ‹x›` · `enqueter` · `purger ap-sud`",
    verbs: {
      scan: { words: ["scanner", "scan", "auditer"], run: scanCmd },
      block: { words: ["bloquer"], run: blockCmd },
      open: { words: ["ouvrir", "publier"], run: openCmd },
      off: { words: ["desactiver", "couper"], run: offCmd },
      enc: { words: ["chiffrer"], run: encCmd },
      restrict: { words: ["restreindre", "limiter"], run: restrictCmd },
      isolate: { words: ["isoler"], run: isolateCmd },
      imds: { words: ["metadonnees", "imds", "sonder"], run: imdsCmd },
      require: { words: ["exiger", "imposer"], run: requireCmd },
      rotate: { words: ["renouveler", "tourner"], run: rotateCmd },
      vault: { words: ["ranger", "stocker"], run: vaultCmd },
      revoke: { words: ["revoquer", "supprimer"], run: revokeCmd },
      trail: { words: ["journaliser", "tracer"], run: trailCmd },
      rights: { words: ["droits", "habilitations"], run: rightsCmd },
      evalr: { words: ["evaluer", "tester"], run: evalCmd },
      pol: { words: ["politique", "creer"], run: polCmd },
      attach: { words: ["attacher", "rattacher"], run: c => attachCmd(c, false) },
      detach: { words: ["detacher"], run: c => attachCmd(c, true) },
      elev: { words: ["elever", "escalader"], run: elevCmd },
      gen: { words: ["generer", "proposer"], run: genCmd },
      adopt: { words: ["adopter"], run: adoptCmd },
      bill: { words: ["facture", "facturer", "couts"], run: billCmd },
      alert: { words: ["alerte", "alarme", "budget"], run: alertCmd },
      enq: { words: ["enqueter", "enquete"], run: enqCmd },
      purge: { words: ["purger", "nettoyer"], run: purgeCmd },
    },
    intro() {
      out("Le Nuage de Port-443", "title");
      out("La Guilde a vidé ses armoires pour déménager ses registres dans « le Nuage », un entrepôt géant que gère un fournisseur lointain. Plus de serrures à tourner : des seaux, des groupes de sécurité, des clés d'accès, des politiques de droits. Hier, la facture a été multipliée par quatre. Maître Ada t'a confié, avec mandat écrit, l'audit du compte et sa correction. Tout est simulé, sur des données fictives.", "");
    },
  };
})();
