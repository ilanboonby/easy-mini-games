"use strict";
/* Les Entrepôts Cloisonnés : conteneurs, isolation, images en couches, durcissement.
   Tout est un modèle jouet : noyau partagé, couches sha256 (réel), scanner contre une base fictive,
   digests (SHA-256 réel), politique réseau, droits minimaux, auditeur automatique. Aucune évasion réelle. */
(function () {
  const F = () => f();

  /* ================= Données du modèle jouet ================= */
  const INIT_CFG = { user: "root", ro: false, caps: ["chown", "dac_override", "fowner", "kill", "net_bind_service", "setuid", "setgid", "net_raw", "sys_chroot", "sys_admin", "net_admin", "sys_ptrace"], seccomp: "aucun", priv: true, socket: true, hmount: true, hostns: true, mem: null };
  const DANGER_CAPS = ["sys_admin", "net_admin", "sys_ptrace", "sys_module", "dac_read_search", "dac_override", "net_raw", "sys_rawio", "sys_boot"];
  const CAP_LIST = ["chown", "dac_override", "fowner", "kill", "net_bind_service", "setuid", "setgid", "net_raw", "sys_chroot", "sys_admin", "net_admin", "sys_ptrace", "sys_module", "dac_read_search"];
  const SECRET_FILE = "CLE_PAIEMENT=sk-demo-7f3a91c2e5\nMDP_BASE=hunter2-demo";
  const GUILD_KEY = "cle-privee-de-la-guilde (jouet)";
  const HOST_MEM = 1000, OTHERS_MEM = 500, BASE_USE = 100, LEAK_STEP = 150;
  const SERVICES = ["vitrine", "billets", "base", "paiement"];
  const REQ_FLOWS = ["vitrine>billets", "billets>base", "billets>paiement"];
  const REQ_RIGHTS = ["configmaps:lire", "secret-db-mdp:lire"];
  const ALL_RIGHTS = ["configmaps:lire", "secret-db-mdp:lire", "secrets:lire", "pods:creer", "nodes:lire", "*:*"];

  const BASES = {
    complet: { mb: 124, pkgs: { tlsmini: "1.1.1", zipette: "1.5.1", curlet: "7.68.0", bashette: "5.0.0", "libc-jouet": "2.31.0" }, txt: "système complet : shell, outils réseau, bibliothèques" },
    slim: { mb: 74, pkgs: { tlsmini: "1.1.1", zipette: "1.5.1", bashette: "5.0.0", "libc-jouet": "2.31.0" }, txt: "allégée : un shell et quelques bibliothèques" },
    minimale: { mb: 18, pkgs: { tlsmini: "1.1.1", "libc-jouet": "2.36.0" }, txt: "minimale : seulement ce que l'application exécute (ni shell, ni outils)" },
  };
  const REPO = { tlsmini: "1.1.3", zipette: "1.5.3", curlet: "7.88.0", bashette: "5.2.0", "libc-jouet": "2.36.0" };
  const VULNS = [
    { id: "PV-2026-0101", pkg: "tlsmini", below: "1.1.3", sev: "CRITIQUE", txt: "vérification de certificat incomplète (fictif)" },
    { id: "PV-2026-0102", pkg: "zipette", below: "1.5.3", sev: "HAUTE", txt: "archive piégée mal contrôlée (fictif)" },
    { id: "PV-2026-0103", pkg: "curlet", below: "7.79.0", sev: "MOYENNE", txt: "redirection vers un hôte imprévu (fictif)" },
    { id: "PV-2026-0104", pkg: "bashette", below: "5.2.1", sev: "HAUTE", txt: "variables d'environnement mal filtrées ; aucun correctif publié (fictif)", nofix: true },
    { id: "PV-2026-0105", pkg: "libc-jouet", below: "2.35.0", sev: "MOYENNE", txt: "fuite d'information du résolveur (fictif)" },
  ];
  const cmpv = (a, b) => { const p = a.split(".").map(Number), q = b.split(".").map(Number); for (let i = 0; i < 3; i++) { const d = (p[i] || 0) - (q[i] || 0); if (d) return d; } return 0; };

  const M0 = "billets|1.0|jour0|tlsmini 1.1.1;libc-jouet 2.36.0;billets-app 1.0";
  const M1 = "billets|1.0|jour1|tlsmini 1.1.1;libc-jouet 2.36.0;billets-app 1.0;minerai-bz 0.1";
  const UP0 = sha256(M0), UP1 = sha256(M1);
  const MANIF = { [UP0]: M0, [UP1]: M1 };
  const short = (d, n) => d.slice(0, n || 12) + "…";

  /* ================= Fonctions de simulation ================= */
  function pkgs() {
    const x = F(), b = BASES[x.base], o = {};
    for (const k in b.pkgs) o[k] = x.updated ? REPO[k] : b.pkgs[k];
    return o;
  }
  const vulns = () => { const P = pkgs(); return VULNS.filter(v => P[v.pkg] && cmpv(P[v.pkg], v.below) < 0); };

  function layersFor() {
    const x = F(), B = BASES[x.base], P = pkgs();
    const plist = Object.entries(P).map(([k, v]) => k + " " + v).join("\n");
    const L = [{ ins: "FROM debian-" + x.base, files: [{ p: "/var/lib/paquets", c: plist }], mb: B.mb }];
    if (x.build === "simple") {
      L.push({ ins: "COPY .env /app/.env", files: [{ p: "/app/.env", c: SECRET_FILE }], mb: 1 });
      L.push({ ins: "COPY . /app", files: [{ p: "/app/billets-app", c: "(binaire jouet)" }, { p: "/app/config.json", c: "{\"port\":8080}" }], mb: 12 });
      L.push({ ins: "RUN rm /app/.env", files: [{ p: "/app/.env", del: true }], mb: 0 });
    } else {
      L.push({ ins: "COPY --from=build /out/billets-app /app/billets-app", files: [{ p: "/app/billets-app", c: "(binaire jouet)" }, { p: "/app/config.json", c: "{\"port\":8080}" }], mb: 12 });
      L.push({ ins: "USER 10001", files: [], mb: 0 });
    }
    let prev = "";
    L.forEach(l => { l.id = sha256(prev + "|" + l.ins + "|" + JSON.stringify(l.files)); prev = l.id; });
    return L;
  }
  function merged(L) {
    const m = {};
    L.forEach(l => l.files.forEach(fl => { if (fl.del) delete m[fl.p]; else m[fl.p] = fl.c; }));
    return m;
  }
  const imgDigest = () => sha256("billets|" + layersFor().map(l => l.id).join(","));
  function secretHits() {
    const hits = [], L = layersFor(), fin = merged(L);
    L.forEach((l, i) => l.files.forEach(fl => {
      if (fl.del) return;
      const re = /(CLE|MDP|SECRET|TOKEN|PASS|KEY)[A-Z_]*\s*=\s*(\S+)/g; let m;
      while ((m = re.exec(fl.c))) hits.push({ i, p: fl.p, k: m[0].split("=")[0], v: m[2], hidden: !(fl.p in fin) });
    }));
    return hits;
  }
  const sigValid = () => { const x = F(); return !!(x.sig && x.sig.digest === imgDigest() && x.sig.v === sha256(GUILD_KEY + "|" + x.sig.digest)); };
  const polOk = () => { const p = F().pol; return !!(p.priv && p.digest && p.sig); };
  const deployValid = () => { const x = F(); return !!(x.deployOk && x.deployDigest === imgDigest() && polOk() && sigValid()); };

  const memOk = () => { const m = F().cfg.mem; return m !== null && m >= 128 && m <= 350; };
  function runtimeChecks() {
    const c = F().cfg, capsBad = c.caps.some(k => k !== "net_bind_service");
    return [
      { id: "priv", label: "pas de mode privilégié", pts: 9, ok: !c.priv },
      { id: "user", label: "utilisateur non privilégié", pts: 9, ok: c.user !== "root" },
      { id: "socket", label: "socket du moteur non monté", pts: 8, ok: !c.socket },
      { id: "hmount", label: "pas de répertoire hôte monté", pts: 4, ok: !c.hmount },
      { id: "hostns", label: "espaces de noms propres", pts: 4, ok: !c.hostns },
      { id: "ro", label: "système de fichiers en lecture seule", pts: 7, ok: c.ro },
      { id: "caps", label: "capacités du noyau réduites", pts: 7, ok: !c.priv && !capsBad },
      { id: "seccomp", label: "profil d'appels système (seccomp)", pts: 7, ok: !c.priv && c.seccomp !== "aucun", got: c.priv ? 0 : c.seccomp === "restreint" ? 7 : c.seccomp === "defaut" ? 5 : 0 },
      { id: "mem", label: "limite de mémoire (cgroup)", pts: 3, ok: memOk() },
    ];
  }
  const runtimeOk = () => runtimeChecks().every(k => k.ok);
  const FIXCMD = { priv: "corriger privilege", user: "corriger utilisateur", socket: "corriger socket", hmount: "corriger montages", hostns: "corriger espaces", ro: "corriger lecture-seule", caps: "corriger capacites aucune", seccomp: "corriger seccomp restreint", mem: "limiter appli memoire 256" };

  function netAllowed(a, b) { const n = F().net; return n.def === "allow" || n.rules.includes(a + ">" + b); }
  const netOk = () => { const n = F().net; return n.def === "deny" && n.rules.length === REQ_FLOWS.length && REQ_FLOWS.every(r => n.rules.includes(r)); };
  const rightsOfBilling = () => { const o = F().orch; return o.bound ? o.acct.billets : o.acct.default; };
  const rightsOk = () => { const o = F().orch; if (!o.bound) return false; const r = o.acct.billets; return r.length === REQ_RIGHTS.length && REQ_RIGHTS.every(k => r.includes(k)); };
  const orchOk = () => F().orch.secretMounted && rightsOk();
  const imgClean = () => vulns().length === 0;
  const layersClean = () => secretHits().length === 0;

  function auditItems() {
    const x = F();
    const it = runtimeChecks().map(k => ({ cat: "exécution", label: k.label, pts: k.pts, got: k.got !== undefined ? k.got : (k.ok ? k.pts : 0) }));
    const add = (cat, label, pts, ok) => it.push({ cat, label, pts, got: ok ? pts : 0 });
    add("image", "aucun secret dans les couches", 8, layersClean());
    add("image", "aucune vulnérabilité connue", 8, imgClean());
    add("image", "déployée par digest (étiquette refusée)", 4, deployValid());
    add("image", "signée, registre privé exigé", 4, deployValid() && polOk());
    add("réseau", "refus par défaut entre services", 5, x.net.def === "deny");
    add("réseau", "seulement les flux nécessaires", 5, netOk());
    add("orchestrateur", "secret monté (pas en variable d'environnement)", 4, x.orch.secretMounted);
    add("orchestrateur", "compte de service aux droits minimaux", 4, rightsOk());
    return it;
  }
  const score = () => auditItems().reduce((s, k) => s + k.got, 0);

  /* ================= Notes ================= */
  const notes = {
    vm: ["Un conteneur n'est pas une machine virtuelle", "Une VM embarque son propre noyau, émulé au-dessus d'un hyperviseur : isolation forte, mais lourde. Un conteneur est un simple processus de l'hôte que le noyau emballe : il PARTAGE le noyau de l'hôte. C'est léger et rapide, mais une faille du noyau ou une mauvaise configuration touche tout le monde. D'où l'importance de durcir."],
    ns: ["Espaces de noms et cgroups", "Les espaces de noms (namespaces) limitent ce qu'un processus VOIT : processus (PID), réseau, montages, utilisateurs, nom d'hôte. Les cgroups limitent ce qu'il CONSOMMAT : mémoire, processeur, nombre de processus. Un conteneur sans limite peut affamer ses voisins ; avec une limite, seul le fautif est arrêté."],
    couches: ["Couches d'image et secrets", "Une image est une pile de couches, chacune identifiée par l'empreinte SHA-256 de son contenu. Supprimer un fichier dans une couche suivante ne l'enlève pas des couches précédentes : il reste récupérable par quiconque télécharge l'image. Solutions : ne jamais copier de secret dans une image ; construction en plusieurs étapes ; secrets de construction montés temporairement ; et révoquer tout secret déjà publié."],
    user: ["Utilisateur non privilégié, lecture seule", "Par défaut, beaucoup de conteneurs tournent en administrateur (root), et sans espace de noms utilisateur, ce root est le root de l'hôte. Exécute l'application avec un utilisateur banal (uid 10001) et monte le système de fichiers en lecture seule (avec un petit espace temporaire pour /tmp) : un intrus ne peut ni installer d'outils ni modifier l'application."],
    caps: ["Capacités du noyau et seccomp", "Le noyau découpe les pouvoirs de root en capacités (net_bind_service, sys_admin, net_admin, sys_ptrace…). Retire-les toutes et ne rends que le strict nécessaire. Le profil seccomp filtre les appels système que le processus a le droit de faire : un profil restreint refuse mount, ptrace, reboot, chargement de modules… Dans un conteneur privilégié, ces protections sont désactivées."],
    montages: ["Montages et mode privilégié dangereux", "Trois erreurs classiques : le mode privilégié (accès à presque tout l'hôte), le socket du moteur de conteneurs monté dans un conteneur (qui peut alors demander au moteur de lancer ce qu'il veut : c'est équivalent à être root sur l'hôte), et le montage de répertoires de l'hôte en écriture. Remplace-les par des volumes nommés, ou, si inévitable, des montages précis en lecture seule."],
    images: ["Images vulnérables et bases minimales", "Un scanner compare les versions des paquets de l'image à une base de vulnérabilités connues. Mettre à jour corrige beaucoup, mais pas tout (un correctif peut ne pas exister). Le meilleur remède est de ne pas embarquer ce dont on n'a pas besoin : une image de base minimale a moins de paquets, donc moins de failles et un scan plus court. Re-scanne régulièrement : de nouvelles failles sont publiées chaque jour."],
    chaine: ["Digest, signatures, registre privé", "Une étiquette (latest, 1.0) est mouvante : celui qui contrôle le registre peut la faire pointer vers autre chose. Le digest est l'empreinte SHA-256 du manifeste : épingler par digest garantit un contenu identique, vérifiable. Une signature prouve qui a publié l'image ; un registre privé et une politique d'admission refusent le reste. La signature atteste l'origine, pas l'absence de défauts."],
    reseau: ["Réseau fermé, secrets, droits minimaux", "Par défaut, tous les conteneurs d'un même réseau peuvent se parler : une vitrine compromise atteint la base et le paiement. Refuse par défaut et n'autorise que les flux nécessaires. Côté orchestrateur : un secret se monte comme un fichier (pas en variable d'environnement visible partout) et chaque application a son compte de service avec les droits minimaux, jamais un compte tout-puissant."],
  };

  /* ================= Entités et lieux ================= */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle tient une tablette d'audit et un air de bibliothécaire qui range les entrepôts au cordeau." },
    bob: { npc: true, names: ["bob", "developpeur"], label: "Bob", desc: () => "Bob, développeur de la billetterie. Il a écrit la configuration de l'entrepôt « billets » en 2 minutes, un vendredi soir." },
    alice: { npc: true, names: ["alice", "douaniere"], label: "Alice la douanière", desc: () => "Alice, qui tient la douane aux scellés : tout ce qui entre dans les entrepôts passe par elle." },
    tablette: { take: true, names: ["tablette", "auditeur", "audit"], label: "la tablette d'audit", desc: () => "Ta tablette d'audit : `auditer` note la configuration de la billetterie sur 100. `scenario` montre ce que Mallory atteindrait. Elles marchent dans tous les lieux." },
    enseigne: { names: ["enseigne", "panneau", "entrepots"], label: "l'enseigne des entrepôts", desc: () => "« ENTREPÔTS CLOISONNÉS DE PORT-443. Chaque application dans son entrepôt, chaque entrepôt dans ses murs. » Les murs, c'est l'objet de l'audit." },
    observatoire: { names: ["observatoire", "lunette", "hublot"], label: "l'observatoire du noyau", vis: () => S.room === "noyau",
      desc: () => "Un observatoire à deux hublots : `sonder appli` (ce que voit le processus DANS son entrepôt), `sonder base` (le voisin) et `sonder hote` (la vue du gardien du noyau). Une balance mesure la mémoire." },
    balance: { names: ["balance", "cgroup", "cgroups"], label: "la balance des ressources", vis: () => S.room === "noyau",
      desc: () => { const m = F().cfg.mem; return `La balance des cgroups. Hôte : ${HOST_MEM} Mo de mémoire dont ${OTHERS_MEM} déjà utilisés par les voisins. Limite actuelle de « billets » : ${m === null ? "aucune" : m + " Mo"}.\n\`fuite appli\` simule un programme qui consomme de plus en plus de mémoire. \`limiter appli memoire ‹Mo›\` pose une limite.`; } },
    pile: { names: ["pile", "couches", "image", "etabli"], label: "la pile de couches", vis: () => S.room === "atelier",
      desc: () => "L'établi où l'image « billets » est empilée couche par couche. `couches` liste les couches, `extraire ‹n›` ouvre l'une d'elles, `extraire fusion` montre ce que voit le conteneur, `fouiller` cherche les secrets, `construire ‹simple|multi›` refait l'image." },
    config: { names: ["config", "configuration", "fiche", "billets"], label: "la fiche de configuration de « billets »", vis: () => S.room === "entrepot",
      desc: () => cfgText() },
    scanner: { names: ["scanner", "detecteur"], label: "le scanner de vulnérabilités", vis: () => S.room === "douane",
      desc: () => "Un scanner à cuivre : `scanner` compare les paquets de l'image à la base des vulnérabilités (fictive). `base ‹complet|slim|minimale›` change l'image de base, `maj` met les paquets à jour." },
    registre: { names: ["registre", "etagere", "etagere des images"], label: "le registre des images", vis: () => S.room === "douane",
      desc: () => { const x = F(); return `Deux étagères : « bazar » (registre public, tout le monde y dépose) et « guilde » (registre privé).\n\`tirer ‹registre/billets:etiquette›\` ou \`tirer ‹registre/billets@sha256:…›\` ; \`attendre\` fait passer une nuit ; \`signer billets\` signe et publie l'image à la guilde ; \`exiger signature|digest|registre\` règle la douane.\nJour ${x.day}. Exigences : registre privé ${x.pol.priv ? "OUI" : "non"}, digest ${x.pol.digest ? "OUI" : "non"}, signature ${x.pol.sig ? "OUI" : "non"}.`; } },
    tableau: { names: ["tableau", "politique", "carrefour"], label: "le tableau des passerelles", vis: () => S.room === "orchestre",
      desc: () => "Le tableau des passerelles entre services (vitrine, billets, base, paiement). `politique` l'affiche, `politique defaut refuser|autoriser`, `politique autoriser ‹a› ‹b›`, `politique retirer ‹a› ‹b›`. `tester` joue les flux réels de la billetterie." },
    coffre: { names: ["coffre", "secrets", "comptes"], label: "le coffre et le registre des comptes", vis: () => S.room === "orchestre",
      desc: () => { const o = F().orch; return `Coffre de l'orchestrateur.\nMot de passe de la base : ${o.secretMounted ? "monté comme fichier /run/secrets/db-mdp (en mémoire, lecture seule)" : "en variable d'environnement DB_PASS (visible dans la description du conteneur et dans les journaux)"}.\nCompte « default » : ${o.acct.default.join(", ")}.\nCompte « billets » : ${o.acct.billets ? (o.acct.billets.join(", ") || "créé, sans droits") : "inexistant"} ; ${o.bound ? "lié à l'application" : "non lié (l'application utilise « default »)"}.\n\`secret monter db-mdp\` · \`compte creer billets\` · \`droit ajouter ‹ressource:verbe›\` · \`droit retirer ‹…›\` · \`compte lier billets\`\nDroits possibles : ${ALL_RIGHTS.join(", ")}`; } },
  };

  function cfgText() {
    const c = F().cfg, o = F().orch;
    const mem = c.mem === null ? "aucune limite" : c.mem + " Mo";
    return `Fiche de l'entrepôt « billets » (image billets, étiquette latest) :
  utilisateur        : ${c.user === "root" ? "root (administrateur)" : "10001 (non privilégié)"}
  privilégié         : ${c.priv ? "OUI" : "non"}
  système de fichiers: ${c.ro ? "lecture seule (+ tmpfs sur /tmp)" : "lecture-écriture"}
  capacités          : ${c.caps.length ? c.caps.join(", ") : "aucune"}
  seccomp            : ${c.seccomp === "aucun" ? "aucun (unconfined)" : c.seccomp}
  PID + réseau       : ${c.hostns ? "ceux de l'hôte (partagés)" : "propres au conteneur"}
  montages           : ${c.socket ? "/var/run/moteur.sock (rw) ; " : ""}${c.hmount ? "/etc de l'hôte -> /hote/etc (rw) ; " : ""}volume ${c.hmount ? "/srv/billets/donnees" : "nommé « donnees »"} -> /donnees
  mémoire (cgroup)   : ${mem}
  variables          : ${o.secretMounted ? "(aucun secret)" : "DB_PASS=hunter2-demo"}
Corrections : \`corriger privilege|utilisateur|lecture-seule|capacites ‹liste ou aucune›|seccomp ‹defaut|restreint›|socket|montages|espaces\`.`;
  }

  const rooms = {
    quai: { name: "Le quai des Entrepôts", short: "Quai", alias: ["quai"], ents: ["ada", "enseigne"], exits: { nord: "noyau", est: "atelier", sud: "entrepot", ouest: "douane", haut: "orchestre" },
      desc: () => "Un quai de pierre où s'alignent de grands entrepôts aux murs lisses. La Guilde y range ses applications : chacune dans son entrepôt, sans voir celui d'à côté… du moins en théorie. Au nord, la salle du noyau commun. À l'est, l'atelier des couches. Au sud, l'entrepôt de la billetterie. À l'ouest, la douane aux scellés. En haut, le poste de l'orchestrateur." },
    noyau: { name: "La salle du noyau commun", short: "Noyau", alias: ["noyau", "salle du noyau"], ents: ["observatoire", "balance"], exits: { sud: "quai" },
      desc: () => "Une salle ronde dont une immense colonne centrale (le noyau) traverse tous les étages : tous les entrepôts s'y adossent. Des cloisons peintes de couleurs différentes montrent ce que chacun peut voir de l'autre." },
    atelier: { name: "L'atelier des couches", short: "Atelier", alias: ["atelier", "couches"], ents: ["pile"], exits: { ouest: "quai" },
      desc: () => "Un atelier où chaque image est fabriquée en posant des couches de papier calque, une par une. Chaque calque porte un cachet : l'empreinte SHA-256 de son contenu. Rien ne s'efface : on ne peut que poser un calque par-dessus." },
    entrepot: { name: "L'entrepôt de la billetterie", short: "Entrepôt", alias: ["entrepot", "billetterie"], ents: ["bob", "config"], exits: { nord: "quai" },
      desc: () => "L'entrepôt « billets », celui qui vend les tickets du festival de Port-443. Ses portes sont grandes ouvertes, un câble relie directement l'intérieur à la salle des machines, et un trousseau de clés pend à la porte. Sur un chevalet : la fiche de configuration." },
    douane: { name: "La douane aux scellés", short: "Douane", alias: ["douane"], ents: ["alice", "scanner", "registre"], exits: { est: "quai" },
      desc: () => "Alice y inspecte toutes les images qui entrent : un scanner à cuivre, des étagères de registre, des cachets et des scellés de cire. Rien n'entre sans papiers." },
    orchestre: { name: "Le poste de l'orchestrateur", short: "Orchestrateur", alias: ["orchestre", "orchestrateur", "poste"], ents: ["tableau", "coffre"], exits: { bas: "quai" },
      desc: () => "Une passerelle surplombant les entrepôts. L'orchestrateur y décide qui parle à qui, qui peut ouvrir quoi, et où sont rangés les secrets. Un tableau de passerelles et un coffre." },
  };

  /* ================= Objectifs et indices ================= */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.audited) return "audit0";
    if (!(x.vApp && x.vHost)) return "sonder";
    if (!x.leaked) return "leak";
    if (!memOk()) return "mem";
    if (!x.contained) return "contain";
    if (!x.secFound) return "couches";
    if (x.build !== "multi") return "multi";
    if (!x.cleanLayers) return "clean";
    if (!x.revoked) return "revoke";
    if (!x.scen) return "scen";
    if (!runtimeOk()) return "fix";
    if (!x.scanned) return "scan";
    if (!imgClean()) return "base";
    if (!x.drift) return "drift";
    if (!x.pinned) return "pin";
    if (!sigValid()) return "sign";
    if (!polOk()) return "pol";
    if (!deployValid()) return "deploy";
    if (!netOk()) return "net";
    if (!orchOk()) return "orch";
    if (!x.tested) return "tested";
    if (!x.finalAudit) return "audit2";
    if (!x.end) return "end";
    return "fin";
  };
  const nextFix = () => { const k = runtimeChecks().find(c => !c.ok); return k ? FIXCMD[k.id] : "auditer"; };
  const hints = {
    quest: () => ["Maître Ada t'attend sur le quai.", "`parler ada`"],
    audit0: () => ["Ta tablette note la configuration actuelle. Regarde de quoi on part.", "`auditer`"],
    sonder: () => ["Va à la salle du noyau (nord) et regarde l'entrepôt de deux points de vue : de l'intérieur et depuis l'hôte.", "`aller nord`, `sonder appli`, `sonder hote`."],
    leak: () => ["Dans la salle du noyau, la balance simule une application qui fuit de la mémoire. Regarde ce que ça fait aux voisins quand rien ne la limite.", "`fuite appli`"],
    mem: () => ["Pose un plafond de mémoire (cgroup) sur « billets » : assez pour tourner (au moins 128 Mo), assez bas pour ne pas gêner l'hôte (pas plus de 350 Mo).", "`limiter appli memoire 256`"],
    contain: () => ["Rejoue la fuite et compare.", "`fuite appli`"],
    couches: () => ["À l'atelier (est du quai), examine les couches de l'image. Un fichier supprimé est-il vraiment parti ?", "Depuis le quai : `aller est`, puis `couches`, `extraire 1` ou `fouiller`."],
    multi: () => ["Reconstruis l'image en plusieurs étapes pour que le secret n'entre jamais dans une couche.", "`construire multi`"],
    clean: () => ["Revérifie toutes les couches de la nouvelle image.", "`fouiller`"],
    revoke: () => ["La clé a été publiée dans l'ancienne image : elle est à considérer comme compromise.", "`revoquer cle`"],
    scen: () => ["Va à l'entrepôt (sud du quai) et simule ce que Mallory atteindrait si l'application était compromise.", "`aller ouest` puis `aller sud` (depuis l'atelier), puis `scenario`."],
    fix: () => ["Lis la fiche de configuration (`examiner config` à l'entrepôt) et corrige les réglages dangereux, un par un. `auditer` dit ce qui reste.", "Prochaine correction : `" + nextFix() + "` (à l'entrepôt ; la limite de mémoire se règle au noyau)."],
    scan: () => ["À la douane (ouest du quai), lance le scanner sur l'image.", "`scanner`"],
    base: () => ["Des vulnérabilités subsistent. Mets à jour, et surtout choisis une base qui n'embarque que le nécessaire. Puis rescanne.", "`maj`, `base minimale`, `scanner`"],
    drift: () => ["Tire l'image publique par son étiquette, laisse passer une nuit, et tire-la de nouveau.", "`tirer bazar/billets:latest`, `attendre`, `tirer bazar/billets:latest`"],
    pin: () => ["Tire l'image publique non par son étiquette mais par son digest (copie le digest affiché, au moins 8 caractères suffisent).", "`tirer bazar/billets@sha256:‹digest›`"],
    sign: () => ["Signe et publie ta propre image (celle que tu as durcie) au registre privé de la Guilde.", "`signer billets`"],
    pol: () => ["Règle la douane pour que seules les images du registre privé, par digest, et signées entrent.", "`exiger registre`, `exiger digest`, `exiger signature`"],
    deploy: () => ["Déploie ton image signée en la tirant depuis la guilde par son digest (celui de `signer billets`).", "`tirer guilde/billets@sha256:‹digest›`"],
    net: () => ["Au poste de l'orchestrateur (haut), ferme le réseau par défaut et n'ouvre que les flux nécessaires : vitrine→billets, billets→base, billets→paiement.", "`aller haut`, `politique defaut refuser`, `politique autoriser vitrine billets`, `politique autoriser billets base`, `politique autoriser billets paiement`"],
    orch: () => ["Monte le mot de passe en secret, crée un compte de service dédié avec les deux droits dont l'application a besoin, et lie-le.", "`secret monter db-mdp`, `compte creer billets`, `droit ajouter configmaps:lire`, `droit ajouter secret-db-mdp:lire`, `compte lier billets`"],
    tested: () => ["Vérifie que l'application fonctionne encore avec tout ce durcissement.", "`tester`"],
    audit2: () => ["Lance l'audit final.", "`auditer`"],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ================= Dialogues ================= */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Bienvenue sur le quai des Entrepôts. La Guilde y range ses applications dans des entrepôts cloisonnés : on les appelle des conteneurs. Beaucoup les prennent pour de petites machines virtuelles. Ce n'est pas le cas, et c'est précisément ce qui rend leur configuration délicate.");
          say("Maître Ada", "La billetterie du festival tourne dans l'entrepôt « billets », configuré par Bob un vendredi soir. Mon auditeur automatique la note. Ton rôle : comprendre pourquoi, corriger, et remonter la note vers 100. Tout est un modèle jouet : on étudie les mauvaises configurations pour les corriger, rien d'autre.");
          out("Lance l'audit avec `auditer` (la tablette est dans ton inventaire).", "sys");
        } else if (x.end) say("Maître Ada", "Les entrepôts sont en ordre. Pense à re-scanner régulièrement !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas fini. `indice` si tu bloques ; `auditer` pour voir ce qui reste.");
        break;
      case "bob":
        if (F().cfg.priv) say("Bob", "J'avais un souci de droits, alors j'ai mis privilégié, monté le socket du moteur et le /etc de l'hôte, et j'ai laissé root. Ça marchait ! Ada dit que c'est comme laisser la porte du coffre ouverte pour ne pas perdre la clé. Ah.");
        else if (!runtimeOk()) say("Bob", "Ça passe encore en privilégié-zéro, ma billetterie. Il reste des réglages que je voulais « simplifier » : `examiner config`.");
        else say("Bob", "Plus de root, plus de socket, plus de privilège. Et l'appli tourne toujours ! Qui l'eût cru.");
        break;
      case "alice":
        if (!x.scanned) say("Alice", "Je ne laisse entrer aucune image sans scan. Lance `scanner` et on regarde ensemble les paquets touchés.");
        else if (!imgClean()) say("Alice", "Mets à jour, mais n'oublie pas : un paquet absent n'a pas de faille. Une base minimale n'a ni shell ni outils à exploiter. `base minimale`, `maj`, `scanner`.");
        else if (!polOk()) say("Alice", "Image propre, c'est bien. Maintenant le papier : registre privé, digest imposé, signature obligatoire. `exiger registre`, `exiger digest`, `exiger signature`.");
        else say("Alice", "Mes scellés tiennent. Une signature dit qui a publié l'image, pas qu'elle est sans défaut : on scanne aussi.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ================= Verbes ================= */
  const rawLow = c => c.rawArg.toLowerCase().trim();
  const tokens = c => norm(c.rawArg).split(" ").filter(t => t && !ART.has(t) && !SEP.has(t));
  const targ = c => tokens(c).join(" ");
  const need = (room, msg) => { if (S.room !== room) { out(msg, "sys"); return false; } return true; };

  function procs() {
    const c = F().cfg, u = c.user === "root" ? "root" : "10001";
    return [
      { pid: 1, u: "root", cmd: "init", cg: "/" }, { pid: 212, u: "root", cmd: "moteur-jouet", cg: "/systeme" },
      { pid: 2104, u: "999", cmd: "base-sgbd", cg: "/moteur/base" }, { pid: 3340, u, cmd: "billets-app --port 8080", cg: "/moteur/billets" },
      { pid: 3500, u: "998", cmd: "paiement-app", cg: "/moteur/paiement" },
    ];
  }
  const table = rows => rows.join("\n");

  function sonder(c) {
    if (!need("noyau", "L'observatoire est dans la salle du noyau (nord du quai).")) return;
    const x = F(), t = targ(c), cfg = x.cfg;
    const lim = cfg.mem === null ? "illimitée" : cfg.mem + " Mo";
    if (/^(appli|billets|application)/.test(t)) {
      x.vApp = true;
      out("Vue DEPUIS l'entrepôt « billets » (ce que voit le processus) :", "sys");
      const L = [];
      L.push("nom d'hôte      : billets-7f3");
      L.push("PID  UTIL.  COMMANDE");
      if (cfg.hostns) procs().forEach(p => L.push(`${String(p.pid).padEnd(5)}${p.u.padEnd(7)} ${p.cmd}`));
      else L.push(`1    ${cfg.user === "root" ? "root" : "10001"}${cfg.user === "root" ? "   " : "  "} billets-app --port 8080`);
      L.push("");
      L.push(cfg.hostns ? "réseau          : eth0 192.168.1.10 (celui de l'HÔTE) + moteur0 172.17.0.1" : "réseau          : eth0 10.0.3.2 (propre au conteneur)");
      L.push("racine /        : " + (cfg.ro ? "image en lecture seule" : "image (couches fusionnées), modifiable"));
      if (cfg.hmount) L.push("/hote/etc       : le /etc de l'HÔTE (écriture permise)");
      if (cfg.socket) L.push("/var/run/moteur.sock : le socket du MOTEUR de conteneurs");
      L.push("mémoire (cgroup): " + lim);
      code(table(L));
      out(cfg.hostns ? "Le processus voit TOUS les processus de l'hôte et son réseau : l'espace de noms n'isole plus rien." : "Le processus se croit seul : PID 1, son réseau, sa racine. C'est l'effet des espaces de noms.", cfg.hostns ? "err" : "ok");
    } else if (/^base/.test(t)) {
      x.vBase = true;
      out("Vue depuis l'entrepôt « base » (le voisin) :", "sys");
      code("nom d'hôte      : base-9d2\nPID  UTIL.  COMMANDE\n1    999    base-sgbd\n\nréseau          : eth0 10.0.3.3\nmémoire         : 300 Mo utilisés");
      out("La base se croit seule elle aussi. Elle ne voit pas « billets » : sauf si on partage les espaces de noms.", "sys");
    } else if (/^(hote|machine|noyau)/.test(t)) {
      x.vHost = true;
      out("Vue de l'HÔTE (le gardien du noyau voit tout) :", "sys");
      const L = ["PID   UTIL.  CGROUP               COMMANDE"];
      procs().forEach(p => L.push(`${String(p.pid).padEnd(6)}${p.u.padEnd(7)}${p.cg.padEnd(21)}${p.cmd}`));
      L.push("");
      L.push("noyau : un seul, partagé par « billets », « base » et « paiement »");
      code(table(L));
      out(`« billets » est le processus ${3340} de l'hôte, avec l'utilisateur ${cfg.user === "root" ? "root (uid 0) : sans espace de noms utilisateur, le root du conteneur est le root de l'hôte" : "10001 (banal)"}. Un conteneur n'est qu'un processus de l'hôte avec des œillères.`, cfg.user === "root" ? "err" : "ok");
    } else { out("Sonder quoi ? `sonder appli`, `sonder base` ou `sonder hote`.", "err"); return; }
    if (x.vApp && x.vHost && !x.shownNoyau) { x.shownNoyau = true; note("vm"); fig("noyau"); out("Même processus, deux vues : voilà la différence avec une machine virtuelle, qui aurait son propre noyau.", "ok"); }
  }

  function limiter(c) {
    if (!need("noyau", "Les limites se posent à la balance, dans la salle du noyau.")) return;
    const m = rawLow(c).match(/(\d+)/);
    if (!m) { out("Quelle limite ? `limiter appli memoire 256` (en Mo).", "err"); return; }
    const n = +m[1], x = F();
    x.cfg.mem = n;
    if (n < 128) out(`${n} Mo : trop peu. L'application a besoin d'environ ${BASE_USE} Mo au repos plus un peu de marge : elle sera tuée dès le démarrage. Limite posée, mais à corriger (128 Mo au moins).`, "err");
    else if (n > 350) out(`${n} Mo : la limite existe, mais l'hôte (${HOST_MEM} Mo dont ${OTHERS_MEM} utilisés par les voisins) souffrira avant que la limite n'agisse. Choisis plus bas (350 Mo au plus).`, "err");
    else out(`Limite de ${n} Mo posée sur le cgroup « billets » : le noyau l'appliquera, quoi que fasse le programme.`, "ok");
    if (memOk() && !x.contained) out("Rejoue `fuite appli` pour voir la différence.", "sys");
  }

  function fuite() {
    if (!need("noyau", "La balance est dans la salle du noyau.")) return;
    const x = F(), L = x.cfg.mem;
    out(`Un programme de « billets » fuit ${LEAK_STEP} Mo par seconde. Hôte : ${HOST_MEM} Mo, voisins : ${OTHERS_MEM} Mo. Limite de « billets » : ${L === null ? "aucune" : L + " Mo"}.`, "sys");
    const rows = ["s   billets   libre(hôte)  état"]; let press = 0, ended = false;
    for (let t = 0; t < 8 && !ended; t++) {
      const use = BASE_USE + LEAK_STEP * t, free = HOST_MEM - OTHERS_MEM - use;
      let st;
      if (L !== null && use > L) { st = "limite du cgroup atteinte : « billets » est arrêté seul"; ended = true; }
      else if (free < 0) { st = "mémoire de l'hôte épuisée : le tueur de mémoire intervient"; ended = true; }
      else if (free < 150) { st = "pression : l'hôte swappe, base et paiement ralentissent"; press++; }
      else st = "ok";
      rows.push(`${String(t).padEnd(4)}${String(use).padEnd(10)}${String(Math.max(free, 0)).padEnd(13)}${st}`);
    }
    code(rows.join("\n"));
    if (L === null || L > 350) {
      x.leaked = true;
      out(`Sans limite efficace, le fautif a affamé ses ${press > 0 ? "voisins (base, paiement) pendant " + press + " seconde(s)" : "voisins"} avant d'être arrêté : un voisin bruyant perturbe tout l'hôte. Il faut un cgroup.`, "err");
    } else if (L < 128) { out("La limite est si basse que l'application ne démarre même pas : règle-la entre 128 et 350 Mo.", "err"); }
    else {
      x.leaked = true; x.contained = true;
      out("Cette fois, seul « billets » est arrêté ; l'hôte et les voisins n'ont rien senti. Les cgroups limitent ce qu'on consomme, les espaces de noms ce qu'on voit.", "ok");
      note("ns"); fig("noyau");
    }
  }

  const COUCHE_REMARK = "Un fichier supprimé par une couche suivante reste dans la couche où il a été ajouté.";
  function couches() {
    if (!need("atelier", "Les couches se voient à l'atelier (est du quai).")) return;
    const L = layersFor(), x = F();
    out("Image « billets » (" + (x.build === "multi" ? "construction en plusieurs étapes" : "construction simple") + ") :", "sys");
    const rows = ["n  empreinte (sha256)     Mo   instruction"];
    L.forEach((l, i) => rows.push(`${i}  ${l.id.slice(0, 16)}…  ${String(l.mb).padEnd(4)} ${l.ins}`));
    rows.push("", "digest de l'image : sha256:" + imgDigest().slice(0, 24) + "…");
    code(rows.join("\n"));
    out("Chaque empreinte dépend du contenu de la couche ET de la couche d'en dessous : changer un octet change tout ce qui est au-dessus. `extraire ‹n›` ouvre une couche.", "sys");
    fig("couches");
  }
  function extraire(c) {
    if (!need("atelier", "L'extraction se fait à l'atelier (est du quai).")) return;
    const L = layersFor(), x = F(), t = targ(c);
    if (/^(fusion|final|vue|image)/.test(t)) {
      const m = merged(L);
      out("Vue fusionnée (ce que voit le conteneur au démarrage) :", "sys");
      code(Object.keys(m).sort().map(p => p + "  " + (m[p].length > 24 ? m[p].slice(0, 20) + "…" : m[p]).replace(/\n/g, " ")).join("\n"));
      if (x.build === "simple") out("Pas de /app/.env ici. On pourrait croire le secret parti. Regarde la couche 1 : `extraire 1`.", "sys");
      return;
    }
    const mm = t.match(/\d+/), n = mm ? parseInt(mm[0], 10) : NaN;
    if (isNaN(n) || n < 0 || n >= L.length) { out(`Quelle couche ? 0 à ${L.length - 1}, ou \`extraire fusion\`.`, "err"); return; }
    const l = L[n];
    out(`Couche ${n} : ${l.ins}  (${l.id.slice(0, 16)}…)`, "sys");
    if (!l.files.length) { out("Aucun fichier : cette couche ne change que les métadonnées (utilisateur de démarrage).", "sys"); return; }
    const rows = [];
    l.files.forEach(fl => {
      if (fl.del) rows.push(`- ${fl.p}   (marque de suppression : ne retire rien des couches en dessous)`);
      else rows.push(`+ ${fl.p}\n${fl.c.split("\n").map(s => "    " + s).join("\n")}`);
    });
    code(rows.join("\n"));
    if (secretHits().some(h => h.i === n)) {
      x.secFound = true;
      out("Le secret est là, en clair, récupérable par n'importe qui qui télécharge l'image, alors que la couche 3 l'a « supprimé » : " + COUCHE_REMARK, "err");
      if (!x.shownCouches) { x.shownCouches = true; note("couches"); fig("couches"); }
    }
  }
  function fouiller() {
    if (!need("atelier", "Le détecteur de secrets est à l'atelier (est du quai).")) return;
    const x = F(), H = secretHits();
    out("Recherche de secrets dans TOUTES les couches (motifs CLE / MDP / SECRET / TOKEN / PASS / KEY)…", "sys");
    if (H.length) {
      code(H.map(h => `couche ${h.i}  ${h.p}  ${h.k}=${h.v.slice(0, 4)}…${h.hidden ? "   (invisible dans la vue finale !)" : ""}`).join("\n"));
      x.secFound = true;
      out(`${H.length} secret(s) trouvé(s). ${COUCHE_REMARK}`, "err");
      if (!x.shownCouches) { x.shownCouches = true; note("couches"); fig("couches"); }
    } else {
      out("Aucun secret dans aucune couche.", "ok");
      if (x.build === "multi" && !x.cleanLayers) { x.cleanLayers = true; out("L'étape de construction (avec ses outils et le secret de build monté temporairement) est jetée : seule la dernière étape fait l'image.", "ok"); fig("couches"); }
    }
  }
  function construire(c) {
    if (!need("atelier", "On construit à l'atelier (est du quai).")) return;
    const x = F(), t = targ(c);
    if (/^(multi|etape|plusieurs)/.test(t)) {
      if (!x.secFound) { say("Maître Ada", "Examine d'abord l'image actuelle : `couches` puis `extraire ‹n›`."); return; }
      x.build = "multi";
      out("Construction en plusieurs étapes :", "ok");
      code("# étape 1 : construction (jetée ensuite)\nFROM debian-complet AS build\nRUN --mount=type=secret,id=cle  construire-appli    # secret monté le temps de la commande, jamais écrit dans une couche\n\n# étape 2 : image finale\nFROM debian-" + x.base + "\nCOPY --from=build /out/billets-app /app/billets-app\nUSER 10001");
      out("L'image finale ne contient que le binaire. Nouvelles empreintes : tout a changé. Vérifie avec `fouiller`.", "ok");
    } else if (/^simple/.test(t)) { x.build = "simple"; out("Retour à la construction simple (avec le secret copié puis supprimé). Pourquoi pas…, mais non.", "sys"); }
    else out("`construire multi` ou `construire simple`.", "err");
  }
  function revoquer(c) {
    if (!need("atelier", "La rotation des clés se décide à l'atelier.")) return;
    const x = F();
    if (!/cle|secret|mdp/.test(targ(c))) { out("Révoquer quoi ? `revoquer cle`", "err"); return; }
    if (!x.secFound) { out("Aucun secret n'a été trouvé pour l'instant.", "sys"); return; }
    if (x.revoked) { out("C'est fait.", "sys"); return; }
    x.revoked = true;
    out("La clé de paiement et le mot de passe de la base sont révoqués et remplacés. Même si l'ancienne image est effacée du registre, des copies ont pu être tirées : un secret qui a fui est un secret mort. Reconstruire l'image ne suffisait pas.", "ok");
  }

  /* --- entrepôt : scénario, corrections --- */
  function scenario() {
    const x = F(), c = x.cfg, o = x.orch;
    const rights = rightsOfBilling();
    const reach = [];
    const A = [];
    const hostWhy = [];
    if (c.priv) hostWhy.push("mode privilégié : presque tout l'hôte est visible, protections coupées");
    if (c.socket) hostWhy.push("socket du moteur monté : on peut demander au moteur de lancer ce qu'on veut (équivalent à root sur l'hôte)");
    if (c.hmount) hostWhy.push("/etc de l'hôte monté en écriture : on peut le modifier");
    if (!c.priv && c.caps.includes("sys_admin") && c.seccomp === "aucun") hostWhy.push("capacité sys_admin sans filtre seccomp");
    A.push(["le noyau et les fichiers de l'hôte", hostWhy]);
    const othersWhy = [];
    if (c.socket) othersWhy.push("le moteur commande tous les conteneurs");
    if (c.priv) othersWhy.push("conteneur privilégié");
    if (c.hostns) othersWhy.push("PID et réseau de l'hôte partagés : on voit et on joint les voisins");
    if (x.net.def === "allow") reach.push(SERVICES.filter(s => s !== "vitrine" && s !== "billets" && netAllowed("vitrine", s)));
    if (x.net.def === "allow") othersWhy.push("réseau ouvert par défaut : la vitrine joint directement la base et le paiement");
    A.push(["les autres conteneurs (base, paiement)", othersWhy]);
    A.push(["l'écriture durable dans l'entrepôt (y installer des outils)", c.ro ? [] : ["système de fichiers modifiable"]]);
    A.push(["tous les secrets de l'orchestrateur", rights.includes("*:*") || rights.includes("secrets:lire") ? ["le compte de service de l'application peut lire les secrets"] : (!o.secretMounted ? ["mot de passe de la base lisible en variable d'environnement"] : [])]);
    A.push(["les ressources de l'hôte (mémoire)", memOk() ? [] : ["aucune limite efficace"]]);
    out("Scénario (modèle jouet) : Mallory a trouvé une faille dans le code de la billetterie et exécute des commandes DANS l'entrepôt « billets ». Que peut-elle atteindre ?", "sys");
    const rows = []; let n = 0;
    A.forEach(([t, why]) => { if (why.length) { n++; rows.push(`✗ ATTEIGNABLE : ${t}`); why.forEach(w => rows.push("     parce que : " + w)); } else rows.push(`✓ protégé    : ${t}`); });
    if (c.user === "root") rows.push("(et elle y est root : chaque porte ci-dessus s'ouvre plus facilement)");
    code(rows.join("\n"));
    out(n ? `${n} zone(s) sur 5 atteignable(s). Chaque réglage dangereux élargit le « rayon d'explosion » d'une simple faille applicative.` : "Rayon d'explosion minimal : la faille reste enfermée dans l'entrepôt.", n ? "err" : "ok");
    if (!x.scen) { x.scen = true; fig("config"); }
  }

  function corriger(c) {
    if (!need("entrepot", "Les corrections se font à l'entrepôt de la billetterie (sud du quai).")) return;
    const x = F(), cfg = x.cfg, t = targ(c), raw = rawLow(c);
    if (!t) { out("Corriger quoi ? " + "`corriger privilege|utilisateur|lecture-seule|capacites ‹liste›|seccomp ‹profil›|socket|montages|espaces`", "err"); return; }
    if (/^(priv)/.test(t)) {
      if (!cfg.priv) { out("Déjà non privilégié.", "sys"); return; }
      cfg.priv = false;
      out("Mode privilégié retiré. Le conteneur n'a plus accès aux périphériques de l'hôte et ses protections (capacités, seccomp, lecture seule) comptent de nouveau. Bob : « ça marche toujours, étrange ».", "ok"); note("montages");
    } else if (/^(util|user|root|uid)/.test(t)) {
      if (cfg.user !== "root") { out("Déjà non privilégié.", "sys"); return; }
      cfg.user = "10001";
      out("L'application tourne maintenant avec l'utilisateur 10001. Un intrus n'y est plus administrateur : il ne peut ni installer, ni écrire dans les répertoires système, ni utiliser les pouvoirs de root.", "ok"); note("user");
    } else if (/^(lect|seule|ro|read)/.test(t)) {
      if (cfg.ro) { out("Déjà en lecture seule.", "sys"); return; }
      cfg.ro = true;
      out("Système de fichiers en lecture seule, avec un petit espace temporaire en mémoire (tmpfs) sur /tmp : l'application peut écrire ses fichiers temporaires, mais ni l'intrus ni elle ne peuvent modifier le programme.", "ok"); note("user");
    } else if (/^cap/.test(t)) {
      const arg = raw.replace(/^cap[a-zé]*/, "").trim();
      if (!arg) { out("Quelles capacités garder ? `corriger capacites aucune` ou `corriger capacites net_bind_service`. Disponibles : " + CAP_LIST.join(", "), "err"); return; }
      const keep = /^aucun/.test(arg) ? [] : arg.split(/[\s,]+/).filter(Boolean).map(s => s.replace(/^cap_/, ""));
      const bad = keep.filter(k => !CAP_LIST.includes(k));
      if (bad.length) { out("Capacité inconnue : " + bad.join(", ") + ". Disponibles : " + CAP_LIST.join(", "), "err"); return; }
      cfg.caps = keep;
      const dang = keep.filter(k => DANGER_CAPS.includes(k));
      if (dang.length) out("Capacités gardées : " + keep.join(", ") + ". Dangereuses : " + dang.join(", ") + ". Elles rendent des pouvoirs d'administration (réseau, trace d'autres processus, montages…) : à retirer. L'application écoute sur le port 8080, elle n'a besoin d'aucune capacité.", "err");
      else if (keep.some(k => k !== "net_bind_service")) out("Capacités gardées : " + keep.join(", ") + ". Aucune n'est inutilement dangereuse, mais l'application (port 8080) n'en a besoin d'aucune : réduis encore.", "sys");
      else out(keep.length ? "Capacités réduites à net_bind_service (écouter sur un port < 1024), ce qui est inoffensif ici." : "Toutes les capacités sont retirées : l'application n'en a besoin d'aucune (elle écoute sur le port 8080).", "ok");
      if (!cfg.priv && !keep.some(k => k !== "net_bind_service")) note("caps");
      if (cfg.priv) out("Attention : tant que le conteneur est privilégié, ce réglage ne sert à rien. `corriger privilege`.", "err");
    } else if (/^(sec|sys|appel|profil)/.test(t)) {
      const p = /restre|strict/.test(t) ? "restreint" : /def/.test(t) ? "defaut" : "restreint";
      cfg.seccomp = p;
      out(p === "restreint" ? "Profil seccomp restreint : seuls les appels système dont la billetterie a besoin sont autorisés (lire, écrire, ouvrir, réseau, mémoire, threads…). Refusés : mount, ptrace, reboot, chargement de modules du noyau, etc. Même un code exécuté par Mallory ne peut pas les demander." : "Profil seccomp par défaut du moteur : bloque déjà plusieurs dizaines d'appels système dangereux. Mieux que rien ; un profil restreint à l'application est mieux encore (`corriger seccomp restreint`).", "ok");
      if (cfg.priv) out("Attention : tant que le conteneur est privilégié, seccomp est désactivé de fait. `corriger privilege`.", "err");
      else note("caps");
    } else if (/^sock/.test(t)) {
      if (!cfg.socket) { out("Déjà retiré.", "sys"); return; }
      cfg.socket = false;
      out("Socket du moteur retiré. L'application n'a pas besoin de piloter le moteur de conteneurs : un conteneur qui y a accès peut créer d'autres conteneurs à sa guise, donc devenir l'hôte.", "ok"); note("montages");
    } else if (/^mont/.test(t)) {
      if (!cfg.hmount) { out("Déjà retiré.", "sys"); return; }
      cfg.hmount = false;
      out("Le /etc de l'hôte n'est plus monté, et le répertoire de données est remplacé par un volume nommé géré par le moteur : l'application garde ses données sans voir le système de fichiers de l'hôte.", "ok"); note("montages");
    } else if (/^(esp|ns|pid|res|names)/.test(t)) {
      if (!cfg.hostns) { out("Déjà isolé.", "sys"); return; }
      cfg.hostns = false;
      out("PID et réseau propres au conteneur : l'application ne voit plus les processus de l'hôte ni ses interfaces. Vérifie avec `sonder appli` au noyau.", "ok");
    } else { out("Je ne connais pas ce réglage. `corriger privilege|utilisateur|lecture-seule|capacites ‹liste›|seccomp ‹profil›|socket|montages|espaces`", "err"); return; }
    if (runtimeOk() && !x.fixShown) { x.fixShown = true; fig("config"); out("La configuration d'exécution est saine. `auditer` pour la note.", "ok"); }
    else if (!runtimeOk()) out("Reste à corriger : " + runtimeChecks().filter(k => !k.ok).map(k => k.label).join(" ; ") + ".", "sys");
  }

  function auditer() {
    const x = F(), I = auditItems(), s = I.reduce((a, k) => a + k.got, 0);
    out("Tablette d'audit : application « billetterie »", "title");
    let cat = "";
    const rows = [];
    I.forEach(k => { if (k.cat !== cat) { cat = k.cat; rows.push("— " + cat); } rows.push(`  ${k.got === k.pts ? "✓" : k.got > 0 ? "~" : "✗"} ${k.label.padEnd(46)} ${k.got}/${k.pts}`); });
    rows.push("", `SCORE : ${s}/100`);
    code(rows.join("\n"));
    out(s >= 90 ? "Excellent : défense en profondeur." : s >= 50 ? "Mieux, mais des portes restent ouvertes." : "Très exposé : une simple faille applicative suffirait à tout perdre.", s >= 90 ? "ok" : "err");
    if (!x.audited) { x.audited = true; x.firstScore = s; }
    if (s >= 90 && objective() === "audit2") x.finalAudit = true;
    x.lastScore = s;
  }

  /* --- douane --- */
  function scanner() {
    if (!need("douane", "Le scanner est à la douane (ouest du quai).")) return;
    const x = F(), V = vulns(), P = pkgs();
    x.scanned = true;
    out(`Scan de l'image « billets » (base debian-${x.base}${x.updated ? ", paquets à jour" : ""}) : ${Object.keys(P).length} paquets.`, "sys");
    code(Object.entries(P).map(([k, v]) => k.padEnd(12) + v).join("\n"));
    if (!V.length) { out("Aucune vulnérabilité connue dans la base fictive. (Ce n'est pas « aucune faille » : seulement aucune faille connue ; rescanne régulièrement.)", "ok"); if (!x.shownImg) { x.shownImg = true; note("images"); } return; }
    code(V.map(v => `${v.id}  ${v.sev.padEnd(9)} ${v.pkg} ${P[v.pkg]}  ${v.nofix ? "(pas de correctif)" : "(corrigé en " + REPO[v.pkg] + ")"}\n    ${v.txt}`).join("\n"));
    out(`${V.length} paquet(s) touché(s). ${V.some(v => v.nofix) ? "Au moins une faille n'a pas de correctif : mettre à jour ne suffira pas. La solution est de ne pas embarquer ce paquet." : "Une mise à jour des paquets les corrigerait."}`, "err");
    if (!x.shownImg) { x.shownImg = true; note("images"); }
  }
  function baseCmd(c) {
    if (!need("douane", "L'image de base se choisit à la douane (ouest du quai).")) return;
    const x = F(), t = targ(c);
    const k = Object.keys(BASES).find(b => t.startsWith(b.slice(0, 4)));
    if (!k) { out("Quelle base ? " + Object.keys(BASES).map(b => `\`base ${b}\` (${BASES[b].txt})`).join(" · "), "err"); return; }
    x.base = k;
    out(`Base choisie : debian-${k}, ${BASES[k].txt} (${BASES[k].mb} Mo). L'image est reconstruite : toutes les couches ont de nouvelles empreintes. Rescanne avec \`scanner\`.`, "ok");
  }
  function maj() {
    if (!need("douane", "Les mises à jour se font à la douane (ouest du quai).")) return;
    const x = F();
    x.updated = true;
    out("Mise à jour des paquets de l'image aux dernières versions du dépôt : " + Object.entries(pkgs()).map(([k, v]) => k + " " + v).join(", ") + ". Rescanne avec `scanner`.", "ok");
  }
  function attendre() {
    if (!need("douane", "L'attente se joue à la douane, devant le registre.")) return;
    const x = F();
    if (!x.tagPulls.length) { out("Rien à surveiller pour l'instant : tire d'abord l'image par son étiquette (`tirer bazar/billets:latest`).", "sys"); return; }
    x.day++;
    out(`Une nuit passe. Jour ${x.day}. Quelqu'un a peut-être déposé du neuf dans le registre public…`, "sys");
  }
  function tirer(c) {
    if (!need("douane", "Les images se tirent à la douane (ouest du quai).")) return;
    const x = F(), ref = rawLow(c);
    const m = ref.match(/^([a-z]+)\/([a-z]+)(?::([\w.\-]+)|@sha256:([0-9a-f]{4,64}))$/);
    if (!m) { out("Référence attendue : `tirer bazar/billets:latest` ou `tirer guilde/billets@sha256:‹digest›`.", "err"); return; }
    const [, reg, name, tag, dg] = m;
    if (name !== "billets" || (reg !== "bazar" && reg !== "guilde")) { out("Rien de tel dans nos registres (« bazar » et « guilde », image « billets »).", "err"); return; }
    if (x.pol.priv && reg !== "guilde") { out("REFUSÉ par la douane : seul le registre privé de la guilde est autorisé. (Le registre public ne passe plus.)", "err"); return; }
    if (x.pol.digest && !dg) { out("REFUSÉ par la douane : une étiquette est mouvante ; indique un digest (`@sha256:…`).", "err"); return; }
    if (dg && dg.length < 8) { out("Digest trop court : donne au moins 8 caractères.", "err"); return; }
    let digest = null, manifest = null, signed = false;
    if (reg === "bazar") {
      if (tag) digest = x.day >= 1 ? UP1 : UP0;
      else digest = [UP0, UP1].find(d => d.startsWith(dg)) || null;
      if (digest) manifest = MANIF[digest];
    } else {
      if (!x.pub) { out("La guilde n'a encore rien publié sous ce nom : `signer billets` d'abord.", "err"); return; }
      if (tag) digest = x.pub.digest; else digest = x.pub.digest.startsWith(dg) ? x.pub.digest : null;
      if (digest) { manifest = x.pub.manifest; signed = !!x.pub.sig; }
    }
    if (!digest) { out("Aucune image avec ce digest dans ce registre.", "err"); return; }
    if (x.pol.sig) {
      const ok = signed && x.sig && x.sig.digest === digest && x.sig.v === sha256(GUILD_KEY + "|" + digest);
      if (!ok) { out("REFUSÉ par la douane : signature absente ou invalide pour ce digest.", "err"); return; }
    }
    out(`Image tirée : ${reg}/billets${tag ? ":" + tag : "@sha256:" + short(digest, 16)} (jour ${x.day}).`, "sys");
    code(`digest : sha256:${digest}\n` + (reg === "bazar" ? "contenu : " + manifest.split("|").pop().split(";").join("\n         ") : "contenu : " + manifest.split("|")[1].split(",").length + " couches de la guilde"));
    const check = sha256(manifest) === digest;
    out(check ? "Intégrité vérifiée : le SHA-256 du manifeste reçu est bien le digest demandé." : "Intégrité NON vérifiée.", check ? "ok" : "err");
    if (/minerai/.test(manifest)) out("Un paquet « minerai-bz » que personne n'a demandé s'est glissé dans l'image : l'étiquette a été repointée vers un contenu modifié (ici : mineur de cryptomonnaie fictif).", "err");
    if (reg === "bazar" && tag) {
      x.tagPulls.push({ day: x.day, digest });
      const first = x.tagPulls[0];
      if (!x.drift && first.digest !== digest) { x.drift = true; out(`L'étiquette « ${tag} » désigne maintenant un autre contenu que ce matin : ${short(first.digest, 10)} → ${short(digest, 10)}. C'est ce qu'on appelle une étiquette mouvante.`, "err"); note("chaine"); fig("chaine"); }
      else if (!x.drift) out("Premier tirage : note ce digest. Laisse passer une nuit (`attendre`) et recommence.", "sys");
    }
    if (reg === "bazar" && dg && !x.pinned && x.drift) { x.pinned = true; out("Épinglé par digest : même après le changement de l'étiquette, tu obtiens exactement le contenu voulu, ou rien. Le digest n'est pas une promesse du registre : c'est une propriété du contenu.", "ok"); fig("chaine"); }
    if (reg === "guilde" && dg && polOk() && sigValid() && !x.deployOk) { x.deployOk = true; x.deployDigest = digest; out("Déployé : image de la guilde, par digest, signature vérifiée. C'est la chaîne complète.", "ok"); }
    else if (reg === "guilde" && dg && polOk() && sigValid()) { x.deployDigest = digest; x.deployOk = true; }
  }
  function signer(c) {
    if (!need("douane", "Les scellés se posent à la douane (ouest du quai).")) return;
    const x = F();
    if (!/billets/.test(targ(c))) { out("Signer quoi ? `signer billets` (l'image que tu as construite).", "err"); return; }
    const L = layersFor(), d = imgDigest();
    const v = sha256(GUILD_KEY + "|" + d);
    x.sig = { digest: d, v };
    x.pub = { digest: d, manifest: "billets|" + L.map(l => l.id).join(","), sig: true };
    out(`Image « billets » signée et publiée au registre de la guilde.`, "ok");
    code(`digest    : sha256:${d}\nsignature : ${v.slice(0, 32)}…\n(jouet : signature à clé secrète partagée ; en vrai, signature asymétrique, avec une clé publique pour vérifier)`);
    if (secretHits().length) out("Attention : tu viens de signer une image qui contient un secret. La signature atteste l'origine, pas la qualité.", "err");
    else if (!imgClean()) out("Attention : tu signes une image qui a des vulnérabilités connues. Signer ne corrige pas : la signature atteste l'origine, pas l'absence de défauts.", "err");
    else out("Pour la tirer : `tirer guilde/billets@sha256:" + d.slice(0, 12) + "`.", "sys");
    if (!x.shownSig) { x.shownSig = true; note("chaine"); }
  }
  function exiger(c) {
    if (!need("douane", "La politique d'admission se règle à la douane (ouest du quai).")) return;
    const x = F(), t = targ(c);
    if (/^regis|^priv/.test(t)) { x.pol.priv = true; out("Politique : seules les images du registre privé de la guilde entrent. Le registre public (bazar) est refusé.", "ok"); }
    else if (/^dig|^empr/.test(t)) { x.pol.digest = true; out("Politique : on ne tire que par digest. Les étiquettes (latest, 1.0), mouvantes, sont refusées.", "ok"); }
    else if (/^sign/.test(t)) { x.pol.sig = true; out("Politique : toute image doit porter une signature valide pour son digest.", "ok"); }
    else out("`exiger registre`, `exiger digest` ou `exiger signature`.", "err");
    if (polOk()) out("Les trois exigences sont en place. Déploie ton image : `tirer guilde/billets@sha256:‹digest›`.", "sys");
  }

  /* --- orchestrateur --- */
  function politique(c) {
    if (!need("orchestre", "Le tableau des passerelles est au poste de l'orchestrateur (haut).")) return;
    const x = F(), n = x.net, t = norm(c.rawArg).split(" ").filter(s => s && !ART.has(s) && !SEP.has(s));
    const svc = s => SERVICES.find(v => v.startsWith(s));
    if (t.length) {
      if (/^def/.test(t[0])) {
        if (/^(ref|den|ferm)/.test(t[1] || "")) { n.def = "deny"; out("Politique par défaut : REFUSER. Plus rien ne passe entre services tant qu'on ne l'autorise pas.", "ok"); }
        else if (/^(aut|ouv)/.test(t[1] || "")) { n.def = "allow"; out("Politique par défaut : AUTORISER tout. (C'est le réglage de départ de nombreux réseaux de conteneurs.)", "err"); }
        else { out("`politique defaut refuser` ou `politique defaut autoriser`.", "err"); return; }
      } else if (/^(aut|ouv|ret|ferm|supp)/.test(t[0])) {
        const a = svc(t[1] || "?"), b = svc(t[2] || "?");
        if (!a || !b) { out("Services : " + SERVICES.join(", ") + ". Exemple : `politique autoriser vitrine billets`.", "err"); return; }
        const r = a + ">" + b;
        if (/^(ret|ferm|supp)/.test(t[0])) { n.rules = n.rules.filter(k => k !== r); out(`Flux ${a} → ${b} retiré.`, "ok"); }
        else {
          if (!n.rules.includes(r)) n.rules.push(r);
          out(`Flux ${a} → ${b} autorisé.` + (REQ_FLOWS.includes(r) ? "" : " Hmm : la billetterie n'en a pas besoin. Un flux inutile est une porte de plus pour Mallory."), REQ_FLOWS.includes(r) ? "ok" : "err");
        }
      } else { out("`politique` · `politique defaut refuser` · `politique autoriser ‹a› ‹b›` · `politique retirer ‹a› ‹b›`", "err"); return; }
    }
    out(`Politique actuelle : par défaut ${n.def === "deny" ? "REFUSER" : "AUTORISER"}${n.def === "deny" ? ", flux autorisés : " + (n.rules.length ? n.rules.map(r => r.replace(">", " → ")).join(" ; ") : "aucun") : " (les règles sont sans effet : tout passe)"}.`, "sys");
    const reachV = SERVICES.filter(s => s !== "vitrine" && netAllowed("vitrine", s));
    out(`Si la vitrine est compromise, elle joint directement : ${reachV.length ? reachV.join(", ") : "personne"}.`, reachV.some(s => s !== "billets") ? "err" : "ok");
    if (netOk()) { if (!x.shownNet) { x.shownNet = true; note("reseau"); fig("reseau"); out("La vitrine ne joint plus que « billets » (son rôle). La base et le paiement lui sont fermés. Lance `tester` pour vérifier que tout fonctionne.", "ok"); } }
    else if (x.net.def === "deny" && !REQ_FLOWS.every(r => n.rules.includes(r)) && n.rules.length) out("Il manque encore des flux nécessaires, la billetterie est cassée : `tester`.", "sys");
  }
  function secretCmd(c) {
    if (!need("orchestre", "Les secrets se gèrent au poste de l'orchestrateur (haut).")) return;
    const x = F(), o = x.orch;
    if (!/mont|db|mdp/.test(targ(c))) { out("`secret monter db-mdp`", "err"); return; }
    if (o.secretMounted) { out("Déjà monté.", "sys"); return; }
    o.secretMounted = true;
    out("Le mot de passe de la base devient un objet secret de l'orchestrateur, monté comme fichier /run/secrets/db-mdp (en mémoire, lecture seule). La variable DB_PASS disparaît de la configuration, de la description du conteneur et des journaux.", "ok");
    if (orchOk()) orchDone();
  }
  function compte(c) {
    if (!need("orchestre", "Les comptes se gèrent au poste de l'orchestrateur (haut).")) return;
    const x = F(), o = x.orch, t = targ(c);
    if (/^(cre|nouv)/.test(t)) { if (o.acct.billets) { out("Le compte « billets » existe déjà.", "sys"); return; } o.acct.billets = []; out("Compte de service « billets » créé, sans aucun droit. Ajoute-lui seulement ce dont l'application a besoin : `droit ajouter ‹ressource:verbe›`.", "ok"); }
    else if (/^lier/.test(t)) {
      if (!o.acct.billets) { out("Crée le compte d'abord : `compte creer billets`.", "err"); return; }
      o.bound = true; out("L'application « billets » s'exécute désormais avec le compte « billets » et non plus « default ». Le jeton monté dans le conteneur ne porte plus que ses droits.", "ok");
      if (o.acct.billets.includes("*:*") || o.acct.billets.includes("secrets:lire")) out("Mais ce compte a des droits excessifs : retire-les.", "err");
      if (orchOk()) orchDone();
    } else out("`compte creer billets` puis `compte lier billets`.", "err");
  }
  function droit(c) {
    if (!need("orchestre", "Les droits se gèrent au poste de l'orchestrateur (haut).")) return;
    const x = F(), o = x.orch, w = rawLow(c).split(/\s+/).filter(Boolean);
    if (!o.acct.billets) { out("Crée d'abord le compte : `compte creer billets`.", "err"); return; }
    const act = w[0], r = w[1];
    if (!/^(ajouter|accorder|retirer|enlever)/.test(act || "") || !r) { out("`droit ajouter ‹ressource:verbe›` ou `droit retirer ‹ressource:verbe›`. Droits : " + ALL_RIGHTS.join(", "), "err"); return; }
    if (!ALL_RIGHTS.includes(r)) { out("Droit inconnu. Droits : " + ALL_RIGHTS.join(", "), "err"); return; }
    const L = o.acct.billets;
    if (/^(ajouter|accorder)/.test(act)) {
      if (!L.includes(r)) L.push(r);
      out(REQ_RIGHTS.includes(r) ? `Droit ${r} accordé au compte « billets ». ` + (r === "configmaps:lire" ? "Lire sa propre configuration." : "Lire son seul secret, et aucun autre.") : `Droit ${r} accordé… mais l'application n'en a pas besoin : c'est un droit de trop, qu'un intrus utiliserait.`, REQ_RIGHTS.includes(r) ? "ok" : "err");
    } else { o.acct.billets = L.filter(k => k !== r); out(`Droit ${r} retiré.`, "ok"); }
    if (orchOk()) orchDone();
  }
  function orchDone() { const x = F(); if (!x.shownOrch) { x.shownOrch = true; note("reseau"); out("Secret monté, compte dédié aux droits minimaux : même si Mallory vole le jeton de l'application, elle ne lit que sa propre configuration. Lance `tester`.", "ok"); } }
  function tester() {
    if (!need("orchestre", "Les tests se jouent au poste de l'orchestrateur (haut).")) return;
    const x = F(), rows = []; let ok = true;
    REQ_FLOWS.forEach(r => { const [a, b] = r.split(">"); const pass = netAllowed(a, b); if (!pass) ok = false; rows.push(`${pass ? "✓" : "✗"} flux ${a} → ${b} ${pass ? "passe" : "BLOQUÉ : l'application est cassée"}`); });
    const r = rightsOfBilling();
    REQ_RIGHTS.forEach(k => { const pass = r.includes(k) || r.includes("*:*"); if (!pass) ok = false; rows.push(`${pass ? "✓" : "✗"} droit ${k} ${pass ? "disponible" : "MANQUANT : l'application ne démarre pas"}`); });
    const dbp = x.orch.secretMounted ? "✓ mot de passe lu depuis /run/secrets/db-mdp" : "~ mot de passe lu depuis une variable d'environnement (marche, mais exposé)";
    rows.push(dbp);
    code(rows.join("\n"));
    if (!ok) out("Un durcissement qui casse l'application sera désactivé par les équipes à la première urgence : corrige la règle, pas l'objectif.", "err");
    else if (!netOk() || !orchOk()) out("Ça fonctionne, mais l'ensemble n'est pas encore durci au minimum : `auditer`.", "sys");
    else { x.tested = true; out("Tout fonctionne : l'application n'a besoin de rien de plus que ce qu'on lui donne. Le principe du moindre privilège ne coûte pas de fonctionnalité.", "ok"); }
  }

  /* ================= Fin ================= */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", `Note de départ : ${x.firstScore}/100. Note finale : ${x.lastScore}/100. La billetterie a les mêmes fonctionnalités, mais Mallory, en entrant par la moindre faille, trouverait un entrepôt sans clés, sans outils, sans voisins joignables et sans secret à voler.`);
    say("Bob", "La prochaine fois, je ne mets pas « privilégié » pour me dépanner.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Les entrepôts cloisonnés = les conteneurs.** Ce sont des processus ordinaires de l'hôte que le noyau Linux emballe : ils PARTAGENT le même noyau, contrairement à une machine virtuelle qui a son propre noyau sous un hyperviseur. Les cloisons sont les espaces de noms (ce qu'on voit : processus, réseau, montages, utilisateurs) et les cgroups (ce qu'on consomme : mémoire, processeur).");
    out("**Les calques = les couches d'image.** Chacune est identifiée par l'empreinte SHA-256 de son contenu (vraie ici). Une suppression ajoute une marque dans une couche supérieure, elle n'efface rien dessous : un secret copié puis supprimé reste extractible. Remèdes : ne pas mettre de secret dans l'image, construire en plusieurs étapes, utiliser des secrets de construction éphémères, et surtout révoquer.");
    out("**Les réglages de la fiche.** Utilisateur non privilégié, système de fichiers en lecture seule, capacités réduites, profil seccomp restreint : chacun réduit ce qu'un code compromis peut faire. Le mode privilégié, le socket du moteur monté et les répertoires de l'hôte montés en écriture sont des « portes » vers l'hôte et les autres conteneurs : elles annulent l'isolation.");
    out("**La douane = scanner, registre privé, digest et signatures.** Le scanner compare les versions des paquets aux vulnérabilités connues (base fictive ici). Les images minimales et à jour réduisent la surface. Le digest (SHA-256 du manifeste) épingle un contenu, une étiquette peut être repointée. Une signature prouve l'origine ; la politique d'admission refuse tout le reste.");
    out("**L'orchestrateur = réseau et droits.** Refuser par défaut entre services et ne rouvrir que les flux nécessaires ; secrets montés comme fichiers plutôt qu'en variables d'environnement ; un compte de service par application avec les droits minimaux.");
    out("**Les simplifications du jeu.** (1) Le noyau, les cgroups et les espaces de noms sont décrits par un modèle de visibilité simplifié ; dans la réalité on ajoute les espaces de noms utilisateur (le root du conteneur correspond à un utilisateur banal de l'hôte), AppArmor/SELinux, des conteneurs « rootless » et, pour une isolation plus forte, des micro-VM ou des bacs à sable (gVisor, Kata). (2) Le tueur de mémoire de l'hôte est présenté très simplement. (3) La base de vulnérabilités est fictive, les versions aussi. (4) La signature est une démonstration à clé partagée, pas de la cryptographie à clé publique. (5) Rien ici ne décrit comment s'évader d'un conteneur : on étudie les mauvaises configurations pour les corriger. (6) Il manque la journalisation, la détection au runtime, la politique d'admission de l'orchestrateur et la gestion des correctifs du noyau (un noyau partagé se patche pour tous).");
    out("Rappel utile : **un conteneur est un processus isolé, pas une machine virtuelle : durcis-le (non-root, lecture seule, peu de capacités, seccomp), ne monte pas le socket du moteur ni l'hôte, ne mets aucun secret dans l'image, scanne et épingle par digest, et refuse le réseau par défaut.**", "ok");
  }

  /* ================= Schémas ================= */
  const figs = {
    noyau: () => {
      const x = F(), c = x.cfg, bad = c.hostns || c.priv;
      const lim = c.mem === null ? "mémoire : illimitée" : "mémoire ≤ " + c.mem + " Mo (cgroup)";
      const l1 = c.hostns ? "PID : ceux de l'hôte" : "PID 1 = billets-app";
      const l2 = c.hostns ? "réseau : celui de l'hôte" : "réseau : eth0 propre";
      return {
        cap: "Deux conteneurs, un seul noyau. Les espaces de noms décident ce que chacun voit, les cgroups ce qu'il consomme. Un conteneur dont on partage les espaces de l'hôte (cadre rouge) ne voit plus de cloison.",
        svg: SVG(268, "Noyau partagé et isolation",
          T(210, 14, "tous les conteneurs partagent le même noyau", "f-s") +
          R(8, 26, 196, 128, bad ? "f-bad" : "f-pub") + T(106, 44, "billets", "f-b " + (bad ? "ft-bad" : "ft-pub")) +
          T(18, 66, l1, "f-s", "start") + T(18, 82, l2, "f-s", "start") + T(18, 98, c.ro ? "racine : lecture seule" : "racine : modifiable", "f-s", "start") +
          T(18, 114, "utilisateur : " + (c.user === "root" ? "root" : "10001"), "f-s " + (c.user === "root" ? "ft-bad" : "ft-ok"), "start") +
          T(18, 130, lim, "f-s " + (c.mem === null ? "ft-bad" : "ft-ok"), "start") + T(18, 146, c.priv ? "PRIVILÉGIÉ" : "capacités réduites", "f-s " + (c.priv ? "ft-bad f-b" : "ft-ok"), "start") +
          R(216, 26, 196, 128, "f-pub") + T(314, 44, "base", "f-b ft-pub") +
          T(226, 66, "PID 1 = base-sgbd", "f-s", "start") + T(226, 82, "réseau : eth0 propre", "f-s", "start") + T(226, 98, "racine : sa propre image", "f-s", "start") +
          T(226, 114, "utilisateur : 999", "f-s", "start") + T(226, 130, "mémoire : 300 Mo", "f-s", "start") +
          AR(106, 154, 106, 178, bad ? "f-bad" : "f-pub") + AR(314, 154, 314, 178, "f-pub") +
          R(8, 178, 404, 46, "f-priv") + T(210, 198, "NOYAU UNIQUE de l'hôte (partagé)", "f-b ft-priv") + T(210, 214, "espaces de noms : voir · cgroups : consommer", "f-s") +
          R(8, 234, 404, 26) + T(210, 251, "matériel de l'hôte", "f-s"))
      };
    },
    couches: () => {
      const L = layersFor(), hits = secretHits(), fin = merged(L);
      let body = T(210, 14, "pile de couches de « billets » (la 0 est en bas)", "f-s");
      const n = L.length;
      for (let k = 0; k < n; k++) {
        const i = n - 1 - k, y = 26 + k * 40, l = L[i], hasSec = hits.some(h => h.i === i), del = l.files.some(fl => fl.del);
        const cls = hasSec ? "f-bad" : del ? "f-dash" : "f-pub";
        const ins = l.ins.length > 44 ? l.ins.slice(0, 43) + "…" : l.ins;
        body += R(8, y, 404, 34, cls) + T(16, y + 15, `${i}  ${ins}`, "f-s f-b", "start") + T(16, y + 28, `sha256:${l.id.slice(0, 14)}…  ${l.mb} Mo`, "f-s", "start");
        if (hasSec) body += T(404, y + 15, "SECRET en clair", "f-s f-b ft-bad", "end");
        else if (del) body += T(404, y + 15, "masque .env", "f-s ft-priv", "end");
      }
      const y = 26 + n * 40 + 6;
      body += R(8, y, 404, 52, hits.length ? "f-bad" : "f-ok") + T(210, y + 18, "vue finale du conteneur (couches fusionnées)", "f-s f-b") +
        T(210, y + 34, "/app/.env : " + (fin["/app/.env"] !== undefined ? "présent" : "absent"), "f-s " + (fin["/app/.env"] !== undefined ? "ft-bad" : "ft-ok")) +
        T(210, y + 48, hits.length ? "mais la couche " + hits[0].i + " est toujours dans l'image téléchargeable" : "aucun secret dans aucune couche", "f-s " + (hits.length ? "ft-bad" : "ft-ok"));
      return { cap: hits.length ? "Le fichier .env est « supprimé » en haut de la pile, mais la couche qui l'a ajouté reste intacte : n'importe qui peut l'extraire." : "Construction en plusieurs étapes : le secret n'est jamais entré dans une couche de l'image finale.", svg: SVG(y + 62, "Couches d'image avec secret", body) };
    },
    config: () => {
      const cur = runtimeChecks();
      let body = T(210, 14, "configuration de « billets » : avant / maintenant", "f-s f-b") + T(300, 36, "avant", "f-s f-b") + T(376, 36, "maintenant", "f-s f-b");
      cur.forEach((k, i) => {
        const y = 58 + i * 22, partial = k.got !== undefined && k.got > 0 && !k.ok;
        body += T(10, y, k.label, "f-s", "start") + T(300, y, "✗", "ft-bad f-b") + T(376, y, k.ok ? "✓" : partial ? "~" : "✗", (k.ok ? "ft-ok" : "ft-bad") + " f-b") + LN(8, y + 7, 412, y + 7, "f-dash");
      });
      const h = 58 + cur.length * 22 + 18;
      body += T(210, h, `score actuel : ${score()}/100`, "f-b " + (score() >= 90 ? "ft-ok" : "ft-bad"));
      return { cap: "Avant : toutes les protections d'exécution sont absentes. Maintenant : l'état de ta configuration. Un conteneur privilégié annule aussi capacités et seccomp.", svg: SVG(h + 14, "Configuration avant et après", body) };
    },
    reseau: () => {
      const n = F().net, allow = n.def === "allow";
      const A = (a, b) => netAllowed(a, b);
      const arrow = (d, cls, dash) => `<path d="${d}" fill="none" class="f-ln ${cls}${dash ? " f-dash" : ""}" marker-end="url(#fa)"/>`;
      let body = T(210, 14, allow ? "politique par défaut : TOUT AUTORISER" : "politique par défaut : REFUSER (flux explicites)", "f-b " + (allow ? "ft-bad" : "ft-ok"));
      body += R(8, 92, 90, 44, "f-bad") + T(53, 118, "vitrine", "f-b") + T(53, 150, "(compromise)", "f-s ft-bad");
      body += R(165, 92, 90, 44, "f-pub") + T(210, 118, "billets", "f-b");
      body += R(322, 32, 90, 44, "f-pub") + T(367, 58, "base", "f-b");
      body += R(322, 152, 90, 44, "f-pub") + T(367, 178, "paiement", "f-b");
      body += A("vitrine", "billets") ? arrow("M98,114 H165", "f-ok") : "";
      body += A("billets", "base") ? arrow("M255,104 L322,60", "f-ok") : "";
      body += A("billets", "paiement") ? arrow("M255,124 L322,170", "f-ok") : "";
      if (A("vitrine", "base")) body += arrow("M53,92 V54 H322", "f-bad", true);
      if (A("vitrine", "paiement")) body += arrow("M53,136 V174 H322", "f-bad", true);
      if (!A("vitrine", "base") && !A("vitrine", "paiement")) body += T(210, 220, "✓ la vitrine ne joint plus la base ni le paiement", "f-s ft-ok");
      else body += T(210, 220, "✗ flèches rouges : la vitrine compromise joint la base et le paiement", "f-s ft-bad");
      REQ_FLOWS.forEach((r, i) => { if (!A(...r.split(">"))) body += T(210, 238 + i * 14, "✗ flux nécessaire bloqué : " + r.replace(">", " → "), "f-s ft-bad"); });
      return { cap: "Flèches pleines : flux autorisés et nécessaires. Flèches rouges pointillées : accès directs de la vitrine compromise que rien ne justifie.", svg: SVG(262, "Politique réseau entre services", body) };
    },
    chaine: () => {
      const x = F(), d1 = x.day >= 1 || x.drift;
      let body = T(210, 14, "étiquette (mouvante) contre digest (contenu)", "f-s f-b");
      body += R(8, 36, 150, 40, "f-bad") + T(83, 54, "bazar/billets:latest", "f-s f-b") + T(83, 68, "étiquette : peut bouger", "f-s ft-bad");
      body += R(262, 24, 150, 36, "f-ok") + T(337, 40, "sha256:" + UP0.slice(0, 10) + "…", "f-s f-b") + T(337, 53, "jour 0 : contenu voulu", "f-s ft-ok");
      body += R(262, 80, 150, 36, d1 ? "f-bad" : "f-dash") + T(337, 96, d1 ? "sha256:" + UP1.slice(0, 10) + "…" : "(pas encore de jour 1)", "f-s f-b") + T(337, 109, d1 ? "jour 1 : + minerai-bz" : "", "f-s ft-bad");
      body += d1 ? AR(158, 56, 262, 98, "f-bad") : AR(158, 50, 262, 42, "f-ok");
      body += R(8, 130, 150, 40, "f-ok") + T(83, 148, "billets@sha256:" + UP0.slice(0, 6) + "…", "f-s f-b") + T(83, 162, "digest : ne bouge pas", "f-s ft-ok");
      body += AR(158, 140, 262, 52, "f-ok");
      body += T(210, 196, "SHA-256(manifeste) = digest : on le revérifie à la réception", "f-s");
      return { cap: "L'étiquette peut être repointée vers un autre contenu ; le digest, empreinte du contenu lui-même, désigne toujours le même objet vérifiable.", svg: SVG(206, "Étiquette mouvante contre digest", body) };
    },
  };

  /* ================= Enregistrement ================= */
  GAMES.containers = {
    id: "containers", order: 41, title: "Les Entrepôts Cloisonnés", pageTitle: "Containers Quest", subtitle: "aventure textuelle · conteneurs et durcissement",
    blurb: "Inspecte des conteneurs fictifs, découvre ce qu'ils partagent avec l'hôte et ce qu'ils cachent dans leurs couches, puis durcis-les jusqu'à faire monter le score de l'auditeur.",
    concept: "Conteneurs : isolation, images, durcissement",
    start: "quai", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      x.day = 0; x.base = "complet"; x.updated = false; x.build = "simple";
      x.cfg = JSON.parse(JSON.stringify(INIT_CFG)); x.tagPulls = [];
      x.pol = { priv: false, digest: false, sig: false };
      x.net = { def: "allow", rules: [] };
      x.orch = { secretMounted: false, bound: false, acct: { default: ["*:*"], billets: null } };
      give("tablette");
    },
    figAlias: { noyau: ["isolation", "partage"], couches: ["image", "secret"], config: ["avant", "apres", "configuration"], reseau: ["politique", "flux"], chaine: ["digest", "etiquette", "tag"] },
    help: "Spécifiques : `auditer` · `scenario` · `sonder ‹appli|base|hote›` · `limiter appli memoire ‹Mo›` · `fuite appli` · `couches` · `extraire ‹n›` · `fouiller` · `construire multi` · `corriger ‹réglage›` · `scanner` · `base ‹nom›` · `maj` · `tirer ‹réf›` · `signer billets` · `exiger ‹x›` · `politique …` · `secret …` · `compte …` · `droit …` · `tester`",
    verbs: {
      audit: { words: ["auditer", "audit", "noter"], run: auditer },
      scen: { words: ["scenario", "simuler", "compromission"], run: scenario },
      sonder: { words: ["sonder", "observer"], run: sonder },
      limiter: { words: ["limiter", "plafonner"], run: limiter },
      fuite: { words: ["fuite", "charger", "stresser"], run: fuite },
      couches: { words: ["couches", "empiler"], run: couches },
      extraire: { words: ["extraire", "deballer"], run: extraire },
      fouiller: { words: ["fouiller", "chercher"], run: fouiller },
      construire: { words: ["construire", "batir", "reconstruire"], run: construire },
      revoquer: { words: ["revoquer", "invalider"], run: revoquer },
      corriger: { words: ["corriger", "durcir", "regler"], run: corriger },
      scanner: { words: ["scanner", "analyser"], run: scanner },
      base: { words: ["base", "rebaser"], run: baseCmd },
      maj: { words: ["maj", "actualiser"], run: maj },
      attendre: { words: ["attendre", "patienter"], run: attendre },
      tirer: { words: ["tirer", "telecharger", "pull"], run: tirer },
      signer: { words: ["signer", "parapher", "publier"], run: signer },
      exiger: { words: ["exiger", "imposer"], run: exiger },
      politique: { words: ["politique", "reseau"], run: politique },
      secret: { words: ["secret"], run: secretCmd },
      compte: { words: ["compte"], run: compte },
      droit: { words: ["droit", "droits"], run: droit },
      tester: { words: ["tester", "essayer"], run: tester },
    },
    intro() {
      out("Les Entrepôts Cloisonnés", "title");
      out("La Guilde de Port-443 range ses applications dans de grands entrepôts aux murs lisses : des conteneurs. Chacun se croit seul au monde. Mais Maître Ada se méfie de ce genre de confort : la billetterie du festival, rangée par Bob un vendredi soir, a des portes qui ne ferment pas très bien. Tout ceci est un modèle jouet, conçu pour comprendre et corriger.", "");
    },
  };
})();
