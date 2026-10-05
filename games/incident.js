"use strict";
/* La Cellule de Crise : gestion d'incident de sécurité. Un moteur de scénario à états : horloge de crise,
   exposition des données, preuves (vrai SHA-256), confiance des parties prenantes, délai légal de 72 h. */
(function () {
  const F = () => f();
  const T0 = Date.UTC(2025, 9, 14, 3, 0);            // mardi 14 octobre 2025, 03:00 : l'alerte tombe
  const DAYS = ["dim.", "lun.", "mar.", "mer.", "jeu.", "ven.", "sam."];
  const MON = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];
  const pad = n => String(n).padStart(2, "0");
  const clk = t => { const d = new Date(T0 + t * 60000); return `${DAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MON[d.getUTCMonth()]} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`; };
  const hm = t => { const d = new Date(T0 + t * 60000); return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`; };
  const dur = m => { m = Math.max(0, Math.round(m)); return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${pad(m % 60)}`; };
  const C2 = "203.0.113.66", C2B = "203.0.113.99", BKIP = "198.51.100.20";
  const TOTAL = 1240, BASE = 300, RATE = 6, LIMIT = 4320;   // fiches membres, déjà sorties à 03:00, fiches/min, 72 h en minutes
  const PH = ["Préparation", "Détection et qualification", "Confinement", "Éradication", "Reprise", "Retour d'expérience"];
  const MEMTXT = "proc=agent.bin(pid 4127) conn=203.0.113.66:443 creds=[svc-maint,db-registre,svc-backup] session=sauvegardes@02:40";
  const DISKTXT = "faille=/admin/registre v4.2.1@lun-22:47 compte=svc-maint@02:05 tache=maj-agent/10min fichier=/var/tmp/agent.bin";
  const BKC = { 1: "SAUVEGARDE|registre|lun. 13 oct. 01:00|donnees+config", 2: "SAUVEGARDE|registre|mar. 14 oct. 01:00|donnees+config" };
  const BKDATE = { 1: "lun. 13 oct. 01:00", 2: "mar. 14 oct. 01:00" };
  const EVN = { memoire: "mémoire vive", disque: "disque" };
  const EVID = { memoire: ["imgmem", "cpmem"], disque: ["imgdisque", "cpdisque"] };

  /* ---------- état : utilitaires ---------- */
  const lg = (tx, k) => { const x = F(); x.log.push({ t: x.t, tx, k: k || "" }); };
  const contained = m => !m.net || !m.on;
  const expNow = () => { const x = F(); return Math.min(TOTAL, x.expFinal !== undefined ? x.expFinal : BASE + RATE * x.t) + x.extraExp; };
  const expShow = () => Math.min(TOTAL, expNow());
  const TRL = { direction: "direction", equipe: "équipe", membres: "membres", autorite: "autorité" };
  function tr(k, d, why) {
    const x = F(); x.tr[k] = Math.max(0, Math.min(100, x.tr[k] + d));
    out(`Confiance (${TRL[k]}) ${d > 0 ? "+" : "−"}${Math.abs(d)} : ${why}`, d > 0 ? "ok" : "err");
  }
  const consigned = k => F().cust.some(e => e.type === "hash" && e.k === k && !e.copy);
  const imgIds = () => Object.keys(F().img);
  const allCons = () => imgIds().every(consigned);
  const allDup = () => imgIds().every(k => F().cp[k]);
  const allAna = () => imgIds().every(k => F().cp[k] && F().cp[k].ana);
  const eradDone = () => { const d = F().done; return d.compte && d.tache && d.agent && d.patch && d.secrets; };
  const patchOK = () => { const x = F(); return x.done.patch === 2 || (x.done.patch === 1 && !x.found.faille); };
  const secOK = () => { const x = F(); return x.done.secrets === 2 || (x.done.secrets === 1 && !x.found.creds); };
  function phaseIdx() {
    const x = F();
    if (!x.plan || !x.called.technique) return 0;
    if (!x.sev) return 1;
    if (!(x.expFinal !== undefined && x.blocked.any && (x.img.disque || x.lost.disque) && (x.img.memoire || x.lost.memoire))) return 2;
    if (!eradDone()) return 3;
    if (!x.monitored) return 4;
    return 5;
  }
  function adv(m) {
    const x = F(); x.t += m;
    if (x.expFinal === undefined && x.t >= 90 && !x.spread) {
      x.spread = true; x.m.sauvegardes.comp = true; lg("Rebond détecté vers le serveur « sauvegardes »", "rebond vers sauvegardes");
      out("Mauvaise nouvelle : l'attaquant a rebondi. Le compte de service vient d'ouvrir une session sur le serveur « sauvegardes ». Un second système est touché : l'étendue grandit, la gravité doit être réévaluée (`qualifier 4`) et il faut aussi `isoler sauvegardes`.", "err");
      tr("direction", -5, "la propagation aurait pu être évitée par un confinement plus rapide.");
    }
    if (x.t >= 300 && !x.told.equipe && !x.rumor) {
      x.rumor = true; lg("Rumeurs dans les couloirs (équipe non informée)", "rumeurs");
      out("08:00 approche : les premiers employés arrivent et la rumeur circule déjà (« on nous a piratés », « les données sont en vente »). L'équipe l'apprend par les couloirs plutôt que par toi.", "err");
      tr("equipe", -10, "la rumeur a pris l'avance sur l'information officielle.");
    }
  }
  const remain = () => { const x = F(); return x.aware === undefined ? null : x.aware + LIMIT - x.t; };
  const MN = { registre: ["registre"], courrier: ["courrier", "messagerie", "mail"], sauvegardes: ["sauvegardes", "sauvegarde", "backup", "backups"] };
  const mach = t => Object.keys(MN).find(k => MN[k].some(n => t.split(" ").includes(n)));
  const mstate = k => { const m = F().m[k]; return !m.on ? "éteinte" : m.net ? "allumée, connectée" : "allumée, isolée du réseau"; };
  const needTech = () => { if (F().called.technique) return false; out("Tu n'as pas les accès : seul Bob, l'administrateur, peut agir sur les machines. `appeler technique`", "sys"); return true; };

  /* ---------- carnet ---------- */
  const notes = {
    prep: ["Se préparer avant la crise", "Une crise ne se prépare pas pendant la crise. Un plan de réponse écrit (qui décide, qui fait quoi, dans quel ordre), une liste d'appel à jour (de nuit aussi), des journaux conservés, des sauvegardes testées et des exercices réguliers font gagner des heures. Le cycle de vie d'un incident (NIST SP 800-61) : préparation, détection et analyse, confinement-éradication-reprise, activité post-incident. Le modèle SANS le découpe en six temps : préparation, identification, confinement, éradication, reprise, retour d'expérience."],
    qualif: ["Qualifier : vrai ou faux positif, gravité 1 à 4", "Une alerte n'est pas encore un incident : on la recoupe avec des indices indépendants (volume, compte, destination, comparaison avec le normal). Puis on fixe une gravité, qui croise l'impact (données personnelles ? arrêt d'activité ?) et l'étendue (un poste, un service, plusieurs systèmes). Sous-qualifier retarde tout ; sur-qualifier use la crédibilité de la cellule. On requalifie quand les faits changent."],
    confinement: ["Confiner : isoler plutôt qu'éteindre", "Le confinement à court terme stoppe la fuite et la propagation : on isole la machine du réseau mais on la laisse sous tension, car l'éteindre efface la mémoire vive (connexions, processus, clés). Le confinement à long terme tient le temps de l'éradication : blocage des adresses malveillantes, correctifs provisoires, segmentation. On confine ce qui est touché, pas ce qui est sain : couper la messagerie « par précaution » a un coût."],
    preuves: ["Préserver les preuves et la chaîne de possession", "Ordre de volatilité (RFC 3227) : registres et cache, puis mémoire vive, processus et connexions, fichiers temporaires, disque, journaux distants, sauvegardes. On capture le plus volatil en premier. On fait des copies bit à bit, on calcule leur empreinte SHA-256 avant et après, et l'on travaille sur la copie, jamais sur l'original. La chaîne de possession note qui a eu quoi, quand et où ; un trou ou une empreinte différente ruine la valeur probante."],
    erad: ["Éradiquer : tout ce que l'attaquant a laissé", "Éradiquer, c'est retirer la persistance (comptes ajoutés, tâches planifiées, portes dérobées), changer tous les secrets qui ont pu être lus, et fermer la faille d'entrée. Si l'on oublie un seul des trois, l'attaquant revient. Bloquer une adresse n'est pas éradiquer : il en changera. Quand le doute est grand, on reconstruit plutôt que de nettoyer."],
    reprise: ["Reprendre : progressif et surveillé", "On restaure depuis une sauvegarde antérieure à la compromission : une empreinte conforme prouve qu'elle n'a pas été altérée, pas qu'elle est saine. On remet en service par paliers (10 %, 50 %, 100 %) pour détecter une réinfection à petite échelle, puis on surveille de près pendant plusieurs jours avec des règles de détection construites sur ce qu'on a appris (adresses, comptes, fichiers)."],
    comm: ["Communiquer en crise", "Direction informée vite ; équipe avant les rumeurs ; un seul porte-parole pour toutes les voix extérieures ; les personnes concernées avant la presse. Le message est factuel : ce que l'on sait, ce que l'on ignore encore, ce qui est fait, ce que chacun doit faire. Pas de spéculation, pas de promesse que l'on ne peut tenir. Se taire laisse la rumeur parler à ta place."],
    legal: ["Notifier : le délai de 72 heures", "RGPD, article 33 : en cas de violation de données personnelles, le responsable de traitement notifie l'autorité de contrôle (en France, la CNIL) dans les 72 heures après en avoir pris connaissance, sauf s'il est improbable que la violation engendre un risque. Le délai court dès qu'on a un degré raisonnable de certitude. La notification peut se faire en plusieurs temps. Article 34 : si le risque est élevé, on informe aussi les personnes concernées. Article 33.5 : toute violation est documentée, même non notifiée."],
    retex: ["Retour d'expérience sans coupable", "Un bon retour d'expérience (post-mortem) est factuel et sans reproche : on reconstruit la chronologie, on mesure les délais (détection, qualification, confinement), on cherche les causes systémiques (correctif absent, droits excessifs, alerte manquante) et on en tire quelques actions avec un responsable et une échéance. Chercher un coupable fait cacher les erreurs la fois suivante."],
  };

  /* ---------- entités ---------- */
  const evDesc = (k, copy) => () => {
    const x = F(), c = copy ? x.cp[k] : x.img[k];
    if (!c) return "";
    const h = sha256(copy ? c.c : evContent(k));
    return `${copy ? "Copie de travail" : "Image forensique originale"} ${k === "disque" ? "du disque" : "de la mémoire vive"} du registre, capturée ${clk(c.t)}${c.stale ? " (mémoire dégradée : capturée après le disque, la machine étant restée allumée)" : ""}.\nEmpreinte actuelle : ${h}${!copy && x.tamper[k] ? "\n⚠ L'original a été ouvert en lecture-écriture : cette empreinte ne correspond plus à celle de la capture." : ""}`;
  };
  function evContent(k) {
    const x = F(), i = x.img[k];
    return `P443-IMG|${k}|registre|${clk(i.t)}|${i.stale ? "degradee" : "ok"}|${k === "memoire" ? MEMTXT : DISKTXT}` + (x.tamper[k] ? "|atime-modifie" : "");
  }
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "direction"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle t'a réveillé, t'a nommé chef de la cellule de crise, et incarne la direction : c'est elle qui décide quand l'enjeu dépasse la technique." },
    bob: { npc: true, names: ["bob", "technique", "administrateur"], label: "Bob, administrateur système", vis: () => F().called.technique, desc: () => "Bob, l'administrateur système, les yeux rouges de sommeil. Il connaît les serveurs de la Guilde par cœur et obéit à ta décision." },
    alice: { npc: true, names: ["alice", "juridique", "dpo", "juriste"], label: "Alice, juriste et déléguée à la protection des données", vis: () => F().called.juridique, desc: () => "Alice, juriste et déléguée à la protection des données (DPO). Elle sait ce que la loi exige, dans quels délais, et ce que doit contenir une notification." },
    plan: { names: ["plan", "plan de reponse", "procedure", "liste d appel"], label: "le plan de réponse aux incidents", desc: () => planText() },
    alerte: { names: ["alerte", "ecran", "console"], label: "l'alerte affichée à l'écran", desc: () => alertText() },
    registre: { names: ["registre", "serveur registre", "registre des membres"], label: "le serveur « registre » (base des membres)", desc: () => `Le serveur « registre » : la base des ${TOTAL} membres de la Guilde (nom, e-mail, adresse). État : ${mstate("registre")}.` },
    courrier: { names: ["courrier", "messagerie", "serveur courrier"], label: "le serveur « courrier » (messagerie)", desc: () => `Le serveur « courrier » : la messagerie de la Guilde. Aucun indice ne le concerne. État : ${mstate("courrier")}.` },
    sauvegardes: { names: ["sauvegardes", "sauvegarde", "serveur sauvegardes", "backup"], label: "le serveur « sauvegardes »", desc: () => `Le serveur « sauvegardes » : les copies nocturnes du registre (lun. 13 oct. 01:00 et mar. 14 oct. 01:00). État : ${mstate("sauvegardes")}${F().spread ? " ; touché par le rebond de l'attaquant." : "."}` },
    violations: { names: ["registre des violations", "violations", "livre des violations"], label: "le registre des violations", desc: () => "Le registre interne des violations de données : on y consigne chaque violation, notifiée ou non (article 33.5 du RGPD). " + (F().told.autorite ? "L'entrée de cette nuit y figure." : "Aucune entrée pour cette nuit : pas encore.") },
    coffre: { names: ["coffre", "registre de possession", "chaine de possession", "scelles"], label: "le coffre et le registre de possession", desc: () => { const c = F().cust; return "Un coffre à scellés et son registre de possession : chaque empreinte et chaque transfert y est consigné.\n" + (c.length ? c.map(e => `· ${clk(e.t)}  ${e.tx}`).join("\n") : "(registre vide)"); } },
    imgmem: { names: ["image memoire", "img memoire", "original memoire"], label: "l'image de la mémoire", ev: { k: "memoire", copy: false }, desc: evDesc("memoire", false) },
    imgdisque: { names: ["image disque", "img disque", "original disque"], label: "l'image du disque", ev: { k: "disque", copy: false }, desc: evDesc("disque", false) },
    cpmem: { names: ["copie memoire", "copie de travail memoire"], label: "la copie de travail (mémoire)", ev: { k: "memoire", copy: true }, desc: evDesc("memoire", true) },
    cpdisque: { names: ["copie disque", "copie de travail disque"], label: "la copie de travail (disque)", ev: { k: "disque", copy: true }, desc: evDesc("disque", true) },
  };
  function planText() {
    const x = F();
    if (!x.plan) { x.plan = true; lg("Plan de réponse consulté"); setTimeout(() => { note("prep"); fig("cycle"); }, 0); }
    return "PLAN DE RÉPONSE AUX INCIDENTS (Guilde de Port-443, version 3)\n" +
      "Principes : confiner avant d'éradiquer · préserver les preuves · tout consigner au journal · une seule voix vers l'extérieur.\n" +
      "Cycle : préparation, détection et qualification, confinement, éradication, reprise, retour d'expérience.\n" +
      "Liste d'appel, de nuit comme de jour : `appeler technique` (Bob, administrateur système) · `appeler juridique` (Alice, DPO) · `appeler communication` (Clémence, porte-parole) · la direction, c'est Maître Ada, ici présente.\n" +
      "Annexe : chaque décision a un coût. Le temps passe et les fiches sortent tant que le serveur parle. `statut` et `journal` donnent la situation.";
  }
  function alertText() {
    const x = F(); x.seen.alerte = true;
    return "ALERTE SOC · mar. 14 oct. 03:00 · priorité : haute\nRègle : « sortie inhabituelle depuis un serveur interne »\nSource : registre (10.0.3.5) → 203.0.113.66:443, trafic continu depuis 02:10.\n\nQuatre pistes pour trancher entre vrai et faux positif : `analyser flux` · `analyser compte` · `analyser adresse` · `analyser sauvegarde`.";
  }
  const rooms = {
    cellule: { name: "La cellule de crise", short: "Cellule", alias: ["cellule", "crise"], ents: ["ada", "plan"], exits: { nord: "soc", est: "serveurs", ouest: "bureau", sud: "labo" },
      desc: () => `Une salle de réunion en pleine nuit : tableau blanc, café froid, horloge murale (${hm(F().t)}). Au nord, le centre de supervision (SOC) ; à l'est, la salle des serveurs ; à l'ouest, le bureau juridique ; au sud, le laboratoire forensique. Le plan de réponse est affiché au mur. \`statut\` et \`journal\` donnent la situation.` },
    soc: { name: "Le centre de supervision (SOC)", short: "SOC", alias: ["soc", "supervision"], ents: ["alerte", "bob"], exits: { sud: "cellule" },
      desc: () => "Des écrans de graphiques. Sur l'un d'eux, une alerte rouge clignote. " + (F().called.technique ? "Bob est installé à la console des pare-feu." : "Le poste de l'administrateur est vide : personne ne peut agir sur les machines tant que Bob n'est pas là (`appeler technique`).") },
    serveurs: { name: "La salle des serveurs", short: "Serveurs", alias: ["serveurs", "salle des serveurs"], ents: ["registre", "courrier", "sauvegardes"], exits: { ouest: "cellule" },
      desc: () => "Des baies bourdonnantes, des diodes vertes, un air glacé. Trois serveurs sont étiquetés : « registre », « courrier » et « sauvegardes »." },
    bureau: { name: "Le bureau juridique", short: "Bureau", alias: ["bureau", "juridique"], ents: ["alice", "violations"], exits: { est: "cellule" },
      desc: () => "Un bureau rangé, des classeurs d'articles de loi, un poste dédié aux déclarations officielles. " + (F().called.juridique ? "Alice y est installée." : "Personne : Alice n'est pas encore là (`appeler juridique`).") },
    labo: { name: "Le laboratoire forensique", short: "Laboratoire", alias: ["labo", "laboratoire", "forensique"], ents: ["coffre"], exits: { nord: "cellule" },
      desc: () => "Une pièce propre et silencieuse : station d'analyse, bloqueurs d'écriture, et un coffre à scellés avec son registre de possession. Ici on calcule les empreintes (`hacher`), on consigne (`consigner`), on duplique (`dupliquer`) et on étudie les copies (`analyser`)." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest"; if (!x.plan) return "plan"; if (!x.called.technique) return "callT";
    if (!x.seen.alerte) return "alerte";
    if (!(x.seen.flux && x.seen.compte && x.seen.adresse)) return "triage";
    if (!x.sev) return "qualify";
    if (x.spread && x.sev < 4) return "qualify4";
    if (!x.told.direction) return "direction";
    if (x.expFinal === undefined) return "isole";
    if (x.spread && contained(x.m.sauvegardes) === false) return "iso2";
    if (!x.img.memoire && !x.lost.memoire) return "mem";
    if (!x.img.disque && !x.lost.disque) return "disk";
    if (!allCons()) return "hash";
    if (!x.blocked.any) return "block";
    if (!allDup()) return "dup";
    if (!allAna()) return "analyse";
    if (!x.called.juridique) return "callJ"; if (!x.called.communication) return "callC";
    if (!x.told.autorite) return "notifA"; if (!x.told.equipe) return "notifE";
    if (!(x.done.compte && x.done.tache && x.done.agent)) return "retire";
    if (!patchOK() || !x.done.patch) return "patch";
    if (!secOK() || !x.done.secrets) return "secrets";
    if (!x.restored) return "restore";
    if (x.reprise < 100) return "reprise";
    if (!x.monitored) return "surveil";
    if (!x.told.membres) return "notifM";
    if (!x.retex) return "retex";
    if (!x.end) return "adopt";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend dans la cellule.", "`parler ada`"],
    plan: () => ["Avant d'agir, relis le plan de réponse affiché au mur.", "`examiner plan`"],
    callT: () => ["Tu ne peux pas agir sur les machines seul : la liste d'appel prévoit quelqu'un.", "`appeler technique`"],
    alerte: () => ["L'alerte est affichée au centre de supervision, au nord.", "`aller nord`, puis `examiner alerte`."],
    triage: () => { const x = F(); const m = ["flux", "compte", "adresse"].filter(k => !x.seen[k]); return ["Avant de décider si c'est un vrai incident, recoupe plusieurs indices au SOC. Il en manque : " + m.join(", ") + ".", "`analyser " + m[0] + "` (au SOC, au nord de la cellule)."]; },
    qualify: () => ["Tu as des faits : impact (données personnelles ?) et étendue (combien de systèmes ?). Regarde la matrice avec `schema gravite` si tu l'as, puis tranche à la cellule.", "`aller sud` (retour à la cellule) puis `qualifier 3` : impact élevé, un seul serveur touché."],
    qualify4: () => ["Un second système est touché : les faits ont changé, requalifie.", "`qualifier 4`"],
    direction: () => ["Maître Ada est la direction : elle doit être informée vite d'un incident de cette gravité.", "`notifier direction`"],
    isole: () => ["Chaque minute, des fiches sortent. Coupe la fuite sans effacer ce qui est en mémoire vive.", "`aller est` (salle des serveurs), puis `isoler registre` (et non `eteindre`)."],
    iso2: () => ["Le second serveur touché doit aussi être coupé du réseau.", "`isoler sauvegardes` (salle des serveurs ou SOC)."],
    mem: () => ["La mémoire vive est la plus volatile des preuves disponibles : capture-la d'abord, puis le disque.", "`copier registre` (salle des serveurs) fait mémoire puis disque, dans l'ordre."],
    disk: () => ["Il te manque la copie du disque.", "`copier disque registre`"],
    hash: () => ["Au laboratoire (sud de la cellule) : calcule l'empreinte de chaque image, puis consigne-la au registre de possession.", "`hacher image disque`, `consigner image disque` (idem pour `image memoire`)."],
    block: () => ["Confinement à long terme : l'adresse inconnue ne doit plus pouvoir être jointe. Cela se règle à la console du pare-feu, au SOC.", "`bloquer " + C2 + "`"],
    dup: () => ["On ne travaille jamais sur l'original : fais une copie de travail de chaque image, au laboratoire.", "`dupliquer image disque` (et `dupliquer image memoire`)."],
    analyse: () => ["Analyse les copies de travail pour savoir ce que l'attaquant a laissé et ce qu'il a lu.", "`analyser copie disque`, `analyser copie memoire`."],
    callJ: () => ["Une fuite de données personnelles : la juriste doit entrer dans la cellule.", "`appeler juridique`"],
    callC: () => ["Une seule voix vers l'extérieur : appelle le porte-parole avant de communiquer.", "`appeler communication`"],
    notifA: () => ["Le délai de 72 h court depuis que tu sais. La déclaration à l'autorité se prépare au bureau juridique (ouest de la cellule).", "`aller ouest` puis `notifier autorite`."],
    notifE: () => ["L'équipe arrive à 08:00 : mieux vaut qu'elle l'apprenne de toi que d'une rumeur.", "`notifier equipe`"],
    retire: () => ["Retire ce que l'attaquant a laissé et que tu as identifié en analysant le disque : un compte, une tâche, un fichier. À la salle des serveurs.", "`retirer compte`, `retirer tache`, `retirer agent`."],
    patch: () => ["Ferme la porte par laquelle il est entré.", "`patcher` (salle des serveurs)."],
    secrets: () => ["Il a pu lire des identifiants : change-les tous.", "`changer secrets` (salle des serveurs)."],
    restore: () => ["Restaure les données. Choisis une sauvegarde antérieure à l'intrusion (date relevée sur le disque).", "`restaurer` liste les sauvegardes ; puis `restaurer 1` (lun. 01:00) : l'intrusion date de lun. 22:47."],
    reprise: () => ["Remets en service par paliers.", "`reprendre 10`, puis `reprendre 50`, puis `reprendre 100`."],
    surveil: () => ["Surveillance renforcée avant de crier victoire. Au SOC.", "`surveiller`"],
    notifM: () => ["Les membres dont les données ont fui doivent être informés (risque élevé), avant toute presse, par la voix du porte-parole.", "`aller ouest` (bureau), `notifier membres`."],
    retex: () => ["La crise est finie. Retour à la cellule pour le retour d'expérience.", "`retex` (à la cellule)."],
    adopt: () => ["Choisis trois actions qui corrigent les causes systémiques, pas des coupables.", "`adopter 1`, `adopter 3`, `adopter 4` (ou `adopter 6`)."],
    fin: () => ["Gestion d'incident terminée. Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    if (id === "ada") {
      if (!x.quest) {
        x.quest = true;
        say("Maître Ada", "Il est 3 h du matin. Une alerte vient de tomber : le serveur « registre », celui qui contient les fiches de tous nos membres, parle à une adresse inconnue. Tu es chef de la cellule de crise : tu décides, les autres exécutent.");
        say("Maître Ada", "Une règle : chaque action prend du temps, et pendant ce temps l'attaquant avance. Les fiches sortent, la mémoire des machines change, les rumeurs se préparent. `statut` te donne la situation à tout moment, `journal` ce qui a été décidé. Rien n'est irréversible, mais tout a un coût.");
        out("Commence par `examiner plan`.", "sys");
      } else if (x.end) say("Maître Ada", "Merci pour cette nuit. Le plan est à jour, et personne n'a été désigné coupable.");
      else if (objective() === "retex") say("Maître Ada", "La crise est derrière nous. Passons au retour d'expérience : `retex`.");
      else say("Maître Ada", `Il est ${hm(x.t)}. Phase en cours : ${PH[phaseIdx()]}. Je te fais confiance. \`indice\` si tu bloques.`);
    } else if (id === "bob") {
      if (!x.sev) say("Bob", "Je suis là. Les pistes sont dans l'alerte : `analyser flux`, `compte`, `adresse` et `sauvegarde`. Le plus dur est de ne pas foncer : une alerte à 3 h n'est pas toujours un vrai incident.");
      else if (x.expFinal === undefined) say("Bob", "Mon réflexe : on tire la prise du registre. Ça arrête tout, c'est sûr. Mais la mémoire vive s'efface à l'extinction… C'est ton choix : `isoler` coupe le réseau, `eteindre` coupe le courant.");
      else if (!x.blocked.any) say("Bob", "La machine est coupée, mais l'adresse 203.0.113.66 reste joignable depuis le reste du réseau. Un blocage au pare-feu, ça se fait ici.");
      else say("Bob", "Dis-moi ce que tu veux que je fasse sur les serveurs : copier, retirer, patcher, changer les secrets, restaurer.");
    } else if (id === "alice") {
      const r = remain();
      if (r === null) say("Alice", "Quand tu auras confirmé que des données personnelles ont réellement quitté la Guilde, préviens-moi : à ce moment commence un délai de 72 heures pour notifier l'autorité.");
      else say("Alice", `Tu as confirmé la fuite à ${clk(x.aware)} : ${x.told.autorite ? "l'autorité est notifiée, " : ""}il ${r >= 0 ? "reste " + dur(r) + " sur les 72 h" : "y a un dépassement de " + dur(-r)}. La déclaration comporte la nature de la violation, le nombre approximatif de personnes, les conséquences probables et les mesures prises. Si le risque pour les personnes est élevé, il faudra aussi les informer, directement.`);
    } else out("Il ne répond pas.", "sys");
  }

  /* ---------- commandes ---------- */
  function statusCmd() {
    const x = F(), r = remain();
    const ev = (k) => x.img[k] ? (x.img[k].stale ? "capturée (dégradée)" : "capturée") : x.lost[k] ? "PERDUE" : "à capturer";
    code([
      `Heure          : ${clk(x.t)}   (alerte + ${dur(x.t)})`,
      `Phase          : ${PH[phaseIdx()]}`,
      `Gravité        : ${x.sev ? x.sev + " / 4" : "non qualifiée"}`,
      `Registre       : ${mstate("registre")}${x.spread ? "   Sauvegardes : " + mstate("sauvegardes") : ""}`,
      `Fiches exposées: ${expShow()} / ${TOTAL}  ${x.expFinal !== undefined ? "(fuite arrêtée)" : "(la fuite continue : ~" + RATE + " fiches/min)"}`,
      `Preuves        : mémoire ${ev("memoire")} · disque ${x.lost.disque ? "PERDU" : ev("disque")}`,
      `Notification   : ${r === null ? "délai 72 h pas encore déclenché (aucune fuite confirmée)" : x.told.autorite ? "autorité notifiée " + clk(x.autT) : "il reste " + (r >= 0 ? dur(r) : "0 (dépassé de " + dur(-r) + ")") + " sur 72 h"}`,
      `Confiance      : direction ${x.tr.direction} · équipe ${x.tr.equipe} · membres ${x.tr.membres} · autorité ${x.tr.autorite}`,
    ].join("\n"));
  }
  function journalCmd(c) {
    const x = F(), tx = c.rawArg.trim();
    if (tx) { x.log.push({ t: x.t, tx: "[note] " + tx, k: "", man: true }); x.manual = (x.manual || 0) + 1; out(`Entrée ajoutée au journal à ${clk(x.t)}.`, "ok"); return; }
    out("Journal de bord de la cellule", "title");
    code(x.log.map(e => `${clk(e.t)}  ${e.tx}`).join("\n"));
    out("`journal ‹texte›` ajoute une note horodatée de ta main (décision, raisonnement, heure d'un appel).", "sys");
  }
  function callCmd(c) {
    const x = F(), t = norm(c.rawArg);
    const role = /technique|bob|admin/.test(t) ? "technique" : /juridique|alice|dpo|juriste/.test(t) ? "juridique" : /communication|clemence|porte parole|presse/.test(t) ? "communication" : /direction|ada/.test(t) ? "direction" : null;
    if (!role) { out("Qui appeler ? La liste d'appel du plan : `appeler technique` · `appeler juridique` · `appeler communication`.", "err"); return; }
    if (role === "direction") { out("Maître Ada est déjà dans la pièce : `notifier direction` pour la mettre à jour.", "sys"); return; }
    if (x.called[role]) { out("Déjà joint.", "sys"); return; }
    x.called[role] = true; adv(role === "technique" ? 12 : 8);
    if (role === "technique") { out("Tu composes le numéro de Bob, administrateur système. Il décroche à la troisième sonnerie et arrive au SOC en dix minutes.", "ok"); lg("Bob (technique) appelé et sur place", "Bob arrive"); }
    else if (role === "juridique") { out("Alice, la DPO, décroche. Elle arrive dans l'heure, avec le registre des violations.", "ok"); lg("Alice (juridique/DPO) appelée", "Alice appelée"); }
    else { x.porte = "Clémence"; out("Clémence, responsable de la communication, accepte d'être la porte-parole unique : plus personne d'autre ne parlera à l'extérieur.", "ok"); lg("Clémence désignée porte-parole unique", "porte-parole désignée"); note("comm"); }
  }
  function analyseCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room === "soc") {
      const k = /flux|trafic|volume/.test(t) ? "flux" : /compte|svc|utilisateur/.test(t) ? "compte" : /adresse|ip|203/.test(t) ? "adresse" : /sauvegarde|backup/.test(t) ? "sauv" : null;
      if (!k) { out("Quelle piste ? `analyser flux` · `analyser compte` · `analyser adresse` · `analyser sauvegarde`.", "err"); return; }
      const first = !x.seen[k]; x.seen[k] = true;
      if (k === "flux") {
        code("Volume sortant du serveur « registre » (7 jours)\n  moyenne  : 0,3 Mo / nuit\n  cette nuit depuis 02:10 : 6 fiches par minute vers 203.0.113.66\n  contenu : lignes (nom ; e-mail ; adresse) de la base des membres\n  sorties estimées à 03:00 : ~" + BASE + " fiches sur " + TOTAL);
        out("Ce ne sont pas des statistiques anonymes : ce sont des données personnelles de membres, qui quittent la Guilde. Impact élevé.", "err");
        if (x.aware === undefined) { x.aware = x.t; lg("Fuite de données personnelles CONFIRMÉE : début du délai de 72 h", "fuite confirmée = prise de connaissance"); out(`À partir de maintenant, tu sais : le délai de 72 heures pour notifier l'autorité court. Échéance : ${clk(x.aware + LIMIT)}. (\`statut\` affiche le temps restant.)`, "ok"); }
      } else if (k === "compte") {
        code("Comptes du serveur « registre »\n  svc-maint : créé mar. 14 oct. 02:05, groupe administrateurs, connecté depuis 203.0.113.66\n  aucun ticket de changement correspondant\n  les autres comptes : inchangés");
        out("Un compte de service inconnu, créé en pleine nuit : ce n'est pas un administrateur de la Guilde.", "err");
      } else if (k === "adresse") {
        code("203.0.113.66\n  aucune relation métier, absente de la liste blanche\n  jamais contactée avant cette nuit\n  n'héberge aucun service connu de la Guilde");
        out("Une destination inconnue, jamais vue : un indicateur de compromission de plus (une adresse n'est jamais qu'un indicateur : elle peut changer).", "err");
      } else {
        code("Sauvegarde nocturne\n  01:00-01:40 : registre → 198.51.100.20 (sauvegarde externe prévue, ticket changement #212)\n  volume habituel, destination habituelle");
        out("Voilà un trafic de nuit parfaitement légitime : il explique un pic de trafic mais pas celui-ci, vers une autre adresse. Une fausse piste écartée.", "ok");
      }
      if (first) { adv(7); lg("Analyse : " + (k === "sauv" ? "sauvegarde nocturne (légitime)" : k)); }
      if (x.seen.flux && x.seen.compte && x.seen.adresse && !x.triageDone) { x.triageDone = true; out("Trois indices indépendants convergent : ce n'est pas un faux positif. Retourne à la cellule (sud) pour qualifier l'incident.", "sys"); }
      return;
    }
    if (S.room === "labo") {
      const id = resolve(c.target, e => e.ev); if (!id) return;
      const { k, copy } = ents[id].ev;
      if (copy ? !x.cp[k] : !x.img[k]) { out("Il n'y a rien là.", "sys"); return; }
      if (!copy && !x.tamper[k]) {
        x.tamper[k] = true;
        out(`Tu as ouvert l'ORIGINAL en lecture-écriture : les horodatages d'accès ont changé, son empreinte aussi. La valeur probante de cette preuve est entamée (\`controler\` le montrera). On travaille sur une copie.`, "err");
      }
      if (copy) x.cp[k].ana = true; else x.anaOrig = true;
      if (k === "disque") {
        x.found.faille = x.found.compte = x.found.tache = x.found.agent = true;
        out("Chronologie reconstituée à partir du disque :", "sys");
        code("lun. 13 oct. 22:47  requête forgée sur le panneau d'admin /admin/registre (version 4.2.1, correctif non appliqué)\nmar. 14 oct. 02:05  compte svc-maint créé (groupe administrateurs)\nmar. 14 oct. 02:08  tâche planifiée « maj-agent » (toutes les 10 min) → /var/tmp/agent.bin\nmar. 14 oct. 02:10  agent.bin ouvre une connexion vers 203.0.113.66:443");
        out("Tu tiens la porte d'entrée (la faille du panneau d'admin, lundi 22:47) et la persistance : un compte, une tâche planifiée, un programme. Retiens la date : l'intrusion est antérieure à la sauvegarde de mardi 01:00.", "ok");
      } else {
        const st = x.img.memoire.stale;
        out("Contenu de la mémoire vive au moment de la capture :", "sys");
        if (st) { code("agent.bin (pid 4127) : connexion vers 203.0.113.66:443\n[zones écrasées : identifiants illisibles]"); out("Tu as capturé le disque en premier et la machine est restée allumée pendant 45 minutes : la mémoire a changé, une partie des traces est illisible. Tu ne sais pas quels secrets étaient chargés.", "err"); }
        else { x.found.creds = true; code("agent.bin (pid 4127) : connexion vers 203.0.113.66:443\nidentifiants chargés en mémoire : svc-maint, db-registre, svc-backup\nsession ouverte vers « sauvegardes » à 02:40 avec svc-backup"); out("Seule la mémoire montre cela : l'attaquant a lu trois identifiants, dont celui de la sauvegarde. Il faudra tous les changer, pas seulement le mot de passe de la base.", "ok"); }
      }
      adv(12); lg(`Analyse de ${copy ? "la copie de travail" : "l'ORIGINAL"} (${EVN[k]})`, "analyse " + EVN[k]);
      return;
    }
    out("Les alertes s'analysent au SOC (nord de la cellule), les preuves au laboratoire (sud).", "sys");
  }
  function qualifyCmd(c) {
    const x = F(), t = norm(c.rawArg);
    const n = /faux positif|faux/.test(t) ? 1 : +((t.match(/[1-4]/) || [])[0]);
    if (!(n >= 1 && n <= 4)) { out("Gravité de 1 à 4 : `qualifier ‹n›` (matrice : `schema gravite`). 1 mineur, 2 modéré, 3 majeur, 4 critique.", "err"); return; }
    if (!x.seen.alerte) { out("Qualifier quoi ? Va d'abord voir l'alerte au SOC (nord).", "sys"); return; }
    const ok = x.spread ? 4 : 3, first = !x.sev;
    if (x.sev === ok && n === ok) { out(`Déjà qualifié : gravité ${ok}.`, "sys"); return; }
    if (n === ok) {
      x.sev = ok; adv(5);
      if (!x.evid) x.evid = !!(x.seen.flux && (x.seen.compte || x.seen.adresse)) && !x.badQual;
      if (first && !(x.seen.flux && (x.seen.compte || x.seen.adresse))) out("Tu as tapé juste, mais presque à l'aveugle : un bon chef de cellule s'appuie sur des indices.", "sys");
      out(ok === 3 ? "Gravité 3 (majeur) : impact élevé (données personnelles de membres), un seul serveur touché pour l'instant. La cellule de crise est complète : direction informée, juriste prévenue, preuves préservées." : "Gravité 4 (critique) : impact élevé sur plusieurs systèmes. Toute l'organisation est mobilisée, la communication externe est préparée.", "ok");
      lg(`Incident qualifié : gravité ${ok}`, "qualifié gravité " + ok); note("qualif"); fig("gravite");
    } else if (n < ok) {
      x.badQual++; adv(30 * (ok - n));
      out(n === 1 ? "Tu classes l'alerte comme faux positif. Mais les faits disent le contraire : le temps perdu à tort laisse la fuite et la propagation avancer." : `Gravité ${n} : tu sous-estimes. L'escalade arrive trop tard, les bonnes personnes ne sont pas mobilisées à temps.`, "err");
      tr("direction", -6, "une sous-qualification retarde l'escalade.");
      lg(`Qualification erronée (${n}) : ${30 * (ok - n)} min perdues`, "mauvaise qualification");
    } else {
      x.badQual++; adv(10);
      out(`Gravité ${n} : tu sur-qualifies. Réveiller tout le comité et la presse pour un incident de cette ampleur use la crédibilité de la cellule et fait perdre du temps à tout le monde.`, "err");
      tr("direction", -8, "une alerte disproportionnée entame la crédibilité.");
      lg(`Qualification erronée (${n}) : sur-estimation`, "mauvaise qualification");
    }
  }
  function containReg(how) {
    const x = F();
    if (x.expFinal === undefined) { x.expFinal = Math.min(TOTAL, BASE + RATE * x.t); x.isoT = x.t; x.method = how; }
  }
  function isolateCmd(c) {
    const x = F();
    if (!["soc", "serveurs"].includes(S.room)) { out("Les machines se pilotent au SOC ou dans la salle des serveurs.", "sys"); return; }
    if (needTech()) return;
    const m = mach(norm(c.rawArg)); if (!m) { out("Quelle machine ? `isoler registre` (ou courrier, sauvegardes).", "err"); return; }
    const M = x.m[m];
    if (!M.on) { out("Elle est éteinte : rien à isoler.", "sys"); return; }
    if (!M.net) { out("Elle est déjà isolée.", "sys"); return; }
    M.net = false; adv(5);
    if (m === "registre") {
      containReg("isoler");
      out(`Bob bascule le registre dans un VLAN de quarantaine. La machine reste sous tension : sa mémoire vive est intacte. À ${hm(x.t)}, la fuite s'arrête : ${expShow()} fiches sur ${TOTAL} sont sorties.`, "ok");
      lg(`Registre ISOLÉ du réseau (machine allumée). ${expShow()} fiches sorties`, "registre isolé"); note("confinement"); fig("chrono");
      const tt = x.t; const d = tt - 0;
      out(d <= 20 ? "Réaction rapide : peu de fiches exposées." : d <= 60 ? "Réaction correcte, mais chaque minute écoulée a coûté des fiches." : "Réaction tardive : le délai a un prix mesurable en fiches exposées.", d <= 20 ? "ok" : "sys");
    } else if (m === "sauvegardes" && x.spread) {
      out("Le serveur « sauvegardes » est coupé du réseau : le rebond est arrêté.", "ok"); lg("Sauvegardes isolées", "sauvegardes isolées");
    } else {
      x.pen[m] = true; out(`Le serveur « ${m} » n'avait rien à voir avec l'incident : tu viens de couper ${m === "courrier" ? "la messagerie de toute la Guilde" : "les sauvegardes de nuit"} sans raison. Confiner, oui ; couper ce qui est sain, non. \`reconnecter ${m}\` pour réparer.`, "err");
      tr("equipe", -5, "un service sain coupé par excès de précaution."); lg(`${m} isolé sans raison`, "coupure inutile");
    }
  }
  function reconnectCmd(c) {
    const x = F(), m = mach(norm(c.rawArg));
    if (!m) { out("Reconnecter quoi ? `reconnecter courrier`", "err"); return; }
    if (!x.m[m].on || x.m[m].net) { out("Rien à reconnecter.", "sys"); return; }
    if (m === "registre") { out("Le registre ne revient pas avant la remise en service (`reprendre`).", "err"); return; }
    if (m === "sauvegardes" && x.spread) { out("Pas encore : ce serveur est touché.", "err"); return; }
    x.m[m].net = true; adv(3); out("Le service est rétabli.", "ok"); lg(`${m} reconnecté`);
  }
  function powerOffCmd(c) {
    const x = F();
    if (!["soc", "serveurs"].includes(S.room)) { out("Les machines se pilotent au SOC ou dans la salle des serveurs.", "sys"); return; }
    if (needTech()) return;
    const m = mach(norm(c.rawArg)); if (!m) { out("Quelle machine ? `eteindre registre`", "err"); return; }
    if (m !== "registre") { say("Bob", "Éteindre ne sert à rien ici : si une machine doit être coupée du réseau, `isoler` suffit, et celle-ci ne mérite même pas ça pour l'instant."); return; }
    const M = x.m.registre;
    if (!M.on) { out("Elle est déjà éteinte.", "sys"); return; }
    M.on = false; adv(3); containReg("eteindre");
    out(`Bob tire la prise. La fuite s'arrête à ${hm(x.t)} : ${expShow()} fiches sorties.`, "ok");
    if (!x.img.memoire) {
      x.lost.memoire = true;
      out("Mais la mémoire vive est vidée : connexions, processus actifs, clés et identifiants chargés, tout est perdu. Tu ne sauras jamais ce que l'attaquant a lu en mémoire. (Règle : isoler d'abord, copier la mémoire, puis éteindre si nécessaire.)", "err");
      lg("Registre ÉTEINT sans copie de la mémoire : mémoire vive PERDUE", "registre éteint, mémoire perdue");
    } else { out("La mémoire a déjà été copiée : l'extinction ne détruit plus rien d'irremplaçable.", "ok"); lg("Registre éteint après copie de la mémoire", "registre éteint après copie"); }
    note("confinement"); fig("volatilite"); fig("chrono");
  }
  function evNotice() { const x = F(); if (x.expFinal === undefined) out("Attention : le registre est encore connecté. Pendant la copie, la fuite continue et l'attaquant peut remarquer ton outil. Un confinement avant l'acquisition aurait été plus sûr.", "err"); }
  function copyCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "serveurs") { out("L'acquisition se fait sur place, dans la salle des serveurs (est de la cellule).", "sys"); return; }
    if (needTech()) return;
    const m = mach(t); if (!m) { out("Quelle machine ? `copier registre` (ou `copier memoire registre`, `copier disque registre`).", "err"); return; }
    if (m !== "registre") { say("Bob", "Cette machine n'est pas suspecte : inutile d'y passer du temps. Priorité au registre."); return; }
    const wm = /memoire|ram/.test(t), wd = /disque|disk/.test(t), both = !wm && !wd;
    if (wm || both) {
      if (x.img.memoire) out("La mémoire est déjà copiée.", "sys");
      else if (!x.m.registre.on) { x.lost.memoire = true; out("Le serveur est éteint : la mémoire vive est vide, il n'y a plus rien à copier.", "err"); }
      else { evNotice(); const stale = !!x.img.disque; x.img.memoire = { t: x.t, stale }; give("imgmem"); adv(15); out(`Mémoire vive copiée (${clk(x.t)})${stale ? " : mais le disque a été copié avant, 45 minutes pendant lesquelles la mémoire a évolué, la capture est dégradée" : " : c'est la plus volatile, capturée en premier"}. Image forensique créée.`, stale ? "err" : "ok"); lg(`Copie de la mémoire du registre${stale ? " (dégradée : disque copié avant)" : ""}`, "mémoire copiée"); x.evShown = true; note("preuves"); fig("volatilite"); }
    }
    if (wd || both) {
      if (x.img.disque) out("Le disque est déjà copié.", "sys");
      else if (x.lost.disque) out("Le disque a été reconstruit : il n'y a plus de trace à copier.", "err");
      else { evNotice(); x.img.disque = { t: x.t }; give("imgdisque"); adv(45); out(`Disque copié bit à bit avec un bloqueur d'écriture (${clk(x.t)}, 45 minutes). Image forensique créée.`, "ok"); lg("Copie du disque du registre", "disque copié"); note("preuves"); fig("volatilite"); }
    }
    if (x.img.memoire || x.img.disque) out("Étape suivante : au laboratoire, calcule l'empreinte (`hacher`) et consigne-la (`consigner`).", "sys");
  }
  const hashOf = id => { const x = F(), { k, copy } = ents[id].ev; return sha256(copy ? x.cp[k].c : evContent(k)); };
  function evTarget(c) {
    if (S.room !== "labo") { out("Cela se fait au laboratoire forensique (sud de la cellule).", "sys"); return null; }
    const id = resolve(c.target, e => e.ev); if (!id) return null;
    const { k, copy } = ents[id].ev, x = F();
    if (copy ? !x.cp[k] : !x.img[k]) { out("Il n'y a rien là.", "sys"); return null; }
    return id;
  }
  function hashCmd(c) {
    const id = evTarget(c); if (!id) return;
    const h = hashOf(id); adv(2);
    out("SHA-256 calculé sur l'image :", "sys"); code(`SHA-256(${ents[id].label.replace(/^l[ae'] ?/, "")})\n= ${h}`);
  }
  function consignCmd(c) {
    const x = F(), id = evTarget(c); if (!id) return;
    const { k, copy } = ents[id].ev, h = hashOf(id);
    const prev = x.cust.find(e => e.type === "hash" && e.k === k && e.copy === copy);
    if (prev) { out(prev.h === h ? "Cette empreinte est déjà consignée." : "Une empreinte est déjà consignée, et elle est différente : l'image a changé depuis. On ne réécrit pas le registre.", prev.h === h ? "sys" : "err"); return; }
    adv(3);
    const e = { t: x.t, type: "hash", k, copy, h, tx: `${copy ? "copie" : "original"} ${EVN[k]} · SHA-256 ${h.slice(0, 16)}… · saisie par : chef de cellule` };
    x.cust.push(e);
    out(`Consigné au registre de possession : ${clk(x.t)}, ${e.tx}.`, "ok"); lg(`Empreinte consignée (${copy ? "copie" : "original"} ${EVN[k]})`, "empreinte consignée"); note("preuves"); fig("custody");
  }
  function controlCmd(c) {
    const x = F(), id = evTarget(c); if (!id) return;
    const { k, copy } = ents[id].ev, prev = x.cust.find(e => e.type === "hash" && e.k === k && e.copy === copy);
    if (!prev) { out("Rien à comparer : aucune empreinte n'a été consignée pour cette pièce.", "err"); return; }
    const h = hashOf(id); adv(2);
    code(`consignée : ${prev.h}\nrecalculée: ${h}`);
    out(prev.h === h ? "Les deux empreintes sont identiques : la pièce n'a pas bougé depuis sa capture. Elle est intègre." : "Les empreintes DIFFÈRENT : la pièce a été modifiée. Elle n'a plus de valeur probante, et toute analyse devait se faire sur une copie.", prev.h === h ? "ok" : "err");
  }
  function dupCmd(c) {
    const x = F(), id = evTarget(c); if (!id) return;
    const { k, copy } = ents[id].ev;
    if (copy) { out("Duplique l'original, pas une copie.", "sys"); return; }
    if (!consigned(k)) { out("Pas si vite : calcule et consigne d'abord l'empreinte de l'original (`hacher`, `consigner`). Sans elle, on ne pourra pas prouver que la copie est fidèle.", "err"); return; }
    if (x.cp[k]) { out("La copie de travail existe déjà.", "sys"); return; }
    const cons = x.cust.find(e => e.type === "hash" && e.k === k && !e.copy);
    if (cons.h !== hashOf(id)) { out("L'original ne correspond plus à l'empreinte consignée : il a été altéré. Une copie ne rattraperait rien.", "err"); return; }
    x.cp[k] = { t: x.t, c: evContent(k) }; give(EVID[k][1]); adv(10);
    const hc = sha256(x.cp[k].c);
    code(`original : ${cons.h}\ncopie    : ${hc}`);
    out(hc === cons.h ? "Empreintes identiques : la copie est conforme. Tu analyseras la copie, et l'original reste scellé." : "Les empreintes diffèrent !", hc === cons.h ? "ok" : "err");
    x.cust.push({ t: x.t, type: "copie", k, copy: true, tx: `copie de travail ${EVN[k]} créée, conforme à l'original (même empreinte)` }); lg(`Copie de travail créée (${EVN[k]}), empreinte identique`, "copie de travail");
    fig("custody");
  }
  function giveEv(item, who) {
    const x = F(), e = ents[item];
    if (!e.ev) return false;
    if (who === "bob" || who === "alice" || who === "ada") {
      const nm = ents[who].names[0];
      adv(3); x.cust.push({ t: x.t, type: "transfert", tx: `transfert : ${e.label.replace(/^l[ae'] ?/, "")} → ${nm}` });
      say(ents[who].names[0] === "ada" ? "Maître Ada" : nm[0].toUpperCase() + nm.slice(1), "Je prends en charge la pièce, et je signe le registre de possession.");
      out("Un transfert de plus dans la chaîne de possession : qui, quand, quoi. Aucun trou n'est permis.", "ok"); return true;
    }
    return false;
  }
  function blockCmd(c) {
    const x = F();
    if (S.room !== "soc") { out("Les règles du pare-feu se modifient à la console du SOC (nord de la cellule).", "sys"); return; }
    if (needTech()) return;
    const ip = (c.rawArg.match(/\d+\.\d+\.\d+\.\d+/) || [])[0];
    if (!ip) { out("Quelle adresse ? `bloquer 203.0.113.66`", "err"); return; }
    if (ip === C2 || ip === C2B) {
      if (x.blocked[ip]) { out("Déjà bloquée.", "sys"); return; }
      x.blocked[ip] = true; x.blocked.any = true; adv(5);
      out(`Règle ajoutée au pare-feu : tout trafic vers ${ip} est refusé, pour tout le réseau. C'est un confinement à long terme : même si une machine est rebranchée, elle ne pourra plus appeler cette adresse. Mais ce n'est qu'un indicateur : Mallory peut en changer.`, "ok");
      lg(`Adresse ${ip} bloquée au pare-feu`, "adresse bloquée"); note("confinement");
    } else if (ip === BKIP) {
      adv(10); x.pen.bk = true;
      out("Tu viens de bloquer la sauvegarde externe de la Guilde ! Bob annule la règle aussitôt, mais dix minutes ont été perdues : une règle écrite sans réfléchir peut faire plus de dégâts que l'attaque.", "err");
      tr("equipe", -3, "erreur de manipulation en pleine crise."); lg("Blocage erroné de la sauvegarde externe (annulé)", "erreur de blocage");
    } else out("Cette adresse n'apparaît dans aucun de tes indices : la règle serait inutile (ou nuisible).", "err");
  }
  function removeCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "serveurs") { out("Cela se fait sur les machines : salle des serveurs (est de la cellule).", "sys"); return; }
    if (needTech()) return;
    const k = /compte|svc/.test(t) ? "compte" : /tache|maj/.test(t) ? "tache" : /agent|programme|fichier/.test(t) ? "agent" : null;
    if (!k) { out("Retirer quoi ? `retirer compte` · `retirer tache` · `retirer agent` (ce que ton analyse a révélé).", "err"); return; }
    if (!x.found[k]) { out("Tu ne sais pas encore ce qui est en place : l'analyse de la copie du disque ne t'a rien appris à ce sujet. Supprimer au hasard, ce n'est pas éradiquer.", "err"); return; }
    if (x.done[k]) { out("C'est déjà fait.", "sys"); return; }
    x.done[k] = true; adv(15);
    const txt = { compte: "Le compte svc-maint est supprimé du registre.", tache: "La tâche planifiée « maj-agent » est supprimée.", agent: "Le fichier /var/tmp/agent.bin est supprimé." + (x.spread ? " Même nettoyage sur « sauvegardes »." : "") }[k];
    out(txt + " (La copie forensique du disque, elle, reste intacte au coffre.)", "ok"); lg(txt, "persistance retirée : " + k); note("erad");
  }
  function patchCmd() {
    const x = F();
    if (S.room !== "serveurs") { out("Cela se fait sur les machines : salle des serveurs (est de la cellule).", "sys"); return; }
    if (needTech()) return;
    if (x.done.patch === 2) { out("Le panneau d'admin est déjà corrigé.", "sys"); return; }
    adv(25); note("erad");
    if (x.found.faille) { x.done.patch = 2; out("Bob met à jour le panneau d'administration vers la version corrigée (4.2.2) : la requête forgée de lundi ne passe plus. La porte d'entrée est fermée.", "ok"); lg("Faille du panneau d'admin corrigée", "faille corrigée"); }
    else { x.done.patch = 1; out("Tu demandes « d'appliquer les mises à jour » sans savoir quelle faille a servi. Bob s'exécute, mais personne ne peut garantir que la bonne a été fermée : sans analyse du disque, c'est un pari.", "err"); lg("Mises à jour génériques (faille d'entrée non identifiée)", "patch générique"); }
  }
  function secretsCmd() {
    const x = F();
    if (S.room !== "serveurs") { out("Cela se fait sur les machines : salle des serveurs (est de la cellule).", "sys"); return; }
    if (needTech()) return;
    if (x.done.secrets === 2) { out("Tous les secrets exposés ont déjà été changés.", "sys"); return; }
    adv(20); note("erad");
    if (x.found.creds) { x.done.secrets = 2; out("Tu changes tous les secrets que la mémoire montre comme lus : mot de passe de la base (db-registre), identifiant de sauvegarde (svc-backup), clés de service. Les anciens ne servent plus à rien.", "ok"); lg("Secrets changés (db-registre, svc-backup, clés)", "secrets changés"); }
    else { x.done.secrets = 1; out("Tu changes ce que tu connais (le mot de passe de la base), mais tu ignores ce que l'attaquant a lu en mémoire : sans la mémoire, tu ne sais pas lister les secrets exposés. Un identifiant oublié suffit pour revenir.", "err"); lg("Changement partiel des secrets (mémoire inconnue)", "secrets partiels"); }
  }
  function restoreCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "serveurs") { out("Cela se fait sur les machines : salle des serveurs (est de la cellule).", "sys"); return; }
    if (needTech()) return;
    const n = +((t.match(/[12]/) || [])[0]);
    if (!n) {
      out("Sauvegardes disponibles du registre :", "sys");
      code("1  lun. 13 oct. 01:00   empreinte conforme au manifeste\n2  mar. 14 oct. 01:00   empreinte conforme au manifeste");
      out("`restaurer ‹1 ou 2›`. Une empreinte conforme prouve que le fichier n'a pas bougé depuis sa création ; elle ne dit rien de ce qu'il contenait déjà.", "sys"); return;
    }
    const manifest = sha256(BKC[n]), now = sha256(BKC[n]);
    code(`manifeste : ${manifest.slice(0, 32)}…\nrecalculée: ${now.slice(0, 32)}…`);
    out("Intégrité vérifiée : l'empreinte est conforme. (Attention : intégrité ne veut pas dire propreté.)", "ok");
    if (!x.img.disque && !x.lost.disque) { x.lost.disque = true; out("Mais tu viens d'écraser le disque sans en avoir fait de copie : les preuves y sont détruites. (On copie avant de nettoyer ou de reconstruire.)", "err"); lg("Disque écrasé sans copie préalable : preuves PERDUES", "preuves disque perdues"); }
    x.restored = n; adv(60);
    x.m.registre.on = true;
    const loss = n === 1 ? "26 heures" : "2 heures";
    out(`Restauration de la sauvegarde du ${BKDATE[n]} : perte de données à rejouer ou ressaisir (${loss} de modifications).`, "ok");
    if (n === 2 && !x.badBackup) { x.badBackup = true; }
    lg(`Restauration depuis la sauvegarde du ${BKDATE[n]}`, "restauration " + BKDATE[n]);
  }
  function resumeCmd(c) {
    const x = F(), n = +((c.rawArg.match(/\d+/) || [])[0]);
    if (S.room !== "serveurs") { out("La remise en service se pilote dans la salle des serveurs (est de la cellule).", "sys"); return; }
    if (needTech()) return;
    if (![10, 50, 100].includes(n)) { out("Par paliers : `reprendre 10`, puis `reprendre 50`, puis `reprendre 100` (pourcentage du trafic).", "err"); return; }
    if (!x.restored) { out("Il n'y a encore rien à remettre en service : `restaurer`.", "sys"); return; }
    if (n <= x.reprise) { out("Ce palier est déjà atteint.", "sys"); return; }
    if (n !== [10, 50, 100].find(v => v > x.reprise)) x.brusque = true;
    x.m.registre.net = true; adv(n === 100 ? 40 : 30);
    const imm = [];
    if (!(x.done.compte && x.done.tache && x.done.agent)) imm.push("persistance");
    if (x.restored === 2) imm.push("backup");
    if (imm.length) {
      x.reinf++; x.extraExp += n === 100 ? 100 : 20; x.found.compte = x.found.tache = x.found.agent = true; x.reprise = 0; x.m.registre.net = false; adv(45);
      out(`Palier ${n} % : dès les premières minutes, l'agent se réveille et rappelle ${C2}${x.blocked[C2] ? " (refusé par ton pare-feu : le confinement à long terme tient)" : ""}. ${imm.includes("backup") ? "La sauvegarde du mardi 01:00 contenait déjà l'intrusion (elle date de lundi 22:47) : tu as restauré l'attaquant avec tes données. " : "Tu as remis en service un système où la persistance n'a pas été retirée. "}Le registre est réisolé.`, "err");
      tr("direction", -8, n === 100 ? "la réinfection touche tous les utilisateurs." : "un palier raté, mais sans impact sur tous les utilisateurs grâce au déploiement progressif.");
      if (n < 100) out("Tu as de la chance : à 10 %, la réinfection n'a presque touché personne. C'est le but des paliers.", "ok");
      x.restored = 0; lg(`Réinfection détectée au palier ${n} %`, "réinfection au palier " + n);
      out(imm.includes("backup") ? "Reprends depuis une sauvegarde antérieure à lundi 22:47 : `restaurer 1`. Et retire la persistance si besoin." : "Retire d'abord la persistance (`retirer …`), puis `restaurer`.", "sys"); return;
    }
    x.reprise = n;
    out(`Palier ${n} % : ${n === 10 ? "10 % du trafic bascule sur le registre restauré ; tu surveilles les connexions sortantes, aucune anomalie." : n === 50 ? "la moitié du trafic, toujours rien d'anormal." : "tout le trafic est rétabli : le registre est de retour, avec ses données (hors modifications perdues)."}`, "ok");
    lg(`Remise en service : ${n} %`, "remise en service " + n + " %");
    if (n === 100 && x.brusque) out("Tu as sauté des paliers : cela a marché, mais un défaut aurait touché tout le monde d'un coup.", "sys");
    note("reprise");
  }
  function monitorCmd() {
    const x = F();
    if (S.room !== "soc") { out("La surveillance se règle au SOC (nord de la cellule).", "sys"); return; }
    if (x.reprise < 100) { out("La surveillance renforcée suit la remise en service complète : `reprendre 100` d'abord.", "sys"); return; }
    if (x.monitored) { out("La surveillance renforcée est terminée : rien à signaler.", "sys"); return; }
    out("Tu ajoutes des règles de détection construites sur l'incident (adresses 203.0.113.66 et 203.0.113.99, création de comptes de service, volumes sortants du registre) et tu surveilles de près.", "sys");
    const res = [];
    if (x.done.patch !== 2) res.push("faille");
    if (x.done.secrets !== 2) res.push("creds");
    if (res.length) {
      adv(600); x.reinf++; x.extraExp += 40; x.found.faille = true; x.found.creds = true;
      out(`${clk(x.t)} : alerte ! Depuis ${C2B} (une autre adresse : Mallory a changé), ${res.includes("faille") ? "la même requête forgée passe encore sur le panneau d'administration (faille non corrigée)" : ""}${res.length === 2 ? " et " : ""}${res.includes("creds") ? "le compte svc-backup, dont le secret n'avait pas été changé, ouvre une session sur « sauvegardes »" : ""}. Grâce aux nouvelles règles, c'est repéré en deux minutes : l'intrusion est stoppée.`, "err");
      tr("direction", -6, "l'éradication était incomplète."); lg("Réinfection détectée par la surveillance renforcée : " + res.join(" + "), "réinfection détectée");
      out((res.includes("faille") ? "Il faut `patcher` (maintenant tu connais la faille). " : "") + (res.includes("creds") ? "Il faut `changer secrets` (tous ceux que la compromission a pu exposer). " : "") + "Puis relance `surveiller`. (`bloquer " + C2B + "` aide mais ne règle rien : la cause n'est pas l'adresse.)", "sys");
      return;
    }
    adv(x.reinf ? 1440 : 2880); x.monitored = true;
    out(`${x.reinf ? "24" : "48"} heures de surveillance renforcée : aucune connexion suspecte, aucun compte inattendu, volumes sortants normaux. L'éradication a tenu.`, "ok");
    lg("Surveillance renforcée terminée : RAS", "surveillance : RAS"); note("reprise");
  }
  function notifyCmd(c) {
    const x = F(), t = norm(c.rawArg);
    const who = /direction|ada/.test(t) ? "direction" : /equipe|personnel|salarie|staff/.test(t) ? "equipe" : /autorite|cnil|regulateur/.test(t) ? "autorite" : /membre|concerne|personne/.test(t) ? "membres" : /presse|media/.test(t) ? "presse" : null;
    if (!who) { out("Qui prévenir ? `notifier direction` · `notifier equipe` · `notifier autorite` · `notifier membres` · `notifier presse`.", "err"); return; }
    if (who === "direction") {
      if (x.told.direction !== undefined) { out("Maître Ada est déjà informée.", "sys"); return; }
      if (!x.sev) { say("Maître Ada", "Je veux bien être informée, mais d'abord : qu'est-ce qui se passe, exactement ? Qualifie l'incident."); return; }
      x.told.direction = x.t; adv(5);
      say("Toi → Maître Ada", `Gravité ${x.sev}, ${x.seen.flux ? "des fiches de membres sortent vers 203.0.113.66" : "un serveur parle à une adresse inconnue"}. Je confine, je préserve les preuves, je te tiens au courant.`);
      if (x.t <= 60) tr("direction", 10, "informée tôt, en fait et pas en rumeur."); else if (x.t <= 150) tr("direction", 3, "informée, un peu tard."); else tr("direction", -8, "informée trop tard : elle l'apprend presque par la presse.");
      lg("Direction (Maître Ada) informée", "direction informée"); note("comm"); return;
    }
    if (who === "equipe") {
      if (x.told.equipe !== undefined) { out("L'équipe est déjà informée.", "sys"); return; }
      x.told.equipe = x.t; adv(5);
      out("Message interne : « Un incident de sécurité est en cours sur un serveur. Les équipes techniques s'en occupent. Ne commentez pas à l'extérieur, adressez toute question à la porte-parole. »", "ok");
      if (x.rumor) tr("equipe", 3, "l'information officielle arrive, mais après la rumeur."); else tr("equipe", 10, "informée avant que la rumeur ne s'installe.");
      lg("Équipe informée par message interne", "équipe informée"); note("comm"); return;
    }
    if (who === "autorite" || who === "membres") {
      if (S.room !== "bureau") { out("Les déclarations officielles se rédigent au bureau juridique (ouest de la cellule).", "sys"); return; }
      if (x.aware === undefined) { out(who === "autorite" ? "Quelle violation ? Rien n'est encore confirmé : sans fuite de données personnelles avérée, il n'y a rien à notifier." : "Personne n'a encore de raison d'être alerté : la fuite n'est pas confirmée.", "err"); return; }
    }
    if (who === "autorite") {
      if (x.told.autorite !== undefined) { out("L'autorité est déjà notifiée.", "sys"); return; }
      const el = x.t - x.aware, left = LIMIT - el;
      x.told.autorite = x.t; x.autT = x.t; adv(15);
      const lines = ["NOTIFICATION DE VIOLATION DE DONNÉES PERSONNELLES (art. 33 RGPD) : CNIL",
        `Prise de connaissance : ${clk(x.aware)}`, `Notification           : ${clk(x.t)}  (${dur(el)} après, il restait ${left >= 0 ? dur(left) : "rien"} sur 72 h)`,
        "Nature      : accès non autorisé au serveur « registre », puis exfiltration de la base des membres",
        `Catégories  : identité, e-mail, adresse postale · personnes concernées : ${TOTAL} (au plus)`,
        `Ampleur     : ${expShow()} fiches sorties${x.expFinal === undefined ? " à ce jour (fuite en cours : notification initiale, complétée ensuite)" : " (fuite stoppée à " + hm(x.isoT) + ")"}`,
        "Conséquences probables : hameçonnage ciblé, usurpation d'identité",
        `Mesures     : ${x.expFinal !== undefined ? "serveur isolé" : "isolement en cours"}${x.blocked.any ? ", adresse malveillante bloquée" : ""}, preuves préservées, analyse en cours`,
        "Contact     : Alice, déléguée à la protection des données"];
      code(lines.join("\n"));
      if (left < 0) { x.late = true; out("Délai de 72 heures dépassé : tu devras justifier le retard.", "err"); tr("autorite", -20, "notification tardive."); }
      else out(`Dans les temps : notifiée à ${dur(el)} sur 72 h. Le RGPD permet de notifier en plusieurs temps : on envoie ce qu'on sait, on complète ensuite.`, "ok");
      if (!x.called.juridique) { x.pen.declSolo = true; tr("autorite", -8, "déclaration rédigée sans la juriste : champs imprécis."); } else tr("autorite", 8, "déclaration claire, rédigée avec la DPO.");
      lg(`Autorité (CNIL) notifiée, ${dur(el)} après la prise de connaissance`, "autorité notifiée"); note("legal"); fig("chrono"); return;
    }
    if (who === "membres") {
      if (x.told.membres !== undefined) { out("Les membres sont déjà informés.", "sys"); return; }
      x.told.membres = x.t; adv(10);
      if (!x.called.communication) { x.pen.voices = true; tr("membres", -8, "plusieurs voix sans porte-parole désigné : les messages se contredisent."); }
      if (x.told.autorite === undefined) { x.pen.order = true; tr("autorite", -8, "les membres sont informés avant elle."); }
      if (x.expFinal === undefined) { x.pen.incomplete = true; tr("membres", -5, "message prématuré : tu ne peux pas encore dire ce qui est stoppé."); }
      code(`Objet : incident de sécurité sur les données des membres de la Guilde\n— Ce qui s'est passé : un accès non autorisé au registre, dans la nuit du 13 au 14 octobre.\n— Données concernées : nom, e-mail, adresse postale (pas de moyen de paiement).\n— Ce que nous avons fait : serveur isolé, accès de l'attaquant supprimés, autorité informée.\n— Ce que vous devez faire : méfiez-vous des messages inattendus se réclamant de la Guilde, ne cliquez sur aucun lien, changez vos mots de passe si vous les avez réutilisés.\n— Contact : ${x.porte || "(pas de porte-parole désigné)"}, porte-parole de la Guilde.`);
      out("Message factuel : ce que l'on sait, ce qui est fait, ce que chacun doit faire.", "ok"); tr("membres", 8, "informés directement et franchement, avec des gestes concrets.");
      lg("Membres informés (article 34)", "membres informés"); note("comm"); return;
    }
    if (who === "presse") {
      if (x.told.presse !== undefined) { out("Un communiqué est déjà paru.", "sys"); return; }
      x.told.presse = x.t; adv(5);
      if (!x.called.communication) { x.pen.voices = true; tr("membres", -6, "qui parle au nom de la Guilde ? Plusieurs voix contradictoires."); }
      if (x.told.membres === undefined) { x.pen.press = true; tr("membres", -12, "ils apprennent la fuite par la presse avant de l'apprendre de toi."); }
      else tr("membres", 2, "communiqué bref, cohérent avec le message envoyé aux membres.");
      lg("Communiqué de presse publié", "communiqué de presse"); note("comm");
    }
  }
  function retexCmd() {
    const x = F();
    if (S.room !== "cellule") { out("Le retour d'expérience se tient à la cellule.", "sys"); return; }
    if (!x.monitored) { say("Maître Ada", "Pas encore : la crise n'est pas close tant que la surveillance renforcée n'est pas terminée."); return; }
    if (!x.told.autorite) { say("Maître Ada", "On ne clôt pas avant d'avoir notifié l'autorité : c'est une obligation légale avec un délai."); out(remain() !== null ? `(Il reste ${dur(remain())} sur 72 h.)` : "", "sys"); return; }
    if (!x.told.membres) { say("Maître Ada", "Les membres dont les données ont fui doivent être informés (risque élevé) : `notifier membres`, au bureau juridique."); return; }
    x.retex = true; note("retex");
    out("Retour d'expérience (post-mortem, sans chercher de coupable)", "title");
    out("Chronologie :", "sys"); code(x.log.filter(e => e.k).map(e => `${clk(e.t)}  ${e.k}`).join("\n"));
    const d = (a, b) => dur(Math.max(0, b - a));
    out("Délais :", "sys");
    code([`Détection : ${d(-50, 0)} entre le début de la fuite (02:10) et l'alerte (03:00)`, `Qualification : ${dur((x.log.find(e => /qualifié/.test(e.k)) || { t: 0 }).t)} après l'alerte`, `Confinement : ${d(0, x.isoT)} après l'alerte`, `Fiches exposées : ${expShow()} sur ${TOTAL}`, `Notification à l'autorité : ${d(x.aware, x.autT)} après la prise de connaissance`].join("\n"));
    say("Maître Ada", "Chercher un coupable ne répare rien. Cherchons ce qui, dans notre organisation, a rendu cette nuit possible. Trois actions, pas plus, choisies avec leur responsable et leur échéance.");
    out("Actions proposées :", "sys");
    out(RETEX.map(([n, tx]) => `${n}. ${tx}`).join("\n"), "");
    out("`adopter ‹n›` pour retenir une action (trois bonnes suffisent).", "sys");
  }
  const RETEX = [
    [1, "Inventorier les services exposés à Internet et appliquer les correctifs de manière suivie, avec des scans de vulnérabilités réguliers."],
    [2, "Sanctionner l'administrateur qui n'a pas appliqué le correctif."],
    [3, "Réduire les droits des comptes de service, un secret distinct par compte, avec rotation planifiée."],
    [4, "Alerter sur toute création de compte et sur les gros volumes sortants des serveurs ; répéter l'exercice de crise chaque trimestre."],
    [5, "Acheter un nouvel antivirus et classer le dossier."],
    [6, "Conserver des sauvegardes hors ligne et tester régulièrement la restauration."],
    [7, "Ne rien dire de plus aux membres pour ne pas les inquiéter."],
  ];
  const GOOD = [1, 3, 4, 6];
  function adoptCmd(c) {
    const x = F(), n = +((c.rawArg.match(/\d/) || [])[0]);
    if (!x.retex) { out("Pas encore de retour d'expérience en cours : `retex` à la cellule.", "sys"); return; }
    if (!(n >= 1 && n <= 7)) { out("Quelle action ? `adopter ‹n›` (1 à 7).", "err"); return; }
    if (x.adopted.includes(n)) { out("Déjà retenue.", "sys"); return; }
    if (!GOOD.includes(n)) {
      x.retexBad++;
      const why = { 2: "Une sanction ne corrige rien : l'oubli d'un correctif vient d'un processus (pas d'inventaire, pas de suivi), pas d'un individu. Et la fois suivante, on cachera l'erreur.", 5: "Un outil de plus ne répond à aucune des causes observées (faille non corrigée, droits excessifs, détection tardive). Classer le dossier, c'est se préparer à le rouvrir.", 7: "Se taire laisse la rumeur parler à ta place, et la loi impose d'informer les personnes en cas de risque élevé. La transparence est un devoir, pas une option." }[n];
      out("Refusé par Maître Ada. " + why, "err"); return;
    }
    x.adopted.push(n); adv(10);
    out(`Action ${n} retenue : « ${RETEX[n - 1][1]} » Responsable et échéance fixés.`, "ok");
    if (x.adopted.length >= 3) ending();
    else out(`${x.adopted.length}/3 actions retenues.`, "sys");
  }

  /* ---------- score, épilogue, bilan ---------- */
  function score() {
    const x = F(), L = [];
    let a = x.sev ? Math.max(0, 6 - 2 * x.badQual) : 0; if (x.evid) a += 4; L.push(["Détection et qualification", a, 10]);
    let b = 0; if (x.method === "isoler") b += 6; else if (x.method === "eteindre") b += x.lost.memoire ? 1 : 3;
    if (x.blocked.any) b += 4; b -= (x.pen.courrier ? 2 : 0) + (x.pen.sauvegardes ? 2 : 0) + (x.pen.bk ? 2 : 0) + (x.spread && !contained(x.m.sauvegardes) ? 2 : 0); L.push(["Confinement (méthode)", Math.max(0, Math.min(10, b)), 10]);
    L.push(["Exposition des données", Math.max(0, Math.min(15, Math.round(15 * (TOTAL - Math.min(TOTAL, expNow())) / (TOTAL - BASE)))), 15]);
    let p = 0; if (x.img.memoire) p += x.img.memoire.stale || x.tamper.memoire ? 4 : 8; if (x.img.disque) p += x.tamper.disque ? 2 : 4; if (imgIds().length && allCons()) p += 4; if (imgIds().length && allAna() && !x.tamper.memoire && !x.tamper.disque) p += 4;
    L.push(["Preuves et chaîne de possession", Math.min(20, p), 20]);
    let e = x.reinf === 0 ? 10 : x.reinf === 1 ? 6 : 3; if (!x.badBackup) e += 4; if (!x.brusque) e += 3; e += x.reinf ? 1 : 3; L.push(["Éradication et reprise", Math.min(20, e), 20]);
    let m = 0; if (x.told.autorite !== undefined && !x.late) m += 8; if (x.told.direction !== undefined) m += x.told.direction <= 60 ? 3 : x.told.direction <= 150 ? 1 : 0;
    m += 5 - (x.pen.voices ? 2 : 0) - (x.pen.order ? 1 : 0) - (x.pen.press ? 2 : 0) - (x.pen.incomplete ? 1 : 0) - (x.pen.declSolo ? 1 : 0); m += x.rumor ? 1 : 4; L.push(["Communication et notification", Math.max(0, Math.min(20, m)), 20]);
    L.push(["Retour d'expérience et journal", Math.max(0, 3 - x.retexBad) + Math.min(2, x.manual || 0), 5]);
    return L;
  }
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Il est " + hm(x.t) + ". L'incident est clos : le serveur est reconstruit et surveillé, l'autorité et les membres ont été informés dans les formes, et la Guilde sait mieux dans quel ordre agir. Personne n'a été désigné coupable, et c'est pour cela que la prochaine fois, on nous dira plus tôt qu'un serveur parle à une adresse inconnue.");
    const L = score(), tot = L.reduce((s, r) => s + r[1], 0);
    out("Score final", "title");
    code(L.map(r => `${r[0].padEnd(34)} ${String(r[1]).padStart(2)} / ${r[2]}`).join("\n") + `\n${"".padEnd(34, "─")} ─────\n${"Total".padEnd(34)} ${String(tot).padStart(2)} / 100`);
    out(`Durée de la crise : ${dur(x.t)} · fiches exposées : ${expShow()} sur ${TOTAL} · confiance moyenne : ${Math.round((x.tr.direction + x.tr.equipe + x.tr.membres + x.tr.autorite) / 4)} / 100${x.reinf ? " · réinfections : " + x.reinf : ""}.`, "sys");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La cellule de crise = l'organisation de la réponse à incident.** Un chef qui décide, des rôles clairs (technique, juridique, communication, direction), un plan écrit, une liste d'appel et un journal horodaté. Elle suit un cycle : préparation, détection et qualification, confinement, éradication, reprise, retour d'expérience (NIST SP 800-61 ; SANS PICERL).");
    out("**L'horloge de la crise = le temps de détection et de réaction.** Les fiches sortaient à un rythme constant : chaque minute avant l'isolement a un coût mesurable. Les équipes mesurent ces délais (détection, qualification, confinement) pour s'améliorer. Mallory est l'intruse ; Ève, qui écoute, c'est tout le trafic sortant qu'on n'observait pas : l'adresse 203.0.113.66 (plage réservée à la documentation, donc fictive) était la destination d'un canal de commande et de contrôle.");
    out("**Isoler contre éteindre.** Isoler coupe la fuite et la propagation tout en gardant la machine sous tension ; éteindre efface la mémoire vive (processus, connexions, clés, identifiants chargés). La mémoire t'a appris ce que le disque ne disait pas : trois identifiants lus, dont celui de la sauvegarde. Nuance réelle : certains logiciels malveillants réagissent à la perte de réseau, et l'extinction peut être un bon choix une fois la mémoire copiée.");
    out("**L'ordre de volatilité (RFC 3227) et la chaîne de possession.** On capture d'abord ce qui disparaît le plus vite : registres et cache, mémoire, fichiers temporaires, disque, journaux distants, sauvegardes. On empreinte (SHA-256, ici réel) chaque image, on consigne qui l'a eue, quand et où, on travaille sur une copie dont l'empreinte est identique, et on contrôle que l'original n'a pas bougé. Ouvrir l'original en écriture modifie ses horodatages et ruine sa valeur probante.");
    out("**L'éradication : trois choses.** La persistance (compte svc-maint, tâche maj-agent, programme agent.bin), la porte d'entrée (le panneau d'administration non corrigé) et les secrets lus (base, sauvegarde). Oublier l'une des trois, c'est être réinfecté. Bloquer 203.0.113.66 ne suffit pas : Mallory est revenue de 203.0.113.99 quand il restait une faille.");
    out("**La reprise.** On restaure depuis une sauvegarde antérieure à l'intrusion (lundi 22:47), pas la plus récente : une empreinte conforme prouve l'intégrité du fichier, pas sa propreté. On remet en service par paliers (10, 50, 100 %) pour limiter les dégâts d'un raté, puis on surveille avec des règles de détection construites sur l'incident.");
    out("**La communication et la loi.** Direction vite, équipe avant les rumeurs, un seul porte-parole, les personnes concernées avant la presse. Le RGPD impose de notifier l'autorité (en France, la CNIL) dans les 72 heures après la prise de connaissance (art. 33), d'informer les personnes si le risque est élevé (art. 34) et de documenter toute violation (art. 33.5). Le jeu calcule le délai restant à partir du moment où la fuite est confirmée.");
    out("**Le retour d'expérience sans coupable.** Chronologie factuelle, causes systémiques (correctif manquant, droits excessifs, détection tardive), quelques actions avec responsable et échéance. Sanctionner l'administrateur fait cacher les erreurs la fois suivante.");
    out("**Les simplifications du jeu.** (1) Le temps est compressé : une crise réelle dure des jours et mobilise des dizaines de personnes, avec prestataires de réponse à incident, assurance, parfois police et CERT-FR. (2) Les images forensiques sont symboliques, seul le SHA-256 est réel ; une vraie acquisition de mémoire passe par des outils dédiés et dure plus longtemps. (3) Le choix « à notifier ou non » est simplifié : on évalue le risque pour les personnes, et certaines violations n'ont pas à être notifiées. (4) Un seul serveur est vraiment touché ; en réalité, on cherche l'étendue avec des journaux et des indicateurs sur tout le parc. (5) D'autres obligations existent selon le secteur (NIS 2, contrats, assurance), non abordées ici.");
    out("Rappel utile : **contiens vite sans effacer les preuves, documente tout, notifie dans les délais, parle d'une seule voix, et cherche des causes, pas des coupables.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    cycle: () => {
      const p = phaseIdx(), P = [["1 Préparation", "plan, rôles, appels", 10, 20], ["2 Détection", "triage, gravité", 150, 20], ["3 Confinement", "isoler, preuves", 290, 20], ["4 Éradication", "persistance, secrets", 290, 110], ["5 Reprise", "restaurer, surveiller", 150, 110], ["6 Retour d'exp.", "sans coupable", 10, 110]];
      return {
        cap: "Le cycle de vie d'un incident (NIST SP 800-61 / SANS). En orange : la phase où tu te trouves ; en vert : les phases déjà franchies. Le retour d'expérience nourrit la préparation suivante.",
        svg: SVG(222, "Cycle de vie d'un incident",
          P.map((b, i) => R(b[2], b[3], 120, 56, i < p ? "f-ok" : i === p ? "f-priv" : "") + T(b[2] + 60, b[3] + 24, b[0], "f-b " + (i === p ? "ft-priv" : i < p ? "ft-ok" : "")) + T(b[2] + 60, b[3] + 42, b[1], "f-s")).join("") +
          AR(130, 48, 150, 48) + AR(270, 48, 290, 48) + AR(350, 76, 350, 110) + AR(290, 138, 270, 138) + AR(150, 138, 130, 138) + `<line x1="70" y1="110" x2="70" y2="76" class="f-ln f-dash" marker-end="url(#fa)"/>` +
          T(210, 190, "Phase actuelle : " + PH[p], "f-b ft-priv") + T(210, 210, "chaque incident améliore le plan suivant", "f-s"))
      };
    },
    volatilite: () => {
      const x = F(), rows = [["Registres, cache du processeur", "nanosecondes"], ["Mémoire, processus, connexions", "efface à l'extinction"], ["Fichiers temporaires", "minutes à heures"], ["Disque", "persistant"], ["Journaux distants, supervision", "selon rétention"], ["Sauvegardes, archives", "années"]];
      const mark = i => { if (i === 1) return x.img.memoire ? [x.img.memoire.stale ? "~ dégradée" : "✔ copiée", x.img.memoire.stale ? "ft-bad" : "ft-ok"] : x.lost.memoire ? ["✘ perdue", "ft-bad"] : null; if (i === 3) return x.img.disque ? ["✔ copié", "ft-ok"] : x.lost.disque ? ["✘ perdu", "ft-bad"] : null; return null; };
      return {
        cap: "Ordre de volatilité (RFC 3227) : on capture d'abord ce qui disparaît le plus vite. Ici, la mémoire vive du registre passait avant son disque.",
        svg: SVG(252, "Ordre de volatilité des preuves",
          rows.map((r, i) => { const y = 12 + i * 36, m = mark(i); return R(96, y, 314, 30, m && m[1] === "ft-ok" ? "f-ok" : m ? "f-bad" : "") + T(106, y + 13, (i + 1) + ". " + r[0], "f-b", "start") + T(106, y + 25, r[1], "f-s", "start") + (m ? T(400, y + 19, m[0], m[1] + " f-b", "end") : ""); }).join("") +
          T(46, 10, "volatil", "f-s ft-bad") + AR(46, 226, 46, 24, "f-bad") + T(46, 244, "durable", "f-s ft-ok"))
      };
    },
    chrono: () => {
      const x = F(), r = remain(), el = x.aware === undefined ? 0 : Math.min(LIMIT, x.t - x.aware), w = Math.round(400 * el / LIMIT);
      const ev = x.log.filter(e => e.k).slice(-8);
      return {
        cap: x.aware === undefined ? "Chronologie de la crise : l'horloge tourne dès l'alerte. Le délai légal de 72 h ne démarre qu'à la prise de connaissance d'une violation confirmée." : "Chronologie de la crise. La barre montre le délai légal de 72 h consommé depuis la prise de connaissance ; en dessous, les derniers jalons du journal.",
        svg: SVG(100 + ev.length * 17, "Chronologie de la crise",
          T(10, 16, "Heure : " + clk(x.t) + "  (alerte + " + dur(x.t) + ")", "f-b", "start") +
          R(10, 28, 400, 18) + (w ? `<rect x="10" y="28" width="${Math.max(6, w)}" height="18" rx="6" fill="${el > LIMIT * 0.8 ? "var(--bad)" : "var(--ok)"}" opacity=".55"/>` : "") +
          T(10, 62, x.aware === undefined ? "délai de 72 h : pas encore déclenché" : "72 h depuis " + clk(x.aware) + (r >= 0 ? " : reste " + dur(r) : " : DÉPASSÉ"), "f-s ft-" + (x.aware !== undefined && r < 0 ? "bad" : "pub"), "start") +
          ev.map((e, i) => T(10, 90 + i * 17, clk(e.t) + "  " + e.k, "f-s", "start")).join("") +
          LN(10, 74, 410, 74, "f-dash"))
      };
    },
    gravite: () => {
      const x = F(), V = [[2, 3, 4], [1, 2, 3], [1, 1, 2]], cur = [0, x.spread ? 2 : 1];
      const cls = v => v === 1 ? "f-ok" : v === 2 ? "" : v === 3 ? "f-priv" : "f-bad";
      let g = "";
      V.forEach((row, ri) => row.forEach((v, ci) => { g += R(122 + ci * 96, 38 + ri * 44, 92, 40, cls(v)) + T(168 + ci * 96, 64 + ri * 44, String(v), "f-b"); }));
      g += `<rect x="${122 + cur[1] * 96 - 2}" y="${38 + cur[0] * 44 - 2}" width="96" height="44" rx="8" fill="none" stroke="var(--ink)" stroke-width="3"/>`;
      return {
        cap: "Matrice de gravité : impact × étendue. Le cadre noir marque la situation de la Guilde cette nuit (impact élevé : données personnelles ; un serveur, puis deux si l'attaquant rebondit).",
        svg: SVG(262, "Matrice de gravité",
          ["1 poste", "1 service", "plusieurs"].map((t, i) => T(168 + i * 96, 28, t, "f-s")).join("") + T(168 + 96, 15, "étendue", "f-s ft-pub") +
          ["Impact élevé", "Impact moyen", "Impact faible"].map((t, i) => T(114, 62 + i * 44, t, "f-s", "end")).join("") +
          g + T(10, 182, "1 mineur : traité en routine", "f-s", "start") + T(10, 198, "2 modéré : équipe technique, information", "f-s", "start") + T(10, 214, "3 majeur : cellule de crise, DPO, direction", "f-s", "start") + T(10, 230, "4 critique : tout le monde, communication externe, autorités", "f-s", "start") +
          T(10, 252, "Gravité retenue : " + (x.sev ? x.sev : "pas encore qualifiée"), "f-b ft-priv", "start"))
      };
    },
    custody: () => {
      const x = F(), k = x.img.disque ? "disque" : x.img.memoire ? "memoire" : null;
      const orig = k && x.cust.find(e => e.type === "hash" && e.k === k && !e.copy), cp = k && x.cp[k];
      const h = k && x.img[k] ? sha256(evContent(k)) : null;
      const steps = [
        ["1 Capture", k ? EVN[k] + " copiée, " + clk(x.img[k].t) : "(à faire)", !!k],
        ["2 Empreinte SHA-256", h ? h.slice(0, 40) + "…" : "(à calculer)", !!h],
        ["3 Consignée au registre", orig ? clk(orig.t) + " : " + orig.h.slice(0, 16) + "…" : "(à consigner)", !!orig],
        ["4 Copie de travail", cp ? "empreinte identique : " + sha256(cp.c).slice(0, 16) + "…" : "(à dupliquer)", !!cp],
        ["5 Analyse", cp && cp.ana ? "faite sur la copie, original intact" : "sur la copie seulement", !!(cp && cp.ana)],
      ];
      return {
        cap: "La chaîne de possession : chaque étape est datée et vérifiable, et l'empreinte SHA-256 prouve que l'image n'a pas changé entre la capture et l'analyse.",
        svg: SVG(222, "Chaîne de possession",
          steps.map((s, i) => R(10, 10 + i * 40, 400, 34, s[2] ? "f-ok" : "") + T(20, 25 + i * 40, s[0], "f-b " + (s[2] ? "ft-ok" : ""), "start") + T(20, 39 + i * 40, s[1], "f-s", "start")).join(""))
      };
    },
  };

  GAMES.incident = {
    id: "incident", order: 22, title: "La Cellule de Crise", pageTitle: "Incident Quest", subtitle: "aventure textuelle · gestion d'incident de sécurité",
    blurb: "À 3 h du matin, un serveur parle à une adresse inconnue : confine, préserve les preuves, notifie dans les 72 h, reprends.",
    concept: "Gestion d'incident de sécurité",
    start: "cellule", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      Object.assign(F(), {
        t: 0, quest: false, plan: false, called: {}, seen: {}, told: {}, found: {}, done: {}, img: {}, cp: {}, lost: {}, tamper: {}, cust: [], log: [], pen: {},
        tr: { direction: 70, equipe: 70, membres: 70, autorite: 70 }, blocked: {}, restored: 0, reprise: 0, reinf: 0, extraExp: 0, badQual: 0, retexBad: 0, adopted: [],
        m: { registre: { on: true, net: true }, courrier: { on: true, net: true }, sauvegardes: { on: true, net: true, comp: false } },
      });
      lg("Alerte reçue : le registre parle à 203.0.113.66", "alerte reçue");
    },
    refig(name) { fig(name); },
    figAlias: { cycle: ["cycle de vie", "phases", "nist"], volatilite: ["preuves", "ordre", "volatil"], chrono: ["chronologie", "horloge", "temps"], gravite: ["matrice", "severite"], custody: ["possession", "chaine", "empreinte"] },
    give(item, who) { return giveEv(item, who); },
    help: "Spécifiques : `statut` · `journal [texte]` · `appeler ‹role›` · `analyser ‹piste›` · `qualifier ‹n›` · `isoler|eteindre ‹machine›` · `copier ‹machine›` · `hacher|consigner|dupliquer|controler ‹preuve›` · `bloquer ‹ip›` · `retirer ‹élément›` · `patcher` · `changer secrets` · `restaurer` · `reprendre ‹%›` · `surveiller` · `notifier ‹qui›` · `retex` · `adopter ‹n›`",
    verbs: {
      status: { words: ["statut", "etat", "situation", "heure", "horloge"], run: statusCmd },
      journal: { words: ["journal", "log"], run: journalCmd },
      call: { words: ["appeler", "contacter", "joindre", "reveiller"], run: callCmd },
      analyse: { words: ["analyser", "investiguer", "trier"], run: analyseCmd },
      qualify: { words: ["qualifier", "classer", "evaluer"], run: qualifyCmd },
      isolate: { words: ["isoler", "deconnecter", "quarantaine"], run: isolateCmd },
      reconnect: { words: ["reconnecter", "rebrancher"], run: reconnectCmd },
      off: { words: ["eteindre", "arreter", "debrancher"], run: powerOffCmd },
      copy: { words: ["copier", "acquerir", "imager"], run: copyCmd },
      hash: { words: ["hacher", "empreinte", "sha"], run: hashCmd },
      consign: { words: ["consigner", "enregistrer"], run: consignCmd },
      control: { words: ["controler", "recalculer"], run: controlCmd },
      dup: { words: ["dupliquer", "cloner"], run: dupCmd },
      block: { words: ["bloquer", "filtrer"], run: blockCmd },
      remove: { words: ["retirer", "supprimer", "nettoyer", "desactiver"], run: removeCmd },
      patch: { words: ["patcher", "corriger", "colmater"], run: patchCmd },
      secrets: { words: ["changer", "renouveler", "tourner"], run: secretsCmd },
      restore: { words: ["restaurer", "rebatir"], run: restoreCmd },
      resume: { words: ["reprendre", "rouvrir", "basculer"], run: resumeCmd },
      monitor: { words: ["surveiller", "veiller"], run: monitorCmd },
      notify: { words: ["notifier", "prevenir", "informer", "avertir", "alerter"], run: notifyCmd },
      retex: { words: ["retex", "postmortem", "post mortem"], run: retexCmd },
      adopt: { words: ["adopter", "retenir"], run: adoptCmd },
    },
    intro() {
      out("La Cellule de Crise", "title");
      out("Port-443, mardi 14 octobre, 03:00. Ton téléphone vibre : l'alerte du centre de supervision est tombée. Un serveur de la Guilde, le « registre », celui qui contient les fiches de tous les membres, parle à une adresse inconnue.\nMaître Ada te nomme chef de la cellule de crise. Tu as une horloge qui tourne, un plan de réponse, quatre personnes à joindre et un adversaire, Mallory, qui n'attend pas. Chaque décision a des conséquences calculées : le temps écoulé, les données exposées, les preuves préservées ou détruites, la confiance des parties prenantes. Rien n'est un QCM : le jeu simule vraiment ce que tu fais.", "");
    },
  };
})();
