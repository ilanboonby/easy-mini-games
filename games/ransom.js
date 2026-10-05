"use strict";
/* La Cité Verrouillée : réponse à un rançongiciel (scénarisé), sauvegardes 3-2-1-1-0, RPO/RTO, prévention.
   Aucun code offensif : la « charge » n'est qu'un événement du scénario ; les contenus sont des données fictives du jeu. */
(function () {
  const F = () => f();

  /* ---------- Données fictives et calculs réels ---------- */
  const NOMS = ["Aelis", "Brun", "Cassel", "Dorel", "Elwen", "Fauré", "Garnier", "Halvar", "Iseult", "Jorel"];
  const pad = n => String(n).padStart(3, "0");
  const GEN = {
    membres: i => `membre ${pad(i)} ; ${NOMS[i % 10]} ${NOMS[(i * 3 + 1) % 10]} ; grade ${["novice", "scribe", "maître"][i % 3]} ; cotisation ${i % 7 === 0 ? "en retard" : "à jour"}`,
    comptes: i => `écriture ${pad(i)} ; ${NOMS[i % 10]} ; ${100 + (i * 37) % 900} écus ; ${i % 2 ? "crédit" : "débit"}`,
    chartes: i => `article ${i} : la Guilde s'engage à ${["protéger", "former", "auditer", "partager", "documenter"][i % 5]} les savoirs du port ${i}`,
    affiche: i => ["Banquet de la Guilde", "Samedi, à la tombée du jour", "Salle des fêtes de Port-443", "Apportez votre plat", "Ada fera un discours", "Bob chantera", "Entrée libre", "Soupe offerte", "Fin vers minuit", "Merci de votre présence", "Port-443 vous attend", "À samedi !"][i % 12],
  };
  const NLIGNES = { membres: 60, comptes: 50, chartes: 30, affiche: 12 };
  const NLIGNES_ANCIEN = { membres: 52, comptes: 44, chartes: 30 };
  const SIZE_GO = { membres: 240, comptes: 280, chartes: 20 };
  const VOLUME = 540; // Go : 240 + 280 + 20
  const REG = ["membres", "comptes", "chartes"];
  const plain = (file, n) => Array.from({ length: n || NLIGNES[file] }, (_, i) => GEN[file](i + 1)).join("\n");
  const memo = {};
  // « contenu chiffré » : octets pseudo-aléatoires dérivés de SHA-256 (simple décor : ce n'est PAS un vrai chiffrement de fichier)
  function noise(key) {
    if (memo[key]) return memo[key];
    let s = ""; for (let i = 0; i < 64; i++) { const h = sha256(key + i); for (let j = 0; j < 64; j += 2) s += String.fromCharCode(parseInt(h.slice(j, j + 2), 16)); }
    return (memo[key] = s);
  }
  function entropy(s) {
    const m = {}; let n = 0;
    for (const ch of s) { m[ch] = (m[ch] || 0) + 1; n++; }
    let h = 0; for (const k in m) { const p = m[k] / n; h -= p * Math.log2(p); }
    return h;
  }
  const BASE = {}; REG.forEach(k => BASE[k] = sha256(plain(k)));
  const NOTE_TXT = "VOS REGISTRES SONT VERROUILLES.\nPour les récupérer : 40 000 écus en cryptomonnaie sous 72 heures.\nPassé ce délai, vos registres seront publiés.\nN'avertissez ni la Garde ni Maître Ada.\n(signé : Mallory)";

  const FILES = [
    { id: "membres", disp: "membres.reg", enc: true, get: () => noise("verrou-membres") },
    { id: "comptes", disp: "comptes.reg", enc: true, get: () => noise("verrou-comptes") },
    { id: "chartes", disp: "chartes.reg", enc: true, get: () => noise("verrou-chartes") },
    { id: "affiche", disp: "affiche.txt", get: () => plain("affiche") },
    { id: "sceaux", disp: "sceaux.zip", get: () => noise("archive-compressee-sceaux") },
    { id: "lisezmoi", disp: "LISEZMOI.txt", get: () => NOTE_TXT },
  ];
  const fname = fl => fl.disp + (fl.enc ? ".verrou" : "");

  /* ---------- Les quatre copies ---------- */
  const COPIES = {
    nas: { nom: "le NAS", type: "en ligne", etat: "chiffrée" },
    nuage: { nom: "le dossier synchronisé", type: "en ligne · hors site", etat: "effacée" },
    disque: { nom: "le disque hors ligne", type: "hors ligne · hors site", etat: "saine (ancienne)" },
    coffre: { nom: "le coffre immuable", type: "immuable · hors site", etat: "saine" },
  };
  // contenu d'un fichier tel qu'il se trouve dans une copie
  function getCopy(copy, file) {
    const x = F();
    if (copy === "nas") return noise("nas" + file);
    if (copy === "nuage") return noise("nuage" + file);
    if (copy === "disque") {
      if (x.cLost) return noise("disque-chiffre" + file);
      return file === "chartes" ? plain("chartes") : plain(file, NLIGNES_ANCIEN[file]);
    }
    if (copy === "coffre") return file === "chartes" ? plain("chartes", 17).slice(0, -22) : plain(file);
    if (copy === "papier") return plain(file);
    return "";
  }
  function judge(file, content) {
    if (entropy(content) > 7) return { k: "enc", t: "CHIFFRÉ (entropie très élevée)" };
    if (sha256(content) === BASE[file]) return { k: "ok", t: "conforme à l'empreinte du journal de 02h00" };
    const lines = content.split("\n"), full = plain(file).split("\n");
    if (!full.includes(lines[lines.length - 1])) return { k: "cut", t: `TRONQUÉ en pleine ligne (${lines.length} lignes sur ${NLIGNES[file]})` };
    return { k: "old", t: `ANCIENNE version (${lines.length} lignes au lieu de ${NLIGNES[file]})` };
  }
  const fmtDur = s => { const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = Math.round(s % 60); return h ? `${h} h ${String(m).padStart(2, "0")}` : m ? `${m} min ${String(r).padStart(2, "0")} s` : `${r} s`; };
  const RATE = { disque: 150, coffre: 50, papier: 0.0001 };

  const hostsHit = () => { const x = F(); return x.isolated ? x.hostsAtIso : Math.min(9, 1 + (x.t || 0)); };
  const tick = n => { const x = F(); if (!x.isolated) x.t = (x.t || 0) + (n || 1); };

  /* ---------- Carnet ---------- */
  const notes = {
    signes: ["Reconnaître une infection", "Trois signes se recoupent : des renommages massifs (extension inhabituelle sur des fichiers qui n'ont pas été touchés par un humain), une note de rançon déposée dans les dossiers, et une entropie très élevée : un fichier chiffré ressemble à du hasard (proche de 8 bits par octet) alors qu'un texte lisible reste autour de 4 à 5. Attention : un fichier légitimement compressé (zip, jpeg) a aussi une entropie élevée : seule, l'entropie ne prouve rien."],
    confiner: ["Confiner avant tout", "Premier réflexe : isoler du réseau (débrancher le câble, couper le Wi-Fi, bloquer la sortie vers Internet, déconnecter les sauvegardes en ligne) pour stopper la propagation et l'exfiltration. On n'éteint pas tout de suite : la mémoire vive contient des traces utiles à l'enquête. On ne paye pas d'emblée. Puis on reconstruit les machines depuis un média sain et on renouvelle les identifiants avant toute restauration."],
    copies: ["Sauvegarde en ligne, hors ligne, immuable", "Une sauvegarde en ligne (NAS monté, dossier synchronisé) est à la portée de l'attaquant dès qu'il obtient des droits d'administration : elle est chiffrée ou effacée, et la synchronisation réplique même les fichiers abîmés. Une copie hors ligne (déconnectée) ou immuable (écriture verrouillée pendant une durée fixée, impossible à modifier même pour un administrateur) survit, elle."],
    regle: ["La règle 3-2-1-1-0", "3 copies des données, sur 2 types de supports différents, dont 1 hors site ; plus 1 copie hors ligne ou immuable ; et 0 erreur : la restauration est vérifiée, pas seulement la sauvegarde. Les quatre derniers chiffres comptent surtout contre les rançongiciels : une copie que l'attaquant ne peut pas atteindre, et une preuve qu'elle est utilisable."],
    rporto: ["RPO et RTO", "RPO (Recovery Point Objective) : la quantité de données qu'on accepte de perdre, mesurée en temps entre la dernière copie saine et l'incident. RTO (Recovery Time Objective) : la durée maximale d'indisponibilité acceptée. Le temps de restauration se calcule : volume ÷ débit (attention aux Mbit/s, à diviser par 8 pour des Mo/s), plus les contrôles et la remise en service. Une copie rapide mais ancienne et une copie récente mais lente : on arbitre selon les objectifs."],
    test: ["Tester la restauration", "Une sauvegarde jamais restaurée n'est qu'une hypothèse. On teste dans un bac à sable isolé en comparant les empreintes (SHA-256) aux valeurs d'un journal d'intégrité : on découvre alors les copies tronquées ou périmées, avant le jour où l'on en a besoin. Le test se répète régulièrement."],
    nepayer: ["Ne pas payer", "Payer ne garantit rien : le déchiffreur peut être partiel, défaillant ou ne jamais arriver ; cela finance d'autres attaques, désigne l'organisation comme cible solvable (les attaquants reviennent), et ne règle pas l'exfiltration : les données volées peuvent être publiées quand même. On signale (plainte, équipe de réponse à incident, assureur, autorité de protection des données sous 72 h si des données personnelles sont en jeu) et on restaure depuis les sauvegardes. Des déchiffreurs publics existent parfois (projet No More Ransom)."],
    prevention: ["Prévention en profondeur", "Aucune mesure n'est parfaite : on en empile, chacune coupant une étape de la chaîne d'attaque. Sensibilisation (hameçonnage), mises à jour (failles connues), authentification multifacteur (identifiants volés), segmentation du réseau (propagation), moindre privilège (un compte de bureautique ne peut pas effacer les sauvegardes). Plus des copies hors ligne ou immuables et un plan de crise répété."],
  };

  /* ---------- Entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle garde son calme : « Dans une crise, on suit une procédure, on ne s'agite pas. »" },
    bob: { npc: true, names: ["bob"], label: "Bob", vis: () => S.room === "scriptorium", desc: () => "Bob, le scribe, pâle comme un parchemin. C'est lui qui a vu les fichiers en premier, ce matin." },
    eve: { npc: true, names: ["eve"], label: "Ève", vis: () => S.room === "carrefour", desc: () => "Ève, qui surveille les flux du réseau de la Guilde. Elle garde les journaux (et un journal des empreintes à 02h00)." },
    alice: { npc: true, names: ["alice"], label: "Alice", vis: () => S.room === "archives", desc: () => "Alice, l'archiviste responsable des sauvegardes. Elle est sûre que « tout était sauvegardé »." },
    mallory: { npc: true, names: ["mallory", "attaquante"], label: "le salon de négociation de Mallory", vis: () => S.room === "conseil", desc: () => "Un écran où la note de rançon renvoie vers un salon de discussion. Mallory, en face, a tout son temps." },
    registres: { names: ["registres", "registre", "fichiers", "dossier", "fichier"], label: "les registres de la Guilde", vis: () => S.room === "scriptorium",
      desc: () => { const x = F(); return "Les fichiers du dossier des registres :\n" + FILES.map(fl => `  · ${fname(fl)}`).join("\n") + "\n\nTrois fichiers portent l'extension « .verrou » que personne n'a ajoutée. Les autres (affiche.txt, sceaux.zip) semblent intacts.\n`mesurer ‹fichier›` calcule l'entropie d'un fichier ; `lire note` ouvre le message." + (x.isolated ? "" : "\nLe nombre de postes touchés augmente de minute en minute."); },
      onExamine: () => { F().listed = true; tick(); checkSigns(); } },
    note: { names: ["note", "lisezmoi", "rancon", "message", "parchemin"], label: "la note de rançon", vis: () => S.room === "scriptorium",
      desc: () => "LISEZMOI.txt, déposé dans chaque dossier :\n" + NOTE_TXT,
      onExamine: () => { F().read = true; tick(); checkSigns(); } },
    poste: { names: ["poste", "pupitre", "machine", "ordinateur"], label: "le pupitre de Bob (le poste touché)", vis: () => S.room === "scriptorium",
      desc: () => { const x = F(); return `Le pupitre de Bob, où tout a commencé. ${x.isolated ? `Isolé du réseau : ${x.hostsAtIso} postes sur 12 ont été touchés avant le confinement.` : `Il est encore relié au réseau : ${hostsHit()} poste${hostsHit() > 1 ? "s" : ""} sur 12 déjà touché${hostsHit() > 1 ? "s" : ""}, et ça continue.`}`; } },
    commutateur: { names: ["commutateur", "cables", "cable", "reseau", "armoire"], label: "l'armoire de brassage", vis: () => S.room === "carrefour",
      desc: () => { const i = F().iso || {}; return `L'armoire où arrivent tous les câbles de la Guilde. Trois zones à couper : les postes (\`isoler postes\`) ${i.postes ? "✔ isolés" : "✘ branchés"}, le NAS de sauvegarde (\`isoler nas\`) ${i.nas ? "✔ isolé" : "✘ branché"}, la sortie vers Internet (\`isoler sortie\`) ${i.sortie ? "✔ coupée" : "✘ ouverte"}. (\`isoler tout\` fait les trois.) Le salon du conseil, lui, n'est pas touché.`; } },
    journal: { names: ["journal", "empreintes", "journal d empreintes", "integrite"], label: "le journal d'empreintes de 02h00", vis: () => S.room === "carrefour" || S.room === "archives",
      desc: () => "Le journal d'intégrité d'Ève, enregistré à 02h00 (avant l'attaque) :\n" + REG.map(k => `  ${(k + ".reg").padEnd(13)} ${BASE[k].slice(0, 16)}…  ${plain(k).length} octets`).join("\n") + "\nIl sert de référence pour vérifier une restauration." },
    nas: { names: ["nas", "serveur de sauvegarde"], label: "le NAS (copie en ligne)", vis: () => S.room === "archives",
      desc: () => "Le NAS de la salle des serveurs, monté en permanence sur le réseau des postes. Dernière sauvegarde : 02h00. Mais les identifiants d'administrateur qui l'écrivent ont servi à l'attaquant : les fichiers y portent l'extension .verrou depuis 03h25." },
    nuage: { names: ["nuage", "dossier synchronise", "synchro", "synchronise"], label: "le dossier synchronisé (copie hors site, en ligne)", vis: () => S.room === "archives",
      desc: () => "Un dossier synchronisé avec un service en ligne, hors des murs de la Guilde. Dernière synchronisation : 07h00. La synchronisation est fidèle… aux fichiers chiffrés, qu'elle a copiés. Et l'historique des versions a été supprimé à 03h25 avec le compte administrateur." },
    disque: { names: ["disque", "disque hors ligne", "usb"], label: "le disque hors ligne", vis: () => S.room === "archives",
      desc: () => `Un disque rangé dans une armoire ignifugée, débranché de tout. Dernière sauvegarde complète : il y a 3 jours, 22h00 (J-3 22h00). Volume : ${VOLUME} Go. Débit de lecture USB : 150 Mo/s. ${F().cLost ? "ÉTAT : chiffré lors d'une connexion à un réseau compromis, inutilisable." : "Aucun accès possible pour l'attaquant : il n'était pas branché. Mais il est ancien."}` },
    coffre: { names: ["coffre", "coffre immuable", "immuable", "objet"], label: "le coffre immuable (copie WORM)", vis: () => S.room === "archives",
      desc: () => `Un stockage objet en mode immuable (écriture verrouillée 30 jours) chez un hébergeur. Dernière copie : 02h00 cette nuit. Même un administrateur ne peut ni modifier ni effacer une version verrouillée. Volume : ${VOLUME} Go. Liaison : 400 Mbit/s. Cette copie n'a jamais été testée.` },
    papier: { names: ["papier", "exemplaires papier", "grand livre"], label: "le Grand Livre papier", vis: () => S.room === "archives" && !!F().cLost,
      desc: () => "Les chartes de la Guilde, imprimées dans le Grand Livre. Les ressaisir à la main prendrait deux jours-personne." },
    etabli: { names: ["etabli", "atelier", "poste propre"], label: "l'établi de reconstruction", vis: () => S.room === "atelier",
      desc: () => { const x = F(); return `Un poste neuf, à réinstaller depuis un média de confiance.\n  · \`reconstruire poste\` : ${x.rebuilt ? "FAIT" : "à faire"}\n  · \`renouveler identifiants\` : ${x.creds ? "FAIT" : "à faire"}\nTant que les deux ne sont pas faits, restaurer (\`restaurer ‹copie›\`) serait risqué.`; } },
    tableau: { names: ["tableau", "mesures", "prevention"], label: "le tableau des mesures de prévention", vis: () => S.room === "atelier",
      desc: () => { const m = F().meas2 || {}; return "Mesures à déployer (\`durcir ‹mesure›\`) :\n" + Object.entries(MESURES).map(([k, v]) => `  · ${k.padEnd(16)} ${m[k] ? "✔ en place" : "à faire"} : ${v.court}`).join("\n") + "\n\n`simuler attaque` rejoue la chaîne d'attaque de ce matin contre tes défenses."; } },
  };

  const MESURES = {
    sensibilisation: { court: "former au hameçonnage", re: /sensib|form|phish|hame/, stage: 0, txt: "Séances de sensibilisation : Bob apprend à repérer les fausses factures et à signaler le courriel plutôt que de l'ouvrir. Cela réduit le risque, jamais à zéro." },
    "mises à jour": { court: "corriger les failles connues", re: /maj|jour|correct|patch/, stage: 1, txt: "Correctifs appliqués régulièrement : la faille connue exploitée pour s'installer est refermée avant que l'attaquant n'arrive." },
    mfa: { court: "second facteur partout", re: /mfa|multi|facteur|2fa/, stage: 2, txt: "Authentification multifacteur : un identifiant volé ne suffit plus ; l'attaquant ne peut pas se faire passer pour l'administrateur." },
    segmentation: { court: "cloisonner le réseau", re: /segment|cloison|reseau/, stage: 3, txt: "Segmentation : les postes de bureautique ne parlent plus aux serveurs ni entre eux sans besoin ; une infection reste dans son casier." },
    "moindre privilège": { court: "des droits minimaux", re: /privil|moindre|droit|admin/, stage: 4, txt: "Moindre privilège : le compte qui sert aux sauvegardes n'est plus celui qui administre le reste, et les sauvegardes exigent une approbation à part pour être effacées." },
  };
  const STAGES = [
    ["Hameçonnage : Bob ouvre une fausse facture", "Bob est averti et signale le courriel."],
    ["Installation via une faille déjà corrigée ailleurs", "La faille est corrigée : l'installation échoue."],
    ["Vol de l'identifiant administrateur", "Sans second facteur, l'attaquant n'a pas pu se connecter."],
    ["Propagation sur un réseau plat", "Le cloisonnement arrête la progression."],
    ["Effacement et chiffrement des sauvegardes en ligne", "Le compte compromis n'a pas les droits sur les sauvegardes."],
  ];

  /* ---------- Salles ---------- */
  const rooms = {
    scriptorium: { name: "Le scriptorium", short: "Scriptorium", alias: ["scriptorium", "scriptoria"], ents: ["ada", "bob", "registres", "note", "poste"],
      exits: { est: "carrefour", ouest: "archives", nord: "conseil", sud: "atelier" },
      desc: () => "La grande salle où les scribes tiennent les registres de la Guilde : membres, comptes, chartes. Ce matin, personne n'écrit : tous les regards sont fixés sur l'écran du pupitre de Bob. À l'est, le carrefour des câbles ; à l'ouest, les archives ; au nord, la salle du conseil ; au sud, l'atelier." },
    carrefour: { name: "Le carrefour des câbles", short: "Câbles", alias: ["carrefour", "cables", "reseau"], ents: ["eve", "commutateur", "journal"], exits: { ouest: "scriptorium" },
      desc: () => "Une armoire de brassage et des centaines de câbles : tout le réseau de la Guilde passe ici. Ève y garde ses journaux, les yeux sur des flux de données." },
    archives: { name: "Les archives", short: "Archives", alias: ["archives", "archive", "sauvegardes"], ents: ["alice", "nas", "nuage", "disque", "coffre", "papier", "journal"], exits: { est: "scriptorium" },
      desc: () => "Des rayonnages, un NAS qui ronronne, une armoire ignifugée et, au fond, un poste isolé de tout, le bac à sable, où l'on peut essayer une restauration (`tester ‹copie›`). Quatre copies des registres sont conservées ici ou ailleurs." },
    conseil: { name: "La salle du conseil", short: "Conseil", alias: ["conseil", "salle du conseil"], ents: ["mallory"], exits: { sud: "scriptorium" },
      desc: () => "Une table ronde. C'est ici que la Guilde décide dans une crise : payer ou non, qui prévenir, comment communiquer. Un écran affiche le salon de négociation de Mallory." },
    atelier: { name: "L'atelier", short: "Atelier", alias: ["atelier"], ents: ["etabli", "tableau"], exits: { nord: "scriptorium" },
      desc: () => "Un atelier d'artisans : un établi pour reconstruire un poste propre, un tableau où s'affichent les mesures de prévention." },
  };

  /* ---------- Objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.signs) return !x.listed ? "list" : !x.read ? "read" : "measure";
    if (!x.isolated) return "iso";
    if (!x.bkSeen) return "bk";
    if (!(x.tested && x.tested.disque && x.tested.coffre)) return "test";
    if (!x.rpo) return "rpo";
    if (!x.rto) return "rto";
    if (!x.decision) return "decide";
    if (!x.reported) return "report";
    if (!x.clean) return "clean";
    if (!x.recovered) return Object.keys(x.prod || {}).length ? "verify" : "restore";
    if (!x.prevAll) return "prev";
    if (!x.sim) return "sim";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend au scriptorium.", "`parler ada`"],
    list: () => ["Commence par regarder les fichiers touchés, au scriptorium.", "`examiner registres`"],
    read: () => ["Un message a été déposé dans les dossiers.", "`lire note`"],
    measure: () => ["L'entropie distingue un texte lisible d'un contenu qui ressemble à du hasard. Mesure un fichier renommé et un fichier lisible (et le zip, pour comparer).", "`mesurer membres`, `mesurer affiche`, `mesurer sceaux`"],
    iso: () => ["Chaque minute compte : coupe les zones touchées au carrefour des câbles (à l'est). Ne pas éteindre, ne pas payer.", "`aller est`, puis `isoler postes`, `isoler nas`, `isoler sortie` (ou `isoler tout`)."],
    bk: () => ["Va aux archives (à l'ouest du scriptorium) et examine chacune des quatre copies.", "`examiner nas`, `examiner nuage`, `examiner disque`, `examiner coffre`"],
    test: () => ["Une copie qui n'est pas testée n'est qu'une hypothèse. Aux archives, essaie les copies encore saines dans le bac à sable.", "`tester disque` puis `tester coffre`"],
    rpo: () => ["Quelle durée de données perdrait-on avec la meilleure copie ? Dernière copie saine : 02h00, début du chiffrement : 03h10 (journal d'Ève). Estime-le en minutes.", "`estimer rpo 70`"],
    rto: () => ["Volume 540 Go ; liaison 400 Mbit/s = 50 Mo/s (divise par 8). Durée de transfert + 1 h de contrôle et remise en service. Utilise `calc`.", "`calc 540*1000/50/3600` donne 3 h, donc `estimer rto 4`"],
    decide: () => ["Au conseil (au nord du scriptorium), Alice hésite : payer la rançon ? Décide.", "`aller nord`, puis `decider ne pas payer`"],
    report: () => ["Une crise se signale : prévenir les autorités et l'équipe de réponse. Toujours au conseil.", "`signaler`"],
    clean: () => ["Avant de restaurer, il faut un poste propre et des identifiants neufs. À l'atelier (au sud du scriptorium).", "`reconstruire poste` et `renouveler identifiants`"],
    restore: () => ["Restaure depuis la copie qui respecte les objectifs (RPO 24 h, RTO 8 h), à l'atelier, sur le poste reconstruit.", "`restaurer coffre`, puis `controler production`"],
    verify: () => ["Vérifie la production avec le journal d'empreintes. Si un fichier est en défaut, restaure-le depuis une autre copie saine (`restaurer ‹copie› ‹fichier›`).", "`controler production` ; si chartes est tronqué : `restaurer disque chartes`, puis `controler production`"],
    prev: () => ["À l'atelier, déploie les cinq mesures qui coupent chacune une étape de l'attaque.", "`durcir sensibilisation`, `durcir mises a jour`, `durcir mfa`, `durcir segmentation`, `durcir moindre privilege`"],
    sim: () => ["Mets tes défenses à l'épreuve : rejoue l'attaque de ce matin.", "`simuler attaque`"],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Réponse terminée ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- Dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Ce matin, Bob a trouvé tous nos registres avec une extension étrange, « .verrou », et une note exigeant une rançon. La Guilde a décidé de traiter cela comme un exercice grandeur nature : tout ce que tu vas manipuler est fictif, mais la procédure est celle d'une vraie crise.");
          say("Maître Ada", "Ton rôle : mener la réponse. D'abord reconnaître les signes avec méthode, puis confiner, évaluer nos sauvegardes, calculer ce que l'on perdrait et le temps qu'il faudrait, tester, décider, restaurer, enfin durcir. Commence par examiner les registres.");
          out("`examiner registres`", "sys");
        } else if (x.end) say("Maître Ada", "La Guilde est plus solide qu'avant la crise. Merci.");
        else if (objective() === "end") ending();
        else say("Maître Ada", { list: "Regarde les registres : `examiner registres`.", read: "Lis la note : `lire note`.", measure: "Mesure l'entropie : `mesurer ‹fichier›`.", iso: "Vite, au carrefour des câbles : `isoler tout`. On ne paye pas et on n'éteint pas.", bk: "Aux archives, examine nos quatre copies.", test: "Teste les copies saines dans le bac à sable : `tester ‹copie›`.", rpo: "Estime notre perte : `estimer rpo ‹minutes›`. Nos objectifs : RPO 24 h, RTO 8 h.", rto: "Estime la durée de restauration : `estimer rto ‹heures›`.", decide: "Le conseil attend ta décision.", report: "Il faut signaler l'incident : `signaler`, au conseil.", clean: "Atelier : poste reconstruit et identifiants renouvelés, avant toute restauration.", restore: "Restaure depuis la bonne copie, à l'atelier.", verify: "Contrôle la production : `controler production`.", prev: "Déploie les mesures de prévention.", sim: "Rejoue l'attaque : `simuler attaque`." }[objective()] || "`indice` si tu bloques.");
        break;
      case "bob":
        if (!x.quest) { say("Bob", "Je… je ne sais pas ce qui s'est passé."); break; }
        say("Bob", "Hier soir, j'ai ouvert une facture « urgente » reçue par courriel. Rien ne s'est passé sur le moment. Ce matin… tout est verrouillé. Je suis désolé.");
        say("Maître Ada", "Personne ne te reproche rien, Bob. Une chaîne d'attaque a besoin que PLUSIEURS défenses cèdent : le courriel n'est que la première. On cherche à renforcer le système, pas à désigner un coupable.");
        x.bob = true;
        break;
      case "eve":
        if (!x.quest) { say("Ève", "Passe voir Maître Ada d'abord."); break; }
        say("Ève", "J'écoute les flux. Voilà ce que disent mes journaux : entre 01h20 et 02h40, environ 2 Go sont sortis vers une adresse inconnue. À 03h10, début des renommages en masse. À 03h25, le NAS et l'historique du nuage sont touchés avec le compte administrateur. Détection à 07h40.");
        say("Ève", "Les 2 Go qui sont sortis, c'est de la double extorsion : même si tu restaures tout, ils peuvent menacer de publier. Et j'ai pris à 02h00 un journal des empreintes de nos registres : il nous servira à vérifier une restauration.");
        x.eve = true;
        if (!x.isolated) out("Il est urgent de couper : `isoler tout`.", "sys");
        break;
      case "alice":
        if (!x.quest) { say("Alice", "Bonjour."); break; }
        if (!x.bkSeen) say("Alice", "Rassure-toi : nous avons quatre copies. Un NAS, un dossier synchronisé dans le nuage, un disque rangé à la banque, et une copie immuable chez un hébergeur. Examine-les.");
        else if (!(x.tested && x.tested.coffre)) say("Alice", "La copie immuable, je ne l'ai jamais testée : le tableau de bord disait « succès » chaque nuit. Mais teste-la, c'est le bac à sable dans le fond de la salle.");
        else say("Alice", "Un tableau de bord vert ne prouve pas qu'on sait restaurer. J'ai compris.");
        break;
      case "mallory":
        if (!x.quest) break;
        if (x.paid) say("Mallory", "Merci pour le paiement. Si tu veux ce que tu as déjà : un déchiffreur qui marche presque. Et pour la suite : 80 000 écus, ou la publication. Les bons clients reviennent.");
        else say("Mallory", "Quarante mille écus et tout redevient comme avant. Vous êtes pressés, non ? Chaque heure sans registres vous coûte plus cher que ça.");
        out("(Mallory ne te dira jamais la vérité sur ce qu'elle a fait de tes données.)", "sys");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- Signes ---------- */
  function checkSigns() {
    const x = F(); if (x.signs) return;
    const m = x.meas || {};
    if (x.listed && x.read && REG.some(k => m[k]) && m.affiche) {
      x.signs = true;
      out("Les trois signes se recoupent : extensions changées en masse, note de rançon, entropie de ~8 bits sur les fichiers renommés contre ~4 sur un texte lisible. C'est bien un rançongiciel (ici : un événement scénarisé du jeu).", "ok");
      say("Maître Ada", `Maintenant, chaque minute compte : ${hostsHit()} poste${hostsHit() > 1 ? "s" : ""} sur 12 déjà touché${hostsHit() > 1 ? "s" : ""}. Va au carrefour des câbles (à l'est) : il faut confiner.`);
      note("signes"); fig("entropie");
    }
  }
  function measure(c) {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "scriptorium") { out("Les fichiers sont au scriptorium.", "sys"); return; }
    const t = norm(c.rawArg).split(" ")[0];
    if (!t) { out("Quel fichier ? `mesurer membres`, `mesurer affiche`…", "err"); return; }
    const fl = FILES.find(fi => fi.id.startsWith(t) || norm(fi.disp).startsWith(t));
    if (!fl) { out("Je ne trouve pas ce fichier. Regarde la liste : `examiner registres`.", "err"); return; }
    const data = fl.get(), e = entropy(data);
    x.meas = x.meas || {}; x.meas[fl.id] = e; tick();
    out(`Entropie de Shannon de « ${fname(fl)} » (échantillon de ${data.length} octets) : **${e.toFixed(2)} bits par octet** (maximum : 8).`, e > 7 ? "err" : "ok");
    if (e > 7) {
      if (fl.enc) out("Quasi aléatoire : c'est la signature d'un contenu chiffré. Un texte lisible serait vers 4 à 5.", "sys");
      else { out("Entropie très élevée… alors que l'extension n'a pas changé : c'est un fichier légitimement compressé (zip). L'entropie seule ne prouve rien : il faut la croiser avec les renommages et la note.", "sys"); x.zip = true; }
    } else out("Entropie de texte lisible : rien d'anormal.", "sys");
    checkSigns();
    if (x.signs && !x.zipWarn && !x.zip && fl.id !== "sceaux") { /* piste facultative */ }
  }

  /* ---------- Confinement ---------- */
  function isolate(c) {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "carrefour") { out("L'isolement se fait à l'armoire de brassage, au carrefour des câbles (à l'est du scriptorium).", "sys"); return; }
    const t = norm(c.rawArg);
    x.iso = x.iso || {};
    if (!t) { out("Quoi isoler ? `isoler postes`, `isoler nas`, `isoler sortie` ou `isoler tout`.", "err"); return; }
    const zones = [];
    if (/tout|reseau|complet/.test(t)) zones.push("postes", "nas", "sortie");
    else {
      if (/poste|scriptor|machine|bureau/.test(t)) zones.push("postes");
      if (/nas|sauvegarde|archive|serveur/.test(t)) zones.push("nas");
      if (/sortie|internet|exterieur|dehors|passerelle|pare/.test(t)) zones.push("sortie");
    }
    if (/conseil/.test(t)) { out("Le salon du conseil n'est pas touché : l'isoler n'arrêterait rien et coûterait de l'activité. On coupe le strict nécessaire.", "sys"); }
    if (!zones.length) { if (!/conseil/.test(t)) out("Je ne connais pas cette zone. `isoler postes`, `isoler nas`, `isoler sortie` ou `isoler tout`.", "err"); return; }
    zones.forEach(z => {
      if (x.iso[z]) { out(`La zone « ${z} » est déjà isolée.`, "sys"); return; }
      x.iso[z] = true;
      out({ postes: "Tu débranches les câbles des postes du scriptorium : le réseau local ne laisse plus passer ni les renommages ni la propagation. Les machines restent allumées (on garde leur mémoire pour l'enquête).", nas: "Tu déconnectes le NAS et les partages réseau : la copie en ligne ne peut plus être atteinte, ni par l'attaquant ni par un poste infecté.", sortie: "Tu coupes la sortie vers Internet : plus de sorties de données, et l'attaquant perd son accès à distance." }[z], "ok");
    });
    if (x.iso.postes && x.iso.nas && x.iso.sortie && !x.isolated) {
      x.hostsAtIso = hostsHit(); x.isolated = true;
      say("Ève", `Plus rien ne bouge. ${x.hostsAtIso} poste${x.hostsAtIso > 1 ? "s" : ""} sur 12 touché${x.hostsAtIso > 1 ? "s" : ""} avant le confinement.${x.evLost ? " Dommage pour la mémoire du poste éteint : nous n'aurons pas ses traces." : ""}`);
      say("Maître Ada", "Voilà le bon réflexe : isoler, puis comprendre. Maintenant, voyons ce qui nous reste côté sauvegardes : aux archives.");
      note("confiner"); fig("chrono");
    } else if (!x.isolated) out("Il reste des zones à couper : regarde l'armoire (`examiner armoire`).", "sys");
  }
  function shutdown() {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (x.isolated) { out("Maintenant que tout est isolé, rien ne presse : on capture d'abord la mémoire et les journaux, puis on décidera. Éteindre n'arrêterait plus rien.", "sys"); return; }
    if (x.evLost) { out("Le poste de Bob est déjà éteint.", "sys"); return; }
    x.evLost = true; tick(2);
    out("Tu coupes le courant du pupitre de Bob. Écran noir. Soulagement… de courte durée.", "err");
    say("Maître Ada", `Tu as stoppé UN poste, pas le réseau : les autres continuent de chiffrer (${hostsHit()} touchés maintenant). Et la mémoire vive de Bob, qui contenait des traces de l'attaque, est perdue. D'abord isoler du réseau, ensuite on réfléchit.`);
  }
  function pay() {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (x.paid) { out("La caisse est vide : Maître Ada refuse de signer un second paiement. Poursuis la reprise.", "err"); return; }
    x.paid = true; tick(2);
    out("Tu envoies 40 000 écus en cryptomonnaie à l'adresse de la note. Silence. Une heure plus tard, Mallory « généreuse » envoie un déchiffreur…", "err");
    out("…qui ne rend que 3 fichiers sur 5, en abîme un, et un nouveau message arrive : « 80 000 écus pour le reste, ou nous publions les 2 Go volés ». Les données volées n'ont de toute façon pas été « rendues ».", "err");
    say("Maître Ada", "Voilà ce qui arrive quand on paye d'emblée : aucune garantie, 40 000 écus offerts aux attaquants, et la certitude que tu es un bon client. Le mal est fait ; restaurons depuis les sauvegardes.");
    if (!x.isolated) out("Et pendant ce temps, rien n'est confiné.", "err");
  }

  /* ---------- Sauvegardes ---------- */
  const copyOf = t => /papier|livre/.test(t) ? "papier" : /nas/.test(t) ? "nas" : /nuage|synchro/.test(t) ? "nuage" : /disque|hors ligne|usb/.test(t) ? "disque" : /coffre|immuable|objet/.test(t) ? "coffre" : null;
  function onCopyExamined(id) {
    const x = F(); x.seen = x.seen || {}; x.seen[id] = true;
    if (!x.bkSeen && ["nas", "nuage", "disque", "coffre"].every(k => x.seen[k])) {
      x.bkSeen = true;
      say("Maître Ada", "Voilà l'état des lieux : le NAS est chiffré, le nuage synchronisé a répliqué le désastre. Il reste le disque hors ligne et le coffre immuable. Compare-les à la règle d'or de la sauvegarde.");
      note("copies"); note("regle"); fig("regle");
    }
  }
  ["nas", "nuage", "disque", "coffre"].forEach(id => { ents[id].onExamine = () => onCopyExamined(id); });
  function testCmd(c) {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "archives") { out("Le bac à sable est aux archives (à l'ouest du scriptorium).", "sys"); return; }
    const cp = copyOf(norm(c.rawArg));
    if (!cp || cp === "papier") { out("Quelle copie ? `tester nas`, `tester nuage`, `tester disque` ou `tester coffre`.", "err"); return; }
    out(`Bac à sable isolé (aucun réseau, rien ne touche la production) : restauration d'un échantillon depuis ${COPIES[cp].nom} et comparaison avec le journal d'empreintes de 02h00.`, "sys");
    const lines = REG.map(k => {
      const d = getCopy(cp, k), j = judge(k, d);
      return `${(k + ".reg").padEnd(12)} ${sha256(d).slice(0, 12)}…  entropie ${entropy(d).toFixed(1)}  ${j.k === "ok" ? "OK " : "KO "} ${j.t}`;
    });
    code(lines.join("\n"));
    x.tested = x.tested || {}; x.tested[cp] = true;
    const res = REG.map(k => judge(k, getCopy(cp, k)).k);
    if (res.every(r => r === "enc")) out("Tout est chiffré : cette copie est inutilisable. (Une copie accessible en permanence par l'attaquant n'était pas une protection.)", "err");
    else if (cp === "disque") out("Le disque hors ligne est intact et complet pour les chartes, mais ses registres de membres et de comptes datent de il y a 3 jours : aucune trace de ce qui a été saisi depuis. Bon état, mais ancien (grand RPO).", "ok");
    else if (cp === "coffre") {
      out("La copie immuable est récente et intacte sauf un fichier : « chartes.reg » est tronqué. Le tableau de bord de sauvegarde indiquait « succès » : le travail avait bien tourné, mais n'avait pas tout copié. Sans ce test, on l'aurait découvert le jour de la crise.", "err");
      x.coffreCut = true;
    }
    if (x.tested.disque && x.tested.coffre && !x.noteTest) { x.noteTest = true; say("Maître Ada", "Tu vois pourquoi on teste ? Une sauvegarde n'est jamais « bonne » avant d'avoir été restaurée. Il va falloir combiner : le coffre pour le récent, le disque pour ce qui manque."); note("test"); fig("regle"); }
  }
  function parseMin(raw) {
    let m = raw.replace(/,/g, ".").match(/(\d+(?:\.\d+)?)\s*h\s*(\d+)?/i);
    if (m) return +m[1] * 60 + (m[2] ? +m[2] : 0);
    m = raw.replace(/,/g, ".").match(/(\d+(?:\.\d+)?)/);
    return m ? +m[1] : NaN;
  }
  function estimate(c) {
    const x = F(), raw = c.rawArg, t = norm(raw);
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (!x.bkSeen) { out("Examine d'abord les quatre copies aux archives pour savoir de quoi on dispose.", "sys"); return; }
    if (/rpo/.test(t)) {
      const m = parseMin(raw.replace(/rpo/i, ""));
      if (!Number.isFinite(m)) { out("`estimer rpo ‹minutes›` (ex. estimer rpo 70).", "err"); return; }
      if (Math.abs(m - 70) < 1 || Math.abs(m - 70) < 0.01) {
        x.rpo = true;
        out("Exact : dernière copie saine du coffre à 02h00, incident à 03h10 : **70 minutes** de données perdues. Dans les 24 h d'objectif.", "ok");
        out("Le disque hors ligne, lui, perdrait 3 jours + 5 h 10 = 77 h 10 de données : hors objectif, même s'il est plus rapide à relire.", "sys");
        if (x.rto) done2(); else out("Estime maintenant le temps de restauration : `estimer rto ‹heures›`. (`calc` est ton ami.)", "sys");
      } else if (Math.abs(m - 4630) < 1) out("C'est le RPO du disque hors ligne (77 h 10 = 4 630 min), bien au-delà des 24 h visées. Calcule pour la copie la plus récente saine : le coffre immuable.", "err");
      else out(`${m} minutes : ce n'est pas ça. Le RPO est l'écart entre la dernière copie saine (coffre, 02h00) et l'incident (début du chiffrement, 03h10), pas la détection.`, "err");
    } else if (/rto/.test(t)) {
      const hm = /min/.test(t) ? parseMin(raw.replace(/rto/i, "")) / 60 : /h/.test(t) && /\d\s*h\s*\d/.test(t) ? parseMin(raw.replace(/rto/i, "")) / 60 : parseFloat(raw.replace(/,/g, ".").replace(/rto/i, "").match(/\d+(?:\.\d+)?/)?.[0]);
      if (!Number.isFinite(hm)) { out("`estimer rto ‹heures›` (ex. estimer rto 4).", "err"); return; }
      if (Math.abs(hm - 4) < 0.02) {
        x.rto = true;
        out("Exact : 540 Go à 50 Mo/s (400 Mbit/s ÷ 8) = 10 800 s = 3 h de transfert, plus 1 h de contrôles et remise en service : **4 heures**, sous l'objectif de 8 h.", "ok");
        if (x.rpo) done2(); else out("Estime aussi le RPO : `estimer rpo ‹minutes›`.", "sys");
      } else if (Math.abs(hm - 3) < 0.02) out("3 h, c'est le transfert seul. N'oublie pas 1 h de contrôle et de remise en service (empreintes, tests applicatifs) : ça se compte dans le RTO.", "err");
      else if (Math.abs(hm - 2) < 0.02 || Math.abs(hm - 1) < 0.02) out("Ça ressemble à la copie du disque hors ligne (540 Go à 150 Mo/s = 1 h, +1 h de contrôles = 2 h) : rapide, mais ancienne. Calcule pour le coffre immuable, 400 Mbit/s = 50 Mo/s.", "err");
      else if (Math.abs(hm - 24) < 0.5 || hm > 20) out("Le débit est exprimé en Mbit/s : divise par 8 pour obtenir des Mo/s. 400 Mbit/s = 50 Mo/s. Puis 540 Go = 540 000 Mo.", "err");
      else out(`${hm} h : ce n'est pas ça. Débit : 400 Mbit/s ÷ 8 = 50 Mo/s ; volume : 540 Go = 540 000 Mo ; durée = volume ÷ débit ; puis ajoute 1 h de contrôle. Essaie \`calc 540*1000/50/3600\`.`, "err");
    } else out("`estimer rpo ‹minutes›` ou `estimer rto ‹heures›`.", "err");
  }
  function done2() {
    say("Maître Ada", "Parfait : 70 minutes de données perdues, 4 heures de restauration. Les deux sont dans nos objectifs (24 h et 8 h) avec le coffre immuable. Il reste une décision de conseil.");
    note("rporto"); fig("rporto");
  }

  /* ---------- Conseil ---------- */
  function decide(c) {
    const x = F(), t = norm(c.rawArg);
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "conseil") { out("Les décisions se prennent en conseil (au nord du scriptorium).", "sys"); return; }
    if (!x.rto || !x.rpo) { say("Alice", "Avant de décider, il faut savoir ce que nos sauvegardes permettent : estime le RPO et le RTO."); return; }
    if (x.decision) { out("La décision est prise : on ne paye pas.", "sys"); return; }
    if (/ne pas|refus|non|jamais|pas payer/.test(t)) {
      x.decision = true;
      say("Alice", x.paid ? "Nous avons déjà payé une fois et ça n'a rien réglé. Ne payons pas davantage." : "Ne pas payer : nous avons des sauvegardes saines et testées.");
      say("Maître Ada", "Ce n'est pas qu'une question de morale : payer ne garantit pas de récupérer les fichiers (déchiffreur défaillant, partiel, ou jamais envoyé), finance les attaques suivantes, nous marque comme cibles solvables, et ne protège pas les 2 Go déjà volés. Quand on a de bonnes sauvegardes, la question tombe : on restaure.");
      note("nepayer"); fig("arbre");
    } else if (/payer|oui|accept/.test(t)) {
      say("Alice", "Quarante mille écus, c'est moins cher que des jours d'arrêt… non ?");
      say("Maître Ada", "Calcule : nous pouvons restaurer en 4 heures avec 70 minutes de pertes. Payer coûterait plus cher, sans garantie, et n'efface pas la menace de publication. Retiens la proposition de ne pas payer : `decider ne pas payer`.");
    } else out("`decider ne pas payer` ou `decider payer`.", "err");
  }
  function report() {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "conseil") { out("Le signalement se prépare en conseil (au nord du scriptorium).", "sys"); return; }
    if (x.reported) { out("C'est déjà fait.", "sys"); return; }
    x.reported = true;
    out("Tu prépares le signalement :", "ok");
    out("· dépôt de plainte (la Garde de Port-443) avec les journaux d'Ève et la note de rançon conservés ;\n· alerte de l'équipe de réponse à incident et de l'assureur ;\n· notification à l'autorité de protection des données sous 72 h si des données personnelles ont pu sortir (2 Go ont été exfiltrés) ;\n· information des membres concernés et communication de crise.", "");
    say("Maître Ada", "Garde les preuves : journaux, note, mémoire des postes. Signaler aide aussi les autres : plus on partage, plus on déchiffre ou bloque vite.");
  }

  /* ---------- Reconstruction et restauration ---------- */
  function rebuild(c) {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "atelier") { out("La reconstruction se fait à l'atelier (au sud du scriptorium).", "sys"); return; }
    if (!x.isolated) { say("Maître Ada", "Pas avant d'avoir confiné : sinon tu reconstruis dans un réseau encore infecté."); return; }
    if (x.rebuilt) { out("Le poste est déjà reconstruit.", "sys"); return; }
    x.rebuilt = true;
    out("Tu réinstalles un poste neuf depuis un média de confiance, avec tous les correctifs. Aucun « nettoyage à la main » : on ne peut pas être sûr d'avoir tout retiré d'une machine compromise.", "ok");
    cleanCheck();
  }
  function renew() {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "atelier") { out("Le renouvellement des identifiants se prépare à l'atelier (au sud du scriptorium).", "sys"); return; }
    if (!x.isolated) { say("Maître Ada", "Confine d'abord."); return; }
    if (x.creds) { out("C'est déjà fait.", "sys"); return; }
    x.creds = true;
    out("Tous les mots de passe et jetons d'administration sont renouvelés, les sessions ouvertes sont révoquées. Sinon l'attaquant, qui avait volé le compte administrateur, reviendrait aussitôt.", "ok");
    cleanCheck();
  }
  function cleanCheck() {
    const x = F();
    if (x.rebuilt && x.creds && !x.clean) { x.clean = true; say("Maître Ada", "L'environnement est propre. On peut restaurer : `restaurer ‹copie›`, selon nos objectifs."); }
  }
  function restore(c) {
    const x = F();
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    const t = norm(c.rawArg), cp = copyOf(t);
    if (S.room !== "atelier") { out("La restauration se fait à l'atelier, sur le poste reconstruit (au sud du scriptorium).", "sys"); return; }
    if (!cp) { out("Quelle copie ? `restaurer coffre` ou `restaurer disque chartes`.", "err"); return; }
    const files = REG.filter(k => t.split(" ").some(w => w && k.startsWith(w) && w.length > 2));
    const list = files.length ? files : REG;
    if (cp === "nas" || cp === "nuage") {
      out(`Tu restaures depuis ${COPIES[cp].nom}…`, "sys");
      out("…et tu récupères des fichiers chiffrés : l'attaquant les avait déjà verrouillés. Cette copie était accessible depuis le réseau avec les identifiants volés. Entropie des fichiers restaurés : ~8 bits.", "err");
      return;
    }
    if (cp === "papier") {
      if (!x.cLost) { out("Le Grand Livre papier ne sert qu'en dernier recours.", "sys"); return; }
      if (!list.includes("chartes") || files.length !== 1) { out("Seules les chartes peuvent être ressaisies : `restaurer papier chartes`.", "err"); return; }
      x.prod = x.prod || {}; x.prod.chartes = "papier";
      out("Deux jours-personne plus tard, les chartes sont ressaisies à la main depuis le Grand Livre. `controler production` pour vérifier.", "ok");
      return;
    }
    if (!x.tested || !x.tested[cp]) { say("Maître Ada", "Pas sans test préalable : essaie d'abord cette copie dans le bac à sable (`tester " + (cp === "coffre" ? "coffre" : "disque") + "`, aux archives)."); return; }
    if (!x.clean) {
      if (cp === "disque" && !x.cLost) {
        x.cLost = true;
        out("Tu branches le disque hors ligne… sur un environnement encore compromis (poste pas reconstruit, identifiants non renouvelés). En quelques minutes, le disque est chiffré à son tour. La copie hors ligne n'est plus hors ligne dès qu'on la branche n'importe où.", "err");
        say("Maître Ada", "C'est la pire erreur : on ne branche jamais une sauvegarde sur un réseau ou une machine qui n'est pas propre. Il nous reste le coffre immuable. Pour les chartes, si le coffre est tronqué, il faudra les ressaisir depuis le Grand Livre papier.");
      } else if (cp === "coffre") {
        x.wasted = (x.wasted || 0) + 1;
        out("Tu relances la restauration depuis le coffre… vers une machine encore compromise. Les fichiers sont rechiffrés en cours de route : 3 h de perdues. (La copie immuable n'a pas bougé : elle, on ne peut pas l'abîmer.) Reconstruis d'abord un poste propre et renouvelle les identifiants.", "err");
      } else out("Cette copie n'est plus utilisable.", "err");
      return;
    }
    if (cp === "disque" && x.cLost) { out("Le disque hors ligne a été chiffré : inutilisable.", "err"); return; }
    x.prod = x.prod || {};
    const go = list.reduce((s, k) => s + SIZE_GO[k], 0), sec = go * 1000 / RATE[cp];
    list.forEach(k => { x.prod[k] = cp; });
    out(`Restauration de ${list.map(k => k + ".reg").join(", ")} depuis ${COPIES[cp].nom} : ${go} Go à ${RATE[cp]} Mo/s = ${fmtDur(sec)} de transfert.`, "ok");
    out("Il reste à vérifier : `controler production`.", "sys");
  }
  function controlCmd() {
    const x = F();
    if (S.room !== "atelier") { out("Le contrôle se fait à l'atelier.", "sys"); return; }
    if (!x.prod || !Object.keys(x.prod).length) { out("Rien n'a encore été restauré.", "sys"); return; }
    let bad = 0, missing = [];
    const lines = REG.map(k => {
      const src = x.prod[k];
      if (!src) { missing.push(k); return `${(k + ".reg").padEnd(12)} (pas encore restauré)`; }
      const d = getCopy(src, k), j = judge(k, d);
      if (j.k !== "ok") bad++;
      return `${(k + ".reg").padEnd(12)} ${sha256(d).slice(0, 12)}…  ${j.k === "ok" ? "OK " : "KO "} ${j.t}`;
    });
    out("Contrôle des empreintes de la production, contre le journal d'Ève :", "sys");
    code(lines.join("\n"));
    if (missing.length) { out("Il manque des fichiers : restaure-les (`restaurer ‹copie› ‹fichier›`).", "sys"); return; }
    if (!bad) {
      x.recovered = true;
      out("Tout est conforme : les registres sont revenus à l'état de 02h00. Les 70 minutes de saisie perdues sont à ressaisir, c'est la définition du RPO.", "ok");
      if (x.prod.chartes === "disque") out("(Les chartes viennent du disque hors ligne : inchangées depuis des mois, elles étaient identiques.)", "sys");
      say("Maître Ada", "Reprise réussie. Mais restaurer sans corriger ce qui a permis l'attaque, ce serait reprendre le même chemin demain. À l'atelier : la prévention.");
    } else if (x.prod.membres === "disque" || x.prod.comptes === "disque") out("Une partie vient d'une copie ANCIENNE : il manque des écritures de ces trois derniers jours. Restaure ces fichiers depuis la copie la plus récente saine (le coffre).", "err");
    else out("Un fichier est tronqué (celui du coffre). Restaure-le depuis une autre copie saine, par exemple `restaurer disque chartes` (ses chartes n'ont pas bougé depuis des mois).", "err");
  }

  /* ---------- Prévention ---------- */
  function harden(c) {
    const x = F(), t = norm(c.rawArg);
    if (!x.quest) { say("Maître Ada", "Parle-moi d'abord."); return; }
    if (S.room !== "atelier") { out("Les mesures se déploient depuis l'atelier.", "sys"); return; }
    if (!x.recovered) { say("Maître Ada", "D'abord reprendre l'activité : restaurons les registres."); return; }
    const key = Object.keys(MESURES).find(k => MESURES[k].re.test(t));
    if (!key) { out("Quelle mesure ? `durcir sensibilisation`, `mises a jour`, `mfa`, `segmentation`, `moindre privilege`.", "err"); return; }
    x.meas2 = x.meas2 || {};
    if (x.meas2[key]) { out("Déjà en place.", "sys"); return; }
    x.meas2[key] = true;
    out(MESURES[key].txt, "ok");
    out(`(Étape de la chaîne coupée : « ${STAGES[MESURES[key].stage][0]} »)`, "sys");
    if (Object.keys(MESURES).every(k => x.meas2[k]) && !x.prevAll) {
      x.prevAll = true; note("prevention"); fig("arbre");
      say("Maître Ada", "Cinq barrières, cinq étapes. Aucune n'est parfaite, ensemble elles se rattrapent. Rejoue maintenant l'attaque : `simuler attaque`.");
    }
  }
  function simulate() {
    const x = F();
    if (S.room !== "atelier") { out("La simulation se joue à l'atelier.", "sys"); return; }
    if (!x.recovered) { say("Maître Ada", "Après la reprise."); return; }
    const m = x.meas2 || {};
    out("Rejeu de la chaîne d'attaque de ce matin (simulation sur des événements fictifs du jeu) :", "sys");
    let reached = 0, stopped = false;
    const lines = STAGES.map((s, i) => {
      if (stopped) return `${i + 1}. ${s[0]}\n   (non atteint)`;
      const key = Object.keys(MESURES).find(k => MESURES[k].stage === i);
      if (m[key]) { stopped = true; return `${i + 1}. ${s[0]}\n   BLOQUÉ : ${s[1]}`; }
      reached++; return `${i + 1}. ${s[0]}\n   passé`;
    });
    code(lines.join("\n"));
    const dmg = ["Aucun dommage : l'attaque échoue dès la première étape.", "Un poste est touché. Réinstallé en quelques minutes.", "Un poste est touché, l'attaquant s'arrête là faute de privilèges.", "Quelques postes touchés mais pas les serveurs.", "Les postes et le réseau sont touchés, mais pas les sauvegardes.", "Tout est chiffré, sauvegardes comprises : le scénario de ce matin."][reached];
    out("Dommages : " + dmg, reached === 5 ? "err" : "ok");
    if (x.prevAll) { x.sim = true; say("Maître Ada", "Chaque défense a sa place. Et même si elles lâchaient toutes, la copie immuable et le disque hors ligne resteraient là. Reviens me voir pour conclure."); }
    else out("Il reste des mesures non déployées : chaque trou est un chemin ouvert. `examiner tableau`", "sys");
  }

  /* ---------- Fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "En quelques heures, la Guilde a retrouvé ses registres sans payer un écu, a perdu 70 minutes de saisie, et sait désormais ce qui a rendu l'attaque possible. La rançon aurait réglé… quoi, au juste ?");
    if (x.paid) say("Maître Ada", "Sauf pour les 40 000 écus que tu as laissé partir au début. Retiens : on ne paye pas d'emblée, jamais avant d'avoir regardé les sauvegardes.");
    if (x.evLost) out("(Tu avais éteint le poste de Bob trop tôt : l'enquête s'est faite sans sa mémoire vive.)", "sys");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Les registres « verrouillés » = des fichiers chiffrés par un rançongiciel.** Le logiciel malveillant chiffre les données de l'organisation (souvent en renommant les fichiers) et laisse une note. Ici ce n'est qu'un événement du scénario : il n'y a, dans ce jeu, ni code réel ni technique d'attaque.");
    out("**L'entropie.** L'entropie de Shannon mesure l'imprévisibilité des octets : un texte tourne autour de 4 à 5 bits par octet, un contenu chiffré ou compressé s'approche de 8. C'est un indice utilisé par la détection, mais pas une preuve : le zip légitime a aussi une entropie élevée.");
    out("**Le carrefour des câbles = l'isolement réseau.** On débranche les postes, on coupe la sortie Internet (exfiltration, accès distant), on déconnecte les sauvegardes en ligne. On n'éteint pas tout de suite : la mémoire vive contient des traces. (Cas particulier : si l'on ne peut pas isoler autrement et que le chiffrement progresse, couper l'alimentation peut être le moindre mal.)");
    out("**Les quatre copies.** NAS (en ligne, même réseau) = chiffrée avec les identifiants administrateur. Dossier synchronisé = la synchronisation réplique les erreurs, pas une vraie sauvegarde. Disque hors ligne = sauvegarde déconnectée, à l'abri mais ancienne. Coffre immuable = stockage à écriture verrouillée (object lock / WORM), ni modifiable ni effaçable avant échéance, même par un administrateur.");
    out("**3-2-1-1-0.** 3 copies, 2 supports différents, 1 hors site, 1 hors ligne ou immuable, 0 erreur après restauration vérifiée. Le journal d'empreintes (SHA-256) est ce qui a révélé le fichier tronqué.");
    out("**RPO et RTO.** RPO réel = écart entre la dernière copie saine (02h00) et l'incident (03h10) = 70 min. RTO ≈ volume ÷ débit + contrôles = 540 000 Mo ÷ 50 Mo/s = 3 h, +1 h = 4 h. Le débit réseau est en Mbit/s : 400 ÷ 8 = 50 Mo/s. Le disque aurait été plus rapide (1 h + 1 h) mais le RPO de 77 h 10 dépassait la cible.");
    out("**Mallory et la rançon.** Payer = aucune garantie, financement du crime, cible rentable, et les données volées ne sont pas « rendues ». Le signalement (plainte, équipe de réponse, assureur, autorité de protection des données) fait partie de la gestion de crise.");
    out("**La prévention.** Hameçonnage, faille non corrigée, identifiant volé, réseau plat, sauvegardes effaçables : cinq étapes, cinq barrières (sensibilisation, mises à jour, MFA, segmentation, moindre privilège). Défense en profondeur.");
    out("**Les simplifications du jeu.** (1) Le chiffrement est un décor : les contenus « chiffrés » sont des octets pseudo-aléatoires, et l'entropie n'est calculée que sur des échantillons de quelques milliers d'octets. (2) Une vraie attaque passe par des mois d'intrusion silencieuse, des rôles d'équipes (SOC, CERT, juristes, communication) et des décisions bien plus nuancées. (3) Le RTO se compte en vrai dès le début de l'incident, détection et décision comprises (ici : uniquement la restauration). (4) Les vraies restaurations incluent la reconstruction d'annuaires, applications et bases de données dans le bon ordre. (5) Une analyse forensique complète (preuves, périmètre exact de la compromission) précède souvent le retour à la normale. (6) L'assurance et le cadre juridique varient selon les pays.");
    out("Rappel utile : **une sauvegarde qui n'a pas été restaurée n'est pas une sauvegarde ; et une copie que l'attaquant peut atteindre n'en est pas une non plus.** Isoler d'abord, ne pas payer d'emblée, restaurer depuis une copie hors ligne ou immuable testée.", "ok");
  }

  /* ---------- Schémas ---------- */
  const figs = {
    entropie: () => {
      const x = F(), m = x.meas || {};
      let rows = "";
      FILES.forEach((fl, i) => {
        const y = 22 + i * 26, e = m[fl.id];
        rows += T(8, y + 12, fname(fl), "f-s", "start") + R(150, y, 200, 16);
        if (e !== undefined) rows += `<rect x="150" y="${y}" width="${(e / 8 * 200).toFixed(1)}" height="16" rx="4" fill="${e > 7 ? "var(--bad)" : "var(--ok)"}"/>` + T(358, y + 12, e.toFixed(2), "f-b", "start");
        else rows += T(358, y + 12, "?", "f-s", "start");
      });
      return {
        cap: "Entropie (bits par octet) des fichiers que tu as mesurés : ~4 pour un texte lisible, ~8 pour un contenu chiffré ou compressé. Le zip légitime est élevé aussi : l'entropie seule ne prouve rien.",
        svg: SVG(194, "Entropie des fichiers",
          T(150, 12, "0", "f-s", "start") + T(350, 12, "8 bits", "f-s", "end") + rows +
          LN(150 + 7 * 25, 18, 150 + 7 * 25, 176, "f-bad f-dash") + T(325, 188, "seuil ≈ 7", "f-s ft-bad", "end"))
      };
    },
    chrono: () => {
      const x = F(), i = x.iso || {};
      const X = h => (20 + (h - 1) * 55).toFixed(1);
      let ticks = "";
      for (let h = 1; h <= 8; h++) ticks += T(X(h), 114, "0" + h + "h", "f-s") + LN(X(h), 96, X(h), 104);
      const zone = (n, k, title, a, b) => R(8 + n * 138, 168, 130, 62, i[k] ? "f-ok" : "f-bad") + T(73 + n * 138, 188, title, "f-b") + T(73 + n * 138, 205, i[k] ? a : b, i[k] ? "f-s ft-ok" : "f-s ft-bad") + T(73 + n * 138, 220, i[k] ? "✔ isolé" : "✘ exposé", i[k] ? "f-s ft-ok" : "f-s ft-bad");
      return {
        cap: "Chronologie de la nuit (journaux d'Ève) et zones de confinement : le temps passé entre le début et l'isolement se paye en postes touchés.",
        svg: SVG(242, "Chronologie de l'attaque",
          LN(20, 100, 410, 100) + ticks +
          T(81, 22, "02h00 coffre", "f-s ft-ok", "start") + LN(75, 26, 75, 100, "f-ok") +
          T(136, 40, "03h10 début du chiffrement", "f-s ft-bad", "start") + LN(130, 44, 130, 100, "f-bad") +
          T(146, 58, "03h25 NAS + versions du nuage", "f-s ft-bad", "start") + LN(139, 62, 139, 100, "f-bad") +
          T(400, 22, "07h40 détection · 07h45 isolement", "f-s", "end") + LN(387, 26, 387, 100) +
          `<rect x="38" y="122" width="74" height="9" rx="3" fill="var(--bad)"/>` + T(8, 148, "01h20-02h40 : ~2 Go sortis (exfiltration)", "f-s ft-bad", "start") +
          zone(0, "postes", "Postes", "sans propagation", "touchés : " + hostsHit() + "/12") +
          zone(1, "nas", "NAS", "copie protégée", "atteignable") +
          zone(2, "sortie", "Sortie web", "fuite coupée", "ouverte"))
      };
    },
    regle: () => {
      const x = F(), t = x.tested || {};
      const st = {
        nas: ["chiffrée", false], nuage: ["effacée", false],
        disque: x.cLost ? ["chiffrée", false] : t.disque ? ["saine, ancienne", true] : ["à tester ?", null],
        coffre: t.coffre ? ["saine, 1 KO", true] : ["à tester ?", null],
      };
      let rows = "";
      Object.keys(COPIES).forEach((k, n) => {
        const y = 8 + n * 36, ok = st[k][1];
        rows += R(8, y, 404, 30, ok === true ? "f-ok" : ok === false ? "f-bad" : "") + T(16, y + 19, k, "f-b", "start") + T(76, y + 19, COPIES[k].type, "f-s", "start") + T(290, y + 19, st[k][0], "f-s " + (ok === true ? "ft-ok" : ok === false ? "ft-bad" : ""), "start");
      });
      const healthy = ["disque", "coffre"].filter(k => st[k][1] !== false).length;
      const chip = (n, big, l1, l2, ok) => R(8 + n * 82, 162, 78, 62, ok === true ? "f-ok" : ok === false ? "f-bad" : "") + T(47 + n * 82, 184, big, "f-b " + (ok === true ? "ft-ok" : ok === false ? "ft-bad" : "")) + T(47 + n * 82, 200, l1, "f-s") + T(47 + n * 82, 213, l2 || "", "f-s");
      const allTested = t.disque && t.coffre;
      const zero = !allTested ? null : false;
      return {
        cap: "Les quatre copies après l'attaque, et la règle 3-2-1-1-0 évaluée sur ce qui reste : seules les copies que l'attaquant n'a pas pu atteindre comptent, et le « 0 erreur » exige un test réel.",
        svg: SVG(236, "Règle 3-2-1-1-0",
          rows + chip(0, "3", "copies", "(≥ 2 saines)", healthy >= 2 ? true : false) +
          chip(1, "2", "supports", "différents", healthy >= 2 ? true : false) + chip(2, "1", "hors site", "", healthy >= 1 ? true : false) +
          chip(3, "1", "hors ligne", "ou immuable", healthy >= 1 ? true : false) + chip(4, "0", "erreur", allTested ? "(1 KO)" : "(non testé)", zero))
      };
    },
    rporto: () => {
      const x = F();
      return {
        cap: "RPO réel : l'écart entre la dernière copie saine (02h00) et l'incident (03h10). RTO : le temps de restauration (540 Go à 50 Mo/s = 3 h, plus 1 h de contrôle).",
        svg: SVG(206, "RPO et RTO",
          LN(20, 82, 410, 82) +
          T(70, 18, "02h00", "f-b ft-ok") + T(70, 31, "copie coffre", "f-s") + LN(70, 38, 70, 82, "f-ok") +
          T(170, 18, "03h10", "f-b ft-bad") + T(170, 31, "incident", "f-s") + LN(170, 38, 170, 82, "f-bad") +
          T(280, 18, "07h40", "f-b") + T(280, 31, "détection", "f-s") + LN(280, 38, 280, 82) +
          T(405, 18, "fin", "f-b", "end") + T(405, 31, "restauration", "f-s", "end") + LN(396, 38, 396, 82) +
          AR(70, 62, 170, 62, "f-bad", true) + T(120, 56, "RPO 70 min", "f-s ft-bad") +
          AR(280, 108, 396, 108, "f-ok", true) + T(338, 102, "RTO 4 h", "f-s ft-ok") + T(412, 126, "3 h transfert + 1 h contrôle", "f-s", "end") +
          T(8, 158, "Cibles de la Guilde : RPO 24 h · RTO 8 h", "f-s", "start") +
          T(8, 178, "coffre immuable : RPO 70 min ✔ · RTO 4 h ✔", "f-s ft-ok", "start") +
          T(8, 196, "disque hors ligne : RPO 77 h 10 ✘ · RTO 2 h ✔", "f-s ft-bad", "start"))
      };
    },
    arbre: () => {
      const x = F();
      const b = (x1, y, w, l1, l2, ok) => R(x1, y, w, 38, ok ? "f-ok" : "") + T(x1 + w / 2, y + 16, l1, "f-b") + T(x1 + w / 2, y + 30, l2, "f-s");
      return {
        cap: "Arbre de décision de la réponse : isoler d'abord, évaluer les sauvegardes, ne pas payer d'emblée, tester, reconstruire, restaurer, signaler et durcir.",
        svg: SVG(312, "Arbre de décision",
          b(110, 6, 200, "Signes d'infection ?", "renommages, note, entropie", !!x.signs) + AR(210, 44, 210, 58) +
          b(110, 58, 200, "1. ISOLER du réseau", "ne pas éteindre ni payer", !!x.isolated) + AR(210, 96, 210, 110) +
          b(110, 110, 200, "2. Sauvegardes saines ?", "hors ligne / immuable", !!x.bkSeen) +
          AR(150, 148, 90, 168) + T(98, 160, "non", "f-s ft-bad", "end") + AR(270, 148, 330, 168) + T(322, 160, "oui", "f-s ft-ok", "start") +
          b(8, 168, 164, "Déchiffreur public ?", "sinon reconstruire", false) +
          b(250, 168, 164, "3. TESTER", "bac à sable, empreintes", !!(x.tested && x.tested.coffre)) + AR(332, 206, 332, 222) +
          b(250, 222, 164, "4. RESTAURER", "poste propre, mdp neufs", !!x.recovered) + AR(250, 241, 210, 270) +
          b(110, 266, 200, "5. Signaler · durcir", "plainte, 72 h, 5 barrières", !!(x.reported && x.prevAll)))
      };
    },
  };

  GAMES.ransom = {
    id: "ransom", order: 17, title: "La Cité Verrouillée", pageTitle: "Ransom Quest", subtitle: "aventure textuelle · rançongiciels et sauvegardes",
    blurb: "Un matin, les registres de la Guilde sont verrouillés : isole, évalue les sauvegardes, calcule, teste, restaure.",
    concept: "Rançongiciels, sauvegardes, reprise d'activité",
    start: "scriptorium", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.t = 0; x.iso = {}; x.meas = {}; x.tested = {}; x.prod = {}; x.seen = {}; x.meas2 = {}; },
    refig(name) { fig(name); },
    figAlias: { entropie: ["signes", "infection"], chrono: ["confinement", "attaque", "zones"], regle: ["321", "sauvegardes", "copies"], rporto: ["rpo", "rto", "temps"], arbre: ["decision", "reponse"] },
    help: "Spécifiques : `mesurer ‹fichier›` · `isoler postes|nas|sortie|tout` · `eteindre poste` · `payer` · `tester ‹copie›` · `estimer rpo ‹minutes›` / `estimer rto ‹heures›` · `decider ne pas payer` · `signaler` · `reconstruire poste` · `renouveler identifiants` · `restaurer ‹copie› [‹fichier›]` · `controler production` · `durcir ‹mesure›` · `simuler attaque`",
    verbs: {
      measure: { words: ["mesurer", "entropie"], run: measure },
      isolate: { words: ["isoler", "couper", "debrancher", "deconnecter"], run: isolate },
      shutdown: { words: ["eteindre", "arreter", "stopper"], run: shutdown },
      pay: { words: ["payer", "rembourser", "verser"], run: pay },
      test: { words: ["tester", "essayer"], run: testCmd },
      estimate: { words: ["estimer", "annoncer", "evaluer"], run: estimate },
      decide: { words: ["decider", "trancher"], run: decide },
      report: { words: ["signaler", "declarer", "alerter"], run: report },
      rebuild: { words: ["reconstruire", "reinstaller", "reformater"], run: rebuild },
      renew: { words: ["renouveler", "revoquer", "reinitialiser"], run: renew },
      restore: { words: ["restaurer", "recuperer"], run: restore },
      control: { words: ["controler", "valider", "comparer"], run: controlCmd },
      harden: { words: ["durcir", "deployer", "activer", "installer"], run: harden },
      simulate: { words: ["simuler", "rejouer"], run: simulate },
    },
    intro() {
      out("La Cité Verrouillée", "title");
      out("Un matin à Port-443, Bob pousse la porte du scriptorium : tous les registres de la Guilde portent une extension qu'il ne connaît pas, « .verrou », et une note exige une rançon. Maître Ada te confie la conduite de la réponse. Exercice autorisé et entièrement simulé : les fichiers, les copies et les « attaquants » sont fictifs, et rien dans ce jeu n'est un outil d'attaque. L'enjeu : garder la tête froide, confiner, évaluer, restaurer, comprendre.", "");
    },
  };
})();
