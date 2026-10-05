"use strict";
/* L'Écoute aux Portes : canaux auxiliaires (temps, consommation, cache, exécution spéculative).
   Tout se passe sur des machines et des mesures JOUETS, simulées avec un générateur à graine fixe.
   Les calculs sont réels (exponentiation « carré-multiplication », aveuglement RSA vérifié par le calcul,
   modèle de cache, modèle de prédicteur de branchement) mais aucun n'est transposable à du vrai matériel. */
(function () {
  const F = () => f();

  /* ---------- paramètres du monde jouet ---------- */
  const CODE = "3057";                              // code de la serrure du coffre (comparaison à tester)
  const RN = 3233, RE = 17, RD = 2753, RPHI = 3120; // paire RSA jouet : n = 61 × 53, e × d ≡ 1 (mod φ)
  const RM = 65;                                    // défi signé par la carte
  const SECRET = [5, 2, 6, 3], PUB = [3, 6, 1, 5];  // cache : octets secrets (3 bits) et entrées publiques
  const MEM = [1, 3, 2, 0, 6, 4, 1], TAB = 4;       // Augure : ardoise de 4 cases, puis 3 cases secrètes
  const SEC_BITS = RD.toString(2);

  /* ---------- outils ---------- */
  const fx = (v, d) => v.toFixed(d == null ? 1 : d).replace(".", ",");
  const pad = (s, n) => String(s).padStart(n, " ");
  const mean = a => a.reduce((s, v) => s + v, 0) / a.length;
  const bin3 = v => v.toString(2).padStart(3, "0");
  function rnd() {
    const x = F();
    let t = (x.seed = ((x.seed == null ? 443 : x.seed) + 0x6D2B79F5) >>> 0);
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  function gauss(sd) { const u = Math.max(rnd(), 1e-9), v = rnd(); return sd * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }
  function modinv(a, m) {
    let [r0, r1, s0, s1] = [m, a % m, 0, 1];
    while (r1) { const q = Math.floor(r0 / r1); [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    return ((s0 % m) + m) % m;
  }
  function need(room, msg) {
    if (S.room !== room) { out(msg, "sys"); return false; }
    if (!F().quest) { say("Maître Ada", "Viens d'abord me voir : `parler ada`."); return false; }
    return true;
  }
  const argNums = c => (c.rawArg.match(/\d+/g) || []).map(Number);

  /* ---------- simulations ---------- */
  // 1. temps : comparaison octet par octet
  function cmpSteps(g) {
    let s = 0;
    for (let i = 0; i < 4; i++) { s++; if (g[i] !== CODE[i]) return { ok: false, steps: s }; }
    return { ok: true, steps: 4 };
  }
  function trueTime(g) {
    if (F().tc) return 116; // comparaison en temps constant : toujours 4 tours, décision à la fin
    const r = cmpSteps(g);
    return 100 + 4 * r.steps + (r.ok ? 6 : 0);
  }
  const measure = (g, n) => { const v = []; for (let i = 0; i < n; i++) v.push(trueTime(g) + gauss(5)); return v; };

  // 2. consommation : carré-multiplication (de gauche à droite) et échelle de Montgomery (régulière)
  function sqmul(m, d, n) {
    let r = 1; const ops = [];
    for (const b of d.toString(2)) { r = (r * r) % n; ops.push("S"); if (b === "1") { r = (r * m) % n; ops.push("M"); } }
    return { r, ops };
  }
  function ladder(m, d, n) {
    let r0 = 1, r1 = m % n; const ops = [];
    for (const b of d.toString(2)) {
      if (b === "0") { r1 = (r0 * r1) % n; r0 = (r0 * r0) % n; } else { r0 = (r0 * r1) % n; r1 = (r1 * r1) % n; }
      ops.push("M", "S"); // même séquence quel que soit le bit
    }
    return { r: r0, ops };
  }

  // 3. cache
  const evicted = L => { const x = F(); return x.cmode === "uni" ? [0, 1, 2, 3, 4, 5, 6, 7] : x.cmode === "part" ? [] : [L]; };

  /* ---------- carnet ---------- */
  const notes = {
    canal: ["Canal auxiliaire", "Un algorithme peut être parfait sur le papier et pourtant fuir par son exécution : le temps qu'il met, l'énergie qu'il consomme, les cases mémoire qu'il touche, le bruit ou le rayonnement qu'il produit. Un canal auxiliaire (side channel) est ce qui fuit EN PLUS de la sortie officielle. On n'attaque pas les mathématiques : on écoute la machine."],
    temps: ["Canal temporel", "Une comparaison qui s'arrête à la première différence dure plus longtemps quand le début du code est juste. Une mesure isolée est noyée dans le bruit, mais la moyenne de nombreuses mesures le fait sortir : on retrouve le code octet par octet, en 10 séries de mesures par position au lieu d'essayer les 10 000 codes."],
    conso: ["Consommation (analyse simple)", "Dans « carré-multiplication », chaque bit à 1 de l'exposant ajoute une multiplication après le carré. Si la multiplication consomme autrement que le carré, la trace se lit comme le secret : un carré seul = bit 0, un carré suivi d'une multiplication = bit 1. C'est le principe de l'analyse simple de consommation (SPA)."],
    cache: ["Cache partagé", "Le cache est partagé entre programmes : un accès rapide ou lent révèle si une ligne a été utilisée par un autre. Si l'adresse accédée dépend d'un secret (table indexée par le secret), l'observateur déduit le secret des lignes touchées. Contre-mesures : accès indépendants du secret (tout parcourir), partitionnement du cache entre domaines."],
    speculation: ["Exécution spéculative", "Pour aller vite, le processeur devine l'issue d'un branchement et exécute à l'avance. Si le pari est faux, les résultats sont jetés, mais les traces laissées dans le cache restent : c'est le principe des failles de type Spectre et Meltdown (publiées en 2018). Les correctifs (barrières, masquage d'index, isolation, microcode, nouveaux processeurs) coûtent en performances."],
    tempsconstant: ["Temps constant", "Le secret ne doit pas influencer le temps. Comparer TOUTES les positions et accumuler les différences (OU des XOR) avant de décider donne toujours la même durée. Les bibliothèques cryptographiques sérieuses offrent des comparaisons et des opérations en temps constant : on les utilise, on n'écrit pas les siennes."],
    aveuglement: ["Régularité, masquage, aveuglement", "Un algorithme régulier fait la même séquence d'opérations quel que soit le secret. L'aveuglement (blinding) randomise l'entrée de façon réversible : (m × r^e)^d × r⁻¹ = m^d (mod n), donc l'observateur ne voit jamais l'entrée réelle ; on peut aussi masquer l'exposant (d + k·φ). Le bruit ajouté ne fait qu'augmenter le nombre de mesures nécessaires : il ne protège pas seul."],
    defense: ["Défense en profondeur matérielle", "Règle : le secret ne doit influencer ni le temps, ni l'énergie, ni les accès mémoire. En pratique : bibliothèques à temps constant, séparation des domaines de confiance (processus, machines virtuelles, locataires du cloud), limitation des essais et de la précision des chronomètres, mises à jour de microcode et de matériel, boîtiers protégés. Aucune couche ne suffit seule."],
  };

  /* ---------- entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada, doyenne de la Guilde",
      desc: () => "Maître Ada, lunettes sur le front, tient un coffre-fort contre son oreille comme un coquillage. Elle écoute." },
    coffre: { names: ["coffre", "coffre fort", "carte", "carte de la guilde"], label: "le coffre-fort à carte de la Guilde",
      desc: () => "Le coffre-fort neuf de la Guilde : un lecteur de carte, un clavier à code, une serrure à signature. Son algorithme a été relu et prouvé. Sur le papier, il est irréprochable. Dans la vraie vie, il est posé sur une table, et il fait du bruit, de la chaleur et des ombres." },
    revue: { names: ["revue", "revue de code", "dossier", "dossier de revue"], label: "le dossier de revue de code", vis: () => !!F().sfixOK,
      desc: () => "Le dossier de revue de code de la Guilde : quatre extraits de programmes à classer. `examiner revue` les affiche, `classer ‹n› ‹canal›` rend ton verdict (canaux : temps, consommation, cache, ou sain).",
      onExamine: () => {
        out("Les quatre extraits (pseudo-code) :", "sys");
        code("1.  pour i de 0 à 3 :\n      si pin[i] != essai[i] : renvoyer FAUX\n    renvoyer VRAI\n\n2.  resultat = TABLE[octet_secret]\n\n3.  r = 1\n    pour chaque bit b de d :\n      r = r × r\n      si b == 1 : r = r × m\n\n4.  diff = 0\n    pour i de 0 à 3 :\n      diff = diff OU (pin[i] XOR essai[i])\n    renvoyer (diff == 0)");
      } },
    eve: { npc: true, names: ["eve", "ève"], label: "Ève, qui écoute (avec autorisation)",
      desc: () => "Ève porte un casque trop grand et un chronomètre au cou. D'habitude on la croise là où elle n'est pas invitée. Aujourd'hui elle travaille pour la Guilde, avec un ordre de mission signé : c'est sa plus belle journée." },
    banc: { names: ["banc", "banc chronometrique", "serrure", "banc d essai", "chronometre"], label: "le banc chronométrique",
      desc: () => "Un exemplaire d'essai de la serrure du coffre, branché à un chronomètre de jeu. Le banc accepte `mesurer ‹code› ‹n›` (n mesures du code de 4 chiffres), `balayer ‹n› ‹préfixe›` (les 10 chiffres possibles pour la position suivante) et `proposer ‹code›` (essai officiel). L'unité est le « tic » ; le chronomètre est bruité : chaque mesure s'écarte d'environ 5 tics de la valeur vraie.",
      onExamine: () => {
        out("Le programme de la serrure, tel qu'il est écrit :", "sys");
        code("comparer(code, essai) :\n  pour i de 0 à 3 :\n    si code[i] != essai[i] : renvoyer FAUX   # sortie anticipée\n  renvoyer VRAI");
      } },
    alice: { npc: true, names: ["alice"], label: "Alice, ingénieure de la carte",
      desc: () => "Alice, ingénieure de la carte, tient un fer à souder comme un stylo. Elle a conçu la signature de la carte : « Elle est juste, je te le jure. »" },
    oscillo: { names: ["oscilloscope", "oscillo", "trace", "sonde"], label: "l'oscilloscope",
      desc: () => `Un oscilloscope relié à l'alimentation de la carte. La carte signe un défi (m = ${RM}) avec son exposant secret d, par « carré-multiplication » : pour chaque bit de d, un CARRÉ ; si le bit vaut 1, une MULTIPLICATION de plus. Chaque opération = une barre dans la trace (hauteur = consommation). Commandes : \`capter ‹n›\` (moyenne de n captures), \`deduire ‹bits›\`, \`aveugler ‹m›\`, \`activer ‹régulier|bruit|normal›\`.` },
    bob: { npc: true, names: ["bob"], label: "Bob, développeur du coffre",
      desc: () => "Bob, développeur, sirote un café. Il est persuadé que son programme est « de la cryptographie propre, avec des tables précalculées pour aller vite »." },
    casiers: { names: ["casiers", "cache", "lignes", "tableau"], label: "les huit casiers du cache",
      desc: () => `Huit casiers numérotés de 0 à 7 : c'est le cache partagé entre ton programme d'observation et la routine de Bob. Bob traite 4 octets secrets (de 3 bits) ; pour l'octet n°i il lit le casier « secret XOR entrée publique ». Entrées publiques connues : octet 1 → ${PUB[0]}, octet 2 → ${PUB[1]}, octet 3 → ${PUB[2]}, octet 4 → ${PUB[3]}. Commandes : \`remplir\`, \`declencher ‹octet›\`, \`sonder\`, \`deduire ‹4 nombres›\`, \`activer ‹uniforme|partition|normal›\`, \`xor ‹a› ‹b›\`.` },
    mallory: { npc: true, names: ["mallory"], label: "Mallory (côté équipe rouge, autorisée)",
      desc: () => "Mallory, côté équipe rouge pour cet audit, a posé sur la table un petit processeur-jouet en verre transparent. Elle sourit comme quelqu'un qui connaît la fin de l'histoire." },
    augure: { names: ["augure", "processeur", "l augure", "cpu"], label: "l'Augure (processeur-jouet)",
      desc: () => `Un processeur-jouet qui devine les verdicts. Son programme : « donne la case i de l'ardoise (4 cases : 0 à 3) ; si i est hors de l'ardoise, réponds REFUSÉ ». Mais pour gagner du temps, il parie sur le verdict AVANT de le connaître et avance à blanc. Juste après l'ardoise, la mémoire contient 3 cases secrètes (indices 4, 5 et 6). Commandes : \`entrainer ‹n›\`, \`provoquer ‹i›\` (i de 0 à 6), \`sonder\`, \`deduire ‹3 nombres›\`, \`activer ‹barriere|ciblee|masque|isolation|normal›\`, \`couts\`.` },
    panneau: { names: ["panneau", "autres canaux", "mur"], label: "le panneau « Autres canaux »",
      desc: () => "Un panneau de liège, trois fiches épinglées.\n**Acoustique** : les composants (condensateurs, bobines) et les claviers émettent des sons qui varient avec ce qu'ils calculent ou tapent.\n**Électromagnétique** : un circuit qui calcule rayonne ; une antenne proche peut voir ce rayonnement, comme la consommation, sans toucher la machine.\n**Défauts injectés** : ici l'attaquant n'écoute plus, il PERTURBE (variation de tension, lumière, chaleur) pour faire se tromper un calcul ; la comparaison d'une sortie fausse avec une bonne peut trahir une clé.\nDéfenses d'ensemble : blindage, capteurs de perturbation, vérifier le résultat avant de le rendre, ne pas laisser de secret influencer ce qui sort." },
  };

  const rooms = {
    hall: { name: "Le Hall du Coffre", short: "Hall", alias: ["hall", "coffre", "entree"], ents: ["ada", "coffre", "revue"], exits: { nord: "chrono", est: "oscillo", sud: "cache", ouest: "augures" },
      desc: () => "Le hall de la Guilde, où trône le coffre-fort neuf. Quatre portes : au nord l'Atelier du Chronomètre, à l'est la Salle de l'Oscilloscope, au sud la Galerie du Cache, à l'ouest le Cabinet des Augures." },
    chrono: { name: "L'Atelier du Chronomètre", short: "Chronomètre", alias: ["chrono", "atelier", "chronometre"], ents: ["eve", "banc"], exits: { sud: "hall" },
      desc: () => "Un atelier où tout tictaque. Sur l'établi, un exemplaire d'essai de la serrure du coffre est relié à un chronomètre de jeu." },
    oscillo: { name: "La Salle de l'Oscilloscope", short: "Oscilloscope", alias: ["oscillo", "oscilloscope", "salle"], ents: ["alice", "oscillo"], exits: { ouest: "hall" },
      desc: () => "Une salle sombre, éclairée par l'écran vert d'un oscilloscope. Des fils minces relient la carte du coffre à l'appareil." },
    cache: { name: "La Galerie du Cache", short: "Cache", alias: ["cache", "galerie"], ents: ["bob", "casiers"], exits: { nord: "hall" },
      desc: () => "Une galerie de casiers numérotés, que tout le monde se partage. Bob y range et y retrouve les données de son programme ; toi aussi." },
    augures: { name: "Le Cabinet des Augures", short: "Augures", alias: ["augures", "cabinet", "augure"], ents: ["mallory", "augure", "panneau"], exits: { est: "hall" },
      desc: () => "Un cabinet de curiosités. Un processeur-jouet en verre pulse sur la table de Mallory. Au mur, un panneau de liège." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.swept) return "tmes";
    if (!x.opened) return "tcode";
    if (!x.tc) return "tfix";
    if (!x.tproof) return "tproof";
    if (!x.tr) return "ccap";
    if (!x.dkeyOK) return "cbits";
    if (!x.regSeen) return "creg";
    if (!x.blindDone) return "cblind";
    if (!x.kleak) return "kprobe";
    if (!x.kdeduced) return "kdeduce";
    if (!x.uniSeen) return "kuni";
    if (!x.partSeen) return "kpart";
    if (!x.spLeak) return "sprime";
    if (!x.sread) return "sread";
    if (!x.sfixOK) return "sfix";
    if (!x.rvDone) return "revue";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada attend dans le hall.", "`parler ada`"],
    tmes: () => ["Va à l'Atelier du Chronomètre (au nord) et fais des mesures : une seule est trop bruitée, il en faut beaucoup.", "`aller nord`, `parler eve`, puis `balayer 100` : pour chacun des 10 chiffres, 100 mesures moyennées."],
    tcode: () => ["Le chiffre dont la moyenne est la plus haute est juste (la comparaison est allée plus loin). Fixe-le, passe à la position suivante.", "`balayer 100` (position 1), puis `balayer 100 ‹chiffre trouvé›` (position 2), `balayer 100 ‹deux chiffres›`... Avec 4 chiffres : `proposer ‹code›`."],
    tfix: () => ["Le code est ouvert, mais la serrure fuit. Applique la contre-mesure : une comparaison qui dure toujours pareil.", "`activer temps constant`"],
    tproof: () => ["Vérifie que la contre-mesure fonctionne : refais un balayage avec beaucoup de mesures.", "`balayer 100` (au moins 50 mesures) : plus aucun chiffre ne doit se détacher."],
    ccap: () => ["Va dans la Salle de l'Oscilloscope (à l'est du hall) et capte la consommation de la carte.", "`aller sud` (retour au hall) puis `aller est`, `parler alice`, `capter`."],
    cbits: () => ["Lis la trace : chaque bit commence par une barre S (carré) ; si une barre M suit, le bit vaut 1, sinon 0. La première barre S est le bit de poids fort.", "Écris les bits dans l'ordre : `deduire ‹bits›` (par exemple 0 pour un S seul, 1 pour S puis M ; il y a 12 barres S)."],
    creg: () => ["Passe l'algorithme en comportement régulier et capte à nouveau : la trace doit cesser de te renseigner.", "`activer regulier` puis `capter`."],
    cblind: () => ["Dernière contre-mesure : l'aveuglement. Regarde ce que la carte calcule vraiment.", "`aveugler 65` (tu peux le relancer : r change, le résultat non)."],
    kprobe: () => ["Va à la Galerie du Cache (au sud du hall). Amorce les casiers avec tes données, laisse Bob travailler, puis mesure tes accès.", "`remplir`, `declencher 1`, `sonder` : une ligne est lente, c'est celle que Bob a touchée."],
    kdeduce: () => ["Pour chaque octet : ligne touchée = secret XOR entrée publique, donc secret = ligne XOR entrée. Fais les 4 octets.", "`remplir`, `declencher ‹1 à 4›`, `sonder`, puis `xor ‹ligne› ‹entrée publique›`. Quand tu as les 4 valeurs : `deduire ‹a› ‹b› ‹c› ‹d›`."],
    kuni: () => ["Première contre-mesure : des accès indépendants du secret. Active-la, relance la même expérience.", "`activer uniforme`, `remplir`, `declencher 1`, `sonder`."],
    kpart: () => ["Seconde contre-mesure : partager le cache en domaines séparés.", "`activer partition`, `remplir`, `declencher 1`, `sonder`."],
    sprime: () => ["Va au Cabinet des Augures (à l'ouest du hall). Il faut d'abord convaincre l'Augure que « tout va bien » : entraîne-le avec des demandes légitimes, puis demande hors de l'ardoise, puis regarde le cache.", "`entrainer 3`, `provoquer 4`, `sonder`."],
    sread: () => ["Les cases 4, 5, 6 sont secrètes. La ligne rapide donne la valeur. Attention : chaque erreur de pari affaiblit la confiance de l'Augure, ré-entraîne-le au besoin.", "`entrainer 3`, `provoquer ‹4, 5 ou 6›`, `sonder` pour chacune ; puis `deduire ‹a› ‹b› ‹c›`."],
    sfix: () => ["Choisis un correctif, vérifie qu'il ferme la fuite, regarde ce qu'il coûte.", "`couts` compare ; puis par exemple `activer masque`, `entrainer 3`, `provoquer 4`, `sonder`."],
    revue: () => ["Maître Ada a un dossier de revue de code pour toi, dans le hall. Classe les quatre extraits.", "`aller est` (retour au hall), `examiner revue`, puis `classer ‹n› ‹temps|consommation|cache|sain›`."],
    end: () => ["Tu as tout compris. Retourne voir Maître Ada.", "`parler ada`"],
    fin: () => ["Mission terminée ! Relis ton carnet.", "`carnet` et `analogies`"],
  };

  /* ---------- dialogues ---------- */
  const NEXT = {
    tmes: "Au nord, l'Atelier du Chronomètre : Ève t'y attend avec son chronomètre.",
    tcode: "Retourne à l'Atelier du Chronomètre : il faut encore retrouver le code.",
    tfix: "Le code est tombé ; corrige la serrure (`activer temps constant`).",
    tproof: "Vérifie que la serrure corrigée ne fuit plus (`balayer 100`).",
    ccap: "À l'est, la Salle de l'Oscilloscope : Alice t'y attend.",
    cbits: "Lis la trace de consommation et retrouve l'exposant secret (`deduire ‹bits›`).",
    creg: "Passe la carte à un algorithme régulier (`activer regulier`) et recapte.",
    cblind: "Teste l'aveuglement (`aveugler 65`).",
    kprobe: "Au sud, la Galerie du Cache : Bob t'y attend.",
    kdeduce: "Retrouve les quatre octets secrets de Bob (`deduire ‹a› ‹b› ‹c› ‹d›`).",
    kuni: "Teste l'accès uniforme (`activer uniforme`).",
    kpart: "Teste le partitionnement (`activer partition`).",
    sprime: "À l'ouest, le Cabinet des Augures : Mallory t'y attend.",
    sread: "Lis les trois cases secrètes derrière l'ardoise (`deduire ‹a› ‹b› ‹c›`).",
    sfix: "Choisis un correctif pour l'Augure et vérifie-le (`couts`, `activer ...`).",
    revue: "Examine le dossier de revue de code ici même, dans le hall.",
  };

  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Le coffre-fort neuf de la Guilde a passé toutes les revues : l'algorithme est correct, prouvé, relu trois fois. Et pourtant je ne dors pas. Un cadenas parfait qui grince quand on tourne la bonne molette n'est plus un cadenas parfait.");
          say("Maître Ada", "Je t'engage pour un audit autorisé : tu joueras Ève, celle qui écoute. Tu n'attaques pas les mathématiques, tu écoutes la machine : son temps, sa consommation, ses accès à la mémoire, ses paris de processeur. Tout se passe sur des machines et des mesures de jeu, avec des nombres minuscules.");
          note("canal");
          out("Commence par l'Atelier du Chronomètre, au nord (`aller nord`).", "sys");
        } else if (x.end) say("Maître Ada", "Le coffre dort enfin avec une serrure qui ne grince plus. La Guilde te doit un thé, et un budget pour l'audit du reste des machines.");
        else if (x.sfixOK && x.rvDone) ending();
        else if (x.sfixOK) say("Maître Ada", "Il ne reste que la revue de code : mon dossier est posé là, près du coffre (`examiner revue`). Classe chaque extrait : temps, consommation, cache, ou sain.");
        else say("Maître Ada", NEXT[objective()] || "Continue.");
        break;
      case "eve":
        if (!x.opened) {
          say("Ève", "Je ne sais rien du code du coffre. Je sais seulement que la serrure compare ce qu'on lui donne au vrai code, chiffre par chiffre, et qu'elle s'arrête à la première différence. Dis-moi : que se passe-t-il pour la durée ?");
          code("comparer(code, essai) :\n  pour i de 0 à 3 :\n    si code[i] != essai[i] : renvoyer FAUX   # sortie anticipée\n  renvoyer VRAI");
          say("Ève", "Si le premier chiffre est juste, elle fait un tour de plus avant de s'arrêter. Chaque tour dure 4 tics. Mais mon chronomètre bruite de ±5 tics : une mesure isolée ne sert à rien. Alors on moyenne : `balayer ‹n› ‹préfixe›` mesure n fois chacun des 10 chiffres possibles à la position suivante. Essaie avec n = 1, puis avec n = 100, et compare.");
        } else if (!x.tc) say("Ève", "Le code est tombé. Mais ce n'est pas lui le problème, c'est la serrure : sa durée dépend du secret. Applique la correction : `activer temps constant`.");
        else if (!x.tproof) say("Ève", "Refais un balayage avec au moins 50 mesures par chiffre : on veut voir qu'il n'y a plus rien à lire.");
        else say("Ève", "Le temps ne dit plus rien. Mais attention : un code qui ne fuit plus par le temps peut encore fuir par autre chose. Va voir Alice, à l'est du hall.");
        break;
      case "alice":
        if (!x.tr) {
          say("Alice", "Ma carte signe un défi avec son exposant secret d, par « carré-multiplication ». Pour chaque bit de d, du plus fort au plus faible : un carré ; et si le bit vaut 1, une multiplication de plus. C'est l'algorithme du manuel. Le défi et la signature sont publics ; d, jamais.");
          say("Alice", "L'oscilloscope trace la consommation de la carte : une barre par opération. Un carré est plus sobre qu'une multiplication. Essaie : `capter`.");
        } else if (!x.dkeyOK) say("Alice", `Lis chaque barre. S = carré. M = multiplication. Un S suivi d'un M : bit 1. Un S suivi d'un autre S : bit 0. Écris tous les bits (la trace compte 12 barres S), puis \`deduire ‹bits›\`.`);
        else if (!x.regSeen) say("Alice", "Tu as lu mon secret dans la consommation. Ça arrive avec du vrai matériel, sur les premiers modèles. Première parade : un algorithme régulier, qui fait la même chose pour chaque bit. `activer regulier`, puis `capter`.");
        else if (!x.blindDone) say("Alice", "Seconde parade : l'aveuglement. Je randomise l'entrée avant de signer, et j'enlève la randomisation après. `aveugler 65` te montre le calcul réel.");
        else say("Alice", "Régulier, aveuglé, éventuellement un peu bruité : trois couches. Une couche seule, ça se contourne ; plusieurs, ça coûte cher à l'attaquant.");
        break;
      case "bob":
        if (!x.kleak) {
          say("Bob", "Ma routine traite 4 octets secrets de 3 bits. Pour aller vite, j'ai une table de 8 entrées, rangée dans les casiers du cache. Pour chaque octet, je lis l'entrée « secret XOR entrée publique » : instantané. Aucune fuite à l'écran, aucune erreur, aucun message. Que voudrais-tu qu'on en tire ?");
          say("Bob", "Mais le cache est partagé : si tu y ranges tes propres données (`remplir`), ma routine en évince une, celle qu'elle utilise (`declencher ‹octet›`). Après, tu chronomètres tes propres accès (`sonder`) : rapide = ta donnée est toujours là, lent = quelqu'un l'a évincée.");
        } else if (!x.kdeduced) say("Bob", "Pour chaque octet, la ligne touchée = secret XOR entrée publique. `xor ‹a› ‹b›` t'aide à calculer.");
        else if (!x.uniSeen || !x.partSeen) say("Bob", "D'accord, j'ai compris. Je peux réécrire ma routine pour toucher toutes les lignes à chaque fois (`activer uniforme`), ou on peut séparer les caches (`activer partition`). Essaie les deux.");
        else say("Bob", "Bien. Je reste sur l'accès uniforme dans le code critique, et le partitionnement sur les machines partagées.");
        break;
      case "mallory":
        if (!x.spLeak) {
          say("Mallory", "L'Augure est un processeur-jouet très pressé. Son programme : « donne la case i de l'ardoise ; si i est hors de l'ardoise, réponds REFUSÉ ». Mais vérifier prend du temps, alors il parie sur le verdict avant de le connaître, et lit quand même. Si le pari était faux, il jette tous les résultats, mais pas les traces laissées dans le cache.");
          say("Mallory", "Entraîne-le d'abord avec des demandes légitimes (`entrainer 3`), puis demande hors de l'ardoise (`provoquer 4`), puis regarde quel casier est rapide (`sonder`). C'est un modèle de jeu : la vraie histoire est bien plus compliquée, et je ne t'en dirai pas les détails.");
        } else if (!x.sread) say("Mallory", "Chaque fausse alerte affaiblit un peu sa confiance : au bout de deux ratés, il ne parie plus. Ré-entraîne-le entre deux lectures. Trois cases secrètes : 4, 5 et 6.");
        else if (!x.sfixOK) say("Mallory", "Le secret est lu, alors maintenant la question qui fâche : que fait-on ? `couts` compare les correctifs, et `activer ...` en met un en place. Vérifie ensuite que la fuite est fermée.");
        else say("Mallory", "Trois correctifs, trois prix. Les équipes désactivent ce qui ralentit trop : un bon correctif est un correctif qu'on garde.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- 1. temps ---------- */
  function cmdMesurer(c) {
    const x = F();
    if (!need("chrono", "Le chronomètre est à l'Atelier (nord du hall).")) return;
    const t = c.rawArg.split(/\s+/).filter(Boolean), g = t[0] || "", n = t[1] == null ? 1 : parseInt(t[1], 10);
    if (!/^\d{4}$/.test(g)) { out("Le banc attend un code de 4 chiffres : `mesurer 0000 50` (code, puis nombre de mesures).", "err"); return; }
    if (!(n >= 1 && n <= 500)) { out("Le nombre de mesures doit être entre 1 et 500.", "err"); return; }
    x.swept = true;
    const v = measure(g, n);
    if (n === 1) {
      out(`Une mesure du code ${g} : **${fx(v[0])} tics**. (Le chronomètre bruite d'environ ±5 tics : une seule mesure ne prouve rien.)`, "ok");
    } else {
      const m = mean(v), sd = Math.sqrt(mean(v.map(a => (a - m) ** 2)));
      out(`${n} mesures du code ${g} : moyenne **${fx(m)} tics** (écart-type des mesures ${fx(sd)} ; incertitude sur la moyenne ≈ ±${fx(5 / Math.sqrt(n), 2)}).`, "ok");
      if (n <= 5) out("Valeurs : " + v.map(a => fx(a)).join(" ; ") + ".", "sys");
    }
  }
  function cmdBalayer(c) {
    const x = F();
    if (!need("chrono", "Le chronomètre est à l'Atelier (nord du hall).")) return;
    const t = c.rawArg.split(/\s+/).filter(Boolean), n = parseInt(t[0], 10), pre = t[1] || "";
    if (!(n >= 1 && n <= 500) || !/^\d{0,3}$/.test(pre)) { out("`balayer ‹n› ‹préfixe›` : n entre 1 et 500 mesures par chiffre, préfixe = les chiffres déjà trouvés (0 à 3 chiffres, vide pour la position 1). Exemple : `balayer 100 30`.", "err"); return; }
    x.swept = true;
    const avg = [];
    for (let d = 0; d <= 9; d++) avg.push(mean(measure(pre + d + "-".repeat(3 - pre.length), n)));
    out(`Position ${pre.length + 1}, préfixe « ${pre || "∅"} », ${n} mesure${n > 1 ? "s" : ""} par chiffre :`, "sys");
    code(avg.map((a, d) => `${pre}${d}${"-".repeat(3 - pre.length)}  ${pad(fx(a), 6)} tics  ${"█".repeat(Math.max(1, Math.round((a - 96) / 1.5)))}`).join("\n"));
    const srt = avg.slice().sort((a, b) => b - a), gap = srt[0] - srt[1], sdm = 5 / Math.sqrt(n);
    if (x.tc) {
      out(`Écart entre le plus long et le plus court : ${fx(srt[0] - srt[9])} tics, pour une incertitude de ±${fx(sdm, 2)} : tout est dans le bruit, plus aucun chiffre ne se détache.`, "ok");
      if (n >= 50 && !x.tproof) {
        x.tproof = true; note("tempsconstant"); fig("temps");
        say("Ève", "Muet. Le temps ne dépend plus du secret : je n'ai plus rien à écouter de ce côté-là. Mais le temps n'est pas le seul bruit d'une machine : va voir Alice, à l'est du hall.");
      } else if (n < 50) out("(Avec si peu de mesures, tout paraît plat de toute façon. Pour être convaincant : au moins 50 mesures par chiffre.)", "sys");
    } else if (gap < 3 * sdm) {
      out(`Les deux chiffres les plus longs ne sont séparés que de ${fx(gap)} tics, pour une incertitude de ±${fx(sdm, 2)} sur chaque moyenne : tu ne peux pas conclure. Fais plus de mesures (le bruit baisse comme 1/√n).`, "err");
    } else out("Un chiffre se détache nettement du lot.", "ok");
  }
  function cmdProposer(c) {
    const x = F();
    if (!need("chrono", "Le coffre d'essai est à l'Atelier (nord du hall).")) return;
    const g = c.rawArg.replace(/\s+/g, "");
    if (!/^\d{4}$/.test(g)) { out("Propose un code de 4 chiffres : `proposer 1234`.", "err"); return; }
    if (g === CODE) {
      if (x.opened) { out("Le coffre d'essai est déjà ouvert avec ce code.", "sys"); return; }
      x.opened = true;
      out(`Clic. Le banc s'ouvre : **${CODE}**. ${x.tries ? "Tu n'as eu que " + x.tries + " essai" + (x.tries > 1 ? "s" : "") + " raté" + (x.tries > 1 ? "s" : "") + " ; le reste, c'était" : "Aucun essai raté : tout est venu"} de l'écoute du chronomètre.`, "ok");
      say("Ève", "Sans jamais deviner à l'aveugle : 10 chiffres × 4 positions = au plus 40 séries de mesures, au lieu de 10 000 essais. L'écoute transforme une montagne en escalier.");
      note("temps"); fig("temps");
      out("Reste à corriger la serrure : `activer temps constant`.", "sys");
    } else {
      x.tries = (x.tries || 0) + 1;
      out(`Bip. Code refusé (erreur n°${x.tries}).`, "err");
      if (x.tries >= 3 && !x.triesTold) {
        x.triesTold = true;
        say("Ève", "Sur un vrai coffre, trois erreurs bloqueraient la carte : voilà pourquoi il faut mesurer sans essayer, ou sur un exemplaire à soi. Ici le banc est un modèle d'essai : il ne bloque pas. Limiter les essais est utile, mais ça ne ferme pas la fuite.");
      } else out("Astuce : tu n'as pas besoin d'essayer au hasard. `balayer 100` te dit quel chiffre est juste, position par position.", "sys");
    }
  }

  /* ---------- 2. consommation ---------- */
  function cmdCapter(c) {
    const x = F();
    if (!need("oscillo", "L'oscilloscope est dans la Salle de l'Oscilloscope (est du hall).")) return;
    const n = c.rest[0] == null ? 1 : parseInt(c.rest[0], 10);
    if (!(n >= 1 && n <= 64)) { out("Le nombre de captures doit être entre 1 et 64 : `capter 16`.", "err"); return; }
    const run = x.reg ? ladder(RM, RD, RN) : sqmul(RM, RD, RN);
    const sd = (x.noise ? 20 : 3) / Math.sqrt(n);
    const ops = run.ops.map(k => ({ k, v: (k === "S" ? 40 : 70) + gauss(sd) }));
    x.tr = { ops, reg: !!x.reg, n, noise: !!x.noise };
    x.sig = run.r;
    if (x.reg) x.regSeen = true;
    out(`${n > 1 ? "Moyenne de " + n + " captures" : "Capture unique"} : la carte signe le défi m = ${RM}, signature publique s = ${run.r}. Une ligne par opération (S = carré, M = multiplication) :`, "sys");
    code(ops.map((o, i) => `${pad(i + 1, 2)}  ${o.k}  ${"█".repeat(Math.max(1, Math.round(o.v / 6)))} ${fx(o.v)}`).join("\n"));
    if (x.reg) {
      out("Chaque bit donne exactement la même séquence (M puis S) : rien ne distingue un 0 d'un 1. La signature, elle, est identique : la contre-mesure ne change pas le résultat, seulement ce qui fuit.", "ok");
    } else if (x.noise) {
      out(n === 1 ? "Le bruit ajouté rend la lecture incertaine : les barres S et M se mélangent. Mais le secret n'est pas caché pour autant : essaie `capter 16`, en moyennant, il réapparaît." : "En moyennant les captures, le bruit s'efface : la trace redevient lisible. Le bruit coûte des mesures à l'attaquant, il ne cache rien.", "sys");
    } else if (!x.dkeyOK) {
      say("Alice", "Voilà ma trace. Rappelle-toi : un S seul est un bit 0, un S suivi d'un M est un bit 1. À toi de lire.");
    }
    fig("trace");
  }
  function deduceBits(c) {
    const x = F();
    if (!need("oscillo", "Les traces se lisent à la Salle de l'Oscilloscope (est du hall).")) return;
    if (!x.tr) { out("Capte d'abord une trace : `capter`.", "err"); return; }
    const bits = c.rawArg.replace(/\s+/g, "");
    if (!/^[01]+$/.test(bits)) { out("Écris les bits lus : `deduire 1011...` (des 0 et des 1).", "err"); return; }
    if (x.dkeyOK) { out("Tu as déjà retrouvé l'exposant secret.", "sys"); return; }
    if (x.reg) { out("La carte est en mode régulier : sa trace est la même quel que soit le secret, ta lecture ne serait qu'une devinette. (`activer normal` pour revenir à l'algorithme du manuel.)", "err"); return; }
    const d = parseInt(bits, 2), s = modpow(RM, d, RN), ref = x.sig != null ? x.sig : modpow(RM, RD, RN);
    if (bits === SEC_BITS) {
      x.dkeyOK = true;
      out(`${bits} = ${d} en décimal. Vérification par le calcul : ${RM}^${d} mod ${RN} = **${s}**, exactement la signature émise par la carte (${ref}).`, "ok");
      out(`Et avec la clé publique : ${s}^${RE} mod ${RN} = ${modpow(s, RE, RN)}. Tu viens de retrouver la clé privée de la carte avec un oscilloscope.`, "ok");
      say("Alice", "Je n'ose pas dire que j'avais prévenu. Seulement : l'algorithme était juste, c'est son exécution qui parlait.");
      note("conso"); fig("trace");
      out("Maintenant, ferme cette fuite : `activer regulier`, puis `capter`.", "sys");
    } else {
      let msg = `${bits} = ${d} : ${RM}^${d} mod ${RN} = ${s}, alors que la carte a signé ${ref}. Ce n'est pas le bon exposant.`;
      if (bits.length !== SEC_BITS.length) msg += ` Compte les barres S de la trace : il y en a une par bit (${SEC_BITS.length}).`;
      else {
        const bad = []; for (let i = 0; i < bits.length; i++) if (bits[i] !== SEC_BITS[i]) bad.push(i + 1);
        msg += ` Relis les bits n° ${bad.join(", ")} (en partant du bit de poids fort = n°1).`;
      }
      out(msg, "err");
    }
  }
  function cmdAveugler(c) {
    const x = F();
    if (!need("oscillo", "Alice montre l'aveuglement à la Salle de l'Oscilloscope (est du hall).")) return;
    const arg = c.rawArg.trim(), m = arg === "" ? RM : parseInt(arg, 10);
    if (!(m >= 2 && m < RN)) { out(`Donne un message entre 2 et ${RN - 1} : \`aveugler ${RM}\`.`, "err"); return; }
    let r; do { r = 2 + Math.floor(rnd() * (RN - 3)); } while (gcd(r, RN) !== 1);
    const mp = (m * modpow(r, RE, RN)) % RN, sp = modpow(mp, RD, RN), ri = modinv(r, RN), s = (sp * ri) % RN, ref = modpow(m, RD, RN);
    x.blind = { m, r, mp, sp, s, ri, ok: s === ref };
    const L = [
      `Signature aveuglée du message m = ${m}`,
      `1. tirage d'un facteur aléatoire r = ${r} (premier avec n = ${RN})`,
      `2. entrée aveuglée : m' = m × r^e mod n = ${m} × ${r}^${RE} mod ${RN} = ${mp}`,
      `3. la carte signe m' (c'est CE qu'on peut observer) : s' = m'^d mod n = ${sp}`,
      `4. retrait du facteur : s = s' × r⁻¹ mod n = ${sp} × ${ri} mod ${RN} = ${s}`,
      `5. contrôle : m^d mod n = ${ref}  ->  ${s === ref ? "identique" : "DIFFÉRENT (erreur)"}`,
    ];
    if (gcd(m, RN) === 1) {
      const k = 1 + Math.floor(rnd() * 8), d2 = RD + k * RPHI, s2 = modpow(m, d2, RN);
      L.push(`6. variante : exposant masqué d' = d + k × φ = ${RD} + ${k} × ${RPHI} = ${d2} (${d2.toString(2).length} bits) -> m^d' mod n = ${s2}  ->  ${s2 === ref ? "même signature" : "DIFFÉRENT"}`);
    }
    code(L.join("\n"));
    out(`Pourquoi ça marche : (m × r^e)^d = m^d × r^(e·d) ≡ m^d × r (mod n), car e·d ≡ 1 (mod φ). Il suffit alors de diviser par r. Chaque relance tire un autre r : l'entrée vue par l'observateur (${mp}) n'est jamais ${m}, et ne se répète pas. Quant à l'exposant masqué, il a une autre écriture binaire à chaque fois : la trace d'une capture ne ressemble plus à celle d'une autre.`, "ok");
    if (!x.blindDone) { x.blindDone = true; note("aveuglement"); say("Alice", "Retiens la limite : l'aveuglement protège contre les attaques qui exploitent l'entrée connue ou plusieurs traces comparées. Il ne remplace pas un algorithme régulier. Trois couches valent mieux qu'une."); }
    fig("blinding");
  }

  /* ---------- 3. cache ---------- */
  function cmdRemplir() {
    const x = F();
    if (!need("cache", "Les casiers sont à la Galerie du Cache (sud du hall).")) return;
    x.cprimed = true; x.vic = null;
    out("Tu ranges tes propres données dans les 8 casiers. Chacun est maintenant à toi.", "ok");
  }
  function cmdDeclencher(c) {
    const x = F();
    if (!need("cache", "Bob travaille à la Galerie du Cache (sud du hall).")) return;
    const i = parseInt(c.rest[0], 10);
    if (!(i >= 1 && i <= 4)) { out("Quel octet de Bob ? `declencher 1` à `declencher 4`.", "err"); return; }
    const L = SECRET[i - 1] ^ PUB[i - 1];
    x.vic = { i, line: L };
    out(`Bob lance sa routine sur l'octet n°${i} (entrée publique : ${PUB[i - 1]}). Il lit un casier de sa table...`, "sys");
    say("Bob", "Rien à signaler de mon côté : j'ai lu une entrée de ma table, et voilà.");
    if (!x.cprimed) out("(Tes casiers n'étaient pas amorcés : tu n'as rien préparé pour l'observer. `remplir` d'abord.)", "sys");
  }
  function probeCache() {
    const x = F();
    if (!need("cache", "Les casiers sont à la Galerie du Cache (sud du hall).")) return;
    const prim = !!x.cprimed, ev = x.vic ? evicted(x.vic.line) : [];
    const slow = i => !prim || ev.includes(i);
    const times = []; for (let i = 0; i < 8; i++) times.push(slow(i) ? 40 + gauss(4) : 4 + gauss(1.2));
    x.probe = times.map(v => Math.round(v * 10) / 10); x.probeMode = x.cmode;
    out("Tu relis tes 8 casiers en chronométrant chaque lecture :", "sys");
    code(times.map((t, i) => `ligne ${i}  ${pad(fx(t), 5)} tics  ${"█".repeat(Math.max(1, Math.round(t / 4)))}  ${t > 20 ? "lente" : "rapide"}`).join("\n"));
    const sl = times.map((t, i) => (t > 20 ? i : -1)).filter(i => i >= 0);
    const vic = x.vic; x.cprimed = true; x.vic = null; // la sonde re-remplit les casiers
    if (!prim) { out("Tout est lent : tes données n'étaient pas dans les casiers, il n'y avait rien à comparer. La sonde vient de les remplir : le prochain `declencher` sera lisible.", "err"); return; }
    if (!vic) { out("Tout est rapide : personne n'a touché tes casiers depuis la dernière fois. (Fais travailler Bob : `declencher ‹octet›`.)", "sys"); return; }
    if (x.cmode === "uni") {
      out("Les 8 lignes sont lentes : la routine de Bob lit toute la table à chaque fois. Tu sais que Bob a travaillé, mais pas quelle entrée il voulait : l'accès ne dépend plus du secret.", "ok");
      if (!x.uniSeen) { x.uniSeen = true; say("Bob", "Huit fois plus d'accès, c'est le prix. Mais plus rien ne fuit par là."); }
    } else if (x.cmode === "part") {
      out("Les 8 lignes sont rapides : les accès de Bob restent dans SA partition du cache et n'évincent rien chez toi. Plus de signal.", "ok");
      if (!x.partSeen) { x.partSeen = true; say("Bob", "Chacun son quartier, plus de voisin bruyant. Mais le cache de chacun est deux fois plus petit."); }
    } else if (sl.length === 1) {
      const L = sl[0], X = PUB[vic.i - 1];
      out(`Une seule ligne lente : la n°${L}. C'est la ligne que Bob a lue pour l'octet n°${vic.i}. Comme ligne = secret XOR entrée publique (${X}), secret = ${L} XOR ${X}. (Besoin d'aide ? \`xor ${L} ${X}\`.)`, "ok");
      if (!x.kleak) { x.kleak = true; say("Bob", "Mais... je n'ai affiché aucune donnée secrète, rien n'est sorti de ma routine !"); fig("cache"); }
    } else out("Le résultat est ambigu : relance `remplir`, `declencher ‹octet›`, puis `sonder`.", "sys");
  }
  function deduceCache(c) {
    const x = F();
    if (!need("cache", "Les casiers sont à la Galerie du Cache (sud du hall).")) return;
    const v = (c.rawArg.match(/\d/g) || []).map(Number);
    if (v.length !== 4 || v.some(a => a > 7)) { out("Donne les 4 octets secrets (chacun de 0 à 7) : `deduire 1 2 3 4`.", "err"); return; }
    if (x.kdeduced) { out("Tu as déjà retrouvé les octets secrets de Bob.", "sys"); return; }
    if (v.every((a, i) => a === SECRET[i])) {
      x.kdeduced = true;
      out(`Exact : ${SECRET.join(" ")}. Tu as retrouvé les 4 octets secrets de Bob sans jamais voir une de ses variables, juste en regardant des casiers.`, "ok");
      say("Bob", "Elle est rapide, ma table. Et bavarde.");
      note("cache"); fig("cache");
      out("Voyons maintenant les contre-mesures : `activer uniforme`, puis `activer partition`.", "sys");
    } else {
      const ok = v.map((a, i) => a === SECRET[i]);
      out(`Pas tout à fait : octet${ok.filter(b => !b).length > 1 ? "s" : ""} n°${ok.map((b, i) => (b ? 0 : i + 1)).filter(Boolean).join(", ")} à revoir. (secret = ligne XOR entrée publique ; \`xor ‹a› ‹b›\`.)`, "err");
    }
  }

  /* ---------- 4. exécution spéculative ---------- */
  const COSTS = {
    barriere: { nom: "Barrière après chaque branchement", cout: "+8 000 cycles sur 10 000 : +80 %", n: "ferme la fuite partout, mais ruine les performances" },
    ciblee: { nom: "Barrière seulement sur les 40 vérifications sensibles", cout: "+320 cycles : +3,2 %", n: "peu coûteux, mais à condition d'avoir trouvé TOUS les endroits sensibles sur 1 000 branchements" },
    masque: { nom: "Masquage de l'index (on le force dans l'ardoise)", cout: "+40 cycles : +0,4 %", n: "quasi gratuit, mais à écrire à la main à chaque endroit sensible" },
    isolation: { nom: "Vider le prédicteur à chaque changement de domaine", cout: "+1 500 cycles (100 changements × 15) : +15 %", n: "protège les frontières entre domaines, pas les vérifications à l'intérieur d'un même programme" },
  };
  function cmdEntrainer(c) {
    const x = F();
    if (!need("augures", "L'Augure est au Cabinet des Augures (ouest du hall).")) return;
    const n = c.rest[0] == null ? 3 : parseInt(c.rest[0], 10);
    if (!(n >= 1 && n <= 10)) { out("Entraîne l'Augure de 1 à 10 fois : `entrainer 3`.", "err"); return; }
    x.pred = Math.min(3, (x.pred == null ? 1 : x.pred) + n);
    const lines = []; for (let k = 0; k < Math.min(n, 4); k++) lines.push(MEM[k]);
    x.hot = Array.from(new Set(lines)); x.spLast = null;
    out(`Tu envoies ${n} demande${n > 1 ? "s" : ""} légitime${n > 1 ? "s" : ""} (cases de l'ardoise) : l'Augure répond à chaque fois, et son pari « c'est autorisé » se renforce. Confiance : **${x.pred}/3** (il parie « oui » à partir de 2).`, "ok");
  }
  function cmdProvoquer(c) {
    const x = F();
    if (!need("augures", "L'Augure est au Cabinet des Augures (ouest du hall).")) return;
    const i = parseInt(c.rest[0], 10);
    if (!(i >= 0 && i <= 6)) { out("Quelle case ? `provoquer 4` (de 0 à 6 ; 0 à 3 = ardoise, 4 à 6 = hors ardoise).", "err"); return; }
    const p0 = x.pred == null ? 1 : x.pred, ctx = { i, pred0: p0, spec: false, leak: null, masked: false, blocked: null, legit: false };
    if (i < TAB) {
      ctx.legit = true; x.pred = Math.min(3, p0 + 1); x.hot = [MEM[i]];
      out(`Case ${i} de l'ardoise : réponse ${MEM[i]}. Confiance : ${x.pred}/3.`, "ok");
    } else if (x.sfix === "isolation") {
      x.pred = 0; x.hot = []; ctx.blocked = "isolation";
      out(`Case ${i}, hors de l'ardoise. Au changement de domaine, le prédicteur a été vidé : l'Augure n'a plus de pari, il attend la vérification. Réponse : **REFUSÉ**. Confiance : 0/3.`, "ok");
    } else if (x.sfix === "barriere" || x.sfix === "ciblee") {
      x.hot = []; ctx.blocked = "barriere";
      out(`Case ${i}, hors de l'ardoise. La barrière interdit toute avance tant que la vérification n'est pas rendue : pas de lecture spéculative. Réponse : **REFUSÉ**.`, "ok");
    } else if (p0 >= 2) {
      ctx.spec = true; x.pred = p0 - 1;
      if (x.sfix === "masque") { ctx.masked = true; x.hot = [MEM[i & 3]]; }
      else { ctx.leak = MEM[i]; x.hot = [MEM[i]]; }
      out(`Case ${i}, hors de l'ardoise. L'Augure a parié « autorisé » (confiance ${p0}/3) : il a lu ${x.sfix === "masque" ? "la case " + (i & 3) + " (l'index masqué a été ramené DANS l'ardoise)" : "la case " + i} et touché un casier, avant même la vérification. La vérification échoue : tout est annulé. Réponse officielle : **REFUSÉ**. Confiance : ${x.pred}/3.`, "ok");
    } else {
      x.pred = Math.max(0, p0 - 1); x.hot = [];
      out(`Case ${i}, hors de l'ardoise. L'Augure n'a pas osé parier (confiance ${p0}/3, il faut 2) : il a attendu la vérification. Réponse : **REFUSÉ**. Rien d'autre ne s'est passé. (Ré-entraîne-le : \`entrainer 3\`.)`, "sys");
    }
    x.spLast = ctx;
  }
  function probeSpec() {
    const x = F();
    if (!need("augures", "L'Augure est au Cabinet des Augures (ouest du hall).")) return;
    if (!x.hot) { out("Rien à sonder : fais d'abord travailler l'Augure (`entrainer 3`, `provoquer ‹i›`).", "sys"); return; }
    const hot = x.hot, times = []; for (let i = 0; i < 8; i++) times.push(hot.includes(i) ? 4 + gauss(1.2) : 40 + gauss(4));
    x.probe = times.map(v => Math.round(v * 10) / 10); x.probeMode = "spec";
    out("Tu chronomètres la lecture de chaque casier (rapide = déjà là, donc touché par l'Augure) :", "sys");
    code(times.map((t, i) => `casier ${i}  ${pad(fx(t), 5)} tics  ${"█".repeat(Math.max(1, Math.round(t / 4)))}  ${t > 20 ? "lent" : "rapide"}`).join("\n"));
    const ctx = x.spLast; x.hot = null;
    if (!ctx || ctx.legit) out("Les casiers rapides sont ceux des lectures légitimes : des valeurs de l'ardoise, publiques. Rien de secret.", "sys");
    else if (ctx.leak != null) {
      out(`Le casier ${ctx.leak} est rapide, alors que la réponse officielle était REFUSÉ. L'Augure a lu la case ${ctx.i} à blanc et touché le casier de sa valeur : la case ${ctx.i} contient donc **${ctx.leak}**.`, "ok");
      if (!x.spLeak) { x.spLeak = true; say("Mallory", "Voilà. Rien n'est sorti « officiellement ». Il y a juste une trace sur le sol, que personne n'avait pensé à balayer."); fig("specul"); }
    } else if (ctx.masked) {
      out(`Un casier rapide (${MEM[ctx.i & 3]}), mais c'est la valeur d'une case PUBLIQUE de l'ardoise (case ${ctx.i & 3}) : elle ne dit rien du secret. Fuite fermée.`, "ok");
      if (ctx.pred0 >= 2 && !x.sfixOK) { x.sfixOK = true; fig("specul"); say("Mallory", "Pour trois fois rien. Mais il faut y penser à chaque vérification de ce genre, dans tout le code."); }
    } else if (ctx.blocked) {
      out("Aucun casier rapide : l'Augure n'a rien touché de secret. Fuite fermée.", "ok");
      if (ctx.pred0 >= 2 && !x.sfixOK) { x.sfixOK = true; fig("specul"); say("Mallory", "Ça marche : la trace n'a plus lieu d'être. Reste la facture, regarde `couts`."); }
    } else out("Aucun casier rapide : l'Augure n'avait pas parié, il n'y a rien à lire. (Ré-entraîne-le puis relance.)", "sys");
  }
  function deduceSpec(c) {
    const x = F();
    if (!need("augures", "L'Augure est au Cabinet des Augures (ouest du hall).")) return;
    const v = (c.rawArg.match(/\d/g) || []).map(Number);
    if (v.length !== 3 || v.some(a => a > 7)) { out("Donne les 3 cases secrètes (4, 5, 6) : `deduire 1 2 3`.", "err"); return; }
    if (x.sread) { out("Tu as déjà lu les cases secrètes.", "sys"); return; }
    if (v.every((a, i) => a === MEM[TAB + i])) {
      x.sread = true;
      out(`Exact : ${v.join(" ")}. Tu as lu trois cases que le programme refusait officiellement de montrer. (Dans le jeu : un modèle ; dans la vraie vie, il s'agit de pertes de confidentialité entre domaines que les fabricants ont dû corriger en 2018.)`, "ok");
      note("speculation"); fig("specul");
      out("Ferme la fuite : `couts` pour comparer, puis `activer ‹barriere|ciblee|masque|isolation›`, `entrainer 3`, `provoquer 4`, `sonder`.", "sys");
    } else out("Pas tout à fait. Pour chaque case : `entrainer 3`, `provoquer ‹4, 5 ou 6›`, `sonder`. La ligne rapide donne la valeur.", "err");
  }
  function cmdCouts() {
    if (!need("augures", "Le tableau des coûts est au Cabinet des Augures (ouest du hall).")) return;
    out("Charge de test de jeu : 10 000 cycles, 1 000 branchements dont 40 « sensibles » (vérifications sur des valeurs non fiables). Valeurs fictives : seuls les ordres de grandeur comptent, et les vrais coûts dépendent beaucoup de la charge.", "sys");
    code(Object.entries(COSTS).map(([k, v]) => `${k.padEnd(9)} ${v.nom}\n          coût : ${v.cout}\n          ${v.n}`).join("\n"));
    out("`activer ‹barriere|ciblee|masque|isolation›` en met un en place ; `activer normal` l'enlève.", "sys");
  }

  /* ---------- activer (contre-mesures, selon la salle) ---------- */
  function cmdActiver(c) {
    const x = F(), a = c.rest.join(" ");
    if (!F().quest) { say("Maître Ada", "Viens d'abord me voir : `parler ada`."); return; }
    switch (S.room) {
      case "chrono":
        if (/constant/.test(a)) {
          if (x.tc) { out("La comparaison est déjà en temps constant.", "sys"); return; }
          if (!x.opened) { out("Tu n'as pas encore montré la fuite : retrouve d'abord le code (`balayer`, `proposer`).", "sys"); return; }
          x.tc = true;
          out("La serrure est réécrite :", "ok");
          code("comparer_constant(code, essai) :\n  diff = 0\n  pour i de 0 à 3 :\n    diff = diff OU (code[i] XOR essai[i])   # on parcourt TOUT, toujours\n  renvoyer (diff == 0)");
          out("Même résultat, même durée. Vérifie : `balayer 100`.", "sys");
        } else if (/normal|anticip|ancien/.test(a)) { x.tc = false; out("La serrure d'origine (sortie anticipée) est remise.", "sys"); }
        else out("Ici, une seule correction : `activer temps constant` (ou `activer normal` pour revenir en arrière).", "sys");
        break;
      case "oscillo":
        if (/regul/.test(a)) { x.reg = true; out("La carte utilise maintenant un algorithme régulier : à chaque bit, une multiplication et un carré, dans le même ordre. Recapte : `capter`.", "ok"); }
        else if (/bruit/.test(a)) { x.noise = true; out("Du bruit est ajouté à la consommation de la carte (écart-type 20 au lieu de 3). Recapte : `capter`, puis `capter 16`.", "ok"); }
        else if (/aveugl/.test(a)) out("L'aveuglement se regarde à l'œuvre : `aveugler 65`.", "sys");
        else if (/normal|manuel/.test(a)) { x.reg = false; x.noise = false; out("La carte revient à l'algorithme du manuel, sans bruit.", "sys"); }
        else out("Ici : `activer regulier`, `activer bruit`, `activer normal` (et `aveugler ‹m›` pour l'aveuglement).", "sys");
        break;
      case "cache":
        if (/uniform/.test(a)) { x.cmode = "uni"; out("Bob réécrit sa routine : elle lit TOUTES les entrées de sa table à chaque fois, et ne garde que celle dont elle a besoin. Coût : 8 fois plus d'accès pour ce code. Relance : `remplir`, `declencher 1`, `sonder`.", "ok"); }
        else if (/partit/.test(a)) { x.cmode = "part"; out("Le cache est partagé en deux partitions : une pour Bob, une pour toi. Coût : chaque domaine dispose de moitié moins de place (plus de ratés pour tout le monde). Relance : `remplir`, `declencher 1`, `sonder`.", "ok"); }
        else if (/normal/.test(a)) { x.cmode = "none"; out("Le cache redevient partagé, la routine redevient celle d'origine.", "sys"); }
        else out("Ici : `activer uniforme`, `activer partition`, `activer normal`.", "sys");
        break;
      case "augures": {
        const k = /cible/.test(a) ? "ciblee" : /barri/.test(a) ? "barriere" : /masqu/.test(a) ? "masque" : /isol/.test(a) ? "isolation" : /normal|rien|aucun/.test(a) ? "normal" : null;
        if (!k) { out("Ici : `activer barriere|ciblee|masque|isolation`, ou `activer normal` pour retirer le correctif. `couts` compare.", "sys"); return; }
        if (k === "normal") { x.sfix = null; out("Plus de correctif : l'Augure est à nouveau tel quel.", "sys"); return; }
        x.sfix = k;
        out(`Correctif « ${COSTS[k].nom} » en place. Coût : ${COSTS[k].cout}. ${COSTS[k].n[0].toUpperCase() + COSTS[k].n.slice(1)}.`, "ok");
        out("Vérifie qu'il ferme bien la fuite : `entrainer 3`, `provoquer 4`, `sonder`.", "sys");
        if (k === "barriere") say("Mallory", "+80 %... Les équipes la désactiveront en moins d'une semaine. Un correctif qu'on débranche ne protège de rien.");
        break;
      }
      default: out("Il n'y a rien à activer ici. Les contre-mesures se règlent là où se mesure la fuite.", "sys");
    }
  }

  /* ---------- verbes communs répartis selon la salle ---------- */
  function cmdDeduire(c) {
    if (S.room === "oscillo") deduceBits(c);
    else if (S.room === "cache") deduceCache(c);
    else if (S.room === "augures") deduceSpec(c);
    else out("Il n'y a rien à déduire ici : les mesures se font dans les salles (Chronomètre, Oscilloscope, Cache, Augures).", "sys");
  }
  function cmdSonder() {
    if (S.room === "cache") probeCache();
    else if (S.room === "augures") probeSpec();
    else out("On sonde dans la Galerie du Cache (sud du hall) ou chez l'Augure (ouest du hall).", "sys");
  }
  function cmdXor(c) {
    const v = argNums(c);
    if (v.length !== 2 || v.some(a => a > 7)) { out("`xor ‹a› ‹b›` : deux nombres de 0 à 7. Exemple : `xor 6 3`.", "err"); return; }
    out(`${v[0]} = ${bin3(v[0])}, ${v[1]} = ${bin3(v[1])}. Bit à bit (1 si les bits diffèrent) : ${bin3(v[0] ^ v[1])} = **${v[0] ^ v[1]}**.`, "ok");
  }

  /* ---------- revue de code ---------- */
  const ANS = {
    1: { main: ["temps"], alt: [], why: "Sortie anticipée : la durée dépend du nombre de positions justes." },
    2: { main: ["cache"], alt: ["temps"], why: "L'adresse lue dépend du secret : la ligne de cache touchée trahit l'octet. (Le temps de l'accès suit la ligne, donc « temps » est vrai à moitié : le canal, c'est le cache.)" },
    3: { main: ["consommation", "conso"], alt: ["temps"], why: "Une multiplication de plus pour chaque bit à 1 : la consommation (et aussi la durée) reflète les bits du secret." },
    4: { main: ["sain"], alt: [], why: "Toutes les positions sont parcourues, le résultat n'est décidé qu'à la fin : temps constant." },
  };
  function cmdClasser(c) {
    const x = F();
    if (!need("hall", "Le dossier de revue de code est dans le hall (Maître Ada).")) return;
    if (!x.sfixOK) { out("Ada n'a pas encore sorti son dossier : termine d'abord les quatre bancs d'essai.", "sys"); return; }
    const t = c.rawArg.split(/\s+/).filter(Boolean), n = parseInt(t[0], 10), w = norm(t.slice(1).join(" "));
    if (!(n >= 1 && n <= 4) || !w) { out("`classer ‹1 à 4› ‹temps|consommation|cache|sain›`. Exemple : `classer 1 temps`. (`examiner revue` pour relire les extraits.)", "err"); return; }
    if (!["temps", "consommation", "conso", "cache", "sain"].includes(w)) { out("Canaux possibles : temps, consommation, cache, ou sain (aucune fuite).", "err"); return; }
    x.rv = x.rv || {};
    const a = ANS[n];
    if (a.main.includes(w)) {
      x.rv[n] = true; out(`Extrait ${n} : ${w === "sain" ? "sain" : "fuite par " + w}. ${a.why}`, "ok");
    } else if (a.alt.includes(w)) {
      out(`Extrait ${n} : pas faux, mais ce n'est pas le canal principal. ${a.why} Reclasse-le.`, "sys");
    } else if (w === "sain") out(`Extrait ${n} : non, il fuit. Cherche ce qui dépend du secret : la durée, l'énergie ou l'adresse mémoire ?`, "err");
    else if (n === 4) out("Extrait 4 : non, rien ne dépend du secret ici : il parcourt tout, toujours. Il est sain.", "err");
    else out(`Extrait ${n} : non. Demande-toi ce qui varie avec le secret : le nombre d'opérations, le type d'opérations, l'adresse lue ?`, "err");
    if (Object.keys(x.rv).length === 4 && !x.rvDone) {
      x.rvDone = true; note("defense");
      say("Maître Ada", "Quatre sur quatre. Voilà ce qu'on fera à la Guilde : le secret n'influence jamais le temps, l'énergie ni les accès mémoire ; on utilise des bibliothèques à temps constant, on sépare les domaines de confiance, on met le matériel à jour. Reviens me voir.");
      out("Retourne voir Maître Ada : `parler ada`.", "sys");
    }
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Le coffre est le même qu'hier : même algorithme, mêmes mathématiques. Ce qui a changé, c'est que sa serrure dure toujours pareil, que sa carte consomme toujours pareil, que sa table ne se lit plus par morceaux, et que l'on sait ce que coûtent les paris d'un processeur. Un cadenas parfait, ça n'existe pas sans sa quincaillerie.");
    say("Ève", "Et moi, je retourne écouter... mais seulement ce qu'on m'autorise.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le coffre « parfait sur le papier » = un algorithme correct, mais exécuté sur du matériel physique.** Un canal auxiliaire (side channel) n'attaque pas les mathématiques : il exploite ce que l'exécution laisse échapper en plus de la sortie officielle (durée, énergie, accès mémoire, rayonnement).");
    out("**Ève et son chronomètre = attaque temporelle.** Une comparaison à sortie anticipée dure plus longtemps quand le début du code est juste. Une mesure est bruitée, mais la moyenne de beaucoup de mesures annule le bruit : on retrouve le code octet par octet (au pire 10 × 4 séries au lieu de 10 000 essais). Des attaques à distance sur le temps de réponse ont été démontrées en pratique, avec de très nombreuses mesures. Contre-mesure : comparaison en temps constant (parcourir tout, décider à la fin), à laquelle s'ajoute la limitation des essais.");
    out("**L'oscilloscope = analyse de consommation.** Dans « carré-multiplication », chaque bit à 1 de l'exposant ajoute une multiplication : la trace se lit comme le secret (analyse simple, SPA). Contre-mesures : algorithme à comportement régulier (même séquence quel que soit le bit), aveuglement (m × r^e avant, r⁻¹ après : l'entrée vue de l'extérieur change à chaque fois, et on vérifie par le calcul que la signature est la même), masquage de l'exposant (d + k·φ), bruit ajouté (qui ne fait que demander plus de mesures). Les attaques plus fines (analyse différentielle) exploitent des variations bien plus petites, avec de nombreuses traces, et c'est contre elles que l'aveuglement est surtout utile.");
    out("**Les casiers = le cache partagé.** Un programme voisin évince ou laisse en place des lignes selon ses accès ; en chronométrant les siens, on voit lesquelles ont été touchées. Si l'adresse lue dépend d'un secret (table indexée par un octet secret), le secret fuit. Contre-mesures : accès indépendants du secret (tout parcourir), partitionnement du cache entre domaines, ou ne pas partager le cache avec des inconnus.");
    out("**L'Augure = exécution spéculative (Spectre, Meltdown, 2018).** Le processeur parie sur l'issue d'un branchement et exécute à l'avance ; s'il se trompe, les résultats sont jetés mais les traces dans le cache restent. Les correctifs (barrières, masquage d'index, vidage des prédicteurs, mises à jour de microcode, nouvelles générations de processeurs) coûtent en performance et en travail de déploiement ; certains sont à placer à la main à chaque endroit sensible.");
    out("**Les autres canaux.** Acoustique (sons des composants et des claviers), électromagnétique (rayonnement d'un circuit qui calcule), et défauts injectés (perturber un calcul par la tension, la lumière ou la chaleur, et comparer les sorties). Ces attaques demandent un accès physique ou une grande proximité.");
    out("**Les simplifications du jeu.** (1) Tous les nombres sont minuscules (code de 4 chiffres, exposant de 12 bits, cache de 8 lignes) et les mesures sont simulées avec un bruit simple et une graine fixe : en réel, il y a du bruit non gaussien, des caches à plusieurs niveaux, un ordonnanceur, du bruit système. (2) Le coffre d'essai ne bloque pas après des erreurs, alors qu'un vrai limite les essais. (3) La consommation d'une opération dépend aussi des données manipulées, pas seulement de son type : le jeu ne modélise que le type. (4) Le cache est modélisé à la manière d'un petit cache direct, sans politique de remplacement ni préchargement. (5) L'Augure est une caricature pédagogique : un vrai processeur a des dizaines de mécanismes de ce genre, et les failles réelles demandent beaucoup plus de conditions. (6) Aucun de ces modèles n'est transposable à du vrai matériel, et ce n'est pas le but : ce qu'il faut retenir, c'est le principe et les défenses.");
    out("Les noms sont des clins d'œil : Ève est l'écoute classique de la cryptographie ; le coffre « à carte » évoque les cartes à puce et les modules matériels de sécurité.", "sys");
    out("Rappel utile : **le secret ne doit influencer ni le temps, ni l'énergie, ni les accès mémoire ; et une défense en profondeur (bibliothèques à temps constant, séparation des domaines, mises à jour matérielles) vaut mieux que n'importe quelle parade unique.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    temps: () => {
      const x = F(), tc = !!x.tc;
      const vals = [104, 108, 112, 116, 122].map(v => (tc ? 116 : v));
      let b = T(210, 18, tc ? "Comparaison en temps constant" : "Comparaison à sortie anticipée", "f-b") + LN(14, 200, 406, 200);
      vals.forEach((v, i) => {
        const h = Math.round((v - 96) * 5.5), xx = 22 + i * 78, y = 200 - h;
        b += `<rect x="${xx}" y="${y}" width="56" height="${h}" rx="4" fill="var(${tc ? "--ok" : i === 4 ? "--ok" : "--you"})"/>` +
          T(xx + 28, y - 6, v + " tics", "f-s") + T(xx + 28, 218, i + (i > 1 ? " justes" : " juste"), "f-s");
      });
      b += T(210, 238, "Durée en fonction du nombre d'octets justes en tête du code", "f-s");
      return {
        cap: tc ? "En temps constant, la durée ne dépend plus du nombre d'octets justes : plus rien à écouter." : "Chaque octet juste en tête fait faire un tour de plus à la comparaison : 4 tics de plus (6 de plus pour la décision finale). Le bruit (±5 tics) se moyenne.",
        svg: SVG(248, "Durée de la comparaison selon le nombre d'octets justes", b),
      };
    },
    trace: () => {
      const x = F(), t = x.tr || { ops: [], reg: false };
      const n = Math.max(1, t.ops.length), step = Math.floor(396 / n), w = Math.max(6, Math.min(20, step - 3));
      let b = T(210, 16, t.reg ? "Trace d'un algorithme régulier" : "Trace d'un carré-multiplication", "f-b") + LN(8, 140, 412, 140);
      t.ops.forEach((o, i) => {
        const xx = 12 + i * step, h = Math.round(o.v * 1.3), y = 140 - h;
        b += `<rect x="${xx}" y="${y}" width="${w}" height="${h}" rx="3" fill="var(${o.k === "S" ? "--you" : "--bad"})"/>` + T(xx + w / 2, 156, o.k, "f-s");
      });
      b += T(14, 180, "S = carré (sobre)   M = multiplication (gourmande)", "f-s", "start");
      let bits = "";
      if (x.dkeyOK && !t.reg) t.ops.forEach((o, i) => { if (o.k === "S") bits += t.ops[i + 1] && t.ops[i + 1].k === "M" ? "1" : "0"; });
      b += T(14, 200, t.reg ? "chaque bit : M puis S, toujours : rien à lire" : bits ? "bits lus : " + bits : "bits : un S seul = 0, un S puis un M = 1", "f-s" + (bits ? " ft-ok" : ""), "start");
      return {
        cap: t.reg ? "Algorithme régulier : la trace est la même pour un bit 0 et pour un bit 1." : "Chaque barre est une opération. Un S suivi d'un M est un bit 1 ; un S suivi d'un S est un bit 0 : la trace se lit comme l'exposant secret.",
        svg: SVG(212, "Trace de consommation d'une exponentiation modulaire", b),
      };
    },
    cache: () => {
      const x = F(), p = x.probe;
      let b = T(210, 18, "Les huit lignes du cache, après ta sonde", "f-b");
      for (let i = 0; i < 8; i++) {
        const xx = 10 + i * 50, tt = p ? p[i] : null, slow = tt != null && tt > 20;
        b += `<rect x="${xx}" y="30" width="44" height="50" rx="5" fill="${tt == null ? "var(--line)" : slow ? "var(--bad)" : "var(--ok)"}" opacity=".85"/>` +
          T(xx + 22, 100, "ligne " + i, "f-s") + T(xx + 22, 116, tt == null ? "?" : fx(tt), "f-s");
      }
      b += `<rect x="14" y="140" width="12" height="12" rx="2" fill="var(--ok)"/>` + T(34, 151, "rapide : ta donnée est restée, personne n'y a touché", "f-s", "start") +
        `<rect x="14" y="162" width="12" height="12" rx="2" fill="var(--bad)"/>` + T(34, 173, "lente : quelqu'un d'autre l'a évincée", "f-s", "start");
      const mode = x.probeMode === "spec" ? "sonde de l'Augure (casier rapide = touché)" : x.cmode === "uni" ? "mode : accès uniforme (Bob lit tout)" : x.cmode === "part" ? "mode : cache partitionné" : "mode : cache partagé, accès dépendant du secret";
      b += T(210, 200, mode, "f-b");
      return {
        cap: "Une ligne lente indique la ligne que la victime a lue : si cette ligne dépend du secret, le secret fuit. Avec un accès uniforme, tout est lent ; avec un cache partitionné, tout est rapide : plus de signal.",
        svg: SVG(212, "État du cache vu par l'observateur", b),
      };
    },
    blinding: () => {
      const x = F(), k = x.blind || { m: RM, r: "?", mp: "?", sp: "?", s: "?", ri: "?", ok: false };
      const bx = i => 5 + i * 110;
      let b = T(210, 16, "Aveuglement : l'entrée réelle ne passe jamais dans le calcul", "f-b");
      const box = (i, t1, t2, cls) => R(bx(i), 40, 80, 56, cls) + T(bx(i) + 40, 62, t1, "f-b f-s") + T(bx(i) + 40, 82, String(t2), "f-s");
      b += box(0, "m", k.m, "") + box(1, "m'", k.mp, "f-bad") + box(2, "s'", k.sp, "f-bad") + box(3, "s", k.s, "f-ok");
      b += AR(bx(0) + 80, 68, bx(1), 68) + AR(bx(1) + 80, 68, bx(2), 68, "f-priv") + AR(bx(2) + 80, 68, bx(3), 68);
      b += T(bx(0) + 95, 34, "× r^e", "f-s") + T(bx(1) + 95, 34, "^d secret", "ft-priv f-s") + T(bx(2) + 95, 34, "× r⁻¹", "f-s");
      b += T(210, 124, `facteur aléatoire r = ${k.r}  (r⁻¹ = ${k.ri})`, "f-s");
      b += T(210, 148, "Ève voit m' et s' : ni l'un ni l'autre n'est m ou s.", "ft-bad f-s");
      b += T(210, 172, k.ok ? `Contrôle : s = m^d mod n = ${k.s}  ✔` : "(pas encore exécuté : `aveugler 65`)", "f-s" + (k.ok ? " ft-ok" : ""));
      b += T(210, 196, "Autre r, autre m', même s : la trace ne se répète pas.", "f-s");
      b += T(210, 218, "Variante : exposant masqué d' = d + k·φ.", "f-s");
      return {
        cap: "(m × r^e)^d × r⁻¹ = m^d (mod n) : la signature est la bonne, mais l'observateur ne voit que des valeurs randomisées.",
        svg: SVG(232, "Aveuglement d'une signature RSA", b),
      };
    },
    specul: () => {
      const x = F(), c = x.spLast, pred = x.pred == null ? 1 : x.pred;
      let b = T(210, 16, "L'Augure : pari, avance à blanc, annulation", "f-b");
      b += T(14, 42, "confiance du pari :", "f-s", "start");
      for (let i = 0; i < 3; i++) b += `<rect x="${130 + i * 28}" y="30" width="22" height="16" rx="3" fill="${i < pred ? "var(--you)" : "var(--line)"}"/>`;
      b += T(226, 42, pred >= 2 ? "il parie « oui »" : "il attend", "f-s", "start");
      b += R(8, 64, 124, 72, "") + T(70, 84, "1. pari", "f-b f-s") + T(70, 102, "« i est valide »", "f-s") + T(70, 120, "avant la vérif.", "f-s");
      b += R(148, 64, 124, 72, "f-bad") + T(210, 84, "2. avance à blanc", "f-b f-s") + T(210, 102, "lit la case i et", "f-s") + T(210, 120, "touche un casier", "f-s");
      b += R(288, 64, 124, 72, "f-ok") + T(350, 84, "3. vérification", "f-b f-s") + T(350, 102, "hors ardoise : tout", "f-s") + T(350, 120, "est annulé : REFUSÉ", "f-s");
      b += AR(132, 100, 148, 100) + AR(272, 100, 288, 100);
      const msg = !c ? "Aucun essai hors ardoise pour l'instant."
        : c.leak != null ? `Le casier ${c.leak} reste chaud après l'annulation : la trace trahit la case ${c.i}.`
        : c.masked ? "Index masqué : la trace ne concerne qu'une case publique."
        : c.blocked ? "Correctif en place : pas d'avance à blanc, pas de trace."
        : c.legit ? "Demande légitime : valeur publique." : "L'Augure n'a pas parié : pas de trace.";
      b += T(210, 168, msg, "f-s" + (c && c.leak != null ? " ft-bad" : ""));
      b += T(210, 196, "Annuler les RÉSULTATS ne suffit pas :", "f-s") + T(210, 214, "les TRACES dans le cache survivent.", "f-s");
      b += T(210, 240, x.sfix ? "correctif actif : " + COSTS[x.sfix].nom.toLowerCase().slice(0, 40) : "aucun correctif actif", "f-s");
      return {
        cap: "L'exécution spéculative annule les résultats d'un mauvais pari, pas son empreinte dans le cache. Modèle jouet à très gros traits.",
        svg: SVG(252, "Exécution spéculative et trace dans le cache", b),
      };
    },
  };

  GAMES.sidechan = {
    id: "sidechan", order: 42, title: "L'Écoute aux Portes", pageTitle: "Side Channel Quest", subtitle: "aventure textuelle · canaux auxiliaires",
    blurb: "Un coffre-fort parfait sur le papier fuit par son temps, sa consommation et son cache : écoute-le (sur des machines jouets), puis bouche les fuites.",
    concept: "Canaux auxiliaires : temps, consommation, cache, exécution spéculative",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    refig(name) { fig(name); },
    figAlias: { temps: ["chronometre", "chrono", "comparaison", "duree"], trace: ["consommation", "oscilloscope", "conso"], cache: ["casiers"], blinding: ["aveuglement", "blind"], specul: ["speculation", "augure", "spectre"] },
    setup() { const x = F(); x.seed = 443; x.pred = 1; x.cmode = "none"; x.sfix = null; },
    help: "Spécifiques : `mesurer ‹code› ‹n›` · `balayer ‹n› ‹préfixe›` · `proposer ‹code›` · `capter ‹n›` · `deduire ‹…›` · `aveugler ‹m›` · `remplir` · `declencher ‹octet›` · `sonder` · `entrainer ‹n›` · `provoquer ‹i›` · `couts` · `activer ‹contre-mesure›` · `classer ‹n› ‹canal›` · `xor ‹a› ‹b›`",
    verbs: {
      mesurer: { words: ["mesurer", "chronometrer"], run: cmdMesurer },
      balayer: { words: ["balayer", "scanner"], run: cmdBalayer },
      proposer: { words: ["proposer", "essayer"], run: cmdProposer },
      capter: { words: ["capter", "enregistrer"], run: cmdCapter },
      deduire: { words: ["deduire", "decoder"], run: cmdDeduire },
      aveugler: { words: ["aveugler", "masquer"], run: cmdAveugler },
      remplir: { words: ["remplir", "amorcer"], run: cmdRemplir },
      declencher: { words: ["declencher", "lancer"], run: cmdDeclencher },
      sonder: { words: ["sonder", "ecouter"], run: cmdSonder },
      entrainer: { words: ["entrainer", "dresser"], run: cmdEntrainer },
      provoquer: { words: ["provoquer", "interroger"], run: cmdProvoquer },
      couts: { words: ["couts", "cout"], run: cmdCouts },
      activer: { words: ["activer", "regler", "corriger"], run: cmdActiver },
      classer: { words: ["classer", "juger"], run: cmdClasser },
      xor: { words: ["xor", "ouex"], run: cmdXor },
    },
    intro() {
      out("L'Écoute aux Portes", "title");
      out("Port-443. La Guilde vient de recevoir un coffre-fort à carte tout neuf. Son algorithme a été relu, prouvé, validé : sur le papier, il est parfait. Maître Ada n'est pas rassurée pour autant : « Un cadenas parfait qui grince quand on tourne la bonne molette n'est plus un cadenas parfait. »\nElle t'engage pour un audit autorisé. Tu joueras Ève, celle qui écoute : pas les mathématiques, la machine elle-même. Tout se passe sur des machines et des mesures de jeu.", "");
    },
  };
})();
