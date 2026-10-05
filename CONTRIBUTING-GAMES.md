# Guide pour écrire un jeu de Port-443 Quest

Ce guide s'adresse à toute personne ou tout agent qui écrit un nouveau jeu. Lis-le en entier, puis lis `engine.js`, puis au moins deux jeux de référence : `games/dns.js`, `games/firewall.js`, `games/incident.js` ou `games/logs.js` (niveau de qualité à égaler ou dépasser) et `games/hash.js` ou `games/kerberos.js` (structure plus simple).

## Livrables
- `games/<id>.js` : remplace le fichier stub.
- `tests/<id>.json` : tableau JSON de commandes (chaînes) qui joue la partie complète jusqu'à la fin, avec tout le carnet débloqué.
- Ne modifie AUCUN autre fichier (ni `engine.js`, `engine.css`, `index.html`, README, ROADMAP, autres jeux ou tests). Pas de `git commit`/`push` : l'intégration est faite par l'agent principal. Si une limite du moteur te gêne, contourne-la dans ton fichier et signale-la dans ton rapport. Ne définis pas de champ `theme`.
- D'autres agents écrivent d'autres jeux en parallèle dans le même dépôt : ne touche pas à leurs fichiers.

## Structure d'un jeu
Tout dans une IIFE qui se termine par l'enregistrement :
```js
"use strict";
(function () {
  const F = () => f();
  // ents, rooms, notes, hints, figs, objective, talk, debrief, ...
  GAMES.<id> = { id: "<id>", order: N, title, pageTitle, subtitle, blurb, concept,
    start: "<salle>", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    verbs: { cle: { words: ["mot1", "mot2"], run: ctx => {...} } },
    help: "Spécifiques : ...", intro() {...},
    // optionnels : setup(), gate(dest), use(cleTriee, a, b), give(item, who), say(texte, ctx), refig(nom), figAlias }
  };
})();
```
- `rooms[id] = { name, short, alias: [...], ents: [ids], exits: { nord: "autre" }, desc: () => "..." }`. Directions : nord, sud, est, ouest, haut, bas.
- `ents[id] = { names: [...], label, desc: () => "...", npc?, take?, vis?: () => bool, onExamine? }`. Les `names` sont comparés après normalisation (voir plus bas) ; `label` apparaît dans « Tu vois : ».
- `notes[id] = [titre, texte]` : entrées de carnet, débloquées par `note(id)`.
- `objective()` renvoie une clé d'étape ; `hints[cle] = () => [indice vague, indice explicite avec la syntaxe exacte des commandes]`.
- `figs[nom] = (arg) => ({ cap, svg })` : schémas SVG ; affichés par `fig(nom, arg)`, réaffichés par `schema ‹nom›` (via `refig`).
- `talk(id)` gère `parler ‹personnage›`. `debrief()` s'affiche à la fin et par `analogies`.
- L'état est dans `S.f` (= `f()`), persisté automatiquement dans le navigateur. `setup()` est appelé à la création d'une partie ET après `recommencer oui`.

## API du moteur (variables globales)
- État et sortie : `S`, `f()`, `out(texte, classe)` avec classes `"ok" "err" "sys" "note" "title"`, `say(qui, texte)`, `code(texte)` (bloc monospace, texte brut), `note(id)`, `fig(nom, arg)`, `give(id)`, `drop(id)`, `resolve(texte, filtre)`.
- Dans `out`, `**gras**` et `` `commande` `` sont interprétés : une commande entre accents graves est cliquable (si elle contient `‹ ›`, c'est un modèle à compléter). Attention : `**` dans un texte (motifs, commentaires) déclenche le gras ; neutralise-le.
- Calcul : `modpow`, `gcd`, `isPrime`, `sha256(texte)` (réel, synchrone, texte uniquement), `b64u`, `unb64u`, `norm`. `calc` (calculatrice du joueur) est global : ne l'utilise pas comme verbe.
- Schémas : `T(x,y,texte,classe,ancre)`, `R(x,y,w,h,classe)`, `AR(x1,y1,x2,y2,classe,both)`, `LN`, `LOCK`, `KEY`, `SVG(hauteur, label, corps)` (viewBox de 420 de large). Classes : `f-b` (gras), `f-s` (petit), `ft-pub ft-priv ft-ok ft-bad` (couleurs de texte), `f-pub f-priv f-ok f-bad` (contours), `f-dash`. **Échappe `<`, `>` et `&` dans le texte SVG** (`&lt; &gt; &amp;`), sinon le HTML casse. Laisse des marges : le texte doit tenir dans 420 de large (≈ 7 px par caractère à la taille normale).

## Analyse des commandes : pièges connus
- `norm` retire accents, tirets, points et ponctuation, passe en minuscules. Le moteur retire de `ctx.rest` les articles `le la les l un une des du de d mon ma mes ce cette ces en et`. Les mots `a au aux sur avec vers dans pour contre depuis par` sont des séparateurs. Conséquences : n'utilise pas `ctx.rest` pour des arguments d'une seule lettre (`d`, `a`), pour des versions (`1.2.3`), des adresses IP, des URL, des expressions ou du texte libre. Utilise **`ctx.rawArg`** (texte original après le verbe) ou `ctx.raw`.
- Un verbe se déclare avec `words`. Un mot déclaré dans un verbe personnalisé l'emporte sur les verbes de base. Verbes de base et leurs mots : `examiner` (examiner, ex, x, inspecter, lire, etudier, **verifier**), `utiliser` (utiliser, appliquer, **sceller, signer, fermer**, combiner), `prendre` (prendre, ramasser, attraper, **saisir**), `aller` (aller, va, marcher, entrer, monter, descendre), `donner` (donner, remettre, tendre, offrir, livrer), `dire` (dire, repondre, annoncer, enoncer), `parler` (parler, discuter, saluer), `regarder`, `inventaire`, `carnet`, `indice`, `aide`, `analogies`, `schema`, `recommencer`. `calc`, `calculer`, `boulier` sont réservés à la calculatrice. Évite d'écraser un verbe de base sans raison, et si tu le fais, garde un moyen d'examiner les objets.
- Le moteur appelle `G.use(cleTriee, a, b)` pour `utiliser a sur b` (clé = ids triés joints par `+`) ; retourne `false` si non géré. `G.give(item, who)` pour `donner`.
- Les verbes personnalisés reçoivent `ctx = { k, verb, rest, target, raw, rawArg }`.

## Contenu attendu
- 4 à 6 lieux, 4 à 12 personnages et objets décrits, 7 à 9 entrées de carnet, 4 à 5 schémas SVG (au moins 2 dynamiques selon l'état du joueur), des indices à deux niveaux pour chaque étape (avec la syntaxe exacte des commandes), un épilogue et un `debrief()`.
- `debrief()` décode chaque analogie de l'histoire vers la réalité technique, puis un paragraphe « Les simplifications du jeu » honnête, puis un « Rappel utile » (classe `"ok"`).
- L'histoire se passe à Port-443 avec les personnages récurrents : Maître Ada (doyenne de la Guilde, guide), Mallory (attaquante), Ève (qui écoute), Alice et Bob. Un ton clair, un peu d'humour, jamais condescendant.
- **Éthique** : audits autorisés ; tout est simulé sur des données fictives du jeu ; aucun outil, code ou charge utile réellement offensif, aucun contournement opérationnel ; l'accent est sur la compréhension et la défense. Pour les sujets sensibles (exploitation mémoire, déni de service, élévation de privilèges, logiciels malveillants, attaques d'IA), reste conceptuel : modèles jouets, chiffres expliqués, pas de technique réutilisable contre de vrais systèmes.
- Les puzzles sont de vraies simulations : le code calcule réellement le résultat de ce que fait le joueur (vrai SHA-256, vrai moteur de règles, vraie évaluation de requêtes) plutôt que des QCM déguisés. Exactitude technique irréprochable : vérifie tes affirmations. Durée visée : 10 à 20 minutes.
- Les mauvaises commandes et mauvais choix reçoivent un retour pédagogique, jamais une erreur JavaScript. Un mauvais choix a une conséquence visible mais ne bloque pas la partie.
- Le hasard doit être reproductible (générateur à graine fixe) pour que `tests/<id>.json` rejoue toujours la même partie.

## Tester
Depuis le dépôt (Playwright et Chromium sont installés) :
```
cd /tmp && CHROMIUM=/opt/pw-browsers/chromium NODE_PATH=$(npm root -g) node /home/user/claude/tests/play.js <id> /home/user/claude/tests/<id>.json /tmp/<id>_out
```
Affiche l'état final : `end` doit être `true`, le carnet complet (`n/n`), « Erreurs JS : [] ». `/tmp/<id>_out.txt` contient le journal complet à relire (vérifie les textes, les accents, l'absence de « undefined »), `/tmp/<id>_out.png` une capture mobile.

Schémas : `node /home/user/claude/tests/onefig.js <id> /home/user/claude/tests/<id>.json /tmp/<id>_f` écrit un fichier PNG par schéma distinct (`f0.png`, `f1.png`…) ; regarde-les avec l'outil Read et corrige tout texte coupé ou chevauchant (fais cette vérification APRÈS tes dernières modifications de schémas, sur chaque image). Teste aussi quelques mauvais chemins (commande inconnue, mauvaise salle, mauvais argument).

## Rapport final
Termine par un rapport de moins de 150 mots : ce qui est implémenté (lieux, puzzles, notes, schémas), résultat du test, limites du moteur éventuelles.
