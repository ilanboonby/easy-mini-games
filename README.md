# Port-443 Quest

Onze aventures textuelles en français (à la Terminus) pour comprendre des concepts de cybersécurité réputés pénibles, chacune avec une vraie histoire, des puzzles, des schémas SVG qui se débloquent en jouant, un carnet de cours et un bilan final qui décode les analogies et liste les simplifications.

| # | Jeu | Concept | Fil rouge |
|---|-----|---------|-----------|
| 1 | Le Courrier de Port-443 | TLS, certificats, HTTPS | Livrer une lettre à la banque malgré Mallory |
| 2 | La Forge de Rivest | RSA, factorisation, signature | Forger une paire de clés à la main |
| 3 | Les Archives de Port-443 | Injection SQL, XSS | Auditer (avec mandat) puis corriger |
| 4 | Le Palais des Passeports | OAuth 2.0, JWT | Une « clé de voiturier » numérique, et quatre attaques |
| 5 | La Citadelle des Tickets | Kerberos | S'authentifier sans que le mot de passe circule |
| 6 | L'Apothicaire des Empreintes | Hachage, sel, mots de passe | Analyser une fuite avec du vrai SHA-256 |
| 7 | Le Quartier des Douanes | SOP, CORS, CSRF | Le navigateur à la frontière |
| 8 | Le Tunnel de Port-443 | VPN, WireGuard, IPsec | Sécuriser le travail depuis un café Wi-Fi |
| 9 | L'Annuaire de Port-443 | DNS, empoisonnement de cache, DNSSEC | Une course contre Mallory pour falsifier l'annuaire |
| 10 | La Muraille de Port-443 | Pare-feu, NAT, segmentation | Écrire les règles qui protègent trois zones |
| 11 | Le Café du Wi-Fi | WEP, WPA2, WPA3 | De la poignée de main capturée au faux point d'accès |

**Jouer** : ouvrir `index.html` dans un navigateur (aucun build, aucune dépendance). La progression de chaque jeu est sauvegardée dans le navigateur.
**Réviser** : `revision.html` contient la version quiz du jeu TLS.

## Organisation du code
- `engine.js` / `engine.css` : moteur partagé (analyse des commandes, inventaire, indices, carnet, schémas, menu).
- `games/*.js` : un fichier par jeu (lieux, personnages, puzzles, schémas, bilan).
- `tests/` : un parcours complet par jeu, rejoué dans un navigateur par `node tests/run-all.js` (nécessite Playwright).

Les prochaines idées sont dans [ROADMAP.md](ROADMAP.md).
