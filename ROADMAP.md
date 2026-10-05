# Roadmap — mini-jeux de cybersécurité

Objectif : un petit jeu interactif par concept « pénible à comprendre ».

| # | Concept | Statut | Idée de gameplay |
|---|---------|--------|------------------|
| 1 | **TLS / certificats / handshake** | ✅ fait (`index.html`) | Quiz clés pub/priv, Diffie-Hellman interactif, juger des certificats, ordonner le handshake, boss « homme du milieu » |
| 2 | **Chiffrement asymétrique & signatures (RSA en détail)** | à faire | Fabriquer une paire de clés RSA avec de petits nombres premiers, chiffrer/signer à la main |
| 3 | **Injections SQL / XSS** | à faire | Bac à sable : attaquer un faux formulaire, puis corriger (requêtes préparées, échappement) |
| 4 | **Authentification : OAuth 2.0 / OpenID Connect / JWT** | à faire | Suivre les redirections et tokens d'un flux, repérer la faille (redirect_uri, `alg: none`…) |
| 5 | **Kerberos** | à faire | Jouer le client : obtenir un TGT, puis un ticket de service, comprendre qui connaît quelle clé |
| 6 | **Hachage, sel et mots de passe** | à faire | Casser des hachages avec/sans sel, comprendre bcrypt/argon2 |
| 7 | **CORS / Same-Origin Policy / CSRF** | à faire | Simuler des requêtes inter-sites et décider ce que le navigateur autorise |

## Idées transverses
- Sauvegarde de progression partagée entre les jeux
- Mode « révision » avec fiches mémo
- Version anglaise
