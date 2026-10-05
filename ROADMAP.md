# Roadmap

## Fait
| # | Jeu | Concept |
|---|-----|---------|
| 1 | Le Courrier de Port-443 | TLS, certificats, HTTPS |
| 2 | La Forge de Rivest | RSA, factorisation, signature |
| 3 | Les Archives de Port-443 | Injection SQL, XSS |
| 4 | Le Palais des Passeports | OAuth 2.0, JWT |
| 5 | La Citadelle des Tickets | Kerberos |
| 6 | L'Apothicaire des Empreintes | Hachage, sel, mots de passe |
| 7 | Le Quartier des Douanes | SOP, CORS, CSRF |
| 8 | Le Tunnel de Port-443 | VPN, IPsec, WireGuard |
| 9 | L'Annuaire de Port-443 | DNS, DNSSEC |
| 10 | La Muraille de Port-443 | Pare-feu, NAT, segmentation |
| 11 | Le Café du Wi-Fi | WPA2, WPA3 |

## À faire : identité et accès
| Concept | Idée de gameplay |
|---------|------------------|
| Phishing et authentification multifacteur (TOTP, WebAuthn) | Distinguer de vrais courriers de faux, voir pourquoi un code à 6 chiffres peut être volé alors qu'une clé matérielle résiste |
| Gestion des droits (RBAC, moindre privilège) | Configurer qui peut entrer où, puis observer comment un compte trop puissant devient une porte d'entrée |
| Gestionnaires de mots de passe et secrets | Apprendre où ranger les clés d'API, et pourquoi pas dans le dépôt de code |

## À faire : logiciel et données
| Concept | Idée de gameplay |
|---------|------------------|
| Chaîne d'approvisionnement logicielle | Un paquet empoisonné dans l'entrepôt : signatures, verrouillage des versions, dépendances confuses |
| Chiffrement de disque et de sauvegardes | Protéger un coffre contre un vol de support : modes de chiffrement, gestion des clés |
| Rançongiciels et sauvegardes | Observer une attaque simulée, puis concevoir des sauvegardes qu'elle ne peut pas atteindre (3-2-1, copies hors ligne) |

## À faire : cryptographie avancée
| Concept | Idée de gameplay |
|---------|------------------|
| Cryptographie post-quantique | Le jour où les cadenas RSA tombent : alternatives par réseaux euclidiens, migration |
| Blockchain et preuves de travail | Miner des blocs à la main avec du vrai SHA-256, puis tenter de réécrire l'historique |
| Preuves à divulgation nulle (zero-knowledge) | Prouver qu'on connaît un secret sans le révéler (la caverne d'Ali Baba) |

## À faire : détection et réponse
| Concept | Idée de gameplay |
|---------|------------------|
| Journaux et détection d'intrusion | Lire des logs, repérer la trace de Mallory, écrire une règle d'alerte |
| Gestion d'incident | Une alerte tombe : confinement, analyse, reprise, dans le bon ordre |
| Ingénierie sociale | Jouer le standard téléphonique face à des appels qui essaient de te manipuler |

## Idées transverses
- Sauvegarde de progression partagée entre les jeux, avec un « passeport » de badges
- Mode « révision » avec fiches mémo de tous les carnets
- Version anglaise
