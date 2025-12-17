# Scripter l'analyse de traffic Réseau et Web

Script Rust pour analyser une requête HTTP/HTTPS vers un site web et extraire les informations techniques.

## AUTEURS

Nom et Prénom : 

- Kévin MESQUITA DOS SANTOS

- Théo CAUDAN

## Fonctionnalités

    Résolution DNS du nom de domaine

    Affichage de l'IP et du port source/destination

    Extraction des headers de sécurité

    Identification du Content-Type

    Extraction des balises HTML

    Récupération du titre H1

    Analyse du certificat TLS (clé publique, autorité signataire)

    Traceroute vers le serveur

## Prérequis

    Rust 1.56+

    Les dépendances suivantes dans Cargo.toml:

- `reqwest`
- `trust-dns-resolver`
- `regex`
- `rustls`
- `x509-parser`
- `webpki-roots`

## Installation

git clone https://github.com/KevinMDS/Scripting-WEB.git

cd Scripting-WEB

cargo build --release

## Utilisation

cargo run --release

Le script affiche les informations dans cet ordre:

    Serveur DNS et IP du serveur

    IP et ports source/destination

    Headers de sécurité (et s'il y en a ou pas)

    Content-Type et son utilité

    Balises HTML trouvées

    Titre H1

    Informations du certificat TLS

    Traceroute vers le serveur

