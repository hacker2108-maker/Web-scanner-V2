# Web-Scanner: Website Analyzer & Vulnerability Scanner

[![Licence](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Made with Python](https://img.shields.io/badge/Made%20with-Python-blue.svg)](https://www.python.org/)

Web-Scanner est un outil en ligne de commande développé en Python 3 pour analyser des sites web et identifier des vulnérabilités potentielles. Il automatise la collecte d'informations importantes et effectue des vérifications de sécurité courantes pour vous donner un aperçu de la posture de sécurité d'un site web cible.

**Auteur:** Hacker2108

## Fonctionnalités

* **Informations de Base:** Récupération de l'adresse IP du domaine cible.
* **Enregistrements DNS:** Collecte des enregistrements DNS (A, AAAA, MX, NS, TXT, SOA, CNAME).
* **Informations WHOIS:** Obtention des informations WHOIS du domaine.
* **En-têtes HTTP:** Récupération et analyse des en-têtes HTTP du site web.
* **Détection de Technologies:** Identification des technologies utilisées par le site web (WordPress, Joomla, etc.).
* **Découverte de Sous-domaines:** Recherche de sous-domaines actifs par force brute et analyse DNS.
* **Scan de Ports:** Scan des ports communs sur le serveur cible.
* **Vérification de Vulnérabilités:** Détection de vulnérabilités courantes telles que :
    * Divulgation d'informations du serveur et des technologies.
    * Absence d'en-têtes de sécurité importants (HSTS, CSP, X-Frame-Options, etc.).
    * Vulnérabilités spécifiques à WordPress.
    * Activation de l'indexation de répertoires.
    * Présence du fichier `robots.txt`.
* **Rapports:** Possibilité d'enregistrer les résultats dans un fichier JSON.
* **Optimisation Termux:** Prise en charge et correction de la résolution DNS pour l'environnement Termux.
* **Multithreading:** Utilisation du multithreading pour accélérer la découverte de sous-domaines et le scan de ports.
* **Sortie Colorée:** Utilisation de `colorama` pour une sortie plus lisible dans le terminal.

## Prérequis

* Python 3
* Bibliothèques Python suivantes (installables via pip) :
    * `dns.resolver`
    * `requests`
    * `whois`
    * `beautifulsoup4`
    * `colorama`

Vous pouvez installer les dépendances avec la commande suivante :

```bash
pip install dns.resolver requests python-whois beautifulsoup4 colorama
