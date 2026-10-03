# netprobe

[English](README.md) · [Français](README.fr.md)

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-aucune-brightgreen)

**netprobe** est un **scanner de ports TCP** léger, multithreadé et sans dépendance, écrit en Python pur. Il détecte les ports ouverts, récupère les bannières des services et exporte des rapports propres en texte, JSON, CSV ou HTML.

Je l'ai développé pour comprendre concrètement le fonctionnement des scanners réseau (handshake TCP, états des ports, concurrence, identification par bannière) et pour m'exercer à une programmation sécurisée par défaut : toute donnée provenant d'une machine distante est considérée comme non fiable.

> ⚠️ **Avertissement légal.** Ne scannez que des systèmes qui vous appartiennent ou pour lesquels vous disposez d'une autorisation écrite explicite. Un scan non autorisé peut être illégal. Ce projet est destiné à l'apprentissage et aux audits de sécurité autorisés.

## Fonctionnalités

- **Scan TCP connect** avec trois états : `open`, `closed` (connexion refusée) et `filtered` (délai dépassé / rejet réseau).
- **Multithreadé** (jusqu'à 1000 threads) pour scanner rapidement de nombreux ports.
- **Récupération de bannières** (`-b`) et identification du service à partir de la bannière elle-même, pas seulement du numéro de port (un serveur SSH sur le port 2222 est tout de même identifié comme `ssh`).
- **Cibles flexibles :** noms d'hôte, adresses IPv4 et blocs CIDR (ex. `192.168.1.0/28`, limités à 1024 hôtes).
- **Ports flexibles :** `top` (ports de services courants), `all`, listes et plages (`22,80,8000-8100`).
- **Quatre formats de rapport :** texte, JSON, CSV, HTML autonome. Le format est déduit de l'extension du fichier de sortie.
- **Aucun privilège root requis** (sockets classiques, pas de paquets bruts) et **aucune dépendance externe**.

## Installation

```bash
git clone https://github.com/<ayabenakcha002>/netprobe.git
cd netprobe
python -m pip install -e .
```

Nécessite Python 3.9 ou supérieur. Vous pouvez aussi l'exécuter sans l'installer : `PYTHONPATH=src python -m netprobe ...`

## Utilisation

```bash
# Scanner les ports courants d'un hôte
netprobe 192.168.1.10

# Ports et plages précis, avec récupération des bannières
netprobe 192.168.1.10 -p 22,80,443,8000-8100 -b

# Scanner un petit sous-réseau et enregistrer un rapport HTML
netprobe 192.168.1.0/28 -p top -b -o rapport.html

# JSON pour un traitement ultérieur, avec les ports fermés/filtrés
netprobe mon-serveur.exemple.org -p 1-1024 -a -o scan.json
```

### Options

| Option | Description |
|---|---|
| `CIBLE...` | Nom d'hôte, adresse IPv4 ou bloc CIDR IPv4 |
| `-p, --ports` | `top` (défaut), `all`, ou une liste/plage comme `22,80,8000-8100` |
| `-t, --timeout` | Délai par connexion en secondes (défaut `1.0`) |
| `-w, --workers` | Threads simultanés, de 1 à 1000 (défaut `100`) |
| `-b, --banners` | Récupérer les bannières des ports ouverts |
| `-a, --all` | Inclure les ports fermés et filtrés dans le rapport |
| `-o, --output FICHIER` | Écrire le rapport dans un fichier (format selon l'extension) |
| `-f, --format` | Forcer `text`, `json`, `csv` ou `html` |
| `-q, --quiet` | Pas de progression ni d'avertissement légal sur stderr |

Codes de sortie : `0` succès, `1` aucune cible résolue, `2` arguments invalides.

### Exemple (sortie réelle sur des serveurs de test locaux)

```text
$ netprobe 127.0.0.1 -p 2222,8080,9999 -b
netprobe: only scan systems you own or have explicit written permission to test.
[*] Scanning 127.0.0.1 (3 ports)...
[+] 127.0.0.1:2222/tcp open ssh
[+] 127.0.0.1:8080/tcp open http
netprobe 0.1.0 - scan started 2026-10-02T21:11:46+00:00

Target: 127.0.0.1 (127.0.0.1) - 2 open, 1 closed, 0 filtered - 0.006s
  PORT     STATE     SERVICE        BANNER
  2222/tcp open      ssh            SSH-2.0-OpenSSH_9.6p1 Ubuntu
  8080/tcp open      http           HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 Python/3.13.16
```

La progression en direct est écrite sur **stderr** et le rapport sur **stdout** : vous pouvez donc rediriger ou chaîner le rapport proprement.

<details>
<summary>Extrait d'un rapport JSON</summary>

```json
{
  "tool": "netprobe",
  "version": "0.1.0",
  "started_at": "2026-10-02T21:11:46+00:00",
  "ports_spec": "2222,8080,9999",
  "hosts": [
    {
      "target": "127.0.0.1",
      "address": "127.0.0.1",
      "summary": { "open": 2, "closed": 1, "filtered": 0 },
      "ports": [
        {
          "port": 2222,
          "state": "open",
          "service": "ssh",
          "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu",
          "latency_ms": 2.71
        }
      ]
    }
  ]
}
```
</details>

## Fonctionnement

1. **Analyse** des cibles et de la spécification des ports (`ports.py`), avec validation des plages et limitation de l'expansion CIDR.
2. **Résolution** de la cible, puis soumission d'une sonde par port à un pool de threads (`scanner.py`). Le scan étant limité par les entrées/sorties, les threads offrent une accélération quasi linéaire malgré le GIL.
3. **Classification** de chaque port selon le résultat de `connect()` :
   - handshake réussi → `open`
   - connexion refusée (RST) → `closed`
   - délai dépassé ou autre erreur réseau → `filtered`
4. **Identification** (optionnelle) : lecture de la bannière d'accueil (les ports HTTP reçoivent d'abord une requête `HEAD /`) puis association à un service (`services.py`).
5. **Rapport** dans le format demandé (`report.py`).

```text
src/netprobe/
├── cli.py       analyse des arguments, sortie en direct, codes de sortie
├── ports.py     analyse et validation des ports/cibles
├── scanner.py   scan connect multithreadé, récupération de bannières
├── services.py  table port → service, identification par bannière
└── report.py    rendus texte / JSON / CSV / HTML
tests/           70 tests unitaires (sockets locaux, sans internet)
```

## Considérations de sécurité

Un scanner lit des données provenant de machines qu'il ne contrôle pas : la sécurité de la sortie compte autant que celle du scan.

- **Injection dans le terminal :** les bannières sont débarrassées des caractères de contrôle (dont les séquences d'échappement ANSI) et tronquées.
- **Injection HTML / XSS :** toutes les valeurs sont échappées et la page générée inclut une Content-Security-Policy restrictive.
- **Injection de formules CSV :** les cellules commençant par `=`, `+`, `-` ou `@` sont préfixées par `'` pour que les tableurs ne les exécutent pas.
- **Limites de ressources :** l'expansion CIDR est plafonnée, le nombre de threads est borné et les délais doivent être positifs.

Tous ces comportements sont couverts par des tests.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Les tests lancent des serveurs jetables sur `127.0.0.1` et fonctionnent donc hors ligne. GitHub Actions les exécute sur Python 3.9 à 3.13 (voir `.github/workflows/ci.yml`).

## Limites et feuille de route

- IPv4 uniquement, scan TCP connect uniquement (pas de scan SYN/furtif, pas d'UDP).
- La récupération de bannières ne négocie pas TLS : les ports HTTPS ne renvoient donc pas encore de bannière.
- Prévu : IPv6, inspection des certificats TLS, sondes UDP pour les services courants, limitation de débit et comparaison de deux rapports pour détecter les changements.

## Licence

MIT. Voir [LICENSE](LICENSE).
