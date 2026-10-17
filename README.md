# 🔓 legacy2json

[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

> **Outil d'extraction et de rétro-ingénierie de données piégées dans des formats de fichiers anciens, fermés ou inconnus.**

---

## 🎯 Problématique & Utilité

De nombreuses bases de données historiques, sauvegardes d'entreprises et archives logicielles sont stockées dans des formats propriétaires obsolètes (dBase/DBF, Microsoft Access 97-2003, conteneurs OLE2/CFB, archives fermées). Les logiciels d'origine ne tournent plus sur les OS modernes, rendant l'accès aux données critique difficile.

**legacy2json** résout ce problème :
1. **Zéro dépendance obligatoire** (utilise la bibliothèque standard Python).
2. **Identification par signature magique** (ne se fie jamais à l'extension du fichier).
3. **Parseurs dédiés** pour les formats structurés connus.
4. **Moteur d'analyse heuristique** pour les fichiers non reconnus (détection de tables à pas fixe, brute-force XOR/ADD, flux compressés masqués, extraction de texte ASCII/UTF-16).
5. **Garantie lecture seule** et option de sauvegarde sans perte (`--embed-raw`).

---

## 🚀 Formats supportés

| Format | Extensions courantes | Type de support | Description |
|---|---|---|---|
| **dBase / FoxPro** | `.dbf` (avec `.dbt` / `.fpt`) | Natif complet | Détection d'en-tête, types C/N/F/D/L/I/B/Y/T, drapeaux supprimés, résolution automatique des mémos compagnons |
| **SQLite 3** | `.sqlite`, `.db` | Natif complet | Schéma complet, tables, vues, dump ordonné des lignes |
| **OLE2 / CFB** | `.doc`, `.xls`, `.ppt`, `.msg` | Structurel natif | Parseur d'arborescence FAT/MiniFAT, extraction des streams et storages |
| **Archives ZIP** | `.zip`, `.docx`, `.xlsx`, `.odt` | Natif récursif | Arborescence, métadonnées, analyse imbriquée du contenu |
| **Flux compressés** | `.gz`, `.bz2`, `.xz` | Natif récursif | Décompression en mémoire et analyse récursive automatique |
| **Apple Property List**| `.plist` | Natif complet | Formats binaires et XML |
| **Microsoft Access** | `.mdb`, `.accdb` | Via `mdbtools` | Jet3/4 et ACE, dump des tables via connecteur CLI |
| **Formats Textes** | `.json`, `.xml`, `.csv`, `.ini`, `.env` | Auto-détecté | Parseur intelligent avec détection de délimiteur et sniffer |
| **Formats Inconnus** | N'importe quel binaire | Analyse heuristique | Signatures imbriquées, calcul d'entropie, scan XOR/ADD, détection de colonnes à enregistrement fixe |

---

## 💻 Installation & Utilisation

### Prérequis
- Python 3.7+ (aucune bibliothèque tierce requise).
- *(Optionnel)* `mdbtools` (`apt install mdbtools` ou `brew install mdbtools`) uniquement pour les bases Microsoft Access `.mdb`.

### Ligne de commande

```bash
# Analyser un fichier et afficher le résultat sur la sortie standard
python legacy2json.py donnees.dbf

# Sauvegarder dans un fichier JSON
python legacy2json.py donnees.dbf -o sortie.json

# Traiter tout un dossier d'archives de manière récursive
python legacy2json.py archives/ -o exports/

# Mode verbeux (logs de détection et étapes)
python legacy2json.py donnees.dbf -v

# Mode complet sans limite de lignes/aperçus + conservation du binaire brut en base64
python legacy2json.py donnees.dbf --full --embed-raw -o backup.json
```

---

## 💡 Exemple de sortie

Pour une table DBF d'époque :
```json
{
  "file": "clients.dbf",
  "size": 4096,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "entropy": 4.12,
  "detected": "dbf",
  "data": {
    "version_byte": "0x3",
    "last_update": "1998-04-12",
    "encoding": "cp1252",
    "declared_records": 150,
    "records_found": 150,
    "deleted_records": 2,
    "memo_note": "fichier mémo chargé avec succès",
    "fields": [
      {"name": "NOM", "type": "C", "length": 30, "decimals": 0},
      {"name": "SOLDE", "type": "N", "length": 10, "decimals": 2},
      {"name": "REMARQUES", "type": "M", "length": 10, "decimals": 0}
    ],
    "rows": [
      {
        "NOM": "DUPONT JEAN",
        "SOLDE": 1250.50,
        "REMARQUES": "Client fidèle depuis 1992."
      }
    ]
  }
}
```

---

## 🔬 Comment ajouter un nouveau format ?

L'architecture est modulaire et extensible en quelques lignes :

1. Ajouter la signature dans la liste `MAGIC` ou une fonction d'analyse structurelle (`is_monformat(d)`).
2. Définir votre fonction `parse_monformat(d, depth)` retournant un dictionnaire `dict`.
3. L'enregistrer dans `PARSERS["monformat"] = parse_monformat`.

---

## ⚠️ Limites connues

- **Validé sur des fichiers synthétiques**, construits d'après les spécifications binaires des formats. Pas encore testé à grande échelle sur de vrais fichiers d'époque (Paradox, Lotus 1-2-3, Clarion…).
- **Mémos DBF** : les fichiers compagnons `.dbt` (dBase III/IV) et `.fpt` (FoxPro) sont lus automatiquement s'ils sont dans le même dossier que le `.dbf` (casse ignorée). Sinon, seul le numéro de bloc est conservé.
- **Non gérés** : dBase 7, chiffrements à clé multi-octets (seuls XOR/ADD mono-octet sont détectés), fichiers protégés par mot de passe.
- **Formats inconnus** : l'outil extrait ce qui est récupérable (chaînes de caractères, flux compressés cachés, structure à enregistrements fixes) et fournit des indices, mais ne peut pas deviner la signification des champs sans spécification.
- **Access (`.mdb`/`.accdb`)** : nécessite `mdbtools` installé. La prise en charge de `.accdb` y est partielle.

## ⚙️ Tests

Une suite de tests automatisée est fournie avec `pytest` :

```bash
pip install pytest
pytest -v
```

---

## 📄 Licence

Ce projet est sous licence [MIT](LICENSE).
