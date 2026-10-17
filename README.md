# 🔓 legacy2json

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Récupère les données piégées dans des formats de fichiers anciens ou fermés et les convertit en JSON.**
> Python pur, aucune dépendance, lecture seule.

---

## 🎯 Pourquoi

Beaucoup de bases historiques, sauvegardes et archives sont stockées dans des formats propriétaires obsolètes (dBase/DBF, conteneurs OLE2, bases Access…). Les logiciels d'origine ne tournent plus sur les systèmes modernes, et les données restent bloquées.

**legacy2json** :
1. n'utilise **que la bibliothèque standard** de Python ;
2. **identifie le format par signature et structure**, jamais par l'extension ;
3. fournit des **parseurs dédiés** pour les formats connus ;
4. applique une **analyse heuristique** aux fichiers non reconnus (chaînes ASCII/UTF-16, flux compressés cachés, XOR/ADD mono-octet, enregistrements de taille fixe) ;
5. ne modifie jamais le fichier source et peut en conserver une copie exacte dans le JSON (`--embed-raw`).

---

## 🚀 Formats supportés

| Format | Extensions courantes | Support | Détail |
|---|---|---|---|
| **dBase / FoxPro** | `.dbf` (+ `.dbt` / `.fpt`) | Complet | Types C/N/F/D/L/I/B/Y/T/M, enregistrements supprimés, page de code, mémos lus depuis le fichier compagnon (dBase III/IV et FoxPro, casse du nom ignorée) |
| **SQLite 3** | `.sqlite`, `.db` | Complet | Schéma (tables, index, vues) et lignes de chaque table (limitées par défaut, `--full` pour tout) |
| **OLE2 / CFB** | `.doc`, `.xls`, `.ppt`, `.msg` | Structurel | FAT/MiniFAT, arborescence, extraction des flux et de leur contenu texte ou binaire |
| **ZIP** | `.zip`, `.docx`, `.xlsx`, `.odt`, `.jar` | Récursif | Liste des entrées, métadonnées, analyse du contenu de chaque entrée |
| **Flux compressés** | `.gz`, `.bz2`, `.xz` | Récursif | Décompression en mémoire puis analyse du contenu |
| **Property list binaire** | `.plist` | Complet | Les plist XML passent par le parseur XML |
| **Microsoft Access** | `.mdb`, `.accdb` | Via `mdbtools` | Nécessite `mdbtools` installé |
| **Formats texte** | `.json`, `.xml`, `.csv`, `.ini`, `.env` | Détecté | Détection d'encodage et de séparateur |
| **Formats inconnus** | n'importe quel binaire | Heuristique | Voir « Limites » |

---

## ⚠️ Limites connues

- **Validé sur des fichiers synthétiques**, construits d'après les spécifications binaires des formats. Pas encore testé à grande échelle sur de vrais fichiers d'époque (Paradox, Lotus 1-2-3, Clarion…).
- **Mémos DBF** : les fichiers `.dbt` et `.fpt` sont lus automatiquement s'ils sont dans le même dossier que le `.dbf`. Sinon, seul le numéro de bloc est conservé.
- **Non gérés** : dBase 7, chiffrements à clé multi-octets (seuls XOR/ADD mono-octet sont détectés), fichiers protégés par mot de passe.
- **Formats inconnus** : l'outil extrait ce qui est récupérable (chaînes, flux compressés cachés, structure à enregistrements fixes) et donne des indices, mais ne peut pas deviner la signification des champs sans spécification.
- **Access** : nécessite `mdbtools` ; la prise en charge de `.accdb` y est partielle.

---

## 💻 Installation & utilisation

### Prérequis
- Python 3.8 ou plus récent, aucune bibliothèque tierce.
- *(Optionnel)* `mdbtools` (`apt install mdbtools` ou `brew install mdbtools`) pour les fichiers Access.

### Utilisation

```bash
# Analyser un fichier (JSON sur la sortie standard)
python legacy2json.py donnees.dbf

# Écrire le résultat dans un fichier
python legacy2json.py donnees.dbf -o sortie.json

# Traiter un dossier de façon récursive (un JSON par fichier)
python legacy2json.py archives/ -o exports/

# Afficher la progression (-v) ou le détail du débogage (-vv)
python legacy2json.py archives/ -o exports/ -v

# Aucune limite de lignes ou d'aperçus + copie exacte du fichier dans le JSON
python legacy2json.py donnees.dbf --full --embed-raw -o backup.json
```

Pour l'installer comme commande : `pip install .` puis `legacy2json donnees.dbf`.

---

## 💡 Exemple de sortie

`clients.dbf` accompagné de `clients.dbt` :

```json
{
  "file": "clients.dbf",
  "size": 232,
  "sha256": "0be40c0cf992d6a766f1bedd1d108fc6d881b8dcd497be5eb1b0e53bf8136fa3",
  "entropy": 3.043,
  "detected": "dbf",
  "data": {
    "version_byte": "0x83",
    "last_update": "1998-04-12",
    "encoding": "cp1252",
    "declared_records": 2,
    "records_found": 2,
    "deleted_records": 0,
    "memo_note": "fichier mémo chargé avec succès",
    "fields": [
      {"name": "NOM", "type": "C", "length": 30, "decimals": 0},
      {"name": "SOLDE", "type": "N", "length": 10, "decimals": 2},
      {"name": "REMARQUES", "type": "M", "length": 10, "decimals": 0}
    ],
    "rows": [
      {"NOM": "DUPONT JEAN", "SOLDE": 1250.5, "REMARQUES": "Client fidèle depuis 1992."},
      {"NOM": "MARTIN CLAIRE", "SOLDE": 87.0, "REMARQUES": "Remise exceptionnelle accordée."}
    ],
    "rows_truncated": false
  }
}
```

---

## 🔬 Ajouter un nouveau format

1. Ajouter une signature dans `MAGIC` ou une fonction de validation structurelle dans `detect()`.
2. Écrire `parse_monformat(d, depth)` qui retourne un `dict`.
3. L'enregistrer : `PARSERS["monformat"] = parse_monformat`.

---

## ✅ Tests

```bash
python -m unittest -v
```

29 tests (bibliothèque standard uniquement) : détection, parseurs DBF/mémos/OLE2/SQLite/ZIP/gzip, heuristiques, et un test de robustesse qui envoie des fichiers tronqués ou corrompus à l'analyseur. La CI GitHub Actions les lance sur Python 3.8 et 3.12.

---

## 📄 Licence

[MIT](LICENSE)
