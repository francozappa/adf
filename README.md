# AttackDefense Framework (ADF)

## Introduction

This repository is a fork of the original [AttackDefense Framework (ADF)](https://github.com/francozappa/adf) — a threat-modeling framework for IoT devices and lifecycles.

The aim of this fork is to establish a relationship with the newly introduced [MITRE EMB3D™ Threat Model](https://emb3d.mitre.org/), which has some advantages over ADF, including faster modeling over a fixed structure of attack surfaces (EMB3D Device Properties).

On the other hand, the flexibility and easy-to-adopt approach of ADF make it possible to extend and enrich the MITRE EMB3D™ Threat Model by intermapping threats with a custom ADF database, allowing rapid and more precise threat modeling at the same time.

Additionally, we provide a comprehensive database of ADF files based on the list of AD objects created in the ORSHIN project as a starting point for detailed modeling of constrained CMOS devices, where the MITRE EMB3D is not very detailed.

The ADF repository has the following structure:

* `catalog/` contains the AD files
* `analyze.py` automatically analyzes ADs (maps, chains, trees, ...)
* `check.py` checks syntax and semantics of the ADs
* `parse.py` parses ADs from other sources (CAPEC, ...)
* `*_test.py` test scripts
* `Makefile` runs tests, scripts, etc

This repository fork has been extended by the following content compared to the original [AttackDefense Framework (ADF)](https://github.com/francozappa/adf) (see [Connecting AD Catalog with MITRE EMB3D](#connecting-ad-catalog-with-mitre-em3ed) for a detailed description):

* `catalog-mitre/` AD file catalog with content from `catalog` deduplicated and optimized for generic use in the area of constrained devices
* `dict/` contains the definition of the newly added AD dictionary: allowed phrases for `surf`, `vect`, `model`, and `tag`
* `check_tool.py` checks syntax and semantics of the ADs, extended by:
  - the ability to compare two AD files and rank ability between ADs
  - the ability to use ADF dictionaries
  - the ability to generate the ADF dictionary from the AD file
* `mitre/` MITRE EMB3D-related resources
* `visualization/` shows the MITRE EMB3D–ADF database relationship by means of the hierarchically structured generated static web page


## ADF Research Paper (ACM TECS)

The ADF is presented in the [AttackDefense Framework (ADF): Enhancing IoT Devices
and Lifecycles Threat Modeling](https://dl.acm.org/doi/abs/10.1145/3698396)
paper, published in the ACM Transactions on Embedded Computing Systems (TECS) in 2025.

```tex
@article{sacchetti2025attackdefense,
  title={{AttackDefense Framework (ADF): Enhancing IoT Devices and Lifecycles Threat Modeling}},
  author={Sacchetti, Tommaso and Bognar, Marton and De Meulemeester, Jesse and Gierlichs, Benedikt and Piessens, Frank and Bezsmertnyi, Volodymyr and Molteni, Maria Chiara and Cristalli, Stefano and Gringiani, Arianna and Thomas, Olivier and others},
  journal={ACM Transactions on Embedded Computing Systems},
  volume={24},
  number={5},
  pages={1--34},
  year={2025},
  publisher={ACM New York, NY}
}
```

## AD object

The ADF utilizes the *AttackDefense (AD)* object to model a threat.
An AD is a named data structure with primary and optional fields. An AD can be
written in any serialization language like YAML
(preferred), JSON, XML, TOML, and so on. It is also programming-language
agnostic as it can be represented by a dictionary. It is machine and human
friendly.


```yaml
ad_name:
  # Primary fields
  a: attack
  d:
    policy1: [mech1, mech2]
    policy2: [mech1, mech2]
    ...
  surf: [surf, subsurf, subsubsurf, ...]
  vect: [vector1, vector2, ...]
  model: [model1, model2, ...]
  tag: [tag1, tag2, ...]
  # Optional fields
  risk: [score1, score2, ...]
  year: 2023
  cve: ["123", "456", ...]
  cwe: ["123", "456", ...]
  capec: ["123", "456", ...]
  vref: ["vendor-ref1", ...]
  ...: ...
```

Above, we show an AD represented as a YAML object. The AD includes a set of
*primary fields*:
* unique name (`ad_name`)
* attack description (`a`)
* high-level defense policies and concrete defense mechanisms (`d: policy1: [mech1, mech2]`)
* attack surface (`surf`)
* attack vector (`vect`)
* general-purpose tags (`tag`)

Moreover, the AD is extensible with *optional fields*. Below we describe some
that we used in our experiments:
* risk scores (`risk`)
* threat year (`year`)
* CWE, CVE, and CAPEC IDs (`cve`, `cwe`, `capec`)
* vendor references (`vref`)

To see other AD representations look at [template/](template).


## Modules

The ADF has *four* modules:

1. **Catalogue** contains a curated collection of YAML files. Each file
   includes a collection of ADs for a threat domain (see [catalog/](catalog)).
2. **Analyze**: describe analyze API (`analyze.py`) and tests (`analyze_test.py`).
3. **Check**: describe analyze API (`check.py`) and tests (`check_test.py`).
4. **Parse**: describe analyze API (`parse.py`) and tests (`parse_test.py`).

## Cryptowallet case study

We evaluated the ADF by running a threat modeling exercise on a
*cryptowallet (product)*
and its *life cycle (process)*.
We involved seven expert groups covering orthogonal threat categories spanning
hardware, software, firmware, security, privacy, and protocols.

1. **Security Pattern** (lead: Gringiani) covered *ETSI EN 303 645 process threats*.
   They produced 9 ADs in [etsi.yaml](catalog/etsi.yaml).
2. **KUL COSIC** (lead: De Meulemeester) covered *side channel and
   fault injection threats*.
   They produced 20 ADs in [side-channel-phy.yaml](catalog/side-channel-phy.yaml)
3. **KUL DistriNet** (lead: Bognar) covered *microarchitectural and speculative execution threats*.
   They produced 14 ADs in [microa.yaml](catalog/microa.yaml).
4. **NXP Germany** (lead: Bezsmertnyi) covered *presilicon RISC-V secure element threats*.
   They produced 8 ADs in [presil.yaml](catalog/presil.yaml).
5. **Texplained** (lead: Thomas) covered *invasive physical IC threats*.
   They produced 26 ADs in [physical.yaml](catalog/physical.yaml).
6. **EURECOM** (lead: Sacchetti) covered *BLE protocol and implementation threats*.
   They produced 46 ADs in [bt.yaml](catalog/bt.yaml).
7. **Security Pattern** (lead: Gringiani) covered *FIDO2 authentication threats*.
   They produced 21 ADs in [fido_device.yaml](catalog/fido_device.yaml),
   [fido_solokey.yaml](catalog/fido_solokey.yaml), and
   [fido_system.yaml](catalog/fido_system.yaml).


## Connecting AD Catalog with MITRE EMB3D

### Generic AD Catalog for Constrained CMOS Devices

An original [catalog/](catalog) created by the expert groups was reviewed and slightly modified, and [catalog-mitre/](catalog-mitre) was created in the following steps:
  - removed deprecated files and examples
  - created AD database files to closely reflect the MITRE EMB3D structure
  - merged similar and overlapping AD objects
  - to improve consistency, we prefer the use of **Title Case** style (in dictionaries and through ADs as a consequence) for `surf`, `vect`, `model`, and `tag` terms.

The resulting AD database files were validated, and noncompliance with respect to YAML and ADF standards was fixed.

Additionally, dictionaries in [dicts/](dicts) were created to simplify validation.
[Dictionaries](dicts) contain allowed phrases and the description of `surf`, `vect`, `model`, and `tag`. Additionally, they allow linkage with MITRE by Threat IDs (TID) connected to top-level attack vectors, and MITRE Device Properties (PID) connected to main attack surfaces.
The `check_tool.py` enforces that at least one (the most top-level) AD's attack surface must be linked with a MITRE TID.

The resulting [catalog-mitre](catalog-mitre) contains deduplicated ADs interlinked with MITRE EMB3D by TIDs connected to top-level attack surfaces and PIDs connected to top-level attack vectors, allowing mapping ADs to MITRE EMB3D threats and device properties.


### AD Checker Tool Examples

#### Creating Dictionary from AD File

```bash
python3 check_tool.py -i catalog-mitre/physical.yaml -g > dicts/physical.yaml
```

#### Validate the AD Dictionary

```bash
python3 check_tool.py -i dicts/physical.yaml
```

#### Validate the AD File

To validate AD file syntax, run:
```bash
python3 check_tool.py -i catalog/fido_device.yaml
ERR : AD format not compliant with schema!

python3 check_tool.py -i catalog/fido_device.yaml -v
DBG : Checking YAML syntax: catalog/fido_device.yaml
DBG : check_yamllint: catalog/fido_device.yaml: passed
ERR : AD format not compliant with schema!
Key 'time_khandles' error:
Key 'risk' error:
<lambda>([]) should evaluate to True
```

To validate AD file syntax, and check the AD structure, use dictionary:
```bash
python3 check_tool.py -i catalog-mitre/physical.yaml -d dicts/physical.yaml
```

#### Compare the Content of Two AD files

```bash
python3 check_tool.py -i catalog-mitre/physical.yaml -c catalog/physical.yaml -d dicts/physical.yaml
```

### Generate ADF Vizualization and/or Threat Model

The ADF Visualization uses Jekyll (a static site generator) to generate a structured view of the threat model.

Ruby and Jekyll must be installed.

On Debian-based distributions, typically run (tested on Ubuntu 24.04 LTS):

```bash
sudo apt install ruby ruby-dev gem
sudo gem install jekyll
```

To generate a threat model, based on the MITRE EMB3D surfaces (PIDs), for a particular device:
- go to the `visualization/_data`
- modify all `model_*.yaml` files to reflect your device needs by removing or adding attack surfaces (PIDs) -  take [model_emb3d.yaml](visualization/_data/model_emb3d.yaml) as a reference

Then execute:

```bash
make model
```

The static page representing a defined threat model is generated: open [visualization/_site/index.html](visualization/_site/index.html).


## Tests

We use `pytest` and `make`.

Test all modules:

```make
make test
```

Test `modname`:

```make
make test-modname
```

## Acknowledgements

We thank the ADF dev team.

This work was partially funded by the European Union under grant agreement no.
101070008 (ORSHIN project) and by the European Commission through the Horizon
2020 research and innovation program Belfort ERC Advanced Grant 101020005
695305. Views and opinions expressed are however those of the author(s)
only and do not necessarily reflect those of the European Union. Neither the
European Union nor the granting authority can be held responsible for them.

It was additionally supported by the CyberSecurity Research Flanders with
reference number VR20192203. Moreover, it has been partially supported
by the French National Research Agency under the France 2030 label
(NF-HiSec ANR-22-PEFT-0009) and the Apricot/ENCOPIA ANR MESRI-BMBF project
(ANR-20-CYAL-0001). The views relected herein do not necessarily reflect the
opinion of the French government. Jesse De Meulemeester is funded by an FWO
fellowship (11PFE24N).

## Standardization

We are discussing with
[ENISA (EU)](https://www.enisa.europa.eu/),
[BSI (Germany)](https://www.bsi.bund.de/EN/Home/home_node.html), and
[ANSSI (France)](https://cyber.gouv.fr/en) the possibility to standardize the
ADF.

## ORSHIN Logo

![ORSHIN logo](https://horizon-orshin.eu/wp-content/uploads/2022/10/ORSHIN-Logo-4C-webicon.png)
