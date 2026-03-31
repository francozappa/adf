# AttackDefense Framework (ADF)

## Introduction

The AttackDefense Framework (ADF) is a threat modeling framework for IoT
devices and life cycles.

In this [blog post](blogpost.md) we explain how we used the ADF to threat model a crypto
wallet.

The repository has the following structure:

* `yaml/` contains the AD files
* `analyze.py` automatically analyze ADs (maps, chains, trees, ...)
* `check.py` check syntax and semantic of the ADs
* `parse.py` parse ADs from other sources (CAPEC, ...)
* `*_test.py` test scripts
* `Makefile` run tests, scripts, etc


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
   They produced 9 ADs in [etsi.yaml](yaml/etsi.yaml).
2. **KUL COSIC** (lead: De Meulemeester) covered *side channel and
   fault injection threats*.
   They produced 20 ADs in [sc-fi.yaml](yaml/sc-fi.yaml)
3. **KUL DistriNet** (lead: Bognar) covered *microarchitectural and speculative execution threats*.
   They produced 14 ADs in [microa.yaml](yaml/microa.yaml).
4. **NXP Germany** (lead: Bezsmertnyi) covered *presilicon RISC-V secure element threats*.
   They produced 8 ADs in [presil.yaml](yaml/presil.yaml).
5. **Texplained** (lead: Thomas) covered *invasive physical IC threats*.
   They produced 26 ADs in [physical.yaml](yaml/physical.yaml).
6. **EURECOM** (lead: Sacchetti) covered *BLE protocol and implementation threats*.
   They produced 46 ADs in [bt.yaml](yaml/bt.yaml).
7. **Security Pattern** (lead: Gringiani) covered *FIDO2 authentication threats*.
   They produced 21 ADs in [fido_device.yaml](yaml/fido_device.yaml),
   [fido_solokey.yaml](yaml/fido_solokey.yaml), and
   [fido_system.yaml](yaml/fido_system.yaml).


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
