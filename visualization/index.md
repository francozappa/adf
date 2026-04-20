---
# index.md

layout: default
---

# ADF to MITRE EMB3D Mapping

The following pages show how all AD objects defined in the [generic catalog](https://github.com/ORSHIN/tropic-adf/tree/main/catalog-mitre) map to MITRE Device Properties (PID) and Threat IDs (TID):

  * [Physical MITRE EMB3D and ADF Mapping](map_physical.html)
  * [Software MITRE EMB3D and ADF Mapping](map_software.html)
  * [Bluetooth MITRE EMB3D and ADF Mapping](map_bt.html)
  * [FIDO Device MITRE EMB3D and ADF Mapping](map_fido.html)


# Example Device Threat Model

This example demonstrates the part of Threat Modeling called the Threat Identification phase. In this phase, the attack surface is identified, leading to a list of potential vulnerabilities and threats.

The following pages enumerate potential vulnerabilities of a particular system — the [ORSHIN Demonstrator Platform](https://github.com/ORSHIN/demo) — in a hierarchical way, as specified by given device properties (PIDs) in three relevant areas.

  * [Physical Threat Enumeration](model_physical.html) - for the source model file [model_physical.yaml](https://github.com/ORSHIN/tropic-adf/tree/main/visualization/_data/model_physical.yaml)
    * [Physical Threat Catalog](catalog_physical.html)
  * [Software Threat Enumeration](model_software.html) - for the source model file [model_software.yaml](https://github.com/ORSHIN/tropic-adf/tree/main/visualization/_data/model_software.yaml)
    * [Software Threat Catalog](catalog_software.html)
  * [Bluetooth Threat Enumeration](model_bt.html) - for the source model file [model_bt.yaml](https://github.com/ORSHIN/tropic-adf/tree/main/visualization/_data/model_bt.yaml)
    * [Bluetooth Threat Catalog](catalog_bt.html)

The threat model, risk assessment, measures, and related reasoning are described in the [Demonstrator Threat Model: Attack Defense Framework](https://github.com/ORSHIN/demo#demonstrator-threat-model).
