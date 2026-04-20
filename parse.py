"""
parse.py

Parse well formatted ADs from different formats.

"""

from pathlib import Path

import xmltodict

import json

import yaml

import csv

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def _parse_excel(path: Path) -> dict:
    """Parse from a excel AD file in a Python dict"""
    raise NotImplementedError


# NOTE: this is ad hoc,
def _parse_csv(path: Path) -> dict:
    """Parse from a csv AD file in a Python dict"""
    with open(path) as csv_file:
        reader = csv.reader(csv_file, delimiter=";")
        reader.__next__()
        attacks = {}
        count = 0
        for row in reader:
            attacks["attack_" + str(count)] = {
                "a": row[0].strip().replace("\n", ","),
                "d": {
                    row[1].strip(): [d.strip("-").strip() for d in row[2].split("\n")]
                },
                "surf": [s.strip("-").strip() for s in row[4].split("\n")],
                "vect": [v.strip("-").strip() for v in row[5].split("\n")],
                "model": [m.strip() for m in row[3].split("\n")],
            }
            tag = [m.strip() for m in row[6].split("\n")]
            if len(tag) > 0 and tag[0] != "":
                attacks["attack_" + str(count)]["model"] += tag
            count += 1

        with open("yaml/phy_attacks.yaml", "w") as yaml_file:
            yaml.dump(attacks, yaml_file)


def _parse_xml(path: Path) -> dict:
    """Parse from a xml AD file in a Python dict"""
    with open(path, "rb") as file:
        xml_dict = xmltodict.parse(file)["root"]

    # NOTE: remove None values from AD lists and convert year into a int
    for ad in xml_dict:
        xml_dict[ad]["year"] = int(xml_dict[ad]["year"])
        for key in [
            "surf",
            "vect",
            "model",
            "tag",
            "risk",
            "cve",
            "cwe",
            "capec",
            "vref",
        ]:
            xml_dict[ad][key] = [x for x in xml_dict[ad][key] if x is not None]

    return xml_dict


def _parse_json(path: Path) -> dict:
    """Parse from a JSON AD file in a Python dict"""
    with open(path, "r", encoding="utf8") as file:
        json_dict = json.load(file)

    return json_dict


def _parse_yaml(path: Path) -> dict:
    """Parse from a yaml AD file in a Python dict"""
    with open(path, "r", encoding="utf8") as file:
        yaml_dict = yaml.load(file, SafeLoader)

    return yaml_dict


def _parse_toml(path: Path) -> dict:
    """Parse from a toml AD file in a Python dict"""
    with open(path, "rb") as file:
        toml_dict = tomllib.load(file)

    return toml_dict


def parse(path: Path) -> dict:
    """Parse from a AD file in a Python dict"""

    match path.suffix:
        case ".yaml" | ".yml":
            parsed_dict = _parse_yaml(path)
        case ".toml":
            parsed_dict = _parse_toml(path)
        case ".json":
            parsed_dict = _parse_json(path)
        case ".xml":
            parsed_dict = _parse_xml(path)
        case _:
            print(str(path) + ": invalid extension!")
            raise Exception

    return parsed_dict


if __name__ == "__main__":
    yaml_dict = parse(Path("template/ad.yaml"))
    xml_dict = parse(Path("template/ad.xml"))
    # _parse_csv(Path("APC_draft.csv"))
