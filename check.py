"""
Schema to validate AD dicts

surf is a list of strings, where each string is more specific. E.g., for the
KNOB attack surf = [BC, Session, Entropy negotiation].

The order of the fields does not matter in the schema.

Schema([str]) validates an array of str.

TODO is currently a valid word in the dictionary>

"""

from pathlib import Path
from yamllint.config import YamlLintConfig
from yamllint import linter
from schema import Optional, Schema, SchemaError, Regex, And

from parse import parse

BT_WORDS = {
    "surf": [
        "A2MP",
        "ACL",
        "Android",
        "Android",
        "Association",
        "Authentication",  # challenge response
        "BC",
        "BLE",
        "BLE-Stack",
        "BM",
        "BlueZ",
        "CTKD",
        "Entropy negotiation",
        "Feature exchange",
        "Flouride",
        "GATT",
        "HCI",
        "Kernel",
        "Key agreement",  # Key exchange, ECDH, ad-hoc
        "LEAP",
        "Legacy pairing",
        "Linux",
        "MagicPairing",
        "SMP",
        "LMP",
        "Pairing",  # SSP
        "Provisioning",  # Mesh
        "Scanning",
        "Session establishment",
        "Session",
        "TODO",
        "Windows",
        "iOS",
    ],
    "vect": [
        "TODO",
        "Heap overflow",
        "Buffer overflow",
        "Kernel panic",
        "Pointer corruption",
        "Pointer dereference",
        "Information leak",
        "Entropy downgrade",
        "Key brute force",
        "Brute force",  # keys, chall resp
        "Authentication skip",
        "Authentication role switch",
        "Authentication challenge reflection",
        "SC downgrade",
        "No IO downgrade",
        "Encryption downgrade",
        "Cross-transport pairing",
        "Invalid ECC point",
        "MitM",
        "Relay",
        "Replay",
        "Eavesdropping",
        "Tracking",
        "RCE",
        "RID",
        "DoS",
        "DDoS",
    ],
    "model": [
        "CloseProximity",  # NFC
        "Downgrade",
        "Eavesdropper",
        "Fingerprinting",
        "Hijacking",
        "Impersonation",
        "MitM",
        "Physical",  # invasive or non-invasive access
        "Proximity",  # Bluetooth, Wi-Fi range
        "Remote",  # Internet
        "Spoofing",
        "TODO",
        "Unintended session",
        "Zero-Click",
    ],
    "tag": [
        "TODO",
        "ACL",
        "BLELL",
        "BMP",
        "BNEP",
        "Confidentiality",
        "Fuzz",
        "ID",
        "Impl",
        "L2CAP",
        "LELSC",
        "LESC",
        "LSC",
        "PAN",
        "Privacy",
        "Probabilistic",
        "Protocol",
        "SC",
        "SCO",
        "SDP",
        "SSP",
        "dual-mode",
    ],
}

PROC_WORDS = {
    "surf": [
        "TODO",
        "Apple",
        "MacOS",
        "Xcode",
        "Jenkins",
        "Travis CI",
        "GitHub Actions",
        "Tekton",
        "PyPI",
        "Npm",
        "RubyGems",
        "SourceForge",
        "JCenter",
        "AUR",
        "Snappy",
        "DockerHub",
    ],
    "vect": [
        "TODO",
        "Compiler backdoor",
    ],
    "model": [
        "TODO",
    ],
    "tag": [
        "TODO",
        "IDE",
        "EDA",
        "CAD",
    ],
}

FT_WORDS = {
    "surf": [
        "TODO",
    ],
    "vect": [
        "TODO",
    ],
    "model": [
        "TODO",
    ],
    "tag": [
        "TODO",
    ],
}

ES_WORDS = {
    "surf": [
        "TODO",
    ],
    "vect": [
        "TODO",
    ],
    "model": [
        "TODO",
    ],
    "tag": [
        "TODO",
    ],
}


def check_yamllint(path: Path):
    """Check with default yamllint config"""

    # NOTE: https://yamllint.readthedocs.io/en/stable/configuration.html
    # NOTE: duplicates, syntax, ...
    conf = YamlLintConfig(
        """
    extends: default

    rules:
      line-length: disable
    """
    )
    with open(path, "r", encoding="utf8") as file:
        gen = linter.run(file, conf)
        errors = list(gen)
        if errors:
            for e in errors:
                print(e)
            raise SystemExit("Invalid YAML")
    print(f"check_yamllint: {path}: passed")


def _check_list(list1: list, key: str, list2=None) -> bool:
    """Check if list1 is not empty and words in list1 are contained in list2."""
    if list2 is None:
        return True
    else:
        return (len(list1) > 0) and len(set(list1) - set(list2[key])) == 0


def check_schema(ad_dict: dict, words=None):
    """Check schema and fields"""

    # NOTE: Once stable move to https://github.com/SchemaStore/schemastore
    schema = Schema(
        {
            Regex(r"^[a-z0-9_]+$"): {
                "a": And(str, lambda a: len(a) > 0),
                # "d": And(Schema([{str: [str]}])),
                "d": And(Schema({str: [str]})),
                Optional("year"): And(
                    int, lambda year: (1980 <= year <= 2030) or year == 0
                ),
                # NOTE: surf ideally lists from the broadest to the most specific
                "surf": And(
                    Schema([str]),
                    lambda surf: _check_list(surf, "surf", words),
                ),
                "vect": And(
                    Schema([str]),
                    lambda vect: _check_list(vect, "vect", words),
                ),
                "model": And(
                    Schema([str]),
                    lambda model: _check_list(model, "model", words),
                ),
                "tag": And(
                    Schema([str]),
                    lambda tag: _check_list(tag, "tag", words),
                ),
                Optional("req"): And(
                    Schema([str]),
                    lambda s: (len(s) > 0),
                ),
                # NOTE: we strip the CVE-nnnn
                Optional("risk"): And(Schema(float), lambda s: s >= 0),
                Optional("cve"): And(Schema([str]), lambda s: len(s) > 0),
                Optional("cwe"): And(Schema([str]), lambda s: len(s) > 0),
                Optional("capec"): And(Schema([str]), lambda s: len(s) > 0),
                Optional("vref"): And(Schema([str]), lambda s: len(s) > 0),
            }
        }
    )

    try:
        schema.validate(ad_dict)
        print(f"check_schema: {len(ad_dict)} ads")
    except SchemaError as se:
        raise SystemExit(se)


def check(path: Path, words=None) -> dict:
    """Return a sanitized AD dict"""

    # NOTE: file specific checks
    match path.suffix:
        case ".yaml" | ".yml":
            check_yamllint(path)

    ad_dict = parse(path)

    # NOTE: Python dict checks
    check_schema(ad_dict, words)

    return ad_dict


if __name__ == "__main__":
    check(Path("yaml/bt.yaml"), BT_WORDS)
    # check(Path("yaml/proc.yaml"), PROC_WORDS)
    # check(Path("yaml/fitness-trackers.yaml"), FT_WORDS)
    # check(Path("yaml/e-scooters.yaml"), ES_WORDS)
