"""
Schema to validate AD dicts and a tool to check and compare ADs

surf is a list of strings, where each string is more specific. E.g., for the
KNOB attack surf = [BC, Session, Entropy negotiation].

The order of the fields does not matter in the schema.

Schema([str]) validates an array of str.

"""

import os.path
import sys
from difflib import get_close_matches, SequenceMatcher
import argparse

from pathlib import Path
from yamllint.config import YamlLintConfig
from yamllint import linter
from schema import Optional, Schema, SchemaError, Regex, And

from parse import parse


# Empty dictionary - no checks
DICT_WORDS = {
    "surf": [
    ],
    "vect": [
    ],
    "model": [
    ],
    "tag": [
    ],
}

# list of surfaces with PID/TID - for MITRE EM3ED mappin
DICT_SURF_PID = []
DICT_SURF_TID = []


_VERBOSE_OUTPUT = False
_SCORE = 0.5

#
# Print hints
def print_hint(msg: str):
    print("HINT: " + msg)

#
# Print info
def print_info(msg: str):
    print("INFO: " + msg)

#
# Print errors
def print_err(msg: str):
    print("ERR : " + msg)

#
# Print verbose
def print_verbose(msg: str):
    global _VERBOSE_OUTPUT

    if _VERBOSE_OUTPUT:
        print("DBG : " + msg)


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
    print_verbose(f"check_yamllint: {path}: passed")


def _check_list(list1: list, key: str, list2=None) -> bool:
    """Verify key existence, and check if list1 is not empty and words in list1 are contained in list2."""
    if list1 is None:
        print_hint("Missing required tag \"" + key + "\"!")
        return False
    if list2 is None:
        return True
    else:
        if ((len(list1) > 0) and len(set(list1) - set(list2[key])) == 0):
            # ITRE EM3ED mapping test - at least one surf must have pid
            if key == "surf":
                if len(set(list1) - set(DICT_SURF_PID)) == len(set(list1)):
                    print_hint("Missing pid for \"" + key + "\". At least one \"surf\" must have pid (see the dictionary).")
                    return False
            if key == "vect":
                if len(set(list1) - set(DICT_SURF_TID)) == len(set(list1)):
                    print_hint("Missing tid for \"" + key + "\". At least one \"vect\" must have tid (see the dictionary).")
                    return False
            return True
        else:
            for missing in (set(list1) - set(list2[key])):
                print_hint("Missing \"" + key + "\": \"" + missing + "\"")
                hints = get_close_matches(missing, list2[key], n=3, cutoff=0.2)
                if len(hints) == 0:
                    print_hint("  - there are no similar terms in the dictionary!")
                else:
                    print_hint("  - did you mean one of: \"" + str(hints) + "\"?")
            return False


def check_schema_dict(ad_dict: dict):
    """Check schema and fields"""

    schema = Schema(
        {
            Regex(r"[surf|vect|model|tag]"): {
                Regex(r"^[A-Za-z0-9_\-\s]+$"): {
                    "alias": And(Schema([str])),
                    "description": And(str, lambda d: len(d) > 0),
                    Optional("pid"): And(
                        int, lambda pid: (11 <= pid <= 5000) # pid is optional - for MITRE EM3ED maping, only for some surfaces
                    ),
                    Optional("tid"): And(
                        int, lambda tid: (100 <= tid <= 5000) # Added optional mipping to MITRE EM3ED TID
                    ),
                }
            }
        }
    )

    try:
        schema.validate(ad_dict)
        print_verbose(f"check_schema: {len(ad_dict)} dictionaries")
    except SchemaError as se:
        print_err("Dictionary format not compliant with schema!")
        if _VERBOSE_OUTPUT:
            raise SystemExit(se)
        else:
            raise SystemExit()


def check_schema(ad_dict: dict, words=None):
    """Check schema and fields"""

    # NOTE: Once stable move to https://github.com/SchemaStore/schemastore
    schema = Schema(
        {
            Regex(r"^[a-z0-9_]+$"): {
                "a": And(str, lambda a: len(a) > 0),
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
                Optional("cve"): And(Schema([str]), lambda s: len(s) >= 0),
                Optional("cwe"): And(Schema([str]), lambda s: len(s) >= 0),
                Optional("capec"): And(Schema([str]), lambda s: len(s) >= 0),
                Optional("vref"): And(Schema([str]), lambda s: len(s) >= 0),
            }
        }
    )

    try:
        schema.validate(ad_dict)
        print_verbose(f"check_schema: {len(ad_dict)} ads")
    except SchemaError as se:
        print_err("AD format not compliant with schema!")
        if _VERBOSE_OUTPUT:
            raise SystemExit(se)
        else:
            raise SystemExit()

##
#
#  Check the AD file
#
def check(path: Path, words=None) -> dict:
    """Return a sanitized AD dict"""

    # NOTE: file specific checks
    match path.suffix:
        case ".yaml" | ".yml":
            print_verbose("Checking YAML syntax: " + str(path))
            check_yamllint(path)

    ad_dict = None

    try:
        ad_dict = parse(path)
        # NOTE: Python dict checks
        check_schema(ad_dict, words)
    except Exception as err:
        print_err("Parsing " + str(path) +  " failed!")
        print_verbose(err)


    return ad_dict


##
# Compare two AD files and report simiarities
#
# NOTE: compliant AD files expected (check AD file first)
#
def compare(in1: Path, in2: Path):

    global _SCORE

    try:
        ad1_dict = parse(in1)
        ad2_dict = parse(in2)
    except Exception as err:
        print_err("Parsing " + str(in1) + ", "  + str(in2) + " failed!")
        print_verbose(err)
        raise SystemExit()

    for ad1 in ad1_dict.items():
        for ad2 in ad2_dict.items():
            log = ""
            score = 1.0 # different ADs have score close to 1.0
            if ad1[0] == ad2[0]:
                print("Duplicate key: " + ad1[0] + "," + ad2[0])
                score = 0.0
                continue

            if "tid" in ad1[1].keys():
                if "tid" in ad2[1].keys():
                    if ad1[1]["tid"] == ad2[1]["tid"]:
                        log = log + "identic TID, "
                        score = score / 2

            if "pid" in ad1[1].keys():
                if "pid" in ad2[1].keys():
                    if ad1[1]["pid"] == ad2[1]["pid"]:
                        log = log + "identic PID, "
                        score = score / 4

            if "cve" in ad1[1].keys():
                if "cve" in ad2[1].keys():
                    if ad1[1]["cve"] == ad2[1]["cve"]:
                        log = log + "identic CVE, "
                        score = score / 2

            if "cwe" in ad1[1].keys():
                if "cwe" in ad2[1].keys():
                    for cwe in ad1[1]["cwe"]:
                        if cwe in ad2[1]["cwe"]:
                            log = log + "identic CWE, "
                            score = score / 1.5
                            break

            for tag in {"surf", "tag", "model", "vect"}:
                for cross in (set(ad1[1][tag]) - set(ad2[1][tag])):
                    if len(cross) < len(ad1[1][tag]):
                        log = log + "matching " + tag + ", "
                        score = score / 1.25
                        break

            adiff = SequenceMatcher(None, ad1[1]["a"], ad2[1]["a"]).ratio()
            if adiff > 0.2:
                score = score / (1 + adiff/2)
                log = log + "attack description, "

            if score < _SCORE:
                print_hint("Similar ADs " + "(" + str(round(1-score,2)) + "): " + ad1[0] + ", " + ad2[0] + ":")

                if len(log) > 0:
                    print_verbose("Symptoms: " + log)

##
# Generate dictionary based on the content of an AD file
#
# NOTE: compliant AD file is expected (check AD file first)
#
def gendict(ad: Path):
    gen = {
        "surf": [
        ],
        "vect": [
        ],
        "model": [
        ],
        "tag": [
        ],
    }

    try:
        dict = parse(ad)
    except Exception as err:
        print_err("Parsing " + str(ad) + " failed!")
        print_verbose(err)
        raise SystemExit()

    for ad in dict.items():
        for tag in {"surf", "vect", "model", "tag"}:
            try:
                for item in ad[1][tag]:
                    if item not in gen[tag]:
                        gen[tag].append(item)
            except Exception as err:
                print_err("Missing required tag \"" + tag + "\" in \"" + ad[0] + "\"!")
                print_verbose(err)
                raise SystemExit()

    print("---");
    print("# NOTE: dictionary for the check.py tool")

    for item in gen:
        print(str(item) + ":")
        for member in gen[item]:
            print("    " + str(member) + ":")
            print("        alias: [\"" + str(member) + "\"]")
            print("        description: \"" + str(member) + "\"")
            if (item == "surf"):
                print("        pid:")
            if (item == "vect"):
                print("        tid:")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = 'AD Checker')
    parser.add_argument('-v', '--verbose', help='Show detailed debug output', action='store_true')
    parser.add_argument('-i', '--input', help='Input AD file name', required=True)
    parser.add_argument('-d', '--dict', help='Dictionary file name')
    parser.add_argument('-g', '--gendict', help='Generate dictionary from the AD file', action='store_true')
    parser.add_argument('-c', '--compare', help='AD file name for comparison with the input file')
    parser.add_argument('-s', '--score', help='AD file similarity score threshold when comaring two ADs [0, 1.0] (higher is higher similarity)')

    args = parser.parse_args()

    _VERBOSE_OUTPUT = args.verbose

    if args.dict == None:
        # No dictionary - do not check against dictionary
        DICT_WORDS = None
    else:
        # Read the dictionary
        if os.path.isfile(args.dict):
            # read words
            print_verbose("Checking the dictionary YAML syntax: " + str(args.dict))
            check_yamllint(args.dict)

            try:
                parsed_dict = parse(Path(args.dict))
            except Exception as err:
                print_err("Parsing " + str(args.dict) + " failed!")
                print_verbose(str(err))
                raise SystemExit()

            try:
                # NOTE: Python dict checks
                check_schema_dict(parsed_dict)
            except Exception as err:
                print_err("Checking " + str(args.dict) + " failed!")
                print_verbose(str(err))
                raise SystemExit()

            for dicts in ["surf" , "vect", "model", "tag"]:
                del DICT_WORDS[dicts][:]

                # Add primary keys to the dictionary
                for item, value in parsed_dict[dicts].items():
                    if item in DICT_WORDS[dicts]:
                        print_err("Dictionary \"" + dicts + "\" contains duplicate term: \"" + item + "\"")
                        raise SystemExit()
                    else:
                        DICT_WORDS[dicts].append(item)

                    # Add aliases to the dictionary
                    effective_aliases = [] # remember processed aliases to add to MM3ED-helper arrays
                    for alias in parsed_dict[dicts][item]["alias"]:
                        if alias == item:
                            # already in dictionary - alias equal to the primary key is enabled
                            pass
                        elif alias in DICT_WORDS[dicts]:
                            # conflict of alias with other item key
                            print_err("Dictionary contains duplicate term: \"" + alias + "\" (alias of: \"" + item + "\")")
                            raise SystemExit()
                        else:
                            DICT_WORDS[dicts].append(alias)
                            effective_aliases.append(alias)

                    # MITRE EM3ED mapping - PID mapping
                    if dicts == "surf":
                        if "pid" in parsed_dict[dicts][item]:
                            DICT_SURF_PID.append(item)
                            DICT_SURF_PID += effective_aliases
                    if dicts == "vect":
                        if "tid" in parsed_dict[dicts][item]:
                            DICT_SURF_TID.append(item)
                            DICT_SURF_TID += effective_aliases

            print_verbose("Loaded PIDs: " + str(DICT_SURF_PID))
            print_verbose("Loaded TIDs: " + str(DICT_SURF_TID))

            print_info("Dictionary loaded.")

        else:
            print_err("Dictionary " + args.dict + " not found!")
            raise SystemExit()

    if os.path.isfile(args.input):
        check(Path(args.input), DICT_WORDS)

        print_info("Input file processed.")

        if args.gendict:
            # Dump Dictionary based on string in the input file
            gendict(Path(args.input))

            print_info("Dictionary generated.")


        # Copare ADs in the input and compare files
        if args.compare != None:
            if os.path.isfile(args.compare):
                check(Path(args.compare), DICT_WORDS)
                # check if a custom score is provided
                if args.score == None:
                    pass
                elif (type(float(args.score)) is float) and (float(args.score) <= 1.0):
                    _SCORE = 1.0 - float(args.score)
                    print_verbose("Using score: " + str(_SCORE))
                else:
                    print_err("Invalid score: " + str(args.score))
                # Display similar items
                compare(Path(args.input), Path(args.compare))

                print_info("Comparison finished.")
            else:
                print_err("File " + args.compare + " not found!")
                raise SystemExit()


    else:
        print_err("File " + args.input + " not found!")
        raise SystemExit()

