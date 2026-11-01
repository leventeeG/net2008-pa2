# Name: Levi Gosling
# Student ID: 041244769
"""checks an xml inventory against a yaml policy"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml


class InputFileError(Exception):
    """handles missing or invalid input and output files"""


def load_inventory(path):
    """loads the inventory xml and returns its root element"""
    try:
        with Path(path).open("rb") as handle:
            return ET.parse(handle).getroot()
    except ET.ParseError:
        raise InputFileError(f"{path}: not valid XML")
    except OSError:
        raise InputFileError(f"{path}: cannot read file")


def load_policy(path):
    """loads the policy yaml and returns it as a dictionary"""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise InputFileError(f"{path}: cannot read file")
    try:
        policy = yaml.safe_load(text)
    except yaml.YAMLError:
        raise InputFileError(f"{path}: not valid YAML")
    if policy is None:
        return {}
    if not isinstance(policy, dict):
        raise InputFileError(f"{path}: policy must be a mapping")
    return policy
