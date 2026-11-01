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


def write_report(report, path="audit.json"):
    """writes the report dictionary to a json file"""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
    except OSError:
        raise InputFileError(f"{path}: cannot write file")


def build_report(root, policy):
    """checks each device and builds the audit report"""
    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}
    violations = []
    compliant = []
    skipped = 0
    total = 0
    for element in root.findall("device"):
        if element.get("id") is None:
            skipped += 1
            continue
        device = Device(element)
        total += 1
        roles[device.role] = roles.get(device.role, 0) + 1
        counts = device.count_interfaces()
        for key in counts:
            interfaces[key] += counts[key]
        found = device.violations(policy)
        violations.extend(found)
        if not found:
            compliant.append(device.id)
    return {
        "site": root.get("site"),
        "total_devices": total,
        "skipped_devices": skipped,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant),
    }


def main(argv):
    """runs the auditor and returns the exit code"""
    if len(argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        return 2
    try:
        root = load_inventory(argv[1])
        policy = load_policy(argv[2])
        report = build_report(root, policy)
        write_report(report)
    except InputFileError as err:
        print(f"error: {err}")
        return 1
    print(
        f"site: {report['site']} | devices: {report['total_devices']} "
        f"| skipped: {report['skipped_devices']} "
        f"| violations: {len(report['violations'])} "
        f"| compliant: {len(report['compliant'])}"
    )
    print("report written to audit.json")
    return 0


class Device:
    """stores information about one network device"""

    def __init__(self, element):
        """gets the device id, role, os, owner and interface statuses"""
        self.id = element.get("id")
        self.role = element.get("role", "")
        self.os = element.get("os")
        owner = element.find("owner")
        text = owner.text if owner is not None else None
        self.owner = (text or "").strip()
        self.statuses = []
        for interface in element.findall("interface"):
            self.statuses.append(interface.get("status"))

    def count_interfaces(self):
        """counts the up, down and other interfaces"""
        counts = {"up": 0, "down": 0, "other": 0}
        for status in self.statuses:
            if status == "up" or status == "down":
                counts[status] += 1
            else:
                counts["other"] += 1
        return counts

    def check_role(self, policy):
        """checks whether the device role is allowed"""
        min_os = policy.get("min_os")
        if isinstance(min_os, dict) and self.role not in min_os:
            return {"device": self.id, "type": "unknown_role", "role": self.role}
        return None

    def check_owner(self, policy):
        """checks whether the device has an owner"""
        if policy.get("require_owner") is True and not self.owner:
            return {"device": self.id, "type": "missing_owner"}
        return None

    def check_down(self, policy):
        """checks whether the device has too many down interfaces"""
        limit = policy.get("max_down_interfaces")
        if isinstance(limit, bool) or not isinstance(limit, (int, float)):
            return None
        down = self.count_interfaces()["down"]
        if down > limit:
            return {"device": self.id, "type": "too_many_down", "down": down}
        return None

    def parse_version(self, text):
        """converts a version string into a list of numbers"""
        parts = []
        for piece in str(text).strip().split("."):
            if piece.isdigit():
                parts.append(int(piece))
            else:
                parts.append(0)
        while parts and parts[-1] == 0:
            parts.pop()
        return parts

    def check_os(self, policy):
        """checks whether the device os is below the required version"""
        min_os = policy.get("min_os")
        if not isinstance(min_os, dict) or self.role not in min_os or self.os is None:
            return None
        required = str(min_os[self.role])
        if self.parse_version(self.os) < self.parse_version(required):
            return {
                "device": self.id,
                "type": "os_outdated",
                "found": self.os,
                "required": required,
            }
        return None

    def violations(self, policy):
        """runs all policy checks and returns the violations"""
        found = []
        checks = (
            self.check_role(policy),
            self.check_os(policy),
            self.check_owner(policy),
            self.check_down(policy),
        )
        for problem in checks:
            if problem is not None:
                found.append(problem)
        return found
