#!/usr/bin/env python3
"""Validation and log-correlation checks for SOC-Wazuh-pfSense-IR-Lab artifacts.

Verifies:
1. Wazuh XML configuration snippets are well-formed and contain valid FIM sregex
   patterns and unique custom rule IDs (>= 100000).
2. FIM exclusion regexes suppress noisy .tmp/.log files while alerting on real files.
3. Custom pfSense rule correlation triggers Rule 100903 (Level 12) on blocked IOCs.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class ValidationSummary:
    xml_files_checked: int
    ignore_patterns: List[str]
    custom_rules: Dict[str, int]
    fim_test_results: Dict[str, bool]
    triggered_rules: List[str]


def parse_fim_ignore_patterns(ossec_xml_path: Path) -> List[str]:
    """Parse and compile `<ignore type='PCRE2'>` rules from Wazuh XML."""
    tree = ET.parse(ossec_xml_path)
    root = tree.getroot()
    patterns: List[str] = []
    for elem in root.findall(".//syscheck/ignore"):
        if elem.attrib.get("type") in {"PCRE2", "sregex"} and elem.text:
            re.compile(elem.text.strip())
            patterns.append(elem.text.strip())
    if not patterns:
        raise ValueError(f"No regex <ignore> patterns found in {ossec_xml_path}")
    return patterns


def should_suppress_fim_event(filename: str, ignore_patterns: List[str]) -> bool:
    """Return True if a filename matches any Wazuh FIM noise-exclusion regex."""
    return any(re.search(pat, filename, re.IGNORECASE) for pat in ignore_patterns)


def parse_wazuh_rules(rules_xml_path: Path) -> Dict[str, Dict[str, object]]:
    """Parse and validate custom Wazuh rule IDs, levels, and field matchers."""
    tree = ET.parse(rules_xml_path)
    root = tree.getroot()
    rules: Dict[str, Dict[str, object]] = {}
    for rule_el in root.findall(".//rule"):
        rule_id = rule_el.attrib.get("id")
        level_str = rule_el.attrib.get("level")
        if not rule_id or not level_str:
            raise ValueError("Each <rule> must define 'id' and 'level'")
        rid_num = int(rule_id)
        level = int(level_str)
        if rid_num < 100000:
            raise ValueError(f"Custom local rule ID must be >= 100000, got {rid_num}")
        if not (0 <= level <= 15):
            raise ValueError(f"Rule level must be between 0 and 15, got {level}")
        if rule_id in rules:
            raise ValueError(f"Duplicate rule ID detected: {rule_id}")

        if_sid = rule_el.findtext("if_sid")
        fields = {
            f.attrib["name"]: re.compile(f.text.strip())
            for f in rule_el.findall("field")
            if "name" in f.attrib and f.text
        }
        rules[rule_id] = {
            "id": rule_id,
            "level": level,
            "if_sid": if_sid.strip() if if_sid else None,
            "description": (rule_el.findtext("description") or "").strip(),
            "fields": fields,
        }
    return rules


def evaluate_pfsense_event(
    event: Dict[str, str], rules: Dict[str, Dict[str, object]]
) -> List[str]:
    """Evaluate a parsed pfSense filterlog dict against loaded Wazuh rules."""
    matched: List[str] = []
    # Pass 1: base rules (no if_sid)
    for rid, rule in rules.items():
        if rule["if_sid"] is not None:
            continue
        fields: Dict[str, re.Pattern[str]] = rule["fields"]  # type: ignore[assignment]
        if all(
            k in event and pat.search(event[k]) for k, pat in fields.items()
        ):
            matched.append(rid)

    # Pass 2: dependent correlation rules (if_sid)
    for rid, rule in rules.items():
        parent = rule["if_sid"]
        if parent is None or parent not in matched:
            continue
        fields = rule["fields"]  # type: ignore[assignment]
        if all(
            k in event and pat.search(event[k]) for k, pat in fields.items()
        ):
            matched.append(rid)

    return matched


def run_validation(repo_root: Path = REPO_ROOT) -> ValidationSummary:
    ossec_xml = repo_root / "configs" / "wazuh" / "ossec-fim-syslog.xml"
    rules_xml = repo_root / "configs" / "wazuh" / "local-rules-pfsense.xml"

    ignore_patterns = parse_fim_ignore_patterns(ossec_xml)
    rules = parse_wazuh_rules(rules_xml)

    fim_samples = {
        r"C:\Users\User\Desktop\FIM_Test\2nd_file.txt": False,
        r"C:\Users\User\Desktop\FIM_Test\noise.tmp": True,
        r"C:\Users\User\Desktop\FIM_Test\system.log": True,
    }
    fim_results = {
        path: should_suppress_fim_event(path, ignore_patterns) for path in fim_samples
    }
    for path, expected_suppressed in fim_samples.items():
        if fim_results[path] != expected_suppressed:
            raise AssertionError(
                f"FIM expectation failed for {path}: got suppressed={fim_results[path]}"
            )

    sample_event = {
        "decoder": "pf-filterlog",
        "action": "block",
        "srcip": "192.168.1.100",
        "dstip": "89.238.73.97",
        "dstport": "443",
        "proto": "tcp",
    }
    triggered = evaluate_pfsense_event(sample_event, rules)
    if "100903" not in triggered:
        raise AssertionError(f"Expected rule 100903 to trigger, got {triggered}")

    return ValidationSummary(
        xml_files_checked=2,
        ignore_patterns=ignore_patterns,
        custom_rules={rid: int(r["level"]) for rid, r in rules.items()},  # type: ignore[arg-type]
        fim_test_results=fim_results,
        triggered_rules=triggered,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Wazuh XML configs, FIM regexes, and pfSense rule correlation."
    )
    parser.add_argument(
        "--repo-root", type=Path, default=REPO_ROOT, help="Repository root path"
    )
    args = parser.parse_args(argv)

    summary = run_validation(args.repo_root)
    print(f"[+] XML config files validated: {summary.xml_files_checked}")
    print(f"[+] FIM sregex exclusions:      {summary.ignore_patterns}")
    print(f"[+] Custom Wazuh rules loaded:  {summary.custom_rules}")
    print(f"[+] FIM suppression checks:     {summary.fim_test_results}")
    print(f"[+] Simulated EICAR block alert triggered rules: {summary.triggered_rules}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
