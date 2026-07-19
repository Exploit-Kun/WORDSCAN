"""
Semantic version parser and comparator
"""

import re
from typing import Tuple, Optional


class VersionParser:
    """Semantic version parser and comparator"""

    @staticmethod
    def parse(version: str) -> Tuple[int, ...]:
        """Parse version string to tuple"""
        if not version or version in ["unknown", "dev", "nightly"]:
            return (0, 0, 0)

        # Remove pre-release suffix
        version = re.sub(r"[-_].*$", "", version)

        parts = version.split(".")
        parsed = []
        for part in parts[:3]:  # Only major.minor.patch
            try:
                parsed.append(int(part))
            except ValueError:
                parsed.append(0)

        while len(parsed) < 3:
            parsed.append(0)

        return tuple(parsed)

    @staticmethod
    def compare(v1: str, v2: str) -> int:
        """Compare two versions. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2"""
        parsed1 = VersionParser.parse(v1)
        parsed2 = VersionParser.parse(v2)

        for p1, p2 in zip(parsed1, parsed2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        return 0

    @staticmethod
    def is_valid(version: str) -> bool:
        """Check if version is valid"""
        if not version:
            return False
        if version in ["unknown", "dev", "nightly"]:
            return True
        return bool(re.match(r"^\d+(\.\d+){0,2}$", version))
