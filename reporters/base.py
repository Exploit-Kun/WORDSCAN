"""
Base reporter class
"""

from abc import ABC, abstractmethod
from typing import List
from pathlib import Path
from core.models import ScanResult


class BaseReporter(ABC):
    """Base class for all reporters"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    async def export(self, results: List[ScanResult]) -> None:
        """Export scan results to file"""
        pass
