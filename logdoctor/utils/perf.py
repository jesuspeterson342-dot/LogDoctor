"""Performance measurement utilities."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path


def measure_peak_memory() -> int:
    """Return current process RSS in KB (Linux only)."""
    try:
        with Path("/proc/self/status").open(encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return 0


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""

    file_path: str
    total_lines: int = 0
    events_found: int = 0
    elapsed_ms: float = 0.0
    lines_per_second: float = 0.0
    memory_peak_kb: int = 0

    @property
    def memory_human(self) -> str:
        """Return human-readable memory usage."""
        if self.memory_peak_kb < 1024:
            return f"{self.memory_peak_kb} KB"
        return f"{self.memory_peak_kb / 1024:.1f} MB"


@dataclass
class Benchmark:
    """Runs a benchmark on a log file."""

    file_path: str = ""
    _start_time: float = 0.0
    elapsed_ms: float = 0.0
    memory_start_kb: int = 0

    def start(self) -> None:
        """Record starting state."""
        self._start_time = time.perf_counter()
        self.memory_start_kb = measure_peak_memory()

    def finish(self, total_lines: int, events_found: int) -> BenchmarkResult:
        """Finish benchmark and return result."""
        self.elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        mem_after = measure_peak_memory()
        memory_peak = max(mem_after - self.memory_start_kb, 0)
        lps = (total_lines / self.elapsed_ms * 1000) if self.elapsed_ms > 0 else 0.0
        return BenchmarkResult(
            file_path=self.file_path,
            total_lines=total_lines,
            events_found=events_found,
            elapsed_ms=self.elapsed_ms,
            lines_per_second=lps,
            memory_peak_kb=memory_peak,
        )
