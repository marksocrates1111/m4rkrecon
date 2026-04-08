"""M4rkRecon - Logging with Rich console output + file logging."""

import os
import logging
from datetime import datetime
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel

custom_theme = Theme({
    "phase": "bold cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "info": "bold white",
    "dim": "dim",
    "highlight": "bold magenta",
})

console = Console(theme=custom_theme)


class M4rkLogger:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.log_file = os.path.join(output_dir, "m4rkrecon.log")
        os.makedirs(output_dir, exist_ok=True)

        logging.basicConfig(
            filename=self.log_file,
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.logger = logging.getLogger("m4rkrecon")

    def phase_start(self, phase_num, phase_name, tool_name=""):
        msg = f"Phase {phase_num}: {phase_name}"
        if tool_name:
            msg += f" [{tool_name}]"
        console.print(Panel(
            f"[phase]{msg}[/phase]",
            border_style="cyan",
            padding=(0, 2),
        ))
        self.logger.info(msg)

    def phase_end(self, phase_num, phase_name, count=0):
        msg = f"Phase {phase_num} complete: {phase_name} - {count} results"
        console.print(f"  [success][+][/] {msg}\n")
        self.logger.info(msg)

    def info(self, msg):
        console.print(f"  [info][*][/] {msg}")
        self.logger.info(msg)

    def success(self, msg):
        console.print(f"  [success][+][/] {msg}")
        self.logger.info(msg)

    def warning(self, msg):
        console.print(f"  [warning][!][/] {msg}")
        self.logger.warning(msg)

    def error(self, msg):
        console.print(f"  [error][-][/] {msg}")
        self.logger.error(msg)

    def tool_not_found(self, tool_name):
        self.warning(f"{tool_name} not found in PATH - skipping")

    def result(self, msg):
        console.print(f"    [dim]{msg}[/]")

    def found_count(self, label, count):
        style = "success" if count > 0 else "dim"
        console.print(f"  [{style}][+] Found {count} {label}[/{style}]")
        self.logger.info(f"Found {count} {label}")

    def separator(self):
        console.print("[dim]" + "─" * 70 + "[/dim]")

    def scan_summary(self, results):
        console.print("\n")
        console.print(Panel(
            "[bold white]Scan Summary[/bold white]",
            border_style="green",
        ))
        for key, val in results.items():
            count = len(val) if isinstance(val, list) else val
            console.print(f"  [info]{key}:[/] [highlight]{count}[/highlight]")
        console.print()
