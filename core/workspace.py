"""
core/workspace.py  —  Scan session save & resume (workspace manager).
Allows practitioners to pause and resume scans, compare results over time.
"""
import json
import os
from datetime import datetime
from pathlib import Path


class WorkspaceManager:
    def __init__(self, root_dir=None, console=None):
        self._root  = Path(root_dir) if root_dir else Path.cwd()
        self._ws    = self._root / "workspaces"
        self._ws.mkdir(exist_ok=True)
        self._con   = console

    def _print(self, msg: str):
        if self._con:
            self._con.print(msg)
        else:
            print(msg)

    def save(self, name: str, targets: list, findings: list, modules_run: list) -> Path:
        """Save current scan state."""
        import re as _re
        name = _re.sub(r"[^a-zA-Z0-9_\-]", "_", name.strip()) or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        name = name[:64]  # Limit length
        path   = self._ws / f"{name}.json"
        data   = {
            "name":        name,
            "created":     datetime.now().isoformat(),
            "targets":     targets,
            "modules_run": modules_run,
            "findings":    [f.to_dict() for f in findings],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        self._print(f"[bold green]✓ Workspace saved: {path.name}[/bold green]")
        return path

    def load(self, name: str) -> dict:
        """Load a saved workspace by name (without .json extension)."""
        candidates = list(self._ws.glob(f"{name}*.json"))
        if not candidates:
            self._print(f"[red]Workspace '{name}' not found.[/red]")
            return {}
        path = sorted(candidates)[-1]
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self._print(f"[cyan]Loaded workspace: {path.name}[/cyan]")
            return data
        except Exception as e:
            self._print(f"[red]Failed to load workspace: {e}[/red]")
            return {}

    def list_workspaces(self) -> list:
        """List all saved workspaces sorted by modification time."""
        files = sorted(
            self._ws.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        return files

    def interactive(self):
        """Interactive workspace menu (called from main menu)."""
        from rich.table import Table
        from rich import box

        files = self.list_workspaces()
        if not files:
            self._print("[yellow]No saved workspaces found.[/yellow]")
            return

        tbl = Table(title="Saved Workspaces", box=box.SIMPLE_HEAVY, border_style="cyan")
        tbl.add_column("#",        min_width=4)
        tbl.add_column("Name",     min_width=28)
        tbl.add_column("Created",  min_width=19)
        tbl.add_column("Targets",  min_width=20)
        tbl.add_column("Findings", min_width=8, justify="right")

        for i, f in enumerate(files[:20], 1):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                tbl.add_row(
                    str(i),
                    f.stem,
                    d.get("created", "")[:19],
                    ", ".join(d.get("targets", []))[:30],
                    str(len(d.get("findings", []))),
                )
            except Exception:
                tbl.add_row(str(i), f.stem, "?", "?", "?")

        self._print(tbl)
        self._print("[dim]Workspaces are stored in /workspaces/  — load them with --workspace NAME[/dim]")
