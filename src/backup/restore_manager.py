"""Restores backups."""

from __future__ import annotations

from pathlib import Path


class RestoreManager:
    def restore(self, backup_path: Path) -> None:
        if not backup_path.exists():
            raise FileNotFoundError(str(backup_path))
        print(f"Restoring from {backup_path}")


if __name__ == "__main__":
    manager = RestoreManager()
    try:
        manager.restore(Path("/tmp/does-not-exist"))
    except FileNotFoundError as exc:
        print("Error:", exc)
