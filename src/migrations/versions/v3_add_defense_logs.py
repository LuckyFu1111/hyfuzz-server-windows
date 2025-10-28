"""Migration v3_add_defense_logs."""

from __future__ import annotations


def upgrade() -> None:
    print("Applying v3_add_defense_logs")


def downgrade() -> None:
    print("Reverting v3_add_defense_logs")


if __name__ == "__main__":
    upgrade()
