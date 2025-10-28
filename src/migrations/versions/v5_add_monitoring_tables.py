"""Migration v5_add_monitoring_tables."""

from __future__ import annotations


def upgrade() -> None:
    print("Applying v5_add_monitoring_tables")


def downgrade() -> None:
    print("Reverting v5_add_monitoring_tables")


if __name__ == "__main__":
    upgrade()
