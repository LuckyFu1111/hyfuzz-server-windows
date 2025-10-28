"""Migration v2_add_judge_tables."""

from __future__ import annotations


def upgrade() -> None:
    print("Applying v2_add_judge_tables")


def downgrade() -> None:
    print("Reverting v2_add_judge_tables")


if __name__ == "__main__":
    upgrade()
