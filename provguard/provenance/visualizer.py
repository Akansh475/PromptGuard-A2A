"""
Lineage visualization utilities for terminal output and web UI rendering.
"""

from __future__ import annotations

from typing import List
from rich.tree import Tree
from rich.text import Text
from provguard.provenance.tracker import ProvenanceTracker


def build_rich_lineage_tree(tracker: ProvenanceTracker, target_message_id: str) -> Tree:
    """Constructs a Rich Tree visualizing the full provenance ancestry of a message."""
    ancestry = tracker.trace_ancestry(target_message_id)
    if not ancestry:
        return Tree("[bold red]No provenance lineage found[/bold red]")

    root = ancestry[0]
    tree = Tree(
        f"[bold cyan]Root Origin:[/bold cyan] {root.root_source_id} "
        f"([yellow]{root.root_trust.name}[/yellow]) | Initial Taint: {root.taint_score:.2f}"
    )

    current_node = tree
    for rec in ancestry:
        taint_color = "green" if rec.taint_score < 0.3 else ("yellow" if rec.taint_score < 0.7 else "red")
        label = Text()
        label.append(f"Hop {rec.hop_count}: ", style="bold magenta")
        label.append(f"{rec.source_role.value} ({rec.source_agent_id})", style="bold blue")
        label.append(" ──► ", style="white")
        label.append(f"{rec.target_role.value} ({rec.target_agent_id})", style="bold cyan")
        label.append(f" [Taint: {rec.taint_score:.2f}]", style=f"bold {taint_color}")
        
        transforms = ", ".join([t.step for t in rec.transformations]) if rec.transformations else "PASSTHROUGH"
        label.append(f"\n   ↳ Transformations: {transforms}", style="dim")

        child_node = current_node.add(label)
        current_node = child_node

    return tree
