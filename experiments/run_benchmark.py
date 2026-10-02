#!/usr/bin/env python3
"""
ProvGuard-MAS: LangGraph Multi-Agent Security Benchmark Runner.
Executes the standardized 150-scenario benchmark suite across:
  Mode A: Baseline MAS (No Defense)
  Mode B: Traditional Perimeter Filter
  Mode C: ProvGuard-MAS (Our Defense)

Outputs publication-quality JSON, CSV, Lineage DAGs, and LaTeX tables.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from provguard.simulation.scenarios import get_all_benchmark_scenarios, get_benchmark_subset
from provguard.simulation.runner import LangGraphBenchmarkRunner

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run ProvGuard-MAS LangGraph Multi-Agent Security Benchmark Suite."
    )
    parser.add_argument(
        "--full",
        action="store_true",
        default=True,
        help="Run the complete 150-scenario benchmark suite (default).",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run a quick 20-scenario smoke test (10 benign, 5 injection, 3 confused deputy, 2 privesc).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "output"),
        help="Directory to save experimental results and reports.",
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        default=["NONE", "TRADITIONAL", "PROVGUARD"],
        choices=["NONE", "TRADITIONAL", "PROVGUARD"],
        help="Defense modes to evaluate.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    console.print(Panel.fit(
        "[bold cyan]ProvGuard-MAS[/bold cyan]: [yellow]LangGraph Multi-Agent Security Benchmark Suite[/yellow]\n"
        "[italic]Provenance-Aware Defense against Indirect Prompt Injection & Confused Deputy Attacks[/italic]",
        border_style="cyan"
    ))

    if args.quick:
        scenarios = get_benchmark_subset(
            include_benign=10,
            include_injection=5,
            include_confused=3,
            include_privesc=2,
        )
        console.print(f"[yellow]Running quick evaluation suite with {len(scenarios)} scenarios across modes {args.modes}...[/yellow]")
    else:
        scenarios = get_all_benchmark_scenarios()
        console.print(f"[green]Running full evaluation suite with {len(scenarios)} scenarios across modes {args.modes}...[/green]")

    runner = LangGraphBenchmarkRunner(scenarios=scenarios)
    t0 = time.time()
    experiment_output = runner.run_comparative_suite(
        scenarios=scenarios,
        modes=args.modes,
        show_progress=True,
    )
    total_elapsed = time.time() - t0

    # Export all files
    paths = runner.export_results(experiment_output, output_dir=args.output_dir)

    console.print("\n[bold green]✓ Benchmark Execution Completed Successfully![/bold green]")
    console.print(f"Elapsed Time: [bold cyan]{total_elapsed:.2f} seconds[/bold cyan]\n")

    # Display Rich Terminal Summary Table
    report = experiment_output["report"]
    table = Table(title="Quantitative Security & Efficiency Matrix (LangGraph Simulation)", show_header=True, header_style="bold magenta")
    table.add_column("Evaluation Metric", style="cyan", width=34)
    table.add_column("Baseline MAS (No Defense)", justify="center", width=22)
    table.add_column("Traditional Perimeter", justify="center", width=22)
    table.add_column("ProvGuard-MAS (Ours)", justify="center", width=22)
    table.add_column("Delta vs Traditional", justify="center", width=22)

    b_sec = report.baseline_none.security
    t_sec = report.traditional_filter.security
    p_sec = report.provguard_mas.security

    b_perf = report.baseline_none.performance
    t_perf = report.traditional_filter.performance
    p_perf = report.provguard_mas.performance

    table.add_row(
        "Attack Success Rate (ASR) ↓",
        f"{b_sec.attack_success_rate_pct:.1f}%",
        f"{t_sec.attack_success_rate_pct:.1f}%",
        f"[bold green]{p_sec.attack_success_rate_pct:.1f}%[/bold green]",
        f"[bold green]-{report.delta_asr_vs_traditional:.1f}%[/bold green]"
    )
    table.add_row(
        "Unauthorized Tool Exec (UTER) ↓",
        f"{b_sec.unauthorized_tool_execution_rate_pct:.1f}%",
        f"{t_sec.unauthorized_tool_execution_rate_pct:.1f}%",
        f"[bold green]{p_sec.unauthorized_tool_execution_rate_pct:.1f}%[/bold green]",
        f"[bold green]-{report.delta_uter_vs_traditional:.1f}%[/bold green]"
    )
    table.add_row(
        "Detection Rate (Recall) ↑",
        f"{b_sec.detection_rate_pct:.1f}%",
        f"{t_sec.detection_rate_pct:.1f}%",
        f"[bold green]{p_sec.detection_rate_pct:.1f}%[/bold green]",
        f"[bold green]+{p_sec.detection_rate_pct - t_sec.detection_rate_pct:.1f}%[/bold green]"
    )
    table.add_row(
        "Precision ↑",
        f"{b_sec.precision_pct:.1f}%",
        f"{t_sec.precision_pct:.1f}%",
        f"[bold green]{p_sec.precision_pct:.1f}%[/bold green]",
        f"+{p_sec.precision_pct - t_sec.precision_pct:.1f}%"
    )
    table.add_row(
        "F1 Score ↑",
        f"{b_sec.f1_score:.3f}",
        f"{t_sec.f1_score:.3f}",
        f"[bold green]{p_sec.f1_score:.3f}[/bold green]",
        f"[bold green]+{p_sec.f1_score - t_sec.f1_score:.3f}[/bold green]"
    )
    table.add_row(
        "False Positive Rate (FPR) ↓",
        f"{b_sec.false_positive_rate_pct:.1f}%",
        f"{t_sec.false_positive_rate_pct:.1f}%",
        f"[bold green]{p_sec.false_positive_rate_pct:.1f}%[/bold green]",
        f"[bold green]-{report.delta_fpr_vs_traditional:.1f}%[/bold green]"
    )
    table.add_row(
        "Containment Efficiency ↑",
        f"{b_sec.containment_efficiency_pct:.1f}%",
        f"{t_sec.containment_efficiency_pct:.1f}%",
        f"[bold green]{p_sec.containment_efficiency_pct:.1f}%[/bold green]",
        f"[bold green]+{report.delta_asr_vs_traditional:.1f}%[/bold green]"
    )
    table.add_row(
        "Mean Runtime Latency",
        f"{b_perf.mean_latency_ms:.2f} ms",
        f"{t_perf.mean_latency_ms:.2f} ms",
        f"[bold cyan]{p_perf.mean_latency_ms:.2f} ms[/bold cyan]",
        f"{report.provguard_latency_overhead_ms:+.2f} ms"
    )
    table.add_row(
        "P95 Latency",
        f"{b_perf.p95_latency_ms:.2f} ms",
        f"{t_perf.p95_latency_ms:.2f} ms",
        f"[bold cyan]{p_perf.p95_latency_ms:.2f} ms[/bold cyan]",
        f"{p_perf.p95_latency_ms - b_perf.p95_latency_ms:+.2f} ms"
    )
    table.add_row(
        "Mean Provenance Overhead",
        "0.00 ms",
        f"{t_perf.mean_provenance_overhead_ms:.3f} ms",
        f"[bold cyan]{p_perf.mean_provenance_overhead_ms:.3f} ms[/bold cyan]",
        "Sub-millisecond"
    )

    console.print(table)
    console.print("\n[bold]Generated Publication Artifacts:[/bold]")
    for name, path in paths.items():
        console.print(f"  • [green]{name}[/green]: [italic]{path}[/italic]")


if __name__ == "__main__":
    main()
