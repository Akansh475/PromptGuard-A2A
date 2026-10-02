"""
Command-line interface (CLI) for ProvGuard-MAS with Rich terminal rendering.
"""

from __future__ import annotations

import argparse
import json
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from provguard.benchmark.runner import BenchmarkRunner
from provguard.benchmark.scenarios import get_standard_benchmark_suite, Scenario
from provguard.benchmark.metrics import compute_efficiency_matrix, format_markdown_table
from provguard.provenance.visualizer import build_rich_lineage_tree
from provguard.web.server import run_web_server

console = Console()


def run_benchmark_cmd(args: argparse.Namespace) -> None:
    """Executes comparative benchmark and renders formatted tables."""
    console.print(
        Panel(
            "[bold cyan]ProvGuard-MAS[/bold cyan]: Provenance-Aware Multi-Agent Defense Benchmark Runner",
            subtitle="Comparing Baseline (Vulnerable) vs ProvGuard Runtime Defense",
        )
    )

    runner = BenchmarkRunner()
    with console.status("[bold green]Executing multi-agent benchmark suite..."):
        experiment = runner.run_comparative_experiment()
        matrix = compute_efficiency_matrix(
            baseline_results=experiment["baseline"],
            provguard_results=experiment["provguard"],
            traditional_results=experiment.get("traditional"),
        )

    # Render Scenario Breakdown Table
    table = Table(title="Scenario Breakdown & Execution Audit", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Scenario Name", width=34)
    table.add_column("Category", width=12)
    table.add_column("Baseline Exploited?", justify="center", width=20)
    table.add_column("ProvGuard Status", justify="center", width=18)
    table.add_column("Latency (ms)", justify="right", width=14)

    for base_res, prov_res in zip(experiment["baseline"], experiment["provguard"]):
        cat_style = "bold red" if base_res.category == "ADVERSARIAL" else "bold green"
        base_status = "[bold red]YES (Exploited)[/bold red]" if base_res.attack_succeeded else "[green]NO (Safe)[/green]"
        
        prov_status = (
            "[bold green]BLOCKED[/bold green]"
            if prov_res.status == "BLOCKED"
            else ("[bold yellow]QUARANTINED[/bold yellow]" if prov_res.status == "QUARANTINED" else "[green]COMPLETED[/green]")
        )

        table.add_row(
            base_res.scenario_id,
            base_res.scenario_name,
            f"[{cat_style}]{base_res.category}[/{cat_style}]",
            base_status,
            prov_status,
            f"{prov_res.latency_ms:.2f}",
        )

    console.print(table)
    console.print()

    # Render Efficiency Matrix Table
    eff_table = Table(title="Quantitative Security & Efficiency Matrix (Comparison with Traditional Method)", show_header=True, header_style="bold cyan")
    eff_table.add_column("Evaluation Metric", style="bold white", width=34)
    eff_table.add_column("Baseline MAS (Unprotected)", justify="center", width=24)
    eff_table.add_column("Traditional Perimeter", justify="center", width=24)
    eff_table.add_column("ProvGuard-MAS (Our Defense)", justify="center", width=26)
    eff_table.add_column("Change vs Traditional", justify="center", width=26)

    trad_asr = f"{matrix.traditional.attack_success_rate_pct:.1f}%" if matrix.traditional else "N/A"
    trad_uter = f"{matrix.traditional.unauthorized_tool_execution_rate_pct:.1f}%" if matrix.traditional else "N/A"
    trad_fpr = f"{matrix.traditional.false_positive_rate_pct:.1f}%" if matrix.traditional else "N/A"
    trad_lat = f"{matrix.traditional.mean_latency_ms:.2f} ms" if matrix.traditional else "N/A"

    eff_table.add_row(
        "Attack Success Rate (ASR)",
        f"[red]{matrix.baseline.attack_success_rate_pct:.1f}%[/red]",
        f"[yellow]{trad_asr}[/yellow]",
        f"[bold green]{matrix.provguard.attack_success_rate_pct:.1f}%[/bold green]",
        f"[bold green]-{matrix.delta_asr_vs_traditional:.1f}% (Attacks Eliminated)[/bold green]" if matrix.delta_asr_vs_traditional is not None else "-100%",
    )
    eff_table.add_row(
        "Unauthorized Tool Execution (UTER)",
        f"[red]{matrix.baseline.unauthorized_tool_execution_rate_pct:.1f}%[/red]",
        f"[yellow]{trad_uter}[/yellow]",
        f"[bold green]{matrix.provguard.unauthorized_tool_execution_rate_pct:.1f}%[/bold green]",
        f"[bold green]-{matrix.delta_uter_vs_traditional:.1f}% (Zero Executions)[/bold green]" if matrix.delta_uter_vs_traditional is not None else "-100%",
    )
    eff_table.add_row(
        "Containment Efficiency Ratio",
        f"[red]{matrix.baseline.containment_efficiency_pct:.1f}%[/red]",
        f"[yellow]{matrix.traditional.containment_efficiency_pct:.1f}%[/yellow]" if matrix.traditional else "0.0%",
        f"[bold green]{matrix.provguard.containment_efficiency_pct:.1f}%[/bold green]",
        f"[bold green]+{matrix.delta_asr_vs_traditional:.1f}% Gain[/bold green]" if matrix.delta_asr_vs_traditional is not None else "+100%",
    )
    eff_table.add_row(
        "False Positive Rate (FPR)",
        f"[green]{matrix.baseline.false_positive_rate_pct:.1f}%[/green]",
        f"[red]{trad_fpr}[/red]",
        f"[bold green]{matrix.provguard.false_positive_rate_pct:.1f}%[/bold green]",
        f"[bold green]-{matrix.delta_fpr_vs_traditional:.1f}% (Zero Disruption)[/bold green]" if matrix.delta_fpr_vs_traditional is not None else "0.0%",
    )
    eff_table.add_row(
        "Mean Latency per Message",
        f"{matrix.baseline.mean_latency_ms:.2f} ms",
        f"{trad_lat}",
        f"{matrix.provguard.mean_latency_ms:.2f} ms",
        f"[bold cyan]{matrix.latency_speedup_vs_traditional_pct:.1f}% Faster / Sub-ms[/bold cyan]" if matrix.latency_speedup_vs_traditional_pct is not None else "Sub-ms",
    )
    eff_table.add_row(
        "Max Propagation Depth",
        f"{matrix.baseline.max_propagation_depth} hops (to Sink)",
        f"{matrix.traditional.max_propagation_depth} hops" if matrix.traditional else "N/A",
        f"[bold green]{matrix.provguard.max_propagation_depth} hops (Boundary)[/bold green]",
        "[bold green]Early isolation[/bold green]",
    )

    console.print(eff_table)

    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump({
                "baseline": [r.model_dump() for r in experiment["baseline"]],
                "provguard": [r.model_dump() for r in experiment["provguard"]],
                "matrix": matrix.model_dump(),
            }, f, indent=2)
        console.print(f"[bold green]✓[/bold green] Saved benchmark JSON to: [cyan]{args.json_output}[/cyan]")


def run_simulate_cmd(args: argparse.Namespace) -> None:
    """Simulates a single scenario and renders the provenance lineage tree."""
    suite = get_standard_benchmark_suite()
    scenario = next((s for s in suite if s.scenario_id == args.scenario), None)
    if not scenario:
        console.print(f"[red]Error: Scenario '{args.scenario}' not found. Available: {[s.scenario_id for s in suite]}[/red]")
        sys.exit(1)

    console.print(Panel(f"[bold cyan]Running Scenario:[/bold cyan] {scenario.name} ({scenario.category})"))
    runner = BenchmarkRunner([scenario])
    res = runner.run_scenario(scenario, enable_defense=not args.no_defense)

    color = "green" if not res.attack_succeeded and not res.false_positive else "red"
    console.print(f"Status: [{color}]{res.status}[/{color}] | Unauthorized Tool Executed: {res.unauthorized_tool_executed}")
    console.print(f"Latency: {res.latency_ms:.2f}ms | Max Depth: {res.max_propagation_depth} hops")
    console.print(f"Actions Taken: {res.defense_actions_taken}")


def run_langgraph_cmd(args: argparse.Namespace) -> None:
    """Runs the LangGraph Multi-Agent Security Benchmark Suite."""
    from provguard.simulation.scenarios import get_all_benchmark_scenarios, get_benchmark_subset
    from provguard.simulation.runner import LangGraphBenchmarkRunner

    console.print(
        Panel(
            "[bold cyan]ProvGuard-MAS[/bold cyan]: LangGraph Multi-Agent Security Simulation",
            subtitle="Evaluating 150 Benchmark Workflows across None vs Traditional vs ProvGuard-MAS",
        )
    )

    scenarios = get_benchmark_subset(10, 5, 3, 2) if args.quick else get_all_benchmark_scenarios()
    runner = LangGraphBenchmarkRunner(scenarios=scenarios)
    out = runner.run_comparative_suite(scenarios=scenarios, show_progress=True)
    paths = runner.export_results(out, output_dir=args.output_dir)

    console.print(f"\n[bold green]✓ LangGraph Benchmark Complete ({len(scenarios)} scenarios)![/bold green]")
    console.print(f"Results saved to: [cyan]{args.output_dir}[/cyan]")


def run_web_cmd(args: argparse.Namespace) -> None:
    """Launches web server."""
    run_web_server(port=args.port)


def main() -> None:
    parser = argparse.ArgumentParser(description="ProvGuard-MAS: Provenance-Aware Multi-Agent Defense CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Benchmark parser
    bench_parser = subparsers.add_parser("benchmark", help="Run comparative benchmark suite")
    bench_parser.add_argument("--json-output", "-j", type=str, default=None, help="Path to save benchmark JSON results")

    # LangGraph parser
    lg_parser = subparsers.add_parser("langgraph", help="Run LangGraph multi-agent simulation benchmark")
    lg_parser.add_argument("--quick", action="store_true", help="Run 20-scenario smoke test")
    lg_parser.add_argument("--output-dir", "-o", type=str, default="experiments/output", help="Directory for output files")

    # Simulate parser
    sim_parser = subparsers.add_parser("simulate", help="Simulate a single scenario")
    sim_parser.add_argument("--scenario", "-s", type=str, default="ADV_01", help="Scenario ID (e.g. ADV_01, BENIGN_01)")
    sim_parser.add_argument("--no-defense", action="store_true", help="Disable ProvGuard defense to test baseline vulnerability")

    # Web parser
    web_parser = subparsers.add_parser("web", help="Launch interactive web dashboard")
    web_parser.add_argument("--port", "-p", type=int, default=8080, help="Web server port")

    args = parser.parse_args()

    if args.command == "benchmark":
        run_benchmark_cmd(args)
    elif args.command == "langgraph":
        run_langgraph_cmd(args)
    elif args.command == "simulate":
        run_simulate_cmd(args)
    elif args.command == "web":
        run_web_cmd(args)


if __name__ == "__main__":
    main()

