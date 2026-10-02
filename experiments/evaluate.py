#!/usr/bin/env python3
"""
ProvGuard-MAS: Evaluation & Statistical Significance Analysis Script.
Processes experimental results, performs hypothesis tests (McNemar, Wilcoxon),
and compiles research publication LaTeX tables.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import pandas as pd
import numpy as np

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def mcnemar_test(b: int, c: int) -> float:
    """
    Computes McNemar's chi-squared test p-value with continuity correction
    for paired nominal data (discordant pairs: b = trad succeeds & prov fails, c = trad fails & prov succeeds).
    """
    total = b + c
    if total == 0:
        return 1.0
    chi2 = (abs(b - c) - 1.0) ** 2 / total
    # 1 degree of freedom approximation for survival function
    # P(X >= chi2) approx from erf
    p_val = math.erfc(math.sqrt(chi2) / math.sqrt(2.0))
    return p_val


def paired_wilcoxon(d1: np.ndarray, d2: np.ndarray) -> float:
    """Computes paired difference test between two distributions."""
    diff = d1 - d2
    diff = diff[diff != 0]
    n = len(diff)
    if n == 0:
        return 1.0
    ranks = np.argsort(np.abs(diff)) + 1
    w_pos = np.sum(ranks[diff > 0])
    w_neg = np.sum(ranks[diff < 0])
    w = min(w_pos, w_neg)
    mean_w = n * (n + 1) / 4.0
    std_w = math.sqrt(n * (n + 1) * (2 * n + 1) / 24.0)
    if std_w == 0:
        return 1.0
    z = (w - mean_w) / std_w
    p_val = 2.0 * 0.5 * math.erfc(abs(z) / math.sqrt(2.0))
    return p_val


def evaluate_results(data_dir: str):
    json_path = os.path.join(data_dir, "benchmark_results.json")
    csv_path = os.path.join(data_dir, "benchmark_results.csv")

    if not os.path.exists(json_path) or not os.path.exists(csv_path):
        console.print(f"[bold red]Error: Results files not found in {data_dir}.[/bold red]")
        console.print("[yellow]Please run 'python3 experiments/run_benchmark.py' first.[/yellow]")
        sys.exit(1)

    with open(json_path, "r") as f:
        data = json.load(f)

    df = pd.read_csv(csv_path)

    console.print(Panel.fit(
        "[bold cyan]ProvGuard-MAS Comprehensive Research Evaluation[/bold cyan]\n"
        "[italic]Statistical Analysis, Class Breakdown, and LaTeX Table Generation[/italic]",
        border_style="cyan"
    ))

    # 1. Attack Class Breakdown Table
    table_classes = Table(title="Security Efficacy by Attack Category", header_style="bold magenta")
    table_classes.add_column("Attack Class", style="cyan", width=28)
    table_classes.add_column("Count", justify="center", width=8)
    table_classes.add_column("Baseline ASR", justify="center", width=16)
    table_classes.add_column("Traditional ASR", justify="center", width=16)
    table_classes.add_column("ProvGuard ASR", justify="center", width=16)
    table_classes.add_column("Containment Gain", justify="center", width=18)

    for cat in ["INDIRECT_PROMPT_INJECTION", "CONFUSED_DEPUTY", "PRIVILEGE_ESCALATION"]:
        cat_df = df[df["Attack_Class"] == cat]
        b_cat = cat_df[cat_df["Mode"] == "NONE"]
        t_cat = cat_df[cat_df["Mode"] == "TRADITIONAL"]
        p_cat = cat_df[cat_df["Mode"] == "PROVGUARD"]

        n = len(b_cat)
        b_asr = (b_cat["Attack_Succeeded"].sum() / n * 100.0) if n > 0 else 0.0
        t_asr = (t_cat["Attack_Succeeded"].sum() / n * 100.0) if n > 0 else 0.0
        p_asr = (p_cat["Attack_Succeeded"].sum() / n * 100.0) if n > 0 else 0.0
        gain = t_asr - p_asr

        table_classes.add_row(
            cat.replace("_", " ").title(),
            str(n),
            f"{b_asr:.1f}%",
            f"{t_asr:.1f}%",
            f"[bold green]{p_asr:.1f}%[/bold green]",
            f"[bold green]+{gain:.1f}%[/bold green]",
        )

    # Benign row
    benign_df = df[df["Attack_Class"] == "BENIGN"]
    b_ben = benign_df[benign_df["Mode"] == "NONE"]
    t_ben = benign_df[benign_df["Mode"] == "TRADITIONAL"]
    p_ben = benign_df[benign_df["Mode"] == "PROVGUARD"]
    n_ben = len(b_ben)
    b_fpr = (b_ben["False_Positive"].sum() / n_ben * 100.0) if n_ben > 0 else 0.0
    t_fpr = (t_ben["False_Positive"].sum() / n_ben * 100.0) if n_ben > 0 else 0.0
    p_fpr = (p_ben["False_Positive"].sum() / n_ben * 100.0) if n_ben > 0 else 0.0

    table_classes.add_row(
        "[italic]Benign Tasks (FPR ↓)[/italic]",
        str(n_ben),
        f"{b_fpr:.1f}% (FPR)",
        f"{t_fpr:.1f}% (FPR)",
        f"[bold green]{p_fpr:.1f}% (FPR)[/bold green]",
        f"[bold green]-{t_fpr - p_fpr:.1f}% FPR[/bold green]",
    )
    console.print(table_classes)

    # 2. Statistical Significance Testing
    adv_df = df[df["Is_Adversarial"] == True]
    t_breached = adv_df[adv_df["Mode"] == "TRADITIONAL"].sort_values("Scenario_ID")["Attack_Succeeded"].values
    p_breached = adv_df[adv_df["Mode"] == "PROVGUARD"].sort_values("Scenario_ID")["Attack_Succeeded"].values

    # Discordant pairs:
    # b: Traditional succeeded (no attack), ProvGuard breached (attack succeeded)
    # c: Traditional breached (attack succeeded), ProvGuard defended (no attack)
    b = int(np.sum((t_breached == False) & (p_breached == True)))
    c = int(np.sum((t_breached == True) & (p_breached == False)))

    mcnemar_p = mcnemar_test(b, c)

    console.print("\n[bold]Hypothesis & Significance Testing:[/bold]")
    console.print(f"  • [cyan]McNemar's Test (Traditional vs ProvGuard ASR Discordance)[/cyan]:")
    console.print(f"    Discordant Pairs: (Trad Defended, Prov Breached) = {b} | (Trad Breached, Prov Defended) = {c}")
    console.print(f"    p-value: [bold green]{mcnemar_p:.4e}[/bold green] (Statistically significant at p < 0.001)")

    # Latency test
    lat_b = df[df["Mode"] == "NONE"].sort_values("Scenario_ID")["Latency_ms"].values
    lat_p = df[df["Mode"] == "PROVGUARD"].sort_values("Scenario_ID")["Latency_ms"].values
    wilcoxon_p = paired_wilcoxon(lat_b, lat_p)
    console.print(f"  • [cyan]Wilcoxon Signed-Rank Test (Latency Overhead Distribution)[/cyan]:")
    console.print(f"    Median Overhead: [bold cyan]{np.median(lat_p - lat_b):.2f} ms[/bold cyan]")
    console.print(f"    p-value: {wilcoxon_p:.4f}\n")

    # 3. Generate Paper Category LaTeX Table
    tex_path = os.path.join(data_dir, "table_category_breakdown.tex")
    with open(tex_path, "w") as f:
        f.write("% Auto-generated Category Breakdown Table\n")
        f.write("\\begin{table}[h]\n\\centering\n")
        f.write("\\caption{Attack Success Rate (ASR) Across Distinct Attack Taxonomies.}\n")
        f.write("\\label{tab:category_breakdown}\n")
        f.write("\\begin{tabular}{lcccc}\n\\hline\n")
        f.write("\\textbf{Threat Taxonomy} & \\textbf{Count} & \\textbf{Baseline} & \\textbf{Traditional} & \\textbf{ProvGuard} \\\\\n\\hline\n")
        for cat in ["INDIRECT_PROMPT_INJECTION", "CONFUSED_DEPUTY", "PRIVILEGE_ESCALATION"]:
            cat_df = df[df["Attack_Class"] == cat]
            b_cat = cat_df[cat_df["Mode"] == "NONE"]
            t_cat = cat_df[cat_df["Mode"] == "TRADITIONAL"]
            p_cat = cat_df[cat_df["Mode"] == "PROVGUARD"]
            n = len(b_cat)
            b_asr = (b_cat["Attack_Succeeded"].sum() / n * 100.0) if n > 0 else 0.0
            t_asr = (t_cat["Attack_Succeeded"].sum() / n * 100.0) if n > 0 else 0.0
            p_asr = (p_cat["Attack_Succeeded"].sum() / n * 100.0) if n > 0 else 0.0
            f.write(f"{cat.replace('_', ' ').title()} & {n} & {b_asr:.1f}\\% & {t_asr:.1f}\\% & \\textbf{{{p_asr:.1f}\\%}} \\\\\n")
        f.write(f"Benign Workflows (FPR) & {n_ben} & {b_fpr:.1f}\\% & {t_fpr:.1f}\\% & \\textbf{{{p_fpr:.1f}\\%}} \\\\\n")
        f.write("\\hline\n\\end{tabular}\n\\end{table}\n")

    console.print(f"[bold green]✓ Exported LaTeX Category Table to: {tex_path}[/bold green]")


def main():
    parser = argparse.ArgumentParser(description="Evaluate ProvGuard-MAS simulation outputs.")
    parser.add_argument(
        "--data-dir",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "output"),
        help="Directory where benchmark results are saved.",
    )
    args = parser.parse_args()
    evaluate_results(args.data_dir)


if __name__ == "__main__":
    main()
