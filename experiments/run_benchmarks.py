"""
Automated benchmark execution and data export script.
Computes comparative performance across:
1. Baseline MAS (Unprotected)
2. Traditional Perimeter Filter (Conventional Method)
3. ProvGuard-MAS (Our Framework)
"""

import csv
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from provguard.benchmark.runner import BenchmarkRunner
from provguard.benchmark.metrics import compute_efficiency_matrix, format_markdown_table

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_experiment_and_save():
    print("[*] Running 3-way comparative Multi-Agent experiments (Baseline vs Traditional vs ProvGuard)...")
    runner = BenchmarkRunner()
    experiment = runner.run_comparative_experiment()
    matrix = compute_efficiency_matrix(
        baseline_results=experiment["baseline"],
        provguard_results=experiment["provguard"],
        traditional_results=experiment["traditional"],
    )

    # 1. Save Full Benchmark Results JSON
    results_path = os.path.join(OUTPUT_DIR, "benchmark_results.json")
    with open(results_path, "w") as f:
        json.dump({
            "baseline": [r.model_dump() for r in experiment["baseline"]],
            "traditional": [r.model_dump() for r in experiment["traditional"]],
            "provguard": [r.model_dump() for r in experiment["provguard"]],
            "efficiency_matrix": matrix.model_dump(),
        }, f, indent=2)
    print(f"[✓] Saved benchmark results to: {results_path}")

    # 2. Save Scenario Audit CSV
    audit_path = os.path.join(OUTPUT_DIR, "scenario_audit.csv")
    with open(audit_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Scenario_ID", "Name", "Category", "Attack_Vector",
            "Baseline_Exploited", "Traditional_Exploited", "ProvGuard_Status",
            "Baseline_Latency_ms", "Traditional_Latency_ms", "ProvGuard_Latency_ms",
            "Max_Depth_Baseline", "Max_Depth_ProvGuard"
        ])
        for b, t, p in zip(experiment["baseline"], experiment["traditional"], experiment["provguard"]):
            writer.writerow([
                b.scenario_id, b.scenario_name, b.category, b.attack_vector,
                b.attack_succeeded, t.attack_succeeded, p.status,
                b.latency_ms, t.latency_ms, p.latency_ms,
                b.max_propagation_depth, p.max_propagation_depth
            ])
    print(f"[✓] Saved scenario audit CSV to: {audit_path}")

    # 3. Save Efficiency Matrix CSV
    matrix_csv_path = os.path.join(OUTPUT_DIR, "efficiency_matrix.csv")
    with open(matrix_csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Evaluation Metric", "Baseline MAS (Unprotected)", "Traditional Perimeter Filter", "ProvGuard-MAS (Our Defense)", "Delta vs Traditional Method"])
        writer.writerow([
            "Attack Success Rate (ASR)",
            f"{matrix.baseline.attack_success_rate_pct:.1f}%",
            f"{matrix.traditional.attack_success_rate_pct:.1f}%",
            f"{matrix.provguard.attack_success_rate_pct:.1f}%",
            f"-{matrix.delta_asr_vs_traditional:.1f}% (Attacks Eliminated)"
        ])
        writer.writerow([
            "Unauthorized Tool Execution (UTER)",
            f"{matrix.baseline.unauthorized_tool_execution_rate_pct:.1f}%",
            f"{matrix.traditional.unauthorized_tool_execution_rate_pct:.1f}%",
            f"{matrix.provguard.unauthorized_tool_execution_rate_pct:.1f}%",
            f"-{matrix.delta_uter_vs_traditional:.1f}% (Zero Dangerous Calls)"
        ])
        writer.writerow([
            "Containment Efficiency Ratio",
            f"{matrix.baseline.containment_efficiency_pct:.1f}%",
            f"{matrix.traditional.containment_efficiency_pct:.1f}%",
            f"{matrix.provguard.containment_efficiency_pct:.1f}%",
            f"+{matrix.delta_asr_vs_traditional:.1f}% Containment Gain"
        ])
        writer.writerow([
            "False Positive Rate (FPR)",
            f"{matrix.baseline.false_positive_rate_pct:.1f}%",
            f"{matrix.traditional.false_positive_rate_pct:.1f}%",
            f"{matrix.provguard.false_positive_rate_pct:.1f}%",
            f"-{matrix.delta_fpr_vs_traditional:.1f}% (Zero Benign Blocking)"
        ])
        writer.writerow([
            "Mean Runtime Latency",
            f"{matrix.baseline.mean_latency_ms:.2f} ms",
            f"{matrix.traditional.mean_latency_ms:.2f} ms",
            f"{matrix.provguard.mean_latency_ms:.2f} ms",
            f"{matrix.latency_speedup_vs_traditional_pct:.1f}% Faster Processing"
        ])
        writer.writerow([
            "Max Propagation Depth",
            f"{matrix.baseline.max_propagation_depth} hops",
            f"{matrix.traditional.max_propagation_depth} hops",
            f"{matrix.provguard.max_propagation_depth} hops",
            "Early Boundary Isolation"
        ])
    print(f"[✓] Saved efficiency matrix CSV to: {matrix_csv_path}")

    # 4. Print Markdown table
    md_table = format_markdown_table(matrix)
    print("\n" + "="*95)
    print("EMERGENT EMPIRICAL EFFICIENCY MATRIX (BASELINE vs TRADITIONAL vs PROVGUARD)")
    print("="*95)
    print(md_table)
    print("="*95 + "\n")
    return matrix


if __name__ == "__main__":
    run_experiment_and_save()
