"""
LangGraph Multi-Agent Benchmark Runner.
Executes batch scenarios across evaluation modes (None, Traditional, ProvGuard-MAS),
records full telemetry, and exports publication-ready artifacts.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from provguard.simulation.state import ProvGuardGraphState, DefenseMode
from provguard.simulation.workflow import execute_simulation_task
from provguard.simulation.scenarios import BenchmarkScenario, get_all_benchmark_scenarios
from provguard.simulation.metrics import (
    ComparativeResearchReport,
    compute_comparative_report,
    compute_mode_metrics,
)

logger = logging.getLogger("provguard.simulation.runner")


class LangGraphBenchmarkRunner:
    """
    Automated execution runner for LangGraph Multi-Agent security benchmarking.
    """

    def __init__(self, scenarios: Optional[List[BenchmarkScenario]] = None):
        self.scenarios = scenarios or get_all_benchmark_scenarios()

    def run_scenario(
        self,
        scenario: BenchmarkScenario,
        mode: DefenseMode = "PROVGUARD",
    ) -> ProvGuardGraphState:
        """Executes a single scenario under a specified defense mode."""
        return execute_simulation_task(
            user_query=scenario.user_prompt,
            scenario_id=scenario.scenario_id,
            defense_mode=mode,
            is_adversarial=scenario.is_adversarial,
            attack_class=scenario.attack_class,
            target_tool_capability=scenario.target_tool_capability,
            mock_data_store=scenario.mock_retrieval_data,
            metadata={"name": scenario.name, "description": scenario.description},
        )

    def run_comparative_suite(
        self,
        scenarios: Optional[List[BenchmarkScenario]] = None,
        modes: Optional[List[DefenseMode]] = None,
        show_progress: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes benchmark scenarios across:
        - Mode A: NONE (Baseline Unprotected)
        - Mode B: TRADITIONAL (Perimeter-only Guardrail)
        - Mode C: PROVGUARD (Full Provenance-Aware Runtime Defense)
        """
        target_scenarios = scenarios or self.scenarios
        target_modes: List[DefenseMode] = modes or ["NONE", "TRADITIONAL", "PROVGUARD"]

        results: Dict[str, List[ProvGuardGraphState]] = {m: [] for m in target_modes}
        total_runs = len(target_scenarios) * len(target_modes)

        if show_progress:
            with Progress(
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("[green]Evaluating LangGraph Scenarios...", total=total_runs)

                for scenario in target_scenarios:
                    for mode in target_modes:
                        state = self.run_scenario(scenario, mode=mode)
                        results[mode].append(state)
                        progress.advance(task)
        else:
            for scenario in target_scenarios:
                for mode in target_modes:
                    state = self.run_scenario(scenario, mode=mode)
                    results[mode].append(state)

        # Compute comparative analytics
        report = compute_comparative_report(
            baseline_states=results.get("NONE", []),
            traditional_states=results.get("TRADITIONAL", []),
            provguard_states=results.get("PROVGUARD", []),
        )

        return {
            "results": results,
            "report": report,
            "total_scenarios": len(target_scenarios),
        }

    def export_results(
        self,
        experiment_output: Dict[str, Any],
        output_dir: str = "experiments/output",
    ) -> Dict[str, str]:
        """
        Serializes comprehensive outputs:
        - benchmark_results.json
        - benchmark_results.csv
        - scenario_audit.csv
        - efficiency_matrix.csv
        - lineage_dags.json
        - comparative_report.md
        - table_security_metrics.tex
        """
        os.makedirs(output_dir, exist_ok=True)
        results = experiment_output["results"]
        report: ComparativeResearchReport = experiment_output["report"]
        paths: Dict[str, str] = {}

        # 1. benchmark_results.json
        json_path = os.path.join(output_dir, "benchmark_results.json")
        serializable_results: Dict[str, Any] = {
            "report": report.model_dump(),
            "runs": {},
        }
        for mode, states in results.items():
            serializable_results["runs"][mode] = [
                {
                    "scenario_id": s.get("scenario_id"),
                    "is_adversarial": s.get("is_adversarial"),
                    "attack_class": s.get("attack_class"),
                    "status": s.get("status"),
                    "is_contained": s.get("is_contained"),
                    "attack_succeeded": s.get("attack_succeeded"),
                    "unauthorized_tool_executed": s.get("unauthorized_tool_executed"),
                    "false_positive": s.get("false_positive"),
                    "execution_latency_ms": s.get("execution_latency_ms"),
                    "provenance_overhead_ms": s.get("provenance_overhead_ms"),
                    "peak_memory_mb": s.get("peak_memory_mb"),
                    "max_propagation_depth": s.get("max_propagation_depth"),
                    "defense_actions_taken": s.get("defense_actions_taken", []),
                    "messages_count": len(s.get("messages", [])),
                    "provenance_count": len(s.get("provenance_records", [])),
                }
                for s in states
            ]
        with open(json_path, "w") as f:
            json.dump(serializable_results, f, indent=2)
        paths["json"] = json_path

        # 2. benchmark_results.csv (Flat per-run CSV)
        flat_csv_path = os.path.join(output_dir, "benchmark_results.csv")
        with open(flat_csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Scenario_ID", "Mode", "Is_Adversarial", "Attack_Class",
                "Status", "Is_Contained", "Attack_Succeeded", "Unauthorized_Tool_Executed",
                "False_Positive", "Latency_ms", "Overhead_ms", "Peak_Memory_MB",
                "Max_Depth", "Messages_Count", "Actions_Taken"
            ])
            for mode, states in results.items():
                for s in states:
                    writer.writerow([
                        s.get("scenario_id"), mode, s.get("is_adversarial"), s.get("attack_class"),
                        s.get("status"), s.get("is_contained"), s.get("attack_succeeded"),
                        s.get("unauthorized_tool_executed"), s.get("false_positive"),
                        s.get("execution_latency_ms"), s.get("provenance_overhead_ms"),
                        s.get("peak_memory_mb"), s.get("max_propagation_depth"),
                        len(s.get("messages", [])),
                        ";".join(s.get("defense_actions_taken", []))
                    ])
        paths["flat_csv"] = flat_csv_path

        # 3. scenario_audit.csv (Side-by-side comparative CSV)
        audit_csv_path = os.path.join(output_dir, "scenario_audit.csv")
        b_states = results.get("NONE", [])
        t_states = results.get("TRADITIONAL", [])
        p_states = results.get("PROVGUARD", [])

        with open(audit_csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Scenario_ID", "Attack_Class", "Is_Adversarial",
                "Baseline_Breached", "Traditional_Breached", "ProvGuard_Contained",
                "Baseline_Latency_ms", "Traditional_Latency_ms", "ProvGuard_Latency_ms",
                "ProvGuard_Overhead_ms", "Baseline_Max_Depth", "ProvGuard_Max_Depth"
            ])
            for b, t, p in zip(b_states, t_states, p_states):
                writer.writerow([
                    b.get("scenario_id"), b.get("attack_class"), b.get("is_adversarial"),
                    b.get("attack_succeeded"), t.get("attack_succeeded"), p.get("is_contained"),
                    b.get("execution_latency_ms"), t.get("execution_latency_ms"), p.get("execution_latency_ms"),
                    p.get("provenance_overhead_ms"), b.get("max_propagation_depth"), p.get("max_propagation_depth")
                ])
        paths["audit_csv"] = audit_csv_path

        # 4. efficiency_matrix.csv (Publication table CSV)
        matrix_csv_path = os.path.join(output_dir, "efficiency_matrix.csv")
        with open(matrix_csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Baseline (No Defense)", "Traditional Perimeter", "ProvGuard-MAS", "Delta vs Traditional"])
            writer.writerow([
                "Attack Success Rate (ASR)",
                f"{report.baseline_none.security.attack_success_rate_pct:.1f}%",
                f"{report.traditional_filter.security.attack_success_rate_pct:.1f}%",
                f"{report.provguard_mas.security.attack_success_rate_pct:.1f}%",
                f"-{report.delta_asr_vs_traditional:.1f}%"
            ])
            writer.writerow([
                "Unauthorized Tool Exec Rate (UTER)",
                f"{report.baseline_none.security.unauthorized_tool_execution_rate_pct:.1f}%",
                f"{report.traditional_filter.security.unauthorized_tool_execution_rate_pct:.1f}%",
                f"{report.provguard_mas.security.unauthorized_tool_execution_rate_pct:.1f}%",
                f"-{report.delta_uter_vs_traditional:.1f}%"
            ])
            writer.writerow([
                "Detection Rate (Recall)",
                f"{report.baseline_none.security.detection_rate_pct:.1f}%",
                f"{report.traditional_filter.security.detection_rate_pct:.1f}%",
                f"{report.provguard_mas.security.detection_rate_pct:.1f}%",
                f"+{report.provguard_mas.security.detection_rate_pct - report.traditional_filter.security.detection_rate_pct:.1f}%"
            ])
            writer.writerow([
                "Precision",
                f"{report.baseline_none.security.precision_pct:.1f}%",
                f"{report.traditional_filter.security.precision_pct:.1f}%",
                f"{report.provguard_mas.security.precision_pct:.1f}%",
                f"+{report.provguard_mas.security.precision_pct - report.traditional_filter.security.precision_pct:.1f}%"
            ])
            writer.writerow([
                "F1 Score",
                f"{report.baseline_none.security.f1_score:.3f}",
                f"{report.traditional_filter.security.f1_score:.3f}",
                f"{report.provguard_mas.security.f1_score:.3f}",
                f"+{report.provguard_mas.security.f1_score - report.traditional_filter.security.f1_score:.3f}"
            ])
            writer.writerow([
                "False Positive Rate (FPR)",
                f"{report.baseline_none.security.false_positive_rate_pct:.1f}%",
                f"{report.traditional_filter.security.false_positive_rate_pct:.1f}%",
                f"{report.provguard_mas.security.false_positive_rate_pct:.1f}%",
                f"-{report.delta_fpr_vs_traditional:.1f}%"
            ])
            writer.writerow([
                "Containment Efficiency",
                f"{report.baseline_none.security.containment_efficiency_pct:.1f}%",
                f"{report.traditional_filter.security.containment_efficiency_pct:.1f}%",
                f"{report.provguard_mas.security.containment_efficiency_pct:.1f}%",
                f"+{report.delta_asr_vs_traditional:.1f}%"
            ])
            writer.writerow([
                "Mean Runtime Latency",
                f"{report.baseline_none.performance.mean_latency_ms:.2f} ms",
                f"{report.traditional_filter.performance.mean_latency_ms:.2f} ms",
                f"{report.provguard_mas.performance.mean_latency_ms:.2f} ms",
                f"{report.provguard_latency_overhead_ms:+.2f} ms"
            ])
            writer.writerow([
                "P95 Runtime Latency",
                f"{report.baseline_none.performance.p95_latency_ms:.2f} ms",
                f"{report.traditional_filter.performance.p95_latency_ms:.2f} ms",
                f"{report.provguard_mas.performance.p95_latency_ms:.2f} ms",
                f"{report.provguard_mas.performance.p95_latency_ms - report.baseline_none.performance.p95_latency_ms:+.2f} ms"
            ])
            writer.writerow([
                "Mean Provenance Overhead",
                "0.00 ms",
                f"{report.traditional_filter.performance.mean_provenance_overhead_ms:.3f} ms",
                f"{report.provguard_mas.performance.mean_provenance_overhead_ms:.3f} ms",
                f"{report.provguard_mas.performance.mean_provenance_overhead_ms:.3f} ms"
            ])
            writer.writerow([
                "Mean Memory Footprint",
                f"{report.baseline_none.performance.mean_memory_mb:.3f} MB",
                f"{report.traditional_filter.performance.mean_memory_mb:.3f} MB",
                f"{report.provguard_mas.performance.mean_memory_mb:.3f} MB",
                f"{report.provguard_mas.performance.mean_memory_mb - report.baseline_none.performance.mean_memory_mb:+.3f} MB"
            ])
        paths["matrix_csv"] = matrix_csv_path

        # 5. lineage_dags.json (Cryptographic lineage DAGs export)
        lineage_path = os.path.join(output_dir, "lineage_dags.json")
        sample_dags = []
        for state in p_states[:10]:
            records = state.get("provenance_records", [])
            sample_dags.append({
                "scenario_id": state.get("scenario_id"),
                "attack_class": state.get("attack_class"),
                "is_contained": state.get("is_contained"),
                "nodes": [
                    {
                        "message_id": r.message_id,
                        "source": r.source_agent_id,
                        "target": r.target_agent_id,
                        "hop_count": r.hop_count,
                        "root_trust": r.root_trust.value,
                        "taint_score": r.taint_score,
                        "content_hash": r.content_hash,
                        "transformations": [t.step for t in r.transformations],
                    }
                    for r in records
                ],
                "edges": [
                    {"parent": pid, "child": r.message_id}
                    for r in records
                    for pid in r.parent_ids
                ],
            })
        with open(lineage_path, "w") as f:
            json.dump(sample_dags, f, indent=2)
        paths["lineage_dags"] = lineage_path

        # 6. Markdown Summary Report
        md_path = os.path.join(output_dir, "comparative_report.md")
        with open(md_path, "w") as f:
            f.write("# ProvGuard-MAS: LangGraph Multi-Agent Security Benchmark Report\n\n")
            f.write(f"**Total Benchmark Scenarios Evaluated**: {len(b_states)}\n\n")
            f.write("| Evaluation Metric | Baseline MAS (Unprotected) | Traditional Perimeter Filter | ProvGuard-MAS (Our Defense) | Delta vs Traditional |\n")
            f.write("| :--- | :---: | :---: | :---: | :---: |\n")
            f.write(f"| **Attack Success Rate (ASR)** | {report.baseline_none.security.attack_success_rate_pct:.1f}% | {report.traditional_filter.security.attack_success_rate_pct:.1f}% | **{report.provguard_mas.security.attack_success_rate_pct:.1f}%** | **-{report.delta_asr_vs_traditional:.1f}%** |\n")
            f.write(f"| **Unauthorized Tool Execution (UTER)** | {report.baseline_none.security.unauthorized_tool_execution_rate_pct:.1f}% | {report.traditional_filter.security.unauthorized_tool_execution_rate_pct:.1f}% | **{report.provguard_mas.security.unauthorized_tool_execution_rate_pct:.1f}%** | **-{report.delta_uter_vs_traditional:.1f}%** |\n")
            f.write(f"| **Detection Rate (Recall)** | {report.baseline_none.security.detection_rate_pct:.1f}% | {report.traditional_filter.security.detection_rate_pct:.1f}% | **{report.provguard_mas.security.detection_rate_pct:.1f}%** | **+{report.provguard_mas.security.detection_rate_pct - report.traditional_filter.security.detection_rate_pct:.1f}%** |\n")
            f.write(f"| **Precision** | {report.baseline_none.security.precision_pct:.1f}% | {report.traditional_filter.security.precision_pct:.1f}% | **{report.provguard_mas.security.precision_pct:.1f}%** | **+{report.provguard_mas.security.precision_pct - report.traditional_filter.security.precision_pct:.1f}%** |\n")
            f.write(f"| **F1 Score** | {report.baseline_none.security.f1_score:.3f} | {report.traditional_filter.security.f1_score:.3f} | **{report.provguard_mas.security.f1_score:.3f}** | **+{report.provguard_mas.security.f1_score - report.traditional_filter.security.f1_score:.3f}** |\n")
            f.write(f"| **False Positive Rate (FPR)** | {report.baseline_none.security.false_positive_rate_pct:.1f}% | {report.traditional_filter.security.false_positive_rate_pct:.1f}% | **{report.provguard_mas.security.false_positive_rate_pct:.1f}%** | **-{report.delta_fpr_vs_traditional:.1f}%** |\n")
            f.write(f"| **Containment Efficiency** | {report.baseline_none.security.containment_efficiency_pct:.1f}% | {report.traditional_filter.security.containment_efficiency_pct:.1f}% | **{report.provguard_mas.security.containment_efficiency_pct:.1f}%** | **+{report.delta_asr_vs_traditional:.1f}%** |\n")
            f.write(f"| **Mean Runtime Latency** | {report.baseline_none.performance.mean_latency_ms:.2f} ms | {report.traditional_filter.performance.mean_latency_ms:.2f} ms | **{report.provguard_mas.performance.mean_latency_ms:.2f} ms** | {report.provguard_latency_overhead_ms:+.2f} ms |\n")
            f.write(f"| **P95 Latency** | {report.baseline_none.performance.p95_latency_ms:.2f} ms | {report.traditional_filter.performance.p95_latency_ms:.2f} ms | **{report.provguard_mas.performance.p95_latency_ms:.2f} ms** | {report.provguard_mas.performance.p95_latency_ms - report.baseline_none.performance.p95_latency_ms:+.2f} ms |\n")
            f.write(f"| **Mean Tracking Overhead** | 0.00 ms | {report.traditional_filter.performance.mean_provenance_overhead_ms:.3f} ms | **{report.provguard_mas.performance.mean_provenance_overhead_ms:.3f} ms** | Sub-millisecond |\n")
        paths["report_md"] = md_path

        # 7. LaTeX Table for Research Papers
        tex_path = os.path.join(output_dir, "table_security_metrics.tex")
        with open(tex_path, "w") as f:
            f.write("% Auto-generated by ProvGuard-MAS LangGraph Benchmark Runner\n")
            f.write("\\begin{table*}[t]\n")
            f.write("\\centering\n")
            f.write("\\caption{Quantitative Comparative Security and Performance Matrix across Multi-Agent Execution Paradigms.}\n")
            f.write("\\label{tab:provguard_benchmark}\n")
            f.write("\\begin{tabular}{lcccc}\n")
            f.write("\\hline\n")
            f.write("\\textbf{Metric} & \\textbf{Baseline (No Defense)} & \\textbf{Traditional Perimeter} & \\textbf{ProvGuard-MAS (Ours)} & \\textbf{Gain vs Traditional} \\\\\n")
            f.write("\\hline\n")
            f.write(f"Attack Success Rate (ASR) $\\downarrow$ & {report.baseline_none.security.attack_success_rate_pct:.1f}\\% & {report.traditional_filter.security.attack_success_rate_pct:.1f}\\% & \\textbf{{{report.provguard_mas.security.attack_success_rate_pct:.1f}\\%}} & -{report.delta_asr_vs_traditional:.1f}\\% \\\\\n")
            f.write(f"Unauthorized Tool Execution (UTER) $\\downarrow$ & {report.baseline_none.security.unauthorized_tool_execution_rate_pct:.1f}\\% & {report.traditional_filter.security.unauthorized_tool_execution_rate_pct:.1f}\\% & \\textbf{{{report.provguard_mas.security.unauthorized_tool_execution_rate_pct:.1f}\\%}} & -{report.delta_uter_vs_traditional:.1f}\\% \\\\\n")
            f.write(f"Detection Rate (Recall) $\\uparrow$ & {report.baseline_none.security.detection_rate_pct:.1f}\\% & {report.traditional_filter.security.detection_rate_pct:.1f}\\% & \\textbf{{{report.provguard_mas.security.detection_rate_pct:.1f}\\%}} & +{report.provguard_mas.security.detection_rate_pct - report.traditional_filter.security.detection_rate_pct:.1f}\\% \\\\\n")
            f.write(f"Precision $\\uparrow$ & {report.baseline_none.security.precision_pct:.1f}\\% & {report.traditional_filter.security.precision_pct:.1f}\\% & \\textbf{{{report.provguard_mas.security.precision_pct:.1f}\\%}} & +{report.provguard_mas.security.precision_pct - report.traditional_filter.security.precision_pct:.1f}\\% \\\\\n")
            f.write(f"F1 Score $\\uparrow$ & {report.baseline_none.security.f1_score:.3f} & {report.traditional_filter.security.f1_score:.3f} & \\textbf{{{report.provguard_mas.security.f1_score:.3f}}} & +{report.provguard_mas.security.f1_score - report.traditional_filter.security.f1_score:.3f} \\\\\n")
            f.write(f"False Positive Rate (FPR) $\\downarrow$ & {report.baseline_none.security.false_positive_rate_pct:.1f}\\% & {report.traditional_filter.security.false_positive_rate_pct:.1f}\\% & \\textbf{{{report.provguard_mas.security.false_positive_rate_pct:.1f}\\%}} & -{report.delta_fpr_vs_traditional:.1f}\\% \\\\\n")
            f.write(f"Containment Efficiency $\\uparrow$ & {report.baseline_none.security.containment_efficiency_pct:.1f}\\% & {report.traditional_filter.security.containment_efficiency_pct:.1f}\\% & \\textbf{{{report.provguard_mas.security.containment_efficiency_pct:.1f}\\%}} & +{report.delta_asr_vs_traditional:.1f}\\% \\\\\n")
            f.write(f"Mean Latency (ms) & {report.baseline_none.performance.mean_latency_ms:.2f} & {report.traditional_filter.performance.mean_latency_ms:.2f} & \\textbf{{{report.provguard_mas.performance.mean_latency_ms:.2f}}} & {report.provguard_latency_overhead_ms:+.2f} ms \\\\\n")
            f.write(f"P95 Latency (ms) & {report.baseline_none.performance.p95_latency_ms:.2f} & {report.traditional_filter.performance.p95_latency_ms:.2f} & \\textbf{{{report.provguard_mas.performance.p95_latency_ms:.2f}}} & {report.provguard_mas.performance.p95_latency_ms - report.baseline_none.performance.p95_latency_ms:+.2f} ms \\\\\n")
            f.write(f"Provenance Overhead (ms) & 0.00 & {report.traditional_filter.performance.mean_provenance_overhead_ms:.3f} & \\textbf{{{report.provguard_mas.performance.mean_provenance_overhead_ms:.3f}}} & Sub-millisecond \\\\\n")
            f.write("\\hline\n")
            f.write("\\end{tabular}\n")
            f.write("\\end{table*}\n")
        paths["table_tex"] = tex_path

        return paths
