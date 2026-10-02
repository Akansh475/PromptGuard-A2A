"""
Lightweight embedded HTTP server serving the ProvGuard Web Dashboard and REST API.
Enhanced with Mustang Theme support, 150-scenario benchmark catalog, and live telemetry.
"""

from __future__ import annotations

import json
import logging
import os
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Any, Dict, List

from provguard.benchmark.runner import BenchmarkRunner
from provguard.benchmark.scenarios import get_standard_benchmark_suite, Scenario
from provguard.benchmark.metrics import compute_efficiency_matrix
from provguard.simulation.scenarios import get_all_benchmark_scenarios, BenchmarkScenario
from provguard.simulation.workflow import execute_simulation_task

logger = logging.getLogger("provguard.web.server")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "experiments", "output")


def _serialize_item(obj: Any) -> Any:
    """Recursively serializes Pydantic models, dicts, lists, and enums."""
    if hasattr(obj, "model_dump"):
        return _serialize_item(obj.model_dump())
    elif hasattr(obj, "dict"):
        return _serialize_item(obj.dict())
    elif isinstance(obj, dict):
        return {k: _serialize_item(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [_serialize_item(x) for x in obj]
    elif hasattr(obj, "value"):
        return obj.value
    return obj


class ProvGuardAPIHandler(BaseHTTPRequestHandler):
    """Handles REST API queries and serves static web dashboard assets."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_static_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
        elif path.startswith("/static/"):
            filename = path.replace("/static/", "")
            filepath = os.path.join(STATIC_DIR, filename)
            mime, _ = mimetypes.guess_type(filepath)
            self._serve_static_file(filepath, mime or "application/octet-stream")
        elif path == "/api/scenarios":
            # Return both simulation catalog and standard scenarios
            all_scenarios = get_all_benchmark_scenarios()
            category_filter = query.get("category", [None])[0]

            data = []
            for s in all_scenarios:
                if category_filter and s.attack_class != category_filter:
                    continue
                data.append({
                    "scenario_id": s.scenario_id,
                    "name": s.name,
                    "category": "ADVERSARIAL" if s.is_adversarial else "BENIGN",
                    "attack_class": s.attack_class,
                    "description": s.description,
                    "user_prompt": s.user_prompt,
                    "mock_retrieval_data": s.mock_retrieval_data,
                    "target_tool": s.target_tool_capability,
                })
            self._send_json(data)
        elif path == "/api/benchmark":
            results_json_path = os.path.join(OUTPUT_DIR, "benchmark_results.json")
            if os.path.exists(results_json_path):
                with open(results_json_path, "r") as f:
                    self._send_json(json.load(f))
            else:
                # Fallback to standard runner benchmark
                runner = BenchmarkRunner()
                experiment = runner.run_comparative_experiment()
                matrix = compute_efficiency_matrix(experiment["baseline"], experiment["provguard"])
                self._send_json({
                    "baseline_results": [r.model_dump() for r in experiment["baseline"]],
                    "provguard_results": [r.model_dump() for r in experiment["provguard"]],
                    "efficiency_matrix": matrix.model_dump(),
                })
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/simulate":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")
            data = json.loads(body) if body else {}

            scenario_id = data.get("scenario_id", "ADV_001")
            defense_mode = data.get("defense_mode")
            if not defense_mode:
                enable_defense = data.get("enable_defense", True)
                defense_mode = "PROVGUARD" if enable_defense else "NONE"
            custom_prompt = data.get("custom_prompt")

            # Look up in 150-scenario catalog first
            catalog = get_all_benchmark_scenarios()
            matched_sim = next((s for s in catalog if s.scenario_id == scenario_id), None)
            if not matched_sim:
                matched_sim = next((s for s in catalog if s.scenario_id.replace("0", "") == scenario_id.replace("0", "")), None)
            if not matched_sim:
                std_suite = get_standard_benchmark_suite()
                matched_std = next((s for s in std_suite if s.scenario_id == scenario_id), None)
                if matched_std:
                    matched_sim = BenchmarkScenario(
                        scenario_id=matched_std.scenario_id,
                        name=matched_std.name,
                        attack_class=matched_std.category if matched_std.category != "ADVERSARIAL" else "INDIRECT_PROMPT_INJECTION",
                        is_adversarial=(matched_std.category == "ADVERSARIAL"),
                        description=matched_std.description,
                        user_prompt=matched_std.user_prompt,
                        mock_retrieval_data=matched_std.mock_retrieval_data,
                        target_tool_capability="execute_shell_command" if matched_std.expected_dangerous_tool else None,
                    )

            if matched_sim:
                res_state = execute_simulation_task(
                    user_query=matched_sim.user_prompt,
                    scenario_id=matched_sim.scenario_id,
                    defense_mode=defense_mode,
                    is_adversarial=matched_sim.is_adversarial,
                    attack_class=matched_sim.attack_class,
                    target_tool_capability=matched_sim.target_tool_capability,
                    mock_data_store=matched_sim.mock_retrieval_data,
                )
                self._send_json({
                    "scenario": {
                        "scenario_id": matched_sim.scenario_id,
                        "name": matched_sim.name,
                        "category": "ADVERSARIAL" if matched_sim.is_adversarial else "BENIGN",
                        "attack_class": matched_sim.attack_class,
                        "description": matched_sim.description,
                        "user_prompt": matched_sim.user_prompt,
                        "target_tool": matched_sim.target_tool_capability,
                        "mock_retrieval_data": matched_sim.mock_retrieval_data,
                    },
                    "result": {
                        "scenario_id": res_state.get("scenario_id", scenario_id),
                        "status": res_state.get("status"),
                        "defense_mode": defense_mode,
                        "is_contained": res_state.get("is_contained", False),
                        "containment_node": res_state.get("containment_node"),
                        "attack_succeeded": res_state.get("attack_succeeded", False),
                        "unauthorized_tool_executed": res_state.get("unauthorized_tool_executed", False),
                        "false_positive": res_state.get("false_positive", False),
                        "latency_ms": res_state.get("execution_latency_ms", 0.0),
                        "provenance_overhead_ms": res_state.get("provenance_overhead_ms", 0.0),
                        "max_propagation_depth": res_state.get("max_propagation_depth", 0),
                        "defense_actions_taken": res_state.get("defense_actions_taken", []),
                        "risk_scores": res_state.get("risk_scores", []),
                        "messages_count": len(res_state.get("messages", [])),
                        "provenance_count": len(res_state.get("provenance_records", [])),
                        "tool_call": _serialize_item(res_state.get("tool_call_request")),
                        "tool_execution": _serialize_item(res_state.get("tool_execution_result")),
                        "evaluations": _serialize_item(res_state.get("evaluations", [])),
                        "messages": _serialize_item(res_state.get("messages", [])),
                        "provenance_records": _serialize_item(res_state.get("provenance_records", [])),
                    }
                })
                return

            # Custom or fallback scenario
            prompt = custom_prompt or "research: Custom Injection"
            is_adv = any(k in prompt.lower() for k in ["rm -rf", "chmod", "drop table", "system override", "cat /etc/shadow"])
            res_state = execute_simulation_task(
                user_query=prompt,
                scenario_id="CUSTOM_01",
                defense_mode=defense_mode,
                is_adversarial=is_adv,
                attack_class="CUSTOM_TEST",
                mock_data_store={"Custom": prompt},
            )
            self._send_json({
                "scenario": {
                    "scenario_id": "CUSTOM_01",
                    "name": "Custom User Scenario",
                    "category": "ADVERSARIAL" if is_adv else "BENIGN",
                    "attack_class": "CUSTOM",
                    "description": "User-defined interactive execution prompt",
                    "user_prompt": prompt,
                    "target_tool": "execute_shell_command" if is_adv else None,
                    "mock_retrieval_data": {"Custom": prompt},
                },
                "result": {
                    "scenario_id": "CUSTOM_01",
                    "status": res_state.get("status"),
                    "defense_mode": defense_mode,
                    "is_contained": res_state.get("is_contained", False),
                    "containment_node": res_state.get("containment_node"),
                    "attack_succeeded": res_state.get("attack_succeeded", False),
                    "unauthorized_tool_executed": res_state.get("unauthorized_tool_executed", False),
                    "false_positive": res_state.get("false_positive", False),
                    "latency_ms": res_state.get("execution_latency_ms", 0.0),
                    "provenance_overhead_ms": res_state.get("provenance_overhead_ms", 0.0),
                    "max_propagation_depth": res_state.get("max_propagation_depth", 0),
                    "defense_actions_taken": res_state.get("defense_actions_taken", []),
                    "risk_scores": res_state.get("risk_scores", []),
                    "messages_count": len(res_state.get("messages", [])),
                    "provenance_count": len(res_state.get("provenance_records", [])),
                    "tool_call": _serialize_item(res_state.get("tool_call_request")),
                    "tool_execution": _serialize_item(res_state.get("tool_execution_result")),
                    "evaluations": _serialize_item(res_state.get("evaluations", [])),
                    "messages": _serialize_item(res_state.get("messages", [])),
                    "provenance_records": _serialize_item(res_state.get("provenance_records", [])),
                }
            })
        else:
            self.send_error(404, "Endpoint Not Found")

    def _serve_static_file(self, filepath: str, content_type: str) -> None:
        if not os.path.exists(filepath):
            self.send_error(404, "File Not Found")
            return
        with open(filepath, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, data: Any) -> None:
        content = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        return


def run_web_server(port: int = 8080) -> None:
    """Launches local web server."""
    server_address = ("", port)
    httpd = HTTPServer(server_address, ProvGuardAPIHandler)
    print(f"[*] ProvGuard-MAS Mustang Dashboard active at: http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        httpd.server_close()
