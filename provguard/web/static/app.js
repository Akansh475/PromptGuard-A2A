/**
 * ProvGuard-MAS Frontend Application Logic
 */

document.addEventListener("DOMContentLoaded", async () => {
    let scenarios = [];
    const scenarioSelect = document.getElementById("scenarioSelect");
    const scenarioName = document.getElementById("scenarioName");
    const scenarioCategoryBadge = document.getElementById("scenarioCategoryBadge");
    const scenarioDesc = document.getElementById("scenarioDesc");
    const scenarioPromptSnippet = document.getElementById("scenarioPromptSnippet");
    const defenseToggle = document.getElementById("defenseToggle");
    const btnRunSimulation = document.getElementById("btnRunSimulation");
    const btnRunFullBenchmark = document.getElementById("btnRunFullBenchmark");
    const simResultBanner = document.getElementById("simResultBanner");
    const bannerTitle = document.getElementById("bannerTitle");
    const bannerBody = document.getElementById("bannerBody");
    const logStream = document.getElementById("logStream");

    // Load available scenarios
    try {
        const resp = await fetch("/api/scenarios");
        scenarios = await resp.json();
        populateScenarioSelect(scenarios);
        if (scenarios.length > 0) {
            updateScenarioDetails(scenarios[0]);
        }
    } catch (e) {
        console.error("Failed to load scenarios:", e);
    }

    function populateScenarioSelect(list) {
        scenarioSelect.innerHTML = "";
        list.forEach(s => {
            const opt = document.createElement("option");
            opt.value = s.scenario_id;
            const prefix = s.category === "ADVERSARIAL" ? "⚔️ [ATTACK]" : "✅ [BENIGN]";
            opt.textContent = `${prefix} ${s.scenario_id}: ${s.name}`;
            scenarioSelect.appendChild(opt);
        });
    }

    scenarioSelect.addEventListener("change", (e) => {
        const selected = scenarios.find(s => s.scenario_id === e.target.value);
        if (selected) {
            updateScenarioDetails(selected);
        }
    });

    function updateScenarioDetails(s) {
        scenarioName.textContent = `${s.scenario_id}: ${s.name}`;
        scenarioCategoryBadge.textContent = s.category;
        scenarioCategoryBadge.className = `badge ${s.category === "ADVERSARIAL" ? "badge-danger" : "badge-success"}`;
        scenarioDesc.textContent = s.description;

        let preview = `User Prompt: ${s.user_prompt}`;
        if (Object.keys(s.mock_retrieval_data).length > 0) {
            const firstKey = Object.keys(s.mock_retrieval_data)[0];
            preview += `\n\nExternal Ingestion:\n${s.mock_retrieval_data[firstKey]}`;
        }
        scenarioPromptSnippet.textContent = preview;
    }

    // Run Single Simulation
    btnRunSimulation.addEventListener("click", async () => {
        const scenarioId = scenarioSelect.value;
        const enableDefense = defenseToggle.checked;

        appendLog(`[Simulation Started] Running scenario '${scenarioId}' (Defense: ${enableDefense ? "ENABLED" : "DISABLED"})...`, "info");

        // Animate DAG
        highlightDAGFlow(enableDefense);

        try {
            const resp = await fetch("/api/simulate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scenario_id: scenarioId, enable_defense: enableDefense })
            });
            const data = await resp.json();
            renderSimulationResult(data.result, data.scenario);
        } catch (e) {
            appendLog(`[Error] Simulation request failed: ${e.message}`, "danger");
        }
    });

    // Run Full Comparative Benchmark
    btnRunFullBenchmark.addEventListener("click", async () => {
        appendLog("[Benchmark] Starting full comparative benchmark run across all 10 scenarios...", "info");
        btnRunFullBenchmark.disabled = true;
        btnRunFullBenchmark.textContent = "⏳ Running Benchmark...";

        try {
            const resp = await fetch("/api/benchmark");
            const data = await resp.json();
            renderBenchmarkMetrics(data.efficiency_matrix);
            appendLog("[Benchmark Complete] Matrix metrics updated successfully.", "success");
        } catch (e) {
            appendLog(`[Benchmark Failed]: ${e.message}`, "danger");
        } finally {
            btnRunFullBenchmark.disabled = false;
            btnRunFullBenchmark.textContent = "⚡ Run Full Benchmark Suite";
        }
    });

    function renderSimulationResult(res, scn) {
        simResultBanner.style.display = "block";
        if (res.attack_succeeded) {
            simResultBanner.className = "sim-result-banner danger";
            bannerTitle.textContent = "⚠️ ATTACK SUCCEEDED — Unauthorized Tool Executed!";
            bannerBody.textContent = `Scenario: ${res.scenario_name}. Baseline system allowed indirect prompt injection to trigger privileged capability without provenance verification. Execution Latency: ${res.latency_ms}ms.`;
            appendLog(`[EXPLOIT DETECTED] Dangerous tool executed at tool_executor_01!`, "danger");
            document.getElementById("nodeExecutor").className = "agent-node blocked";
        } else if (res.status === "BLOCKED" || res.status === "QUARANTINED") {
            simResultBanner.className = "sim-result-banner success";
            bannerTitle.textContent = `🛡️ THREAT CONTAINED — Defense Action: ${res.status}`;
            bannerBody.textContent = `ProvGuard intercepted untrusted lineage and blocked unauthorized tool execution. Max Depth Contained: ${res.max_propagation_depth} hops. Latency: ${res.latency_ms}ms.`;
            appendLog(`[DEFENSE INTERVENTION] Message intercepted & quarantined before downstream execution. Actions: ${res.defense_actions_taken.join(", ")}`, "success");
            document.getElementById("nodeExecutor").className = "agent-node";
        } else {
            simResultBanner.className = "sim-result-banner success";
            bannerTitle.textContent = "✅ BENIGN WORKFLOW COMPLETED";
            bannerBody.textContent = `Workflow executed successfully without false positives. Total Messages: ${res.total_messages}, Latency: ${res.latency_ms}ms.`;
            appendLog(`[BENIGN COMPLETED] Authorized workflow processed cleanly.`, "success");
            document.getElementById("nodeExecutor").className = "agent-node";
        }
    }

    function renderBenchmarkMetrics(matrix) {
        document.getElementById("metricAsr").textContent = `${matrix.provguard.attack_success_rate_pct.toFixed(1)}%`;
        document.getElementById("baseAsr").textContent = `vs ${matrix.baseline.attack_success_rate_pct.toFixed(1)}% Base`;

        document.getElementById("metricUter").textContent = `${matrix.provguard.unauthorized_tool_execution_rate_pct.toFixed(1)}%`;
        document.getElementById("baseUter").textContent = `vs ${matrix.baseline.unauthorized_tool_execution_rate_pct.toFixed(1)}% Base`;

        document.getElementById("metricFpr").textContent = `${matrix.provguard.false_positive_rate_pct.toFixed(1)}%`;
        document.getElementById("metricLatency").textContent = `${matrix.provguard.mean_latency_ms.toFixed(2)} ms`;
    }

    function highlightDAGFlow(defenseActive) {
        const nodes = ["nodeUserProxy", "nodePlanner", "nodeRetrieval", "nodeSummarizer", "nodeExecutor"];
        nodes.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.className = "agent-node active";
        });
        setTimeout(() => {
            nodes.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.className = "agent-node";
            });
        }, 1200);
    }

    function appendLog(msg, type = "info") {
        const entry = document.createElement("div");
        entry.className = `log-entry ${type}`;
        const timeStr = new Date().toLocaleTimeString();
        entry.textContent = `[${timeStr}] ${msg}`;
        logStream.appendChild(entry);
        logStream.scrollTop = logStream.scrollHeight;
    }
});
