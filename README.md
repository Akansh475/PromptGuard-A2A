# PromptGuard-A2A

<!-- One-line description + language/framework badges -->
A modular Python library for security benchmarking, defense mechanisms, and provenance analysis in agent-based systems.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![CLI](https://img.shields.io/badge/CLI-supported-green?logo=terminal)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-scikit--learn%2C%20pandas-yellow?logo=scikit-learn)

## Overview

PromptGuard-A2A provides a robust framework for evaluating and defending agent-based workflows against security risks. It features modular components for agents, benchmarking, defense, and evaluation, integrated with command-line tools and visualization utilities. The library supports advanced provenance and lineage analysis, offers extensibility for custom agent logic, and leverages machine learning libraries for data-driven reporting.

## Tech Stack

- **Languages:** Python, CSS, HTML, JavaScript, TeX
- **Frameworks/Libraries:**
  - pydantic
  - rich
  - matplotlib
  - pandas
  - numpy
  - seaborn
  - langgraph
  - scikit-learn
  - joblib
  - pytest (for testing)

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Recommended: virtualenv for isolated environments

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Akansh475/PromptGuard-A2A.git
   cd PromptGuard-A2A
   ```

2. **Install dependencies:**
   ```bash
   pip install pydantic rich matplotlib pandas numpy seaborn langgraph scikit-learn joblib pytest
   ```

## Usage

1. **Interact via CLI:**
   ```bash
   python -m provguard.cli
   ```

2. **Run benchmarks:**
   ```bash
   python experiments/run_benchmarks.py
   ```

3. **Generate visual reports:**
   ```bash
   python experiments/generate_figures.py
   ```

4. **Apply defense mechanisms:**
   - Utilize modules in `provguard/defense/` (e.g., `circuit_breaker.py`, `quarantine.py`) within your workflow.

5. **Extend agents:**
   - Customize or add agent logic in `provguard/agents/` for specialized planning, execution, retrieval, and summarization.

## Project Structure

```
PromptGuard-A2A/
├── .gitignore
├── README.md
├── docs/
│   ├── ABSTRACT_AND_REPORT.md
│   └── ARCHITECTURE.md
├── experiments/
│   ├── evaluate.py
│   ├── generate_figures.py
│   ├── generate_visuals.py
│   ├── output/
│   │   ├── [figures, results, reports, tables]
│   ├── run_benchmark.py
│   └── run_benchmarks.py
├── provguard/
│   ├── __init__.py
│   ├── agents/
│   │   ├── base.py
│   │   ├── executor.py
│   │   ├── planner.py
│   │   ├── retrieval.py
│   │   ├── summarizer.py
│   │   └── user_proxy.py
│   ├── benchmark/
│   │   ├── metrics.py
│   │   ├── runner.py
│   │   └── scenarios.py
│   ├── cli.py
│   ├── core/
│   │   ├── bus.py
│   │   ├── security.py
│   │   └── types.py
│   ├── defense/
│   │   ├── circuit_breaker.py
│   │   ├── pipeline.py
│   │   ├── quarantine.py
│   │   ├── risk.py
│   │   ├── sanitizer.py
│   │   └── traditional.py
│   └── evaluator/
│       └── __init__.py
```
- **docs/**: Documentation, architecture, and reports.
- **experiments/**: Scripts for evaluation, benchmarking, and visual output.
- **provguard/**: Core library with modular components for agents, defense, benchmarking, CLI, and evaluation.

## Contributing

We welcome contributions! Please follow the workflow:

1. **Fork** the repository.
2. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b your-feature-name
   ```
3. **Commit** your changes.
4. **Push** to your fork:
   ```bash
   git push origin your-feature-name
   ```
5. **Open a Pull Request** and describe your changes.

## License

No license specified. Please contact the repository owner for usage guidelines.

---
[![README powered by ReadmeAI](https://img.shields.io/badge/README-powered%20by%20ReadmeAI-4c9be8?style=flat-square&logo=markdown)](https://www.readmeai.in)
