# ProvGuard-MAS: LangGraph Multi-Agent Security Benchmark Report

**Total Benchmark Scenarios Evaluated**: 150

| Evaluation Metric | Baseline MAS (Unprotected) | Traditional Perimeter Filter | ProvGuard-MAS (Our Defense) | Delta vs Traditional |
| :--- | :---: | :---: | :---: | :---: |
| **Attack Success Rate (ASR)** | 91.0% | 91.0% | **0.0%** | **-91.0%** |
| **Unauthorized Tool Execution (UTER)** | 91.0% | 91.0% | **0.0%** | **-91.0%** |
| **Detection Rate (Recall)** | 9.0% | 9.0% | **100.0%** | **+91.0%** |
| **Precision** | 100.0% | 100.0% | **99.0%** | **+-1.0%** |
| **F1 Score** | 0.165 | 0.165 | **0.995** | **+0.830** |
| **False Positive Rate (FPR)** | 0.0% | 0.0% | **2.0%** | **--2.0%** |
| **Containment Efficiency** | 9.0% | 9.0% | **100.0%** | **+91.0%** |
| **Mean Runtime Latency** | 20.46 ms | 20.40 ms | **18.97 ms** | -1.49 ms |
| **P95 Latency** | 22.41 ms | 22.39 ms | **21.20 ms** | -1.21 ms |
| **Mean Tracking Overhead** | 0.00 ms | 0.126 ms | **0.368 ms** | Sub-millisecond |
