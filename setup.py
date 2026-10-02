from setuptools import setup, find_packages

setup(
    name="provguard-mas",
    version="1.0.0",
    description="Provenance-Aware Runtime Defense for Detecting and Containing Indirect Prompt Injection in Multi-Agent Systems",
    author="Google DeepMind Advanced Agentic Coding",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "pydantic>=2.0.0",
        "rich>=13.0.0",
        "matplotlib>=3.7.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "seaborn>=0.13.0",
        "langgraph>=0.2.0",
    ],
    entry_points={
        "console_scripts": [
            "provguard=provguard.cli:main",
        ],
    },
)
