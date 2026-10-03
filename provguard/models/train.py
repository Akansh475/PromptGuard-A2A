"""
Model training pipeline for ProvGuard Prompt Injection & Adversarial Intent Guardrail.
Trains a subword/character + word n-gram feature union classifier with calibrated probabilities.
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
from typing import Any, Dict, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import FeatureUnion, Pipeline

from provguard.models.dataset import get_training_corpus

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
MODEL_FILE = os.path.join(ARTIFACT_DIR, "injection_detector.joblib")


def build_pipeline() -> Pipeline:
    """
    Constructs an NLP pipeline:
    - Word-level TF-IDF (1 to 3 ngrams): captures semantic phrases and explicit override commands
    - Character-level TF-IDF (3 to 6 ngrams): captures delimiter syntax (<|...|>), obfuscation, shell flags
    - LogisticRegression with balanced class weights and L2 regularization
    """
    word_vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 3),
        max_features=4000,
        sublinear_tf=True,
    )

    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 6),
        max_features=6000,
        sublinear_tf=True,
    )

    feature_union = FeatureUnion(
        transformer_list=[
            ("word_tfidf", word_vectorizer),
            ("char_tfidf", char_vectorizer),
        ]
    )

    classifier = LogisticRegression(
        C=3.0,
        class_weight="balanced",
        max_iter=1000,
        solver="lbfgs",
        random_state=42,
    )

    return Pipeline([
        ("features", feature_union),
        ("classifier", classifier),
    ])


def prepare_data() -> Tuple[list, list]:
    """Extracts texts and labels from corpus, performing synthetic data augmentation."""
    raw_corpus = get_training_corpus()
    texts = []
    labels = []

    for item in raw_corpus:
        t = item["text"]
        lbl = item["label"]
        texts.append(t)
        labels.append(lbl)

        # Light augmentation: lower-cased version for resilience
        if t != t.lower():
            texts.append(t.lower())
            labels.append(lbl)

    return texts, labels


def train_and_evaluate(output_path: str = MODEL_FILE) -> Dict[str, Any]:
    """Trains the model, performs cross-validation, and saves model artifact."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    texts, labels = prepare_data()

    X = texts
    y = np.array(labels)

    pipeline = build_pipeline()

    # 5-Fold Stratified Cross Validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    acc_scores = cross_val_score(pipeline, X, y, cv=cv, scoring="accuracy")
    f1_scores = cross_val_score(pipeline, X, y, cv=cv, scoring="f1")

    # Train on full dataset
    pipeline.fit(X, y)
    y_pred = pipeline.predict(X)
    y_prob = pipeline.predict_proba(X)[:, 1]

    train_acc = accuracy_score(y, y_pred)
    train_prec = precision_score(y, y_pred, zero_division=0)
    train_rec = recall_score(y, y_pred, zero_division=0)
    train_f1 = f1_score(y, y_pred, zero_division=0)
    train_auc = roc_auc_score(y, y_prob)

    metadata = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_samples": len(texts),
        "benign_count": int(np.sum(y == 0)),
        "adversarial_count": int(np.sum(y == 1)),
        "cv_accuracy_mean": float(np.mean(acc_scores)),
        "cv_accuracy_std": float(np.std(acc_scores)),
        "cv_f1_mean": float(np.mean(f1_scores)),
        "cv_f1_std": float(np.std(f1_scores)),
        "train_accuracy": float(train_acc),
        "train_precision": float(train_prec),
        "train_recall": float(train_rec),
        "train_f1": float(train_f1),
        "train_roc_auc": float(train_auc),
        "pipeline_stages": ["FeatureUnion(word_tfidf, char_tfidf)", "LogisticRegression(C=3.0)"],
    }

    artifact = {
        "pipeline": pipeline,
        "metadata": metadata,
    }

    joblib.dump(artifact, output_path)

    return metadata


def main():
    parser = argparse.ArgumentParser(description="Train ProvGuard Prompt Injection Detector Model.")
    parser.add_argument(
        "--output",
        type=str,
        default=MODEL_FILE,
        help="Target filepath for saved model artifact (.joblib).",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ProvGuard-MAS: Training Machine Learning Guardrail Model")
    print("=" * 60)

    metadata = train_and_evaluate(args.output)

    print(f"Artifact Saved to: {args.output}")
    print(f"Total Samples (Augmented): {metadata['total_samples']} (Benign: {metadata['benign_count']}, Adv: {metadata['adversarial_count']})")
    print(f"5-Fold CV Accuracy: {metadata['cv_accuracy_mean']*100:.2f}% (+/- {metadata['cv_accuracy_std']*100:.2f}%)")
    print(f"5-Fold CV F1 Score: {metadata['cv_f1_mean']*100:.2f}% (+/- {metadata['cv_f1_std']*100:.2f}%)")
    print(f"Train Accuracy:     {metadata['train_accuracy']*100:.2f}%")
    print(f"Train Precision:    {metadata['train_precision']*100:.2f}%")
    print(f"Train Recall:       {metadata['train_recall']*100:.2f}%")
    print(f"Train F1-Score:     {metadata['train_f1']*100:.2f}%")
    print(f"Train ROC-AUC:      {metadata['train_roc_auc']:.4f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
