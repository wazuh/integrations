"""
Contrastive training for decoder similarity using the same decoder pattern text
that inference ranks against.

Input: data/datasets/train.jsonl and val.jsonl (from build_dataset.py)
Output: data/models/decoder-sbert/ containing the SentenceTransformer model
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from sentence_transformers import InputExample, losses, models, SentenceTransformer
from sentence_transformers.evaluation import BinaryClassificationEvaluator
from torch.utils.data import DataLoader

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "datasets"
MODEL_DIR = BASE_DIR / "data" / "models" / "decoder-sbert"
HF_CACHE_DIR = Path.home() / ".cache" / "huggingface" / "hub" / "models--sentence-transformers--all-MiniLM-L6-v2" / "snapshots"
DEFAULT_BASE_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def resolve_base_model() -> str:
    if os.getenv("BASE_MODEL"):
        return os.getenv("BASE_MODEL", DEFAULT_BASE_MODEL)
    if HF_CACHE_DIR.exists():
        snapshots = sorted(p for p in HF_CACHE_DIR.iterdir() if p.is_dir())
        if snapshots:
            return str(snapshots[-1])
    return DEFAULT_BASE_MODEL


def load_pairs(path: Path):
    pairs = []
    with path.open() as f:
        for line in f:
            rec = json.loads(line)
            log = rec["log"]
            target_text = rec.get("target_text") or rec.get("decoder", {}).get("name")
            if not target_text:
                continue
            pairs.append((log, target_text))
    return pairs


def build_evaluator(val_pairs):
    sentences1, sentences2, labels = [], [], []
    for log, decoder in val_pairs:
        sentences1.append(log)
        sentences2.append(decoder)
        labels.append(1)
    return BinaryClassificationEvaluator(sentences1, sentences2, labels)


def main():
    train_path = DATA_DIR / "train.jsonl"
    val_path = DATA_DIR / "val.jsonl"
    if not train_path.exists():
        raise SystemExit("Run scripts/build_dataset.py first.")

    train_pairs = load_pairs(train_path)
    val_pairs = load_pairs(val_path) if val_path.exists() else train_pairs[:100]

    base_model = resolve_base_model()
    local_files_only = os.getenv("LOCAL_FILES_ONLY", "true").lower() != "false"

    word_embedding_model = models.Transformer(base_model, model_args={"local_files_only": local_files_only})
    pooling_model = models.Pooling(word_embedding_model.get_word_embedding_dimension())
    model = SentenceTransformer(modules=[word_embedding_model, pooling_model])

    # Use MultipleNegativesRankingLoss so we only need positive pairs; in-batch examples serve as negatives.
    train_examples = [InputExample(texts=[log, decoder]) for log, decoder in train_pairs]
    train_loader = DataLoader(train_examples, shuffle=True, batch_size=32)
    train_loss = losses.MultipleNegativesRankingLoss(model)

    evaluator = build_evaluator(val_pairs)

    model.fit(
        train_objectives=[(train_loader, train_loss)],
        evaluator=evaluator,
        epochs=1,
        warmup_steps=100,
        output_path=str(MODEL_DIR),
    )
    print(f"Model saved to {MODEL_DIR}")


if __name__ == "__main__":
    main()
