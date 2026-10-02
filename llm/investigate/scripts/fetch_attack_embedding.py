"""Explicitly install or verify the pinned local ATT&CK embedding model."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from attack_mapping.catalog import read_manifest

# Files used by the pinned E5 SentenceTransformer runtime (PyTorch safetensors).
MODEL_FILES = (
    "config.json", "modules.json", "1_Pooling/config.json",
    "sentence_bert_config.json", "model.safetensors", "sentencepiece.bpe.model",
    "special_tokens_map.json", "tokenizer.json", "tokenizer_config.json",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true",
                        help="check the local cache without downloading")
    args = parser.parse_args()

    manifest = read_manifest()
    model = manifest.get("embedding_model")
    revision = manifest.get("embedding_revision")
    if not isinstance(model, str) or not model:
        parser.error("manifest.embedding_model must be configured")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        parser.error("manifest.embedding_revision must be a pinned commit SHA")

    from huggingface_hub import snapshot_download

    path = snapshot_download(repo_id=model, revision=revision,
                             local_files_only=args.verify, allow_patterns=MODEL_FILES)
    missing = [name for name in MODEL_FILES if not (Path(path) / name).is_file()]
    if missing:
        parser.error(f"local model cache is incomplete: {', '.join(missing)}")
    print(f"ATT&CK embedding model ready: {model}@{revision} ({path})")


if __name__ == "__main__":
    main()
