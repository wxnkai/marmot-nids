#!/usr/bin/env python
"""
scripts/ingest_knowledge.py
=============================
Ingest RAG knowledge base markdown files into ChromaDB.

Usage::

    python scripts/ingest_knowledge.py
    python scripts/ingest_knowledge.py --knowledge-dir path/to/knowledge
    python scripts/ingest_knowledge.py --persist-dir ./custom_vector_db

Reads all ``.md`` files from the knowledge directory, splits them into
chunks by H2 heading, and upserts them into a ChromaDB collection with
sentence-transformer embeddings.

Prerequisites:
    pip install chromadb sentence-transformers

Security note:
    This script only reads from the local knowledge directory and writes
    to a local ChromaDB persistence directory.  No network calls are made
    unless ChromaDB downloads an embedding model on first run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow imports from the project root
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest RAG knowledge base into ChromaDB."
    )
    parser.add_argument(
        "--knowledge-dir",
        type=Path,
        default=_PROJECT_ROOT / "core" / "detection" / "llm" / "rag" / "knowledge",
        help="Path to knowledge directory containing .md files",
    )
    parser.add_argument(
        "--persist-dir",
        type=str,
        default=str(_PROJECT_ROOT / "vector_db"),
        help="Path to ChromaDB persistence directory",
    )
    parser.add_argument(
        "--collection",
        type=str,
        default="threat_intel",
        help="ChromaDB collection name",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1000,
        help="Maximum characters per chunk",
    )
    args = parser.parse_args(argv)

    from core.detection.llm.rag.ingestor import KnowledgeIngestor  # noqa: E402

    ingestor = KnowledgeIngestor(
        knowledge_dir=args.knowledge_dir,
        persist_dir=args.persist_dir,
        collection_name=args.collection,
        chunk_size=args.chunk_size,
    )

    try:
        total = ingestor.ingest()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Ingestion failed: {exc}", file=sys.stderr)
        return 1

    print(f"Successfully ingested {total} chunk(s) into ChromaDB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
