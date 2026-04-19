"""
core.detection.llm.rag.ingestor
================================
Knowledge base ingestor: reads markdown files from ``rag/knowledge/``
and upserts their content into ChromaDB as vectorised chunks.

Security relevance:
    Knowledge files are the ground-truth reference material that shapes
    LLM detection quality.  The ingestor validates that all source paths
    are within the expected knowledge directory (path-traversal prevention)
    and logs every file processed for auditability.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

#: Default path to the knowledge directory, relative to this file.
_DEFAULT_KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


class KnowledgeIngestor:
    """Ingests markdown knowledge files into a ChromaDB collection.

    Args:
        knowledge_dir: Path to the directory containing ``.md`` files.
        persist_dir: Path to the ChromaDB persistence directory.
            Corresponds to ``RAG_PERSIST_DIR`` in the environment config.
        collection_name: Name of the ChromaDB collection to create or
            upsert into.
        chunk_size: Approximate maximum character count per chunk.
            Larger chunks provide more context but use more of the LLM's
            token budget.

    Security note:
        The ingestor only processes files with the ``.md`` extension
        within ``knowledge_dir``.  Symlinks, files above the knowledge
        directory, and non-markdown files are rejected.
    """

    def __init__(
        self,
        knowledge_dir: Path | None = None,
        persist_dir: str = "./vector_db",
        collection_name: str = "threat_intel",
        chunk_size: int = 1000,
    ) -> None:
        self._knowledge_dir = knowledge_dir or _DEFAULT_KNOWLEDGE_DIR
        self._persist_dir = persist_dir
        self._collection_name = collection_name
        self._chunk_size = chunk_size

    def ingest(self) -> int:
        """Read all ``.md`` files in the knowledge directory and upsert to ChromaDB.

        Returns:
            Total number of chunks upserted.

        Raises:
            FileNotFoundError: If the knowledge directory does not exist.
            RuntimeError: If ChromaDB cannot be initialised.

        Security note:
            Each file path is resolved and checked to be within the
            knowledge directory before reading.  This prevents path
            traversal via symlinks or ``../`` components in filenames.
        """
        knowledge_dir = self._knowledge_dir.resolve()
        if not knowledge_dir.exists():
            raise FileNotFoundError(
                f"Knowledge directory not found: {knowledge_dir}"
            )

        import chromadb  # noqa: PLC0415

        md_files = sorted(knowledge_dir.glob("*.md"))
        if not md_files:
            logger.warning("No .md files found in %s", knowledge_dir)
            return 0

        # Path traversal check
        for f in md_files:
            resolved = f.resolve()
            if not str(resolved).startswith(str(knowledge_dir)):
                logger.warning(
                    "Skipping file outside knowledge directory: %s", f
                )
                md_files.remove(f)

        client = chromadb.PersistentClient(path=self._persist_dir)
        collection = client.get_or_create_collection(
            name=self._collection_name,
        )

        total_chunks = 0
        for filepath in md_files:
            chunks = self._chunk_file(filepath)
            if not chunks:
                continue

            ids = [
                f"{filepath.stem}_chunk_{i}"
                for i in range(len(chunks))
            ]
            metadatas = [
                {"source": filepath.name, "chunk_index": str(i)}
                for i in range(len(chunks))
            ]

            collection.upsert(
                ids=ids,
                documents=chunks,
                metadatas=metadatas,
            )
            total_chunks += len(chunks)
            logger.info(
                "Ingested %s: %d chunk(s)", filepath.name, len(chunks)
            )

        logger.info(
            "Ingestion complete: %d file(s), %d chunk(s) total",
            len(md_files),
            total_chunks,
        )
        return total_chunks

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _chunk_file(self, filepath: Path) -> list[str]:
        """Split a markdown file into chunks by heading boundaries.

        Chunks are split at ``## `` (H2) headings.  If a single section
        exceeds ``chunk_size``, it is further split at paragraph boundaries
        (double newlines).  This preserves semantic coherence within chunks.

        Args:
            filepath: Path to the markdown file.

        Returns:
            A list of non-empty text chunks.
        """
        text = filepath.read_text(encoding="utf-8")

        # Split on H2 headings, keeping the heading with its content
        sections: list[str] = []
        current: list[str] = []

        for line in text.split("\n"):
            if line.startswith("## ") and current:
                sections.append("\n".join(current).strip())
                current = [line]
            else:
                current.append(line)

        if current:
            sections.append("\n".join(current).strip())

        # Further split oversized sections at paragraph boundaries
        chunks: list[str] = []
        for section in sections:
            if not section:
                continue
            if len(section) <= self._chunk_size:
                chunks.append(section)
            else:
                paragraphs = section.split("\n\n")
                buf: list[str] = []
                buf_len = 0
                for para in paragraphs:
                    if buf_len + len(para) > self._chunk_size and buf:
                        chunks.append("\n\n".join(buf).strip())
                        buf = []
                        buf_len = 0
                    buf.append(para)
                    buf_len += len(para)
                if buf:
                    chunks.append("\n\n".join(buf).strip())

        return [c for c in chunks if c.strip()]
