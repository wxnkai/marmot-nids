"""
core.detection.llm.rag.retriever
==================================
ChromaDB-backed similarity search for RAG context injection.

Security relevance:
    The retriever supplies threat-intelligence context to the LLM prompt.
    Relevance filtering (``min_similarity``) ensures that only genuinely
    related chunks are included — injecting irrelevant context increases
    false-positive rates and wastes the LLM's limited context window.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetrievedChunk:
    """A single knowledge chunk returned by the retriever.

    Attributes:
        text: The content of the chunk (markdown text).
        source: Origin filename of the chunk.
        score: Cosine similarity score between the query and the chunk
            embedding.  Higher is more relevant.
        metadata: Any additional metadata stored alongside the chunk.

    Security note:
        Chunk text originates from the trusted knowledge base files in
        ``rag/knowledge/``.  It is not attacker-controlled.  However,
        the text is interpolated into LLM prompts and should never be
        treated as an executable instruction.
    """

    text: str
    source: str
    score: float
    metadata: dict[str, str] | None = None


class RAGRetriever:
    """Retrieves relevant threat-intelligence chunks from ChromaDB.

    Args:
        persist_dir: Path to the ChromaDB persistence directory.
            Corresponds to ``RAG_PERSIST_DIR`` in the environment config.
        collection_name: Name of the ChromaDB collection to query.
        top_k: Maximum number of chunks to return per query.
            Corresponds to ``RAG_TOP_K``.
        min_similarity: Minimum cosine similarity score for a chunk to
            be included.  Chunks below this threshold are filtered out.
            Corresponds to ``RAG_MIN_SIMILARITY``.

    Security note:
        The retriever reads from a local ChromaDB instance.  No network
        calls are made during retrieval.  The embedding model runs locally
        via sentence-transformers.
    """

    def __init__(
        self,
        persist_dir: str = "./vector_db",
        collection_name: str = "threat_intel",
        top_k: int = 5,
        min_similarity: float = 0.3,
    ) -> None:
        self._persist_dir = persist_dir
        self._collection_name = collection_name
        self._top_k = top_k
        self._min_similarity = min_similarity
        self._collection = None
        self._is_ready = False

    def initialize(self) -> bool:
        """Initialize the ChromaDB client and load the collection.

        Returns:
            ``True`` if the collection was loaded successfully,
            ``False`` if ChromaDB is unavailable or the collection
            does not exist.

        Security note:
            Initialization reads from a local directory only.  A missing
            or corrupt database does not crash the application — it
            disables RAG context and logs a warning.
        """
        try:
            import chromadb  # noqa: PLC0415

            client = chromadb.PersistentClient(path=self._persist_dir)
            self._collection = client.get_collection(
                name=self._collection_name
            )
            self._is_ready = True
            logger.info(
                "RAG retriever ready: collection '%s' (%d documents)",
                self._collection_name,
                self._collection.count(),
            )
            return True
        except Exception as exc:
            logger.warning(
                "RAG retriever unavailable (ChromaDB): %s. "
                "LLM prompts will not include threat intelligence context.",
                exc,
            )
            self._is_ready = False
            return False

    @property
    def is_ready(self) -> bool:
        """Whether the retriever has a loaded collection."""
        return self._is_ready

    def retrieve(self, query: str) -> list[RetrievedChunk]:
        """Search for relevant knowledge chunks by semantic similarity.

        Args:
            query: The search query string, typically derived from flow
                statistics or threat-type keywords.

        Returns:
            A list of ``RetrievedChunk`` objects sorted by descending
            relevance score, filtered to exclude chunks below
            ``min_similarity``.  Returns an empty list if the retriever
            is not initialized.

        Security note:
            Query text is derived from flow metadata (IP addresses, port
            numbers, protocol names) — not from raw packet payloads.
            This limits the information exposed to the embedding model.
        """
        if not self._is_ready or self._collection is None:
            return []

        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=self._top_k,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:
            logger.warning("RAG retrieval failed: %s", exc)
            return []

        chunks: list[RetrievedChunk] = []
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for doc, meta, dist in zip(documents, metadatas, distances):
            # ChromaDB returns L2 distances by default; convert to similarity
            # For cosine distance: similarity = 1 - distance
            # (ChromaDB uses cosine distance when using sentence-transformers)
            similarity = 1.0 - dist if dist <= 1.0 else 0.0

            if similarity < self._min_similarity:
                continue

            source = (meta or {}).get("source", "unknown")
            chunks.append(
                RetrievedChunk(
                    text=doc or "",
                    source=source,
                    score=similarity,
                    metadata=meta,
                )
            )

        logger.debug(
            "RAG retrieved %d chunk(s) for query (top score: %.3f)",
            len(chunks),
            chunks[0].score if chunks else 0.0,
        )
        return chunks

    def format_context(self, chunks: list[RetrievedChunk]) -> str:
        """Format retrieved chunks into a context string for prompt injection.

        Args:
            chunks: List of ``RetrievedChunk`` objects from ``retrieve()``.

        Returns:
            A formatted string with each chunk labelled with source and
            relevance score.  Suitable for direct insertion into the
            ``THREAT INTELLIGENCE`` section of the LLM prompt.
        """
        if not chunks:
            return ""

        parts: list[str] = []
        for i, chunk in enumerate(chunks, 1):
            parts.append(
                f"[Source: {chunk.source} | Relevance: {chunk.score:.2f}]\n"
                f"{chunk.text}"
            )

        return "\n\n---\n\n".join(parts)
