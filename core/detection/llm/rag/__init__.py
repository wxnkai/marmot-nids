"""
core.detection.llm.rag
======================
Retrieval-Augmented Generation (RAG) pipeline for threat intelligence
context injection into LLM prompts.

Ingested knowledge lives in ``rag/knowledge/`` as markdown files.
``ingestor.py`` vectorises them into ChromaDB; ``retriever.py``
performs similarity search at query time to supply the LLM with
relevant threat intel context.
"""
