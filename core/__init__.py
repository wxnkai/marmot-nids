"""
marmot-nids — core application package.

This package contains all server-side components of the marmot-nids detection
pipeline: packet capture, signature and LLM detection engines, blockchain
audit logging, API layer, and storage.

Security note:
    No secrets, API keys, or private keys should ever be imported at the
    module level.  All sensitive configuration is loaded lazily through
    core.config using python-decouple.
"""
