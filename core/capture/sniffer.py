"""
core.capture.sniffer
====================
Scapy-backed asynchronous packet capture with an asyncio queue interface.

Security relevance:
    This module is the *only* place in the codebase that directly touches
    raw network packets.  All other modules receive ``ParsedPacket`` objects
    with payload bytes stripped.  This isolation boundary is important:

    * It limits the Scapy import surface — Scapy runs with elevated
      privileges (``CAP_NET_RAW``); confining its use to this module
      reduces the blast radius of any Scapy vulnerability.

    * Scapy's layers are imported *inside* ``_parse_scapy_packet`` rather
      than at module level.  This allows the rest of the codebase to import
      ``sniffer`` without Scapy being available (e.g. in test environments
      or on hosts without ``CAP_NET_RAW``), as long as ``PacketSniffer``
      is never instantiated.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from core.capture.flow_assembler import ParsedPacket

logger = logging.getLogger(__name__)

# IANA protocol numbers referenced in the parser
_PROTO_ICMP: int = 1
_PROTO_TCP: int = 6
_PROTO_UDP: int = 17


def _parse_scapy_packet(pkt: Any) -> ParsedPacket:
    """Convert a raw Scapy packet to a ``ParsedPacket``.

    Extracts all relevant fields at call time so the Scapy object can be
    released immediately, preventing the Scapy layer cache from accumulating
    long-lived references to captured packet data.

    Args:
        pkt: A Scapy packet object with at least an IP or IPv6 layer.

    Returns:
        A ``ParsedPacket`` with all fields populated.

    Raises:
        ValueError: If the packet contains no recognisable IP or IPv6 layer.
            Packets from non-IP link-layer protocols (ARP, STP) fall here
            and should be silently discarded by the caller.

    Security note:
        Only metadata fields are extracted — payload *bytes* are never
        stored.  ``payload_len`` records the *length* so that statistical
        signatures based on packet size remain accurate, but the content
        is not retained.
    """
    # Lazy imports keep the Scapy footprint confined to this function.
    # Python's module cache ensures the cost is paid only on the first call.
    from scapy.layers.inet import ICMP  # noqa: PLC0415
    from scapy.layers.inet import IP, TCP, UDP  # noqa: PLC0415

    timestamp = float(pkt.time)

    # ---------------------------------------------------------------
    # Network layer (IP or IPv6)
    # ---------------------------------------------------------------
    src_ip: str
    dst_ip: str
    protocol: int

    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        protocol = int(ip_layer.proto)
    else:
        try:
            from scapy.layers.inet6 import IPv6  # noqa: PLC0415

            if pkt.haslayer(IPv6):
                ip6_layer = pkt[IPv6]
                src_ip = str(ip6_layer.src)
                dst_ip = str(ip6_layer.dst)
                protocol = int(ip6_layer.nh)
            else:
                raise ValueError("Packet has no IP or IPv6 layer")
        except ImportError:
            raise ValueError("Packet has no IP layer and IPv6 is unavailable")

    # ---------------------------------------------------------------
    # Transport layer
    # ---------------------------------------------------------------
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    payload_len: int = 0

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags = int(tcp_layer.flags)
        payload_len = len(bytes(tcp_layer.payload))

    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        payload_len = len(bytes(udp_layer.payload))

    elif pkt.haslayer(ICMP):
        icmp_layer = pkt[ICMP]
        icmp_type = int(icmp_layer.type)
        payload_len = len(bytes(icmp_layer.payload))

    return ParsedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        payload_len=payload_len,
        timestamp=timestamp,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
    )


class PacketSniffer:
    """Asynchronous packet capture engine backed by Scapy's ``AsyncSniffer``.

    Captures raw packets from a network interface and places
    ``ParsedPacket`` objects onto an ``asyncio.Queue`` for consumption by
    the flow assembly loop.  Scapy's ``AsyncSniffer`` runs the capture in a
    dedicated background thread; ``PacketSniffer`` bridges the thread
    boundary safely using ``asyncio.run_coroutine_threadsafe``.

    Args:
        interface: Network interface name to capture on (e.g. ``"eth0"``).
            Corresponds to ``CAPTURE_INTERFACE`` in the environment config.
        queue: The asyncio queue onto which parsed packets are placed.
            The caller owns the queue and is responsible for draining it.
        bpf_filter: Optional BPF filter string passed to Scapy
            (e.g. ``"tcp"`` or ``"not arp"``).  Filters at the kernel level
            for efficiency.
        max_queue_size: Drop packets if the queue reaches this depth, rather
            than blocking the capture thread.  Corresponds to
            ``CAPTURE_MAX_QUEUE_SIZE`` in the environment config.

    Security note:
        This class requires ``CAP_NET_RAW`` (Linux) or administrator
        privileges (Windows).  It should be instantiated *only* by the
        lifespan startup handler in ``core/main.py``, never from within
        request handlers.  See ``docs/threat-model.md`` §3 for the full
        privilege analysis.
    """

    def __init__(
        self,
        interface: str,
        queue: asyncio.Queue[ParsedPacket],
        bpf_filter: str = "",
        max_queue_size: int = 10_000,
    ) -> None:
        self._interface: str = interface
        self._queue: asyncio.Queue[ParsedPacket] = queue
        self._bpf_filter: str = bpf_filter
        self._max_queue_size: int = max_queue_size

        self._loop: asyncio.AbstractEventLoop | None = None
        self._sniffer: Any | None = None  # scapy.sendrecv.AsyncSniffer
        self._running: bool = False
        self._drop_count: int = 0

    async def start(self) -> None:
        """Start the background packet capture thread.

        Captures the running event loop reference so the Scapy callback can
        safely schedule coroutines on it.  The capture thread starts
        immediately; the first packets arrive as soon as the interface
        begins producing traffic.

        Raises:
            RuntimeError: If called outside a running asyncio event loop.
            ImportError: If Scapy is not installed in the current environment.

        Security note:
            The capture thread runs with whatever privileges the process
            holds.  The main FastAPI server process should have ``CAP_NET_RAW``
            granted to the Python binary, not run as root.
        """
        from scapy.sendrecv import AsyncSniffer  # noqa: PLC0415

        self._loop = asyncio.get_running_loop()
        self._running = True

        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=self._bpf_filter,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        logger.info(
            "Packet capture started on interface %r (filter=%r)",
            self._interface,
            self._bpf_filter or "none",
        )

    async def stop(self) -> None:
        """Signal the capture thread to stop and wait for it to finish.

        After this coroutine returns, no further packets will be enqueued.
        The queue may still contain packets that were captured before the
        stop signal was processed.

        Security note:
            Stopping capture cleanly (rather than abandoning the thread)
            ensures that any in-flight packets are not left in an
            inconsistent state and that the privilege-holding thread is
            not left running after the rest of the application has shut down.
        """
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
                self._sniffer.join()
            except Exception as exc:  # pragma: no cover
                logger.warning("Error stopping sniffer: %s", exc)

        logger.info(
            "Packet capture stopped (total drops: %d)", self._drop_count
        )

    @property
    def is_running(self) -> bool:
        """``True`` if the capture thread is active."""
        return self._running and (
            self._sniffer is not None and getattr(self._sniffer, "running", False)
        )

    @property
    def drop_count(self) -> int:
        """Cumulative count of packets dropped due to queue saturation."""
        return self._drop_count

    # ------------------------------------------------------------------
    # Internal: Scapy callback (runs in capture thread)
    # ------------------------------------------------------------------

    def _on_packet(self, pkt: Any) -> None:
        """Scapy per-packet callback — runs in the sniffer thread.

        Parses the raw Scapy packet, checks queue capacity, and schedules
        an enqueue coroutine on the asyncio event loop.

        Args:
            pkt: Raw Scapy packet object.

        Security note:
            This method must not raise — an unhandled exception here
            would silently kill the Scapy callback, dropping all subsequent
            packets without any indication in the logs.  All errors are
            caught and logged.
        """
        if not self._running or self._loop is None:
            return

        try:
            parsed = _parse_scapy_packet(pkt)
        except ValueError:
            # Non-IP packet (ARP, STP, etc.) — silently discard.
            return
        except Exception as exc:
            logger.debug("Failed to parse packet: %s", exc)
            return

        # Check queue depth before scheduling the put to avoid scheduling
        # a coroutine that will immediately block on a full queue.
        if self._queue.qsize() >= self._max_queue_size:
            self._drop_count += 1
            if self._drop_count % 1_000 == 1:
                # Log on first drop and every 1000th to avoid log flooding.
                logger.warning(
                    "Capture queue full (%d capacity) — dropping packets "
                    "(total drops: %d)",
                    self._max_queue_size,
                    self._drop_count,
                )
            return

        # Thread-safe bridge: schedule the coroutine on the asyncio loop.
        asyncio.run_coroutine_threadsafe(
            self._queue.put(parsed), self._loop
        )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"PacketSniffer("
            f"interface={self._interface!r}, "
            f"running={self.is_running}, "
            f"drops={self._drop_count})"
        )
