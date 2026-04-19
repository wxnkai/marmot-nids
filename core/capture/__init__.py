"""
core.capture
============
Packet capture, bidirectional flow assembly, and volumetric DoS tracking.

Public API exported from this package:

* ``CapturedPacket`` — structural Protocol; any conforming object can be
  processed by ``FlowAssembler``.
* ``ParsedPacket`` — concrete, Scapy-free packet dataclass.
* ``FlowKey`` — normalised 5-tuple flow identifier (hashable, frozen).
* ``FlowRecord`` — mutable per-flow state container.
* ``FlowStats`` — per-flow statistical accumulator.
* ``DoSTracker`` — sliding-window volumetric attack tracker.
* ``DoSTrigger`` — dataclass returned on threshold breach.
* ``PacketSniffer`` — Scapy-backed async capture engine.
"""

from core.capture.dos_tracker import DoSTrigger, DoSTracker
from core.capture.flow_assembler import (
    CapturedPacket,
    FlowAssembler,
    FlowKey,
    FlowRecord,
    ParsedPacket,
)
from core.capture.flow_stats import FlowStats
from core.capture.sniffer import PacketSniffer

__all__ = [
    "CapturedPacket",
    "DoSTrigger",
    "DoSTracker",
    "FlowAssembler",
    "FlowKey",
    "FlowRecord",
    "FlowStats",
    "PacketSniffer",
    "ParsedPacket",
]
