"""
core.capture.dos_tracker
========================
Sliding-window volumetric attack tracker.

Security relevance:
    DoS and DDoS attacks are the highest-volume threat class handled by a
    NIDS.  Detection must be fast (O(1) amortised) and stateless between
    packets — no per-IP session needed.  The sliding window avoids the
    boundary artefacts of fixed-interval counters: an attacker cannot time a
    burst to straddle two intervals and evade both windows.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class DoSTrigger:
    """Returned by DoSTracker when a volumetric threshold is exceeded.

    Attributes:
        threat_type: Human-readable label for the attack class detected.
            One of: ``"syn_flood"``, ``"icmp_flood"``, ``"rst_flood"``.
        rate: Number of matching events observed within the current window.
        threshold: Configured threshold that was exceeded.
        window_size: Width of the sliding window in seconds.
        timestamp: Timestamp of the packet that caused the trigger.

    Security note:
        A ``DoSTrigger`` is a pre-detection signal raised *before* the flow
        is fully assembled.  This allows the system to react to volumetric
        attacks before the FlowAssembler queue fills up.
    """

    threat_type: str
    rate: int
    threshold: int
    window_size: float
    timestamp: float


class DoSTracker:
    """Tracks volumetric attack indicators using per-protocol sliding windows.

    Maintains independent sliding-window counters for SYN, ICMP, and RST
    packet events.  Each window holds the timestamps of recent events; stale
    timestamps (older than ``window_size`` seconds) are pruned on each update.

    The caller passes explicit timestamps rather than reading the clock
    internally.  This makes the tracker deterministically testable and keeps
    time-source control in the caller (the main capture loop).

    Args:
        window_size: Width of the sliding window in seconds.
            Corresponds to ``DOS_WINDOW_SIZE`` in the environment config.
        syn_threshold: SYN event count in the window required to trigger
            ``"syn_flood"``.  Corresponds to ``DOS_SYN_THRESHOLD``.
        icmp_threshold: ICMP event count required to trigger
            ``"icmp_flood"``.  Corresponds to ``DOS_ICMP_THRESHOLD``.
        rst_threshold: RST event count required to trigger
            ``"rst_flood"``.  Corresponds to ``DOS_RST_THRESHOLD``.

    Security note:
        Thresholds should be tuned to the baseline traffic of the monitored
        network.  A threshold that is too low causes alert fatigue; one that
        is too high allows attacks to go undetected.  The defaults are
        conservative starting points for a typical enterprise network segment.
    """

    def __init__(
        self,
        window_size: float = 10.0,
        syn_threshold: int = 1000,
        icmp_threshold: int = 500,
        rst_threshold: int = 500,
    ) -> None:
        self._window_size: float = window_size
        self._syn_threshold: int = syn_threshold
        self._icmp_threshold: int = icmp_threshold
        self._rst_threshold: int = rst_threshold

        self._syn_events: deque[float] = deque()
        self._icmp_events: deque[float] = deque()
        self._rst_events: deque[float] = deque()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune(self, events: deque[float], now: float) -> None:
        """Remove timestamps older than the sliding window from the deque.

        Args:
            events: The event-timestamp deque to prune in-place.
            now: The current reference time.  Events with
                ``timestamp < now - window_size`` are removed.

        Security note:
            Pruning is O(k) where k is the number of expired events, not O(n)
            for the full window.  Each event is appended once and removed
            once, so the amortised cost across many packets is O(1).
        """
        cutoff = now - self._window_size
        while events and events[0] < cutoff:
            events.popleft()

    def _record(
        self,
        events: deque[float],
        threshold: int,
        threat_type: str,
        timestamp: float,
    ) -> DoSTrigger | None:
        """Core sliding-window record-and-check logic shared across protocols.

        Prunes the window, appends the new event, then returns a
        ``DoSTrigger`` if the updated count meets or exceeds the threshold.

        Args:
            events: Protocol-specific event deque.
            threshold: Count at which the trigger fires.
            threat_type: Label for the alert (``"syn_flood"`` etc.).
            timestamp: Timestamp of the triggering packet.

        Returns:
            A ``DoSTrigger`` if the threshold is met, otherwise ``None``.
        """
        self._prune(events, timestamp)
        events.append(timestamp)
        rate = len(events)
        if rate >= threshold:
            return DoSTrigger(
                threat_type=threat_type,
                rate=rate,
                threshold=threshold,
                window_size=self._window_size,
                timestamp=timestamp,
            )
        return None

    # ------------------------------------------------------------------
    # Public record methods
    # ------------------------------------------------------------------

    def record_syn(self, timestamp: float) -> DoSTrigger | None:
        """Record a TCP SYN packet and check for SYN flood conditions.

        Args:
            timestamp: Unix epoch timestamp of the SYN packet.

        Returns:
            A ``DoSTrigger`` if the SYN rate exceeds ``syn_threshold``
            within the current window, otherwise ``None``.

        Security note:
            SYN flood attacks exploit the TCP three-way handshake by sending
            large volumes of SYN packets without completing the handshake,
            exhausting connection tables on the target host.  Early detection
            here allows the system to alert before the target becomes
            unreachable.
        """
        return self._record(
            self._syn_events, self._syn_threshold, "syn_flood", timestamp
        )

    def record_icmp(self, timestamp: float) -> DoSTrigger | None:
        """Record an ICMP packet and check for ICMP flood conditions.

        Args:
            timestamp: Unix epoch timestamp of the ICMP packet.

        Returns:
            A ``DoSTrigger`` if the ICMP rate exceeds ``icmp_threshold``
            within the current window, otherwise ``None``.

        Security note:
            ICMP flood (ping flood) can saturate network links and exhaust
            CPU on hosts that process every ICMP echo request.  DNS
            amplification attacks also use ICMP as a side-channel indicator.
        """
        return self._record(
            self._icmp_events, self._icmp_threshold, "icmp_flood", timestamp
        )

    def record_rst(self, timestamp: float) -> DoSTrigger | None:
        """Record a TCP RST packet and check for RST flood conditions.

        Args:
            timestamp: Unix epoch timestamp of the RST packet.

        Returns:
            A ``DoSTrigger`` if the RST rate exceeds ``rst_threshold``
            within the current window, otherwise ``None``.

        Security note:
            RST flood attacks inject forged TCP RST packets to terminate
            established connections on the target, causing denial of service
            without a volume-based signature detectable at the IP level alone.
        """
        return self._record(
            self._rst_events, self._rst_threshold, "rst_flood", timestamp
        )

    # ------------------------------------------------------------------
    # Rate queries (read-only, for dashboards and logging)
    # ------------------------------------------------------------------

    def syn_rate(self, now: float) -> int:
        """Return the number of SYN events in the current sliding window.

        Args:
            now: Current reference time.  Events older than
                ``now - window_size`` are excluded from the count.

        Returns:
            Count of SYN events within the window.
        """
        self._prune(self._syn_events, now)
        return len(self._syn_events)

    def icmp_rate(self, now: float) -> int:
        """Return the number of ICMP events in the current sliding window.

        Args:
            now: Current reference time.

        Returns:
            Count of ICMP events within the window.
        """
        self._prune(self._icmp_events, now)
        return len(self._icmp_events)

    def rst_rate(self, now: float) -> int:
        """Return the number of RST events in the current sliding window.

        Args:
            now: Current reference time.

        Returns:
            Count of RST events within the window.
        """
        self._prune(self._rst_events, now)
        return len(self._rst_events)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"DoSTracker("
            f"window={self._window_size}s, "
            f"syn_thresh={self._syn_threshold}, "
            f"icmp_thresh={self._icmp_threshold}, "
            f"rst_thresh={self._rst_threshold})"
        )
