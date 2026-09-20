"""Hot WebSocket connection pool, keyed by (DC, is_media).

Telegram clients open lots of short-lived MTProto sessions; opening a WSS
connection for each one is the slowest part of the path. We pre-open a
small pool per (DC, is_media) bucket and lend connections out as needed.
Also provides a hot pool for Cloudflare Worker connections (`CloudflareWorkerPool`).
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from urllib.parse import urlencode
from typing import Deque, Dict, List, Optional, Set, Tuple

from .constants import DEFAULT_FRONTING_SNI, DC_DEFAULT_IPS
from .stats import Stats
from .websocket import RawWebSocket, WsHandshakeError

log = logging.getLogger("tgwsproxy.ws_pool")

PoolKey = Tuple[int, bool]


def ws_domains_for(dc: int, is_media: Optional[bool]) -> List[str]:
    """Native Telegram WS endpoints. Responsive variants are ordered first."""
    if dc == 203:
        dc = 2
    if not is_media:
        # Non-media / control sessions: ALWAYS use standard kws{dc} first!
        # Telegram's main session handles auth, messages, and state sync.
        return [
            f"kws{dc}.web.telegram.org",
            f"kws{dc}-1.web.telegram.org",
        ]
    # Media sessions:
    if dc == 4:
        # On gateway 149.154.167.220, kws4 handles media while kws4-1 hangs
        return [
            f"kws4.web.telegram.org",
            f"kws4-1.web.telegram.org",
        ]
    return [
        f"kws{dc}-1.web.telegram.org",
        f"kws{dc}.web.telegram.org",
    ]


class WebSocketPool:
    """Idle-keep-alive pool with background refill and domain fronting."""

    MAX_AGE_SECONDS = 120.0

    def __init__(
        self,
        target_size: int,
        buffer_size: int,
        stats: Stats,
        fronting_enabled: bool = True,
        fronting_sni: str = DEFAULT_FRONTING_SNI,
    ):
        self._target = max(0, target_size)
        self._buffer = buffer_size
        self._stats = stats
        self._idle: Dict[PoolKey, Deque[Tuple[RawWebSocket, float]]] = {}
        self._refilling: Set[PoolKey] = set()
        self.fronting_enabled = fronting_enabled
        self.fronting_sni = fronting_sni or DEFAULT_FRONTING_SNI
        self.try_fronting_first = fronting_enabled

    @property
    def target_size(self) -> int:
        return self._target

    def set_target(self, size: int) -> None:
        self._target = max(0, size)

    async def acquire(
        self, dc: int, is_media: bool, target_ip: str, domains: List[str]
    ) -> Optional[RawWebSocket]:
        key = (dc, is_media)
        bucket = self._idle.setdefault(key, deque())
        now = time.monotonic()

        while bucket:
            ws, created = bucket.popleft()
            if now - created > self.MAX_AGE_SECONDS or ws.closed:
                asyncio.create_task(self._quiet_close(ws))
                continue
            self._stats.pool_hits += 1
            self._schedule_refill(key, target_ip, domains)
            return ws

        self._stats.pool_misses += 1
        self._schedule_refill(key, target_ip, domains)
        return None

    async def connect_candidate(
        self, target_ip: str, domains: List[str], timeout: float = 4.0
    ) -> Optional[RawWebSocket]:
        """Try candidates with fronting and fast-fail."""
        for domain in domains:
            ws = await self._connect_single_domain(target_ip, domain, timeout=timeout)
            if ws is not None:
                return ws
        return None

    async def _connect_single_domain(
        self, target_ip: str, domain: str, timeout: float = 4.0
    ) -> Optional[RawWebSocket]:
        # 1. If fronting is preferred first (typical to bypass DPI on Telegram domains)
        if self.fronting_enabled and self.try_fronting_first:
            ws = await self._connect_fronted(target_ip, domain, timeout=timeout)
            if ws is not None:
                return ws

        # 2. Direct connect with domain SNI
        try:
            ws = await RawWebSocket.connect(
                target_ip,
                domain,
                timeout=timeout,
                buffer_size=self._buffer,
            )
            self.try_fronting_first = False
            return ws
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            # Direct connection blocked or timed out by DPI — try fronting
            if self.fronting_enabled and not self.try_fronting_first:
                return await self._connect_fronted(target_ip, domain, timeout=timeout)
            return None
        except WsHandshakeError as exc:
            if exc.is_redirect:
                return None
            return None
        except Exception:
            return None

    async def _connect_fronted(
        self, target_ip: str, domain: str, timeout: float = 4.0
    ) -> Optional[RawWebSocket]:
        try:
            ws = await RawWebSocket.connect(
                target_ip,
                domain,
                timeout=timeout,
                buffer_size=self._buffer,
                sni=self.fronting_sni,
            )
            self._stats.connections_fronting += 1
            self.try_fronting_first = True
            return ws
        except Exception:
            return None

    async def warmup(self, dc_to_ip: Dict[int, str]) -> None:
        for dc, target_ip in dc_to_ip.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                self._schedule_refill(
                    (dc, is_media), target_ip, ws_domains_for(dc, is_media)
                )
        log.info("WS pool warmup started for %d DC(s)", len(dc_to_ip))

    def reset(self) -> None:
        for bucket in self._idle.values():
            for ws, _ in bucket:
                asyncio.create_task(self._quiet_close(ws))
        self._idle.clear()
        self._refilling.clear()

    def _schedule_refill(
        self, key: PoolKey, target_ip: str, domains: List[str]
    ) -> None:
        if key in self._refilling or self._target == 0:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(
        self, key: PoolKey, target_ip: str, domains: List[str]
    ) -> None:
        dc, is_media = key
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = self._target - len(bucket)
            if needed <= 0:
                return
            connectors = [
                asyncio.create_task(
                    self.connect_candidate(target_ip, domains, timeout=4.0)
                )
                for _ in range(needed)
            ]
            for task in connectors:
                try:
                    ws = await task
                except Exception:
                    continue
                if ws is not None:
                    bucket.append((ws, time.monotonic()))
            log.debug(
                "WS pool refilled DC%d%s -> %d ready",
                dc,
                "m" if is_media else "",
                len(bucket),
            )
        finally:
            self._refilling.discard(key)

    @staticmethod
    async def _quiet_close(ws: RawWebSocket) -> None:
        try:
            await ws.close()
        except Exception:
            pass


class CloudflareWorkerPool:
    """Hot pool for Cloudflare Worker connections.

    Dramatically reduces media latency for DCs not routed directly (DC 1, 3, 5)
    by eliminating repeated TLS handshake overhead.
    """

    WS_POOL_MAX_AGE = 100.0
    PER_DC_LIMIT = 2

    def __init__(self, buffer_size: int, stats: Stats, no_secure: bool = False):
        self._buffer = buffer_size
        self._stats = stats
        self._no_secure = no_secure
        self._idle: Dict[int, Deque[Tuple[RawWebSocket, float, str]]] = {}
        self._refilling: Set[int] = set()
        self._exhausted_until: Dict[str, float] = {}

    async def acquire(
        self, dc: int, fallback_dst: str, worker_domains: List[str]
    ) -> Optional[Tuple[RawWebSocket, str]]:
        if not worker_domains:
            return None
        now = time.monotonic()
        bucket = self._idle.setdefault(dc, deque())
        while bucket:
            ws, created, worker_domain = bucket.popleft()
            age = now - created
            if age > self.WS_POOL_MAX_AGE or ws.closed:
                asyncio.create_task(self._quiet_close(ws))
                continue
            self._stats.cf_pool_hits += 1
            log.debug(
                "CF worker pool hit DC%d via %s (age=%.1fs, left=%d)",
                dc,
                worker_domain,
                age,
                len(bucket),
            )
            self._schedule_refill(dc, fallback_dst, worker_domains)
            return ws, worker_domain

        self._stats.cf_pool_misses += 1
        self._schedule_refill(dc, fallback_dst, worker_domains)
        return None

    def available_domains(self, worker_domains: List[str]) -> List[str]:
        now = time.time()
        result: List[str] = []
        for d in worker_domains:
            if d in result:
                continue
            exhausted = self._exhausted_until.get(d, 0)
            if exhausted > now:
                continue
            if exhausted:
                self._exhausted_until.pop(d, None)
            result.append(d)
        random.shuffle(result)
        return result

    def report_failure(self, worker_domain: str, exc: Exception) -> None:
        if isinstance(exc, WsHandshakeError) and exc.status_code == 429:
            now = time.time()
            exhausted_until = now + 3600
            self._exhausted_until[worker_domain] = exhausted_until
            log.warning(
                "CF worker %s returned 429 (rate limit), disabling for 1 hour",
                worker_domain,
            )

    def _schedule_refill(
        self, dc: int, fallback_dst: str, worker_domains: List[str]
    ) -> None:
        if dc in self._refilling or not worker_domains:
            return
        self._refilling.add(dc)
        asyncio.create_task(self._refill(dc, fallback_dst, list(worker_domains)))

    async def _refill(
        self, dc: int, fallback_dst: str, worker_domains: List[str]
    ) -> None:
        try:
            bucket = self._idle.setdefault(dc, deque())
            needed = self.PER_DC_LIMIT - len(bucket)
            if needed <= 0:
                return
            for _ in range(needed):
                conn = await self._connect_one(worker_domains, fallback_dst, dc)
                if conn is None:
                    break
                ws, domain = conn
                bucket.append((ws, time.monotonic(), domain))
            log.debug("CF worker pool refilled DC%d -> %d ready", dc, len(bucket))
        finally:
            self._refilling.discard(dc)

    async def _connect_one(
        self, worker_domains: List[str], fallback_dst: str, dc: int
    ) -> Optional[Tuple[RawWebSocket, str]]:
        query = urlencode({"dst": fallback_dst, "dc": str(dc)})
        path = f"/apiws?{query}"
        for domain in self.available_domains(worker_domains):
            try:
                ws = await RawWebSocket.connect(
                    domain,
                    domain,
                    timeout=5.0,
                    path=path,
                    buffer_size=self._buffer,
                    secure=not self._no_secure,
                )
                return ws, domain
            except Exception as exc:
                self.report_failure(domain, exc)
                continue
        return None

    async def warmup(
        self, dc_to_ip: Dict[int, str], worker_domains: List[str]
    ) -> None:
        if not worker_domains:
            return
        # Warmup for non-redirected DCs (e.g. 1, 3, 5)
        for dc, ip in DC_DEFAULT_IPS.items():
            if dc not in dc_to_ip:
                self._schedule_refill(dc, ip, worker_domains)
        log.info("CF worker pool warmup started for worker domains")

    def reset(self) -> None:
        for bucket in self._idle.values():
            for ws, _, _ in bucket:
                asyncio.create_task(self._quiet_close(ws))
        self._idle.clear()
        self._refilling.clear()
        self._exhausted_until.clear()

    @staticmethod
    async def _quiet_close(ws: RawWebSocket) -> None:
        try:
            await ws.close()
        except Exception:
            pass
