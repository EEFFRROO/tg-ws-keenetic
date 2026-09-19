"""Unit tests for tgwsproxy components."""
import asyncio
import os
import struct
import unittest

from tgwsproxy._aes import Cipher, algorithms, modes
from tgwsproxy.bridge import MessageSplitter
from tgwsproxy.config import Config, default_config, _from_dict, _decode_cfproxy, _is_valid_domain
from tgwsproxy.constants import (
    PROTO_INT_ABRIDGED,
    PROTO_INT_INTERMEDIATE,
    PROTO_TAG_ABRIDGED,
    DEFAULT_FRONTING_SNI,
)
from tgwsproxy.logging_setup import DomainCensorFilter
from tgwsproxy.stats import Stats
from tgwsproxy.ws_pool import ws_domains_for, WebSocketPool, CloudflareWorkerPool


class TestCrypto(unittest.TestCase):
    def test_aes_ctr_roundtrip(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        data = b"Hello, Telegram MTProto WebSocket proxy! 1234567890" * 50

        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        ciphertext = enc.update(data)
        self.assertNotEqual(ciphertext, data)

        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        plaintext = dec.update(ciphertext)
        self.assertEqual(plaintext, data)


class TestMessageSplitter(unittest.TestCase):
    def test_splitter_abridged(self):
        relay_init = os.urandom(64)
        # Create encryptor to generate encrypted abridged packets
        enc = Cipher(
            algorithms.AES(relay_init[8:40]),
            modes.CTR(relay_init[40:56]),
        ).encryptor()
        enc.update(b"\x00" * 64)  # skip 64 bytes

        splitter = MessageSplitter(relay_init, PROTO_INT_ABRIDGED)

        # Build 3 small abridged packets: 1 byte len (words) + payload
        packet1_payload = b"test" * 4  # 16 bytes = 4 words
        packet1 = bytes([len(packet1_payload) // 4]) + packet1_payload

        packet2_payload = b"data" * 8  # 32 bytes = 8 words
        packet2 = bytes([len(packet2_payload) // 4]) + packet2_payload

        plain_stream = packet1 + packet2
        cipher_stream = enc.update(plain_stream)

        # Feed to splitter in one chunk
        parts = splitter.split(cipher_stream)
        self.assertEqual(len(parts), 2)
        self.assertEqual(len(parts[0]), len(packet1))
        self.assertEqual(len(parts[1]), len(packet2))


class TestDomainsAndRouting(unittest.TestCase):
    def test_domain_ordering(self):
        # DC 4: kws4 must be first because kws4-1 hangs
        dc4_domains = ws_domains_for(4, True)
        self.assertEqual(dc4_domains[0], "kws4.web.telegram.org")

        dc4_domains_nonmedia = ws_domains_for(4, False)
        self.assertEqual(dc4_domains_nonmedia[0], "kws4.web.telegram.org")

        # DC 2: kws2-1 must be first because it is the responsive web endpoint
        dc2_domains = ws_domains_for(2, False)
        self.assertEqual(dc2_domains[0], "kws2-1.web.telegram.org")

        dc2_domains_media = ws_domains_for(2, True)
        self.assertEqual(dc2_domains_media[0], "kws2-1.web.telegram.org")

    def test_cfproxy_decode(self):
        self.assertTrue(_is_valid_domain(_decode_cfproxy("virkgj.com")))
        self.assertTrue(_decode_cfproxy("virkgj.com").endswith(".co.uk"))


class TestConfig(unittest.TestCase):
    def test_config_defaults(self):
        cfg = default_config()
        self.assertTrue(cfg.fronting)
        self.assertEqual(cfg.fronting_sni, "sprinthost.ru")
        self.assertEqual(cfg.update_repo, "EEFFRROO/tg-ws-keenetic")
        self.assertEqual(cfg.validate(), [])

    def test_multi_worker_domains(self):
        raw = {
            "cfproxy_worker_domain": "w1.workers.dev, w2.workers.dev",
            "update_repo": "EEFFRROO/tg-ws-keenetic",
        }
        cfg = _from_dict(raw)
        self.assertEqual(cfg.worker_domains_list, ["w1.workers.dev", "w2.workers.dev"])


class TestPools(unittest.TestCase):
    def test_cf_worker_pool_available_domains(self):
        stats = Stats()
        pool = CloudflareWorkerPool(buffer_size=65536, stats=stats)
        domains = ["w1.workers.dev", "w2.workers.dev", "w1.workers.dev"]
        avail = pool.available_domains(domains)
        self.assertEqual(set(avail), {"w1.workers.dev", "w2.workers.dev"})


class TestLogging(unittest.TestCase):
    def test_domain_censor(self):
        import logging

        censor = DomainCensorFilter()
        rec = logging.LogRecord(
            "test",
            logging.INFO,
            "test.py",
            1,
            "Connecting to mysecretworker.workers.dev and kws4.web.telegram.org",
            (),
            None,
        )
        censor.filter(rec)
        self.assertIn("kws4.web.telegram.org", rec.msg)
        self.assertNotIn("mysecretworker", rec.msg)
        self.assertIn(".dev", rec.msg)


if __name__ == "__main__":
    unittest.main()
