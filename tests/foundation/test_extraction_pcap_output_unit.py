# -*- coding: utf-8 -*-
"""Regression tests for #1127: extraction with ``format='pcap'``.

:class:`~pcapkit.foundation.extraction.Extractor` creates the output writer at
the engine's global-header step, via
:meth:`~pcapkit.foundation.extraction.Extractor._open_output`, because
:class:`~pcapkit.dumpkit.pcap.PCAPIO` needs that header's link type, byte order
and timestamp resolution to write its own.

A PCAP-NG input declares those fields per section and per interface, so its
PCAP output is planned by
:mod:`pcapkit.foundation.engines.pcapng_pcap` before any output file exists.

"""
from __future__ import annotations

import importlib
import importlib.util
import io
import json
import os
import struct
import tempfile
import unittest
import warnings
from decimal import Decimal

from tests._support import sample_path
from tests.foundation._roundtrip import pcapng, read_pcap

HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def _current(module: str, name: str):
    """``module.name`` from the :mod:`pcapkit` import live in :data:`sys.modules` now.

    Not a top-level import (GitHub issue #981): a sibling test that re-imports
    :mod:`pcapkit` leaves a newer generation behind under plain :mod:`unittest`,
    and the extractor resolves its writer from that one. A stale ``extract``
    then runs an engine whose ``PCAPIO`` check misses the newer writer class.
    """
    return getattr(importlib.import_module(module), name)


def _extract(fin: str, fout: str, **kwargs):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return _current('pcapkit.interface', 'extract')(fin=fin, fout=fout, nofile=False, **kwargs)


def _read(path: str) -> bytes:
    with open(path, 'rb') as file:
        return file.read()


class PCAPOutputTests(unittest.TestCase):

    def test_pcap_output_reproduces_the_input(self) -> None:
        for fmt in ('pcap', 'cap'):
            with self.subTest(format=fmt), tempfile.TemporaryDirectory() as tmp:
                extractor = _extract(sample_path('in.pcap'), os.path.join(tmp, 'out'), format=fmt)
                self.assertEqual(extractor.format, 'pcap')
                self.assertEqual(_read(extractor.output), _read(sample_path('in.pcap')))

    def test_split_pcap_output_writes_one_capture_per_frame(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extractor = _extract(sample_path('in.pcap'), os.path.join(tmp, 'out'),
                                 format='pcap', files=True)
            self.assertEqual(extractor.format, 'pcap')
            header = _read(sample_path('in.pcap'))[:24]
            self.assertEqual(_read(os.path.join(extractor.output, 'Global Header.pcap')), header)
            for num in range(1, extractor.length + 1):
                path = os.path.join(extractor.output, f'Frame {num}.pcap')
                self.assertEqual(_read(path)[:24], header)
                self.assertEqual(_extract(path, os.path.join(tmp, 'again'), format='json').length, 1)

    def test_zero_frame_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, 'empty.pcap')
            with open(empty, 'wb') as file:
                file.write(_read(sample_path('in.pcap'))[:24])
            extractor = _extract(empty, os.path.join(tmp, 'out'), format='pcap')
            self.assertEqual(extractor.format, 'pcap')
            self.assertEqual(_read(extractor.output), _read(empty))

    def test_pcapng_input_converts_to_pcap_and_reads_back_frame_for_frame(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _current('pcapkit.interface', 'extract')(
                fin=sample_path('dhcp.pcapng'), nofile=True, store=True)
            extractor = _extract(sample_path('dhcp.pcapng'), os.path.join(tmp, 'out'), format='pcap')
            self.assertEqual(extractor.format, 'pcap')
            self.assertEqual(extractor.length, source.length)

            written = read_pcap(_read(extractor.output))
            self.assertEqual(written.byteorder, 'little')
            self.assertFalse(written.nanosecond)
            self.assertEqual(written.linktype, 1)
            # snapshot length is the carrying interface's, 65535 for dhcp.pcapng
            self.assertEqual(written.records[0][3], written.records[0][2])

            reread = _current('pcapkit.interface', 'extract')(
                fin=extractor.output, nofile=True, store=True)
            self.assertEqual(reread.length, source.length)
            for source_frame, record, pcap_frame in zip(source.frame, written.records, reread.frame):
                # raw octets, frame order, original and captured length
                self.assertEqual(record[4], source_frame.info.packet)
                self.assertEqual(pcap_frame.info.packet, source_frame.info.packet)
                self.assertEqual(record[2], source_frame.info.captured_len)
                self.assertEqual(record[3], source_frame.info.original_len)
                # original capture time, at the output file's microsecond resolution
                self.assertEqual(
                    pcap_frame.info.time_epoch, source_frame.info.timestamp_epoch)
                sec, fraction = record[:2]
                self.assertEqual(
                    Decimal(sec) + Decimal(fraction) / Decimal(1_000_000),
                    source_frame.info.timestamp_epoch)

    def test_pcapng_pcap_header_takes_the_finest_resolution_and_largest_snaplen(self) -> None:
        # two interfaces of one section: microsecond/snaplen 1500, nanosecond/snaplen 9000.
        # The bytes are built by hand because the shared builder makes one IDB.
        order = '<'

        def block(kind: int, body: bytes) -> bytes:
            body += b'\x00' * (-len(body) % 4)
            size = 12 + len(body)
            return struct.pack(f'{order}II', kind, size) + body + struct.pack(f'{order}I', size)

        shb = block(0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))
        us_idb = block(0x00000001, struct.pack(f'{order}HHI', 1, 0, 1500))
        ns_idb = block(0x00000001,
                       struct.pack(f'{order}HHI', 1, 0, 9000)
                       + struct.pack(f'{order}HH', 9, 1) + b'\x09\x00\x00\x00'
                       + struct.pack(f'{order}HH', 0, 0))
        packet_a = b'\xaa' * 12
        packet_b = b'\xbb' * 24
        ticks_a = 1_700_000_000 * 1_000_000 + 123_456
        ticks_b = 1_700_000_001 * 1_000_000_000 + 654_321
        us_epb = block(0x00000006, struct.pack(
            f'{order}IIIII', 0, ticks_a >> 32, ticks_a & 0xFFFFFFFF,
            len(packet_a), len(packet_a)) + packet_a)
        ns_epb = block(0x00000006, struct.pack(
            f'{order}IIIII', 1, ticks_b >> 32, ticks_b & 0xFFFFFFFF,
            len(packet_b), len(packet_b)) + packet_b)
        data = shb + us_idb + ns_idb + us_epb + ns_epb

        with tempfile.TemporaryDirectory() as tmp:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = _current('pcapkit.interface', 'extract')(
                    fin=io.BytesIO(data), fout=os.path.join(tmp, 'out'), format='pcap')
            written = read_pcap(_read(extractor.output))
            self.assertTrue(written.nanosecond)
            self.assertEqual(written.byteorder, 'little')
            # snaplen is a global-header field; read it back directly
            snaplen = struct.unpack('<I', _read(extractor.output)[16:20])[0]
            self.assertEqual(snaplen, 9000)
            # the microsecond frame keeps its instant at nanosecond output (x1000, exact)
            self.assertEqual(written.records[0][:2], (1_700_000_000, 123_456_000))
            self.assertEqual(written.records[1][:2], (1_700_000_001, 654_321))
            self.assertEqual([record[4] for record in written.records], [packet_a, packet_b])

    def test_pcapng_multi_section_byte_order_follows_the_first_packet_section(self) -> None:
        # section 0 is little-endian, section 1 big-endian; both carry Ethernet frames.
        # A PCAP file speaks one byte order, which must be the first packet section's.
        packets = [b'\x01' * 8, b'\x02' * 8, b'\x03' * 8]

        def block(order: str, kind: int, body: bytes) -> bytes:
            body += b'\x00' * (-len(body) % 4)
            size = 12 + len(body)
            return struct.pack(f'{order}II', kind, size) + body + struct.pack(f'{order}I', size)

        def shb(order: str) -> bytes:
            return block(order, 0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))

        def idb(order: str) -> bytes:
            return block(order, 0x00000001, struct.pack(f'{order}HHI', 1, 0, 100))

        def epb(order: str, ticks: int, packet: bytes) -> bytes:
            return block(order, 0x00000006, struct.pack(
                f'{order}IIIII', 0, ticks >> 32, ticks & 0xFFFFFFFF,
                len(packet), len(packet)) + packet)

        data = (shb('<') + idb('<') + epb('<', 1_000_000 + 10, packets[0])
                + epb('<', 2_000_000 + 20, packets[1])
                + shb('>') + idb('>') + epb('>', 3_000_000 + 30, packets[2]))

        with tempfile.TemporaryDirectory() as tmp:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                source = _current('pcapkit.interface', 'extract')(
                    fin=io.BytesIO(data), nofile=True, store=True)
                extractor = _current('pcapkit.interface', 'extract')(
                    fin=io.BytesIO(data), fout=os.path.join(tmp, 'out'), format='pcap')

            written = read_pcap(_read(extractor.output))
            self.assertEqual(written.byteorder, 'little')
            self.assertFalse(written.nanosecond)
            # order and octets of every frame survive, across the section boundary
            self.assertEqual([record[4] for record in written.records], packets)
            self.assertEqual([record[:2] for record in written.records],
                             [(1, 10), (2, 20), (3, 30)])
            reread = _current('pcapkit.interface', 'extract')(
                fin=extractor.output, nofile=True, store=True)
            for source_frame, pcap_frame in zip(source.frame, reread.frame):
                self.assertEqual(pcap_frame.info.packet, source_frame.info.packet)
                self.assertEqual(pcap_frame.info.time_epoch, source_frame.info.timestamp_epoch)

    def test_pcapng_mixed_link_types_are_rejected_with_no_output_file(self) -> None:
        # two Ethernet frames on interfaces whose link types disagree (Ethernet vs. RAW=12)
        order = '<'

        def block(kind: int, body: bytes) -> bytes:
            body += b'\x00' * (-len(body) % 4)
            size = 12 + len(body)
            return struct.pack(f'{order}II', kind, size) + body + struct.pack(f'{order}I', size)

        shb = block(0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))
        idb_eth = block(0x00000001, struct.pack(f'{order}HHI', 1, 0, 100))
        idb_raw = block(0x00000001, struct.pack(f'{order}HHI', 12, 0, 100))
        epb_eth = block(0x00000006, struct.pack(f'{order}IIIII', 0, 0, 1, 4, 4) + b'\x01' * 4)
        epb_raw = block(0x00000006, struct.pack(f'{order}IIIII', 1, 0, 2, 4, 4) + b'\x02' * 4)
        data = shb + idb_eth + idb_raw + epb_eth + epb_raw

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'out.pcap')
            with self.assertRaisesRegex(_current('pcapkit.utilities.exceptions', 'FormatError'),
                                        'more than one link type') as caught:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    _current('pcapkit.interface', 'extract')(
                        fin=io.BytesIO(data), fout=out, format='pcap')
            # the message names both link types and the section/interface each is on
            self.assertIn('[1]', str(caught.exception))
            self.assertIn('[12]', str(caught.exception))
            self.assertIn('0/0', str(caught.exception))
            self.assertIn('0/1', str(caught.exception))
            # forensics: nothing is left behind on a refused conversion
            self.assertEqual(os.listdir(tmp), [])
            self.assertFalse(os.path.exists(out))

    def test_pcapng_without_packets_is_rejected_with_no_output_file(self) -> None:
        order = '<'

        def block(kind: int, body: bytes) -> bytes:
            body += b'\x00' * (-len(body) % 4)
            size = 12 + len(body)
            return struct.pack(f'{order}II', kind, size) + body + struct.pack(f'{order}I', size)

        data = (block(0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))
                + block(0x00000001, struct.pack(f'{order}HHI', 1, 0, 100)))
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'out.pcap')
            with self.assertRaisesRegex(_current('pcapkit.utilities.exceptions', 'FormatError'),
                                        'no packet blocks'):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    _current('pcapkit.interface', 'extract')(
                        fin=io.BytesIO(data), fout=out, format='pcap')
            self.assertEqual(os.listdir(tmp), [])

    def test_pcapng_split_pcap_output_writes_one_capture_per_frame(self) -> None:
        data = pcapng([(1, 10, b'\x01' * 6), (2, 20, b'\x02' * 6)])
        with tempfile.TemporaryDirectory() as tmp:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = _current('pcapkit.interface', 'extract')(
                    fin=io.BytesIO(data), fout=os.path.join(tmp, 'split'),
                    format='pcap', files=True)
            self.assertEqual(extractor.format, 'pcap')
            files = sorted(os.listdir(extractor.output))
            self.assertEqual(files, ['Frame 1.pcap', 'Frame 2.pcap'])
            for name, packet in zip(files, (b'\x01' * 6, b'\x02' * 6)):
                save = read_pcap(_read(os.path.join(extractor.output, name)))
                self.assertEqual(len(save.records), 1)
                self.assertEqual(save.records[0][4], packet)

    def test_other_formats_are_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extractor = _extract(sample_path('in.pcap'), os.path.join(tmp, 'out'), format='json')
            with open(extractor.output, encoding='utf-8') as file:
                records = json.load(file)
        self.assertEqual(extractor.format, 'json')
        self.assertEqual(list(records)[0], 'Global Header')
        self.assertEqual(len(records), 1 + extractor.length)


class ThirdPartyEngineTests(unittest.TestCase):
    """These engines' frames carry no octets, so PCAP output falls back to JSON."""

    def _check(self, engine: str) -> None:
        extract = _current('pcapkit.interface', 'extract')
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertWarnsRegex(_current('pcapkit.utilities.warnings', 'FormatWarning'),
                                       "does not support 'format=pcap'"):
                extractor = extract(fin=sample_path('in.pcap'), fout=os.path.join(tmp, 'out'),
                                    format='pcap', engine=engine, nofile=False)
            self.assertEqual(extractor.format, 'json')
            with open(extractor.output, encoding='utf-8') as file:
                self.assertEqual(list(json.load(file))[0], 'Global Header')

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt(self) -> None:
        self._check('dpkt')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy(self) -> None:
        self._check('scapy')


if __name__ == '__main__':
    unittest.main()
