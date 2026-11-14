# -*- coding: utf-8 -*-
"""PCAP-NG to PCAP conversion planning
========================================

.. module:: pcapkit.foundation.engines.pcapng_pcap

A classic PCAP file carries one global header -- one link type, one snapshot
length, one timestamp resolution and one byte order -- where a PCAP-NG file
declares them per section and per interface. Before a PCAP-NG capture can be
written out as PCAP, the whole file therefore has to be surveyed for the
values that single header must take. :func:`plan_pcap_output` performs that
survey without dissecting a single packet: it walks the block framing only,
and answers every question the
:class:`~pcapkit.dumpkit.pcap.PCAPIO` global header asks.

The survey is deliberately separate from the extraction pass. The extraction
pass parses every block through the protocol stack; the survey needs the block
headers alone, and runs first so that a capture the PCAP container cannot hold
-- interfaces whose link types disagree -- is rejected *before* any output
file exists. A forensic conversion may not leave a partial capture behind.

"""
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.protocols.misc.pcap.header.schema import RESOLUTION as PCAP_RESOLUTION
from pcapkit.protocols.misc.pcapng.schema import (BYTE_ORDER_MAGIC,
                                                  DEFAULT_RESOLUTION,
                                                  GENERIC_BLOCK_MINIMUM)
from pcapkit.utilities.exceptions import FormatError

__all__ = ['PCAPOutputPlan', 'plan_pcap_output']

if TYPE_CHECKING:
    from typing import IO, Literal, Optional

#: Block types that carry a captured packet, mapped to the tag used when an
#: error names one. Kept in step with
#: :attr:`PCAPNG.PACKET_BLOCK_TYPES
#: <pcapkit.foundation.engines.pcapng.PCAPNG.PACKET_BLOCK_TYPES>`.
_PACKET_BLOCK_TYPES = {
    Enum_BlockType.Simple_Packet_Block: 'SPB',
    Enum_BlockType.Enhanced_Packet_Block: 'EPB',
    Enum_BlockType.Packet_Block: 'Packet',
}  # type: dict[int, str]

#: The two timestamp resolutions a classic PCAP global header can declare,
#: microseconds and nanoseconds, in units per second.
_PCAP_RESOLUTIONS = frozenset(PCAP_RESOLUTION.values())


@dataclass(frozen=True)
class _Interface:
    """One interface of one section, as the survey needs it.

    Args:
        linktype: The interface's link type.
        snaplen: The interface's snapshot length, ``0`` meaning no limit.
        resolution: The interface's timestamp resolution, in units per second.
        byteorder: Byte order of the section the interface belongs to.

    """

    linktype: 'Enum_LinkType'
    snaplen: 'int'
    resolution: 'int'
    byteorder: 'Literal["big", "little"]'


@dataclass(frozen=True)
class PCAPOutputPlan:
    """The global-header fields a PCAP-NG capture converts to.

    Every field follows the rule the conversion promises:

    * :attr:`linktype` -- the link type of the interfaces that carry packets,
      which the survey proved all agree on;
    * :attr:`snaplen` -- the largest snapshot length among those interfaces;
    * :attr:`nanosecond` -- :data:`True` when the finest timestamp resolution
      among them is nanoseconds, :data:`False` for microseconds;
    * :attr:`byteorder` -- the byte order of the section the first packet
      block belongs to, which a single PCAP header has to speak for every
      record.

    """

    linktype: 'Enum_LinkType'
    snaplen: 'int'
    nanosecond: 'bool'
    byteorder: 'Literal["big", "little"]'


def _read_exact(stream: 'IO[bytes]', size: 'int') -> 'bytes':
    """Read exactly ``size`` octets from ``stream``, or raise at a short read.

    Args:
        stream: The surveyed input, positioned where the read starts.
        size: Number of octets required.

    Returns:
        The octets read.

    Raises:
        FormatError: If the stream ends before ``size`` octets arrive. A block
            whose framing runs past the end of the capture is malformed, and
            the survey reports it as a format error rather than treating the
            short block as the end of the file.

    """
    data = stream.read(size)
    if len(data) != size:
        raise FormatError(f'PCAP-NG: truncated block: expected {size} octets, got {len(data)}')
    return data


def _idb_resolution(body: 'bytes', byteorder: 'Literal["big", "little"]') -> 'int':
    """Timestamp resolution an Interface Description Block's options declare.

    Args:
        body: The IDB body octets -- everything between the leading block
            framing (type and total length) and the trailing total length.
        byteorder: Byte order of the section the IDB belongs to.

    Returns:
        The resolution in units per second: the value of an ``if_tsresol``
        option if the IDB carries one, otherwise the format's microsecond
        default, :data:`~pcapkit.protocols.misc.pcapng.schema.DEFAULT_RESOLUTION`.

    The option area starts after the IDB's eight fixed body octets
    (link type, reserved, snapshot length). Each option is a two-octet code,
    a two-octet length and that many value octets, padded to a 32-bit
    boundary; a zero code ends the area. The survey reads the codes and
    lengths itself rather than parsing the options through the schema layer,
    since it must not dissect anything.

    """
    offset = 8
    while offset + 4 <= len(body):
        code = int.from_bytes(body[offset:offset + 2], byteorder)
        length = int.from_bytes(body[offset + 2:offset + 4], byteorder)
        if not code:  # opt_endofopt
            break
        value_start = offset + 4
        value_end = value_start + length
        if value_end > len(body):  # malformed option area; nothing more to read
            break
        if code == Enum_OptionType.if_tsresol and length == 1:
            octet = body[value_start]
            base = 2 if octet & 0x80 else 10
            return base ** (octet & 0x7F)
        offset = value_end + (-length % 4)
    return DEFAULT_RESOLUTION


def plan_pcap_output(stream: 'IO[bytes]') -> 'PCAPOutputPlan':
    """Survey a PCAP-NG capture for the PCAP global header it converts to.

    The survey walks every section of ``stream`` from its beginning, reading
    block framing and Interface Description Blocks only. It restores the stream
    position it was given on entry.

    Starting at the beginning rather than at the caller's position keeps the
    first Section Header Block's framing intact: its block type and total length
    are the only bytes that identify the section before its Byte-Order Magic
    settles the byte order, and the engine has normally consumed them already.

    Args:
        stream: A seekable binary input holding a PCAP-NG capture -- an
            extractor's :attr:`~pcapkit.foundation.extraction.Extractor._ifile`.

    Returns:
        The :class:`PCAPOutputPlan` the conversion opens its PCAP writer with.

    Raises:
        FormatError: If a block is truncated or its total length is invalid; if
            a packet block names an interface its section does not describe; or
            if the interfaces that carry packets do not share one link type.
            The last case names every link type seen, each with the sections
            and interfaces that declared it, so the mismatch is traceable.

    Note:
        A capture with no packet blocks has nothing a PCAP file could hold, so
        the survey rejects it rather than inventing a header for zero records.

    """
    position = stream.tell()
    try:
        stream.seek(0, os.SEEK_SET)
        return _survey(stream)
    finally:
        stream.seek(position, os.SEEK_SET)


def _survey(stream: 'IO[bytes]') -> 'PCAPOutputPlan':
    """The survey itself, :func:`plan_pcap_output` restores the position."""
    byteorder = 'little'  # type: Literal['big', 'little']
    #: Every section's interfaces, as flat section-local lists become global
    #: block references: section index -> that section's interfaces.
    sections = []         # type: list[list[_Interface]]
    #: The section currently being walked; ``None`` only before the first SHB.
    current = None        # type: Optional[list[_Interface]]

    #: Interfaces that actually carry at least one packet block, identified by
    #: ``(section index, interface ID)``, in first-use order.
    used = []             # type: list[tuple[int, int]]
    used_seen = set()     # type: set[tuple[int, int]]

    while True:
        head = stream.read(8)
        if not head:
            break
        if len(head) != 8:
            raise FormatError(f'PCAP-NG: truncated block header: got {len(head)} octets')

        # A Section Header Block's type reads the same in either byte order, and
        # a new section may switch byte order. Its length therefore cannot be
        # parsed in the running (previous section's) byte order: the block is
        # read whole by its fixed framing, and its own Byte-Order Magic declares
        # the order for everything after it, including the trailing length.
        if head[:4] == Enum_BlockType.Section_Header_Block.to_bytes(4, 'big'):
            magic = _read_exact(stream, 4)
            if magic == BYTE_ORDER_MAGIC.to_bytes(4, 'big'):
                byteorder = 'big'
            elif magic == BYTE_ORDER_MAGIC.to_bytes(4, 'little'):
                byteorder = 'little'
            else:
                raise FormatError(f'PCAP-NG: [SHB] unknown byte-order magic: {magic!r}')
            total_length = int.from_bytes(head[4:8], byteorder)
            if total_length < GENERIC_BLOCK_MINIMUM or total_length % 4:
                raise FormatError(
                    f'PCAP-NG: [SHB] invalid block total length {total_length}')
            # Four magic octets already consumed; read the remainder of the
            # block, the trailing total length included, and verify it.
            remainder = _read_exact(stream, total_length - 12)
            trailing = int.from_bytes(remainder[-4:], byteorder)
            if trailing != total_length:
                raise FormatError(
                    f'PCAP-NG: [SHB] mismatched total lengths: '
                    f'{total_length} != {trailing}')
            current = []
            sections.append(current)
            continue

        block_type = int.from_bytes(head[:4], byteorder)
        total_length = int.from_bytes(head[4:8], byteorder)
        if total_length < GENERIC_BLOCK_MINIMUM or total_length % 4:
            raise FormatError(
                f'PCAP-NG: invalid block total length {total_length} for block type '
                f'0x{block_type:08X}')

        # The eight framing octets already read; the body runs to the trailing
        # total length, which is itself four octets.
        body = _read_exact(stream, total_length - 8)
        trailing = int.from_bytes(body[-4:], byteorder)
        if trailing != total_length:
            raise FormatError(
                f'PCAP-NG: block type 0x{block_type:08X} has mismatched total lengths: '
                f'{total_length} != {trailing}')
        body = body[:-4]

        if block_type == Enum_BlockType.Interface_Description_Block:
            if current is None:
                # Defensive: a well-formed capture opens every section with an
                # SHB, which sets ``current``. An IDB ahead of one is malformed.
                current = []
                sections.append(current)
            linktype = Enum_LinkType.get(int.from_bytes(body[:2], byteorder))
            snaplen = int.from_bytes(body[4:8], byteorder)
            resolution = _idb_resolution(body, byteorder)
            current.append(_Interface(linktype, snaplen, resolution, byteorder))
            continue

        tag = _PACKET_BLOCK_TYPES.get(block_type)
        if tag is None:
            continue  # NRB, ISB, DSB, custom, unknown blocks carry no packets

        if current is None:
            raise FormatError(f'PCAP-NG: [{tag}] packet block outside a section')

        if block_type == Enum_BlockType.Simple_Packet_Block:
            interface_id = 0
        elif block_type == Enum_BlockType.Packet_Block:
            interface_id = int.from_bytes(body[:2], byteorder)
        else:  # Enhanced Packet Block
            interface_id = int.from_bytes(body[:4], byteorder)

        section_index = len(sections) - 1
        if not 0 <= interface_id < len(current):
            raise FormatError(
                f'PCAP-NG: [{tag}] invalid interface ID: {interface_id} '
                f'(section {section_index} describes {len(current)})')

        key = (section_index, interface_id)
        if key not in used_seen:
            used_seen.add(key)
            used.append(key)

    if not used:
        raise FormatError('PCAP-NG: no packet blocks found, nothing to convert to PCAP')

    used_interfaces = [sections[section_index][interface_id]
                       for section_index, interface_id in used]

    linktypes = {}  # type: dict[int, list[tuple[int, int]]]
    for (section_index, interface_id), interface in zip(used, used_interfaces):
        linktypes.setdefault(int(interface.linktype), []).append((section_index, interface_id))
    if len(linktypes) > 1:
        detail = ', '.join(
            f'{Enum_LinkType.get(code)!r} [{code}] at section/interface '
            + ', '.join(f'{section}/{interface_id}'
                        for section, interface_id in sorted(locations))
            for code, locations in sorted(linktypes.items())
        )
        raise FormatError(
            f'PCAP-NG: cannot write a PCAP file whose packets use more than one link type: {detail}')

    plan_linktype = used_interfaces[0].linktype
    plan_snaplen = max(interface.snaplen for interface in used_interfaces)
    finest = max(interface.resolution for interface in used_interfaces)
    if finest in _PCAP_RESOLUTIONS:
        plan_nanosecond = finest == PCAP_RESOLUTION[True]
    else:
        # An interface on a non-power-of-ten resolution (e.g. 2**-n) cannot be
        # represented exactly; take nanoseconds whenever it is finer than a
        # microsecond, the closest PCAP resolution, and microseconds otherwise.
        plan_nanosecond = finest > PCAP_RESOLUTION[False]
    plan_byteorder = used_interfaces[0].byteorder

    return PCAPOutputPlan(plan_linktype, plan_snaplen, plan_nanosecond, plan_byteorder)
