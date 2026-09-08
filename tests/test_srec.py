"""S-record parsing."""

from subaru_pak import srec

S1 = b"S1130000" + b"00" * 16
LINE = b"S1130000000102030405060708090A0B0C0D0E0F00"


def _line(kind, addr, payload):
    """Build a well-formed S-record (checksum byte is not validated on read)."""
    addr_hex = {1: f"{addr:04X}", 2: f"{addr:06X}", 3: f"{addr:08X}"}[kind]
    count = len(addr_hex) // 2 + len(payload) + 1
    return f"S{kind}{count:02X}{addr_hex}{payload.hex().upper()}00".encode()


def test_parses_s1_s2_s3_addresses():
    blob = b"\r\n".join([_line(1, 0x0010, b"\xAA" * 4),
                         _line(2, 0x010000, b"\xBB" * 4),
                         _line(3, 0x00020000, b"\xCC" * 4)])
    parsed = srec.parse(blob)
    assert parsed.count == 3
    assert parsed.start == 0x10
    assert parsed.end == 0x20004
    assert parsed.data[0x10:0x14] == b"\xAA" * 4
    assert parsed.data[0x10000:0x10004] == b"\xBB" * 4
    assert parsed.data[0x20000:0x20004] == b"\xCC" * 4


def test_mask_marks_only_addressed_bytes():
    parsed = srec.parse(_line(1, 0x100, b"\x01\x02"))
    assert parsed.mask[0x100:0x102] == bytearray(b"\x01\x01")
    assert parsed.mask[0xFF] == 0
    assert parsed.mask[0x102:] == bytearray()


def test_ignores_headers_terminators_and_junk():
    blob = b"\r\n".join([b"S00600004844521B",          # S0 header
                         _line(1, 0, b"\x01" * 4),
                         b"S9030000FC",                # S9 terminator
                         b"garbage",
                         b""])
    parsed = srec.parse(blob)
    assert parsed.count == 1
    assert parsed.end == 4


def test_ignores_malformed_records_without_failing():
    blob = b"\r\n".join([b"S1130000ZZ", b"S1", _line(1, 0, b"\x07")])
    parsed = srec.parse(blob)
    assert parsed.count == 1
    assert parsed.data == bytearray(b"\x07")


def test_later_records_overwrite_earlier_ones():
    blob = b"\r\n".join([_line(1, 0, b"\x11\x11"), _line(1, 0, b"\x22\x22")])
    assert srec.parse(blob).data == bytearray(b"\x22\x22")


def test_empty_input_is_falsey():
    parsed = srec.parse(b"")
    assert not parsed
    assert parsed.count == 0 and parsed.end == 0


def test_accepts_text_as_well_as_bytes():
    assert srec.parse(_line(1, 0, b"\x01").decode("ascii")).count == 1


def test_lf_only_line_endings():
    blob = b"\n".join([_line(1, 0, b"\x01" * 4), _line(1, 4, b"\x02" * 4)])
    assert srec.parse(blob).end == 8
