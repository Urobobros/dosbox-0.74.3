#!/usr/bin/env python3
import argparse
import csv
import glob
import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

MAGIC = b"HRAW"
# Header: magic[4], Bit32u version, Bit32u record_size, Bit32u count
HEADER_STRUCT = struct.Struct('<4sIII')
RECORD_STRUCT_V1 = struct.Struct('<H I B 15s I I I I I I I I H H H H H B')
RECORD_STRUCT_V2 = struct.Struct('<Q H I B 15s I I I I I I I I H H H H H B')
RECORD_STRUCT_V3 = struct.Struct('<Q I H I B 15s I I I I I I I I H H H H H B')
EXPECTED_RECORD_SIZE_V1 = RECORD_STRUCT_V1.size
EXPECTED_RECORD_SIZE_V2 = RECORD_STRUCT_V2.size
EXPECTED_RECORD_SIZE_V3 = RECORD_STRUCT_V3.size

@dataclass
class HeavyRawInst:
    seq: Optional[int]
    linear: Optional[int]
    cs: int
    eip: int
    length: int
    bytes_: bytes
    eax: int
    ebx: int
    ecx: int
    edx: int
    esi: int
    edi: int
    ebp: int
    esp: int
    ds: int
    es: int
    fs: int
    gs: int
    ss: int
    flags: int

    def opcode_hex(self) -> str:
        return ' '.join(f"{b:02X}" for b in self.bytes_[:self.length])

    def flags_bits(self) -> str:
        names = [('CF', 0x01), ('ZF', 0x02), ('SF', 0x04), ('OF', 0x08),
                 ('AF', 0x10), ('PF', 0x20), ('IF', 0x40)]
        return ' '.join(name for name, mask in names if self.flags & mask)

    def cs_eip_str(self) -> str:
        return f"{self.cs:04X}:{self.eip:08X}"

    def dump_line(self) -> str:
        regs = (f"EAX={self.eax:08X} EBX={self.ebx:08X} ECX={self.ecx:08X} "
                f"EDX={self.edx:08X} ESI={self.esi:08X} EDI={self.edi:08X} "
                f"EBP={self.ebp:08X} ESP={self.esp:08X} DS={self.ds:04X} "
                f"ES={self.es:04X} FS={self.fs:04X} GS={self.gs:04X} SS={self.ss:04X}")
        seq_prefix = "" if self.seq is None else f"seq={self.seq} "
        linear_prefix = "" if self.linear is None else f"linear={self.linear:08X} "
        return f"{seq_prefix}{linear_prefix}{self.cs_eip_str()} len={self.length:02d} bytes={self.opcode_hex():<47} flags={self.flags_bits():<15} {regs}"

def read_header(f) -> Tuple[int, int, int]:
    data = f.read(HEADER_STRUCT.size)
    if len(data) != HEADER_STRUCT.size:
        raise ValueError("File too short for header")
    magic, version, record_size, count = HEADER_STRUCT.unpack(data)
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}, expected {MAGIC!r}")
    if version == 1:
        if record_size != EXPECTED_RECORD_SIZE_V1:
            raise ValueError(f"Unexpected record size {record_size}, expected {EXPECTED_RECORD_SIZE_V1} for v1")
    elif version == 2:
        if record_size != EXPECTED_RECORD_SIZE_V2:
            raise ValueError(f"Unexpected record size {record_size}, expected {EXPECTED_RECORD_SIZE_V2} for v2")
    elif version == 3:
        if record_size != EXPECTED_RECORD_SIZE_V3:
            raise ValueError(f"Unexpected record size {record_size}, expected {EXPECTED_RECORD_SIZE_V3} for v3")
    else:
        raise ValueError(f"Unsupported version {version}")
    return count, version, record_size

def read_records(f, count: int, version: int) -> List[HeavyRawInst]:
    recs: List[HeavyRawInst] = []
    if version == 1:
        rec_struct = RECORD_STRUCT_V1
    elif version == 2:
        rec_struct = RECORD_STRUCT_V2
    elif version == 3:
        rec_struct = RECORD_STRUCT_V3
    else:
        raise ValueError(f"Unsupported version {version}")

    expected = rec_struct.size
    for idx in range(count):
        data = f.read(expected)
        if len(data) != expected:
            raise ValueError(f"Truncated at record {idx} (wanted {expected}, got {len(data)})")
        if version == 1:
            (cs, eip, length, bytes_blob,
             eax, ebx, ecx, edx, esi, edi, ebp, esp,
             ds, es, fs, gs, ss, flags) = rec_struct.unpack(data)
            seq = None
            linear = None
        elif version == 2:
            (seq, cs, eip, length, bytes_blob,
             eax, ebx, ecx, edx, esi, edi, ebp, esp,
             ds, es, fs, gs, ss, flags) = rec_struct.unpack(data)
            linear = None
        else:
            (seq, linear, cs, eip, length, bytes_blob,
             eax, ebx, ecx, edx, esi, edi, ebp, esp,
             ds, es, fs, gs, ss, flags) = rec_struct.unpack(data)
        recs.append(HeavyRawInst(
            seq=seq,
            linear=linear,
            cs=cs,
            eip=eip,
            length=length,
            bytes_=bytes_blob,
            eax=eax, ebx=ebx, ecx=ecx, edx=edx,
            esi=esi, edi=edi, ebp=ebp, esp=esp,
            ds=ds, es=es, fs=fs, gs=gs, ss=ss,
            flags=flags,
        ))
    return recs

def _expand_inputs(paths: Sequence[str]) -> List[str]:
    expanded: List[str] = []
    for p in paths:
        matches = sorted(glob.glob(p))
        if not matches:
            raise FileNotFoundError(f"No files match '{p}'")
        expanded.extend(matches)
    # Preserve original ordering with glob-sorted groups while deduplicating
    uniq: List[str] = []
    seen = set()
    for path in expanded:
        if path not in seen:
            seen.add(path)
            uniq.append(path)
    return uniq

def load_records(inputs: Sequence[str]) -> Tuple[List[HeavyRawInst], int]:
    files = _expand_inputs(inputs)
    all_recs: List[HeavyRawInst] = []
    expected_version: Optional[int] = None
    expected_record_size: Optional[int] = None
    for path in files:
        with open(path, 'rb') as fh:
            count, version, record_size = read_header(fh)
            if expected_version is None:
                expected_version = version
                expected_record_size = record_size
            else:
                if version != expected_version or record_size != expected_record_size:
                    raise ValueError(f"Incompatible file {path}: version={version}, record_size={record_size}, expected version={expected_version}, record_size={expected_record_size}")
            all_recs.extend(read_records(fh, count, version))
    if expected_version is None:
        raise ValueError("No input records loaded")
    return all_recs, expected_version

def parse_cs_eip(arg: str) -> Tuple[int, int]:
    if ':' not in arg:
        raise ValueError("Use CS:EIP format, e.g. 0F20:00012345")
    cs_s, eip_s = arg.split(':', 1)
    return int(cs_s, 16), int(eip_s, 16)

def range_filter(records: Iterable[HeavyRawInst], start: Optional[Tuple[int,int]], end: Optional[Tuple[int,int]]) -> Iterable[HeavyRawInst]:
    for rec in records:
        if start and (rec.cs < start[0] or (rec.cs == start[0] and rec.eip < start[1])):
            continue
        if end and (rec.cs > end[0] or (rec.cs == end[0] and rec.eip > end[1])):
            continue
        yield rec

def seq_filter(records: Iterable[HeavyRawInst], start: Optional[int], end: Optional[int]) -> Iterable[HeavyRawInst]:
    for rec in records:
        if rec.seq is None:
            continue
        if start is not None and rec.seq < start:
            continue
        if end is not None and rec.seq > end:
            continue
        yield rec

def write_csv(path: str, records: Iterable[HeavyRawInst]) -> None:
    with open(path, 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow([
            'seq','linear','cs','eip','len','bytes','eax','ebx','ecx','edx','esi','edi','ebp','esp','ds','es','fs','gs','ss','flags'
        ])
        for r in records:
            writer.writerow([
                '' if r.seq is None else r.seq,
                '' if r.linear is None else f"{r.linear:08X}",
                f"{r.cs:04X}", f"{r.eip:08X}", r.length,
                r.opcode_hex(),
                f"{r.eax:08X}", f"{r.ebx:08X}", f"{r.ecx:08X}", f"{r.edx:08X}",
                f"{r.esi:08X}", f"{r.edi:08X}", f"{r.ebp:08X}", f"{r.esp:08X}",
                f"{r.ds:04X}", f"{r.es:04X}", f"{r.fs:04X}", f"{r.gs:04X}", f"{r.ss:04X}",
                r.flags_bits()
            ])

def dump_records(records: Iterable[HeavyRawInst]) -> None:
    for r in records:
        print(r.dump_line())

def try_import_capstone():
    try:
        import capstone  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Capstone is required for disassembly (--disasm)") from exc
    return capstone

def disasm_records(records: Iterable[HeavyRawInst], mode_bits: int):
    capstone = try_import_capstone()
    if mode_bits == 16:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for rec in records:
        code = bytes(rec.bytes_[:rec.length])
        insn = next(md.disasm(code, rec.eip), None)
        if insn is None:
            mnemonic, op_str = 'db', rec.opcode_hex()
        else:
            mnemonic, op_str = insn.mnemonic, insn.op_str
        yield (rec, mnemonic, op_str)

def write_export_csv(path: str, items: Iterable[Tuple[HeavyRawInst,str,str]]) -> None:
    with open(path, 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(['seq','linear','cs','eip','bytes','mnemonic','operands'])
        for rec, mnemonic, op_str in items:
            writer.writerow([
                '' if rec.seq is None else rec.seq,
                '' if rec.linear is None else f"{rec.linear:08X}",
                f"{rec.cs:04X}", f"{rec.eip:08X}", rec.opcode_hex(), mnemonic, op_str
            ])

def main() -> None:
    ap = argparse.ArgumentParser(description="Parse DOSBox-X LOGCPU_RAW.BIN files (supports multiple inputs or globs)")
    ap.add_argument('inputs', nargs='+', help="Path(s) or glob(s) to LOGCPU_RAW_*.BIN")
    ap.add_argument('--csv', help="Write CSV output to file")
    ap.add_argument('--export-csv', help="Write disassembly-friendly CSV (requires --disasm)")
    ap.add_argument('--from', dest='from_addr', help="Start address filter CS:EIP (hex)")
    ap.add_argument('--to', dest='to_addr', help="End address filter CS:EIP (hex)")
    ap.add_argument('--from-seq', type=int, help="Start sequence filter (inclusive)")
    ap.add_argument('--to-seq', type=int, help="End sequence filter (inclusive)")
    ap.add_argument('--disasm', action='store_true', help="Run Capstone disassembly (optional dependency)")
    ap.add_argument('--capstone-mode', type=int, choices=[16,32], default=32, help="Capstone mode (16 or 32-bit)")
    args = ap.parse_args()

    start_addr = parse_cs_eip(args.from_addr) if args.from_addr else None
    end_addr = parse_cs_eip(args.to_addr) if args.to_addr else None

    records, version = load_records(args.inputs)

    filtered = list(range_filter(records, start_addr, end_addr))
    if args.from_seq is not None or args.to_seq is not None:
        filtered = list(seq_filter(filtered, args.from_seq, args.to_seq))
    if args.disasm:
        items = list(disasm_records(filtered, args.capstone_mode))
    else:
        items = None

    if args.export_csv:
        if not args.disasm:
            raise RuntimeError("--export-csv requires --disasm")
        write_export_csv(args.export_csv, items)
    elif args.csv:
        write_csv(args.csv, filtered)
    else:
        if items is None:
            dump_records(filtered)
        else:
            for rec, mnem, op_str in items:
                seq_prefix = "" if rec.seq is None else f"{rec.seq}: "
                linear_prefix = "" if rec.linear is None else f"[{rec.linear:08X}] "
                print(f"{seq_prefix}{linear_prefix}{rec.cs_eip_str()} {mnem} {op_str}")

if __name__ == '__main__':
    main()
