#!/usr/bin/env python3
import argparse
import csv
import struct
from dataclasses import dataclass
from typing import List, Tuple, Iterable, Optional

MAGIC = b"HRAW"
HEADER_STRUCT = struct.Struct('<4sHHI')
RECORD_STRUCT = struct.Struct('<H I B 15s I I I I I I I I H H H H H B')
EXPECTED_RECORD_SIZE = RECORD_STRUCT.size

@dataclass
class HeavyRawInst:
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
        return f"{self.cs_eip_str()} len={self.length:02d} bytes={self.opcode_hex():<47} flags={self.flags_bits():<15} {regs}"

def read_header(f) -> Tuple[int, int]:
    data = f.read(HEADER_STRUCT.size)
    if len(data) != HEADER_STRUCT.size:
        raise ValueError("File too short for header")
    magic, version, record_size, count = HEADER_STRUCT.unpack(data)
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}, expected {MAGIC!r}")
    if record_size != EXPECTED_RECORD_SIZE:
        raise ValueError(f"Unexpected record size {record_size}, expected {EXPECTED_RECORD_SIZE}")
    return count, version

def read_records(f, count: int) -> List[HeavyRawInst]:
    recs: List[HeavyRawInst] = []
    for idx in range(count):
        data = f.read(EXPECTED_RECORD_SIZE)
        if len(data) != EXPECTED_RECORD_SIZE:
            raise ValueError(f"Truncated at record {idx} (wanted {EXPECTED_RECORD_SIZE}, got {len(data)})")
        (cs, eip, length, bytes_blob,
         eax, ebx, ecx, edx, esi, edi, ebp, esp,
         ds, es, fs, gs, ss, flags) = RECORD_STRUCT.unpack(data)
        recs.append(HeavyRawInst(
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

def write_csv(path: str, records: Iterable[HeavyRawInst]) -> None:
    with open(path, 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow([
            'cs','eip','len','bytes','eax','ebx','ecx','edx','esi','edi','ebp','esp','ds','es','fs','gs','ss','flags'
        ])
        for r in records:
            writer.writerow([
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

def main() -> None:
    ap = argparse.ArgumentParser(description="Parse DOSBox-X LOGCPU_RAW.BIN")
    ap.add_argument('input', help="Path to LOGCPU_RAW.BIN")
    ap.add_argument('--csv', help="Write CSV output to file")
    ap.add_argument('--from', dest='from_addr', help="Start address filter CS:EIP (hex)")
    ap.add_argument('--to', dest='to_addr', help="End address filter CS:EIP (hex)")
    args = ap.parse_args()

    start_addr = parse_cs_eip(args.from_addr) if args.from_addr else None
    end_addr = parse_cs_eip(args.to_addr) if args.to_addr else None

    with open(args.input, 'rb') as fh:
        count, version = read_header(fh)
        records = read_records(fh, count)

    filtered = list(range_filter(records, start_addr, end_addr))

    if args.csv:
        write_csv(args.csv, filtered)
    else:
        dump_records(filtered)

if __name__ == '__main__':
    main()
