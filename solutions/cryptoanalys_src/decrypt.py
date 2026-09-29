import sys

MASK32 = 0xFFFFFFFF
SEED_MUL = 952749472
SEED_ADD = -1640519190
LCG_STEP = 1103515245

BYTE_CONSTS = [
    1640531535, 0, -1640531535, 1013904226,
    -626627309, 2027808452, 387276917, -1253254618,
    1401181143, -239350392, -1879881927, 774553834,
    -865977701, 1788458060, 147926525, -1492605010,
]

SECTOR_SIZE = 512
BLOCK_SIZE = 16
BLOCKS_PER_SECTOR = 32
NUM_SECTORS = 2048
STORAGE_OFFSET = 0x100000
STORAGE_SIZE = 0x100000


def key_byte(v10, c):
    return ((v10 + c) & MASK32) >> 24


def keystream_block(v10):
    return bytes(key_byte(v10, c) for c in BYTE_CONSTS)


def sector_seed(lba):
    return (SEED_MUL * lba + SEED_ADD) & MASK32


def process_sector(lba, data):
    out = bytearray(SECTOR_SIZE)
    v10 = sector_seed(lba)
    for i in range(BLOCKS_PER_SECTOR):
        ks = keystream_block(v10)
        base = i * BLOCK_SIZE
        for j in range(BLOCK_SIZE):
            out[base + j] = data[base + j] ^ ks[j]
        v10 = (v10 + LCG_STEP) & MASK32
    return bytes(out)


def process_image(data, start_lba=0):
    out = bytearray(len(data))
    n = len(data) // SECTOR_SIZE
    for i in range(n):
        lba = start_lba + i
        chunk = data[i * SECTOR_SIZE:(i + 1) * SECTOR_SIZE]
        out[i * SECTOR_SIZE:(i + 1) * SECTOR_SIZE] = process_sector(lba, chunk)
    return bytes(out)


def process_firmware(fw, offset=STORAGE_OFFSET, size=STORAGE_SIZE):
    if len(fw) < offset + size:
        size = max(0, len(fw) - offset)
    size = (size // SECTOR_SIZE) * SECTOR_SIZE
    region = fw[offset:offset + size]
    return process_image(region, 0)


def main():
    if len(sys.argv) < 3:
        print("usage: python cybersafe.py <in.bin> <out.bin> [storage|raw] [offset]")
        sys.exit(1)

    in_path = sys.argv[1]
    out_path = sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else "storage"
    offset = int(sys.argv[4], 0) if len(sys.argv) > 4 else STORAGE_OFFSET

    with open(in_path, "rb") as f:
        blob = f.read()

    if mode == "storage":
        result = process_firmware(blob, offset)
    else:
        if len(blob) % SECTOR_SIZE:
            blob = blob[: (len(blob) // SECTOR_SIZE) * SECTOR_SIZE]
        result = process_image(blob, 0)

    with open(out_path, "wb") as f:
        f.write(result)

    print("done:", out_path, len(result), "bytes")


if __name__ == "__main__":
    main()
