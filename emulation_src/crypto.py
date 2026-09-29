from typing import Any
from constants import STORAGE_PERM, STORAGE_KEYS


def decrypt_sector(img: bytes, sec: int) -> bytes:
    state = (sec * 0x38C9CDA0 + 0x9E37A9EA) & 0xFFFFFFFF
    out = bytearray()
    for b in range(32):
        for k in range(16):
            ci = STORAGE_PERM[k]
            kc = state if ci == 0x10 else (state + STORAGE_KEYS[ci])
            out.append(img[0x100000 + sec * 512 + b * 16 + k] ^ ((kc & 0xFFFFFFFF) >> 24))
        state = (state + 0x41C64E6D) & 0xFFFFFFFF
    return bytes(out)


def build_disk(img: bytes, path: str) -> str:
    disk = bytearray(2048 * 512)
    for s in range(1408):
        disk[s * 512:(s + 1) * 512] = decrypt_sector(img, s)
    with open(path, 'wb') as f:
        f.write(bytes(disk))
    return path


def build_disk_emu(t: Any, img: bytes, path: str) -> str:
    disk = bytearray(2048 * 512)
    for s in range(1408):
        disk[s * 512:(s + 1) * 512] = t.emu_decrypt_sector(s)
    with open(path, 'wb') as f:
        f.write(bytes(disk))
    return path
