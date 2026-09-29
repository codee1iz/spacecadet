import argparse
import os
import sys
import struct
import platform
import subprocess

from emulator import Token
from crypto import build_disk_emu
from constants import HERE


def validate_firmware(img: bytes) -> None:
    if len(img) < 0x7000:
        raise ValueError('Invalid firmware length.')

    if img[0xC78:0xC80] != bytes.fromhex('0123524601244546'):
        raise ValueError('Invalid firmware signature.')

    ref = struct.unpack_from('<I', img, 0xE10)[0]
    auth = struct.unpack_from('<I', img, 0xE14)[0]

    if ref != 0x100054FF or auth != 0x20002ED2:
        raise ValueError('Invalid reference literals.')

    if img[0x4EC:0x4F4] != bytes.fromhex('f4fdffffa0cdc938'):
        raise ValueError('Invalid crypto pool.')


def mount_image(disk_path: str) -> None:
    sys_name = platform.system()

    if sys_name == 'Darwin':
        try:
            subprocess.run(['diskutil', 'image', 'attach', '--readOnly', disk_path])
        except FileNotFoundError:
            print(f"macOS: hdiutil not found, but image created at {disk_path}")
    elif sys_name == 'Linux':
        print(
            "\n[!] Linux mounting instructions:\n"
            "    sudo mkdir -p /mnt/token\n"
            f"    sudo mount -o loop,ro {disk_path} /mnt/token"
        )
    elif sys_name == 'Windows':
        print(
            "\n[!] Windows mounting instructions:\n"
            f"    Use OSFMount or ImDisk to attach {disk_path} as a virtual drive."
        )
    else:
        print(f"\n[!] Disk image successfully generated at: {disk_path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', default='usb_token_original.bin')
    ap.add_argument('-o', '--out', default='token_disk.img')
    ap.add_argument('--no-mount', action='store_true')
    ap.add_argument('--no-boot', action='store_true')
    args = ap.parse_args()

    fw_path = args.file if os.path.isabs(args.file) else os.path.join(HERE, args.file)

    if not os.path.exists(fw_path):
        return 1

    with open(fw_path, 'rb') as f:
        img = f.read()

    try:
        validate_firmware(img)
    except ValueError:
        return 1

    t = Token(img)

    if not args.no_boot:
        t.boot(max_insn=1500000, idle_seen=10)

    pin = t.crack_pin()
    if pin is None:
        return 1

    t.setup_emu_decrypt()
    emu_s0 = t.emu_decrypt_sector(0)

    if emu_s0[:11] != b'\xeb<\x90MSDOS5.0' or emu_s0[54:59] != b'FAT12':
        return 1

    disk_path = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
    build_disk_emu(t, img, disk_path)

    if not args.no_mount:
        mount_image(disk_path)

    return 0


if __name__ == '__main__':
    sys.exit(main())
