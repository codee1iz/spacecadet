import struct
from typing import Dict, Set, List, Optional, Any
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_PC, UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_R0, UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R6
from unicorn.arm_const import UC_ARM_REG_R8, UC_ARM_REG_R10

from constants import (
    FLASH_BASE, FLASH_SIZE, RAM_BASE, RAM_SIZE,
    SPIN_PATCHES, INSN_PATCHES, MMIO,
    ROM_FUNC_BASE, ROM_CODE, BOOTROM_TABLE_OFF, BOOTROM_LOOKUP_OFF, ROM_LOOKUP_MAGIC,
    SP_INIT, PC_RESET,
    DECRYPT_RET, EMU_SP, EMU_DEST, DECRYPT_FN,
    CRACK_SP, CRACK_DIG, CRACK_AUTH, CRACK_REF, CRACK_BUF
)
from flash import SPIFlash


class Token:

    def __init__(self, img: bytes) -> None:
        self.img: bytes = img
        self.vtime: int = 0
        self.insn: int = 0
        self.log_limit: Set[int] = set()
        self.trace: List[int] = []
        self.uc: Uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        self._map()
        self._hooks()

        self.uc.mem_write(FLASH_BASE, img[:FLASH_SIZE])
        self.uc.mem_write(RAM_BASE, img[0x100:0x100 + 0xC0])

        for a in SPIN_PATCHES:
            self.uc.mem_write(FLASH_BASE + a, b'\xbf\x00')

        for a, n in INSN_PATCHES:
            self.uc.mem_write(FLASH_BASE + a, b'\xbf\x00' * (n // 2))

        blob = bytearray(img[:FLASH_SIZE])
        code_end = 0x67F0
        offs: Set[int] = set()

        for i in range(code_end - 3):
            b0, b1, b2, b3 = blob[i], blob[i+1], blob[i+2], blob[i+3]
            if b0 == 0xEF and b1 == 0xF3 and b2 == 0x10 and (b3 & 0xF0) == 0x80:
                offs.add(i)
            elif (b0 & 0xF0) == 0x80 and b1 == 0xF3 and b2 == 0x10 and b3 == 0x88:
                offs.add(i)

        for i in offs:
            self.uc.mem_write(FLASH_BASE + i, b'\xbf\x00\xbf\x00')

        self._primask_n: int = len(offs)
        offs2: Set[int] = set()

        for i in range(code_end - 1):
            if blob[i] in (0x20, 0x30) and blob[i + 1] == 0xBF:
                hprev = (blob[i - 1] << 8) | (blob[i - 2] if i >= 2 else 0)
                if hprev < 0xE800:
                    offs2.add(i)

        for i in offs2:
            self.uc.mem_write(FLASH_BASE + i, b'\xbf\x00')

        self._hint_n: int = len(offs2)
        self._rom_setup()
        self._spi: SPIFlash = SPIFlash(img)

    def _map(self) -> None:
        self.uc.mem_map(FLASH_BASE, FLASH_SIZE)
        self.uc.mem_map(RAM_BASE, RAM_SIZE)
        try:
            self.uc.mem_map(0x0, 0x10000)
        except UcError:
            pass
        try:
            self.uc.mem_map(0x1FF00000, 0x100000)
        except UcError:
            pass
        try:
            self.uc.mem_map(0xFFF00000, 0x100000)
        except UcError:
            pass
        for a, s, _ in MMIO:
            self.uc.mem_map(a, s)

    def _hooks(self) -> None:
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code, begin=FLASH_BASE, end=FLASH_BASE + FLASH_SIZE)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_all)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_low, begin=0x0, end=0x2000)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_rom, begin=ROM_LOOKUP_MAGIC, end=ROM_FUNC_BASE + 0x400)
        for a, s, _ in MMIO:
            self.uc.hook_add(UC_HOOK_MEM_READ, self._mem_read, begin=a, end=a + s)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._mem_write_ssi, begin=0x18000000, end=0x18000060)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._bad_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._bad_write)

    def _hook_all(self, uc: Uc, address: int, size: int, data: Any) -> None:
        self.insn += 1

    def _hook_code(self, uc: Uc, address: int, size: int, data: Any) -> None:
        if address == 0x100025C8:
            self.vtime += 10
        self.trace.append(address)
        if len(self.trace) > 40:
            self.trace = self.trace[-40:]

    def _hook_low(self, uc: Uc, address: int, size: int, data: Any) -> None:
        lr = uc.reg_read(UC_ARM_REG_LR)
        if not (0x10000000 <= lr < 0x10200000):
            lr = 0x100028E0
        uc.reg_write(UC_ARM_REG_PC, lr)

    def _rom_setup(self) -> None:
        self._rom_by_code: Dict[int, int] = {}
        self._rom_name: Dict[int, str] = {}
        self._rom_missing: Set[int] = set()
        self._rom_calls: Dict[str, int] = {}

        addr = ROM_FUNC_BASE
        for code, name in ROM_CODE.items():
            self._rom_by_code[code] = addr
            self._rom_name[addr] = name
            addr += 4

        self._rom_stub = addr
        self._rom_name[addr] = 'stub'

        self.uc.mem_write(BOOTROM_TABLE_OFF, struct.pack('<H', 0x2E00))
        self.uc.mem_write(BOOTROM_LOOKUP_OFF, struct.pack('<H', ROM_LOOKUP_MAGIC | 1))

        DATA_FROM, DATA_TO, DATA_LEN = 0x5718, 0x200000C0, 0x10D8
        self.uc.mem_write(DATA_TO, self.img[DATA_FROM:DATA_FROM + DATA_LEN])

        for off, tag in ((0x00, 0x534D), (0x04, 0x434D), (0x08, 0x3453), (0x0C, 0x3443)):
            self.uc.mem_write(0x20001160 + off, struct.pack('<I', self._rom_by_code[tag] | 1))

    def _hook_rom(self, uc: Uc, address: int, size: int, data: Any) -> None:
        lr = uc.reg_read(UC_ARM_REG_LR)
        if address == ROM_LOOKUP_MAGIC:
            code = uc.reg_read(UC_ARM_REG_R1) & 0xFFFF
            addr = self._rom_by_code.get(code)
            if addr is None:
                if code not in self._rom_missing:
                    self._rom_missing.add(code)
                addr = self._rom_stub
            uc.reg_write(UC_ARM_REG_R0, addr | 1)
        else:
            name = self._rom_name.get(address, 'stub')
            self._rom_calls[name] = self._rom_calls.get(name, 0) + 1
            self._rom_call(uc, name)
        uc.reg_write(UC_ARM_REG_PC, lr)

    def _rom_call(self, uc: Uc, name: str) -> None:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)

        if name in ('MC', 'C4'):
            if r2:
                uc.mem_write(r0, bytes(uc.mem_read(r1, r2)))
            uc.reg_write(UC_ARM_REG_R0, r0)
        elif name in ('MS', 'S4'):
            if r2:
                uc.mem_write(r0, bytes([r1 & 0xFF]) * r2)
            uc.reg_write(UC_ARM_REG_R0, r0)
        elif name == 'L3':
            uc.reg_write(UC_ARM_REG_R0, (32 - (r0.bit_length())) if r0 else 32)
        elif name == 'T3':
            uc.reg_write(UC_ARM_REG_R0, (r0 & -r0).bit_length() - 1 if r0 else 32)
        elif name == 'P3':
            uc.reg_write(UC_ARM_REG_R0, bin(r0 & 0xFFFFFFFF).count('1'))
        elif name == 'R3':
            v = r0 & 0xFFFFFFFF
            uc.reg_write(UC_ARM_REG_R0, int('{:032b}'.format(v)[::-1], 2))

    def _reg32(self, address: int, value: int) -> None:
        self.uc.mem_write(address, struct.pack('<I', value & 0xFFFFFFFF))

    def _mem_read(self, uc: Uc, access: int, address: int, size: int, value: int, data: Any) -> None:
        if size != 4:
            return

        if address in (0x40054024,):
            self._reg32(address, (self.vtime >> 32) & 0xFFFFFFFF)
        elif address == 0x40054028:
            self._reg32(address, self.vtime & 0xFFFFFFFF)
        elif address in (0x40054008,):
            self._reg32(address, 0)
        elif address == 0x4000C008:
            self._reg32(address, 0xFFFFFFFF)
        elif address == 0x40024004:
            self._reg32(address, 0x80000000)
        elif 0x40028000 <= address < 0x40029000 or 0x4002C000 <= address < 0x4002D000:
            self._reg32(address, 0x80000000)
        elif (0xD0000100 <= address < 0xD0000200) or address == 0xD00009C0:
            self._reg32(address, 1)
        elif 0x40008000 <= address <= 0x4000BFFF:
            cur = int.from_bytes(self.uc.mem_read(address, 4), 'little')
            self._reg32(address, cur if cur else 1)
        elif address == 0x18000028:
            sr = 0x02
            if self._spi.pending():
                sr |= 0x0C
            self._reg32(address, sr)
        elif address == 0x18000060:
            self._reg32(address, self._spi.rx())

    def _mem_write_ssi(self, uc: Uc, access: int, address: int, size: int, value: int, data: Any) -> None:
        if address == 0x18000060:
            self._spi.tx(value & 0xFF)

    def _bad_read(self, uc: Uc, access: int, address: int, size: int, value: int, data: Any) -> bool:
        return False

    def _bad_write(self, uc: Uc, access: int, address: int, size: int, value: int, data: Any) -> bool:
        return False

    def _patch_insn(self, pc: int) -> bool:
        b = self.uc.mem_read(pc, 4)
        if not b or len(b) != 4:
            return False

        h0 = b[0] | (b[1] << 8)
        h0s = (b[0] << 8) | b[1]

        if (
            h0 in (0xEFF3, 0x80F3, 0x81F3, 0x8CF3, 0x80F3, 0xF381, 0xF3EF, 0xF38C)
            or 0xF380 <= h0 <= 0xF3FF
            or 0xF380 <= h0s <= 0xF3FF
            or h0s in (0xEFF3, 0x80F3, 0x81F3, 0x8CF3, 0xF381)
        ):
            if (b[2] & 0x80):
                rd = (b[2] >> 4) & 0xF
                ins = bytes([0x00, 0x20 | rd]) + b'\xbf\x00'
            else:
                ins = b'\xbf\x00\xbf\x00'
            self.uc.mem_write(pc, ins)
            return True
        return False

    def boot(self, max_insn: int = 400000000, idle_seen: int = 200) -> bool:
        self.uc.reg_write(UC_ARM_REG_SP, SP_INIT)
        self.uc.reg_write(UC_ARM_REG_PC, PC_RESET | 1)
        self.uc.reg_write(UC_ARM_REG_LR, 0xFFFFFFFF)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x20)

        self._semipatched: Set[int] = set()
        cursors: Dict[int, int] = {}
        runs = 0

        while self.insn < max_insn:
            before = self.insn
            try:
                self.uc.emu_start((PC_RESET | 1) & 0xFFFFFFFE | 1, 0x10000001, count=1 << 20, timeout=0)
            except UcError as e:
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                if 'INSN_INVALID' in str(e) and self._patch_insn(pc):
                    self._semipatched.add(pc)
                    if len(self._semipatched) < 6000:
                        continue
                return False

            if self.insn == before:
                break

            runs += 1
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            if 0x10000CC0 <= pc <= 0x100010E0:
                run = cursors.get(pc, 0) + 1
                cursors[pc] = run
                if run >= idle_seen:
                    return True
        return False

    def rd(self, a: int, n: int = 1) -> bytes:
        return self.uc.mem_read(a, n)

    def wr(self, addr: int, data: bytes) -> None:
        self.uc.mem_write(addr, bytes(data))

    def rdm(self, a: int) -> int:
        return int.from_bytes(self.uc.mem_read(a, 4), 'little')

    def pc(self) -> int:
        return self.uc.reg_read(UC_ARM_REG_PC)

    def setup_emu_decrypt(self) -> None:
        def ret_hook(uc: Uc, address: int, size: int, data: Any) -> None:
            uc.emu_stop()
        self.uc.hook_add(UC_HOOK_CODE, ret_hook, begin=DECRYPT_RET, end=DECRYPT_RET)

    def emu_decrypt_sector(self, sec: int, dest: int = EMU_DEST) -> bytes:
        self.uc.mem_write(EMU_SP, struct.pack('<I', 0x200))
        self.uc.reg_write(UC_ARM_REG_SP, EMU_SP)
        self.uc.reg_write(UC_ARM_REG_R1, sec)
        self.uc.reg_write(UC_ARM_REG_R2, 0)
        self.uc.reg_write(UC_ARM_REG_R3, dest)
        self.uc.reg_write(UC_ARM_REG_LR, DECRYPT_RET)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x20)

        try:
            self.uc.emu_start(DECRYPT_FN | 1, 0, count=1000000, timeout=0)
        except UcError:
            pass

        return bytes(self.uc.mem_read(dest, 0x200))

    def crack_pin(self, max_tries: int = 10000) -> Optional[int]:
        self.uc.mem_write(FLASH_BASE + 0xC92, b'\xbf\x00\xbf\x00')
        self._stop_pc: Optional[int] = None

        def stop(uc: Uc, address: int, size: int, data: Any) -> None:
            self._stop_pc = address
            uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, stop, begin=FLASH_BASE + 0xCC6, end=FLASH_BASE + 0xCC6)
        self.uc.hook_add(UC_HOOK_CODE, stop, begin=FLASH_BASE + 0xCD4, end=FLASH_BASE + 0xCD4)

        for cand in range(max_tries):
            digits = bytes([(cand // 1000) % 10, (cand // 100) % 10, (cand // 10) % 10, cand % 10])
            self.uc.mem_write(CRACK_SP + CRACK_DIG, digits)
            self.uc.mem_write(CRACK_AUTH, b'\x00')
            self.uc.mem_write(0x20002ED3, b'\x00')

            self.uc.reg_write(UC_ARM_REG_SP, CRACK_SP)
            self.uc.reg_write(UC_ARM_REG_R8, CRACK_REF)
            self.uc.reg_write(UC_ARM_REG_R10, CRACK_BUF)
            self.uc.reg_write(UC_ARM_REG_R6, 3)
            self.uc.reg_write(UC_ARM_REG_LR, 0xFFFFFFFE)
            self.uc.reg_write(UC_ARM_REG_CPSR, 0x20)

            self._stop_pc = None
            try:
                self.uc.emu_start((FLASH_BASE + 0xC78) | 1, 0, count=100000, timeout=0)
            except UcError:
                pass

            if self.uc.mem_read(CRACK_AUTH, 1)[0] == 1:
                return cand

        return None
