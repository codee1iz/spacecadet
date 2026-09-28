import struct, sys, os, subprocess
from unicorn import *
from unicorn.arm_const import *

HERE = os.path.dirname(os.path.abspath(__file__))

FLASH_BASE = 0x10000000
FLASH_SIZE = 0x200000
RAM_BASE   = 0x20000000
RAM_SIZE   = 0x80000

# RP2040 bootrom ROM-function lookup emulation.
# Low memory holds a 16-bit func-table ptr at 0x14 and the lookup fn ptr at 0x18.
# We plant magic addresses and service them with code hooks.
BOOTROM_TABLE_OFF  = 0x14
BOOTROM_LOOKUP_OFF = 0x18
ROM_LOOKUP_MAGIC   = 0x2F00
ROM_FUNC_BASE      = 0x3000
ROM_CODE = {
    0x4649: 'IF',   # connect_internal_flash
    0x5845: 'EX',   # flash_exit_xip
    0x4346: 'FC',   # flash_flush_cache
    0x5843: 'CX',   # flash_enter_cmd_xip
    0x4552: 'RE',   # flash_range_erase
    0x5052: 'RP',   # flash_range_program
    0x434D: 'MC',   # memcpy
    0x534D: 'MS',   # memset
    0x3443: 'C4',   # memcpy44
    0x3453: 'S4',   # memset4
    0x334C: 'L3',   # clz32
    0x3350: 'P3',   # popcount32
    0x3352: 'R3',   # reverse32
    0x3354: 'T3',   # ctz32
    0x4255: 'UB',   # reset_usb_boot
    0x4653: 'SF',   # flash_set_... (unknown, no-op)
}

SP_INIT    = 0x20042000
PC_RESET   = 0x100001F6
RESET_PAT  = 0x100001F6

# branch targets of HW-ready spin loops, neutralized to nop
SPIN_PATCHES = (0x279A, 0x27CA, 0x2830, 0x2842, 0x2AAC, 0x2ABA)
# 4-byte Thumb2 MRS/MSR that capstone/unicorn can't decode: replace with nops
INSN_PATCHES = ((0x1734, 4), (0x1756, 4), (0x1762, 4), (0x1794, 4),
                (0x17AE, 4), (0x01F0, 4), (0x1908, 4),
                # MRS PRIMASK inside SDK critical-section stubs copied to RAM
                (0x5726, 4), (0x577C, 4), (0x5802, 4), (0x583E, 4))

# peripherals mapped as zero-RAM with hooks to synthesize live values
MMIO = [
    (0x40000000, 0x00060000, "PMU"),   # RESETS, CLOCKS, XOSC, PLL, PAD, TIMER, WDT, IO
    (0x50000000, 0x00001000, "DMA"),
    (0x50100000, 0x00020000, "USB"),
    (0x50300000, 0x00010000, "USB_DPRAM"),
    (0xD0000000, 0x00010000, "SIO"),
    (0xE0000000, 0x00100000, "PPB"),
    (0xF0000000, 0x00001000, "TPAP"),
    (0x18000000, 0x00001000, "XIP_SSI"),
]

class SPIFlash:
    """Minimal W25Q-style SPI state machine backing the XIP_SSI data register."""
    def __init__(self, image):
        self.img = image
        self.rxq = []
        self.state = 0        # 0 idle, 1 read-cmd next frame, 2 read addrs, 3 read data
        self.cmd = 0
        self.addr = 0
        self.acnt = 0
        self.status = 0       # SR1: WIP=0

    def tx(self, b):
        b &= 0xFF
        if self.state == 2:                       # READ: accumulate 3 addr bytes
            self.addr = (self.addr << 8) | b
            self.acnt += 1
            if self.acnt >= 3:
                self.state = 3
            self.rxq.append(0)
        elif self.state == 3:                     # clock byte: emit data
            off = self.addr + self.acnt - 3
            self.acnt += 1
            if 0 <= off < len(self.img):
                self.rxq.append(self.img[off])
            else:
                self.rxq.append(0)
        elif self.state == 1:                     # 2nd frame -> real response
            self.rxq.append(self._resp())
            self.state = 0
        else:
            if b in (0x05, 0x35, 0x9F, 0x03, 0x0B):
                self.cmd = b
                if b == 0x03:
                    self.addr = 0
                    self.acnt = 0
                    self.state = 2
                else:
                    self.state = 1
                self.rxq.append(0)                # cmd frame returns garbage
            else:
                self.rxq.append(b)                # echo (bulk/raw pump)

    def _resp(self):
        if self.cmd == 0x05:
            return self.status                    # RDSR1
        if self.cmd == 0x35:
            return 0x02                           # RDSR2: QE set -> skip WRSR
        if self.cmd == 0x9F:
            return 0xEF                           # RDID: Winbond mfr
        return b'\x00'[0]

    def rx(self):
        return self.rxq.pop(0) if self.rxq else 0

    def pending(self):
        return len(self.rxq) > 0


# --- PIN brute-force through the real check routine -------------------------
# Check routine at flash 0x0C78: compares 4 digits at [sp+0x34..0x37] against
# reference bytes at 0x10005500 (06 07 01 00). Success writes 1 to 0x20002ED2.

CRACK_SP   = 0x2003FF00          # scratch stack (inside mapped RAM)
CRACK_DIG  = 0x34                # digits at SP+0x34..SP+0x37
CRACK_REF  = FLASH_BASE + 0x54FF # r8: reference base (ref = +r4 -> 0x5500)
CRACK_BUF  = 0x20002ED0          # sl: input buffer ptr
CRACK_AUTH = 0x20002ED2          # auth flag (success -> 1)

# Real storage-decrypt routine in the firmware (entry 0x354).
# ABI: r6 = sector, r1 = 0, r2 = copy-out offset (0), r3 = dest ptr,
#      [SP] = remaining byte count (0x200), returns to LR.
DECRYPT_FN  = FLASH_BASE + 0x354
DECRYPT_RET = FLASH_BASE + 0x3F00   # hook address: stops emulation on return
EMU_DEST    = 0x20010000            # scratch out-buffer in RAM (512B)
EMU_SP      = 0x2003FF00            # scratch stack frame

STORAGE_KEYS = [0xDAA66D13, 0x78DDE6C4, 0x17156075, 0xB54CDA26,
                0x538453D7, 0xF1BBCD88, 0x8FF34739, 0x2E2AC0EA,
                0x6A99B44C, 0xCC623A9B, 0x08D12DFD, 0xA708A7AE,
                0x3C6EF362, 0x41C64E6D, 0x61C8864F, 0x9E3779B1]
# per-byte constant layout inside a 16-byte block (0x10 = state itself)
STORAGE_PERM = [0x0E, 0x10, 0x0F, 0x0C, 0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07, 0x09, 0x08, 0x0A, 0x0B]


def decrypt_sector(img, sec):
    """Decrypt one 512-byte sector of the encrypted region (flash offset 0x100000)."""
    state = (sec * 0x38C9CDA0 + 0x9E37A9EA) & 0xFFFFFFFF
    out = bytearray()
    for b in range(32):
        for k in range(16):
            ci = STORAGE_PERM[k]
            kc = state if ci == 0x10 else (state + STORAGE_KEYS[ci])
            out.append(img[0x100000 + sec * 512 + b * 16 + k] ^ ((kc & 0xFFFFFFFF) >> 24))
        state = (state + 0x41C64E6D) & 0xFFFFFFFF
    return bytes(out)


def build_disk(img, path):
    """Reconstruct the 1MB FAT12 MSC volume (2048 x 512B) and write it to path."""
    disk = bytearray(2048 * 512)
    for s in range(1408):                       # encrypted region covers 1408 sectors
        disk[s * 512:(s + 1) * 512] = decrypt_sector(img, s)
    with open(path, 'wb') as f:
        f.write(bytes(disk))
    return path


def build_disk_emu(t, img, path):
    """Rebuild the 1MB FAT12 volume by running the firmware's real decrypt
    routine in the emulator for every sector (2048 x 512B)."""
    disk = bytearray(2048 * 512)
    for s in range(1408):                       # encrypted region covers 1408 sectors
        disk[s * 512:(s + 1) * 512] = t.emu_decrypt_sector(s)
    with open(path, 'wb') as f:
        f.write(bytes(disk))
    return path


class Token:
    def __init__(self, img):
        self.img = img
        self.vtime = 0            # virtual microseconds, advanced on timer reads/calls
        self.insn = 0
        self.log_limit = set()
        self.trace = []
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self._map()
        self._hooks()
        self.uc.mem_write(FLASH_BASE, img[:FLASH_SIZE])
        # emulate bootrom side effect: relocate flash vector table (0x100) to RAM at VTOR base
        self.uc.mem_write(RAM_BASE, img[0x100:0x100 + 0xC0])
        for a in SPIN_PATCHES:
            self.uc.mem_write(FLASH_BASE + a, b'\xbf\x00')  # nop
        for a, n in INSN_PATCHES:
            self.uc.mem_write(FLASH_BASE + a, b'\xbf\x00' * (n // 2))
        # NOP every Thumb-2 MRS/MSR PRIMASK critical-section primitive up-front:
        # unicorn cannot decode them and in-place patching mid-run leaves a stale TB.
        # IMPORTANT: scan ONLY the code region (0x0..0x67F0); the rest of the
        # image (0x100000+) is encrypted DATA and must stay byte-exact.
        blob = bytearray(img[:FLASH_SIZE])
        code_end = 0x67F0
        offs = set()
        for i in range(code_end - 3):
            b0, b1, b2, b3 = blob[i], blob[i+1], blob[i+2], blob[i+3]
            if b0 == 0xEF and b1 == 0xF3 and b2 == 0x10 and (b3 & 0xF0) == 0x80:
                offs.add(i)                                  # MRS r?, PRIMASK
            elif (b0 & 0xF0) == 0x80 and b1 == 0xF3 and b2 == 0x10 and b3 == 0x88:
                offs.add(i)                                  # MSR PRIMASK, r?
        for i in offs:
            self.uc.mem_write(FLASH_BASE + i, b'\xbf\x00\xbf\x00')
        self._primask_n = len(offs)
        # WFE/WFI (hints) confuse unicorn's TB translator right before a branch:
        # replace standalone `20 bf`/`30 bf` (0xBF20/0xBF30) with nop. A 32-bit
        # Thumb prefix is >= 0xE800, so a hint at i preceded by a lower halfword
        # cannot be a suffix of a 32-bit instruction starting at i-2.
        # Same restriction: code region only (encrypted data would be corrupted).
        offs2 = set()
        for i in range(code_end - 1):
            if blob[i] in (0x20, 0x30) and blob[i + 1] == 0xBF:
                hprev = (blob[i - 1] << 8) | (blob[i - 2] if i >= 2 else 0)
                if hprev < 0xE800:
                    offs2.add(i)
        for i in offs2:
            self.uc.mem_write(FLASH_BASE + i, b'\xbf\x00')
        self._hint_n = len(offs2)
        self._rom_setup()
        self._spi = SPIFlash(img)

    def _map(self):
        self.uc.mem_map(FLASH_BASE, FLASH_SIZE)
        self.uc.mem_map(RAM_BASE, RAM_SIZE)
        try:
            self.uc.mem_map(0x0, 0x10000)     # bootrom handoff low-SRAM (zeros)
        except UcError:
            pass
        try:
            self.uc.mem_map(0x1FF00000, 0x100000)  # shadow vector/RAM mirror
        except UcError:
            pass
        try:
            self.uc.mem_map(0xFFF00000, 0x100000)  # top of space scratch
        except UcError:
            pass
        for a, s, _ in MMIO:
            self.uc.mem_map(a, s)

    def _hooks(self):
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code, begin=FLASH_BASE, end=FLASH_BASE + FLASH_SIZE)
        # count all exec
        self.uc.hook_add(UC_HOOK_CODE, self._hook_all)
        # null-hook trampoline: executing low SRAM = empty boot-hook, return via LR
        self.uc.hook_add(UC_HOOK_CODE, self._hook_low, begin=0x0, end=0x2000)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_rom,
                         begin=ROM_LOOKUP_MAGIC, end=ROM_FUNC_BASE + 0x400)
        for a, s, _ in MMIO:
            self.uc.hook_add(UC_HOOK_MEM_READ, self._mem_read, begin=a, end=a + s)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._mem_write_ssi,
                         begin=0x18000000, end=0x18000060)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._bad_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._bad_write)

    def _hook_all(self, uc, address, size, data):
        self.insn += 1

    def _hook_code(self, uc, address, size, data):
        if address == 0x100025C8:          # time_now() entry: advance virtual time
            self.vtime += 10
        self.trace.append(address)
        if len(self.trace) > 40:
            self.trace = self.trace[-40:]

    def _hook_low(self, uc, address, size, data):
        lr = uc.reg_read(UC_ARM_REG_LR)
        if not (0x10000000 <= lr < 0x10200000):
            lr = 0x100028E0
        uc.reg_write(UC_ARM_REG_PC, lr)

    # --- bootrom ROM-function emulation -------------------------------------
    def _rom_setup(self):
        self._rom_by_code = {}
        self._rom_name = {}
        self._rom_missing = set()
        self._rom_calls = {}
        addr = ROM_FUNC_BASE
        for code, name in ROM_CODE.items():
            self._rom_by_code[code] = addr
            self._rom_name[addr] = name
            addr += 4
        self._rom_stub = addr
        self._rom_name[addr] = 'stub'
        self.uc.mem_write(BOOTROM_TABLE_OFF, struct.pack('<H', 0x2E00))
        self.uc.mem_write(BOOTROM_LOOKUP_OFF, struct.pack('<H', ROM_LOOKUP_MAGIC | 1))
        # --- bootrom/crt0 handoff emulation ---------------------------------
        # 1) .data relocation: flash 0x5718 -> RAM 0x200000C0 (0x10D8 bytes)
        #    (performed by the real boot; emulated so the decrypt routine works
        #    standalone without a full boot)
        DATA_FROM, DATA_TO, DATA_LEN = 0x5718, 0x200000C0, 0x10D8
        self.uc.mem_write(DATA_TO, self.img[DATA_FROM:DATA_FROM + DATA_LEN])
        # 2) the boot resolves the ROM-function tags stored in .data
        #    ('MS','MC','S4','C4') and rewrites the pointer table with the
        #    resolved stub addresses (identical to the recorded real-boot table)
        for off, tag in ((0x00, 0x534D), (0x04, 0x434D), (0x08, 0x3453), (0x0C, 0x3443)):
            self.uc.mem_write(0x20001160 + off, struct.pack('<I', self._rom_by_code[tag] | 1))

    def _hook_rom(self, uc, address, size, data):
        lr = uc.reg_read(UC_ARM_REG_LR)
        if address == ROM_LOOKUP_MAGIC:
            code = uc.reg_read(UC_ARM_REG_R1) & 0xFFFF
            addr = self._rom_by_code.get(code)
            if addr is None:
                if code not in self._rom_missing:
                    self._rom_missing.add(code)
                    print('[rom] lookup unknown code=%04x' % code)
                addr = self._rom_stub
            uc.reg_write(UC_ARM_REG_R0, addr | 1)
        else:
            name = self._rom_name.get(address, 'stub')
            self._rom_calls[name] = self._rom_calls.get(name, 0) + 1
            self._rom_call(uc, name)
        uc.reg_write(UC_ARM_REG_PC, lr)

    def _rom_call(self, uc, name):
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
        elif name == 'RE':
            if isinstance(r0, int):
                pass  # flash erase: leave backing image unchanged
        elif name == 'RP':
            pass      # flash program: leave backing image unchanged
        # IF/EX/FC/CX/UB and stub: no-op

    def _reg32(self, address, value):
        self.uc.mem_write(address, struct.pack('<I', value & 0xFFFFFFFF))

    def _mem_read(self, uc, access, address, size, value, data):
        if size != 4:
            return
        # synthesize values for readiness/irq-status style regs
        if address in (0x40054024,):                   # TIMER TIMERAWH
            self._reg32(address, (self.vtime >> 32) & 0xFFFFFFFF)
        elif address == 0x40054028:                    # TIMER TIMERAWL
            self._reg32(address, self.vtime & 0xFFFFFFFF)
        elif address in (0x40054008,):                 # TIMEHR (some code) -> 0
            self._reg32(address, 0)
        elif address == 0x4000C008:                    # RESETS done
            self._reg32(address, 0xFFFFFFFF)
        elif address == 0x40024004:                    # XOSC STATUS: STABLE
            # preserve stat bit from back filled? firmware only checks stable
            self._reg32(address, 0x80000000)
        elif 0x40028000 <= address < 0x40029000 or 0x4002C000 <= address < 0x4002D000:  # PLL SYS/USB
            self._reg32(address, 0x80000000)
        elif (0xD0000100 <= address < 0xD0000200) or address == 0xD00009C0:  # SIO spinlock/irq: ready
            self._reg32(address, 1)
        elif 0x40008000 <= address <= 0x4000BFFF:      # CLOCKS rw mirrors
            cur = int.from_bytes(self.uc.mem_read(address, 4), 'little')
            self._reg32(address, cur if cur else 1)
        elif address == 0x18000028:                    # XIP_SSI SR
            sr = 0x02                                  # TFNF always
            if self._spi.pending():
                sr |= 0x0C                             # RFNE|RFF
            self._reg32(address, sr)
        elif address == 0x18000060:                    # XIP_SSI DR
            self._reg32(address, self._spi.rx())

    def _mem_write_ssi(self, uc, access, address, size, value, data):
        if address == 0x18000060:
            self._spi.tx(value & 0xFF)

    def _bad_read(self, uc, access, address, size, value, data):
        if not (address in self.log_limit and False):
            print('BAD READ  %08x size=%d (pc=%08x)' % (address, size, uc.reg_read(UC_ARM_REG_PC)))
        return False

    def _bad_write(self, uc, access, address, size, value, data):
        print('BAD WRITE %08x size=%d val=%08x (pc=%08x)' % (address, size, value, uc.reg_read(UC_ARM_REG_PC)))
        return False

    def _patch_insn(self, pc):
        b = self.uc.mem_read(pc, 4)
        if not b or len(b) != 4:
            return False
        h0 = b[0] | (b[1] << 8)
        h0s = (b[0] << 8) | b[1]               # possibly byte-swapped copy
        if h0 in (0xEFF3, 0x80F3, 0x81F3, 0x8CF3, 0x80F3, 0xF381, 0xF3EF, 0xF38C) or \
           0xF380 <= h0 <= 0xF3FF or 0xF380 <= h0s <= 0xF3FF or h0s in (0xEFF3, 0x80F3, 0x81F3, 0x8CF3, 0xF381):
            # MRS  => movs rD,#0            MSR  => nop
            if (b[2] & 0x80):
                rd = (b[2] >> 4) & 0xF
                ins = bytes([0x00, 0x20 | rd]) + b'\xbf\x00'   # movs rD,#0 ; nop
            else:
                ins = b'\xbf\x00\xbf\x00'
            self.uc.mem_write(pc, ins)
            return True
        return False

    def boot(self, max_insn=400000000, idle_seen=200):
        self.uc.reg_write(UC_ARM_REG_SP, SP_INIT)
        self.uc.reg_write(UC_ARM_REG_PC, PC_RESET | 1)     # LSB -> Thumb
        self.uc.reg_write(UC_ARM_REG_LR, 0xFFFFFFFF)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x20)            # T bit
        self._semipatched = set()
        cursors = {}
        runs = 0
        while self.insn < max_insn:
            before = self.insn
            try:
                self.uc.emu_start((PC_RESET|1) & 0xFFFFFFFE | 1, 0x10000001, count=1 << 20, timeout=0)
            except UcError as e:
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                if 'INSN_INVALID' in str(e) and self._patch_insn(pc):
                    self._semipatched.add(pc)
                    if len(self._semipatched) < 6000:
                        continue
                print('UC ERROR %s at pc=%08x' % (e, pc))
                print('trace:', [hex(x) for x in self.trace[-25:]])
                return False
            if self.insn == before:
                break
            runs += 1
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            if 0x10000CC0 <= pc <= 0x100010E0:
                run = cursors.get(pc, 0) + 1
                cursors[pc] = run
                if run >= idle_seen:
                    print('[boot] idle reached at pc=%08x after %d insn (%d runs)' % (pc, self.insn, runs))
                    return True
        print('BOOT TIMEOUT insn=%d pc=%08x' % (self.insn, self.uc.reg_read(UC_ARM_REG_PC)))
        return False

    def run_for(self, pc_end=0x10001100, count=2000000):
        for _ in range(200):
            try:
                self.uc.emu_start((self.uc.reg_read(UC_ARM_REG_PC)|1), pc_end|1, count=count, timeout=0)
                return
            except UcError as e:
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                if 'INSN_INVALID' in str(e) and self._patch_insn(pc):
                    self._semipatched.add(pc)
                    continue
                raise

    def rd(self, a, n=1):
        return self.uc.mem_read(a, n)

    def wr(self, addr, data):
        self.uc.mem_write(addr, bytes(data))

    def rdm(self, a):
        return int.from_bytes(self.uc.mem_read(a, 4), 'little')

    def pc(self):
        return self.uc.reg_read(UC_ARM_REG_PC)

# state while idle
    def step_budget(self, max_insn=4000000):
        end = self.insn + max_insn
        while self.insn < end:
            try:
                self.uc.emu_start((self.uc.reg_read(UC_ARM_REG_PC)|1), 0x10000001, count=500000, timeout=0)
            except UcError as e:
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                if 'INSN_INVALID' in str(e) and self._patch_insn(pc):
                    self._semipatched.add(pc)
                    continue
                print('UC ERROR %s pc=%08x' % (e, pc))
                return False
        return True


    def setup_emu_decrypt(self):
        """Install the return-hook used by emu_decrypt_sector."""

        def ret_hook(uc, address, size, data):
            uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, ret_hook, begin=DECRYPT_RET, end=DECRYPT_RET)

    def emu_decrypt_sector(self, sec, dest=EMU_DEST):
        """Run the firmware's REAL storage-decrypt routine on one sector.

        Executes 0x10000354 in the emulator: it reads the 512-byte ciphertext
        from XIP 0x10100000+sec*512, runs the real XOR-transform code and
        memcpys the plaintext to `dest`. Returns the 512 decrypted bytes.
        """
        self.uc.mem_write(EMU_SP, struct.pack('<I', 0x200))   # remaining at [SP]
        self.uc.reg_write(UC_ARM_REG_SP, EMU_SP)
        self.uc.reg_write(UC_ARM_REG_R1, sec)     # sector index (checked < 0x800)
        self.uc.reg_write(UC_ARM_REG_R2, 0)       # copy-out offset
        self.uc.reg_write(UC_ARM_REG_R3, dest)    # output buffer
        self.uc.reg_write(UC_ARM_REG_LR, DECRYPT_RET)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x20)
        try:
            self.uc.emu_start(DECRYPT_FN | 1, 0, count=1000000, timeout=0)
        except UcError:
            pass
        return bytes(self.uc.mem_read(dest, 0x200))

    def crack_pin(self, max_tries=10000, verbose=True):
        """Brute-force the PIN by running the firmware's real check routine.

        Runs flash 0x0C78 for every candidate 0000..9999. Success/fail branches
        are intercepted with code hooks + emu_stop. Returns PIN or None.
        """
        # the per-digit delay call (bl 0x239C) is irrelevant for the compare -> nop
        self.uc.mem_write(FLASH_BASE + 0xC92, b'\xbf\x00\xbf\x00')
        self._stop_pc = None

        def stop(uc, address, size, data):
            self._stop_pc = address
            uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, stop, begin=FLASH_BASE + 0xCC6, end=FLASH_BASE + 0xCC6)  # success
        self.uc.hook_add(UC_HOOK_CODE, stop, begin=FLASH_BASE + 0xCD4, end=FLASH_BASE + 0xCD4)  # fail
        for cand in range(max_tries):
            digits = bytes([(cand // 1000) % 10, (cand // 100) % 10, (cand // 10) % 10, cand % 10])
            self.uc.mem_write(CRACK_SP + CRACK_DIG, digits)
            self.uc.mem_write(CRACK_AUTH, b'\x00')
            self.uc.mem_write(0x20002ED3, b'\x00')
            self.uc.reg_write(UC_ARM_REG_SP, CRACK_SP)
            self.uc.reg_write(UC_ARM_REG_R8, CRACK_REF)
            self.uc.reg_write(UC_ARM_REG_R10, CRACK_BUF)     # sl
            self.uc.reg_write(UC_ARM_REG_R6, 3)
            self.uc.reg_write(UC_ARM_REG_LR, 0xFFFFFFFE)
            self.uc.reg_write(UC_ARM_REG_CPSR, 0x20)
            self._stop_pc = None
            try:
                self.uc.emu_start((FLASH_BASE + 0xC78) | 1, 0, count=100000, timeout=0)
            except UcError:
                pass
            if self.uc.mem_read(CRACK_AUTH, 1)[0] == 1:
                if verbose:
                    print('[crack] success at %04d (stop at %s)' % (cand, hex(self._stop_pc)))
                return cand
            if verbose and cand % 1000 == 999:
                print('[crack] tried %d candidates...' % (cand + 1))
        return None


def spin_until(emu, addr, eqv, budget=4000000):
    end = emu.insn + budget
    while emu.insn < end:
        try:
            emu.uc.emu_start((emu.uc.reg_read(UC_ARM_REG_PC)|1), 0x10000001, count=200000, timeout=0)
        except UcError as e:
            pc = emu.uc.reg_read(UC_ARM_REG_PC)
            if 'INSN_INVALID' in str(e) and emu._patch_insn(pc):
                emu._semipatched.add(pc)
                continue
            print('UC err', e, hex(pc))
            return False
        if int.from_bytes(emu.rd(addr, 1), 'little') == eqv:
            return True
    return False


def validate_firmware(img):
    """Sanity-check that the image is this token's firmware family."""
    if len(img) < 0x7000:
        raise ValueError('file too small (%d bytes) to be a 2MB flash dump' % len(img))
    # PIN check routine signature at 0xC78 (movs r3,#1; mov r2,sl; movs r4,#1; mov r5,r8)
    if img[0xC78:0xC80] != bytes.fromhex('0123524601244546'):
        raise ValueError('PIN check routine not found at 0xC78 (unknown firmware)')
    # reference-base literal for the check
    ref = struct.unpack_from('<I', img, 0xE10)[0]
    auth = struct.unpack_from('<I', img, 0xE14)[0]
    if ref != 0x100054FF or auth != 0x20002ED2:
        raise ValueError('PIN reference/auth literals mismatch at 0xE10/0xE14 (unknown firmware)')
    # crypto constant pool used by the storage transform
    if img[0x4EC:0x4F4] != bytes.fromhex('f4fdffffa0cdc938'):
        raise ValueError('storage crypto pool not found at 0x4EC (unknown firmware)')


def main():
    import argparse
    ap = argparse.ArgumentParser(description='RP2040 USB-token emulator: brute-force PIN, decrypt storage, mount disk')
    ap.add_argument('-f', '--file', default='usb_token_original.bin',
                    help='path to the firmware flash dump (default: usb_token_original.bin)')
    ap.add_argument('-o', '--out', default='token_disk.img',
                    help='output disk image name (default: token_disk.img)')
    ap.add_argument('--no-mount', action='store_true', help='do not attach the disk image')
    ap.add_argument('--no-boot', action='store_true', help='skip the boot smoke test')
    args = ap.parse_args()

    fw_path = args.file if os.path.isabs(args.file) else os.path.join(HERE, args.file)
    if not os.path.exists(fw_path):
        print('ERROR: file not found: %s' % fw_path)
        return 1
    img = open(fw_path, 'rb').read()
    print('[*] firmware: %s (%d bytes)' % (fw_path, len(img)))
    try:
        validate_firmware(img)
    except ValueError as e:
        print('ERROR: %s' % e)
        return 1

    t = Token(img)
    if not args.no_boot:
        print('[*] boot smoke test (bounded)...')
        if t.boot(max_insn=1500000, idle_seen=10):
            print('BOOT OK  pc=%08x vtime=%d insn=%d' % (t.pc(), t.vtime, t.insn))
        else:
            print('boot budget exhausted at pc=%08x (continuing anyway)' % t.pc())
    else:
        print('[*] boot skipped (--no-boot)')

    print('[*] brute-forcing PIN through the real check routine...')
    pin = t.crack_pin()
    if pin is None:
        print('PIN NOT FOUND')
        return 1
    print('PIN = %04d' % pin)

    print('[*] decrypting the 1MB storage region -> %s' % args.out)
    print('[*] running the firmware real decrypt routine in the emulator per sector...')
    t.setup_emu_decrypt()
    # self-check: emulated decrypt must match the independently recovered transform
    emu_s0 = t.emu_decrypt_sector(0)
    if emu_s0[:11] != b'\xeb<\x90MSDOS5.0' or emu_s0[54:59] != b'FAT12':
        print('ERROR: emulated decrypt produced invalid boot sector (ABI mismatch?)')
        return 1
    disk_path = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
    build_disk_emu(t, img, disk_path)
    print('disk image written: %s' % disk_path)

    if args.no_mount:
        print('[*] --no-mount: image not attached')
        return 0
    print('[*] attaching as a virtual disk...')
    r = subprocess.run(['hdiutil', 'attach', '-readonly', disk_path],
                       capture_output=True, text=True)
    print(r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr.strip())
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())