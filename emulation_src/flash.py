from typing import List


class SPIFlash:

    def __init__(self, image: bytes) -> None:
        self.img: bytes = image
        self.rxq: List[int] = []
        self.state: int = 0
        self.cmd: int = 0
        self.addr: int = 0
        self.acnt: int = 0
        self.status: int = 0

    def tx(self, b: int) -> None:
        b &= 0xFF
        if self.state == 2:
            self.addr = (self.addr << 8) | b
            self.acnt += 1
            if self.acnt >= 3:
                self.state = 3
            self.rxq.append(0)
        elif self.state == 3:
            off = self.addr + self.acnt - 3
            self.acnt += 1
            if 0 <= off < len(self.img):
                self.rxq.append(self.img[off])
            else:
                self.rxq.append(0)
        elif self.state == 1:
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
                self.rxq.append(0)
            else:
                self.rxq.append(b)

    def _resp(self) -> int:
        if self.cmd == 0x05:
            return self.status
        if self.cmd == 0x35:
            return 0x02
        if self.cmd == 0x9F:
            return 0xEF
        return 0x00

    def rx(self) -> int:
        return self.rxq.pop(0) if self.rxq else 0

    def pending(self) -> bool:
        return len(self.rxq) > 0
