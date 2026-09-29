import time

from machine import Pin
import rp2


PIN_BTN = 0
PIN_GLITCH = 2

BTN_PRESS_MS = 20
BTN_GAP_MS = 80
BTN_COUNT = 4

COARSE_DELAY_MS = 155

FINE_DELAY_MIN_TICKS = 0
FINE_DELAY_MAX_TICKS = 5_000_000
FINE_DELAY_STEP = 10_000

WIDTH_MIN_TICKS = 12_500
WIDTH_MAX_TICKS = 20_000
WIDTH_STEP = 500


@rp2.asm_pio(set_init=rp2.PIO.OUT_LOW)
def glitch_prog() -> None:
    pull(block)           # noqa: F821 # type: ignore
    mov(x, osr)           # noqa: F821 # type: ignore
    pull(block)           # noqa: F821 # type: ignore
    mov(y, osr)           # noqa: F821 # type: ignore

    label("delay_loop")   # noqa: F821 # type: ignore
    jmp(x_dec, "delay_loop")  # noqa: F821 # type: ignore

    set(pins, 1)          # noqa: F821 # type: ignore

    label("pulse_loop")   # noqa: F821 # type: ignore
    jmp(y_dec, "pulse_loop")  # noqa: F821 # type: ignore

    set(pins, 0)          # noqa: F821 # type: ignore


class GlitchController:

    def __init__(self, btn_pin: int, glitch_pin: int) -> None:
        self.btn: Pin = Pin(btn_pin, Pin.OUT)
        self.btn.value(1)

        self.sm: rp2.StateMachine = rp2.StateMachine(
            0,
            glitch_prog,
            freq=125_000_000,
            set_base=Pin(glitch_pin)
        )
        self.sm.active(1)

    def press_button(self) -> int:
        self.btn.value(0)
        time.sleep_ms(BTN_PRESS_MS)
        self.btn.value(1)

        timestamp = time.ticks_us()
        time.sleep_ms(BTN_GAP_MS)
        return timestamp

    def press_buttons(self, count: int) -> int:
        timestamp = 0
        for _ in range(count):
            timestamp = self.press_button()
        return timestamp

    def fire_glitch(self, fine_delay_ticks: int, width_ticks: int) -> None:
        self.sm.put(fine_delay_ticks)
        self.sm.put(width_ticks)

    def try_glitch(self, fine_delay_ticks: int, width_ticks: int) -> bool:
        time.sleep_ms(COARSE_DELAY_MS)
        self.fire_glitch(fine_delay_ticks, width_ticks)
        time.sleep_ms(500)
        return self.check_unlocked()

    def check_unlocked(self) -> bool:
        return False


def main() -> None:
    print("[*] Starting Fault Injection sweep...")
    print(f"[*] Coarse delay : {COARSE_DELAY_MS} ms")
    print(f"[*] Fine delay   : {FINE_DELAY_MIN_TICKS}..{FINE_DELAY_MAX_TICKS} ticks")
    print(f"[*] Pulse width  : {WIDTH_MIN_TICKS}..{WIDTH_MAX_TICKS} ticks\n")

    controller = GlitchController(PIN_BTN, PIN_GLITCH)
    attempt = 0

    try:
        for fine_delay in range(FINE_DELAY_MIN_TICKS, FINE_DELAY_MAX_TICKS, FINE_DELAY_STEP):
            for width in range(WIDTH_MIN_TICKS, WIDTH_MAX_TICKS, WIDTH_STEP):
                attempt += 1
                success = controller.try_glitch(fine_delay, width)

                total_delay_ns = (COARSE_DELAY_MS * 1_000_000) + (fine_delay * 8)
                width_ns = width * 8

                status = "SUCCESS" if success else "FAIL"
                print(f"[#{attempt:05d}] Delay: {total_delay_ns:010d} ns | Width: {width_ns:06d} ns -> {status}")

                if success:
                    print("\n[+] DEVICE SUCCESSFULLY UNLOCKED")
                    return

    except KeyboardInterrupt:
        print("\n[-] Sweep interrupted by user.")
        return

    print("\n[-] Sweep finished. No success.")


if __name__ == "__main__":
    main()
