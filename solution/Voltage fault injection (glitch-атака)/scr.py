import rp2 import time from machine import Pin
============================================================
SETTINGS
============================================================
PIN_BTN            = 0 PIN_GLITCH         = 2
BTN_PRESS_MS       = 20 BTN_GAP_MS         = 80 BTN_COUNT          = 4
Сдвигаем базу на 140 мс (вместо 60).
140 + 100 (gap) = 240 мс от нажатия.
сброс: длиннее и двойной (если в коде есть константа reset pulse — ставь 500 мс;
если сброс зашит как 250 мс — удвой в коде и добавь второй импульс через 100 мс)
COARSE_DELAY_MS    = 155       # абсолют 255 мс = левый край живой зоны
FINE_DELAY_MIN_TICKS  = 0 FINE_DELAY_MAX_TICKS  = 5000000    # 40 мс: полоса 255–295 мс FINE_DELAY_STEP       = 62500      # 500 мкс шаг (80 точек)
WIDTH_MIN_TICKS    = 12500         # 100 мкс WIDTH_MAX_TICKS    = 37500         # 300 мкс WIDTH_STEP         = 12500         # три ширины: 100/200/300 мкс
============================================================
PIO PROGRAM
============================================================
@rp2.asm_pio(set_init=rp2.PIO.OUT_LOW) def glitch_prog(): pull(block) mov(x, osr) pull(block) mov(y, osr) label("delay_loop") jmp(x_dec, "delay_loop") set(pins, 1) label("pulse_loop") jmp(y_dec, "pulse_loop") set(pins, 0)
sm = rp2.StateMachine( 0, glitch_prog, freq=125_000_000, set_base=Pin(PIN_GLITCH) ) sm.active(1)
============================================================
PIN INIT
============================================================
btn = Pin(PIN_BTN, Pin.OUT) btn.value(1)   # released (active-low)
============================================================
BUTTON EMULATION
============================================================
def press_button(): """Press and release the button. Returns timestamp right after release.""" btn.value(0) time.sleep_ms(BTN_PRESS_MS) btn.value(1) t = time.ticks_us() time.sleep_ms(BTN_GAP_MS) return t
def press_buttons(count): """Press the button count times. Returns timestamp after the last release.""" t = 0 for _ in range(count): t = press_button() return t
============================================================
GLITCH
============================================================
def fire_glitch(fine_delay_ticks, width_ticks): sm.put(fine_delay_ticks) sm.put(width_ticks)
def try_glitch(fine_delay_ticks, width_ticks): # Press 4 times t0 = press_buttons(BTN_COUNT)
# Coarse wait
time.sleep_ms(COARSE_DELAY_MS)

# Fine delay + pulse
fire_glitch(fine_delay_ticks, width_ticks)

time.sleep_ms(500)
return check_unlocked()
def check_unlocked(): """STUB. Implement unlock detection.""" return False
============================================================
MAIN SWEEP
============================================================
def main(): print("Starting glitch sweep...") print(f"Coarse delay: {COARSE_DELAY_MS} ms") print(f"Fine delay: {FINE_DELAY_MIN_TICKS}..{FINE_DELAY_MAX_TICKS} ticks") print(f"Width: {WIDTH_MIN_TICKS}..{WIDTH_MAX_TICKS} ticks")
attempt = 0
for fine_delay in range(FINE_DELAY_MIN_TICKS, FINE_DELAY_MAX_TICKS, FINE_DELAY_STEP):
    for width in range(WIDTH_MIN_TICKS, WIDTH_MAX_TICKS, WIDTH_STEP):
        attempt += 1
        ok = try_glitch(fine_delay, width)
        total_delay_ns = COARSE_DELAY_MS * 1_000_000 + fine_delay * 8
        width_ns = width * 8
        print(f"#{attempt} delay={total_delay_ns}ns width={width_ns}ns -> {'SUCCESS' if ok else 'no'}")
        if ok:
            print("!!! DEVICE UNLOCKED !!!")
            return
print("Sweep finished. No success.")
if name == "main": main()