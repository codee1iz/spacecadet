## Суть

Попытались обойти проверку пароля на уровне микроконтроллера через атаку по питанию. Идея в том, чтобы кратковременно замыкать линию 3.3 В на землю в момент выполнения инструкции сравнения. Если попасть в нужный такт, процессор из-за нехватки напряжения может пропустить эту инструкцию и принять неверный пароль за верный.
## Как именно

**1. Теория**

В отличие от классических glitch-атак, где атакующее устройство отделено от цели, здесь архитектура замкнута. Микроконтроллер сам проверяет пароль, и он же генерирует глитч. Суть метода - намеренно вызвать кратковременную просадку напряжения (brownout) на линии 3.3 В. Если попасть в такт, когда процессор выполняет инструкцию сравнения, из-за нехватки напряжения он может пропустить эту инструкцию или интерпретировать её как истинную, даже если пароль неверный.

**2. Сборка стенда**

Для реализации собрали схему crowbar-атаки. MOSFET должен открываться на доли микросекунды, замыкая 3.3 В на землю, и сразу закрываться.

<p align="center">
  <img src="glitch.jpg?raw=true" alt="glitch">
</p>

Компоненты:
- **MOSFET:** IRLZ44N. N-канальный, logic-level, способен выдержать импульсный ток короткого замыкания.
- **Резистор R1 (Gate Series):** 100 Ом. Ограничивает ток с GPIO на затвор, предотвращает звон и защищает пин микроконтроллера.
- **Резистор R2 (Gate Pull-Down):** 10 кОм. Притягивает затвор к земле, чтобы MOSFET гарантированно не открылся случайно во время загрузки или перезагрузки.

Схема подключения:
- **Source (Исток):** на GND.
- **Drain (Сток):** на линию 3.3 В цели.
- **Gate (Затвор):** через резистор 100 Ом на GPIO атакующей платы. Резистор 10 кОм идёт от Gate к GND.

**3. Софт и синхронизация**

Главная сложность - тайминг. Нужно глитчить строго в момент выполнения инструкции проверки пароля. Написали кастомную прошивку для Pico, которая эмулирует вращение энкодера и нажатие кнопки, дожидается момента, когда контроллер должен перейти к сравнению, и подаёт короткий импульс на затвор MOSFET.

```python
import rp2 import time from machine import Pin

PIN_BTN            = 0 PIN_GLITCH         = 2
BTN_PRESS_MS       = 20 BTN_GAP_MS         = 80 BTN_COUNT          = 4

COARSE_DELAY_MS    = 155      
FINE_DELAY_MIN_TICKS  = 0 FINE_DELAY_MAX_TICKS  = 5000000    
WIDTH_MIN_TICKS    = 12500                

@rp2.asm_pio(set_init=rp2.PIO.OUT_LOW) def glitch_prog(): pull(block) mov(x, osr) pull(block) mov(y, osr) label("delay_loop") jmp(x_dec, "delay_loop") set(pins, 1) label("pulse_loop") jmp(y_dec, "pulse_loop") set(pins, 0)
sm = rp2.StateMachine( 0, glitch_prog, freq=125_000_000, set_base=Pin(PIN_GLITCH) ) sm.active(1)

btn = Pin(PIN_BTN, Pin.OUT) btn.value(1)   

def press_button():  btn.value(0) time.sleep_ms(BTN_PRESS_MS) btn.value(1) t = time.ticks_us() time.sleep_ms(BTN_GAP_MS) return t
def press_buttons(count):  t = 0 for _ in range(count): t = press_button() return t

def fire_glitch(fine_delay_ticks, width_ticks): sm.put(fine_delay_ticks) sm.put(width_ticks)
def try_glitch(fine_delay_ticks, width_ticks):

time.sleep_ms(COARSE_DELAY_MS)

fire_glitch(fine_delay_ticks, width_ticks)

time.sleep_ms(500)
return check_unlocked()
def check_unlocked(): return False
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
            print("DEVICE UNLOCKED")
            return
print("Sweep finished. No success.")
if name == "main": main()
```

## Итог

Окно глитча нашли, но оно оказалось слишком широким. Вместо пропуска одной инструкции мы вызывали полный сбой логики и перезагрузку устройства. Чтобы попасть в наносекундное окно, вероятнее всего, придётся выпаять блокировочные конденсаторы по питанию процессора. Это voltage glitching, не требующий разборки устройства, но требующий точной синхронизации и, возможно, аппаратной доработки.
