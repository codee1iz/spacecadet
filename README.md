# SpaceCadet — Security Research




## Исследуемые направления

| #  | Направление                                                          | Тип                            | Сложность      | Результат                  |
| -- | -------------------------------------------------------------------- | ------------------------------ | -------------- | -------------------------- |
| 01 | [Извлечение прошивки через BOOTSEL](./01-firmware-extraction/)       | Hardware / Software            | 🟢 Низкая      | Полный дамп прошивки       |
| 02 | [Анализ прошивки и извлечение PIN](./02-firmware-analysis/)          | Software                       | 🟢 Тривиальная | PIN-код                    |
| 03 | [Модификация прошивки и обход проверки PIN](./03-firmware-patching/) | Software / Firmware            | 🟢 Низкая      | Обход аутентификации       |
| 04 | [Аппаратный brute-force через GPIO](./04-hardware-bruteforce/)       | Hardware                       | 🟡 Средняя     | Подбор PIN                 |
| 05 | [Эмуляция прошивки в Unicorn](./05-unicorn-emulation/)               | Software / Reverse Engineering | 🔴 Высокая     | Подбор PIN без устройства  |
| 06 | [Криптоанализ виртуального хранилища](./06-storage-cryptanalysis/)   | Software / Cryptanalysis       | 🔴 Высокая     | Расшифрованный образ FAT12 |

---

 
