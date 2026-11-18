---
date: '2026-10-30T13:10:00+07:00'
draft: false
title: 'IoT Story - EvilWhale'
hideSummary: true
type: "blogs"
description: "IoT Story - EvilWhale"
---
## TL;DR

This blog post tells the story of my first time designing a custom PCB, created purely for my thesis and personal research on USB attacks. The project is called [EvilWhale](https://github.com/bigbluewhale111/EvilWhale) which is inspired by [EvilDuck](https://github.com/cifertech/EvilDuck). It is a single-sided PCB built around the RP2040 microcontroller as the brain, paired with 16 MB of flash memory, a microSD card reader, and a USB-A connector.

## Motivation

### Cost

Commercial badUSB devices like the Hak5 USB Rubber Ducky are quite costly. At around $100, it is expensive for a board that essentially consists of a standard microcontroller, flash storage, and a few passive components—especially when factoring in international shipping to Vietnam and the risk of burning a board during testing. Building a custom solution allows me to get the exact features I need for a fraction of the price.

### Experience

Still, my main motivation for designing this board was curiosity. I have a strong personal interest in electrical engineering and hardware security, so designing a PCB from scratch was a great opportunity to learn.

## Prerequisites

Before starting this design, I already had a basic understanding of electronics physics and circuit calculations, along with hands-on experience programming and wiring microcontrollers and microprocessors.

## Learning from Previous Work

The EvilDuck SD version uses an ATmega32U4 as the brain of the device. Looking at its schematics, the design is very simple, consisting mainly of the MCU, a crystal oscillator, USB headers, a power circuit, and an SD card slot.

However, upon closer inspection of the EvilDuck schematics, I noticed there were no filtering capacitors at all. To make my design more reliable, I decided to add decoupling capacitors along with protection components like an ESD diode, a USB fuse, and a USB bulk capacitor. While drafting the initial schematics and calculating the bill of materials (BOM), the estimated cost climbed to around $10 per board (excluding manufacturing and shipping). At that moment, I realized I needed to optimize the design to bring the cost down.

## Cost Reduction

This step was tricky because I had to balance the safety and reliability of the board against the overall cost (and board size, though since this was my first PCB design, size was not a strict constraint).

To explore cheaper microcontroller alternatives to the ATmega32U4, I brainstormed and asked an AI for recommendations. Here is what it suggested:

```text
You can replace the ATmega32U4, but the replacement must have native USB device support. For a Rubber-Ducky-like defensive demo, the MCU must be able to enumerate as a USB HID keyboard/mouse. A normal USB-UART chip like CH340/CP2102 is not enough.
...
Best overall replacement: RP2040
Best compatibility with EvilDuck/Arduino Leonardo style code: ATmega32U4
Best if you already know STM32: STM32F103C8T6
Best if you want WiFi/web UI: ESP32-S3
Do not choose classic ESP32-WROOM-32 for USB HID-over-USB

```

Since I didn't need Wi-Fi or a web interface for this revision, I crossed out the ESP32-S3. Based on my previous experience with the STM32 family, I wasn't too fond of the STM32 flashing workflow, so I ruled out the STM32F103C8T6 as well. Ultimately, I chose the RP2040.

To reduce the cost further, I also decided to omit the dedicated ESD protection diode.

## The Main Design

### RP2040

First came the hardest part: wiring the RP2040. I connected all IOVDD pins, USB_VDD, ADC_AVDD, and VREG_IN to the 3.3V rail (VREG_IN steps the voltage down to output a 1.1V rail on VREG_OUT, which then connects to the DVDD pins). Decoupling capacitors were placed as close to the RP2040 power pins as possible. I also connected TESTEN to GND through an optional 0-ohm resistor, and wired the RUN pin with a 10k pull-up resistor and a reset button to GND.

One critical detail to remember is the pair of series termination resistors on the USB_DP and USB_DM lines. These must be placed right next to the RP2040, with recommended values between 20 and 30 ohms—specifically, 27-ohm 1% resistors are ideal.

Looking back at my USB differential pair routing, my trace geometry was actually far from ideal. With a 1.0 mm PCB thickness, a trace width of 0.254 mm, and a gap of 1.5 mm, the differential impedance reached around 200 ohms (well above the 90-ohm USB 2.0 standard). To fix this in future revisions, the trace width should be increased and the gap between the two traces significantly reduced.

### Crystal Oscillator

Although the RP2040 has an internal ring oscillator and doesn't strictly require an external clock source, I added a 12 MHz crystal to ensure accurate timing for USB communication. The crystal circuit connects to the XIN and XOUT pins and includes two load capacitors and a damping resistor.

The load capacitors must be calculated properly based on the crystal's specifications. I chose the X322512MSB4SI crystal, which has a specified load capacitance ($C_L$) of 20 pF. Using the standard formula $C_L = \frac{C_1 \cdot C_2}{C_1 + C_2} + C_{stray}$, where $C_1 = C_2$ and the stray capacitance ($C_{stray}$) from the XIN/XOUT pins and PCB traces is approximately 3 pF, we get:

$$\frac{C_1}{2} + 3\text{ pF} = 20\text{ pF} \implies C_1 = C_2 = 34\text{ pF}$$

Choosing the closest standard value gave me 33 pF for both capacitors. *(Note: Check your original equation in the draft—you wrote $2 \cdot C_1 + 3\text{ pF} = 20\text{ pF}$, which would mathematically equal 8.5 pF, whereas the parallel combination formula $\frac{C_1}{2} + 3\text{ pF} = 20\text{ pF}$ is what actually yields your correct 33 pF value!)*

### External Flash

Because the RP2040 only contains internal SRAM and no onboard flash, external QSPI flash memory is required to store code. I chose the W25Q16JVSSIQ (16 MB / 128 Mbit, or 2 MB / 16 Mbit depending on your exact part suffix) and placed a decoupling capacitor right next to its power pin. On the CS pin, I added a 10k pull-up resistor (not strictly necessary, but good practice) and a 1k resistor for the USB_BOOT button signal. These resistors were placed close to the flash chip so long copper traces wouldn't degrade the signal. Finally, I routed QSPI_CSn, QSPI_SD0 through QSPI_SD3, and QSPI_CLK to pins 51–56 on the RP2040.

### Power

Next was the power regulation stage. While the classic LM1117-3.3 LDO can supply 0.8A to 1A of current, its dropout voltage of 1.2V is quite high. I wanted an LDO with a much lower dropout voltage, even if it meant accepting a lower maximum output current.

My first choice was the AP2112K-3.3TRG1, a 3.3V LDO offering 0.6A output current and a 400 mV dropout voltage. However, after visiting several electronics shops in Ho Chi Minh City (around District 5 and District 10), none of them had it in stock. Instead, I switched to the RT9013-33GB, which provides 3.3V at 0.5A with an even better 250 mV dropout voltage—and thankfully, I found it locally. Following the datasheet's typical application circuit, I added 1 µF capacitors on both the input and output, and pulled the EN pin up to the 5V rail through a 10k resistor.

### USB Connector

Initially, I wanted to include both USB-A and USB Type-C connectors on the same board. However, once I placed both footprints at the edge of the board, I realized routing them together on a single layer would be too cramped. Since USB-A has only four pins and is much easier to route, I stuck with USB-A and placed a decoupling capacitor close to the connector's VBUS pin.

### MicroSD Socket

For the microSD card slot, I added a decoupling capacitor on the VDD pin and pull-up resistors on the data lines, then wired the interface back to pins 27–30 on the RP2040.

### LEDs and Auxiliaries

I added two indicator LEDs with current-limiting resistors: one connected directly to the 3.3V rail for power, and a status LED connected to GPIO25 (pin 37). Finally, I added accessible test pads for 3V3, GND, SWDIO, SWCLK, UART_TX, and UART_RX to make debugging easier.

### Placement and Routing

Aside from the timing- and noise-sensitive components (decoupling capacitors, crystal oscillator, and USB series resistors) that had to sit tightly next to their respective ICs, the remaining parts could be arranged fairly freely. I organized the board linearly from one end to the other: USB connector -> ICs -> microSD socket.

All routing was done manually. I used 0.254 mm traces for general signal routing and wider 0.5 mm traces for the 5V and 3.3V power rails (stepping down to 0.254 mm only in tight spots where thicker traces couldn't fit). I also kept the USB_DP and USB_DM traces parallel, close together, and length-matched.

## Conclusion

* Here is the completed schematic:
![Schematics](blogs/IoTStory/Schematics.png)
* Here is the bare PCB manufactured by [JLCPCB](https://jlcpcb.com/) (I also used their PCBA service to pre-solder a few surface-mount parts):
![PCB](blogs/IoTStory/PCB.jpg)
* And here is the final assembled board after hand-soldering the remaining components:
![Board](blogs/IoTStory/Board.jpg)

Flashing firmware onto EvilWhale works the exact same way as flashing a Raspberry Pi Pico (holding the BOOT button while plugging it into USB).

I know this first revision still has plenty of room for improvement, especially regarding impedance control and protection circuitry. Still, I gained a ton of practical hardware knowledge from building it, and I hope my write-up helps you learn something new too.

## References

* [EvilDuck](https://github.com/cifertech/EvilDuck)
* [RP2040 Datasheet](https://pip-assets.raspberrypi.com/categories/814-rp2040/documents/RP-008371-DS-1-rp2040-datasheet.pdf)
* [RP2040 Hardware Design Guide](https://pip-assets.raspberrypi.com/categories/814-rp2040/documents/RP-008279-DS-2-hardware-design-with-rp2040.pdf)
* [RP2040 Dev-Board](https://github.com/abhinav937/RP2040-Dev-Board)

**P/S:** I updated the github for better tracing.
