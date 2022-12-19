# mateaberto
Project documentation
Door lock and signaling if there are somebody in the mate room.
WIP!

## Hardware
```
ESP32-WROOM
    |-> Display ssd1306		(I2C: sda(21) scl(22))	ID = 60 #0x3c
    |-> RFID PN532		(I2C: sda(19) scl(18))	ID = 36 #0x24
    |-> Keyboard FT-012/21	(Serial)
```
[ESP32-C3 pico](https://www.aliexpress.com/item/1005004865447043.html)
```
ESP32-C3 pico
    |-> I2C: sda(6)pull-up | scl(6)pull-up. For both peripherals.
    |-> Display ssd1306 ID = 60 #0x3c
    |-> RFID PN532		ID = 36 #0x24
    |-> Keyboard FT-012/21	(Serial)
```