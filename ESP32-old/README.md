# mateaberto
Project documentation
Door lock and signaling if there are somebody in the mate room.
WIP!

## Hardware
```
ESP32
    |-> Display ssd1306		(I2C: sda(21) scl(22))	ID = 60 #0x3c
    |-> RFID PN532		(I2C: sda(19) scl(18))	ID = 36 #0x24
    |-> Keyboard FT-012/21	(Serial)
```