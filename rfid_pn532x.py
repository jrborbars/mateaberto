#import machine
from machine import Pin, SoftI2C
import neopixel

import time
import libs.ssd1306 as ssd1306
# pn_532_i2c wrapper updated by David Somerville to work with Micropython
import libs.pn532_i2c as pn532_i2c
import libs.wifimgr as wifimgr
import ntptime
import btree

# Create a file to the database
try:
    f = open("mydb.db", "r+b")
    print('#1 - DB File exists.')
except OSError as err:
    f = open("mydb.db", "w+b")
    print(f'#1 - DB file does NOT exists.[{err}] Creating...')

# Now open a database itself
try:
    db = btree.open(f)
    print('#2 - DB is open and ok.')
    if b"MASTER" in db:
        print('#3 - MASTER key ok.')
    else:
        db[b"MASTER"] = b"8:1a:83:35"
        db.flush()
        print('#3 - MASTER key created.'+str(db[b"MASTER"])[:-3])
except OSError as err:
    print('#2 - DB was not opened.', str(err), ' Exiting....')
    raise SystemExit

# I2C PINS
#ESP32-C3
SDA = Pin(5, pull=Pin.PULL_UP)
SCL = Pin(6, pull=Pin.PULL_UP)

# I2C adresses
RFID_ID = 36 #0x24
OLED_ID = 60 #0x3c
####################
OLED_W = 128
OLED_H = 64

LED_PIN = Pin(2)
LED = neopixel.NeoPixel(LED_PIN,1)
LED[0] = (255,255,0) # Yellow
LED.write()
time.sleep(.5)
LED[0] = (0,0,0) # Yellow
LED.write()


#GRE_LED = Pin(15, Pin.OUT)
#RED_LED = Pin(16, Pin.OUT)
#i2c = I2C( scl=Pin(5), sda=Pin(4), freq=1000000) # GPIO5 and GPIO4 (D1 and D2)
#i2c = SoftI2C( scl=Pin(18), sda=Pin(19), freq=1000000) # GPIO5 and GPIO4 (D1 and D2) #ESP8266 Pin assignment
i2c = SoftI2C(scl=SCL, sda=SDA) # , freq=1000000 ESP32-C3
#i2c2 = SoftI2C(scl=Pin(22), sda=Pin(21), freq=1000000) # ESP32
#i2c2 = SoftI2C(scl=Pin(6), sda=Pin(5), freq=1000000) # ESP32-C3

# wlan is a working network.WLAN(STA_IF) instance.
wlan = wifimgr.get_connection()
if wlan is None:
    print("#4 - Could not initialize the network connection.")
    while True:
        pass  # you shall not pass :D
else:
    print("#4 - Network connection OK.")
time.sleep(5)

#oled = ssd1306.SSD1306_I2C(OLED_W, OLED_H, i2c)
time.sleep(3)

#ntptime.host = '201.49.148.135'
ntptime.host = '200.20.186.76'
#ntptime.host = 'br.pool.ntp.org'
NTP_FLAG = True
counter = 0

while NTP_FLAG:
    try:
        ntptime.settime()	# this queries the time from an NTP server
    except OSError as err:
        if str(err).split(' ')[2] == "ETIMEDOUT":
            if counter > 5:
                break
            print("NTP Error ",err, f" Trying again[{counter}]...")
            time.sleep(2)
        else:
            print("NTP Error ",err)
            #print(str(err).split(' ')[2])
            NTP_FLAG = False
    counter += 1
print('#5 - UTC TIME: ',time.localtime())

def scan_i2c(iic):
    i2c_devices = None
    try:
        i2c_devices = iic.scan()
        print('#6 - I2C scanned')
    except Exception as e:
        print('#6 - I2C EXP ',str(e))
    if i2c_devices is not None and len(i2c_devices) > 0:
        print('     Something was found...',i2c_devices)
        for s in i2c_devices:
            if s == RFID_ID: 
                print('     PN532 found at I2C address: ', s)
            if s == OLED_ID:
                print('     SSD1306 found at I2C address: ', s)
    else:
        print('#6 - Nothing was found. Exiting...')
        raise SystemExit
    print('     Finished')

scan_i2c(i2c)            

pn532 = pn532_i2c.PN532_I2C(i2c, debug=True)
#ic, ver, rev, support = pn532.get_firmware_version()

#scan_i2c(i2c2)
#print(f"Found PN532 with firmware version: {ver}.{rev} | {ic}.{support}")
#oled.text('Hello, World 1!', 0, 0)
#oled.text('Hello, World 2!', 0, 10)
#oled.text('Hello, World 3!', 0, 20)        
#oled.show()

# Set up configuration for MiFare type cards
print("#7 - Everything OK.")
pn532.SAM_configuration()
print("Waiting RFID/NFC card....")
last_uid = None
counter = 0
save_mode = False
MASTER = db[b"MASTER"]
while True:
    uid = pn532.read_passive_target(timeout=0.5)
    if uid is None:
        last_uid = None
        #oled.fill(0)
        #oled.show()
        continue
    if last_uid == uid and uid == MASTER:
        counter +=1
    else:
        print(f"Found card. UID", [hex(i) for i in uid])
        #oled.fill(0)
        suid = ""
        for i in uid:
            if len(suid) > 0:
                suid +=":"
            s = hex(i)[2:4]
            suid += s
        #oled.text("UID found",0,0)
        #oled.text(suid,0,10)
        #oled.show()
        print("SUID ",suid)
        if save_mode:
            save_mode = False
            db_len = len(db)
            db[bytes(db_len)] = suid
            print("SAVED!")
            print("SAVE MODE OFF!")
            LED[0] = (255,0,0)
            LED.write()
            time.sleep(1)
            LED[0] = (0,255,0)
            LED.write()
            time.sleep(1)
            LED[0] = (0,0,0)
            LED.write()
        else:
            if bytes(suid) in db:
                print("ACCESS GRANTED!")
                LED[0] = (0,255,0)
                LED.write()
                time.sleep(3)
                LED[0] = (0,0,0)
                LED.write()
            else:
                print("ACCESS DENIED!")
    if counter == 10:
        counter = 0
        save_mode = True
        print("SAVE MODE ON!")
        time.sleep(5)
        
    last_uid = uid
