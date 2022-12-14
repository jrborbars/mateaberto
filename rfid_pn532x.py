from machine import Pin, SoftI2C
import time
import libs.ssd1306 as ssd1306
# pn_532_i2c wrapper updated by David Somerville to work with Micropython
import libs.pn532_i2c as pn532_i2c
import libs.wifimgr as wifimgr
import ntptime
import btree

try:
    f = open("mydb", "r+b")
except OSError:
    f = open("mydb", "w+b")

# Now open a database itself
try:
    db = btree.open(f)
    print('DB is open and ok.')
except OSError as err:
    print('DB was not opened.', str(err))

db[b"MASTER"] = b"8:1a:83:35"
# I2C adresses
RFID_ID = 36 #0x24
OLED_ID = 60 #0x3c
####################
OLED_W = 128
OLED_H = 64

GRE_LED = machine.Pin(15, machine.Pin.OUT)
RED_LED = machine.Pin(16, machine.Pin.OUT)
#i2c = I2C( scl=Pin(5), sda=Pin(4), freq=1000000) # GPIO5 and GPIO4 (D1 and D2)
i2c = SoftI2C( scl=Pin(18), sda=Pin(19), freq=1000000) # GPIO5 and GPIO4 (D1 and D2)
i2c2 = SoftI2C(scl=Pin(22), sda=Pin(21), freq=1000000)

# wlan is a working network.WLAN(STA_IF) instance.
wlan = wifimgr.get_connection()
if wlan is None:
    print("Could not initialize the network connection.")
    while True:
        pass  # you shall not pass :D
else:
    print("Network connection OK.")
time.sleep(5)
#oled = ssd1306.SSD1306_I2C(OLED_W, OLED_H, i2c2)
#time.sleep(3)

ntptime.host = 'br.pool.ntp.org'
ntptime.settime()	# this queries the time from an NTP server
print('TIME: ',time.localtime())

def scan_i2c(iic):
    i2c_devices = None
    try:
        i2c_devices = iic.scan()
        print('Scanned')
    except Exception as e:
        print('EXP ',str(e))
    if i2c_devices is not None and len(i2c_devices) > 0:
        print('Something was found...',i2c_devices)
        for s in i2c_devices:
            if s == RFID_ID: 
                print('PN532 found at I2C address: ', s)
                break
            if s == OLED_ID:
                print('SSD1306 found at I2C address: ', s)
                break
    else:
        print('Nothing was found...')
    print('Finished')
            
pn532 = pn532_i2c.PN532_I2C(i2c, debug=False, reset=5)
ic, ver, rev, support = pn532.get_firmware_version()
scan_i2c(i2c)
scan_i2c(i2c2)
print(f"Found PN532 with firmware version: {ver}.{rev} | {ic}.{support}")
#oled.text('Hello, World 1!', 0, 0)
#oled.text('Hello, World 2!', 0, 10)
#oled.text('Hello, World 3!', 0, 20)
        
#oled.show()
# Set up configuration for MiFare type cards
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
        print(suid)
        if save_mode:
            save_mode = False
            db_len = len(db)
            db[bytes(db_len)] = suid
            print("SAVED!")
            print("SAVE MODE OFF!")
            RED_LED.low()
            time.slep(3)
            GRE_LED.low()
        else:
            if bytes(suid) in db:
                print("ACCESS GRANTED!")
                GRE_LED.high()
                time.sleep(3)
                GRE_LED.low()
            else:
                print("ACCESS DENIED!")
    if counter == 10:
        counter = 0
        save_mode = True
        print("SAVE MODE ON!")
        time.sleep(5)
        
    last_uid = uid
