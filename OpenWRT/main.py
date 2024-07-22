import usqlite

import ssl
import sys
from lib.microdot.microdot import Microdot

app = Microdot()

if not usqlite.mem_status():
    usqlite.mem_status(True) # Enable memory usage monitoring

con = usqlite.connect("data.db")

@app.route('/')
async def index(request):
    # con.executemany(
    #     "BEGIN TRANSACTION;"
    #     "CREATE TABLE IF NOT EXISTS data (name TEXT, year INT);"+
    #     "INSERT INTO data VALUES ('Larry', 1902);"+
    #     "INSERT INTO data VALUES ('Curly', 1903);"+
    #     "INSERT INTO data VALUES ('Moe', 1897);"+
    #     "INSERT INTO data VALUES ('Shemp', 1895);"+
    #     "COMMIT;")

    with con.execute("SELECT * from data") as cur:
        for row in cur:
            print("stooge:", row)
            
    con.close()

    print("usqlite mem - current:", usqlite.mem_current(), "peak:", usqlite.mem_peak())

    return 'Hello, world!'



#sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
print(sys.version)
# if sys.version.split(' ')[1] == 'MicroPython':
#     sslctx.load_cert_chain('cert.pem', 'key.pem')
# else:
#       sslctx.load_cert_chain('cert.crt', 'key.crt')
app.run(port=5000, debug=True)
#, ssl=sslctx)