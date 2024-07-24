import usqlite
import ssl
import sys
from lib.microdot.microdot import Microdot

app = Microdot()
"""
Device0 -> keyboard
Device1 -> tag
Device2 -> 
"""
if not usqlite.mem_status():
    usqlite.mem_status(True) # Enable memory usage monitoring

def create_tables():
    con = usqlite.connect("data.db")
    con.executemany("""
        BEGIN TRANSACTION;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            secret_device0 TEXT,
            secret_device1 TEXT,
            secret_device2 TEXT,
            secret_device3 TEXT,
            secret_device4 TEXT,
            secret_device5 TEXT,
            secret_device6 TEXT,
            secret_device7 TEXT,
            secret_device8 TEXT,
            secret_device9 TEXT
        );
        INSERT INTO users (name,secret_device0) VALUES ('admin', '314159265359');
        INSERT INTO users (name,secret_device0) VALUES ('jrb', '1234');
        COMMIT;
    """)

# async def authorize(req):
#     con = usqlite.connect("data.db")
#     device = req.device
#     response = con.execute(f"SELECT name, secret_device{device} from users;")
#     response.fetchone()

# @app.before_request
# async def authenticate(request):
#     user = await authorize(request)
#     if not user:
#         return 'Unauthorized', 401
#     request.g.user = user


@app.errorhandler(404)
async def not_found(request):
    return {'error': 'resource not found'}, 404


@app.post('/user_check/<int:device>/')
async def index(request, device):
    try:
        if device > 10:
            #raise ValueError
            return 'Unauthorized', 401
        passwd = request.json
        print("PASSWD", request.json)
    except ValueError:
        return 'Unauthorized', 401

    con = usqlite.connect("data.db")
    res = con.execute(f"SELECT name from users WHERE secret_device{device}=?",passwd)
    user = res.fetchone()
    con.close()
    if not user:
        return 'Unauthorized', 401
    return f"Ola, {user[0]}", 200

#sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
print(sys.version)
# if sys.version.split(' ')[1] == 'MicroPython':
#     sslctx.load_cert_chain('cert.pem', 'key.pem')
# else:
#       sslctx.load_cert_chain('cert.crt', 'key.crt')
app.run(port=5000, debug=True)
#, ssl=sslctx)