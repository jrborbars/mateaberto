import usqlite

if not usqlite.mem_status():
    usqlite.mem_status(True) # Enable memory usage monitoring

con = usqlite.connect("test.db")

con.executemany(
    "BEGIN TRANSACTION;"
    "CREATE TABLE IF NOT EXISTS data (name TEXT, year INT);"+
    "INSERT INTO data VALUES ('Larry', 1902);"+
    "INSERT INTO data VALUES ('Curly', 1903);"+
    "INSERT INTO data VALUES ('Moe', 1897);"+
    "INSERT INTO data VALUES ('Shemp', 1895);"+
    "COMMIT;")

with con.execute("SELECT * from data") as cur:
    for row in cur:
        print("stooge:", row)

with con.execute("SELECT * from data") as cur:
    for row in cur:
        print("stooge:", row)

with con.execute("SELECT * from data") as cur:
    for row in cur:
        print("stooge:", row)

with con.execute("SELECT * from data") as cur:
    for row in cur:
        print("stooge:", row)

with con.execute("SELECT * from data") as cur:
    for row in cur:
        print("stooge:", row)

con.close()

print("usqlite mem - current:", usqlite.mem_current(), "peak:", usqlite.mem_peak())
