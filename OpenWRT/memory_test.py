import usqlite

def trace(sql):
    print("trace:", sql)

usqlite.mem_status(True)

def mem():
    print("mem current:", usqlite.mem_current(), "peak:", usqlite.mem_peak())

print("Memory Test")

print("sqlite_version:", usqlite.sqlite_version)

db = "test.db"
#db = ":memory:"

mem()

con = usqlite.connect(db)
print("connection:", con)

con.set_trace_callback(trace)

mem()

con.executemany(
    "BEGIN TRANSACTION;"
    "CREATE TABLE IF NOT EXISTS data (name TEXT, year INT);"+
    "INSERT INTO data VALUES ('Larry', 1902);"+
    "INSERT INTO data VALUES ('Cury', 1903);"+
    "INSERT INTO data VALUES ('Moe', 1897);"+
    "COMMIT;"
    "")

print("Total changes:",con.total_changes)

mem()

print("close")
con.close()

mem()
# Output

# Memory Test
# sqlite_version: 3.46.0
# mem current: 0 peak: 32
# connection: <Connection 'test.db'>
# mem current: 11968 peak: 12000
# trace: BEGIN TRANSACTION;
# trace: CREATE TABLE IF NOT EXISTS data (name TEXT, year INT);
# trace: INSERT INTO data VALUES ('Larry', 1902);
# trace: INSERT INTO data VALUES ('Cury', 1903);
# trace: INSERT INTO data VALUES ('Moe', 1897);
# trace: COMMIT;
# Total changes: 3
# mem current: 26144 peak: 28704
# close
# mem current: 0 peak: 28704