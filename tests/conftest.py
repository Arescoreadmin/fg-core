import sqlite3
import pytest

@pytest.fixture()
def clear_decisions(sqlite_path: str):
    con = sqlite3.connect(sqlite_path)
    try:
        try:
            con.execute("DELETE FROM decisions;")
            con.commit()
        except sqlite3.OperationalError as e:
            # Table missing = schema not initialized yet
            # This should not fail the test suite
            if "no such table" not in str(e):
                raise
    finally:
        con.close()