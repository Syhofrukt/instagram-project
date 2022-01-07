import sqlite3
from typing import Iterator
from contextlib import contextmanager

database_file = "just_database.db"


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(database_file)
    yield conn
    conn.commit()
