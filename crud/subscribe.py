from models.user import UserModel
import sqlite3


class SubscribeCRUD:
    def exists(
        self, conn: sqlite3.Connection, user: UserModel, to_subscribe: UserModel
    ) -> bool:
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT COUNT(*) FROM Subsciptions WHERE who_subscribe=? AND to_subscribe=?",
                (user.id, to_subscribe.id),
            )
            count, *_ = cur.fetchone()
            return count == 1
        finally:
            cur.close()

    def create(
        self, conn: sqlite3.Connection, user: UserModel, to_subscribe: UserModel
    ) -> None:
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO Subsciptions VALUES(?, ?)", (user.id, to_subscribe.id)
            )
        finally:
            cur.close()

    def delete(
        self, conn: sqlite3.Connection, user: UserModel, to_unsubscibe: UserModel
    ) -> None:
        cur = conn.cursor()

        try:
            cur.execute(
                "DELETE FROM Subsciptions WHERE who_subscribe=? AND to_subscribe=?",
                (user.id, to_unsubscibe.id),
            )
        finally:
            cur.close()
