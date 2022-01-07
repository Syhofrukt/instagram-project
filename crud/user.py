from models.user import RegistrationModel, UserModel
import sqlite3
from core import passwords
import uuid
from werkzeug.datastructures import Authorization
from core.errors import AuthError
from core.errors import UserExistsError


class UserCRUD:
    def create(self, conn: sqlite3.Connection, data: RegistrationModel) -> None:
        cur = conn.cursor()

        try:
            user = self.get(conn, data.login)
            if user is not None:
                raise UserExistsError(f"User with login {data.login} already exists")

            user_id = uuid.uuid4()
            cur.execute(
                "INSERT INTO User VALUES(?, ?, ?)",
                (
                    str(user_id),
                    data.login,
                    passwords.hash_password_with_salt(data.password),
                ),
            )
        finally:
            cur.close()

    def authenticate(
        self, conn: sqlite3.Connection, auth_data: Authorization
    ) -> UserModel:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT password FROM User WHERE login=?", (auth_data.username,)
            )
            row = cur.fetchone()

            if row is None:
                raise AuthError("There is no such user")

            password_hashed = row[0]

            if not passwords.verify_password(auth_data.password, password_hashed):
                raise AuthError("Password is incorrect")

            assert auth_data.username is not None

            return self.get(conn, auth_data.username)
        finally:
            cur.close()

    def get(self, conn: sqlite3.Connection, login: str) -> UserModel:
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT User.id, User.login, "
                " COUNT(DISTINCT f1.who_subscribe), COUNT(DISTINCT f2.to_subscribe)"
                "FROM User "
                "LEFT JOIN Subsciptions AS f1 ON f1.to_subscribe = User.id "
                "LEFT JOIN Subsciptions AS f2 ON f2.who_subscribe = User.id "
                "WHERE User.login=?",
                (login,),
            )
            row = cur.fetchone()

            if row is None:
                return None

            id, login, followers, follows = row

            if id is None:
                return None

            return UserModel(id=id, login=login, followers=followers, follows=follows)
        finally:
            cur.close()
