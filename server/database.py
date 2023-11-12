import os.path
import sqlite3
from pathlib import Path
from uuid import UUID, uuid4
from datetime import datetime
from threading import Lock

from constants import *


class Client:
    id: UUID
    name: str
    public_key: bytes
    last_seen: datetime
    aes_key: bytes

    def __init__(self, uid, name, public_key=None, aes_key=None):
        self.id = uid
        self.name = name
        self.public_key = public_key
        self.last_seen = datetime.now()
        self.aes_key = aes_key


#  classes Client and File are used to build tables in memory

class File:
    id: UUID
    filename: str
    pathname: str
    verified: bool

    def __init__(self, uid, filename, pathname, verified=None):
        self.id = uid
        self.filename = filename
        self.pathname = pathname
        self.verified = verified


class Database:
    clients = {}
    files = []
    connection: sqlite3.Connection

    def __init__(self):
        self.lock = Lock()

        self.connection = self.__connect_sqlite()
        self.__initiate_db()
        self.__load_db()

    def register_client(self, c_name: str):
        if not self.client_name_exists(c_name):
            client = Client(uuid4(), c_name)
            with self.lock:
                cursor = self.connection.cursor()
                cursor.execute("INSERT INTO clients (id, name, last_seen) VALUES (?,?,?)",
                               [client.id.bytes, client.name, client.last_seen])
                cursor.close()
                self.connection.commit()
                self.clients[client.id] = client
            return client.id
        else:
            print(f"user {c_name} already exists")
            return None

    def add_file(self, uid: UUID, filename: str, pathname: str):
        file = File(uid, filename, pathname, 0)
        with self.lock:  # TODO check if exists in list
            self.files.append(file)
            cursor = self.connection.cursor()
            cursor.execute("INSERT OR REPLACE INTO files (id, filename, pathname, verified) VALUES (?,?,?,?)",
                           [uid.bytes, file.filename, file.pathname, file.verified])
            cursor.close()
            self.connection.commit()

    # Returns True if succeeded, else False
    def delete_file(self, uid: UUID, filename: str):
        path = self.__get_filepath(uid, filename)
        if os.path.exists(path):
            os.remove(path)
            with self.lock:
                for file in self.files:
                    if file.id == uid and file.filename == filename:
                        self.files.remove(file)
                        break
                cursor = self.connection.cursor()
                cursor.execute("DELETE FROM files WHERE id = ? AND filename = ?", [uid.bytes, filename])
                cursor.close()
                self.connection.commit()
        else:
            print("Error: no file with name ", filename)

    def verify_file(self, uid: UUID, filename: str):
        with self.lock:
            for file in self.files:
                if uid == file.id and filename == file.filename:
                    file.verified = True
            cursor = self.connection.cursor()
            cursor.execute("UPDATE files SET verified = ? WHERE id = ? AND filename = ?", [1, uid.bytes, filename])
            cursor.close()
            self.connection.commit()

    def update_last_seen(self, uid: UUID):
        dt = datetime.now()
        with self.lock:
            self.clients[uid].last_seen = dt
            cursor = self.connection.cursor()
            cursor.execute("UPDATE clients SET last_seen = ? WHERE id = ?", [dt, uid.bytes])
            cursor.close()
            self.connection.commit()

    def add_keys(self, uuid: UUID, public_key: bytes, aes_key: bytes):
        with self.lock:
            self.clients[uuid].public_key = public_key
            self.clients[uuid].aes_key = aes_key
            cursor = self.connection.cursor()
            cursor.execute("UPDATE clients SET public_key = ? , aes_key = ? WHERE id = ?",
                           [public_key, aes_key, uuid.bytes])
            cursor.close()
            self.connection.commit()

    def client_name_exists(self, username: str) -> bool:
        exists = False
        with self.lock:
            for c in self.clients.values():
                if c.name == username:
                    exists = True
        return exists

    def client_id_exists(self, uuid: UUID):
        with self.lock:
            return True if self.clients[uuid] is not None else False

    def get_client_uuid(self, name: str):
        with self.lock:
            for client in self.clients.values():
                if client.name == name:
                    return client.id
        return None

    def client_has_RSA(self, uuid: UUID):
        if uuid is None:
            return False
        with self.lock:
            if self.clients[uuid].public_key is not None:
                return True
            else:
                return False

    def get_aes(self, uuid: UUID):
        with self.lock:
            return self.clients[uuid].aes_key

    def get_RSA(self, uuid: UUID):
        with self.lock:
            return self.clients[uuid].public_key

    def __get_filepath(self, uid: UUID, filename: str) -> str:
        with self.lock:
            for file in self.files:
                if file.id == uid and file.filename == filename:
                    return file.pathname
            return ""

    def __load_db(self):
        with self.lock:
            cursor = self.connection.cursor()
            clients = cursor.execute("SELECT * FROM clients").fetchall()
            files = cursor.execute("SELECT * FROM files").fetchall()
            for client in clients:
                uid = UUID(bytes=client[0])
                self.clients[uid] = Client(uid, client[1], client[2], client[3])
            for file in files:
                uid = UUID(bytes=client[0])
                self.files.append(File(uid, file[1], file[2], file[3]))
            cursor.close()

    def __connect_sqlite(self) -> sqlite3.Connection:
        return sqlite3.connect(SERVER_DATABASE_FILE, check_same_thread=False)

    def __initiate_db(self):
        cursor = self.connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS clients(
                            id BLOB PRIMARY KEY,
                            name TEXT,
                            public_key BLOB,
                            last_seen TEXT,
                            aes_key BLOB);""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS files(
                            id BLOB,
                            filename TEXT,
                            pathname TEXT,
                            verified INTEGER,
                            UNIQUE(id, filename));""")  # table 'files' will not have primary key
        self.connection.commit()
        cursor.close()

    def close(self):
        self.connection.close()
