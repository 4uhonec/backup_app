import socket
from constants import *
from database import *
from session import Session

class Server:
    __port: int
    __db: Database
    __host = "0.0.0.0"

    def __init__(self):
        self.__port = self.__get_port()

    def __get_port(self):
        try:
            with open(SERVER_PORT_FILE, 'r') as f:
                return int(f.readline())
        except:
            print(f"failed to read {SERVER_PORT_FILE}, using default port {DEFAULT_SERVER_PORT}")
            return DEFAULT_SERVER_PORT

    def start(self):
        self.__db = Database()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((self.__host, self.__port))
                server_socket.listen()

                while True:
                    client_socket, client_address = server_socket.accept()
                    print(f"New client session from {client_address}")
                    Session(client_socket, self.__db).start()
        except:
            self.__db.close()
            print("Error: server closed")
