#   utilities for parsing requests/building response
import struct
from typing import Type
from uuid import UUID
from constants import *
from socket import socket


class RequestHeader:
    client_id: UUID
    version: int
    code: RequestCode
    payload_size: int

    def __init__(self, uid: UUID, version: int, code: RequestCode, payload_size: int):
        self.client_id = uid
        self.version = version
        self.code = code
        self.payload_size = payload_size


#   validate opcode

def is_valid_code(code: int, enm: Type[Enum]):
    for opt in enm:
        if code == opt.value:
            return True
    return False


def receive_header(client_socket: socket):
    try:
        data = client_socket.recv(REQUEST_HEADER_SIZE)
        uid, version, code, payload_size = struct.unpack(f"<{CLIENT_ID_SIZE}sBHI", data)
        uid = UUID(bytes=uid)
        header = RequestHeader(uid, version, code, payload_size)
        return header
    except:
        print("Did not get enough data to build request header")
        return None


def receive_payload(header: RequestHeader, sock: socket):
    try:
        match header.code:
            case RequestCode.REQUEST_REGISTER.value:
                data = sock.recv(CLIENT_NAME_SIZE)
                client_name = struct.unpack(f"<{CLIENT_NAME_SIZE}s", data)[0].decode('utf-8')
                return client_name
            case RequestCode.REQUEST_RECONNECT.value:
                data = sock.recv(CLIENT_NAME_SIZE)
                client_name = struct.unpack(f"<{CLIENT_NAME_SIZE}s", data)[0].decode('utf-8')
                return client_name
            case RequestCode.REQUEST_SENT_PUBLIC_KEY.value:
                data = sock.recv(CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE)
                client_name, public_key = struct.unpack(f"<{CLIENT_NAME_SIZE}s{PUBLIC_KEY_SIZE}s", data)
                client_name = client_name.decode('utf-8')
                return client_name, public_key
            case RequestCode.REQUEST_SEND_FILE.value:
                print("Receiving file..")
                if header.payload_size == 0:
                    return None
                received_size = 0
                data = b''
                while received_size < header.payload_size:
                    expected = min(BUFFER_SIZE, header.payload_size - received_size)
                    buffer = sock.recv(expected)
                    if not buffer:
                        break
                    data += buffer
                    received_size += len(buffer)
                file_size = struct.unpack_from("<I", data, 0)[0]
                file_name = struct.unpack_from(f"<{FILENAME_SIZE}s", data, CONTENT_SIZE)[0].decode('utf-8')
                encrypted_file = data[CONTENT_SIZE + FILENAME_SIZE:]
                return file_size, file_name, encrypted_file

            case RequestCode.REQUEST_CRC_NOT_OK_RESEND_FILE.value:
                data = sock.recv(FILENAME_SIZE)
                file_name = struct.unpack(f"<{FILENAME_SIZE}s", data)[0].decode('utf-8')
                return file_name

            case RequestCode.REQUEST_CRC_OK.value:
                data = sock.recv(FILENAME_SIZE)
                file_name = struct.unpack(f"<{FILENAME_SIZE}s", data)[0].decode('utf-8')
                return file_name

            case RequestCode.REQUEST_CRC_NOT_OK_ABORT.value:
                data = sock.recv(FILENAME_SIZE)
                file_name = struct.unpack(f"<{FILENAME_SIZE}s", data)[0].decode('utf-8')
                return file_name

    except:
        __send_general_error_message(sock, "Error receiving payload")

# fill string with \0 till 255 bytes length
def add_name_padding(string: str) -> str:
    pad = FILENAME_SIZE - len(string)
    result = string + '\0' * pad
    return result


# strip all null termination symbols
def remove_name_padding(string: str) -> str:
    parts = string.split('\0', 1)
    return parts[0]


def __send_general_error_message(sock: socket, message: str):
    print(f"Error: {message}")
    msg = struct.pack(f"<BHI", SERVER_VERSION, ResponseCode.RESPONSE_GENERAL_ERROR.value, 0)
    sock.sendall(msg)
