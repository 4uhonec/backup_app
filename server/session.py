from threading import Thread
# from socket import socket
from uuid import UUID
from data_utils import *
import os
from crypto import *
from database import Database


class Session(Thread):
    sock: socket
    database: Database
    authorized: bool  # true if connected or reconnected in this session
    exchanged_keys: bool  # true if exchanged keys in current session

    def __init__(self, sock: socket, database: Database):
        super().__init__(daemon=True)
        self.sock = sock
        self.__database = database
        self.authorized = False
        self.exchanged_keys = False
        self.aes_key: bytes

    def run(self):
        try:
            while True:
                self.__receive_request()
        except:
            print("Exception in run() method, general error")

    def __receive_request(self):
        header = receive_header(self.sock)
        if not is_valid_code(header.code, RequestCode):
            print("Error: unknown request opcode")
            self.__send_response(ResponseCode.RESPONSE_GENERAL_ERROR)
        payload = receive_payload(header, self.sock)

        match header.code:
            case RequestCode.REQUEST_REGISTER.value:
                client_name = remove_name_padding(payload)
                uuid = self.__database.get_client_uuid(client_name)
                if not self.__database.client_name_exists(client_name) or not self.__database.client_has_RSA(uuid):
                    if not self.__database.client_name_exists(client_name):
                        client_id = self.__database.register_client(client_name)
                    else:
                        client_id = self.__database.get_client_uuid(client_name)
                    b_payload = struct.pack(f"<{CLIENT_ID_SIZE}s", client_id.bytes)
                    self.__send_response(ResponseCode.RESPONSE_REGISTRATION_SUCCEEDED, len(b_payload), b_payload)
                    self.authorized = True
                    self.__database.update_last_seen(client_id)
                    print("Successful registration of user ", client_name)
                else:
                    print(f"Registration of user {client_name} failed")
                    self.__send_response(ResponseCode.RESPONSE_REGISTRATION_FAILED)

            case RequestCode.REQUEST_RECONNECT.value:
                client_name = remove_name_padding(payload)
                if self.__database.client_name_exists(client_name) and self.__database.client_has_RSA(header.client_id):
                    public_key = self.__database.get_RSA(header.client_id)
                    encrypted_aes = self.__make_encrypted_aes(header.client_id, public_key)
                    b_payload = struct.pack(f"<{CLIENT_ID_SIZE}s{len(encrypted_aes)}s", header.client_id.bytes, encrypted_aes)
                    self.__send_response(ResponseCode.RESPONSE_RECONNECT_APPROVED_SENDING_AES, len(b_payload), b_payload)
                    self.authorized = True
                    self.exchanged_keys = True
                    self.__database.update_last_seen(header.client_id)

                else:
                    print(f"Reconnect of user {client_name} failed")
                    b_payload = struct.pack(f"<{CLIENT_ID_SIZE}s", header.client_id.bytes)
                    self.__send_response(ResponseCode.RESPONSE_RECONNECT_NOT_APPROVED, len(b_payload), b_payload)

            case RequestCode.REQUEST_SENT_PUBLIC_KEY.value:
                client_name, public_key = payload
                if self.authorized:
                    encrypted_aes = self.__make_encrypted_aes(header.client_id, public_key)
                    b_payload = struct.pack(f"<{CLIENT_ID_SIZE}s{len(encrypted_aes)}s", header.client_id.bytes, encrypted_aes)
                    self.__send_response(ResponseCode.RESPONSE_GOT_PUBLIC_SENDING_AES, len(b_payload), b_payload)
                    self.exchanged_keys = True
                else:
                    print(f"Error receiving/processing public key for user {client_name}")
                    self.__send_response(ResponseCode.RESPONSE_GENERAL_ERROR)

            case RequestCode.REQUEST_SEND_FILE.value:
                if self.authorized and self.exchanged_keys:
                    # calc crc, decrypt and save file
                    file_size, filename, encrypted_file = payload
                    filename = remove_name_padding(filename)
                    print("Received request to backup file ", filename)
                    file = decrypt_file(encrypted_file, self.aes_key)
                    self.__save_file(header.client_id, filename, file)
                    print(f"File {filename} successfully backed up, sending CRC32...")
                    crc = crc32(file)
                    filename = add_name_padding(filename)
                    b_payload = struct.pack(f"<{CLIENT_ID_SIZE}sI{FILENAME_SIZE}sI", header.client_id.bytes, file_size, bytes(filename, "utf-8"), crc)
                    payload_size = CLIENT_ID_SIZE + CONTENT_SIZE + FILENAME_SIZE + CHECKSUM_SIZE
                    self.__database.update_last_seen(header.client_id)
                    self.__send_response(ResponseCode.RESPONSE_FILE_RECEIVED_OK, payload_size, b_payload)
                else:
                    self.__send_response(ResponseCode.RESPONSE_GENERAL_ERROR)

            case RequestCode.REQUEST_CRC_NOT_OK_RESEND_FILE.value:  # TODO add checks for authorised and presence of file??
                filename = remove_name_padding(payload)
                print(f"CRC32 for file {filename} didn't match with client's, getting ready to receive file again")
                self.__database.verify_file(header.client_id, filename)
                self.__send_response(ResponseCode.RESPONSE_MESSAGE_RECEIVED)

            case RequestCode.REQUEST_CRC_OK.value:
                filename = remove_name_padding(payload)
                print(f"CRC32 for file {filename} have been verified")
                self.__database.verify_file(header.client_id, filename)
                self.__send_response(ResponseCode.RESPONSE_MESSAGE_RECEIVED)

            case RequestCode.REQUEST_CRC_NOT_OK_ABORT.value:
                filename = remove_name_padding(payload)
                print(f"CRC32 for file {filename} didn't match for fourth time, abort and delete file")
                self.__database.delete_file(header.client_id, filename)
                self.__send_response(ResponseCode.RESPONSE_MESSAGE_RECEIVED)

            case _:
                print(f"Error: unknown opcode {header.code}")
                self.__send_response(ResponseCode.RESPONSE_GENERAL_ERROR)

    def __send_response(self, response_code: ResponseCode, payload_size=0,
                        b_payload: bytes = b''):

        b_header = struct.pack(f"<BHI", SERVER_VERSION, response_code.value, payload_size)
        try:
            self.sock.sendall(b_header + b_payload)
        except:
            print("Error: was unable to send response")

    def __save_file(self, client_id, filename, data):
        if not os.path.exists(str(client_id)):
            os.makedirs(str(client_id))
        pathname = os.path.join(str(client_id), filename)
        try:
            with open(pathname, 'wb') as file:
                file.write(data)
                self.__database.add_file(client_id, filename, pathname)
        except:
            print(f"Error writing file {filename} to disk")

    def __make_encrypted_aes(self, uuid: UUID, public_key: bytes) -> bytes:
        aes_key = generate_aes()
        self.aes_key = aes_key
        encrypted_aes = encrypt_aes_key(public_key, aes_key)
        self.__database.add_keys(uuid, public_key, aes_key)
        return encrypted_aes
