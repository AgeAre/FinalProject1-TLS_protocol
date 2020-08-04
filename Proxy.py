#!/usr/bin/python3
# This is a simple port-forward / proxy, written using only the default python
# library. If you want to make a suggestion or fix something you can contact-me
# at voorloop_at_gmail.com
# Distributed over IDC(I Don't Care) license

import socket
import select
import time
import sys
import os
import subprocess
from Crypto.Cipher import AES

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 8192
delay = 0.0001
forward_to = ('10.10.80.102', 443)

class Forward:

    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print(e)
            return False

class Decryptor:

    def __init__(self):
        # generating random 16 bytes keys just for the sake of initializing
        self.key = os.urandom(16).hex()
        self.iv = os.urandom(16).hex()

    def insert_keys(self, key, iv):
        self.key = key
        self.iv = iv
        # creating a new AES object using CBC mode
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    def decrypt(self, cipher_text):
        plain_text = self.cipher.decrypt(cipher_text)
        return plain_text

class MiddleBox:

    input_list = []
    channel = {}
    decryptor = Decryptor()

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)         # number of requests the proxy is able to process

    def main_loop(self):
        self.input_list.append(self.server)

        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])

            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    # closing connection
                    self.on_close()
                    break
                else:
                    # getting a new data packet
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()

        if forward:
            print("Client @ ", clientaddr, " has connected")
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print("Closing connection with client", clientaddr)
            clientsock.close()

    def on_close(self):
        print("Client @ ", self.s.getpeername(), " has disconnected")

        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]

        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()

        # close the connection with remote server
        self.channel[self.s].close()

        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        # print("".join("{:02x}".format(c) for c in self.data))
        self.parse_data()
        self.channel[self.s].send(data)

    def get_keys_from_client(self):

        # copying the keys from the client.
        # in theory, if the client refuses, the connection is killed
        subprocess.call('/home/compm/Desktop/Scripts/get_key_file.sh', shell=True)
        subprocess.call('/home/compm/Desktop/Scripts/get_iv_file.sh', shell=True)

        key_file = open("/home/compm/Desktop/client_write_key.txt", "r")
        iv_file = open("/home/compm/Desktop/client_write_iv.txt", "r")

        # reading only 32 characters
        client_write_key_str = key_file.read(32)
        client_write_iv_str = iv_file.read(32)

        # formatting the keys to bytes array
        client_write_key = bytes.fromhex(client_write_key_str)
        client_write_iv = bytes.fromhex(client_write_iv_str)

        # inserting the keys to our default decryptor
        self.decryptor.insert_keys(client_write_key, client_write_iv)

    def parse_data(self):
        data_in_hex = "".join("{:02x}".format(c) for c in self.data)

        # handshake message
        if(data_in_hex[0:2] == "16"):

            # Client Key Exchange. Keys have been generated
            if(data_in_hex[10:12] == "10"):

                # get keys from the client
                print("Contacting client for encryption keys...")
                self.get_keys_from_client()
                print("Encryption keys acquired!")

                encrypted_handshake_msg_hex = data_in_hex[data_in_hex.__len__() - 160:]
                encrypted_handshake_msg_bytes = bytes.fromhex(encrypted_handshake_msg_hex)
                self.decryptor.decrypt(encrypted_handshake_msg_bytes)

        # application data
        if (data_in_hex[0:2] == "17"):

            length_in_bytes = int(data_in_hex[6:10], 16)
            length_in_hex = 2 * length_in_bytes

            application_data_hex = data_in_hex[10:length_in_hex+10]
            application_data_bytes = bytes.fromhex(application_data_hex)

            print(repr(self.decryptor.decrypt(application_data_bytes)))

            if (repr(self.decryptor.decrypt(application_data_bytes)).find("launch codes") > -1):
                print("Foul use suspected. Closing connection...")
                self.on_close()

if __name__ == '__main__':
        print("Initializing proxy...")
        mb = MiddleBox('10.10.90.100', 6000)
        print("Proxy has been initialized!")
        try:
            mb.main_loop()
        except KeyboardInterrupt:
            print("Ctrl C - Stopping server")
            sys.exit(1)
