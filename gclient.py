import socket
import threading
import tkinter
import tkinter.scrolledtext
from tkinter import simpledialog
import sys
import os
import pickle
from Crypto.Random import get_random_bytes
import hashlib
import bcrypt

# NOTE ---------------------------custom imports---------------------
from configs.keygen import key_generation
from configs.AES import AESCipher
from configs.RSA import RSACipher

# server ip address and port no
IP_ADDRESS = '127.0.0.1'
PORT = 15000

# buffer size to receive
RECV_SIZE = 4096
userName = None


class Client:

    def __init__(self, host, port):
        global userName
        # initialize tcp socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # connect to the server with specified host and ip
        self.sock.connect((host, port))

        # generate public and private key  pair
        private_key, public_key = key_generation()
        self.RSA = RSACipher()
        self.User = {}

        # intialize gui
        msg = tkinter.Tk()

        # ask for username
        msg.withdraw()
        name = simpledialog.askstring(
            "Nickname", "Please choose a nickname", parent=msg)

        self.User[name] = public_key
        userName = name

        # send public and username to the server
        self.sock.send(pickle.dumps(self.User))

        # receive encrypted session key from the server
        message = self.sock.recv(RECV_SIZE)

        # decrypt the sesssion key using private key
        self.session_key = self.RSA.decrypt(private_key, message)

        # initialize aes cipher
        self.AES = AESCipher(self.session_key)

        self.gui_done = False
        self.running = True

        # start receiving and gui threads
        gui_threading = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)
        gui_threading.start()
        receive_thread.start()

    # render gui
    def gui_loop(self):
        global userName
        self.win = tkinter.Tk()
        self.win.configure(bg="lightgray")
        self.win.title('LetTer')

        self.chat_label = tkinter.Label(
            self.win, text=f'{userName}\'s Chat', bg="lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

        self.textarea = tkinter.scrolledtext.ScrolledText(self.win)
        self.textarea.pack(padx=20, pady=5)
        self.textarea.config(state='disabled')

        self.msg_label = tkinter.Label(
            self.win, text='Message:', bg="lightgray")
        self.msg_label.config(font=("Arial", 12))
        self.msg_label.pack(padx=20, pady=5)

        self.input_area = tkinter.Text(self.win, height="3")
        self.input_area.pack(padx=20, pady=5)

        self.send_button = tkinter.Button(
            self.win, text="Send", command=self.write)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.gui_done = True
        self.win.mainloop()
        self.win.protocol('WM_DELETE_WINDOW', self.stop)

    def write(self):
        # get msg from the user
        message = f"{self.input_area.get('1.0','end')}"

        # quit server
        if(message == '/bye'):
            message = message.encode('utf-8')
            ct = self.AES.encrypt(message)
            h256 = hashlib.sha256(message).hexdigest()
            msg_hash = [ct, h256]
            self.sock.send(pickle.dumps(msg_hash))
            self.running = False
            self.win.destroy()
            self.sock.close()
            sys.exit(0)

           # normal msg send to server
        else:
            msg = message.encode('utf-8')
            # encrypt msg using session key
            ct = self.AES.encrypt(msg)

            # generate hash for the msg
            h256 = hashlib.sha256(msg).hexdigest()
            msg_hash = [ct, h256]

            # send cipher text and hash to the server
            self.sock.send(pickle.dumps(msg_hash))

            # print msg on the client side
            message = 'You: '+message
            self.textarea.config(state='normal')
            self.textarea.insert('end', message)
            self.textarea.yview('end')
            self.textarea.config(state='disabled')

        self.input_area.delete('1.0', 'end')

    # exit handler
    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)

    def receive(self):
        while self.running:
            try:
                # receive cipher text and hash from the server
                msg_hash = self.sock.recv(RECV_SIZE)
                msg_hash = pickle.loads(msg_hash)
                message = msg_hash[0]
                h256 = msg_hash[1]

                # Print to log area
                print('Received CT: ', message)
                print('Received H256', h256)

                # decrypt the cipher using session key
                message = self.AES.decrypt(message)

                # compute hash for the msg and verify with received hash
                if(hashlib.sha256(message).hexdigest() == h256):
                    print('Hash matches verified messages')
                    message = message.decode('utf-8')
                    if self.gui_done:
                        self.textarea.config(state='normal')
                        self.textarea.insert('end', message)
                        self.textarea.yview('end')
                        self.textarea.config(state='disabled')

                else:
                    print('ignored')

            except ConnectionAbortedError:
                break
            except:
                print('error')
                self.sock.close()
                break


client = Client(IP_ADDRESS, PORT)
