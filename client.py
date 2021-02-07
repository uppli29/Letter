from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import sys
import os
import pickle
from Crypto.Random import get_random_bytes
import hashlib

# NOTE ---------------------------custom imports---------------------
from configs.keygen import key_generation
from configs.AES import AESCipher
from configs.RSA import RSACipher


# initialize socket
CLIENT = socket(AF_INET, SOCK_STREAM)  # TCP
IP_ADDRESS = '127.0.0.1'  # server ip address
PORT = 15000  # server port
RECV_SIZE = 4096  # buffer size
ACTIVE = True

RECEIVE_THREAD = None
SEND_THREAD = None
name = ''
user_id = ''
User = {}
AES = None

# generating rsa keys
private_key, public_key = key_generation()

# initialize rsa cipher
RSA = RSACipher()


print('='*20, 'Welcome to LetTer', '='*20)


def set_up_client():
    global ACTIVE
    global AES
    global name

    try:
        # try connecting to the server
        CLIENT.connect((IP_ADDRESS, PORT))
    except ConnectionRefusedError:
        print("failed!\n")
        ACTIVE = False
        return
    print("connected!")
    print(f"Client connected to server at {IP_ADDRESS}.")
    rules()

    print("\nEnter a username: ", end='')
    username = input()  # first get username
    name = username
    print('Your public key', public_key)
    User[name] = public_key

    # send public key and username to the server
    CLIENT.send(pickle.dumps(User))

    START = True
    while START:
        # receive encypted aes key from the server
        message = CLIENT.recv(RECV_SIZE)

        # decypt the aes key using private key
        session_key = RSA.decrypt(private_key, message)
        print('\n'*20)
        print('Start Chatting from here >')

        # initialize aes cipher with session key
        AES = AESCipher(session_key)
        START = False


def start_io_loop():
    if ACTIVE:  # as long as threads allowed to run
        RECEIVE_THREAD = Thread(target=receive_message)
        SEND_THREAD = Thread(target=send_message)

        RECEIVE_THREAD.start()
        SEND_THREAD.start()

        RECEIVE_THREAD.join()
        SEND_THREAD.join()


def rules():
    print('''
   1.Type /online to view list of people online
   2.Type /bye to exit the chat
   3.Type @username <msg> to send message specific to the user
   4.By default messages are sent to public
   5.Type /notes to view this menu again ;)
   ''')


def send_message():
    global name
    global user_id
    global ACTIVE

    while ACTIVE:

        # takes msg from the user
        message = input()

        if(message == '/bye'):  # exit command
            message = message.encode('utf-8')
            print('exit')

            ct = AES.encrypt(message)

            h256 = hashlib.sha256(message).hexdigest()
            msg_and_hash = [ct, h256]
            CLIENT.send(pickle.dumps(msg_and_hash))
            ACTIVE = False
            CLIENT.close()

        elif message == '/online':
            print('Feature yet to be added')

        else:  # normal messages
            message = message.encode('utf-8')

            # encrypts the messsage with aes key
            ct = AES.encrypt(message)

            # compute hash for the message
            h256 = hashlib.sha256(message).hexdigest()

            msg_and_hash = [ct, h256]
            # send cipher text and hash to the server
            CLIENT.send(pickle.dumps(msg_and_hash))


def receive_message():
    global ACTIVE

    while ACTIVE:
        try:
            # receive cipher text and hash from the server
            msg_and_hash = CLIENT.recv(RECV_SIZE)

            msg_and_hash = pickle.loads(msg_and_hash)

            message = msg_and_hash[0]
            h256 = msg_and_hash[1]

            # decrypt the cipher text with session key
            message = AES.decrypt(message)

            # compute hash for the decrypted msg and verify with received
            if(hashlib.sha256(message).hexdigest() == h256):
                message = message.decode('utf-8')
                print(message)
            else:
                print('Data tampered so ignored')
        except OSError:  # i f failed
            ACTIVE = False  # terminate all threads


if __name__ == "__main__":
    print()
    set_up_client()
    start_io_loop()
    CLIENT.close()
    exit(0)
    # time = str(datetime.time(datetime.now()))[0:8]
    # msg = msg+' '+time

    # Saved_MSGS[name].append(msg)
    # print(Saved_MSGS[name])
