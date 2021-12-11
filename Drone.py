from socket import *
import socket
from sys import addaudithook
import LEA
import os
import signal
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import threading
import secrets
import time
import hashlib
from time import sleep
import serial

# if you using Raspberry Pi & Arduino, Activate 18, 92 lines
# ser = serial.Serial('/dev/ttyUSB0', 115200)

def connect_client(server, lea_key, aad):
    global Time_Sync_Timer
    Time_Sync_Timer = False

    tevent = threading.Event()

    # receive nonce & Public Key
    pubkey_and_nonce, client_addr = server.recvfrom(2048)
    split = pubkey_and_nonce.split(b"\r\n", maxsplit=1)
    nonce = split[0]
    client_public_key = split[1]

    nonce = nonce.replace(b"\r\n", b'')

    client_public_key = client_public_key.replace(b"\r\n", b'')
    client_public_key = client_public_key.decode('ascii')

    key = RSA.importKey(client_public_key)
    encryptor = PKCS1_OAEP.new(key)
    encrypt_aad = encryptor.encrypt(aad)
    encrypt_lea_key = encryptor.encrypt(lea_key)

    server.sendto(encrypt_aad + b"\r\n" + encrypt_lea_key, client_addr)

    print("Client is Connected")

    # Time Syncronization
    server.sendto(b'Server_time_Sync', client_addr)

    Time_Sync_Handshake = server.recv(256)
    Time_Sync_timer = threading.Timer(5, bool_Time_Sync_Handshake)
    Time_Sync_timer.start()

    if Time_Sync_Handshake == b'Client_time_Sync':
        print('Time Sync Success')
        Time_Sync_Timer = True
        
        threading_otp = threading.Thread(target = OTP, args = [aad])
        threading_otp.start()

        threading_received_msg = threading.Thread(target = received_message, args = [server, lea_key, nonce])
        threading_received_msg.start()

    else:
        print('Time Sync Fail.. Try Again')
        os.kill(os.getpid(), signal.SIGKILL)


def bool_Time_Sync_Handshake():
    if Time_Sync_Timer == False:
        print("Time_Sync_Fail. Try Again")
        os.kill(os.getpid(), signal.SIGKILL)


def control_signal(control_id):
    signal = None

    control_id = int(control_id)

    if control_id == 54:
        print('takeoff')
        signal = 'takeoff'
    
    elif control_id == 55:
        print('land')
        signal = 'land'
    
    else:
        print('Wrong Pakcet')
    
    # ser.write(signal)


def received_message(server, lea_key, nonce):
    while True:
        encrypted_msg = server.recv(1024)

        receive_leaGCM = LEA.GCM(False, lea_key, nonce, aad_OTP, 16)
        receive_leaGCM.update(encrypted_msg)
        command = receive_leaGCM.final()

        if command == FLAG_QUIT:
            print("Shutdown")
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            print("Server's Encrypted Message: ", command[0:1].hex())

        if command[0:1].hex() == 'cc':
            control_id = command[5:6].hex()
            control_signal(control_id)
        
        else:
            print('Wrong Packet')


def send_message(client, lea_key, nonce):
    while True:
        msg = input("Command: ")
        
        leaGCM = LEA.GCM(True, lea_key, nonce, aad_OTP, 16)
        ct = leaGCM.update(msg)
        ct += leaGCM.final()
        client.sendto(ct)

        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            print(ct)


def OTP(aad):
    global aad_OTP 
    aad_OTP = aad

    hasher = hashlib.md5()

    while True:
        sleep(30)

        hasher.update(aad_OTP)
        aad_OTP = hasher.hexdigest()

        aad_OTP = bytes(aad_OTP, encoding = 'utf-8')
        aad_OTP = bytearray(aad_OTP)


if __name__ == "__main__":

    host = "127.0.0.1"
    port = 8888
    server = ""

    lea_key_16 = secrets.token_hex(16)
    server_random_8bytes = secrets.token_hex(8)
    CONNECTION_LIST = []

    FLAG_READY = "Ready"
    FLAG_QUIT = "exit"

    lea_key = bytes(lea_key_16, encoding = 'utf-8')
    lea_key = bytearray(lea_key)

    nonce = ""

    aad_16 = server_random_8bytes + server_random_8bytes[::-1]
    global aad
    aad = bytes(aad_16, encoding = 'utf-8')
    aad = bytearray(aad)

    connection = False

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    
    print("Waiting...")

    threading_accept = threading.Thread(target = connect_client, args = [server, lea_key, aad])
    threading_accept.start()