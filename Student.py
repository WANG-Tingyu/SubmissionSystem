import socket
import os
import os.path as osp
import sys
import struct
import threading
import re
import argparse
from utils import generate_keypairs, RSA_decrypt_session_key, AES_encrypt_and_digest, AES_decrypt_and_verify



def socket_client(serverIP, sendPort):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((serverIP, sendPort))
    except socket.error as msg:
        print(msg)
        sys.exit(1)

    print(conn.recv(1024).decode('utf-8'))
    return conn



def sendMsg(conn, msg):
    conn.send(msg.encode('utf-8'))
    


def receiveMsg(conn):
    msg = conn.recv(1024).decode('utf-8')
    if msg == 'Certificate is invalid':
        print('Certificate is invalid')
        sys.exit(-1)
    else:
        print(msg)

def sendFile(conn, filepath):
    while 1:
        if os.path.isfile(filepath):
            fileinfo_size = struct.calcsize('256sl')
            fhead = struct.pack('256sl', os.path.basename(filepath).encode('utf-8'),
                                os.stat(filepath).st_size)
            conn.send(fhead)
            # print('client filepath: {0}'.format(filepath))

            fp = open(filepath, 'rb')
            while 1:
                data = fp.read(1024)
                if not data:
                    # print('{0} file send over...'.format(filepath))
                    break
                conn.send(data)
        # conn.close()
        break

def receiveFile(conn, root):
    while 1:
        fileinfo_size = struct.calcsize('256sl')
        buf = conn.recv(fileinfo_size)
        if buf:
            filename, filesize = struct.unpack('256sl', buf)
            # fn = filename
            fn = filename.decode('utf-8').strip('\00')
            new_filename = os.path.join(f'./{root}', fn)
            # print('file new name is {0}, filesize if {1}'.format(new_filename,
            #                                                      filesize))

            recvd_size = 0  
            fp = open(new_filename, 'wb')
            # print('start receiving...')

            while not recvd_size == filesize:
                if filesize - recvd_size > 1024:
                    data = conn.recv(1024)
                    recvd_size += len(data)
                else:
                    data = conn.recv(filesize - recvd_size)
                    recvd_size = filesize
                fp.write(data)
            fp.close()
            # print('end receive...')
        # conn.close()
        break
    return new_filename

def communication(conn, root, session_key):
    while 1:
        msg = input("me: ")
        ### encrypt the message
        encrypt_filepath = osp.join(root, f'{root}.tmp')
        AES_encrypt_and_digest(bytes(msg, "utf-8"), session_key, encrypt_filepath)
        ###
        sendFile(conn, encrypt_filepath)
 

       


def run(serverIP, serverPort, blackboardIP, blackboardPort, root):
    conn = socket_client(serverIP, serverPort)
    pubkey_path = osp.join(root, f'{root}.public.pem') 
    sendFile(conn, pubkey_path)
    receiveFile(conn, root)
    print('Received Certificate from CUHK')
    conn.close()
    conn = socket_client(blackboardIP, blackboardPort)
    cert_path = osp.join(root, f'{root}.cert.pem') ## be replaced by cert of current student
    sendFile(conn, cert_path)
    print('Sent Cert to BlackBoard')
    receiveMsg(conn)
    print('Verified Cert')
    sessionKeyPath = receiveFile(conn, root)
    print('Received encrypted Session key from BlackBoard')
    session_key = RSA_decrypt_session_key(root)
    print('Finish decrypted Session key')
    print('Start communicate with BlackBoard !')
    communication(conn, root, session_key)
    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Student Learning Platform')
    parser.add_argument('--sid', type=str, default='1820', 
                        help='Your student id')
    args = parser.parse_args()

    os.makedirs(args.sid, exist_ok=True)
    generate_keypairs(args.sid)
    print('Finish generate keypairs')
    root = args.sid
    clientIP = '127.0.0.1'
    serverIP = '127.0.0.1'
    blackboardIP = '127.0.0.1'
    serverPort = 12345
    blackboardPort = 12346
    run(serverIP, serverPort, blackboardIP, blackboardPort, root)
