import socket
import os
import signal
import threading
import hashlib
from lazyme.string import color_print
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
import logging
from datetime import datetime
# ------------------------Padding Functions------------------------------
def RemovePadding(s):
    return s.replace('`','')
def Padding(s):
    return s + ((16 - len(s) % 16) * '`') 
# ------------------------Padding Functions------------------------------

#!-----------------------Inputstring Functions--------------------------
def numericonly(inputstring:str,range:bool=False,rangeMax:int=None,rangeMin:int=None,returnstr:bool=False,default:bool=False,default_value:str=None)-> str|int : 
  while True : 
    try : 
      options=int(input(inputstring));
    except ValueError : 
      print('Please enter a numeric value only...');
      continue
    if range==True or returnstr==True : 
      if default==True and options==-1 : return default_value
      elif returnstr==True and rangeMin<=options<=rangeMax : return str(options)
      elif options>=rangeMin and options<=rangeMax : return options;
      else : print(f'Please only enter a number from {rangeMin}, to {rangeMax}');
    elif range==False : 
        return options

#!-----------------------Inputstring Functions--------------------------


#*-------------------------------------------User Functions-------------------------------------------------
logging.basicConfig(filename="transfer_logs.log", level=logging.INFO, format="%(asctime)s: %(message)s")

def authentication(msg,name) :
    print (f"\n[!] {name} Said : Validating User Login");
    # color_print(f'\t\tUser : {msg[0]}, Password : {msg[1]}')
    verified_users={
        'jonas' : 'user',
        'thomas': 'thomas',
        'karun' : 'dharsan'
    }
    if verified_users.get(msg[0])==msg[1] : 
        color_print('[V] Verified User....', color='green')
        return 'Welcome to SPAM2::ServeR'
    else : 
        color_print('[I] Invalid User Connected....', color='red');   
        return FLAG_QUIT

def upload(msg,name) :
    msg[0]=msg[0].split('>')
    print (f"\n[!] {name} Said : Uploading File => ", msg[0][0])
    logging.info("Received data from client %s: %s", msg[0][1],msg[0][0])
    with open(f'{msg[0][0]}','w') as f : 
      f.write(msg[1])
    return 'Upload Success...::ServeR'

def encrypt_file(filename):
    with open(filename, 'r') as f : 
        docu=f.read();
    tobeencrypt=filename+'::'+docu+'::upload'
    return tobeencrypt

def download(msg,name) : 
    print (f"\n[!] {name} Said : Requesting {msg[0]} for download")
    if os.path.isfile(f'{msg[0]}') and msg[0] not in ['Server private.pem','Server public.pem','transfer_logs.log'] : 
        logging.info("Sending data to client %s: %s", msg[0],msg[1])
        return encrypt_file(msg[0])
    else : return ('Not Existent')
    
def comms(msg,name) : 
    return FLAG_READY+'::Server::'+'comms'
client_functions_replies={'auth' : authentication, 'upload' : upload, 'download' : download,'comms' : comms}
#*-------------------------------------------User Functions-------------------------------------------------






#!-------------------------------Connection Set-up----------------------------------------------            
def ConnectionSetup() : 
    while True : 
        if check is True : 
            client, address = server.accept()
            color_print("\n[!] One client is trying to connect...", color="green", bold=True)
            clientPH = client.recv(2048).decode()
            split=clientPH.split(':');
            Client_Public_key = split[0];
            Client_public_hash=split[1];
            color_print("\n[!] Anonymous client's public key\n",color="blue")
            Client_Public_key = Client_Public_key.replace("\r\n", '')
            Client_public_hash = Client_public_hash.replace("\r\n", '')
            tmpHashObject = hashlib.md5(Client_Public_key.encode('utf-8')).hexdigest()
            if tmpHashObject==Client_public_hash : 
                color_print("\n[!] Anonymous client's public key and public key hash matched\n", color="blue")
                clientPublic = RSA.importKey(Client_Public_key)
                cipher = PKCS1_OAEP.new(clientPublic)
                fSend = (( eightByte+ ":".encode() + session.encode() + ":".encode() + my_hash_public.encode()));
                # print(len(fSend))        
                fSend = cipher.encrypt(fSend)
                client.send(server_public_key + "::".encode()+ fSend)
                clientPH = client.recv(2048)
                if clientPH!="" : 
                    clientPH=PKCS1_OAEP.new(keypair).decrypt((clientPH))
                    # print(clientPH)
                    color_print("\n[!] Matching session key\n", color="blue")
                    if clientPH==eightByte : 
                        color_print("\n[!] Creating AES key\n", color="blue")
                        key_128 = eightByte + eightByte[::-1]
                        AESkey = AES.new(key_128, AES.MODE_EAX,nonce=key_128)
                        clientMsg = AESkey.encrypt(Padding(FLAG_READY).encode())
                        client.send(clientMsg)
                        color_print("\n[!] Waiting for client's name\n", color="blue")
                        clientMsg = client.recv(2048)
                        AESkey = AES.new(key_128, AES.MODE_EAX,nonce=key_128)
                        clientMsg=AESkey.decrypt(clientMsg).decode()
                        CONNECTION_LIST.append((clientMsg, client))
                        color_print("\n"+clientMsg+" IS CONNECTED", color="green", underline=True)
                        threading_message = threading.Thread(target=ReceiveMessage,args=[client,key_128,clientMsg]).start()
            else : 
                color_print("\nPublic key and public hash doesn't match", color="red", underline=True)
                client.close()

#!-------------------------------Connection Set-up--------------------------------------------------------

  
#*-------------------------------Messaging-----------------------------------------------------------------
def ReceiveMessage(cli,AESk,name):
    try : 
        while True :
            emsg = cli.recv(1024)
            AESkeyDn=AES.new(AESk, AES.MODE_EAX,nonce=AESk)
            emsg=AESkeyDn.decrypt(emsg)
            # print(emsg)
            emsg=emsg.decode()
            msg=RemovePadding(emsg)
            # print(msg) 
            try : 
                msg_split=msg.split('::')
                if msg_split[1]=='msgC' or 'msgC' in msg_split: 
                    if msg_split[0]=='stop' : 
                        send_message(cli,AESk,encrymsg='Comm Channel Closed...')
                    else :
                        color_print(f'\n[C] {name} Said : {msg_split[0]}',color='magenta')
                        send_message(cli,AESk,noInp=True)
                else : 
                    replies=client_functions_replies.get(msg_split[2])([msg_split[0],msg_split[1]],name)
                    send_message(cli,AESk,encrymsg=replies)
            except IndexError: 
                send_message(cli,AESk,encrymsg='File Uploaded')
    except ConnectionResetError : 
        color_print(f'{name} has been disconnected...',color='Red' )    
                          
         
def send_message(socketClient,AESk, noInp=False, encrymsg=None):
    if noInp==True :
        msg = input("\n[>] ENTER YOUR MESSAGE : ")  
        msg+='::SM'
        
    else : msg= encrymsg
    AeskeyEn=AES.new(AESk,AES.MODE_EAX,nonce=AESk)
    en = AeskeyEn.encrypt(Padding(msg).encode())
    socketClient.send((en))
    if msg == FLAG_QUIT:
        os.kill(os.getpid(), signal.SIGILL)
    else:
        # color_print("\n[!] Your encrypted message \n", color="gray")
        None
            
#*-------------------------------Messaging--------------------------------------------------------------------------



            
            
    
            
            
            
            
#!------------------------------------Main Program-------------------------------------------------------------------       
if __name__ =='__main__' : 
    host='';
    port=0;
    server='';
    AESkey='';
    CONNECTION_LIST = []
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"
    #?--------------Generating RSA Key Pair---------------------------
    keypair = RSA.generate(2048);
    server_private_key=keypair.exportKey();
    server_public_key=keypair.publickey().exportKey();
    #?--------------Generating RSA Key Pair---------------------------
    
    #?-------Digital Public Signature--------------------------------
    tmpPub = hashlib.md5(server_public_key)
    my_hash_public = tmpPub.hexdigest()
    #?-------Digital Public Signature--------------------------------

    
    #!------------Session Key---------------------------------------
    eightByte = get_random_bytes(8)
    session = (hashlib.md5(eightByte)).hexdigest()
    #!------------Session Key--------------------------------------
    
    #*-------------------Establing Connection------------------------------------------
    try : 
        with open("Server private.pem", "w") as f:
            f.write(hashlib.sha256(keypair.exportKey()).hexdigest())
        with open("Server public.pem", "w") as f:
            f.write(hashlib.sha3_256(keypair.publickey().exportKey()).hexdigest())
    except BaseException : color_print("Key storing in failed", color="red", underline=True)
    check=False;
    color_print("[1] Auto connect by with broadcast IP & PORT\n[2] Manually enter IP & PORT\n", color="blue", bold=True)
    ask = input("[>] ")
    if ask=='1' : 
        host=socket.gethostname()
        port=8080
    elif ask=='2' : 
        host = input('Host : ');
        port = numericonly(inputstring='Enter A port : ',range=True,rangeMax=65535,rangeMin=1)

    else : 
        color_print("[!] Invalid selection", color="red", underline=True)
        os.kill(os.getpid(), signal.SIGILL)
    color_print("\n[!] Eight byte session key in hash\n", color="blue")
    print (session)
    color_print("\n[!] Server IP "+host+" & PORT "+str(port), color="green", underline=True);
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, int(port)))
    server.listen(1)
    color_print("\n[!] Server Connection Successful", color="green", bold=True)
    check = True
    threading_accept = threading.Thread(target=ConnectionSetup).start()

    #*-------------------Establing Connection------------------------------------------
    
    #!------------------------------------Main Program-------------------------------------------------------------------       
