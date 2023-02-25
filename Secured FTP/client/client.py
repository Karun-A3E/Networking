import socket
import os
import threading
import hashlib
import signal
from lazyme.string import color_print
from Crypto.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
import tabulate
#-------------------------Identity-----------------------------------------------
identity=socket.gethostname()+socket.gethostbyname(socket.gethostname())
#------------------------Padding Functions---------------------------------------
def RemovePadding(s):
    return s.replace('`','')

def Padding(s):
    return s + ((16 - len(s) % 16) * '`')
#------------------------Padding Functions------------------------------



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

def encrypt_file(filename):
    with open(filename, 'r') as f : 
        docu=f.read();
    tobeencrypt=f'{filename}>{identity}'+'::'+docu+'::upload'
    return tobeencrypt

def send_encrypted() : 
    filename = input('Enter the Filename : ');
    if os.path.isfile(f'{filename}') and filename not in ['Client private.pem','Client public.pem'] : 
        return encrypt_file( filename)
    else : return ('Not Existent')
    
def quit_from_server() : 
    return FLAG_QUIT

def Download() : 
    filename = input('Enter the namem of the file to be downloaded : ');
    return filename +'::'+identity+ '::download'

def Messages() : 
    return FLAG_READY+'::CLIENT::'+'comms'

def start() : 
        color_print(f'===========================================================================\nWelcome To SPAM2 System, user\n===========================================================================' , color='blue');
        function_stri={1 : {'alias':'Uploading','Function' :send_encrypted} ,2 : {'alias':'Messaging','Function' :Messages} ,3 : {'alias':'Downloading','Function' :Download} ,4 : {'alias':'Quit','Function' :quit_from_server} }
        print(tabulate.tabulate(headers=['number','function'],tabular_data=[[i,function_stri[(i)]['alias']] for i in range(1,len(function_stri)+1)],tablefmt='fancy_grid'))
        user_option=numericonly(inputstring='What would you like to do  : ',range=True,rangeMax=len(function_stri),rangeMin=1)
        msg=function_stri.get(user_option)['Function']()
        SendMessage(encryption_required=msg,encrypt_only=True)
        
        
def upload(msg) :
    # print(msg)
    with open(f'{msg[0]}','w') as f : 
      f.write(msg[1])
    return 'Upload Success...'



def login() : 
  print("""
        
 ██▓     ▒█████    ▄████  ██▓ ███▄    █ 
▓██▒    ▒██▒  ██▒ ██▒ ▀█▒▓██▒ ██ ▀█   █ 
▒██░    ▒██░  ██▒▒██░▄▄▄░▒██▒▓██  ▀█ ██▒
▒██░    ▒██   ██░░▓█  ██▓░██░▓██▒  ▐▌██▒
░██████▒░ ████▓▒░░▒▓███▀▒░██░▒██░   ▓██░
░ ▒░▓  ░░ ▒░▒░▒░  ░▒   ▒ ░▓  ░ ▒░   ▒ ▒ 
░ ░ ▒  ░  ░ ▒ ▒░   ░   ░  ▒ ░░ ░░   ░ ▒░
  ░ ░   ░ ░ ░ ▒  ░ ░   ░  ▒ ░   ░   ░ ░ 
    ░  ░    ░ ░        ░  ░           ░ 
        """)
  color_print('*********************************',color='red');
  username = input('Enter Username : ');
  passwd = input('Enter the Password : ');
  user_pass_string=f'{username}::{passwd}::auth';
#   print(user_pass_string)
  SendMessage(encryption_required=user_pass_string)
#*-------------------------------------------User Functions---------------------------------------------------------




#!-------------------------------Messaging--------------------------------------------------------------------------

def sendcomm() : 
    data_sent = (input("\n[>] ENTER YOUR MESSAGE : "));
    data_sent=data_sent+'::msgC'
    AeskeyEn=AES.new(key_128,AES.MODE_EAX,nonce=key_128)
    en = AeskeyEn.encrypt(Padding(data_sent).encode())
    server.send((en))
    

def SendMessage(encrypt_only=True,encryption_required=None,encrypt=True):
    if encrypt_only==False :
        msg = input("[>] YOUR MESSAGE : ");
    else :msg=encryption_required  
    if encrypt==True : 
        AESkeyEn=AES.new(key_128,AES.MODE_EAX, nonce=key_128)
        en = AESkeyEn.encrypt(Padding(msg).encode())
    else : en=msg
    server.send((en))
    if msg == FLAG_QUIT:
        os.kill(os.getpid(), signal.SIGILL)
    else:
        None
    ReceiveMessage()


def ReceiveMessage():
    while True:
        emsg = server.recv(1024)
        # print(emsg)
        AESkeyDn=AES.new(key_128, AES.MODE_EAX,nonce=key_128)
        emsg=AESkeyDn.decrypt(emsg);
        # print(emsg)
        emsg=emsg.decode()
        msg=RemovePadding(emsg)
        if msg == FLAG_QUIT:
            color_print("\n[!] Server was shutdown by admin", color="red", underline=True)
            os.kill(os.getpid(), signal.SIGILL)
        else:
            # color_print("\n[!] Server's encrypted message \n", color="gray")
            # print(msg)
            if 'ServeR' in msg.split('::') : print('\n[S] Server Said : ',msg.split('::')[0]);
            try : 
                msg_split=msg.split('::')
                if  msg.split('::')[1] in['msgS','comms','SM']  or msg=='Ready::Server::comms' :  
                        color_print(f'\n[!] Server Said : {msg_split[0]} ',color='blue')
                        sendcomm()

                        
                else : 
                    if msg_split[2]=='upload' :
                        color_print('Server Said : Download Success',color='Green')
                        upload([msg_split[0],msg_split[1]])
                        start()
            except IndexError: start()
#!-------------------------------Messaging--------------------------------------------------------------------------


    
#!------------------------------------Main Program-------------------------------------------------------------------       

if __name__ == '__main__' : 
    server = ""
    AESKey = ""
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"
    #?-------------------RSA Key--------------------------
    RSAkeys= RSA.generate(2048)
    client_private_key=RSAkeys.exportKey();
    client_public_key=RSAkeys.publickey().exportKey();
    #?-------------------RSA Key--------------------------

   
    #?-------Digital Public Signature---------------
    tmpPub = hashlib.md5(client_public_key)
    my_hash_public = tmpPub.hexdigest()
    #?-------Digital Public Signature---------------
    
    #-----------Host and Port Inputs----------------
    host = input("Host : ")
    port = numericonly(inputstring=("Port : "),range=True,rangeMax=65535,rangeMin=1)
    
    try:
      with open('Client private.pem', 'w') as f : 
           f.write(hashlib.sha256(client_public_key).hexdigest())    
      with open('Client public.pem', 'w') as f : 
           f.write(hashlib.sha256(client_private_key).hexdigest())   
    except BaseException: color_print("Key storing in failed", color="red", underline=True)
    check = False
    try:
      server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      server.connect((host, port))
      check = True
    except BaseException:
      color_print("\n[!] Check Server Address or Port", color="red", underline=True)
    if check is True:
        color_print("\n[!] Connection Successful", color="green", bold=True)
        server.send((client_public_key.decode() + ':'+ my_hash_public).encode())
        fGet = server.recv(4072)
        split=fGet.split('::'.encode())
        ServerPublicKey=split[0].replace(b'\n\r',b'');
        encryptedData=split[1];

        DecryptedData=PKCS1_OAEP.new(RSAkeys).decrypt(((encryptedData)));

        splitDecrypted=DecryptedData.split(':'.encode());
        eigthByte=splitDecrypted[0];
        hashofeigth=splitDecrypted[1];
        ServerHashPublic=splitDecrypted[2];
        # print(splitDecrypted);
        sess = hashlib.md5(eigthByte)
        session = sess.hexdigest()

        hashObj = hashlib.md5(ServerPublicKey)
        server_public_hash = hashObj.hexdigest()
        # print(session)
        color_print("\n[!] Matching server's public key & eight byte key\n", color="blue")
        if server_public_hash.encode() == ServerHashPublic and session.encode() == hashofeigth:
            # encrypt back the eight byte key with the server public key and send it
            color_print("\n[!] Sending encrypted session key\n", color="blue")
            ServerPublicKey=RSA.importKey(ServerPublicKey)
            serverpublicEn=PKCS1_OAEP.new(ServerPublicKey);
            server.send(serverpublicEn.encrypt(eigthByte))
            color_print("\n[!] Creating AES key\n", color="blue")
            key_128 = eigthByte + eigthByte[::-1]
            AESKey = AES.new(key_128,  AES.MODE_EAX,nonce=key_128)
            serverMsg = server.recv(2048)
            serverMsg = RemovePadding(AESKey.decrypt(serverMsg).decode())
            if serverMsg == FLAG_READY:
                color_print("\n[!] Server is ready to communicate\n", color="blue")
                serverMsg = input("\n[>] ENTER YOUR NAME : ")
                if serverMsg == "" or None:
                    color_print('[!] Server was shutdown! Name cannot be left blank!',color='red')
                    exit()
                aesen=AES.new(key_128,AES.MODE_EAX,key_128)
                server.send(aesen.encrypt(serverMsg.encode()))
                # threading_rec = threading.Thread(target=ReceiveMessage).start()
                threading_login=threading.Thread(target=login).start()
        else : color_print('\n[!]Server Hash NOT matching Server Key',color='red')
        
#!------------------------------------Main Program-------------------------------------------------------------------       
