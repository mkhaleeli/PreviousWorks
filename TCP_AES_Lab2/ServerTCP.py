from socket import *
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import secrets 
import ast #For String to List Conversions

serverPort = 12000 #Port for Communication

serverSocket = socket(AF_INET,SOCK_STREAM) #Initializes Socket be calling a constructor of the socket class to make a communication endpoint
'''
AF_INET is for using IPv4 addresses for communication
SOCK_STREAM is for defining a constant as a Socket Type uses Transmission Control Protocol (TCP) for two-way communication
'''

serverSocket.bind(('',serverPort)) #Binds server socket to the server port, making it accessible to all interfaces due to the empty string, listening for all message types

# listen(1) puts the socket into server mode and

# allows up to one client connection request

# to be queued.

serverSocket.listen(1) #Permits the socket to accept incoming connections
print("The server is ready to receive \n")

'''Server Activity:
2. The server will read the ciphertext from the socket, get the secret key (k) from the user (by retrieving the key from a user-specified file), and then decrypt the ciphertext.
   The decrypted message (dm) should be printed in the screen output.
   - Retreive encrypted message and retreive SHA-256 key
   - Decrypt message with SHA-256 key 
   - Display message
'''

#AES-256 Decryption using GCM with new symmetric key
def decrypt(key, ciphertext, iv, aa, tag):
    print(f"Server: Decrypting .... ciphertext: {ciphertext.hex()}, iv: {iv.hex()} \n")    
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend())
    
    decryptor = cipher.decryptor()
    
    #Decrypts Associated Data
    decryptor.authenticate_additional_data(aa)
    
    #Decrypts Ciphertext and return Plaintext + key
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        message = plaintext.decode('utf-8')
        return message, key
    
    #Checks Tag Authenication
    except InvalidTag:
        print("Server: Decryption Failed, Invalid Authenication Tag", tag , '\n')


'''Server Activity:
3. The server then generates a new AES-256 key (nk), encrypts dm using nk, and ecrypts nk using the existing symmetric key.
   The server then sends the encrypted nk and the encrypted dm to the client
   - Generate a new AES-256 key (nk)
   - Encrypt dm with nk
   - Encrypt nk with k
   - Send both encrypted dm and encrypted nk to client
'''

header2 = b"Header Info: Source = 'Server', Destination = 'Client', mode = 'GCM', ..."

def encrypt(key, message, aa):
    
    data = message.encode('utf-8')
    
    #Allows encryption of plaintext into different ciphertext, even if the same message
    iv = secrets.token_bytes(16)
    
    print(f"Server: Encrypting .... data: {message}, iv: {iv.hex()} \n")
    
    #AES-256 Encryption for a new key (nk)
    newkey = secrets.token_bytes(32)
    
    #Key Encrypter
    key_cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend())
        
    #Message Encryptor
    cipher = Cipher(
        algorithms.AES(newkey),
        modes.GCM(iv),
        backend=default_backend())
        
    #Encrypts using Cipher Template
    encryptor = cipher.encryptor()
    
    #Encrypts newkey with original key
    key_encryptor = key_cipher.encryptor()
    
    #Authenticates Associated Data
    encryptor.authenticate_additional_data(aa)
    
    #Creates whole Ciphertext (With additional finalization of encryption to avoid reuse & flush remaining buffered data)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    #Authentication Tag (AEAD)
    tag = encryptor.tag

    #Encrypt nk with k
    e_nk = key_encryptor.update(newkey)
    
    return e_nk, ciphertext, iv, aa, tag 

'''While Connection is Established'''
while True: 

     connectionSocket, addr = serverSocket.accept() #Waits for client to connect, then establishes a connection once a request arrives as a new object

     client_file = connectionSocket.recv(1024).decode() #Receives objects from the connection with the set buffer size of 1024 total bytes to be able to be receive at once,
     #Returned in string form from decode() by converting from bytes
     
     #Read textfile with encrypted message
     with open('data.txt', 'r') as file:
        client_file = file.read()
        
     #Convert string back into a list of values
     def string_to_List(myString):
        result = ast.literal_eval(myString)
        return result
        
     list_of_values = string_to_List(client_file)
     
     k, e_m, iv, header, tag = list_of_values #List unpacking
     
     #Decrypt message with original key (k)
     dm, k = decrypt(k, e_m, iv, header, tag) # Fix Input Variables from reading from a file
     
     print("Server: Decrypted Message from Client: ", dm, '\n')
     
     #Encrypt dm with nk
     e_nk, e_m2, iv, header, tag = encrypt(k, dm, header2)
    
     #list for testing communication
     list_of_values = [e_nk, e_m2, iv, header, tag]
     
     #Convert from list to string
     def list_to_String(mylist):
        result = ",".join(map(str, mylist))
        return result
    
     server_file = list_to_String(list_of_values)
     
     #Send newly encrypted message back to Client
     with open('data.txt', 'w') as file:
         file.write(server_file)
     
     connectionSocket.send(server_file.encode()) #Sends message encoded into bytes back to client

     connectionSocket.close() #Ends connection