#!/usr/bin/env python

#Variables
host = 'localhost'
port = 8080

import socket
import pathlib
from io import open
import json
import elgamal

# modulos para cifrar con RSA
import Crypto
from Crypto.PublicKey import RSA
import binascii
from Crypto.Cipher import PKCS1_OAEP

def variablesElgamal():
    ruta = str(pathlib.Path().absolute()) + "/variables.txt"
    archivo2 = open(ruta, "r")
    variables = archivo2.readlines()
    archivo2.close()
    lista = []
    
    for var in variables:
        lista.append(int(var.strip()))
        
    return lista

#Conexión con servidor
obj = socket.socket()
obj.connect((host, port))
print("Conectado al servidor")

####### Algoritmo RSA
print("####################### Algoritmo RSA #########################\n")
print("Generando las llaves..")
# Generar las llaves
random_generator = Crypto.Random.new().read

private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()
private_key = private_key.exportKey(format='DER')
public_key = public_key.exportKey(format='DER')

## se convierten de binario a utf8
private_key = binascii.hexlify(private_key).decode('utf8')
public_key = binascii.hexlify(public_key).decode('utf8')

## proceso inverso para operar llave privada
private_key = RSA.importKey(binascii.unhexlify(private_key))

# Se envia llave publica al servidor
public_key = public_key.encode()
print(f"Se envía llave pública al servidor: {public_key}")
obj.send(public_key)

# se recibe mensaje del servidor
encrypted_message = obj.recv(1024)
print(f"\nSe recibe mensaje cifrado del servidor: {encrypted_message}")

# Descifrando mensaje y guardando en archivo
cipher = PKCS1_OAEP.new(private_key)
message = cipher.decrypt(encrypted_message)
message = message.decode()
print(f"\nMensaje descifrado: {message}")

ruta = str(pathlib.Path().absolute()) + "/mensajerecibido.txt"
archivo = open(ruta, "w")
archivo.write(message)
archivo.close()

##### Algoritmo Elgamal
print("\n####################### Algoritmo Elgamal #########################")

# Recibiendo mensaje encriptado
print("\nRecibiendo mensaje encriptado del servidor..")
encrypted_message2 = obj.recv(2048)
encrypted_message2 = encrypted_message2.decode()
encrypted_message2 = json.loads(encrypted_message2)

# Definiendo variables
variables = variablesElgamal()
p = variables[0]
q = variables[1]
key = variables[2]

# Descifrando mensaje
decrypted_message2 = elgamal.decryption(encrypted_message2,p,key,q)
decrypted_message2=''.join(decrypted_message2)
print(f"\nMensaje descifrado: {decrypted_message2}")

obj.close()
print("\nConexión cerrada")