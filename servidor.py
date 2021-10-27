#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import pathlib
from io import open
import elgamal
import random
import json

# modulos para cifrar con RSA
from Crypto.PublicKey import RSA
import binascii
from Crypto.Cipher import PKCS1_OAEP

def msgEntrada():
    # lectura de archivo mensajedeentrada
    ruta = str(pathlib.Path().absolute()) + "/mensajedeentrada.txt"
    archivo = open(ruta, "r")
    mensaje = archivo.readlines()
    archivo.close()
    mensaje = mensaje[0]
    return mensaje

def variablesElgamal():
    archivoVariables = open ('variables.txt','w')
    archivoVariables.write(str(p)+"\n")
    archivoVariables.write(str(q)+"\n")
    archivoVariables.write(str(key))
    
#Creando conexión
ser = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ser.bind(("", 8080))
ser.listen(1)
cli, addr = ser.accept()

##### Algoritmo RSA
print("####################### Algoritmo RSA #########################\n")

#Recibimos el mensaje, con el metodo recv recibimos datos. Por parametro la cantidad de bytes para recibir
public_key = cli.recv(1024)
print(f"Llave pública recibida del cliente: {public_key}\n")

# se convierte a obj RSA para poder operarla
public_key = RSA.importKey(binascii.unhexlify(public_key))

# Cifrando el mensaje
message = msgEntrada()
print(f"Mensaje original: {message}")
message = message.encode()
cipher = PKCS1_OAEP.new(public_key) # objeto para cifrar, se cifra con llave publica
encrypted_message = cipher.encrypt(message)
print(f"Mensaje cifrado: {encrypted_message}\n")

# se devuelve mensaje cifrado a cliente
cli.send(encrypted_message)

##### Algoritmo Elgamal
print("####################### Algoritmo Elgamal #########################\n")

# Variables necesarias
q = random.randint(pow(10,20),pow(10,50))
key = elgamal.gen_key(q)
g = random.randint(2,q)
h = elgamal.power(g,key,q)

# Cifrando mensaje
message = msgEntrada()
print(f"Mensaje original: {message}\n")
encrypted_message2, p = elgamal.encryption(message,q,h,g)

enc_message = ""
for elem in encrypted_message2:
    enc_message += str(elem)

encrypted_message2 = json.dumps(encrypted_message2)
print(f"Mensaje cifrado: {enc_message}")

# Enviando mensaje cifrado
cli.send(encrypted_message2.encode())
variablesElgamal()

#Cerramos la instancia del socket cliente y servidor
cli.close()