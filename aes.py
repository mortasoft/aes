#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  aes-lab3-cenfotec.py
#  
#  Copyright 2016 Johnny Pan <codeskill@gmail.com>
#  Copyright 2016 Mario Zamora <mortasoft@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import unicodedata
import codecs
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter

class color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKYELLOW = '\033[33m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# BlockSize
BS = 16

pad = lambda s: s + (BS - len(s) % BS) * bytes([BS - len(s) % BS])
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, mode, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        plaintext = pad(plaintext)
        iv = Random.new().read(AES.block_size)
        if mode == 6:
            ctr = Counter.new(128)
            ciphertext = AES.new(self.key, mode, counter=ctr)
        else:
            ciphertext = AES.new(self.key, mode, iv)
        return base64.urlsafe_b64encode(iv + ciphertext.encrypt(plaintext))

    def decrypt(self, mode, ciphertext):
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        ciphertext = base64.urlsafe_b64decode(ciphertext)
        iv = ciphertext[:BS]
        if mode == 6:
            ctr = Counter.new(128)
            cipher = AES.new(self.key, mode, counter=ctr)
        else:
            cipher = AES.new(self.key, mode, iv)
        return unpad(cipher.decrypt(ciphertext[BS:]))

def remove_accents(input_str):
    input_str = input_str.replace("\u2018", "\"").replace("\u2019", "\"").replace("\u201c","\"").replace("\u201d", "\"")
    nkfd_form = unicodedata.normalize('NFKD', str(input_str))
    return "".join([c for c in nkfd_form if not unicodedata.combining(c)])

def main():
    # Limpia la pantalla
    print('\033c', end='')
    print(color.OKBLUE)
    print('+-----------------------------------------------+')
    print('| MSEG-02 - PRINCIPIOS DE CRIPTOGRAFIA          |')
    print('| LABORATORIO DE CIFRADO AES                    |')
    print('| JOHNNY.PAN | ESTEBAN.CASTILLO | MARIO.ZAMORA  |')
    print('+-----------------------------------------------+')
    print(color.ENDC)

	# Se ingresa el mensaje en texto plano o cifrado
	print color.OKYELLOW + 'DIGITE EL MENSAJE (TEXTO PLANO O CIFRADO)' + color.ENDC
	mensaje = unicode(raw_input(),"utf-8")
	mensaje = remove_accents(mensaje)	
	print
	
	# Se ingresa la llave
	print color.OKYELLOW + 'DIGITE LA LLAVE (KEY)' + color.ENDC
	llave = raw_input()
	key = hashlib.sha256(llave).hexdigest()[:BS]

    # Se el tamaño la llave 16 = 128 bits, 24 = 192 bits, 32 = 256 bits
    #print color.OKYELLOW + 'DIGITE EL TAMAÑO DE LA LLAVE [16 = 128 bits, 24 = 192 bits, 32 = 256 bits]' + color.ENDC
    #key_size = raw_input()
    #print

    # Se ingresa la llave
    print(color.OKYELLOW + 'DIGITE LA LLAVE (KEY)' + color.ENDC)
    llave = input()
    key = hashlib.sha256(llave.encode()).hexdigest()[:BS].encode('utf-8')
    #key = hashlib.sha256(llave).hexdigest()[:int(key_size)]

    ## Se crea el objeto AES
    aes = AESCipher(key)

    # Pregunta si se desea encriptar o desencriptar el mensaje
    print(color.OKYELLOW)
    opcion = input('SELECCIONE [E] ENCRIPTAR | [D] DESENCRIPTAR: ')
    print(color.ENDC)
    if opcion == 'e' or opcion == 'E':
        print(color.OKYELLOW + 'CIFRADO POR BLOQUES')
        print('[1] BCE - Modo de libro de códigos electrónico')
        print('[2] CBC - Modo de cadena de bloques de cifrado')
        print('[3] CFB - Modo de cifrado con retroalimentación')
        print('[4] OFB - Modo de retroalimentación de salida')
        print('[5] CTR - Modo de contador')
        print('[6]  *  - Todos los modos de bloque')
        print()
        modo = input('SELECCIONE EL MODO DE CIFRADO POR BLOQUES: ')
        print(color.ENDC)
        print(color.BOLD + 'MENSAJE ENCRIPTADO' + color.ENDC)
        if modo == '1':
            print(color.OKGREEN + aes.encrypt(1,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '2':
            print(color.OKGREEN + aes.encrypt(2,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '3':
            print(color.OKGREEN + aes.encrypt(3,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '4':
            print(color.OKGREEN + aes.encrypt(5,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '5':
            print(color.OKGREEN + aes.encrypt(6,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '6':
            print(color.OKGREEN + 'BCE: ' + aes.encrypt(1,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'CBC: ' + aes.encrypt(2,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'CFB: ' + aes.encrypt(3,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'OFB: ' + aes.encrypt(5,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'CTR: ' + aes.encrypt(6,mensaje).decode('utf-8') + color.ENDC)
        else:
            main()
        print()
    elif opcion == 'd' or opcion == 'D':
        print(color.OKYELLOW + 'CIFRADO POR BLOQUES')
        print('[1] BCE - Modo de libro de códigos electrónico')
        print('[2] CBC - Modo de cadena de bloques de cifrado')
        print('[3] CFB - Modo de cifrado con retroalimentación')
        print('[4] OFB - Modo de retroalimentación de salida')
        print('[5] CTR - Modo de contador')
        print('[6]  *  - Modo de bloque desconocido')
        print()
        modo = input('SELECCIONE EL MODO DE CIFRADO POR BLOQUES: ')
        print(color.ENDC)
        print(color.BOLD + 'MENSAJE DESENCRIPTADO' + color.ENDC)
        if modo == '1':
            print(color.OKGREEN + aes.decrypt(1,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '2':
            print(color.OKGREEN + aes.decrypt(2,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '3':
            print(color.OKGREEN + aes.decrypt(3,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '4':
            print(color.OKGREEN + aes.decrypt(5,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '5':
            print(color.OKGREEN + aes.decrypt(6,mensaje).decode('utf-8') + color.ENDC)
        elif modo == '6':
            print(color.OKGREEN + 'BCE: ' + aes.decrypt(1,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'CBC: ' + aes.decrypt(2,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'CFB: ' + aes.decrypt(3,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'OFB: ' + aes.decrypt(5,mensaje).decode('utf-8') + color.ENDC)
            print(color.OKGREEN + 'CTR: ' + aes.decrypt(6,mensaje).decode('utf-8') + color.ENDC)
    else:
        main()

if __name__ == "__main__":
    main()
