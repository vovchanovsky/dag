import hashlib
import json
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import datetime
from math import log2, floor
import numpy as np
import random
from functools import reduce 


fog_nodes = {"fog1": "fog1publickey", "fog2": "fog2publickey", "fog3": "fog3publickey", "fog4": "fog4publickey",
             "fog5": "fog5publickey","fog6": "fog6publickey"}

devices = {"device1": "device1publickey", "device2": "device2publickey", "device3": "device3publickey",
           "device4": "device4publickey", "device5": "device5publickey", "device6": "device6publickey",
            "device7": "device7publickey", "device8": "device8publickey", "device9": "device9publickey",        
        }


def fog_req(fog_node, vector, id_list):
    print(fog_node,vector, id_list)
    answer="fffbbgg"
    return answer

def mptas(choosed_device):
    k=5
    m = len(fog_nodes)
    devices_list = list(devices.keys())
    if choosed_device in devices.keys():
        devices_list.remove(choosed_device)
        id_list = random.sample(devices_list, k-1)
        id_list.append(choosed_device)
        random.shuffle(id_list)
        print(id_list)
        loc = id_list.index(choosed_device)
        vectors=np.random.randint(2, size=(m-1, k))
        e = np.zeros(k, dtype=int)
        e[loc] = 1
        sum_vector = np.add(np.sum(vectors, axis=0), e)% 2
        vectors=np.append(vectors, [sum_vector], axis=0)
        # random choose  m unique fog nodes
        sending_nodes=random.sample(list(fog_nodes.keys()), m)
        for i in range(m):
            fog_req(sending_nodes[i],list(vectors[i]), id_list)
        print("key")
    else:
        print("Device not found")
        return
    print(id_list)

print(mptas("device7"))


def read_file(filename):
    with open(filename, "r") as f:
        data = f.read()
    return data

class IoTDevice:
    def __init__(self, producer, model, serial_number):
        self.producer = producer
        self.model = model
        self.serial_number = serial_number

        # generate a public and private key pair
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

        # create a unique identifier with random salt
        self.salt = os.urandom(16)
        self.device_id = self.generate_device_id()
        self.fog_node, self.fog_key = self.findclosestfognode()
        if not os.path.exists(f"{self.serial_number}"):
            os.mkdir(f"{self.serial_number}")
        # save device information and certificates to files
        self.save_device_info()
        self.save_certificates()
        self.generate_self_signed_cert()

    def findclosestfognode(self):
        print("Find closest fog node")
        fog_id = "fog1"
        fog_key = "fog1publickey"
        return fog_id, fog_key
    
    def generate_device_id(self):
        # create a string using producer, model, and serial number
        str_to_hash = f"{self.producer}{self.model}{self.serial_number}{self.salt}"

        # hash the string using SHA256 algorithm
        hashed_bytes = hashlib.sha256(str_to_hash.encode()).digest()

        # encode the hashed bytes into hexadecimal format
        device_id = hashed_bytes.hex()

        return device_id

    def save_device_info(self):
        # create a dictionary with device information
        device_info = {
            "device_id": self.device_id,
            "producer": self.producer,
            "model": self.model,
            "serial_number": self.serial_number,
            "salt": self.salt.hex(),
            "fog_node": self.fog_node,
            "fog_key": self.fog_key,
        }

        # save the devicea information to a file
        with open(f"{self.serial_number}/device_info.json", "w") as f:
            json.dump(device_info, f)
    

    
    def save_certificates(self):
        # save the public key to a file
        with open(f"{self.serial_number}/public.pem", "wb") as f:
            f.write(self.public_key.export_key())

        # save the private key to a file
        with open(f"{self.serial_number}/private.pem", "wb") as f:
            f.write(self.private_key.export_key())

    
    def generate_self_signed_cert(self):
        # create a dictionary with the information to sign
        cert_info = {
            "device_id": self.device_id,
            "public_key": self.public_key.export_key().decode(),
            "fog_node": self.fog_node,
            "valid_period": str(datetime.datetime.utcnow() + datetime.timedelta(days=30)),
        }

        # serialize the dictionary to JSON format
        info_json = json.dumps(cert_info).encode()

        # hash the serialized JSON data using SHA256 algorithm
        hashed_data = SHA256.new(info_json)

        # sign the hashed data using the private key
        signature = pkcs1_15.new(self.private_key).sign(hashed_data)

        # add the signature to the information dictionary
        cert_info["signature"] = base64.b64encode(signature).decode()
        print(cert_info)
        # save the certificate to a file
        with open(f"{self.serial_number}/device_cert.pem", "w") as f:
            json.dump(cert_info, f)

    def send_to_fog(self, fogkey):
        cipher = PKCS1_OAEP.new(fogkey)
        with open(f"{self.serial_number}/device_cert.pem", 'rb') as f:
            file_contents = f.read()
        print(file_contents)
        #encrypted_cert = cipher.encrypt(file_contents)
        #print (encrypted_cert)
        # send the encrypted certificate to the fog node
        """sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('fog_node_address', 12345)) # replace with actual fog node address and port number
        sock.sendall(encrypted_cert)
        sock.close()"""

    def send_auth_req(self):
        self.device_id, self.public_key
        # send the device ID and public key to the fog node

# example usage

device_a = IoTDevice("Acme Corp.", "Walet", "td1234")
print(f"Device A producer: {device_a.producer}")
print(f"Device A model: {device_a.model}")
print(f"Device A serial number: {device_a.serial_number}")
print(f"Device A ID: {device_a.device_id}")
device_a.send_to_fog("fog1publickey")
