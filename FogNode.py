from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import json
import datetime
import socket


class FogNode:
    def __init__(self, id):
        self.ID = id

        # generate a public and private key pair
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        

    def save_certificates(self):
        # save the public key to a file
        with open(f"{self.ID}/public.pem", "wb") as f:
            f.write(self.public_key.export_key())

        # save the private key to a file
        with open(f"{self.ID}/private.pem", "wb") as f:
            f.write(self.private_key.export_key())

    def decrypt(self, encrypted_data):
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_data = cipher.decrypt(encrypted_data)
        print("Decrypted data:", decrypted_data)

    def issuepublickey(self, device_id, device_key):
        cert_info = {
            "device_id": device_id,
            "device_key": device_key,
            "fog_node": self.ID,
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
        


Fog_a = FogNode("Fog1")
Fog_a.issuepublickey("Device1", "Device1key")