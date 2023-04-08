import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import requests
import json
import random

def create_device_folder(device_id):
    os.makedirs(device_id, exist_ok=True)

def generate_keypair(device_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{device_id}/private_key.pem", "wb") as f:
        f.write(private_pem)

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{device_id}/public_key.pem", "wb") as f:
        f.write(public_pem)

    return private_key, public_key

def generate_self_signed_cert(device_id, private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_id),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=30)
    ).sign(private_key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(f"{device_id}/device_cert.pem", "wb") as f:
        f.write(cert_pem)

    return cert_pem

def send_cert_to_fog_node(cert_pem, fog_node_port):
    url = f"http://127.0.0.1:{fog_node_port}/register_device"
    response = requests.post(url, data=cert_pem, headers={"Content-Type": "application/x-pem-file"})
    try:
        response.raise_for_status()
        message_id = response.json()["message_id"]
        print("Successfully registered device")
        print(f"Message ID: {message_id}")
        return message_id
    except:
        print("Connection error")

def save_message_id_to_file(device_id, message_id):
    with open(f"{device_id}/message_id.txt", "w") as f:
        f.write(str(message_id))


def choose_random_fog_node():
    with open("node_dictionary.json", "r") as f:
        node_dict = json.load(f)

    if not node_dict:
        raise ValueError("No fog nodes available now. Please try again later.")

    fog_node_name, fog_node_port = random.choice(list(node_dict.items()))
    return fog_node_name, fog_node_port

def main():
    parser = argparse.ArgumentParser(description="Register IoT Device")
    parser.add_argument('device_id', type=str, help="Device ID")
    args = parser.parse_args()


    fog_node_name, fog_node_port = choose_random_fog_node()
    print(f"Using fog node {fog_node_name} with port {fog_node_port}")

    create_device_folder(args.device_id)
    private_key, _ = generate_keypair(args.device_id)
    cert_pem = generate_self_signed_cert(args.device_id, private_key)
    message_id = send_cert_to_fog_node(cert_pem, fog_node_port)
    save_message_id_to_file(args.device_id, message_id)

if __name__ == "__main__":
    main()
