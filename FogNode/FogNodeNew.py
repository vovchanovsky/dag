import os
import argparse
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import iota_client
from functools import reduce
import json
import atexit

app = Flask(__name__)

def initialize_node(node_name):
    # Create a folder with the node name if it doesn't exist
    if not os.path.exists(node_name):
        os.makedirs(node_name)
    # Generate a public-private key pair and save them to files in the node folder
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(os.path.join(node_name, 'private_key.pem'), 'wb') as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    with open(os.path.join(node_name, 'public_key.pem'), 'wb') as f:
        f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Initialized node {node_name} with public-private key pair.")
    return private_key

def fetch_from_IOTA(INDEX):
    indexmas = client.find_messages([INDEX])
    latest_cert = None
    latest_date = None
    if len(indexmas) == 0:
        print("No messages found")
        return None
    for i in indexmas:
            print(i["message_id"])
            cert_bytes = bytes(i["payload"]["indexation"][0]["data"]).replace(b"b'", b"").replace(b"'", b"").replace(b"\\n", b"")
            cert = x509.load_pem_x509_certificate(cert_bytes)
            if latest_date is None or latest_date < cert.not_valid_before:
                latest_cert = cert
                latest_date = cert.not_valid_before
    public_key = latest_cert.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print(public_key)
    return public_key

def send_to_IOTA(INDEX, msg):
    # send data to IOTA
    # create a socket object
    message_id_indexation = client.message(index=INDEX, data=str(msg).encode())
    print(f"Message sent!\n")
    print("Copy the ID of your message. You'll need it in the next example.")
    print(f"Message ID: {message_id_indexation['message_id']}")
    return message_id_indexation['message_id']

def add_node_to_dictionary(node_name, port):
    filename = 'node_dictionary.json'
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump({}, f)

    with open(filename, 'r') as f:
        node_dict = json.load(f)

    node_dict[node_name] = port

    with open(filename, 'w') as f:
        json.dump(node_dict, f)


def remove_node_from_dictionary(node_name):
    filename = 'node_dictionary.json'
    if not os.path.exists(filename):
        return

    with open(filename, 'r') as f:
        node_dict = json.load(f)

    if node_name in node_dict:
        del node_dict[node_name]

        with open(filename, 'w') as f:
            json.dump(node_dict, f)

@app.route('/mptas', methods=['POST'])
def handle_mptas():
    # Handle POST request with mptas data
    data = request.json
    vector, id_list = data['vector'], data['id_list']
    keys = []
    for i in range(len(vector)):
        if vector[i] == 1:
            print("Asked", id_list[i])
            key=fetch_from_IOTA(id_list[i])
            if key is not None:
                keys.append(key)
    if len(keys) > 1:
        result = reduce(lambda x, y: bytes([a ^ b for a, b in zip(x, y)]), keys)
    elif len(keys) == 1:
        result = keys[0]
    else:
        return jsonify({'status': 'success', 'message': ""})
    result = result.decode("utf-8")
    return jsonify({'status': 'success', 'message': result})

@app.route('/register_device', methods=['POST'])
def handle_register_device():
    fog_node_private_key = private_key
        # Handle POST request to register a device
    device_cert_pem = request.data
    device_cert = x509.load_pem_x509_certificate(device_cert_pem)
    device_public_key = device_cert.public_key()

    # Generate a new certificate for the IoT device
    device_id = device_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_id),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.name),
    ])
    new_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        device_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=30)
    ).sign(fog_node_private_key, hashes.SHA256())

    new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)

    # Call send_to_IOTA function with index = IoT device_id and msg = certificate data
    message_id = send_to_IOTA(device_id, new_cert_pem)

    return jsonify({'status': 'success', 'message': 'device registered', 'message_id': message_id})
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FogNode')
    parser.add_argument('-p', '--port', type=int, required=True, help='port number to run the server on')
    parser.add_argument('-a', '--iotaaddress', type=str, required=True, help='IOTA address for the node')
    parser.add_argument('-n', '--name', type=str, required=True, help='name of the node')
    args = parser.parse_args()
    
    add_node_to_dictionary(args.name, args.port)
    atexit.register(remove_node_from_dictionary, args.name)
    private_key = initialize_node(args.name)
    client = iota_client.Client(nodes_name_password=[[args.iotaaddress]])
    print(f'{client.get_info()}')
    app.run(host='0.0.0.0', port=args.port, debug=False)
