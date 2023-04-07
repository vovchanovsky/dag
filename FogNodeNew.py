import os
import argparse
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import iota_client

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

def fetch_from_IOTA(INDEX):
    indexmas= client.find_messages([INDEX])
    for i in indexmas:
        print(i["message_id"])

@app.route('/mptas', methods=['POST'])
def handle_mptas():
    # Handle POST request with mptas data
    data = request.json
    vector, id_list = data['vector'], data['id_list']
    for i in range(len(vector)):
        if vector[i] == 1:
            print(id_list[i])
            fetch_from_IOTA(id_list[i])

    
    # Process the data as needed
    # ...
    # Return a response
    return jsonify({'status': 'success', 'message': 'mptas data received'})

@app.route('/register_device', methods=['POST'])
def handle_register_device():
    # Handle POST request to register a device
    data = request.json
    # Register the device as needed
    # ...
    # Return a response
    return jsonify({'status': 'success', 'message': 'device registered'})

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FogNode')
    parser.add_argument('-p', '--port', type=int, required=True, help='port number to run the server on')
    parser.add_argument('-a', '--iotaaddress', type=str, required=True, help='IOTA address for the node')
    parser.add_argument('-n', '--name', type=str, required=True, help='name of the node')
    args = parser.parse_args()

    initialize_node(args.name)
    client = iota_client.Client(args.iotaaddress)
    print(f'{client.get_info()}')

    app.run(host='0.0.0.0', port=args.port)
