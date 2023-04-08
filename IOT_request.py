import argparse
import json
import random
import numpy as np
import requests
from functools import reduce

def load_fog_nodes():
    with open("node_dictionary.json", "r") as f:
        fog_nodes = json.load(f)
    return fog_nodes

def fog_req(fog_node, vector, id_list):
    fog_node_port=fog_nodes[fog_node]
    url = f"http://127.0.0.1:{fog_node_port}/mptas"
    payload = {"vector": list(vector), "id_list": id_list}
    print(payload)
    response = requests.post(url, json=payload)
    
    try:
        response.raise_for_status()
        print(f"Successfully sent mptas data to fog node {fog_node}")
    except:
        print(f"Connection error with fog node port {fog_node}")
    return response.json()["message"]

def mptas(choosed_device):
    fog_nodes = load_fog_nodes()
    devices = ["Test", "device2", "device3", "device5", "device6", "device7", "Airpods"] # Your devices dictionary here
    k = 3
    m = len(fog_nodes)
    if choosed_device in devices:
        devices.remove(choosed_device)
        id_list = random.sample(devices, k - 1)
        id_list.append(choosed_device)
        random.shuffle(id_list)
        print(id_list)
        loc = id_list.index(choosed_device)
        vectors = np.random.randint(2, size=(m - 1, k))
        e = np.zeros(k, dtype=int)
        e[loc] = 1
        sum_vector = np.add(np.sum(vectors, axis=0), e) % 2
        vectors = np.append(vectors, [sum_vector], axis=0)
        sending_nodes = random.sample(list(fog_nodes.keys()), m)
        responces = []
        for i in range(m):
            responce = fog_req(sending_nodes[i], vectors[i].tolist(), id_list)
            if len(responce) > 0:
                responces.append(responce.encode())
        if len(responces) > 1:
            key = reduce(lambda x, y: bytes([a ^ b for a, b in zip(x, y)]), responces)
        print(key.decode())
    else:
        print("Device not found")
        return
    
if __name__ == "__main__":
    fog_nodes = load_fog_nodes()
    parser = argparse.ArgumentParser(description="Request Public Key")
    parser.add_argument('device_id', type=str, help="Device ID")
    args = parser.parse_args()
    mptas(args.device_id)