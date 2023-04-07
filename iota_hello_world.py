# This example creates a new instance of the IOTA Client object and prints out
# the node information of the node you are connected to.
import iota_client

LOCAL_NODE_URL = "http://20.238.91.195:14266"
client = iota_client.Client(nodes_name_password=[[LOCAL_NODE_URL]])
# Chrysalis testnet node
print(f'{client.get_info()}')

INDEX = "TestIndex"
DATA = "Hello World!".encode()
message_id_indexation = client.message(index=INDEX, data=DATA)

print(f"Message sent!\n http://20.238.91.195:8081/dashboard/explorer/message/{message_id_indexation['message_id']}")
print("Copy the ID of your message. You'll need it in the next example.")
print(f"Message ID: {message_id_indexation['message_id']}")