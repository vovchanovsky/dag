# This example fetches and prints a message with the given ID.
import iota_client

# *** Replace with the ID you got from the previous example ***
MESSAGE_ID = '6c1b9432f7491242e8a8a3429c7d944797abf911c3e40e87a34aee0f75ae7c6d'
# Chrysalis testnet node
LOCAL_NODE_URL = "http://20.238.91.195:14265"
client = iota_client.Client(nodes_name_password=[[LOCAL_NODE_URL]])

indexmas= client.find_messages(["Chrysalis Python Workshop"])
print(indexmas[1])
"""
message = client.get_message_data(MESSAGE_ID)
message_index = message['payload']['indexation'][0]['index']
message_content = message['payload']['indexation'][0]['data']
print(f'Message data: {message}')
print(f'Message index: {bytes.fromhex(message_index).decode("utf-8")}')
print(f'Message content: {bytes(message_content).decode()}')
"""
