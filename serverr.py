import socket
import select

HEADER_LENGTH = 10
IP='0.0.0.0'
PORT=81
server_socket= socket.socket()
server_socket.bind(('0.0.0.0', 81))
server_socket.listen(5)
open_client_sockets = []  #list of clients waiting to be handled
clients = {}  #dictionary of c sockets and users(information like name and data)
messToSend = [] #list of messages that need to be sent
admins = []
groups = {}


def receiveMessage(client_socket):  #recv the message and its headers(name of the sender)
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode("utf-8").strip())
        return{"header":message_header, "data":client_socket.recv(message_length)} #returns the length of the meesage and the message itself

    except:
        pass



while True:
    rlist, wlist, xlist = select.select([server_socket] + open_client_sockets, open_client_sockets,[])  # list of clients waiting to be handeled
    for current_socket in rlist:  #check if theres a new client or a new data
        if current_socket is server_socket:  #if a new client conected
            (newC_socket, address)= server_socket.accept()  #accepting new client conection

            user = receiveMessage(newC_socket) #recv the message it sent(its name)
            if user is False:
                continue
            open_client_sockets.append(newC_socket)  # add to client list
            clients[newC_socket] = user #adding the user to dictionary
            print("accepted new conection")
        else:
            message = receiveMessage(current_socket)
            if message is False:
                print("connection closed")
                open_client_sockets.remove(current_socket)
                del clients[current_socket]
                continue
            user = clients[current_socket]
            print(f"recived message from {user['data'].decode('utf-8')}:{message['data'].decode('utf-8')}")

            #sharing the message with everyone:
            for client_socket in clients:
                #if client_socket != current_socket:
                client_socket.send(user['header'] + user['data'] +message['header'] + message['data'])
                print("sent")








