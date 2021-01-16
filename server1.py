import socket
import select
import os
import base64

IP = '0.0.0.0'
PORT = 81
clients = {}  # dictionary of c sockets and users(information like name and data)
groups = {}   #dictionary with the groupnames as keys and their admins as values


def IsNormOk(clientsMess):
    '''checks if the normal request is ok. recv the clients message(inclding headers)'''
    user = clientsMess.split("\r\n\r\n")[0]
    user = user.split("\r\n")[0]
    user = user.split(":")[0]
    if user == "USER":
        return 1
    return 0


def getUrl(clientMess):
    '''gets the url of the http request and also checks the request is valid'''
    clientsReq = clientMess
    clientsReq = (clientsReq.split("\r\n")[0].split(" "))  # trying to get the url which is usually in the first line
    print(clientsReq)
    if clientsReq[0] == "POST":
        return clientsReq[1], 1  # returns the url and 1 for the code to know its a post method

    return 0, 0  # if there's an error


def addToClients(user, current_socket):
    '''adds clients name to dictionary,if its not there yet
    the key is the users name and the value is the socket'''
    print("entered to addToClients")
    if not clients:  # if the dictionary is empty
        clients[user] = current_socket  # adds the name of the user to the clients dictionary
    if user not in clients:  # if the user isnt in the dictionary yet
        clients[user] = current_socket
        print(user + "-added to client dictionay")
    print(clients)


def makeNormalReq(clientsMess, messToSend, current_socket):
    '''handles the normal request.gets the username of the sender,adds it to clients list
     then gets the name of the client that the message is for and sets a message
     then adds the dest of the message and the message itself to the messages list'''
    print(("#####################################"))
    print("entered the MakeNormReq")
    headers, message = clientsMess.split("\r\n\r\n")  # splits the headers and the message ifself
    headers = headers.split("\r\n")  # splits all the headers for them to be separate
    print(headers)
    mess = ""
    pubK = headers[2]
    pubK = pubK.split(":")[1]
    for header in headers:
        headeer, data = header.split(":")
        if headeer == "USER":
            user = data
            addToClients(user, current_socket)
            mess += user + ":" + message  # creates the message that will be sent to the client
            mess+="PUBLICKEY:"+pubK
        if headeer == "DEST":
            dest = data
            print("going to be sent to:" + dest)
            messToSend.append((dest, mess))  # adds to the list of messages the tuple of the destination and the message itself
            # saves the message to the file of the chat-if a group adds the first admin
            save(clientsMess,mess,None)

            if IsAdmin(clientsMess):
                adminMessage=user+":IS AN ADMIN"
                messToSend.append((user,adminMessage))
                save(clientsMess,adminMessage,None)

        if headeer == "PUBLICKEY:":
            pass

def save(clientsMess,mess,filename):
    '''saves the messages from the clients to chat files
    the filename will be sent to this function only in cases of http req'''
    folder = getFolder(clientsMess)
    # its an HTTP method
    if mess.find("HTTP")==0:
        message = mess.split(" ")[1:] #gets the message without the HTTP in the begining
        if filename is not None: #its a file Http request
            message = message[1]+filename
            message+="\r\n"
            fd = open(folder + "/" + "chatDecomentation.txt", 'a+')
            fd.write(message)
            fd.close()
        else: #its an encription
            #TODO:DEAL WITH ENCRYPTION
            pass
    else:
        #its a normal text message
        mess+="\r\n"
        fd = open(folder + "/" + "chatDecomentation.txt", 'a+')
        fd.write(mess)
        fd.close()


def addAdmin(client,groupname):
    '''the func adds an admin to the group.
    gets the client that going to be an admin and the groupname'''

    #if the dictionary is empty
    if not groups:
        admins=[client] #setting a new list of clients
        groups[groupname]=admins #adds it as the value of the groupname
        print("opened a new group and added its first admin:" + client)
        print(groups)


    else:
        #the dictionary doesnt contain the group
        if groupname not in groups.keys():
            admins = [client]  #setting a new list of clients
            groups[groupname] = admins #adds it as the value of the groupname
            print("opened a new key-group and added first admin:" + client)


        #the group exists and already has admins
        else:
            #adding a new admin
            admins = groups[groupname]
            admins.append(client)
            groups[groupname] = admins
            print("added new admin:"+client)


def getFolder(clientsMess):
    '''gets or creates a folder for the session being handled
    the name of the folder will be the dest+sender,
    however it might be the opposite incase the sender sent to the dest a message first.
    for groups it will just be the group name'''

    # checks if a folder exists
    sender, dest = getSenderDest(clientsMess)
    #if not a group
    if dest.count("-")==0:
        if os.path.exists(f"./{sender + dest}/"):
            return sender + dest
        if os.path.exists(f"./{dest + sender}/"):
            return dest + sender
        # creates a new folder
        folder = dest + sender
    #its a group
    else:
        folder = dest.split("-")[0]
        if os.path.exists(f"./{folder}"):
            return folder
        else: #folder doesnt exist->the first time a messaage sent in the group
            addAdmin(sender,folder)

    try:
        # opens it
        os.mkdir(f"{folder}/")

    except Exception as e:
        # prints the execption
        print(e)
        # returns 0 as an error
        return 0
    return folder


def getSenderDest(clientsMess):
    ''' gets the clients req and gets out of it the dest and sender names'''

    if clientsMess.find("USER")==0:
        #if its in a normal req
        dest = clientsMess.split("\r\n")[1]
        dest = dest.split(":")[1]
        sender = clientsMess.split("\r\n")[0]
        sender = sender.split(":")[1]
    else:
        dest = clientsMess.split("\r\n")[1]
        dest = dest.split(" ")[1]
        sender = clientsMess.split("\r\n")[5]
        sender = sender.split(" ")[1]

    return sender, dest


def handle_httpPostExec(url, clientsMess, messToSend, current_client):
    '''checks what kind of http req, adds the message to the sending list and the http resp(that the message was recved)
    url-the file asked
    client_request- the http request that was made
    messToSend- list of all the messages
    current_client- the client socket that we deal with'''
    print("######################")
    print("entered to handle_httpPostExec ")

    # checks if its a file req
    if len(url.split("=")) > 1:
        # checks what kind of req we got- admin or file
        req = url.split("?")[1].split("=")[0]
        if req == "file-name":
            # gets the filename
            filename = url.split("=")[1]
            folder = getFolder(clientsMess)
            data = clientsMess.split("\r\n\r\n")[1]
            # decodes the pictures from base64 because it was encoded it the client before sent
            data = base64.b64decode(data)

            with open(f"./{folder}/{filename}", 'wb') as file:
                file.write(data)  # writing the data
                file.close()

            # getting the http type of the file
            type = filename.split(".")[1]
            type = getType(type)
        #its a admin req
        if req == "DEST":
            type = "GroupType"
            action = url.split("?")[0]
            if action=="addMember" or action=="removeMember" or action=="addAdmin":
                adminReq(url,clientsMess,current_client,messToSend)

    length = clientsMess.split("\r\n")[2].split(" ")[1]
    isAdmin = IsAdmin(clientsMess)
    response = f"HTTP/1.1 200 OK\r\nContent-Length:{length}\r\nContent-Type:{type}\r\nAdmin:{isAdmin}\r\n\r\n"

    messToSend.append((current_client, response))  # sending the client a http response
    sendHttpPost(filename, messToSend, clientsMess)

def adminReq(url,clientsMess,current_client,messToSend):
    '''gets the admin req and executes it'''
    action = url.split("?")[0]
    member = url.split("=")[1] #the client the action is done on
    #geting the groupname
    sender, dest = getSenderDest(clientsMess)
    groupname = dest.split("-")[0]
    if action == "addAdmin":
        addAdmin(member, groupname)
        admin = "True"
        newGroupname = dest
        act = f"1,{member}"

    else:
        if action =="addMember":
            admin = "False"
            newGroupname = dest+","+member
            act = f"2,{member}"
        if action =="removeMember":
            admin = "False"
            members = dest.split("-")[1].split(",")
            members.remove(member)
            memberss = ",".join(members)
            newGroupname = groupname+"-"+memberss
            act = f"3,{member}"
    #the message for the member that the action was on
    memberMess =  "HTTP/1.1 200 OK\r\nContent-Length:" + "0" + "\r\n" + "Content-Type:" + "None" + "\r\n" + "Admin:" + admin + "\r\n\r\n"
    #the message for everyone-to know when something changes
    allMember =  "HTTP dest: " + newGroupname + ": content:" + "?NEW:" + newGroupname +"?act:"+ act
    messToSend.append((member,memberMess))
    messToSend.append((newGroupname,allMember))


def IsAdmin(clientsMess):
    '''checks if the client is an admin and sends true of false'''
    sender, dest = getSenderDest(clientsMess)
    if dest.count("-")!=0:#its a group
        groupname= dest.split("-")[0]
        if not groups: #if the groups dic is empty
            return False
        for key in groups: #going through the groups
            if key ==groupname: #finds the group
                for value in groups[key]: #goes through the the admins in the group
                    if value == sender:
                        return True

    print("not a group")
    return False



def sendHttpPost(filename, messToSend, clientsMess):
    '''function appends the data to the messages list that wait to be sent.and saves the chat'''
    content = clientsMess.split("\r\n\r\n")[1]  # base 64 encripted-->string
    #content = base64.b64decode(content) # decoding,back to bytes

    sender, dest = getSenderDest(clientsMess)

    resp = f"HTTP sender: {sender}: file: {filename} content:{content}"
    messToSend.append((dest, resp))
    save(clientsMess,resp,filename)#saves the resp to the chat file


def getType(type):
    '''gets the http file type of a file'''
    if type == "jpg":
        httptype = " image/jpeg"

    elif type == "wav":
        httptype = "audio/wave"

    return httptype


def makeTheReq(clientsMess, messToSend, current_socket):
    '''gets the clients request. checks if its normal or http request and acts acordingly'''
    # first we want to seprate the headers from the message
    print("##############################")
    print("enterd to makeTheReq")
    headers, message = clientsMess.split("\r\n\r\n")
    print("headers:" + headers)
    print(message)

    # if it its the firts time the user sends a message-its his username only
    if headers.split(":")[0] == "USERN":
        user = headers.split(":")[1]
        print(user)
        addToClients(user, current_socket)

    else:  # if its not the first time
        # creating a list of the headers
        headers = headers.split("\r\n")  # separate all the headers
        print(f"all headers:{headers}")
        f = headers[0].split(":")[0]
        if headers[0].split(" ")[0]=="HTTPS":
            encrypted = message  #-->still a string
            dest = headers[1].split(":")[1]
            encrypType = headers[4].split(": ")[1]
            AffKeys = headers[5].split(":")[1] #gets the keys

            #adding the message to the messages list
            req = f"HTTPS:\r\nencrypType:{encrypType}\r\nmess-{encrypted}\r\nkeys:{AffKeys}"
            messToSend.append((dest,req))
            return 1
        if len(headers[0].split(" ")) > 2:  # check if its an http or normal request. checks if in the first header theres more than one space. if there is its not a normal request
            if headers[0].split(" ")[2] == "HTTP/1.1":  # checks if its an http request
                print("http request")
                url, valid = getUrl(clientsMess)  # returns the url and if the request is valid
                print(url)
                if valid != 0:
                    print("its a valid http req")

                    try:
                        # calls a func that will add the message to the list of messages
                        handle_httpPostExec(url, clientsMess, messToSend, current_socket)

                    except Exception as e:
                        print(e)
                        return 0
                    return 1

        else:  # its a normal request
            print("a normal req")
            valid = IsNormOk(clientsMess)  # check if the normal req is ok,return 1 if ok, 0 otherwise
            if valid != 0:  # if the request is fine
                makeNormalReq(clientsMess, messToSend, current_socket)  # handles the normal req
                return valid
            else:
                return valid  # if not valid,returns 0


def handleClient(current_socket, messToSend):
    '''gets the client and the list of messages the wait to be sent. sees if the client connected and if so,
     calls funcs that deal with sending the messages.
     if its not connected sends 1 to the main func that will dissconect the client from all the lists'''
    clientsMess = ""
    print(current_socket)
    try:
        print("entered to try handle client")
        clientsMess = current_socket.recv(1000000).decode("utf-8")  # gets the data.the message is sent in byte form. we convert it to string
        print(f"name recv:{clientsMess}")
        if clientsMess != "":  # if theres a message

            makeTheReq(clientsMess, messToSend,current_socket)  # executes the request-check if normal of http and act acordingly



    except Exception as e:
        print(e)  # prints the exeption that occurd
        print("no data")
        return 1  # returns false
    return 0  # everything ran smootly


def sendWaitingMess(wlist, messToSend):  # TODO:ADD SUPPORT FOR GROPS
    '''the function gets the list of open clients that wait for messages and list of messages the need to be sent
    the function sends the messages'''
    print("entered sendingMessages")
    for message in messToSend:
        # seprates the tuple to two variables
        (dest, data) = message
        print(f"mess des:{dest}")
        print(f"data:{data}")
        client_socket = ""
        #check if its a gruop
        if type(dest)== str:
            if dest.count("-")>0:
                gruMem = dest.split("-")[1].split(",")
                #going through the members and sending the message
                for gruopMember in gruMem:
                    #if the member in clients dictionary
                    if gruopMember in clients:
                        #get its socket
                        client_socket = clients.get(gruopMember)
                        #if its in the writing socket list,send it the message
                        if client_socket in wlist:
                            #sending the message
                            client_socket.send(data.encode('utf-8'))
                #after that was sent to everyone in the gruop deete the message
                #messToSend.remove(message)
                client_socket=""
                dest=""
        if dest in clients:  # if its a single person and not a group
            client_socket = clients.get(dest)  # gets the socket that reffers to the name dest

        elif dest in clients.values():  # incase of http post request the dest is already a socket
            dest.send(data.encode("utf-8"))

        if client_socket in wlist:
            # check if the client is writeable and sent it the message
            client_socket.send(data.encode('utf-8'))
            #messToSend.remove(message)  # removing the message from the list
            print("________________________________")
            print(messToSend)
            print("________________________________")
        print("message sent")
        #messToSend.remove(message)
    messToSend.clear()
    print(messToSend)

def removeClient(current_socket):
    '''removes the  client from client dictionary'''
    if current_socket in clients.values():
        for client in clients.values():
            if client == current_socket:
                name = clients[client]
                del name
    print(clients)


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', PORT))
    server_socket.listen(15)
    open_client_sockets = []  # list of clients waiting to be handled
    messToSend = []  # list of messages that need to be sent contains tupels of the dest of the message and the message itself

    while 1:
        rlist, wlist, xlist = select.select([server_socket] + open_client_sockets, open_client_sockets,
                                            [])  # list of clients waiting to be handeled
        for current_socket in rlist:  # check if theres a new client or a new data
            if current_socket is server_socket:  # if a new client conected
                (newC_socket, address) = server_socket.accept()  # accepting new client conection
                open_client_sockets.append(newC_socket)  # add to client list
                # user = str(address[1])
                print("accepted new conection")

            else:
                ConOrDis = handleClient(current_socket, messToSend)  # checks if the client is connected or not
                if ConOrDis == 1:  # client isnt connected
                    open_client_sockets.remove(current_socket)
                    # removes client from dictionary  TODO:WHEN THERE ARE GROUPS DEL FROM THE GROUP TOO?
                    removeClient(current_socket)
            sendWaitingMess(wlist, messToSend)


if __name__ == "__main__":
    main()
