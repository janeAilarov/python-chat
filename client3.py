import socket
import sys
import os
import msvcrt
import _thread
from appJar import gui
from tkinter import filedialog
from tkinter import *
import pyaudio
import wave
from playsound import playsound
import PIL
from PIL import Image, ImageTk
import base64
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



#HEADER_LENGTH=10 #the length of the username's name(constant) ---->not relevant anymore
IP='127.0.0.1'
PORT=81
MyUsername = input("Username: ")
X = 0
order = 0 #the order num(every action has an order number)
isgroup = False
admin = False #is the client an admin in a group
#creating private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
#creating public key
public_key = private_key.public_key()
KeySent = False
PubKeys = {} #a dictionary where the clients name is the key and its public key is the value


def getDestKey(app):
    '''
    :param app: ''
    :return:the public key of the dest client
    '''
    global PubKeys
    dest = app.label("contact")
    for key in PubKeys: #going through the keys
        if key == dest: #if the key is the destination's name
            Dpublic_key = PubKeys.get(dest) #get its value
    return Dpublic_key


def enterApp(event,app): #gets to the main frame

    if event =="enter app":
        app.prevFrame("Pages")
        user = app.getEntry("Contact")
        #adding the contact's name to the gui-can aso be a group name with the name's of the contacts
        app.label("contact", user)
        global X
        X+=1
        #adding a scrollpaneroll
        #disabeling the horizontal option
        app.startScrollPane("pane"+str(X), disabled="horizontal")

def start(client_socket):  #sends a client request to server.
    print("entered to start")
    print(MyUsername)
    username_header = "USERN:"+MyUsername+"\r\n\r\n"
    username_header = username_header.encode("utf-8")
    client_socket.send(username_header) #sends the username's name
    print(username_header)
    print("name sent")


def saveFile(filename, content, dest):
    content = base64.b64decode(content)
    folder = getFolder(dest)
    fd = open(folder+filename, 'wb')
    fd.write(content)
    fd.close()
    return folder


def getFileType(app,dest,content,dataFserver):
    '''the function destinguishing the type of the file sent and adds it to the gui'''
    global X
    #get the name of the  file->wallpaper.jpg for exemp
    filename = dataFserver.split("file:")[1:][0]
    filename = filename.split(" content:")[0]
    #if its am img
    if filename.split(".")[1] == "jpg":
        #the message came from the server-we need a folder and a file to write to
        if content!="":
            folder = saveFile(filename, content, dest)
            filename = folder+filename

        img = Image.open(filename)
        imgSize = 150,150
        img.thumbnail(imgSize, Image.ANTIALIAS)
        pic = ImageTk.PhotoImage(img)
        X += 1
        label = "l"+ str(X)
        name= f"{dest}:"
        app.label(label, name)
        X += 1
        picname = "pic" + str(X)
        # calling the gui function that adds the image to the gui
        app.addImageData(picname, pic, fmt="PhotoImage")

     #if its an audio
    if filename.split(".")[1]=="wav":
        if content!="":
            folder = saveFile(filename, content, dest)
            filename = folder+filename
        X+=1
        label = "l" + str(X)
        name = f"{dest}:"
        app.label(label, name)

        X+=1
        recName = f"rec{X}"
        #creating a button to play the record when pressed
        app.buttons([recName],[lambda event:playAudio(event,filename,dest)])


def playAudio(event,filename,dest):
    '''palys the recording'''
    print("playing recording")
    chunk = 1024

    # Open the sound file
    wf = wave.open(filename, 'rb')

    # Create an interface to PortAudio
    p = pyaudio.PyAudio()

    # Open a .Stream object to write the WAV file to
    # 'output = True' indicates that the sound will be played rather than recorded
    stream = p.open(format=p.get_format_from_width(wf.getsampwidth()),
                    channels=wf.getnchannels(),
                    rate=wf.getframerate(),
                    output=True)

    # Read data in chunks
    data = wf.readframes(chunk)

    # Play the sound by writing the audio data to the stream
    while data != '':
        stream.write(data)
        data = wf.readframes(chunk)

    # Close and terminate the stream
    stream.close()
    p.terminate()



def addMtoGui(app,dataFserver,client_socket): #edits the gui.adds the message that was sent by server
    #checks if its an http,has more than two ':'
    if dataFserver.count(':')>2:
        global X
        #if its an http resp, check if you are a new admin
        if dataFserver.split(" ")[0]=="HTTP/1.1":
            ''' "HTTP/1.1 200 OK\r\nContent-Length:" + str(length) + "\r\n" + "Content-Type:" + type
                 + "\r\n" + "Admin:" +TRUE/FALSE + "\r\n\r\n"
'''
            adminActions(app,client_socket,dataFserver)

        #if the data came from the server,http req.->can be file req or admin action
        if dataFserver.split(" ")[0]=="HTTP":
            # getting the information ->"http dest :username+"file:"+folder+filename+"content:"
            content = dataFserver.split("content:")[1]

            dest = dataFserver.split(" ")[2].split(':')[0]
            #if its a file
            if dataFserver.find("file:")>0:
                #calling the func that gets the file's type and adds it to the gui
                getFileType(app,dest,content,dataFserver)

            #somethings had changed in the group
            if dataFserver.count("?NEW")>0:
                newGroupname = dataFserver.split(":")[4].split("?")[0]
                #changing the group name to the new one(with or without one of the members)
                app.label("contact",newGroupname)
                act = dataFserver.split("?act:")[1].split(",")[0]
                member = dataFserver.split("?act:")[1].split(",")[1]
                #global X
                if act == "1":
                    #new admin added
                    print(f"{member} is an admin")
                    #global X
                    X += 1
                    label = "l" + str(X)
                    app.label(label,f"{member} is an admin")

                if act=="2":
                    #new member
                    print(f"{member} added")
                    #global X
                    X += 1
                    label = "l" + str(X)
                    app.label(label, f"{member} added")
                if act=="3":
                    #removed member
                    print(f"{member} removed")
                    #global X
                    X += 1
                    label = "l" + str(X)
                    app.label(label, f"{member} removed")
        if dataFserver.split("\r\n")[0].split(":")[0]=="HTTPS":
            encrypType = dataFserver.split("\r\n")[1].split(":")[1]
            mess= dataFserver.split("\r\n")[2].split("-")[1]
            if encrypType =="RSA":
                #encrypt the message
                try:
                    ciphertext_decoded = base64.b64decode(
                        mess) if not isinstance(mess, bytes) else mess
                    original_message = private_key.decrypt(
                        ciphertext_decoded,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    plain_text = str(original_message, encoding='utf8')
                    print(plain_text)
                    X += 1
                    label = "l" + str(X)
                    app.label(label,plain_text)
                except EXCEPTION as e:
                    print(e)
            if encrypType =="Affine_cipher":
                keys = dataFserver.split("\r\n")[3].split(":")[1].split(",")
                keyA = int(keys[0])
                keyB = int(keys[1])
                plain_text = affine_cipher(mess,keyA,keyB,encrypt=False)
                X += 1
                label = "l" + str(X)
                app.label(label, plain_text)

    #its a normal req
    else:
        if dataFserver.split(":")[1]=="IS AN ADMIN":
            global admin
            if admin !=True:
                admin=True
                global isgroup
                isgroup = True
                app.entry("member:", label=True)
                app.addButtons(["addMember", "removeMember", "addAdmin"],[lambda event: sendAdmReq(event, app, client_socket),lambda event: sendAdmReq(event, app, client_socket),lambda event: sendAdmReq(event, app, client_socket)])
        if isgroup==False:
            if dataFserver.split("PUBLICKEY:")[1] != "*":
                setPubK(dataFserver) #setting the key of the sender in the dictionary of keys
        #global X
        X += 1
        label = "l" + str(X)
        printData = dataFserver.split("PUBLICKEY:")[0]
        if printData.split(":")[1]!="IS AN ADMIN": #if its not admin info
            app.label(label, value=printData)

def setPubK(dataFserver):
    '''the func gets the key that was sent by the sender and sets it in a dictionary of public keys'''
    global PubKeys
    pubK = dataFserver.split("PUBLICKEY:")[1]
     #it was converted to a string before sent and need to be byte string so we convert it back
    #TODO:GET THE KEY AS AN RSA OBJECT
    pubKk = serialization.load_pem_public_key(
        pubK.encode('utf-8'),
        backend=default_backend()
    )
    owner = dataFserver.split(":")[0] #getting the USER name
    #adding the key to the dictionary
    PubKeys[owner] = pubKk
    print(PubKeys)


def adminActions(app,client_socket,dataFserver):
    ''''"HTTP/1.1 200 OK\r\nContent-Length:" + str(length) + "\r\n" + "Content-Type:" + ttype
                 + "\r\n" + "Admin:" True/False + "\r\n\r\n"'''

    if dataFserver.split("\r\n")[3].split(":")[1]=="True":
        global admin
        if admin!=True:
            admin=True
            app.addButtons(["addMember","removeMember","addAdmin"],[lambda event:sendAdmReq(event,app,client_socket),lambda event: sendAdmReq(event, app, client_socket),lambda event: sendAdmReq(event, app, client_socket)])
            app.entry("member:",label=True)

def sendAdmReq(event,app,client_socket):
    '''the func sends the server the wanted action of the admin'''

    #gets the member that the action will be on
    member = app.entry("member:")

    #gets the type of action
    if event == "addMember":
        action = "addMember"
    if event == "removeMember":
        action = "removeMember"
    if event == "addAdmin":
        action = "addAdmin"

    #dets the dest and headers
    #dest = app.entry("Contact")
    dest = app.label("contact")
    headers = HttpReqHeaders("",dest,"","")
    req =  "POST " + action + "?DEST=" + member + " HTTP/1.1" + "\r\n" + headers + "\r\n"
    client_socket.send(req.encode("utf-8"))

def recvMessage(client_socket,app): #recv messages from the server

    while 1:
        # recv the message-can be a filename or a text
        dataFserver = client_socket.recv(10000000).decode('utf-8')
        print(f"message recv from server: {dataFserver}")
        # adds the messsage to the gui
        if dataFserver!="":
            addMtoGui(app,dataFserver,client_socket)


def NormalReqHeaders(dest):  #gets the normal headers like name of sender and who to send to
    global MyUsername
    global KeySent
    headers = "USER:" + MyUsername +"\r\n"
    headers +="DEST:"+ dest +"\r\n"
    if dest.count("-")==0: #if its not a group,adding the public key
        if KeySent == False:
            #creating a byte string from the pubic key object
            pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pubK = pem.decode('utf-8') #public_key is a byte string we need it in a string
            KeySent = True
        else:
            pubK = "*"
    else: #if its a group
        pubK = "*"
    headers+="PUBLICKEY:"+pubK+"\r\n"
    headers+="\r\n"
    return headers


def HttpReqHeaders(message, dest, fileName, encryption):
    '''sets the headers for http request'''
    headers = ""
    headers += "Dest: " + dest + "\r\n"
    if message == "": # its a file
        if fileName != "": #checks it its a file
            headers += "File_Length: " + str(os.path.getsize(fileName)) + "\r\n"

    # the name of the server used to implement protocols
    headers += "Origin: " + "http://www.janeAserver.com" + "\r\n"
    # the typical user-agent of google Chrome
    headers += "User-Agent: " + "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " \
                                "(KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" + "\r\n"
    headers += "USER: " + MyUsername + "\r\n"
    if message == "": # checks if its a file or an admin action
        if fileName != "": # its a file
            headers += "File-type: " + "'application/octet-stream'" + "\r\n"
    headers += "Encryption: " + encryption + "\r\n"
    # returns all the headers for an HTTP request
    return headers


def getHttpsHeaders(dest,encryptType,keyA,keyB):
    '''the func gets the encrypted message and the dest and sets the headers
    '''
    headers = ""
    headers ="DEST:"+dest+"\r\n" #can be a group or a name
    headers+= "USER-NAME:"+MyUsername +"\r\n"
    headers+="content-type:" + "'text/plain'"+"\r\n"
    headers+="Encryption: " + encryptType + "\r\n" #the encrypthion type-rsa/affine_cipher
    if keyA != 0:
        headers +="Keys:"+ str(keyA) +","+ str(keyB) +"\r\n" #if affine than adding the keys
    else:
        headers += "Keys:*"+"\r\n"
    return headers


def sendPostHttp(client_socket,dest,app,filename):
    ''''sends a POST HTTP request and calls a function that adds the message to the gui'''
    message = app.entry("message")
    # if a pic/recording post request
    if message =="":
            fileFolder = r""
            fileRoot = filename
            foldersToFile = str(fileRoot).split("/")
            # gets onlt the file name by getting the last section of the file root
            file_name = foldersToFile[len(foldersToFile) - 1]
            foldersToFile.remove(file_name) #removes the name of the file from the list root file

            for folder in foldersToFile : #maybe join???
                fileFolder += folder + "/"
            # open to read the file
            filedata = open(fileRoot, "rb")
            # saves the filedata
            filedata = filedata.read(os.path.getsize(fileRoot))
            # encoding to base64->str
            filedata=base64.b64encode(filedata).decode('utf-8')

            encryption = "" #in this case there's no encryption. therefor its empty
            headers = HttpReqHeaders(message, dest, fileRoot, encryption) #gets the headers to drae the http req

            HttpReq = f"POST {fileFolder}?file-name={file_name} HTTP/1.1\r\n{headers}\r\n{filedata}"
            #HttpReq = "POST " + fileFolder + "?file-name=" + file_name + " HTTP/1.1" + "\r\n" + headers + "\r\n" + filedata.decode("utf-8")
            client_socket.send(HttpReq.encode("utf-8"))
            if dest.count("-")==0:
                #adds the message to the gui,sends the name of the file and the name of the sender
                addMtoGui(app, "HTTP dest: " + MyUsername + ":" + " file:" + fileFolder + file_name + " content:", client_socket)#content empty because its a file,no text

def getKey(dest):
    '''the func returns a key'''
    keyA = 0
    for char in dest:
        keyA += ord(char)
    return keyA

def egcd(a, b): #return g-the gcd of a,b and x,y that make: ax+by=gcd(a,b)
   if a == 0:
       return b, 0, 1
   g, y, x = egcd(b % a, a)
   return g, x - (b//a) * y, y

def module_inverse(keyA, mode):
    '''gets the module inverse num of keyA-for the affine to work'''
    g, x, y = egcd(keyA, mode) #gets the pair of numbers that age the key and its inversive and if there is an inverse
    if g != 1:
        return False, 0
    return True, x % mode


def affine_cipher(message,keyA,keyB,encrypt = True):
    '''encrypting/decrypting a message by affine_cipher encryption'''
    keyA %= 26
    keyB %= 26
    # getting the modulare inverse of the keyA
    isinverse, inveskey = module_inverse(keyA, 26)
    mess = ""
    while not isinverse:
        # not every num has a modular inverse, so if the current num doesnt,adding the key by one.
        # if its larger than 26 than it does module 26 of the number.
        keyA %= 26
        keyA += 1
        # again,callinf the function that finds the module inverse of the specified number for us to be able to decrypt
        isinverse, inveskey = module_inverse(keyA, 26)
    if encrypt==False:
        #if we decrypt than change the key to the inversive
        keyA = inveskey
    for i in range(len(message)):
        char = message[i]
        #if char is a letter
        if 64<ord(char)<123:
            if char.isupper():
                if encrypt:
                    #if we encoding
                    mess += chr((ord(char) * keyA + keyB - 65) % 26 + 65)
                else:
                    #if decoding
                    mess += chr(((ord(char) - keyB) * keyA - 65) % 26 + 65)

            else: #if lower case
                if encrypt:
                    mess += chr((ord(char) * keyA + keyB - 97) % 26 + 97)
                else:
                    mess += chr(((ord(char) - keyB) * keyA - 97) % 26 + 97)
        else:
            # not a letter
            mess += char
    return mess


def sendM(event,app,client_socket):
    print("###################################")
    print("entered to sendM")
    option = app.optionBox("Options")
    print("choosen option:"+ option)
    message = app.entry("message") #gets input from the user
    #message = message.encode("utf-8")
    dest= app.label("contact")


    print("dest:"+dest)

    if option == "normal":
        headers = NormalReqHeaders(dest)
        request = (headers + message).encode("utf-8")
        # sends the server the message with headers
        client_socket.send(request)
        data = MyUsername +":" +message+"PUBLICKEY:*"
        #if not a gruop chat
        if dest.count("-")==0:
            # printing the message to the gui
            addMtoGui(app,data,client_socket)
        print("message sent")

    if option == "HTTP":  #TODO:ADD TEXT HTTP OPTION
        # if a pic request
        if message =="":
            app.entry("message","",callFunction=True) #TODO:callfunction doesnt work,why?
            #getting the file, using tkinter
            root = Tk()
            root.filename = filedialog.askopenfilename(initialdir="/", title="Select file",filetypes=(("jpeg files", "*.jpg"), ("all files", "*.*")))
            #callinf a finction that sends the file to the server
            filename= root.filename
            sendPostHttp(client_socket,dest,app,filename)
    #rsa encrypted text messages
    if option == "HTTPS":
        contact = app.label("contact")
        message = app.entry("message")
        if contact.count("-")>0:
            encryptType = "Affine_cipher"
            dest = app.label("contact")
            #get the first key by coverting the name of the group into a number
            keyA=getKey(dest)
            keyB = keyA+1 #b can be any number
            message = MyUsername + ":" + message
            encrypted = affine_cipher(message,keyA,keyB,encrypt = True) #ecnrypting the message
            headers = getHttpsHeaders(dest,encryptType,keyA,keyB)
            req = f"HTTPS http://www.janeAserver.com\r\n{headers}\r\n{encrypted}"
            req = req.encode("utf-8")
            client_socket.send(req)
            print("encrypted mess sent")

        #not a group
        else:
            encryptType="RSA"
            #ecrypting the message
            message = MyUsername+":"+message
            data = message+"PUBLICKEY:*"
            addMtoGui(app,data,client_socket)#going to add the message to the gui like a normal message
            message = message.encode('utf-8') #the encryption works on byte strings
            Dpublic_key = getDestKey(app)
            encrypted = Dpublic_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            #encrypted = encrypted.decode('utf-8').strip() #converting from byte to string
            encrypted = str(base64.b64encode(encrypted), encoding='utf-8')
            headers = getHttpsHeaders(dest,encryptType,0,0)
            req = f"HTTPS http://www.janeAserver.com\r\n{headers}\r\n{encrypted}"
            req = req.encode("utf-8")
            client_socket.send(req)
            print("encrypted mess sent")


def getFolder(dest): #TODO:GO THROUGH THE FUNC AGAIN
    '''the func creates a new folder for each user and dest(session).
    if already exists,saves the recording there'''
    if os.path.exists('./' + MyUsername + '/'):
        # checks if theres a folder ,inside the folder called username, with the dest's name
        if os.path.exists('./' + MyUsername + '/' + dest + "/"):
            # returning the folders name
            return f"{MyUsername}/{dest}/"
        else:
            # if there is a folder called username but not a folder with the dest name inside
            try:
                # trying to make the new folder
                folder = f"{MyUsername}/{dest}/"
                os.mkdir(folder)
            except OSError as e:
                # if it failed
                print (e)
                return 0
    else:
        # if there's no folder called username
        try:
            # trying to make folder called the username and inside it a folder with the destanation's name
            folder = MyUsername + '/'
            os.mkdir(folder)
            folder += dest + "/"
            os.mkdir(folder)
        except OSError as e:
            #prints error
            print(e)
            return 0
        # returning the correct folder name/names
    return folder


def startRecording(dest):
    chunk = 1024  # Record in chunks of 1024 samples
    sample_format = pyaudio.paInt16  # 16 bits per sample
    channels = 2
    fs = 44100  # Record at 44100 samples per second
    seconds = 3
    global X
    filename = f"rec{X+1}.wav"
    folder = getFolder(dest)
    filename = folder+filename

    p = pyaudio.PyAudio()  # Create an interface to PortAudio

    print('Recording')

    stream = p.open(format=sample_format,
                    channels=channels,
                    rate=fs,
                    frames_per_buffer=chunk,
                    input=True)

    frames = []  # Initialize array to store frames

    # Store data in chunks for 3 seconds
    for i in range(0, int(fs / chunk * seconds)):
        data = stream.read(chunk)
        frames.append(data)

    # Stop and close the stream
    stream.stop_stream()
    stream.close()
    # Terminate the PortAudio interface
    p.terminate()

    print('Finished recording')

    # Save the recorded data as a WAV file
    wf = wave.open(filename, 'wb')
    wf.setnchannels(channels)
    wf.setsampwidth(p.get_sample_size(sample_format))
    wf.setframerate(fs)
    wf.writeframes(b''.join(frames))
    wf.close()

    return filename  #returns the location of the file


def sendRecording(event,app,client_socket):
    '''the function takes care of sending the recording.
    gets the recording itself, saves it to a specific filder of the username that sends it and its destination'''
    dest = app.label("contact")
    fileName = startRecording(dest) #gets the recording and where its saved,calss a func that does so
    #make sure its an http
    option = app.optionBox("Options")
    if option == "HTTP":
        sendPostHttp(client_socket,dest,app,fileName)
        #if not a group
        if dest.count("-")==0:
            #adds the recording to the gui
            addMtoGui(app,"HTTP dest :"+MyUsername+":"+fileName+"content:",client_socket)

def guiBuild(app,client_socket): #builds the user's interface
    #ADD:an error page!!

    app.startFrameStack("Pages")  #starting frameStack with all the frames being used

    app.startFrame()  # second frame-chat frame(the main frame/user interface)

    app.setBg('pink')
    app.setFg('white', override=False)
    app.label("contact"," ",bg="pink",font=12)
    app.entry("message", label=True ,focus = True)
    app.optionBox("Options", ["- sending method -", "normal", "HTTP","HTTPS"])
    app.addButtons(["send"],[lambda event:sendM(event,app, client_socket)])
    app.addButtons(["record"],[lambda event:sendRecording(event,app,client_socket)])

    app.stopFrame()

    app.startFrame()  # first frame-username entry

    app.setBg("pink")
    app.setFg("white")
    app.entry("Contact",label = True , focus = True)
    app.setFont(10)
    app.addButtons(["enter app", "exit app"], [lambda event:enterApp(event,app), app.stop])

    app.stopFrame()

    app.stopFrameStack()



def main():
    client_socket = socket.socket()  #creating a new client
    client_socket.connect((IP,PORT))

    # creating the gui
    app = gui("FRAME STACK", "300x400", bg="pink", font=12)
    # calls the function that builds the user's interface
    guiBuild(app,client_socket)
    print("starting")
    # function sends the clients name +headers
    start(client_socket)

    # thread that calls func that is waiting to recv messages from server
    _thread.start_new_thread(recvMessage, (client_socket,app))
    app.go()


if __name__ == "__main__":
    main()  #calls the main function