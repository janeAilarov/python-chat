from appJar import gui
f= True

def press(button):
    #if button == "exit chat" app.
    if button =="enter app":

        app.prevFrame("Pages")
        user = app.getEntry("Username")
        app.label("hello-"+user)


def send(button):
    messa = app.getEntry("message")
    app.label("mess", messa)

def exit():
    f = False
    app.label("bye")

app = gui("FRAME STACK", "300x400", bg= "pink",font = 12)
app.startFrameStack("Pages")


app.startFrame() #second frame-chat frame


app.entry("message")
app.button("send",send)
app.button("exit",exit)

app.stopFrame()

app.startFrame() #first frame-username

app.addLabelEntry("Username")
app.setFont(10)
app.addButtons(["enter app","exit app"],press)

app.stopFrame()



app.stopFrameStack()


app.go()


