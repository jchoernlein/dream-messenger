# Double-Ratchet End-to-End Asynchronous Messenger
A cross-platform client-server messaging app which implements double-ratchet 
encryption similar to Signal or WhatsApp. The client runs with Python within
a Terminal User Interface.

To run, first install the necessary dependencies outlined in the 
`requirements.txt` file. Then, use Docker to run the necessary components of
the server. Finally, either run the test suite by using the command
`python dream/test.py` or use the client as defined below:

User information is stored in SQLite database files in the current working
directory. To register a user on the server with the client, run the command
`python dream/client.py register {username}`. Then, to message another user,
use the command `python dream/client.py message {recipient} --user {username}`
You must specify your username in the command, since multiple SQLite files
can be in any given directory. To send messages, type in the message box at 
the bottom of the screen, and hit ENTER when ready to send. You can scroll up
and down in the conversation using the scrollbar on the right side of the 
screen. To exit, press CTRL-Q.

To best demonstrate, it is recommended to register two users, Alice and Bob,
and open conversations with eachother in two seperate terminal windows.