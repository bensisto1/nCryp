from flask import Flask, render_template, url_for, request, redirect, session, flash, jsonify
from pymongo import MongoClient
import threading
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import struct
import re
from datetime import datetime
from bson.json_util import dumps
import time


app = Flask(__name__)
app.config['SECRET_KEY']="testkey123"
socket = SocketIO(app)

client = MongoClient('localhost', 27017)




# database
db = client.flask_database
# collections
globalChat = db.globalChat
chat = db.chat
users = db.users
contacts = db.contacts
groups = db.groups
groupMessages = db.groupMessages
contact_requests = db.contact_requests

# Store user sessions for private messaging
user_sessions = {}

def get_current_user(username):
    if username:
        user = users.find_one({"username": username})
        print(user)
        return user
    return None


#SHA256 Password Hashing Algorithm
def right_rotate(value, amount):
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

def sha256(message):
    # padding
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    
    while (len(message) * 8 + 64) % 512 != 0:
        message += b'\x00'
    
    message += struct.pack('>Q', original_bit_len)

    # constants
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19b4c16f, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # hash values
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
    #loop over text in chunks of 64 bytes
    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]
        w = [0] * 64
        # fill in the first 16 words of the message schedule 'w'
        for j in range(16):
            w[j] = struct.unpack('>I', chunk[j * 4:j * 4 + 4])[0]
        # generate the remaining words using message schedule formula
        for j in range(16, 64):
            s0 = right_rotate(w[j - 15], 7) ^ right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = right_rotate(w[j - 2], 17) ^ right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10)
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF
        # initialize working variables from current hash state 'h' (h0-h7)
        a, b, c, d, e, f, g, h0 = h
        # perform main loop for 64 rounds of SHA-256 processing
        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h0 + S1 + ch + k[j] + w[j]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            # update working variables based on computed values
            h0 = (g + temp1) & 0xFFFFFFFF
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        # after 64 rounds update the hash state by adding the working variables a,b,c,d,e,f,g,h
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h0])]
    # finally, return hash as a concatenated byte string of the hash state 'h'
    return b''.join(struct.pack('>I', i) for i in h)

@app.route("/")
def index():
    print("Current session user:", session.get('user'))
    messages = globalChat.find()
    current_user = session.get('user')
    user_data = users.find_one({"username": current_user})
    contacts = user_data.get('contacts', []) if user_data else []
    return render_template("index.html", messages=messages, users=contacts)

@app.route("/privatechat")
def privatechat():
    return render_template("privatechat.html")  

@app.route("/create_account", methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if len(username) < 3 or not re.match(r'^[a-zA-Z0-9]+$', username):
            flash("Username must be at least 3 characters long and can only contain letters and numbers.")
            return redirect(url_for('create_account'))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return redirect(url_for('create_account'))
        
        # Generate salt and hash the password
        salt = os.urandom(16).hex()  # generate salt
        hashed_pw = sha256((salt + password).encode('utf-8')).hexdigest()  # Hash password w/ salt
        
        # Insert into database
        users.insert_one({'username': username, 'password': hashed_pw, 'salt': salt})
        flash("Account created successfully!")
        return redirect(url_for('login'))

    return render_template("create_account.html")

@socket.on('login')
def handle_login(credentials):
    username = credentials['username']
    password = credentials['password']

    # Check if the user exists
    user = users.find_one({"username": username})
    if user:
        salt = user['salt']
        hashed_pw = sha256((salt + password).encode('utf-8'))

        if hashed_pw == user['password']:
            session['user'] = username
            contacts = user.get('contacts', [])
            emit('update_session', {'username': username, 'contacts': contacts}, room=request.sid)
            emit('receive_login', {'message': 'Login successful!', 'success': True}, room=request.sid)
            return

    emit('receive_login', {'message': 'Invalid username or password', 'success': False}, room=request.sid)

@socket.on('send_message')
def handlemsg(msg):
    #save the message to chat database
    globalChat.insert_one({'content': msg})
    #sends message
    emit('receive_message', msg, broadcast=True)

@socket.on('send_private_message')
def handle_send_private_message(message_data):
    sender = message_data['sender']
    receiver = message_data['receiver']
    content = message_data['content']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Save the message in the database
    chat.insert_one({
        'sender': sender,
        'receiver': receiver,
        'content': content,
        'timestamp': timestamp
    })
    message_data['timestamp'] = timestamp
    emit('receive_message', message_data, room=request.sid)
def poll_for_new_messages(sender, receiver):
    def poll():
        last_checked = time.time()
        while True:
            try:
                # Query MongoDB for messages after the last checked time
                new_messages = chat.find({
                    'timestamp': {'$gt': last_checked},
                    'sender': sender,
                    'receiver': receiver
                })

                new_messages_list = list(new_messages)
                if new_messages_list:
                    for message in new_messages_list:
                        print(f"Emitting message: {message}")
                        emit('receive_message', message, broadcast=False)

                    # Update the last checked timestamp to the latest message timestamp
                    last_checked = new_messages_list[-1]['timestamp']
                
                time.sleep(1)  # Sleep for 1 second before polling again
            except Exception as e:
                print(f"Error polling MongoDB: {e}")
                break

    # Start the polling in a separate thread
    threading.Thread(target=poll, daemon=True).start()




@socket.on('send_group_message')
def handle_send_group_message(groupMessageData):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Prepare the message data
    message_data = {
        'sender': groupMessageData['sender'],  # Access 'sender' from the dictionary
        'content': groupMessageData['content'],  # Access 'content' from the dictionary
        'timestamp': timestamp,
    }
    # Add the user fields dynamically from the groupMessageData
    for i in range(1, 11):  # Loop from user1 to user10
        user_key = f'user{i}'
        if user_key in groupMessageData:
            message_data[user_key] = groupMessageData[user_key]
    # Insert into database
    groupMessages.insert_one(message_data)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash("Username and password cannot be empty.")
            return render_template("login.html")

        user = users.find_one({"username": username})
        if user:
            salt = user['salt']
            hashed_pw = sha256((salt + password).encode('utf-8'))
            if hashed_pw == user['password']:
                session['user'] = username
                flash("Login successful!")
                socket.emit('update_session', {'username': username})
                return redirect(url_for('index'))
        
        flash("Invalid username or password")

    return render_template("login.html")



@app.route("/logout", methods=['POST'])
def logout():
    session.pop('user', None)
    flash("You have been logged out.")
    return '', 204



@socket.on('create')
def handle_create(credentials):
    username = credentials['username']
    password = credentials['password']
    publicKey = credentials['publicKey']
    privateKey = credentials['publicKey']
    
    if users.find_one({"username": username}):
        emit('receive_create', {'message': 'Username already exists.', 'success': False})
        return
    
    salt = os.urandom(16).hex()
    hashed_pw = sha256((salt + password).encode('utf-8'))

    users.insert_one({'username': username, 'password': hashed_pw, 'salt': salt, 'publicKey': publicKey, 'privateKey': privateKey})
    emit('receive_create', {'message': 'Account created successfully!', 'success': True})

from datetime import datetime

@socket.on('get_messages')
def handle_get_messages(contact_username, username):
    # Get messages between the two users
    messages = chat.find({
        "$or": [
            {"sender": username, "receiver": contact_username},
            {"sender": contact_username, "receiver": username}
        ]
    })

    # Prepare the messages in the desired format
    formatted_messages = [
        {
            "sender": message['sender'],
            "content": message['content'],
            "timestamp": message['timestamp'] if 'timestamp' in message else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        for message in messages
    ]

    # Send the messages to the client
    emit('receive_messages', {'messages': formatted_messages}, room=request.sid)


#---------------------------------------------------Groups Functionality---------------------------------------
@socket.on('create_group')
def handle_create_group(names, currentuser):
    users = {'user1': currentuser}
    
    for i, name in enumerate(names):
        if i < 9:  # Ensure we don't exceed user10
            users[f'user{i+2}'] = name
    
    new_group = {f'user{i+1}': users.get(f'user{i+1}') for i in range(len(users))}
    groups.insert_one(new_group)
    emit('group_created', {'message': 'Group created successfully!', 'group': users})


@socket.on('add_user_to_group')
def handle_add_user_to_group(user_username, user1):
    current_user = get_current_user(user1)
    if not current_user:
        emit('receive_add_user_to_group', {'message': 'User is not logged in.', 'success': False})
        return 
    if user_username == user1:
        emit('receive_add_user_to_group', {'message': 'You cannot add yourself to a group.', 'success': False})
        return
    contact = users.find_one({"username": user_username})
    if not contact:
        emit('receive_add_user_to_group', {'message': 'Contact does not exist.', 'success': False})
        return
    
    
    emit('receive_add_user_to_group', {'message': 'Added', 'success': True})

from bson import ObjectId

@socket.on('get_group_messages')
def handle_get_group_messages(group):
    group_query = {}
    for i in range(len(group)):
        group_query[f"user{i+1}"] = group[i]
    
    # find and format the messages
    messages = groupMessages.find(group_query)
    formatted_messages = [
        {
            "sender": message['sender'],
            "content": message['content'],
            "timestamp": message['timestamp'] if 'timestamp' in message else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        for message in messages
    ]
    
    # Emit the formatted messages
    emit('receive_group_messages', formatted_messages)








    



#------------------------------------------------Contacts Functionality-------------------------------------------------------------------------------
@socket.on('add_contact')
def handle_add_contact(contact_username, user1):
    current_user = get_current_user(user1)
    
    if not current_user:
        emit('receive_add_contact', {'message': 'User is not logged in.', 'success': False})
        return 

    # A user cannot add themself
    if contact_username == user1:
        emit('receive_add_contact', {'message': 'You cannot add yourself as a contact.', 'success': False})
        return

    # Check if the contact exists
    contact = users.find_one({"username": contact_username})
    if not contact:
        emit('receive_add_contact', {'message': 'Contact does not exist.', 'success': False})
        return

    existing_contact = contacts.find_one({"$or": [{"user1": user1, "user2": contact_username}, {"user1": contact_username, "user2": user1}]})
    if existing_contact:
        emit('receive_add_contact', {'message': 'Contact is already in your list.', 'success': False})
        return

    existing_request = contact_requests.find_one({"requester": user1, "requested": contact_username, "status": "pending"})
    if existing_request:
        emit('receive_add_contact', {'message': 'Contact request already pending.', 'success': False})
        return
    
    contact_requests.insert_one({"requester": user1, "requested": contact_username, "status": "pending"})
    
    emit('receive_add_contact', {'message': 'Contact request sent successfully.', 'success': True})





@socket.on('get_contact_requests')
def handle_get_contact_requests(username):
    pending_requests = contact_requests.find({"requested": username, "status": "pending"})
    requests = [{"requester": request['requester']} for request in pending_requests]
    emit('receive_contact_requests', {'requests': requests}, room=request.sid)

@socket.on('respond_contact_request')
def handle_contact_request_response(data):
    response = data['response']
    requester = data['requester']
    requested = data['requested']

    # Get the contact request
    contact_request = contact_requests.find_one({"requester": requester, "requested": requested, "status": "pending"})
    
    if not contact_request:
        emit('receive_contact_request_response', {'message': 'No pending request found.', 'success': False})
        return

    if response == 'accept':
        contact_requests.update_one(
            {"requester": requester, "requested": requested, "status": "pending"},
            {"$set": {"status": "accepted"}}
        )

        # Add the users to each other's contacts
        contacts.insert_one({"user1": requester, "user2": requested})
        contacts.insert_one({"user1": requested, "user2": requester})

        emit('receive_contact_request_response', {'message': 'Contact request accepted.', 'success': True, 'requester': requester})
        
    elif response == 'reject':
        contact_requests.update_one(
            {"requester": requester, "requested": requested, "status": "pending"},
            {"$set": {"status": "rejected"}}
        )

        emit('receive_contact_request_response', {'message': 'Contact request rejected.', 'success': True, 'requester': requester})
@socket.on('get_contacts')
def handle_get_contacts(username):
    user = users.find_one({"username": username})
    if user:
        user_contacts = contacts.find({
            "$or": [{"user1": username}, {"user2": username}, {"user3": username}, {"user4": username}, {"user5": username}, {"user6": username},{"user7": username}, {"user8": username}, {"user9": username}, {"user10": username}]
        })
        
        # Prepare a list of contact usernames
        contacts_list = []
        for contact in user_contacts:
            # Add the contact from the opposite user (either user1 or user2)
            if contact['user1'] == username:
                contacts_list.append(contact['user2'])
            else:
                contacts_list.append(contact['user1'])
        
        # Send contacts to the client
        emit('receive_contacts', {'contacts': contacts_list}, room=request.sid)
    else:
        emit('receive_contacts', {'contacts': []}, room=request.sid)
    
@socket.on('get_groups')
def handle_get_groups(username):
    user = users.find_one({"username": username})
    if user:
        user_groups = groups.find({
            "$or": [{"user1": username}, {"user2": username}, {"user3": username}, {"user4": username}, {"user5": username}, {"user6": username},{"user7": username}, {"user8": username}, {"user9": username}, {"user10": username}]
        })
        # Prepare a list of groups
        groups_list = []
        for group in user_groups:
                group_members = []
                for i in range(1, 11):
                    user_key = f"user{i}"
                    if group.get(user_key):
                        group_members.append(group[user_key])

                groups_list.append(group_members)

        emit('receive_groups', {'groups': groups_list}, room=request.sid)
        
    else:
        emit('receive_groups', {'groups': []}, room=request.sid)
   
if __name__ == "__main__":
    socket.run(app, debug=True)
