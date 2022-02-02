#importing required modules and setting needed variables
# all exit codes for modules will use integers unless needed
from Crypto.Cipher import AES
import json
from Crypto.Protocol.KDF import PBKDF2
from getpass import getuser
import PySimpleGUI as sg
import hashlib as hash
import os
import datetime as dt
import time
import gc
gc.enable()
LAYOUT_CYCLE_VAR = 0; logged_in = False; count = 0; alert = 0


# added a guard clause function
def guard_Clause(Filename=str or None, decrypting=bool) -> int:
    """
    A function to check for various file errors.
    code of 0: No errors detected.
    error code of 1: path of file is None. Cancelled encrypt/decrypt cycle.
    error code of 2: The program does not have the permission to access the file. 
    error code of 3: The file path is NOT a correct path.
    error code of 4: File is hidden. Avoiding encryption so you don't accidently break another program.
    error code of 5: A file encryption marker was detected during encryption.
    error code of 6: during decryption, file encryption marker was not detected.
    """
    # checking if file encryption was cancelled
    if Filename is None:
        return 1
        # checking for Permission errors and seeing if the given file path is usable
    try:
        with open(Filename, "rb") as file:
            magic = file.read(14)
    except PermissionError:
        return 2 
    except FileNotFoundError:
        return 3
    if "/." in Filename:
        return 4
    # checking if there is a file encryption signature.
    # if there is and decrypting, return 0
    if magic == b"E1m%nj2i$bhilj" and decrypting is True:
        return 0
    # if there is one and encrypting, return 5
    if magic == b"E1m%nj2i$bhilj" and decrypting is False:
        return 5
    # if there is not one and encrypting, return 0
    if magic != b"E1m%nj2i$bhilj" and decrypting is False:
        return 0
    # if there is not one and decrypting, return 6
    if magic != b"E1m%nj2i$bhilj" and decrypting is True:
        return 6
    pass


# added a logger for modules to use
def add_log(mode=str, username=str, file_name=str, encrypted=bool) -> int:
    # guard clause
    if mode is None or username is None or file_name is None:
        return 1
    # once again using s for singular, f for folder, v for vault, c for changed password
    time_ = str(dt.datetime.utcnow())
    try:
        #using the same template for different options
        if mode == "s":
            with open("/home/{}/Revenant/userLog.txt".format(username) ,'a') as file:
                # formatting for either encryption/decryption
                if encrypted is True:
                    string = "encrypted"
                elif encrypted is False:
                    string = "decrypted"
                # writing
                file.write("Singular: File: {} was: {} at: {} UTC.\n".format(file_name, string, time_))
            return 0
        elif mode == "f":
            with open("/home/{}/Revenant/userLog.txt".format(username) ,'a') as file:
                # formatting
                if encrypted is True:
                    string = "encrypted"
                elif encrypted is False:
                    string = "decrypted"
                # writing
                file.write("Folder: Folder: {} was: {} at: {} UTC.\n".format(file_name, string, time_))
            return 0
        elif mode == "v":
            with open("/home/{}/Revenant/userLog.txt".format(username) ,'a') as file:
                # formatting
                if encrypted is True:
                    string = "encrypted"
                elif encrypted is False:
                    string = "decrypted"
                # writing
                file.write("Vault: Vault was: {} at: {} UTC.\n".format(string, time))
            return 0
        elif mode == "c":
            # logging password changes
            with open("/home/{}/Revenant/userLog.txt".format(username) ,'a') as file:
                file.write("Password: password was changed at: {} UTC.\n".format(time_))
            return 0
    except FileNotFoundError:
        # handling exception if UserLog file is deleted
        sg.popup_error("The UserLog file could not be found.\nRebuilding of the UserLog file will commence after this popup is closed.", font="Helvetica")
        file = open("/home/{}/Revenant/userLog.txt".format(username), "w+")
        file.write("userLog recreated due to FileNotFoundError.\n")
        file.close()
        # sleep so it feels like it did something
        time.sleep(2)
        sg.popup_auto_close("Rebuild complete.", font="Helvetica", non_blocking=True)
        return 1


# Making a random hash creation module
def rand_hash() -> str:
    rand_bytes = os.urandom(32)
    rand_hash = hash.sha256(rand_bytes)
    return_value = rand_hash.hexdigest()
    return return_value


# creating an encrypting function to encrypt files. Will be used by other functions to save space.
def encrypt_file_function(key=bytes, salt=bytes, file_name=str, username=str, single=bool) -> int:
    """
    encryption function.
    code of 0: No errors detected.
    error code of 1: path of file is None. Cancelled encrypt/decrypt cycle.
    error code of 2: The program does not have the permission to access the file. 
    error code of 3: The file path is NOT a correct path.
    error code of 4: File is hidden. Avoiding encryption so you don't accidently break another program.
    error code of 5: A file encryption marker was detected during encryption.
    error code of 6: Cannot occur; decryption only.
    """
    # guard clause
    exit_code = guard_Clause(file_name, decrypting=False)
    if exit_code != 0:
        return exit_code
    # setting the encrypted file marker.
    magic = b'E1m%nj2i$bhilj'; intialization_vector = os.urandom(16)
    # opening the file to grab data
    with open (file_name, 'rb') as file:
        data = file.read()
    # making a cipher and encrypting the data
    cipher = AES.new(key, AES.MODE_CFB, iv=intialization_vector); ciphered_data = cipher.encrypt(data)
    # getting key sig
    hash_key = hash.sha256(key); key_signature = hash_key.digest()
    # writing needed info
    with open (file_name, 'wb') as file:
        file.write(magic)
        file.write(intialization_vector)
        file.write(salt)
        file.write(key_signature)
        file.write(ciphered_data)
    # logging
    if single == True:
        add_log('s', username, file_name, encrypted=True)
    return 0


# creating the decrypting function. similar to the encrypting function, with a few changes for decrypting
def decrypt_file_function(password=str, file_name=str, username=str, single=bool) -> int:
    """
    decryption function.
    code of 0: No errors detected.
    error code of 1: Path of file is None. Cancelled encrypt/decrypt cycle.
    error code of 2: The program does not have the permission to access the file. 
    error code of 3: The file path is NOT a correct path.
    error code of 4: Cannot occur; encryption only.
    error code of 5: Cannot occur; encryption only.
    error code of 6: During decryption, file encryption marker was not detected.
    error code of 7: Decryption key signature and and key signature of file do not match; files were encrypted with different keys.
    """
    # guard clause
    exit_code = guard_Clause(file_name, decrypting=True)
    if exit_code != 0:
        return exit_code
    # opening the file to grab required data
    with open (file_name, 'rb') as file:
        file.read(14)
        iv = file.read(16)
        salt = file.read(16)
        key_signature = file.read(32)
        ciphered_data = file.read() 
    # creating the key and cipher, and checking the key signature
    key = PBKDF2(password, salt, dkLen=32); hashed_signature = hash.sha256(key); given_key_signature = hashed_signature.digest()
    if given_key_signature != key_signature:
        return 7
    # creating a cipher and decrypting the data
    cipher = AES.new(key, AES.MODE_CFB, iv=iv); original_data = cipher.decrypt(ciphered_data)
    # writing the data
    with open (file_name, 'wb') as file:
        file.write(original_data)
    # logging
    if single == True:
        add_log("s", username, file_name, encrypted=False)
    return 0


# creating the encryption module for the Vault folder. This feature is to speed up encryption/decryption cycles when I want my files
def Vault_encrypt(password=str, username=str) -> int:
    """
    encryption function for prenamed folder.
    code of 0: No errors detected.
    error code of 1: Folder was not detected and was rebuilt.
    """
    # looping through the sub directories and files with os.walk. Wrapped in try/except block in case Vault is deleted.
    try:
        file_name = "/home/{}/Vault/".format(username)
        for root, dirs, files in os.walk(file_name):
            for file in files:
                # creating needed variables
                salt = os.urandom(16); key = PBKDF2(password, salt, dkLen=32); path_of_file = os.path.join(root, file)
                # calling encrypt function
                encrypt_file_function(key, salt, path_of_file, username, single=False)
        add_log("v", username, file_name, encrypted=True)
        return 0
    except FileNotFoundError:
        sg.popup_error("Vault folder was not found.\nRebuilding will commence after the closing of this popup.", font="Helvetica")
        try:
            os.mkdir("/home/{}/Vault".format(username))
            os.mkdir("/home/{}/Vault/Images/".format(username))
            os.mkdir("/home/{}/Vault/Text Files/".format(username))
            os.mkdir("/home/{}/Vault/Other/".format(username))
            time.sleep(2)
            sg.popup_auto_close("Rebuild complete; Vault folder returned to install default.", font="Helvetica", non_blocking=True)
            return 1
        except FileExistsError:
            pass


# creating vault decrypt function
def Vault_decrypt(password=str, username=str) -> int:
    """
    decryption function for prenamed folder.
    code of 0: No errors detected.
    error code of 1: Path of folder was not detected; folder was rebuilt
    error code of 2: Decryption key signature and and key signature of file do not match; files were encrypted with different keys.
    """
    # looping through files
    key_sig_disparity = False; code = 0
    try:
        file_name = "/home/{}Vault/".format(username)
        for root, dirs, files in os.walk(file_name):
            for file in files:
                path_of_file = os.path.join(root, file)
                # passing over info. doing it like this instead of encryption module so that file error won't kill the decrypt
                exit_code = decrypt_file_function(password, path_of_file, username, single=False)
                if exit_code == 3:
                    key_sig_disparity = True
                # else statement to ensure continuity
                else:
                    continue
        # logging
        add_log("v", username, file_name, encrypted=False)
        if key_sig_disparity is True:
            return 2
    except FileNotFoundError:
        sg.popup_error("Vault folder was not found.\nRebuilding will commence after the closing of this popup.", font="Helvetica")
        try:
            os.mkdir("/home/{}/Vault/Images".format(username))
            os.mkdir("/home/{}/Vault/Text Files".format(username))
            os.mkdir("/home/{}/Vault/Other".format(username))
            time.sleep(2)
            sg.popup_auto_close("Rebuild complete; Vault folder returned to install default.", font="Helvetica", non_blocking=True)
            return 1
        except FileExistsError:
            pass


# creating a folder encryption module
def folder_encryption_function(password=str, filename=str, username=str) -> int:
    """
    encryption function for prenamed folder.
    code of 0: No errors detected.
    error code of 1: Path of folder was None. Encryption was cancelled.
    error code of 2: Path given was not valid.
    """
    # error checking to see if path was inputted wrong or encryption was cancelled.
    if filename is None:
        return 1
    if os.path.exists(filename) is False:
        return 2
    # looping through files
    for root, dirs, files in os.walk(filename):
        for file in files:
            # creating needed variables
            salt = os.urandom(16); key = PBKDF2(password, salt, dkLen=32); path_of_file = os.path.join(root, file)
            # encrypting
            encrypt_file_function(key, salt, path_of_file, username, single=False)
    add_log("f", username, filename, encrypted=True)
    return 0


# making the folder decryption module
def folder_decryption_function(password=str, filename=str, username=str) -> int:
    """
    decryption function for folders.
    code of 0: No errors detected.
    error code of 1: Path of folder was None. decryption cancelled
    error code of 2: Path of folder was not valid.
    error code of 3: Decryption key signature and and key signature of one or more files do not match; files were encrypted with different keys.
    """
    key_sig_disparity = False
    if filename is None:
        return 1
    if os.path.exists(filename) is False:
        return 2
    #looping through files
    for root, dirs, files in os.walk(filename):
        for file in files:
            path_of_file = os.path.join(root, file)
            exit_code = decrypt_file_function(password, path_of_file, username, single=False)
            if exit_code == 7:
                key_sig_disparity = True
            else:
                continue
    add_log("f", username, filename, encrypted=False)
    if key_sig_disparity is False:
        return 0
    elif key_sig_disparity is True:
        return 3
    

# Creating the login date module
def login_date_Script(username=str) -> int:
    """
    A small function to log the login date of a user.
    \n
    Returns 0.
    """
    login_date = dt.datetime.utcnow()
    with open ("/home/{}/Revenant/userLog.txt".format(username), 'a') as file:
        file.write("Login detected at: " + str(login_date) + " UTC.\n")
    return 0


# and the logout date module
def logout_date_Script(username=str) -> int:
    """
    A small function to log the logout date.
    \n
    Returns 0.
    """
    logout_date = dt.datetime.utcnow()
    with open ("/home/{}/Revenant/userLog.txt".format(username), 'a') as file:
        file.write("Logout detected at: " + str(logout_date) + " UTC.\n")
    return 0


# Creating the main login sequence.
def login_sequence(password=str, username=str, count=int):
    """
    Main login sequence. Runs once.
    code of 0: no errors detected.
    Error code of 1: Username is invalid.
    error code of 2: given password did not match cached password.
    error code of 3: password or username was not given.
    """
    global logged_in
    # checking if the user is logged in. killing app if yes
    if logged_in is True:
        sg.popup_error("I dunno how you did this.\nYou somehow clicked on the login button after you logged in, even though\nthere was no programmed way to do that.\nContact me I guess, w.garrioch456@gmail.com\nThe program will now quit, since I do not know how this behaviour will affect its workings.")
        quit()
    # checking if five incorrect attempts to login have occurred.
    if count == 5:
        sg.popup_auto_close("Invalid credentials entered at least 5 times. Exiting application...", font="Helvetica")
        quit()
    # guard clause
    if password == "" or username == "":
        return 3
    # checking if user is valid
    elif os.path.exists("/home/{}".format(username)) is False:
        return 1
    # accessing the password cache and extracting its contents.
    try:
        with open ("/home/{}/Revenant/.password.hash".format(username), 'r') as file:
            contents = file.read()
    except FileNotFoundError:
        sg.popup_error("Password cache not found. Reinstall with the most recent password and decrypt any encrypted files.\nThis program will now quit.", font='Helvetica')
        quit()
    length = len(contents)
    # getting the hash and salt from cache
    password_hash = contents[0:length:4]; salt = contents[1,length,4]
    # creating the hash object and comparing
    full_object = password + username.strip() + salt; full_hash = hash.sha256(full_object.encode()); hex_digest = full_hash.hexdigest()
    # returning values
    if password_hash == hex_digest:
        logged_in = True
        return 0
    elif password_hash != hex_digest:
        return 2


# creating the password change module yaaaaaaaaay
def change_password(old_password=str, new_password=str, username=str):
    """
    Module for changing password.
    String returned: There were no error codes.
    Error code of 1: Old password or new password was not supplied.
    Error code of 2: Old password was not correct.
    """
    if old_password == "" or new_password == "":
        return 1
    list_ = []
    # accessing the cache to extract contents
    try:
        with open ("/home/{}/Revenant/.password.hash".format(username), 'r') as file:
            contents = file.read()
    except FileNotFoundError:
        sg.popup_error("Password cache not found. Reinstall with the most recent password and decrypt any encrypted files. This program will now quit.", font='Helvetica')
        quit()
    # getting hash and salt
    length = len(contents); pass_hash = contents[0:length:4]; salt = contents[1,length,4]
    # creating hash object and comparing
    full = old_password + username.strip() + salt; hashed = hash.sha256(full.encode()); hex_string = hashed.hexdigest()
    if hex_string == pass_hash:
        # creating new salt and two filler hash strings
        new_salt = rand_hash(); filler_1 = rand_hash(); filler_2 = rand_hash()
        # creating the new object
        full_object = new_password + username.strip() + new_salt; password_hash = hash.sha256(full_object.encode()); hex_digest = password_hash.hexdigest()
        # layering hash
        for i in range(64):
            # breaking blocks up into 4 character blocks and appending to the list
            single_hash_pass = hex_digest[i]; single_salt = new_salt[i]; filler_1_single = filler_1[i]; filler_2_single = filler_2[i]
            combined_hash_block = single_hash_pass + single_salt + filler_1_single + filler_2_single; list_.append(combined_hash_block)
        # combining hash blocks
        layered_hash = "".join(list_)
        sg.popup_auto_close("Parsing Drive. This may take a while.", font="Helvetica", non_blocking=True)
        # looping through every file 
        for root, dirs, files in os.walk("/home/{}/".format(username)):
            for file in files:
                path_of_file = os.path.join(root, file)
                # avoiding a few common applications to speed up parsing, and passing any hidden files
                if "steam" in path_of_file or "cache" in path_of_file or "wine" in path_of_file or "/." in path_of_file:
                    continue
                exit_code = decrypt_file_function(old_password, path_of_file, username, single=False)
                if exit_code == 0:
                    # generating needed things for encryption
                    rand_bytes = os.urandom(16); key = PBKDF2(new_password, rand_bytes, dkLen=32)
                    encrypt_file_function(key, rand_bytes, path_of_file, username, single=False)
                else:
                    continue
        add_log("c", username, path_of_file, encrypted=True)
        # writing the new password to the cache
        with open("/home/{}/Revenant/.password.hash".format(username), 'w') as file:
            file.write(layered_hash)
        # returning the new password so that the while True: loop doesn't throw a fit. Else, returning 2.
        return new_password
    elif hex_string != pass_hash:
        return 2


# Auditing function to ensure that userLog doesn't become too large.
def audit_userlog_function(mode=str, username=str) -> int:
    """
    Function to audit the UserLog file.
    Code of 0: no errors detected.
    Error code of 1: Mode was not specified.
    """
    if mode is None:
        return 1
    #s for singular, f for folders, v for vault, a for all
    if mode == "s":
        with open ("/home/{}/Revenant/userLog.txt".format(username), 'r') as file:
            lines = file.readlines()
        with open ("/home/{}/Revenant/userLog.txt".format(username), 'w') as file:
            for line in lines:
                if "Singular:" not in line.strip("\n"):
                    file.write(line)
        return 0
    elif mode == "f":
        with open ("/home/{}/Revenant/userLog.txt".format(username), 'r') as file:
            lines = file.readlines()
        with open ("/home/{}/Revenant/userLog.txt".format(username), 'w') as file:
            for line in lines:
                if "Folder:" not in line.strip("\n"):
                    file.write(line)
        return 0
    elif mode == "v":
        with open ("/home/{}/Revenant/userLog.txt".format(username), 'r') as file:
            lines = file.readlines()
        with open ("/home/{}/Revenant/userLog.txt".format(username), 'w') as file:
            for line in lines:
                if "Vault" not in line.strip("\n"):
                    file.write(line)
        return 0
    elif mode == "a":
        with open ("/home/{}/Revenant/userLog.txt".format(username), 'w') as file:
            file.write("Userlog cleared.\n")
        return 0


# run a check at runtime to see how large the Userlog is. if it's over 64 KB, autoremove
def Auto_edit():
    global alert
    assumed_username = getuser()
    try:
        size = os.path.getsize("/home/{}/Revenant_source_code/userLog.txt".format(assumed_username))
        if size >= 64000:
            audit_userlog_function("a", assumed_username)
            alert = 1
    except FileNotFoundError:
        pass


Auto_edit()


sg.theme('DarkBlue')


# Creating the login layout to get password + username from the user
login_layout = [
    [sg.Text('Enter current Linux username. This will be used to access relevant directories/files.', font="Helvetica")],
    [sg.InputText(key='username', font="Helvetica", border_width=10)],
    [sg.Text("Enter password.", font="Helvetica")],
    [sg.InputText(key="password", password_char='*', font="Helvetica", border_width=10)],
    [sg.Button("Ok", font="Helvetica", border_width=10), sg.Button("Close Window", font="Helvetica", border_width=10)]
] # this layout is done


logged_layout = [
    [sg.Text('Password confirmed, user logged. What would you like to do?', font="Helvetica", border_width=10)],
    [sg.Button('Edit file configurations', key="file_hub", font="Helvetica", border_width=10),
    sg.Button('Change my password', key='password_change', font="Helvetica", border_width=10)],
    [sg.Button('Close Window', key='Close', font="Helvetica", border_width=10)]
] # this layout is done


change_pass_layout = [
    [sg.Text("Please enter your current password.", font="Helvetica")],
    [sg.InputText(key="old_password", password_char='*', font="Helvetica", border_width=10)],
    [sg.Text("Please enter your new password.", font="Helvetica")],
    [sg.InputText(key="new_password", password_char="*", font="Helvetica", border_width=10)],
    [sg.Button("Ok", key="OK_pass", font="Helvetica", border_width=10), sg.Button("Go back", key="back_pass", font="Helvetica", border_width=10)]
] # also done


file_hub_script_layout = [
    [sg.Text("Please select a command.", font="Helvetica")],
    [sg.Frame("External file commands",[
        [sg.Button("File encryption - encrypts a singular file, given the path.", key="file_encrypt", font="Helvetica"),
        sg.Button("File decryption - decrypts an already encrypted file, given the path.", key="file_decrypt", font="Helvetica")]],
        border_width=10, background_color="#626a80", element_justification="C")],
    [sg.Frame('External folder commands',[
        [sg.Button("Folder encryption - encrypts a singular folder, given the path.",key="folder_encrypt", font="Helvetica"),
        sg.Button("Folder decryption - decrypts an already encrypted folder, given the path.", key='folder_decrypt', font="Helvetica")]],
        border_width=10, background_color="#626a80", element_justification="C")],
    [sg.Frame('Vault commands',[
        [sg.Button("Encrypt Vault - encrypts every non-encrypted file in the Vault folder.", key="vault_encrypt", font="Helvetica"),
        sg.Button('Decrypt Vault - decrypts every encrypted file in the Vault folder.', key="vault_decrypt", font="Helvetica")]],
        border_width=10, background_color="#626a80", element_justification="C")],
    [sg.Button('Back - Go back to previous screen', key='back', font="Helvetica", border_width=10), sg.Button("Audit UserLog File", key="Intiate_audit", font="Helvetica", border_width=10)],
    [sg.Button("Logout - terminates application and logs user out.", key="logout", font="Helvetica", border_width=10)]
]# this layout is done


userLog_audit_layout = [
    [sg.Text("UserLog Audit Mode selected. What would you like to do?")],
    [sg.Button("Remove singular file Encryption/Decryption logs", key="single_file_log_audit", font="Helvetica", border_width=10),
    sg.Button("Remove Folder Encryption/Decryption Logs", key="folder_logs_audit", font="Helvetica", border_width=10)],
    [sg.Button("Remove Vault Encryption/Decryption Logs", key="vault_log_audit", font="Helvetica", border_width=10),
    sg.Button('Clear userlog.', key="Clear_userlog", font="Helvetica", border_width=10)],
    [sg.Button("Return to previous screen", key="audit_return", font="Helvetica", border_width=10),
    sg.Button("Close Window", key="Close_Audit", font="Helvetica", border_width=10)]
]


layout = [
    [sg.Column(login_layout, key="Login_Layout", element_justification="C"),
    sg.Column(logged_layout, visible=False, key="Logged_Layout", element_justification="C"),
    sg.Column(file_hub_script_layout, visible=False, key="File_hub_layout", element_justification="C"),
    sg.Column(change_pass_layout, visible=False, key='Change_pass_layout', element_justification="C"),
    sg.Column(userLog_audit_layout, visible=False, key="userLog_audit_layout", element_justification="C")
    ]
]

# Intializing the window.
window = sg.Window("Revenant Version 1.0.0", layout, element_justification="C").Finalize()
window.Maximize()

username = "0"; password = "0"
# Creating the loop to check for events and values
while True:
    event, values = window.read()
    if event in (None, "Close Window", "Close", "logout", "Close_Audit"):
        logout_date_Script(username)
        quit()
    if alert == 1:
        sg.popup_auto_close("userLog capacity reached. userLog cleared.", font="Helvetica", non_blocking=True)
    if event == "Ok":
        username = values["username"]
        password = values["password"]
        exit_code = login_sequence(password, username, count)
        if exit_code ==  0:
            LAYOUT_CYCLE_VAR = 1
        elif exit_code == 1:
            sg.popup_auto_close("The given username is not a valid username.", font="Helvetica", non_blocking=True)
        elif exit_code == 2:
            sg.popup_auto_close("Incorrect credentials.", font="Helvetica", non_blocking=True)
            count += 1
        elif exit_code == 3:
            sg.popup_auto_close("Password or username was not provided.", font="Helvetica", non_blocking=True)
    if LAYOUT_CYCLE_VAR == 1:
        window[f"Login_Layout"].update(visible=False)
        window[f"Logged_Layout"].update(visible=True)
        LAYOUT_CYCLE_VAR = 2
    if event == "file_hub":
        window[f"Logged_Layout"].update(visible=False)
        window[f"File_hub_layout"].update(visible=True)
    elif event == "password_change":
        window[f"Logged_Layout"].update(visible=False)
        window[f"Change_pass_layout"].update(visible=True)
    elif event == "back_pass":
        window[f"Change_pass_layout"].update(visible=False)
        window[f"Logged_Layout"].update(visible=True)
    elif event == "back":
        window[f"File_hub_layout"].update(visible=False)
        window[f"Logged_Layout"].update(visible=True)
    elif event == "Intiate_audit":
        window[f"Logged_Layout"].update(visible=False)
        window[f"File_hub_layout"].update(visible=False)
        window[f"userLog_audit_layout"].update(visible=True)
    elif event == "audit_return":
        window[f"File_hub_layout"].update(visible=True)
        window[f"userLog_audit_layout"].update(visible=False)
    elif event == "file_encrypt":
        window[f"Logged_Layout"].update(visible=False)
        # getting needed variables
        salt = os.urandom(16); key = PBKDF2(password, salt, dkLen=32); file_name = sg.popup_get_file("Please select a file for encryption.", font="Helvetica")
        exit_code = encrypt_file_function(key, salt, file_name, username, single=True)
        if exit_code == 0:
            sg.popup_auto_close("Encryption successful; file: " + file_name + " successfully encrypted.", font="Helvetica", non_blocking=True)
        elif exit_code == 1:
            sg.popup_auto_close("File encryption cancelled.", font="Helvetica", non_blocking=True)
        elif exit_code == 2:
            sg.popup_auto_close("The application does not have the required permissions to access the file.", font="Helvetica", non_blocking=True)
        elif exit_code == 3:
            sg.popup_auto_close("The given file is not a valid path.", font="Helvetica", non_blocking=True)
        elif exit_code == 4:
            sg.popup_auto_close("The file was hidden and will not be encrypted.", font="Helvetica", non_blocking=True)
        elif exit_code == 5:
            sg.popup_auto_close("The file was already encrypted.", font="Helvetica", non_blocking=True)
    elif event == "file_decrypt":
        window[f"Logged_Layout"].update(visible=False)
        file_name = sg.popup_get_file("Please select a file for decryption.", font="Helvetica")
        exit_code = decrypt_file_function(password, file_name, username, single=True)
        if exit_code == 0:
            sg.popup_auto_close("Decryption successful; file: " + file_name + " successfully decrypted.", font="Helvetica", non_blocking=True)
        elif exit_code == 1:
            sg.popup_auto_close("File decryption cancelled.", font="Helvetica", non_blocking=True)
        elif exit_code == 2:
            sg.popup_auto_close("The application does not have the required permissions to access the file.", font="Helvetica", non_blocking=True)
        elif exit_code == 3:
            sg.popup_auto_close("The given file path is not a valid path.", font="Helvetica", non_blocking=True)
        elif exit_code == 6:
            sg.popup_auto_close("The given file was already decrypted.", font="Helvetica", non_blocking=True)
        elif exit_code == 7:
            sg.popup_auto_close("The given file was encrypted with a different key. The file was unable to be decrypted with the current credentials.", font="Helvetica", non_blocking=True)
    elif event == "folder_encrypt":
        window[f"Logged_Layout"].update(visible=False)
        file_name = sg.popup_get_folder("Please select a folder for encryption.")
        exit_code = folder_encryption_function(password, file_name)
        if exit_code == 0:
            sg.popup_auto_close("Folder encryption successful; folder:" +file_name+ " successfully encrypted", font="Helvetica", non_blocking=True)
        elif exit_code == 1:
            sg.popup_auto_close("Folder encryption cancelled.", font="Helvetica", non_blocking=True)
        elif exit_code == 2:
            sg.popup_auto_close("The given folder path does not exist.", font="Helvetica", non_blocking=True)
    elif event == "folder_decrypt":
        window[f"Logged_Layout"].update(visible=False)
        file_name = sg.popup_get_folder("Please select a folder for encryption.")
        exit_code = folder_decryption_function(password, file_name)
        if exit_code == 0:
            sg.popup_auto_close("Folder decryption successful; folder:" +file_name+ " successfully decrypted", font="Helvetica", non_blocking=True)
        elif exit_code == 1:
            sg.popup_auto_close("Folder decryption cancelled.", font="Helvetica", non_blocking=True)
        elif exit_code == 2:
            sg.popup_auto_close("The given folder path does not exist.", font="Helvetica", non_blocking=True)
        elif exit_code == 3:
            sg.popup_auto_close("Some files contained in the given folder were encrypted with a different key and were ignored.", font="Helvetica", non_blocking=True)
    elif event == "vault_encrypt":
        window[f"Logged_Layout"].update(visible=False)
        exit_code = Vault_encrypt(password, username)
        if exit_code == 0:
            sg.popup_auto_close("Encryption successful; Vault is now encrypted.", font="Helvetica", non_blocking=True)
    elif event == "vault_decrypt":
        exit_code = Vault_decrypt(password, username)
        if exit_code == 0:
            sg.popup_auto_close("Decryption successful; Vault is now decrypted.", font="Helvetica", non_blocking=True)
        elif exit_code == 2:
            sg.popup_auto_close("Some files contained in the Vault folder were encrypted with different keys and were ignored.", font="Helvetica", non_blocking=True)
    elif event == "OK_pass":
        window[f"Logged_Layout"].update(visible=False)
        old_pass = values["old_password"]
        new_pass = values["new_password"]
        exit_code = change_password(old_pass, new_pass, username)
        if exit_code == 1:
            sg.popup_error("You did not give either your old password or new password. Password change automatically cancelled.", font="Helvetica")
        elif exit_code == 2:
            sg.popup_auto_close("The old password that was entered is wrong. Password change automatically cancelled.", font="Helvetica", non_blocking=True)
        else:
            sg.popup_auto_close("Password Change successful.", font="Helvetica", non_blocking=True)
            password = exit_code
    elif event == "single_file_log_audit":
        window[f"Logged_Layout"].update(visible=False)
        exit_code = audit_userlog_function("s", username)
        if exit_code == 0:
            sg.popup_auto_close("userLog audit completed. All Singular File log instances have been deleted.", font="Helvetica", non_blocking=True)
    elif event == "folder_logs_audit":
        window[f"Logged_Layout"].update(visible=False)
        exit_code = audit_userlog_function("f", username)
        sg.popup_auto_close("userLog audit completed. All Folder log instances have been deleted.", font="Helvetica", non_blocking=True)
    elif event == "vault_log_audit":
        window[f"Logged_Layout"].update(visible=False)
        exit_code = audit_userlog_function("v", username)
        if exit_code == 0:
            sg.popup_auto_close("userLog audit completed. All Vault log instances have been deleted.", font="Helvetica", non_blocking=True)
    elif event == "Clear_userlog":
        window[f"Logged_Layout"].update(visible=False)
        exit_code = audit_userlog_function("a", username)
        if exit_code == 0:
            sg.popup_auto_close("userLog audit completed. All log instances have been deleted.", font="Helvetica", non_blocking=True)
