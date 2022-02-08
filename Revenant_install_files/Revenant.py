#importing required modules and setting needed variables
# all exit codes for modules will use integers unless needed
from fileinput import filename
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from getpass import getuser
import PySimpleGUI as sg
import hashlib as hash
import datetime as dt # for logging dates
from time import sleep # for delays
from gc import enable # enabling garbage collection
enable()


class log:
    """
    A class to audit the userLog file and log things such as login/logout dates.
    """


    def __init__(self, username) -> None:
        self.username = username
    

    def audit(self, mode=str) -> int:
        """
        Function to audit the UserLog file.

        Parameters:
            s: Removes single file log entries.
            f: Removes folder log entries.
            v: Removes Vault log entries.
            a: Removes all entries.

        Return Codes:
            Code of 0: no errors detected.
            Code of 1: Mode was not specified.
        """
        if mode is None:
            return 1
        #s for singular, f for folders, v for vault, a for all
        if mode == "s":
            with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'r') as file:
                lines = file.readlines()
            with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'w') as file:
                for line in lines:
                    if "Singular:" not in line.strip("\n"):
                        file.write(line)
            return 0
        elif mode == "f":
            with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'r') as file:
                lines = file.readlines()
            with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'w') as file:
                for line in lines:
                    if "Folder:" not in line.strip("\n"):
                        file.write(line)
            return 0
        elif mode == "v":
            with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'r') as file:
                lines = file.readlines()
            with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'w') as file:
                for line in lines:
                    if "Vault" not in line.strip("\n"):
                        file.write(line)
            return 0
        elif mode == "a":
            with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'w') as file:
                file.write("Userlog cleared.\n")
            return 0
        pass
    

    def auto_audit(self) -> int:
        """
        a simple function that runs at runtime to make sure the userlog file does not get too large.
        """
        assumed_username = getuser()
        try:
            size = os.path.getsize("/home/{}/Revenant_source_code/userLog.txt".format(assumed_username))
            if size >= 64000:
                self.audit("a")
                return 1
        except FileNotFoundError:
            pass


    def log(self, mode=str, path=str, encrypted=bool) -> int:
        """
        Logging function for various file operations.

        Parameters:
            mode (string): This is the file operation you are doing.
                Single files = "s"   \n
                Folders = "f"   \n
                Vault operations = "v"   \n
                password change = "c"   \n
            path (string): The file path of the file you have done an operation on.

            encrypted (boolean): Whether or not the operation was an encryption.

        Returns 0 if logging was successful, 1 if mode or path was None, and 2 if userLog does not exist.
        """
        if mode is None or path is None:
            return 1
        time_ = str(dt.datetime.utcnow())
        try:
            if mode == "s":
                with open ("/home/{}/Revenant/userLog.txt".format(self.username), "a") as file:
                    if encrypted is True:
                        string_ = "encrypted"
                    else:
                        string_ = "decrypted"
                    file.write("Singular: File: {} was: {} at: {} UTC".format(path, string_, time_))
                pass
            elif mode == "f":
                with open("/home/{}/Revenant/userLog.txt".format(self.username) ,'a') as file:
                    # formatting
                    if encrypted is True:
                        string_ = "encrypted"
                    elif encrypted is False:
                        string_ = "decrypted"
                    # writing
                    file.write("Folder: Folder: {} was: {} at: {} UTC.\n".format(path, string_, time_))
            elif mode == "v":
                with open("/home/{}/Revenant/userLog.txt".format(self.username) ,'a') as file:
                    # formatting
                    if encrypted is True:
                        string_ = "encrypted"
                    elif encrypted is False:
                        string_ = "decrypted"
                    # writing
                    file.write("Vault: Vault was: {} at: {} UTC.\n".format(string_, time_))
            elif mode == "c":
                with open("/home/{}/Revenant/userLog.txt".format(self.username) ,'a') as file:
                    file.write("Password: password was changed at: {} UTC.\n".format(time_))
        except FileNotFoundError:
            file = open("/home/{}/Revenant/userLog.txt".format(self.username), "w+")
            file.write("userLog recreated due to FileNotFoundError.\n")
            file.close()
            return 2


    def log_logout(self) -> int:
        """
        A small function to log the logout date.
        
        Returns 0.
        """
        logout_date = dt.datetime.utcnow()
        with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'a') as file:
            file.write("Logout detected at: " + str(logout_date) + " UTC.\n")
        return 0


    def log_login(self) -> int:
        """
        A small function to log the login date of a user.
    
        Returns 0.
        """
        login_date = dt.datetime.utcnow()
        with open ("/home/{}/Revenant/userLog.txt".format(self.username), 'a') as file:
            file.write("Login detected at: " + str(login_date) + " UTC.\n")
        return 0


class cipher:
    """
    A class for ciphering/deciphering operations.

    Linux native.

    Parameters:
        Username: The Linux username of the user who is logging in.
        Password: The password of the user.
    """


    def __init__(self, password=str, username=str) -> None:
        self.password = password
        self.username = username
        self.marker  = b"E1m%nj2i$bhilj"
        self.logger = log


    def log(self, mode=str, path=str, encrypted=bool) -> int:
        self.logger.log(mode=mode, path=path, encrypted=encrypted)
        pass


    def guard_clause(self, path=str or None, decrypting=bool) -> int:
        """
        A guard clause for file operations.

        Return codes:
            0: File path is good.
            1: File path is None.
            2: File path is invalid.
            3: App does not have permission to access file.
            4: File is hidden.
            5: File is part of root filesystem and not accessing chromeos.
            6: File encryption marker detected during encryption.
            7: File encryption marker not detected during decryption.
        """
        # checking if file is hidden
        if "/." in path:
            return 4
        # checking if file is part of the root filesystem and not a part of ChromeOS for linux in Chromebooks
        if "/home/" not in path and "/mnt/chromeos/MyFiles" not in path:
            return 5
        # checking if decrypt is cancelled
        if path is None:
            return 1
        try:
            if os.path.isfile(path) is True:
                with open (path, "rb") as file:
                    file_marker = file.read(14)
            elif os.path.isdir(path) is True:
                return 0
        # checking if file exists
        except FileNotFoundError:
            return 2
        # checking if application has permission
        except PermissionError:
            return 3
        # checking if there is a file encryption marker during encryption
        if file_marker == self.marker and decrypting is False:
            return 6
        # checking if there is not a file encryption marker during decryption
        elif file_marker != self.marker and decrypting is True:
            return 7
        else:
            # deleting everything
            del file_marker
            return 0


    def encrypt(self, path=str) -> int:
        """
        A method for encrypting a file/folder object.

        Takes only a file path as an argument.

        Return codes:
            0: File encrypt successful.
            1: Path is None.
            2: Path is invalid.
            3: App does not have permissions required to access file.
            4: File is hidden.
            5: File is part of root filesystem and not part of ChromeOS.
            6: File encryption marker detected during encryption.
        """
        return_code = self.guard_clause(path, decrypting=False)
        if return_code != 0:
            return return_code
        salt = os.urandom(32)
        iv = os.urandom(16)
        key = PBKDF2(self.password, salt, dkLen=32)
        key_hash = hash.sha256(key); key_signature = key_hash.digest()
        if os.path.isfile(path) is True:
            with open (path, "rb") as file:
                data = file.read()
            cipher = AES.new(key, AES.MODE_CFB, iv=iv)
            ciphered_data = cipher.encrypt(data)
            with open(path, "wb") as file:
                file.write(self.marker)
                file.write(iv)
                file.write(salt)
                file.write(key_signature)
                file.write(ciphered_data)
            objects = [return_code, salt, iv, key, key_hash, key_signature, data, cipher, ciphered_data]
            for object_ in objects:
                del object_
            self.log()
            return 0
        elif os.path.isdir(path) is True:
            for root, dirs, files in os.walk():
                for file in files:
                    file_name = os.path.join(root, file)
                    return_code = self.guard_clause(file_name, decrypting=False)
                    if return_code != 0:
                        continue
                    with open (file_name) as file:
                        data = file.read()
                    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                    ciphered_data = cipher.encrypt(data)
                    with open(path, "wb") as file:
                        file.write(self.marker)
                        file.write(iv)
                        file.write(salt)
                        file.write(key_signature)
                        file.write(ciphered_data)
                    objects = [return_code, salt, iv, key, key_hash, key_signature, data, cipher, ciphered_data]
                    for object_ in objects:
                        del object_
            self.log()
            return 0
        else:
            sg.popup_auto_close("WHAT DID YOU DO????? the app didn't detect the file as either a file or a dir. what? email me pls", font="Helvetica")    


    def decrypt(self, filepath=str) -> int:
        """
        A method for decrypting an encrypted file.

        Takes only a file path as an argument.

        return codes:
            0: File decrypt successful.
            1: Path is None.
            2: File path is invalid.
            3: App does not have permissions required to access file.
            4: File is hidden.
            5: File is part of root filesystem and not part of ChromeOS.
            6: File was encrypted with a different key.
            7: File was not encrypted.
        """
        return_code = self.guard_clause(filepath, decrypting=False)
        if return_code != 0:
            return return_code
        if os.path.isfile(filepath) is True:
            with open (filepath, "rb") as file:
                file.read(14)
                iv = file.read(16)
                salt = file.read(32)
                file_signature = file.read(32)
                ciphered_data = file.read()
            key = PBKDF2(self.password, salt, dkLen=32)
            key_hash = hash.sha256(key); key_signature = key_hash.digest()
            if file_signature != key_signature:
                objects = [return_code, iv, salt, file_signature, ciphered_data, key, key_hash, key_signature]
                for object_ in objects:
                    del object_
                return 6
            cipher = AES.new(key, AES.MODE_CFB, iv=iv)
            original_data = cipher.decrypt(ciphered_data)
            with open(filepath, "wb") as file:
                file.write(original_data)
            objects = [return_code, iv, salt, file_signature, ciphered_data, key, key_hash, key_signature, cipher, original_data]
            for object_ in objects:
                del object_
            self.log()
            return 0
        elif os.path.isdir(filepath) is True:
            for root, dirs, files in os.walk(filepath):
                for file in files:
                    file_name = os.path.join(root, file)
                    return_code = self.guard_clause(file_name, decrypting=True)
                    if return_code != 0:
                        continue
                    with open (file_name, "rb") as file:
                        file.read(14)
                        iv = file.read(16)
                        salt = file.read(32)
                        file_signature = file.read(32)
                        ciphered_data = file.read()
                    key = PBKDF2(self.password, salt, dkLen=32)
                    key_hash = hash.sha256(key); key_signature = key_hash.digest()
                    if key_signature != file_signature:
                        return 6
                    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                    original_data = cipher.decrypt(ciphered_data)
                    with open (file_name, "wb") as file:
                        file.write(original_data)
                    objects = [return_code, iv, salt, file_signature, ciphered_data, key, key_hash, key_signature, cipher, original_data]
                    for object_ in objects:
                        del object_
            self.log()
            return 0    
        else:
            sg.popup_auto_close("WHAT DID YOU DO????? the app didn't detect the file as either a file or a dir. what? email me pls", font="Helvetica")    
    
        

        self.log()
        pass


    def Vault_operation(self, decrypting=bool):
        """
        Method for encrypting the Vault folder.

        return codes:
        0: Folder was successfully encrypted/decrypted. Some files which did not meet the requirements were skipped.
        1: Folder was not found on default path and was rebuilt.

        """
        if decrypting is True:
            try:
                for root, dirs, files in os.walk("/home/{}/Vault".format(self.username)):
                    for file in files:
                        file_name = os.path.join(root, file)
                        return_code = self.guard_clause(file_name, decrypting=True)
                        if return_code != 0:
                            continue 
                        with open (file_name, "rb")  as file:
                            file.read(14)
                            iv = file.read(16)
                            salt = file.read(32)
                            file_signature = file.read(32)
                            ciphered_data = file.read()
                        key = PBKDF2(self.password, salt, dkLen=32)
                        key_hash = hash.sha256(key); key_signature = key_hash.digest()
                        if key_signature != file_signature:
                            continue
                        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                        original_data = cipher.decrypt(ciphered_data)
                        with open (file_name, "wb") as file:
                            file.write(original_data)
                return 0
            except FileNotFoundError:
                try:
                    os.mkdir("/home/{}/Vault".format(self.username))
                    os.mkdir("/home/{}/Vault/Images/".format(self.username))
                    os.mkdir("/home/{}/Vault/Text/".format(self.username))
                    os.mkdir("/home/{}/Vault/Other/".format(self.username))
                    return 1
                except FileExistsError:
                    pass
        else:
            try:
                for root, dirs, files in os.walk("/home/{}/Vault".format(self.username)):
                    for file in files:
                        file_name = os.path.join(root, file)
                        return_code = self.guard_clause(file_name, decrypting=False)
                        if return_code != 0:
                            return 8
                        salt = os.urandom(32)
                        iv = os.urandom(16)
                        key = PBKDF2(self.password, salt, dkLen=32)
                        key_hash = hash.sha256(key); key_signature = key_hash.digest()
                        with open (file_name, "rb") as file:
                            data = file.read()
                        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                        ciphered_data = cipher.encrypt(data)
                        with open (file_name, "wb") as file:
                            file.write(self.marker)
                            file.write(iv)
                            file.write(salt)
                            file.write(key_signature)
                            file.write(ciphered_data)
                return 0                        
            except FileNotFoundError:
                try:
                    os.mkdir("/home/{}/Vault".format(self.username))
                    os.mkdir("/home/{}/Vault/Images/".format(self.username))
                    os.mkdir("/home/{}/Vault/Text/".format(self.username))
                    os.mkdir("/home/{}/Vault/Other/".format(self.username))
                    return 1
                except FileExistsError:
                    pass


    def change_password(self, new_password = str):
        self.password = new_password
        pass


class login:
    """
    Class responsible for logging the user in.
    """
    def __init__(self) -> None:
        pass
    

    def rand_hash(self) -> str:
        "a function to generate random hex-encoded hashes."
        rand_bytes = os.urandom(32)
        rand_hash = hash.sha256(rand_bytes)
        return_value = rand_hash.hexdigest()
        return return_value
    

    def login_sequence(self, password=str, username=str, count=int) -> int:
        """
        Main login sequence. Runs once.
        code of 0: no errors detected.
        Error code of 1: Username is invalid.
        error code of 2: given password did not match cached password.
        error code of 3: password or username was not given.
        """
        # checking if five incorrect attempts to login have occurred.
        if count == 5:
            sg.popup_auto_close("Invalid credentials entered at least 5 times. Exiting application...", font="Helvetica")
            quit()
        # guard clause
        if password == "" or username == "":
            return 3
        # checking if user is valid
        elif os.path.exists("/home/{}/".format(username)) is False:
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
        password_hash = contents[0:length:4]; salt = contents[1:length:4]
        # creating the hash object and comparing
        full_object = password + username.strip() + salt; full_hash = hash.sha256(full_object.encode()); hex_digest = full_hash.hexdigest()
        # returning values
        if password_hash == hex_digest:
            return 0
        elif password_hash != hex_digest:
            return 2


    def change_password(self, old_password=str, new_password=str, username=str):
        """
        Module for changing password. Can return either an integer or string.
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
        length = len(contents); pass_hash = contents[0:length:4]; salt = contents[1:length:4]
        # creating hash object and comparing
        full = old_password + username.strip() + salt; hashed = hash.sha256(full.encode()); hex_string = hashed.hexdigest()
        if hex_string == pass_hash:
            # creating new salt and two filler hash strings
            new_salt = self.rand_hash(); filler_1 = self.rand_hash(); filler_2 = self.rand_hash()
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
            old_cipher = cipher(old_password, username)
            new_cipher = cipher(new_password, username)
            for root, dirs, files in os.walk("/home/{}/".format(username)):
                for file in files:
                    path_of_file = os.path.join(root, file)
                    exit_code = old_cipher.decrypt(path_of_file)
                    if exit_code == 0:
                        new_cipher.encrypt(path_of_file)
                    else:
                        continue
            # writing the new password to the cache
            del old_cipher; del new_cipher
            with open("/home/{}/Revenant/.password.hash".format(username), 'w') as file:
                file.write(layered_hash)
            # returning the new password so that the while True: loop doesn't throw a fit. Else, returning 2.
            return new_password
        elif hex_string != pass_hash:
            return 2


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


# Creating the loop to check for events and values
class Main:
    """
    Main class for the application.
    """
    def __init__(self) -> None:
        pass

    def intialize():
        """
        Intializes the app.

        Does not return; call on last line.
        """
        # setting needed variables
        username = "0"; password = "0"; count = 0; LAYOUT_CYCLE_VAR = 0; logged_in = False; count = 0; alert = 0
        # setting the login class
        login_class = login()
        while True:
            event, values = window.read()
            if event in (None, "Close Window", "Close", "logout", "Close_Audit"):
                logger.log_logout()
                quit()
            if alert == 1:
                sg.popup_auto_close("userLog capacity reached. userLog cleared.", font="Helvetica", non_blocking=True)
            if event == "Ok" and logged_in is False:
                username = values["username"]
                password = values["password"]
                exit_code = login_class.login_sequence(password = password, username=username, count=count)
                if exit_code ==  0:
                    LAYOUT_CYCLE_VAR = 1
                    logged_in = True
                    encrypter = cipher(password=password, username=username)
                    logger = log(username=username)
                    log.log_login()
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
                # getting file:
                file = sg.popup_get_file("Select the file you wish to encrypt.", font="Helvetica")
                exit_code = encrypter.encrypt(file)
                if exit_code == "0":
                    sg.popup_auto_close("File encryption successful.", font="Helvetica", non_blocking=True)
                elif exit_code == "1":
                    sg.popup_auto_close("File encryption cancelled.", font="Helvetica", non_blocking=True)
                elif exit_code == "2":
                    sg.popup_auto_close("File path is invalid.", font="Helvetica", non_blocking=True)
                elif exit_code == "3":
                    sg.popup_auto_close("App does not have permission to access file.", font="Helvetica", non_blocking=True)
                elif exit_code == "4":
                    sg.popup_auto_close("File is hidden.", font="Helvetica", non_blocking=True)
                elif exit_code == "5":
                    sg.popup_auto_close("File is part of root filesystem and not part of ChromeOS.", font="Helvetica", non_blocking=True)
                elif exit_code == "6":
                    sg.popup_auto_close("File was already encrypted.", font="Helvetica", non_blocking=True)
            elif event == "file_decrypt":
                file = sg.popup_get_file("Select the file you wish to decrypt.", font="Helvetica", non_blocking=True)
                exit_code = encrypter.decrypt(file)
                if exit_code == "0":
                    sg.popup_auto_close("File decryption successful.", font="Helvetica", non_blocking=True)
                if exit_code == "1":
                    sg.popup_auto_close("File decryption cancelled.", font="Helvetica", non_blocking=True)
                if exit_code == "2":
                    sg.popup_auto_close("File path is invalid.", font="Helvetica", non_blocking=True)
                if exit_code == "3":
                    sg.popup_auto_close("App does not have permission to access file.", font="Helvetica", non_blocking=True)
                if exit_code == "4":
                    sg.popup_auto_close("File is hidden.", font="Helvetica", non_blocking=True)
                if exit_code == "5":
                    sg.popup_auto_close("File is part of root filesystem and not part of ChromeOS.", font="Helvetica", non_blocking=True)
                if exit_code == "6":
                    sg.popup_auto_close("File was encrypted with a different key.", font="Helvetica", non_blocking=True)
                if exit_code == "7":
                    sg.popup_auto_close("File was not encrypted.", font="Helvetica", non_blocking=True)
            elif event == "folder_encrypt":
                folder = sg.popup_get_folder("Select the file you wish to encrypt.", font="Helvetica")
                exit_code = encrypter.encrypt(folder)
                if exit_code == "0":
                    sg.popup_auto_close("Folder encryption successful.", font="Helvetica", non_blocking=True)
                elif exit_code == "1":
                    sg.popup_auto_close("Folder encryption cancelled.", font="Helvetica", non_blocking=True)
                elif exit_code == "2":
                    sg.popup_auto_close("Folder path is invalid.", font="Helvetica", non_blocking=True)
                elif exit_code == "3":
                    sg.popup_auto_close("App does not have permission to access file.", font="Helvetica", non_blocking=True)
                elif exit_code == "4":
                    sg.popup_auto_close("Folder is hidden.", font="Helvetica", non_blocking=True)
                elif exit_code == "5":
                    sg.popup_auto_close("Folder is part of root filesystem and not part of ChromeOS.", font="Helvetica", non_blocking=True)
                elif exit_code == "6":
                    sg.popup_auto_close("Folder was already encrypted.", font="Helvetica", non_blocking=True)
                pass
            elif event == "folder_decrypt":
                folder = sg.popup_get_folder("Select the file you wish to decrypt.", font="Helvetica", non_blocking=True)
                exit_code = encrypter.decrypt(folder)
                if exit_code == "0":
                    sg.popup_auto_close("Folder decryption successful.", font="Helvetica", non_blocking=True)
                if exit_code == "1":
                    sg.popup_auto_close("Folder decryption cancelled.", font="Helvetica", non_blocking=True)
                if exit_code == "2":
                    sg.popup_auto_close("Folder path is invalid.", font="Helvetica", non_blocking=True)
                if exit_code == "3":
                    sg.popup_auto_close("App does not have permission to access file.", font="Helvetica", non_blocking=True)
                if exit_code == "4":
                    sg.popup_auto_close("Folder is hidden.", font="Helvetica", non_blocking=True)
                if exit_code == "5":
                    sg.popup_auto_close("Folder is part of root filesystem and not part of ChromeOS.", font="Helvetica", non_blocking=True)
                if exit_code == "6":
                    sg.popup_auto_close("Folder was encrypted with a different key.", font="Helvetica", non_blocking=True)
                if exit_code == "7":
                    sg.popup_auto_close("Folder was not encrypted.", font="Helvetica", non_blocking=True)
                pass
            elif event == "vault_encrypt":
                pass
            elif event == "OK_pass":
                old_pass = values["old_password"]
                new_pass = values["new_password"]
                exit_code = login_class.change_password(old_pass, new_pass, username)
                if exit_code == 1:
                    sg.popup_error("You did not give either your old password or new password. Password change automatically cancelled.", font="Helvetica")
                elif exit_code == 2:
                    sg.popup_auto_close("The old password that was entered is wrong. Password change automatically cancelled.", font="Helvetica", non_blocking=True)
                else:
                    encrypter.change_password(exit_code)
                    sg.popup_auto_close("Password Change successful.", font="Helvetica", non_blocking=True)
            elif event == "single_file_log_audit":
                logger.audit("s")
                sg.popup_auto_close("Selected entries cleared.", font="Helvetica", non_blocking=True)
            elif event == "folder_logs_audit":
                logger.audit("f")
                sg.popup_auto_close("Selected entries cleared.", font="Helvetica", non_blocking=True)
            elif event == "vault_log_audit":
                logger.audit("v")
                sg.popup_auto_close("Selected entries cleared.", font="Helvetica", non_blocking=True)
            elif event == "Clear_userlog":
                logger.audit("a")
                sg.popup_auto_close("Selected entries cleared.", font="Helvetica", non_blocking=True)


app = Main
app.intialize()
