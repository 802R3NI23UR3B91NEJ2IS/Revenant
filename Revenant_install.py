import os
import sys
import shutil
import hashlib as hash
try:
    import tkinter
    import PySimpleGUI
except ImportError:
    os.system("sudo apt-get install python3-tk")
    os.system("pip3 install PySimpleGUI --user")
import PySimpleGUI as sg

def build_dependencies_check():
    try:
        import Crypto
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
    except ImportError:
        os.system("pip3 install pycryptodome --user")
    try:
        import datetime as dt
    except ImportError:
        os.system("pip3 install datetime --user")
    try:
        from Cython.Build import cythonize
    except ImportError:
        os.system("pip3 install Cython --user")
    return 0


def get_python_version():
    version = sys.version
    if "3.4" in version:
        return "34"
    if "3.5" in version:
        return "35"
    if "3.6" in version:
        return "36"
    if "3.7" in version:
        return "37"
    if "3.8" in version:
        return "38"
    if "3.9" in version:
        return "39"


def rand_hash():
    rand_bytes = os.urandom(32)
    rand_hash = hash.sha256(rand_bytes)
    return_value = rand_hash.hexdigest()
    return return_value


def password_hasher(username=str, password=str):
    if username is None:
        return 1
    if password is None:
        return 1
    list = []
    salt = rand_hash()
    filler_1 = rand_hash()
    filler_2 = rand_hash()
    full_object = password + username.strip() + salt
    hashed_bytestring = hash.sha256(full_object.encode())
    hex_digest = hashed_bytestring.hexdigest()
    for i in range(64):
        single_letter_hash = hex_digest[i]
        single_letter_salt = salt[i]
        filler_1_single = filler_1[i]
        filler_2_single = filler_2[i]
        layered_block = single_letter_hash + single_letter_salt + filler_1_single + filler_2_single
        list.append(layered_block)
    layered_hash = "".join(list)
    return layered_hash


def file_dependencies_check(username=str, password=str):
    version = get_python_version()
    sg.popup_auto_close("Installing Required Dependencies...", font="Helvetica")
    exit_code = build_dependencies_check()
    if exit_code == 0:
        sg.popup_auto_close("Dependencies successfully installed. Building required files...", font="Helvetica")
    # testing if directories exist and building if they don't
    source_folder_exists = os.path.exists("/home/{}/.Revenant_source_code".format(username))
    if source_folder_exists is False:
        os.mkdir("/home/{}/.Revenant_source_code/".format(username))
    hi_vis_folder_exists = os.path.exists("/home/{}/Revenant/".format(username))
    if hi_vis_folder_exists is False:
        os.mkdir("/home/{}/Revenant/".format(username))
    Vault_exists = os.path.exists("/home/{}/Vault/".format(username))
    if Vault_exists is False:
        os.mkdir("/home/{}/Vault/".format(username))
    # checking if various files exist, and building them from copies if not
    so_file_exists = os.path.exists("/home/{}/.Revenant_source_code/Revenant.cpython-{}-x86_64-linux-gnu.so".format(username, version))
    if so_file_exists is False:
        with open("/home/{}/Revenant_install_files/Revenant.py".format(username), "rb") as file:
            source_file = file.read()
        with open("/home/{}/Revenant_install_files/Revenant_build.py".format(username), "rb") as file:
            build_file = file.read()
        with open("/home/{}/Revenant.pyx".format(username), "wb") as file:
            file.write(source_file)
        with open("/home/{}/Revenant_build.py".format(username), "wb") as file:
            file.write(build_file)
        os.system("python3 Revenant_build.py build_ext --inplace")
        shutil.rmtree("/home/{}/build".format(username))
        os.remove("/home/{}/Revenant.pyx".format(username))
        os.remove("/home/{}/Revenant.c".format(username))
        os.remove("/home/{}/Revenant_build.py".format(username))
        shutil.move("/home/{}/Revenant.cpython-{}-x86_64-linux-gnu.so".format(username, version), "/home/{}/.Revenant_source_code/".format(username))
    password_file_exists = os.path.exists("/home/{}/Revenant/.password.hash")
    if password_file_exists is False:
        password_hash = password_hasher(username, password)
        with open ("/home/{}/Revenant/.password.hash".format(username), 'w') as file:
            file.write(password_hash)
    userLog_exists = os.path.exists("/home/{}/Revenant/userLog.txt".format(username))
    if userLog_exists is False:
        with open("/home/{}/Revenant/userLog.txt".format(username), 'w') as file:
            file.write("User Log setup Completed.\n")
    icon_exists = os.path.exists("/home/{}/.Revenant_source_code/Revenant_icon.png".format(username))
    if icon_exists is False:
        with open("/home/{}/Revenant_install_files/Revenant_icon.png".format(username), "rb") as file:
            icon = file.read()
        with open("/home/{}/.Revenant_source_code/Revenant_icon.png".format(username), "wb") as file:
            file.write(icon)
    python_intializer_exists = os.path.exists("/home/{}/.Revenant_source_code/INT.py".format(username))
    if python_intializer_exists is False:
        with open("/home/{}/Revenant_install_files/INT.py".format(username), "rb") as file:
            intializer = file.read()
        with open("/home/{}/.Revenant_source_code/INT.py".format(username), "wb") as file:
            file.write(intializer)
    desktop_file_exists = os.path.exists("/home/{}/Desktop/Revenant_app.desktop".format(username))
    if desktop_file_exists is False:
        with open("/home/{}/Revenant_install_files/Revenant_app.desktop".format(username), 'rb') as file:
            desktop_file = file.read()
        with open("/home/{}/Desktop/Revenant_app.desktop".format(username), 'wb') as file:
            file.write(desktop_file)
    sg.popup_auto_close("File Dependencies successfully created, granting required permissions...", font="Helvetica")
    # doing file permissions
    os.system("chmod +rwx /home/{}/.Revenant_source_code/Revenant.cpython-{}-x86_64-linux-gnu.so".format(username, get_python_version()))
    os.system("chmod +rwx /home/{}/.Revenant_source_code/INT.py".format(username))
    os.system("chmod +rwx /home/{}/Desktop/Revenant_app.desktop".format(username))
    sg.popup_auto_close("permissions finalized, finish installation by selecting the desktop file and setting 'Allow Launching\n This Window will close after this popup.", font="Helvetica")

sg.theme("DarkBlue")
layout = [
    [sg.Text("Please enter your linux username.", font="Helvetica")],
    [sg.InputText(font="Helvetica", key="username", border_width=10)],
    [sg.Text("Please input your preferred password.", font="Helvetica")],
    [sg.InputText(password_char="*", font="Helvetica", key="password", border_width=10)],
    [sg.Button("OK", font="Helvetica", key="OK", border_width=10), sg.Button("Close Window", font="Helvetica", key="Close", border_width=10)]
]

window = sg.Window("Revenant Installer", layout, element_justification="C").Finalize()
window.Maximize()

while True:
    event, values = window.read()
    if event in (None, "Close"):
        break
    if event == "OK":
        username = values["username"]
        password = values["password"]
        file_dependencies_check(username, password)

