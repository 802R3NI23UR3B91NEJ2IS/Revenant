import os


def remove_source_code(username=str):
    os.rmdir("/home/{}/.Revenant_source_code/".format(username))
    return 0


def remove_public_files(username=str):
    os.rmdir("/home/{}/Revenant".format(username))
    exit_code = remove_source_code(username)
    return exit_code


def remove_desktop_file(username=str):
    os.remove("/home/{}/Desktop/Revenant_app.desktop".format(username))
    exit_code = remove_public_files(username)
    return exit_code

username = str(input("Please enter your linux username."))
exit_code = remove_desktop_file(username)
if exit_code == 0:
    print("Uninstall complete. Dependencies (such as libraries) were not removed.")
else:
    print("Uninstall process did not complete.")