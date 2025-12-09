import user
import verify
import welcome
from network import start_network
from contactmanage import (
    add_contact,
    list_contacts,
    verify_contact,
    admin_list,
    admin_clear
)
import os
import sys
import time
import pwinput

def goodbye_msg(username):
    print(f"\n[INFO] Logging out {username}...")
    print("[INFO] You have been removed from discovered users.")
    time.sleep(0.5)
    print("[INFO] Thank you for using Secure Drop! Goodbye!")
    sys.exit(0)

command_map = {
    "add": add_contact,
    "list": list_contacts,
    "verify": verify_contact,
    "admin_list": admin_list,
    "admin_clear": admin_clear,
    "clear": lambda _: os.system("clear"),
    "exit": lambda username: goodbye_msg(username)
}

def login():
    log_user = input("Enter Username: ")
    log_pwd = pwinput.pwinput(prompt="Enter Password: ", mask='*')
    return verify.verify(log_user, log_pwd)

def login_or_register():
    choice = input("Would you like to (l)ogin (r)egister or (e)xit?").strip().lower()
    if choice == 'l':
        return login()
    elif choice == 'r':
        return user.add_user()
    elif choice == 'e':
        sys.exit(0)
    
def main_cli(username):
    while True:
        try:
            cmd = input(f"{username}@SecureDrop> ").strip()
            if cmd in command_map:
                command_map[cmd](username)
            elif cmd == "help":
                    print("Available commands: add, list, verify, clear, exit")
                    if username.lower() == "admin":
                        print("admin_list, admin_clear")
            elif cmd == "":
                continue
            else:
                print(f"Unknown command: {cmd}. Type 'help' for a list of commands.")
        except KeyboardInterrupt:
            goodbye_msg(username)
    
if __name__ == "__main__":
    username = login_or_register()
    welcome.welcome_msg(username)
    start_network(username)
    
    main_cli(username)
