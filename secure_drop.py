import os
import sys
import time
import hashlib
import pwinput

import user
import verify
import welcome
from network import start_network
from messaging import start_file_listener, input_lock
from contactmanage import add_contact, list_contacts, verify_contact, admin_list, admin_clear


def compute_user_port(username):
    base = 51000
    h = int(hashlib.sha256(username.encode()).hexdigest(), 16)
    return base + (h % 1000)


def goodbye_msg(username):
    print(f"\n[INFO] Logging out {username}...")
    time.sleep(0.5)
    print("[INFO] Thank you for using SecureDrop!")
    sys.exit(0)

def print_help(username):
    print("Available commands:")
    print("  add - Add a contact")
    print("  list - List online contacts")
    print("  verify - Verify a contact")
    if username == "admin":
        print("  admin_list - List all users (admin only)")
        print("  admin_clear - Clear all users (admin only)")
    print("  clear - Clear the terminal")
    print("  exit - Exit SecureDrop")
    print("  send <user> <file> - Send a file to a user")

command_map = {
    "add": lambda u, *a: add_contact(u),
    "list": lambda u, *a: list_contacts(u),
    "verify": lambda u, *a: verify_contact(u),
    "help": lambda u, *a: print_help(u),
    "admin_list": lambda u, *a: admin_list(u),
    "admin_clear": lambda u, *a: admin_clear(u),
    "clear": lambda u, *a: os.system("clear"),
    "exit": lambda u, *a: goodbye_msg(u),
    "send": lambda u, *a: __import__("messaging").send_file_command(u, *a),
}


def login():
    usern = input("Enter Username: ")
    pwd = pwinput.pwinput("Enter Password: ", mask="*")
    return verify.verify(usern, pwd)


def login_or_register():
    while True:
        choice = input(
            "Would you like to (l)ogin (r)egister or (e)xit? ").strip()
        if choice == "l":
            return login()
        elif choice == "r":
            new = user.add_user()
            if new:
                return new
        elif choice == "e":
            sys.exit(0)
        print("Please enter 'l', 'r', or 'e'.")


def main_cli(username):
    while True:
        try:
            # Wait for lock — prevents accepting input during file prompt
            with input_lock:
                raw = input(f"{username}@SecureDrop> ").strip()

            if not raw:
                continue

            parts = raw.split()
            cmd, args = parts[0], parts[1:]

            handler = command_map.get(cmd)
            if handler:
                handler(username, *args)
            else:
                print("Unknown command:", cmd)

        except KeyboardInterrupt:
            goodbye_msg(username)


if __name__ == "__main__":
    username = login_or_register()
    welcome.welcome_msg(username)

    USER_PORT = compute_user_port(username)

    start_network(username, USER_PORT)
    start_file_listener(username, USER_PORT)

    main_cli(username)
