#   Author : Lourenco DaSilva (dslourenco22) 
#   Purpose : Adding people to a contacts list then verify them
#   ALT : We should change this up to have users have their own list that they use to verify against the master list

import json
import os

def load_contacts():
    if not os.path.exists("contacts.json"):
        return {}
    with open("contacts.json", "r") as f:
        return json.load(f)

def save_contacts(contacts):
    with open("contacts.json", "w") as f:
        json.dump(contacts, f, indent=4)

def add_contact():
    contacts = load_contacts()
    username = input("Enter Username: ")
    full_name = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    if username not in contacts:
        contacts[username] = {"full_name": full_name, "email": email}
        save_contacts(contacts)
        print("Contact Added.")
    else:
        print("Contact already exists.")

def verify_contact():
    contacts = load_contacts()
    username = input("Enter Username: ")
    if username in contacts:
        print("Contact Verified:")
        print(f"Name: {contacts[username]['full_name']}")
        print(f"Email: {contacts[username]['email']}")
    else:
        print("Contact not found.")

if __name__ == '__main__':
    print("SecureDrop Contact Manager")
    print("Add Contact")
    print("Verify Contact")
    print("(add/verify)")
    choice = input("Enter choice: ")
    if choice.lower() == "add":
        add_contact()
    elif choice.lower() == "verify":
        verify_contact()
    else:
        print("Invalid choice.")
