#   Author : Lourenco DaSilva
#   Purpose : Add user specific contacts to a contact list and log to an admin master file
#   ALT : Basis for managing contacts in Secure Drop

import os
import json
from network import get_online_users

CONTACTS_DIR = "contacts"
MASTER_CONTACTS_FILE = os.path.join(CONTACTS_DIR, "admin_master_contacts.json")

if not os.path.exists(CONTACTS_DIR):
    os.makedirs(CONTACTS_DIR)

if not os.path.exists(MASTER_CONTACTS_FILE):
    with open(MASTER_CONTACTS_FILE, "w") as f:
        json.dump({}, f, indent=4)

def get_user_contacts_file(username):
    return os.path.join(CONTACTS_DIR, f"{username}.json")

def add_contact(username):
    contacts_file = get_user_contacts_file(username)

    if not os.path.exists(contacts_file):
        with open(contacts_file, "w") as f:
            json.dump({}, f, indent=4)

    with open(contacts_file, "r") as f:
        contacts = json.load(f)

    contact_username = input("Enter the username of the contact: ").strip()
    contact_full_name = input("Enter the full name of the contact: ").strip()
    contact_email = input("Enter the email of the contact: ").strip()

    if contact_username in contacts:
        print(f"{contact_username} is already in your contacts.")
        return

    contacts[contact_username] = {
        "full_name": contact_full_name,
        "email": contact_email
    }
    with open(contacts_file, "w") as f:
        json.dump(contacts, f, indent=4)
    print(f"Contact '{contact_username}' added successfully to your personal contacts.")

    with open(MASTER_CONTACTS_FILE, "r") as f:
        master_contacts = json.load(f)

    master_contacts[f"{username}:{contact_username}"] = {
        "added_by": username,
        "contact_full_name": contact_full_name,
        "contact_email": contact_email
    }

    with open(MASTER_CONTACTS_FILE, "w") as f:
        json.dump(master_contacts, f, indent=4)

def list_contacts(username):
    contacts_file = get_user_contacts_file(username)
    if not os.path.exists(contacts_file):
        print("You have no contacts.")
        return

    with open(contacts_file, "r") as f:
        contacts = json.load(f)

    online_set = get_online_users()
    mutual_online = []

    for contact_username in contacts:
        contact_file = get_user_contacts_file(contact_username)
        if not os.path.exists(contact_file):
            continue
        with open(contact_file, "r") as f:
            their_contacts = json.load(f)
        if username in their_contacts and contact_username in online_set:
            mutual_online.append(contact_username)

    if not mutual_online:
        print("No contacts currently online.")
    else:
        print("The following contacts are online:")
        for user in mutual_online:
            details = contacts[user]
            print(f"* {user}: {details['full_name']} ({details['email']})")

def verify_contact(username):
    contacts_file = get_user_contacts_file(username)
    if not os.path.exists(contacts_file):
        print("You have no contacts.")
        return

    with open(contacts_file, "r") as f:
        contacts = json.load(f)

    contact_username = input("Enter the username of the contact to verify: ").strip()
    if contact_username in contacts:
        print(f"Contact '{contact_username}' exists.")
        print(f"Full Name: {contacts[contact_username]['full_name']}")
        print(f"Email: {contacts[contact_username]['email']}")
    else:
        print(f"Contact '{contact_username}' not found in your contacts.")

def admin_list(admin_username):
    if admin_username.lower() != "admin":
        print("Access denied. Only admin can view this file.")
        return

    with open(MASTER_CONTACTS_FILE, "r") as f:
        master_contacts = json.load(f)

    if not master_contacts:
        print("No contacts recorded in the admin file.")
        return

    print("Master Contact Log:")
    for key, details in master_contacts.items():
        added_by = details["added_by"]
        print(f"- {key} | Added by: {added_by} | {details['contact_full_name']} ({details['contact_email']})")

def admin_clear(admin_username):
    if admin_username.lower() != "admin":
        print("Access denied. Only admin can perform this action.")
        return

    confirm = input("Are you sure you want to clear the master contact log? (y/n): ").strip().lower()
    if confirm != "y":
        print("Operation cancelled.")
        return

    with open(MASTER_CONTACTS_FILE, "w") as f:
        json.dump({}, f, indent=4)
    print("Admin master contact log cleared.")
