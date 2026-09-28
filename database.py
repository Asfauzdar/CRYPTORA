import json
import os

DB_FILE = "data/users.json"


def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)


def add_user(username):
    users = load_users()
    if username in users:
        return False
    users[username] = {"username": username, "active": True}
    save_users(users)
    return True


def user_exists(username):
    return username in load_users()


def get_user(username):
    return load_users().get(username)


def revoke_user(username):
    users = load_users()
    if username not in users:
        return False
    users[username]["active"] = False
    save_users(users)
    return True
