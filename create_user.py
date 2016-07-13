
import getpass

import database
from database import User
import config

db = database.db(config.database_url)

# get username
email = input("Enter username or email address: ")

# get password
password = None
while True:
    pass1 = getpass.getpass("Enter new password: ")
    pass2 = getpass.getpass("Enter password again: ")
    if pass1 == pass2:
        if len(pass2) < 2:  # TODO: expand this to 8+ characters
            print("Password should be at least 2 characters!")
        else:
            password = pass2
            break
    else:
        print("Passwords didn't match!")


user = db.create_user(email, password)

print(user)
