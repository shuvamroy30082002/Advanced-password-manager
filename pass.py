
import os
import getpass
import hashlib

def set_password_file_password():
  # Prompt the user for the new password
  password = getpass.getpass("Enter the new password for the password file: ")
  confirm_password = getpass.getpass("Confirm the new password: ")

  # Check that the passwords match
  if password != confirm_password:
    print("Error: Passwords do not match.")
    return

  # Hash the password using SHA-256
  hashed_password = hashlib.sha256(password.encode()).hexdigest()

  # Check if the file exists, create it if it doesn't
  if not os.path.exists('password_file.txt'):
    open('password_file.txt', 'w').close()

  # Write the hashed password to the file
  with open('password_file.txt', 'w') as f:
    f.write(hashed_password)

def store_password(website, username, password):
  # Prompt the user for the password file password
  password_file_password = getpass.getpass("Enter the password for the password file: ")

  # Check the password file password
  with open('password_file.txt', 'r') as f:
    hashed_password_file_password = f.read()
    if hashlib.sha256(password_file_password.encode()).hexdigest() != hashed_password_file_password:
      print("Error: Incorrect password for the password file.")
      return

  # Hash the website password using SHA-256
  hashed_password = hashlib.sha256(password.encode()).hexdigest()

  # Append the hashed password to the file
  with open('password_file.txt', 'a') as f:
    f.write(f'{website}:{username}:{hashed_password}\n')

def get_password(website):
  # Prompt the user for the password file password
  password_file_password = getpass.getpass("Enter the password for the password file: ")

  # Check the password file password
  with open('password_file.txt', 'r') as f:
    hashed_password_file_password = f.readline()
    if hashlib.sha256(password_file_password.encode()).hexdigest() != hashed_password_file_password.strip():
      print("Error: Incorrect password for the password file.")
      return

  # Read the file and search for the matching website
  with open('password_file.txt', 'r') as f:
    for line in f:
      website_, username, hashed_password = line.strip().split(':')
      if website_ == website:
        # Prompt the user for their password
        password = getpass.getpass(f"Enter the password for {username} on {website}: ")

        # Hash the password the user entered and compare it to the stored hash
        if hashlib.sha256(password.encode()).hexdigest() == hashed_password:
          print("Correct password")
        else:  print("Incorrect password")


# Example usage
set_password_file_password()
store_password('gmail.com', 'user@gmail.com', 'mypassword')
store_password('twitter.com', 'user@twitter.com', 'mypassword')
get_password('gmail.com')
get_password('twitter.com')

