# Installation
1. Clone this repo or install main.py and requirements.txt
2. Install the libraries from requirements.txt with the specified versions.
3. Run main.py

# How to Use
Simply type `pwm` or `pwm --help` into the terminal to see the commands.

# How It Works
This program uses [end to end encryption](https://en.wikipedia.org/wiki/End-to-end_encryption); meaning the program itself doesn't know your master password, your login credentials. Your master password acts like a key for the encrypted vault created by python's built in [sqlite3](https://docs.python.org/3/library/sqlite3.html). The data inside of the `PasswordManager.db` makes no sense without your master password.

![Your data without your master password](https://imgur.com/TwwoQFH)
![Your data with your master password](https://imgur.com/3rrcwhU)

### How the program checks what your master password is without knowing what it is
The program asks for your master password when you launch the program for the very first time. When you input your password, the program stores the hashed version of your password, using your password as a "key" for hashing it. So that exact key has to be typed into the program to get to that specific hash which happens to be your master password. Someone else won't have the same hashed version as you either since that result is hashed together with something called "salt" making your version unique. Read more about salting in cryptography [here](https://en.wikipedia.org/wiki/Salt_(cryptography)).

# The Problem?
This program is almost impossible to crack, except for the fact that your master password could get compromised due to the fact that your master password is saved as a variable inside of the program (saved as `globalkey`). If a hacker were to read the memory of the program, they would know your master password, therefore having access to your login credentials, albeit highly unlikely. I'd recommend using this program for non-critical accounts, and not using the program for storing your banking/important info. I'd stick to established tools like Bitwarden or 1Password for high-stakes secrets.