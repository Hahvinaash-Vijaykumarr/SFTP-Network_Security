# 50.005 Programming Assignment 2

This assignment requires knowledge from Network Security and basic knowledge in Python.

## Secure FTP != HTTPs

Note that you will be implementing Secure FTP as your own whole new application layer protocol. In NO WAY we are relying on HTTP/s. Please do not confuse the materials, you don't need to know materials in Week 11 and 12 before getting started.

## Running the code

### Install required modules

This assignment requires Python >3.10 to run.

You can use `pipenv` to create a new virtual environment and install your modules there. If you don't have it, simply install using pip, (assuming your python is aliased as python3):

```
python3 -m pip install pipenv
```

Then start the virtual environment, upgrade pip, and install the required modules:

```
pipenv shell
python -m ensurepip --upgrade
pip install -r requirements.txt
```

If `ensurepip` is not available, you need to install it, e.g with Ubuntu:

```
# Adjust for your python version
sudo apt-get install python3.10-venv
```

### Run `./cleanup.,sh`

Run this in the root project directory:

```
chmod +x ./cleanup.sh
./cleanup.sh
```

This will create 3 directories: `/recv_files`, `/recv_files_enc`, and `/send_files_enc` in project's root. They are all empty directories that can't be added in `.git`.

### Run server and client files

In two separate shell sessions, run (assuming you're in root project directory):

```
python3 source/ServerWithoutSecurity.py
```

and:

```
python3 source/ClientWithoutSecurity.py
```

### Using different machines

You can also host the Server file in another computer:

```sh
python3 source/ServerWithoutSecurity.py [PORT] 0.0.0.0
```

The client computer can connect to it using the command:

```sh
python3 source/ClientWithoutSecurity.py [PORT] [SERVER-IP-ADDRESS]
```

### Exiting pipenv shell

To exit pipenv shell, simply type:

```
exit
```

## Sustainability and Inclusivity Considerations
Sustainability
Efficient Data Handling: The client compresses files before sending them to reduce bandwidth usage and storage requirements on the server.
Inclusivity
User-Friendly Interface: The client application prompts users for input in a straightforward manner and allows them to select text colours to:
Tackle colour-blindness.
Allow users to personalise their experience
Clear Instructions: The code provides clear error messages and feedback 



