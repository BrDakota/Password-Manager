# Password Manager
This is a console application that will generate and store passwords securely. This application handles storage locally on a database on my laptop.

The procees is simple. The program prompts me for a master password on startup and before adding or accessing any passwords. Upon adding or accessing a service it also prompts me to enter an email. The email is not saved anywhere and is used for added security to all of my passwords.

Passwords were all secured using different encryption algorithms and hashing algorithms such as AES and PBKDF2.


This console application starts by greeting me because it was really developed for personal use. Everything is saved locally. The application will prompt me to enter my master password on startup.

https://github.com/user-attachments/assets/11da73c3-bc7e-439a-be74-a68651286b52

The console then provides 3 options for the user. The user can get a password, create a password, or exit the application. If the user chooses to get a password the user will be prompted to enter an email and to re-enter the master password for the added security. After entering these the user can enter the service they would like to access the password for. If the user does not enter the correct information the console will throw an exception and close the program.

https://github.com/user-attachments/assets/c3f2472f-db20-42c8-8d3d-393bd3b12ba3

If the user chooses to add a password then the user will be prompted to enter the service name, an email, and the master password again. After the information is recieved a random password will be generated before it is then encrypted and sent to the DB

https://github.com/user-attachments/assets/9b6d02f3-6b5f-4a86-ab88-b36a74dd5071
