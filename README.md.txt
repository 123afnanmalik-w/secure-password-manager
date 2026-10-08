# Secure Password Manager

## Project

Cyber Security Internship – Project 2

## Objective

This project is a secure local password manager developed in Python. It stores website credentials in an encrypted vault.

## Features

* Master password protection
* AES-GCM encryption
* PBKDF2-HMAC-SHA256 key derivation
* Add password entries
* Search saved passwords
* Retrieve passwords
* Delete passwords
* Strong password generator
* Encrypted local storage

## Technologies Used

* Python
* Cryptography Library
* AES-GCM
* PBKDF2-HMAC-SHA256
* JSON

## Installation

Install the required library:

pip install cryptography

## How to Run

Run the following command:

python password_manager.py

## How It Works

First, the user creates a master password. The master password is used to derive an encryption key.

The password manager allows the user to add, search, retrieve and delete password entries.

The saved vault is encrypted before being stored in the local JSON file.

## Security

The password vault is encrypted using AES-GCM. A random salt is used with PBKDF2-HMAC-SHA256 to derive the encryption key from the master password.

## Project Structure

Password_Manager_Project/

* password_manager.py
* README.md
* screenshots/

## Note

Use dummy/test credentials when taking screenshots. Do not include real passwords or sensitive information.
