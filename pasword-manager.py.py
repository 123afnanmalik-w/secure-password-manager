import os
import json
import base64
import secrets
import string

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# SECURE PASSWORD MANAGER
# Cyber Security Internship - Project 2
# ============================================================

VAULT_FILE = "password_vault.json"

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000


# ============================================================
# 1. DERIVE ENCRYPTION KEY
# ============================================================

def derive_key(master_password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )

    return kdf.derive(master_password.encode("utf-8"))


# ============================================================
# 2. ENCRYPT VAULT
# ============================================================

def encrypt_vault(vault, key):

    plaintext = json.dumps(vault).encode("utf-8")

    # Random nonce for AES-GCM
    nonce = secrets.token_bytes(NONCE_SIZE)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    return nonce, ciphertext


# ============================================================
# 3. DECRYPT VAULT
# ============================================================

def decrypt_vault(nonce, ciphertext, key):

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return json.loads(
        plaintext.decode("utf-8")
    )


# ============================================================
# 4. SAVE ENCRYPTED VAULT
# ============================================================

def save_vault(vault, key, salt):

    nonce, ciphertext = encrypt_vault(
        vault,
        key
    )

    encrypted_data = {

        "salt": base64.b64encode(
            salt
        ).decode("utf-8"),

        "nonce": base64.b64encode(
            nonce
        ).decode("utf-8"),

        "data": base64.b64encode(
            ciphertext
        ).decode("utf-8")
    }

    with open(
        VAULT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            encrypted_data,
            file,
            indent=4
        )

    # Restrict file permissions where supported
    try:
        os.chmod(
            VAULT_FILE,
            0o600
        )
    except OSError:
        pass


# ============================================================
# 5. LOAD VAULT
# ============================================================

def load_vault(master_password):

    if not os.path.exists(VAULT_FILE):
        return None, None, None

    try:

        with open(
            VAULT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            encrypted_data = json.load(file)

        salt = base64.b64decode(
            encrypted_data["salt"]
        )

        nonce = base64.b64decode(
            encrypted_data["nonce"]
        )

        ciphertext = base64.b64decode(
            encrypted_data["data"]
        )

        # Generate key from master password
        key = derive_key(
            master_password,
            salt
        )

        # Decrypt data
        vault = decrypt_vault(
            nonce,
            ciphertext,
            key
        )

        return vault, key, salt

    except Exception:

        return None, None, None


# ============================================================
# 6. CREATE NEW VAULT
# ============================================================

def create_vault():

    print("\n========================================")
    print("        CREATE PASSWORD VAULT")
    print("========================================")

    while True:

        master_password = input(
            "Create master password: "
        )

        if len(master_password) < 8:

            print(
                "Master password must be at least 8 characters."
            )

            continue

        confirm_password = input(
            "Confirm master password: "
        )

        if master_password != confirm_password:

            print(
                "Passwords do not match."
            )

            continue

        break

    # Generate random salt
    salt = secrets.token_bytes(
        SALT_SIZE
    )

    # Generate encryption key
    key = derive_key(
        master_password,
        salt
    )

    # Empty vault
    vault = []

    # Save encrypted vault
    save_vault(
        vault,
        key,
        salt
    )

    print(
        "\nVault created successfully!"
    )

    return vault, key, salt


# ============================================================
# 7. ADD PASSWORD
# ============================================================

def add_entry(vault):

    print("\n========================================")
    print("             ADD PASSWORD")
    print("========================================")

    website = input(
        "Website/App: "
    ).strip()

    username = input(
        "Username/Email: "
    ).strip()

    password = input(
        "Password: "
    )

    if not website:

        print(
            "Website cannot be empty."
        )

        return

    if not username:

        print(
            "Username cannot be empty."
        )

        return

    if not password:

        print(
            "Password cannot be empty."
        )

        return

    entry = {

        "id": secrets.token_hex(8),

        "website": website,

        "username": username,

        "password": password
    }

    vault.append(entry)

    print(
        "\nPassword added successfully!"
    )


# ============================================================
# 8. SEARCH PASSWORD
# ============================================================

def search_entries(vault):

    print("\n========================================")
    print("           SEARCH PASSWORD")
    print("========================================")

    keyword = input(
        "Enter website or username: "
    ).strip().lower()

    if not keyword:

        print(
            "Search keyword cannot be empty."
        )

        return

    results = []

    for entry in vault:

        website = entry["website"].lower()

        username = entry["username"].lower()

        if (
            keyword in website
            or keyword in username
        ):

            results.append(entry)

    if not results:

        print(
            "\nNo matching entries found."
        )

        return

    print("\nMatching Entries:")

    for index, entry in enumerate(
        results,
        start=1
    ):

        print(
            f"{index}. "
            f"{entry['website']} | "
            f"{entry['username']}"
        )


# ============================================================
# 9. RETRIEVE PASSWORD
# ============================================================

def retrieve_entry(vault):

    print("\n========================================")
    print("          RETRIEVE PASSWORD")
    print("========================================")

    keyword = input(
        "Enter website or username: "
    ).strip().lower()

    results = []

    for entry in vault:

        if (
            keyword in entry["website"].lower()
            or
            keyword in entry["username"].lower()
        ):

            results.append(entry)

    if not results:

        print(
            "\nNo matching entry found."
        )

        return

    print("\nMatching Entries:")

    for index, entry in enumerate(
        results,
        start=1
    ):

        print(
            f"{index}. "
            f"{entry['website']} | "
            f"{entry['username']}"
        )

    try:

        choice = int(
            input(
                "\nSelect entry number: "
            )
        )

        if (
            choice < 1
            or
            choice > len(results)
        ):

            print(
                "Invalid selection."
            )

            return

        selected = results[
            choice - 1
        ]

        print("\n--------------------------------")
        print(
            "Website :",
            selected["website"]
        )
        print(
            "Username:",
            selected["username"]
        )
        print(
            "Password:",
            selected["password"]
        )
        print("--------------------------------")

    except ValueError:

        print(
            "Please enter a valid number."
        )


# ============================================================
# 10. DELETE PASSWORD
# ============================================================

def delete_entry(vault):

    print("\n========================================")
    print("           DELETE PASSWORD")
    print("========================================")

    keyword = input(
        "Enter website or username: "
    ).strip().lower()

    results = []

    for entry in vault:

        if (
            keyword in entry["website"].lower()
            or
            keyword in entry["username"].lower()
        ):

            results.append(entry)

    if not results:

        print(
            "\nNo matching entry found."
        )

        return

    print("\nMatching Entries:")

    for index, entry in enumerate(
        results,
        start=1
    ):

        print(
            f"{index}. "
            f"{entry['website']} | "
            f"{entry['username']}"
        )

    try:

        choice = int(
            input(
                "\nSelect entry to delete: "
            )
        )

        if (
            choice < 1
            or
            choice > len(results)
        ):

            print(
                "Invalid selection."
            )

            return

        selected = results[
            choice - 1
        ]

        confirmation = input(
            f"Delete '{selected['website']}'? (y/n): "
        ).lower()

        if confirmation == "y":

            vault.remove(
                selected
            )

            print(
                "\nEntry deleted successfully."
            )

        else:

            print(
                "\nDelete cancelled."
            )

    except ValueError:

        print(
            "Please enter a valid number."
        )


# ============================================================
# 11. GENERATE STRONG PASSWORD
# ============================================================

def generate_password(length):

    characters = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    password = ""

    for _ in range(length):

        password += secrets.choice(
            characters
        )

    return password


# ============================================================
# 12. PASSWORD GENERATOR MENU
# ============================================================

def password_generator():

    print("\n========================================")
    print("         STRONG PASSWORD GENERATOR")
    print("========================================")

    try:

        length = int(
            input(
                "Enter password length (minimum 12): "
            )
        )

        if length < 12:

            print(
                "Password length must be at least 12."
            )

            return

        password = generate_password(
            length
        )

        print(
            "\nGenerated Password:"
        )

        print(
            password
        )

    except ValueError:

        print(
            "Please enter a valid number."
        )


# ============================================================
# 13. MAIN PROGRAM
# ============================================================

def main():

    print("\n")
    print("========================================")
    print("       SECURE PASSWORD MANAGER")
    print("========================================")

    # Check if vault already exists
    if os.path.exists(VAULT_FILE):

        print(
            "\nEncrypted vault found."
        )

        master_password = input(
            "Enter master password: "
        )

        vault, key, salt = load_vault(
            master_password
        )

        if vault is None:

            print(
                "\nIncorrect master password!"
            )

            print(
                "Vault could not be decrypted."
            )

            return

        print(
            "\nVault unlocked successfully!"

        )

    else:

        vault, key, salt = create_vault()

    # Main menu
    while True:

        print("\n")
        print("========================================")
        print("               MAIN MENU")
        print("========================================")

        print(
            "1. Add Password"
        )

        print(
            "2. Search Password"
        )

        print(
            "3. Retrieve Password"
        )

        print(
            "4. Delete Password"
        )

        print(
            "5. Generate Strong Password"
        )

        print(
            "6. Save Vault"
        )

        print(
            "7. Exit"
        )

        print(
            "========================================"
        )

        choice = input(
            "Enter your choice: "
        ).strip()

        # ------------------------------------
        # ADD
        # ------------------------------------

        if choice == "1":

            add_entry(
                vault
            )

            save_vault(
                vault,
                key,
                salt
            )

        # ------------------------------------
        # SEARCH
        # ------------------------------------

        elif choice == "2":

            search_entries(
                vault
            )

        # ------------------------------------
        # RETRIEVE
        # ------------------------------------

        elif choice == "3":

            retrieve_entry(
                vault
            )

        # ------------------------------------
        # DELETE
        # ------------------------------------

        elif choice == "4":

            delete_entry(
                vault
            )

            save_vault(
                vault,
                key,
                salt
            )

        # ------------------------------------
        # PASSWORD GENERATOR
        # ------------------------------------

        elif choice == "5":

            password_generator()

        # ------------------------------------
        # SAVE
        # ------------------------------------

        elif choice == "6":

            save_vault(
                vault,
                key,
                salt
            )

            print(
                "\nVault saved successfully!"
            )

        # ------------------------------------
        # EXIT
        # ------------------------------------

        elif choice == "7":

            save_vault(
                vault,
                key,
                salt
            )

            print(
                "\nVault saved successfully."
            )

            print(
                "Thank you for using Secure Password Manager!"
            )

            break

        # ------------------------------------
        # INVALID
        # ------------------------------------

        else:

            print(
                "\nInvalid choice!"
            )

            print(
                "Please select 1-7."
            )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    main()
