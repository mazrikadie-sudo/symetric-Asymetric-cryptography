import os, hashlib, sys

# ================= CRYPTO CORE =================

def stretch_key(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, 32)

def chaos_stream(key, length):
    stream = bytearray()
    seed = key
    for _ in range(length):
        seed = hashlib.sha256(seed).digest()
        stream.append(seed[0])
    return stream

def encrypt(data: bytes, password: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = stretch_key(password, salt + iv)
    chaos = chaos_stream(key, len(data))

    out = bytearray()
    for i, b in enumerate(data):
        shift = (chaos[i] + i*i) % 256
        out.append((b + shift) % 256)

    return salt + iv + out

def decrypt(cipher: bytes, password: str):
    salt, iv, body = cipher[:16], cipher[16:32], cipher[32:]
    key = stretch_key(password, salt + iv)
    chaos = chaos_stream(key, len(body))

    out = bytearray()
    for i, b in enumerate(body):
        shift = (chaos[i] + i*i) % 256
        out.append((b - shift) % 256)

    return bytes(out)

# ================= CLI TOOL =================

def main():
    print("🔐 CAESAR-X SECURE TOOL")
    print("1) Encrypt text")
    print("2) Decrypt text")
    choice = input("Choose: ").strip()

    password = input("Password: ")

    if choice == "1":
        text = input("Enter plaintext: ").encode()
        cipher = encrypt(text, password)
        print("\nEncrypted (HEX):")
        print(cipher.hex())

    elif choice == "2":
        hexdata = input("Enter HEX cipher: ").strip()
        cipher = bytes.fromhex(hexdata)
        plain = decrypt(cipher, password)
        print("\nDecrypted:")
        print(plain.decode(errors="ignore"))

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()

