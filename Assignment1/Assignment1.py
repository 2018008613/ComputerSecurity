from Crypto.Cipher import AES
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# plaintext를 입력받는다
plaintext = input('plaintext를 입력하시오 : ')

#대칭키 암호화 AES
print()
print("--------------------")
print("대칭 키 암호화 AES")
print("--------------------")

AES_data = plaintext
#padding 수행
#마지막 블럭이 16바이트, 즉 64비트의 크기를 가지도록 부족한 칸을 chr(addtext)로 채워준다
addtext = 16 - (len(AES_data) % 16)
if addtext == 16:
        addtext = 0
AES_data += chr(addtext) * addtext

#16/24/32글자인 key 값을 입력할 때까지 입력받는다
key = 0
while True:
    key = input('key 값을 입력하시오(16/24/32 글자 중 선택하여 입력) : ')
    if len(key) == 16 or len(key) == 24 or len(key) == 32:
        break;
    else:
        print("ERROR! 16/24/32 글자 중 선택하여 입력하시오")

#AES_data와 key를 byte로 변환한다
AES_data = AES_data.encode()
key = key.encode()

#암호화한 것을 ciphertext 변수에 저장한다
encrypt = AES.new(key, AES.MODE_EAX)
nonce = encrypt.nonce
ciphertext, tag = encrypt.encrypt_and_digest(AES_data)

#암호화한 것을 출력한다
print("암호화 :", ciphertext)

#복호화한 것을 cipher_to_plain 변수에 저장해준다
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
cipher_to_plain = cipher.decrypt(ciphertext)

#바이트를 문자열로 변환해준다
cipher_to_plain = cipher_to_plain.decode()

#만약 padding 수행을 통해 원래 문서 뒤에 추가적인 문자를 추가했다면 복호화 후
#이 문자들을 제거해준다
if addtext != 0:
    cipher_to_plain = cipher_to_plain[:-addtext]
print("복호화 :", cipher_to_plain)


print()

#hash 함수 SHA256

print("--------------------")
print("hash 함수 SHA256")
print("--------------------")

#plaintext를 byte로 바꾸어준다
hash_data = plaintext.encode()

#SHA256 객체를 생성한다.
sha = hashlib.new('sha256')

#hash 값을 hashvalue에 저장한 후 출력해준다.
sha.update(hash_data)
hashvalue = sha.hexdigest()
print ('해시값 :', hashvalue)

print()

#비대칭키 암호화 RSA

print("--------------------")
print("비대칭키 암호화 RSA")
print("--------------------")

#plaintext를 RSA_data에 넣은 뒤 byte로 변환한다
RSA_data = plaintext
RSA_data = RSA_data.encode()

key_len = 0
#1024글자 이상의 key 길이를 입력할 때까지 입력받는다. 2048글자를 권장.
while True:
    key_len = int(input("key 길이를 입력하세요(1024이상, 2048 권장) : "))
    if key_len < 1024:
        print("ERROR! 1024 이상의 수를 입력하시오")
    else:
        break;

#입력받은 key 길이에 맞는 public key와 private key를 생성한다. private key의 비밀번호를 sangwook으로 설정함
keypair = RSA.generate(key_len)
public_key = keypair.publickey()
private_key = keypair.export_key(passphrase = 'sangwook')

#public key를 이용해 암호화하여 encrypted 변수에 저장한 뒤 출력해준다.
encryptor = PKCS1_OAEP.new(public_key)
encrypted = encryptor.encrypt(RSA_data)
print("암호화 :", encrypted)

#private key를 이용해 encrypted를 복호화하여 decrypted 변수에 저장한 뒤 바이트를 문자열로 바꾼 후 출력해준다.
private_key = RSA.importKey(private_key, passphrase = 'sangwook')
decryptor = PKCS1_OAEP.new(private_key)
decrypted = decryptor.decrypt(encrypted)
decrypted = decrypted.decode()
print("복호화 :", decrypted)
