import json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time

last_time_stamp = int(time.time())

def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return value.encode('ISO-8859-1')  # 返回bytes


def getPacket(des , message, public_key_test =''):
    if public_key_test == '':
        packet = {
            'des': des,
            'encry_key': public_key_test,
            'encry_text': message
        }
    else :
        encry_key, encry_text = encryption(message, public_key_test)
        packet = {
            'des': des,
            'encry_key': encry_key,
            'encry_text': encry_text
        }
        #print(packet['encry_text'])
    return json.dumps(packet)

def encryption(m, public_key_text):
    
    timestamp = int(time.time())
    timestamp_bytes = timestamp.to_bytes(8, byteorder="big")
    # 生成随机aes密钥
    aes_key = get_random_bytes(16)
    # print(aes_key)
    m = m.encode('ISO-8859-1')
    # m = add_to_16(m)
    aes = AES.new(aes_key,AES.MODE_ECB)
    encry_m = aes.encrypt(pad(m,16))
    
    combined_key = timestamp_bytes + aes_key

    public_key = RSA.import_key(public_key_text)
    encry_key = PKCS1_OAEP.new(public_key).encrypt(combined_key)

    #print(encry_key)
    #print(encry_m)

    encry_key = encry_key.decode('ISO-8859-1')
    encry_m = encry_m.decode('ISO-8859-1')

    return encry_key, encry_m

def decryption(encry_key, encry_text, private_key_text):

    encry_key = encry_key.encode('ISO-8859-1')
    encry_text = encry_text.encode('ISO-8859-1')

    #print(encry_key)
    #print(encry_text)

    private_key = RSA.import_key(private_key_text)
    combined_key = PKCS1_OAEP.new(private_key).decrypt(encry_key)

    extracted_timestamp = int.from_bytes(combined_key[:8], byteorder="big")
    aes_key = combined_key[8:]
    #print(aes_key)
    # base64_decrypted = base64.decodebytes(encry_text.encode(encoding='utf-8'))
    # decrypted_text = AES.new(aes_key,AES.MODE_ECB).decrypt(encry_key).decode('ISO-8859-1').replace('\0','')
    aes = AES.new(aes_key,AES.MODE_ECB)
    m = unpad(aes.decrypt(encry_text),16)
    #print(m)
    m = m.decode('ISO-8859-1')
    return m, extracted_timestamp


def getRSAKey():
    key = RSA.generate(1024)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

# def tess(public_key, private_key ,text):
