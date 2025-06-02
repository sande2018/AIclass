from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# 设置密钥
key = b'turing20250319'  # 密钥长度必须是16、24或32字节
key = key.ljust(16, b'\0')  # 补齐到16字节

# 加密函数
def encrypt(plaintext):
    cipher = AES.new(key, AES.MODE_CBC)  # 使用CBC模式
    iv = cipher.iv  # 获取初始化向量
    padded_text = pad(plaintext.encode(), AES.block_size)  # 对明文进行填充
    ciphertext = cipher.encrypt(padded_text)  # 加密
    # 使用Base64 URL安全编码
    return base64.urlsafe_b64encode(iv + ciphertext).decode()+"_"

# 解密函数
def decrypt(ciphertext):
    ciphertext = ciphertext.rstrip("_")
    # 解码Base64 URL安全编码
    data = base64.urlsafe_b64decode(ciphertext)
    iv = data[:AES.block_size]  # 提取IV
    ciphertext = data[AES.block_size:]  # 提取密文
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)  # 使用相同的IV和密钥进行解密
    padded_text = cipher.decrypt(ciphertext)  # 解密
    plaintext = unpad(padded_text, AES.block_size).decode()  # 去除填充并解码为字符串
    return plaintext

# 测试
if __name__ == "__main__":
    # 明文
    plaintext = "Hello, Turing! This is a secret message."
    print("Original:", plaintext)

    # 加密
    encrypted_text = encrypt(plaintext)
    print("Encrypted:", encrypted_text)

    # 解密
    decrypted_text = decrypt(encrypted_text)
    print("Decrypted:", decrypted_text)