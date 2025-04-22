import rsa
import base64
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def base64Encode(str):
    string_bytes = str.encode('utf-8')
    # Encode to Base64
    base64_encoded = base64.b64encode(string_bytes)
    # Convert Base64 bytes back to string
    plain_text = base64_encoded.decode('utf-8')
    return plain_text


def rsaEncrypt(plaintext, key, mode="RSA/ECB/NoPadding"):
    if mode == "RSA/ECB/NoPadding":
        # 无填充加密（padding=None）
        public_key = RSA.importKey(base64.b64decode(key))
        kLen = rsa.common.byte_size(public_key.n)
        _b = rsa.transform.bytes2int(base64.b64decode(plaintext))
        _i = rsa.core.encrypt_int(_b, public_key.e, public_key.n)
        result = rsa.transform.int2bytes(_i, kLen)
        return base64.b64encode(result)
    elif mode == "RSA/ECB/OAEPWithSHA1AndMGF1Padding":
        public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"
        # Decode the public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        #初始化 OAEP 填充（默认 SHA1 + MGF1 SHA1）
        rsa_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),  # 掩码生成函数
            algorithm=hashes.SHA1(),  # 主哈希算法
            label=None  # 一般留空
        )
        result = public_key.encrypt(base64.b64decode(plaintext), rsa_padding)
        return base64.b64encode(result)



def rsaDecrypt(encryptText, key, mode="RSA/ECB/NoPadding"):
    if mode == "RSA/ECB/NoPadding":
        private_key = RSA.importKey(base64.b64decode(key))
        kLen = rsa.common.byte_size(private_key.n)
        _b = rsa.transform.bytes2int(base64.b64decode(encryptText))
        _i = rsa.core.decrypt_int(_b, private_key.d, private_key.n)
        result = rsa.transform.int2bytes(_i, kLen)
        return base64.b64decode(base64.b64encode(result))
    elif mode == "RSA/ECB/OAEPWithSHA1AndMGF1Padding":
        private_key = f"-----BEGIN PRIVATE KEY-----\n{key}\n-----END PRIVATE KEY-----"
        # Decode the public key
        private_key = serialization.load_pem_private_key(private_key.encode('utf-8'),password=None)
        # 初始化 OAEP 填充（默认 SHA1 + MGF1 SHA1）
        rsa_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),  # 掩码生成函数
            algorithm=hashes.SHA1(),  # 主哈希算法
            label=None  # 一般留空
        )
        result = private_key.decrypt(base64.b64decode(encryptText), rsa_padding)
        return base64.b64decode(base64.b64encode(result))





if __name__ == '__main__':
    privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCoPAb29yDwogN4icz8jbpdE/LU\n37Fg26McWxbFUAWtgR7hKfRctIrD38fAO7qzkoXt2/BLIlbyZN5vTrQxZ4MtfYMrpg8dAZ0rm4Lb\nTjVAAbILsxf33E0v+Sqko5PqXHbW+1rk9mT+mohb9Kso9A5yEbhehT0Q9GM8JYw8j6DlBQ9SJb9d\nBmFhycvUoJj7EA/PTzKPIcE6uwBuvUkRaBVn8VYaDxibxT85CKZ0gzRdTYu2HBTtNFizDPdgUZtV\nMkMBsMNcZ1ATmFzNEelsjxrJB8fyFRtWYZ8V/9+dUAJKWm4WwvnQ3basfPAOqxLOJfXL+qpHEEGs\nriu0+R/RxjhpAgMBAAECggEACazuH50F8CD5PyD5wPABGbel0yK3B7bfZ32WToHJhHmKcPEMme+o\n6Bas3SbyQr/4uOiEe5BoMhJQDVRtnkZxmmz/XW7JrBA63auuInZvLz+0YYzgIi6xjRfw9mgRVTy9\nJE8aIqnzFAYyNSEEs7Bu9kDY+tgB3kGX8CPJWsr4j23w775+8dzNzvhOxBYK0eO+U1SMXc7YLac6\njuDCUUpodWLvakvnzg8w5tsg3XGIc30iWUiMx8UNvizBBYSVlxjLnc8DkUANrqIHCyG9jqWjAYqD\n5Otpby3eTTIpFHE+pBq7ZL05D667htoIXGFklVwHFZSEdk378uLLLwsZIjsoewKBgQDixhjvnWF5\nn8Nbvht7dKkjzatckFx9rj5jxCW5Kr+mbJQ5WhvjkCFSicrFNWWZnVi8y/erOYsRMHi4BbZ3zN67\n4i/HAYvl/W9JT4sbwPH2tlTCu53c8tb5ugJM5msD4sjGpxK6ApROzb7vNdbeQlcHhoJDeEkqvWIE\n5bKjKPZ52wKBgQC96o2nQWvl3DYobcOqDhy9OjyhUnHE4Qe9+UFY/vr+06Y61W+j5HwpCgaCrNAG\nYM56jYePS9LVevYD/xatVDSwbwdclDT4i+J8BNwNXSdS+IDpVhKnS7FOBZOq904yCJ1hsjr6I1vP\nHQU2vFeTTKK4DY3oFPzL9d6DcLk5ltO0CwKBgF7xLRN0wpCXEMViLENdrkqtGudgETkVME24m0qQ\n2TgmEVCJp0940lqqEdjK6ESOGc7BXmmzZ8PElWYGDkTN4xqqMfKRdS7PEj6RLN5rw2HVKFt3DTqp\n+NMIy1nCxl8UHZb979sspUbw4NVppxHamHEwIW15+LgKHfWK7WVeCwMtAoGAJte+OSMsSksL2KD6\nj+FrB1jN5cDS/A16Y+SC9QzRkSUArq/QsZidvFcMldV6hpNuJ6qiuzAq4vbPMmoN3U2HqT5MJyc4\n3kzd+beUujb/P/0LgK3WCtl0XhzN4v3JxHn2lnC5l0d8E5Q/6L4Eu1/FOBetmnYQbjbPV9rKR3kN\nu5kCgYEAkjo92KXua3XG7dedsvvEZNXMWRBKwyFjAFtY36jx/3quzD50s9/Ftc/m2/iLZPm1a6vC\n4MpDxmiUCPLxE2RVU/muzEOfz50vmtach2NmYqChMu0Q4faGVpYxLvFr4QTYxhj/qI8Vdd5Xgu/Z\nl7mdBOH0K3lErsji9MQ6AUks454="
    publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqDwG9vcg8KIDeInM/I26XRPy1N+xYNuj\nHFsWxVAFrYEe4Sn0XLSKw9/HwDu6s5KF7dvwSyJW8mTeb060MWeDLX2DK6YPHQGdK5uC2041QAGy\nC7MX99xNL/kqpKOT6lx21vta5PZk/pqIW/SrKPQOchG4XoU9EPRjPCWMPI+g5QUPUiW/XQZhYcnL\n1KCY+xAPz08yjyHBOrsAbr1JEWgVZ/FWGg8Ym8U/OQimdIM0XU2LthwU7TRYswz3YFGbVTJDAbDD\nXGdQE5hczRHpbI8ayQfH8hUbVmGfFf/fnVACSlpuFsL50N22rHzwDqsSziX1y/qqRxBBrK4rtPkf\n0cY4aQIDAQAB"
    text = "Hello, Base64 encoding!"
    # Convert string to bytes
    plain_text = base64Encode(text)


    print("Base64 Encoded String:", plain_text)
    rsaPaddingText = "XyLNjqmBFRpNP9cOU6VNHsTIxN7WCChji7fizN2tsFVMOoch5L8YIkXfW5tdXIez3w0T3xjL8FVXeO7pnPm+qQ4w9/4kkkLA1vbtLwqn4qMqNv6szyqZEZO5frzTIsEYtq8HR+b/3h3gSgnmHSs99lQbbBhRlrNvGOA3gFdBcH7USAtY29Ima/wcaIGiQ+kj5TksEDJ1Fg/ZjhrMwNrCRomKVfLjSLQDJBjwtW6zVCauTTCZKILHwXVmyP6mNdclX1kbFZl2cbUuRj7ZX/Z5pj9Aock9OvH/IhjaPWDtU/ymi76cXi5azATkYLDgOGXwZ3xXXtcZleSqN6HsAThjYg==";
    rsaNoPaddingText = "UbmKbVqpOdYE8IiRkrqUSDvBn30/7l6/VvM/NSphAn5WlPuJAn6f7m0XkJlxHsVdmw3HvEXgpDbmnJcydJxv/5p5nbs8jsSkowbSUui+DdGB+HHWxLdXiFDmpykVqLV3C9unJ2RLa0bYOjgcSDoAhL7xpaLaXS8fcHKin+1XpQfwztGxyUC+PqPPohNBf3CB9HqDbeYfCPFDpcBi7GaUNqbV938Wo4fVp3bp5UvzOv1qsiLunpYVhDdNRFFI1b82J8Ubbe3bubI2YFJYE4pxXks6QXPHibB7YIFFi5BRE444Ojbtwn20v8IPwsBHiBwjIX+f3o7G9rJYInjCCP+MkA==";
    mode1 = "RSA/ECB/OAEPWithSHA1AndMGF1Padding"
    mode2 = "RSA/ECB/NoPadding"
    print(rsaEncrypt(plain_text, publicKey,mode1))
    print(rsaDecrypt(rsaEncrypt(plain_text, publicKey,mode1), privateKey,mode1))
    print(rsaEncrypt(plain_text, publicKey,mode2))
    print(rsaDecrypt(rsaEncrypt(plain_text, publicKey,mode2), privateKey,mode2))

    # Encrypt the plaintext using the public key
