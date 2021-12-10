from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import sys
import chilkat


stores = ["AuthRoot",
          "Root",
          "TrustedPeople",
          "TrustedPublisher",
          "My"]

def get_all_store_cert(store: str):
    success = certStore.OpenWindowsStore("CurrentUser", store, True)
    if not success:
        print(certStore.lastErrorText())

    numCerts = certStore.get_NumCertificates()

    return [certStore.GetCertificate(i) for i in range(numCerts)]


def reading_file(file_name, type):
    with open(file_name, type) as file:
        text = file.read()
    return text


def writing_file(file_name, type, text):
    with open(file_name, type) as file:
        file.write(text)


if __name__ == '__main__':
    certStore = chilkat.CkCertStore()
    lastPickStore = ""

    while True:
        print("\nРежимы работы:")
        print("\t0 - показать список доступных хранилищ")
        print("\t1 - показывать список доступных сертификатов в хранилище")
        print("\t2 - выбрать сертефикат и сгенерировать PEM файл")
        print("\t3 - шифровать выбранный файл")
        mode = input(">> ")

        if mode == "0":
            print(", ".join(stores))
        elif mode == "1":
            print("Введите название хранилища:")
            store_name = input(">> ")

            for cert in get_all_store_cert(store_name):
                print(f"{cert.subjectDN()}\n"
                      f"HASH отпечаток = {cert.sha1Thumbprint()}\n")
        elif mode == "2":
            print("Введите Command Name выбранного сертификата.\n "
                  "Сертификат будет взят из последнего просмотренного хранилища")

            subCN = input(">> ")
            ret_cert = certStore.FindCertBySubjectCN(subCN)

            publicKey = ret_cert.ExportPublicKey()
            retStr = publicKey.getPem(True)

            writing_file("publicKey.pem", "wb", retStr.encode())
        elif mode == "3":
            print("Введите путь к файлу: ")
            file_path = input(">> ")

            message = reading_file(file_path, "r")

            key = RSA.import_key(reading_file("publicKey.pem", 'r'))
            key = PKCS1_OAEP.new(key)

            encrypted = key.encrypt(message.encode())
            writing_file("encr.bin", "wb", encrypted)
        else:
            print("Выбран несуществующий режим.")
            sys.exit()
