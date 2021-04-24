from Rabin import rabin_encryption, KeyValidationError, rabin_decryption, key_generation, TextValidationError, \
    word_to_number, alphabet


def main():
    plaintext = "If life were predictable it would cease to be life and be without flavor"
    encryption = rabin_encryption(plaintext, 4, 5, 13719989)
    _, _, decrypted_text = rabin_decryption(encryption, [4027, 3407], 13719989, 4, 5)
    plaintext = plaintext.upper()
    assert (decrypted_text == plaintext)

    plaintext = "The best and most beautiful things in the world cannot be seen or even touched they must be felt with your heart"
    encryption = rabin_encryption(plaintext, 4, 5, 8790913)
    _, _, decrypted_text = rabin_decryption(encryption, [1019, 8627], 8790913, 4, 5)
    plaintext = plaintext.upper()
    assert (decrypted_text == plaintext)
    # k,l=4,5
    # pub_key, priv_key = 0, [0,0]
    # while True:
    #     cmd=input(">> Choose a command:\n   1. Generate key\n   2. Encryption\n   3. Decryption\n   0. Exit "
    #               "program\n")
    #     if cmd=="1":
    #         pub_key, priv_key = key_generation(k,l)
    #         print("The generated public key is: "+str(pub_key))
    #         print("The generated private key is: "+str(priv_key))
    #     elif cmd=="2":
    #         try:
    #             text=input(">> Text to encrypt:")
    #             enc = rabin_encryption(text,k, l, pub_key)
    #             print(">> Encrypted text is: "+str(enc))
    #         except KeyValidationError:
    #             print(">> Key not valid!")
    #         except TextValidationError:
    #             print(">> Text not valid!")
    #     elif cmd=="3":
    #         try:
    #             text = input(">> Text to decrypt:")
    #             dec,enc,text = rabin_decryption(text, priv_key, pub_key, k, l)
    #             res=">> Decryption solutions for the ciphertext blocks are:\n"
    #             for e in enc:
    #                 res+=e+" -> "+str(dec[enc.index(e)])+"\n"
    #             print(str(res))
    #
    #             if text!="":
    #                 print("The original text is: "+text)
    #             else:
    #                 print("The decryption result is ambiguous! There are several possible original messages!")
    #         except KeyValidationError:
    #             print(">> Key not valid!")
    #         except TextValidationError:
    #             print(">> Text not valid!")
    #     elif cmd=="0":
    #         break
    #     else:
    #         print(">> Unknown command!")


main()
