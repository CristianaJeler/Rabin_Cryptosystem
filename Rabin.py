import string
from math import sqrt, floor
from random import randint

from MillerRabin import miller_rabin

redundancy_size = 4


class KeyValidationError(Exception):
    pass


class TextValidationError(Exception):
    pass


'''
    function to compute the Jacobi symbol of a modulo n
'''


def jacobi_symbol(a, n):
    t = 1
    while a != 0:
        while a % 2 == 0:
            a /= 2
            r = n % 8
            if r == 3 or r == 5:
                t = -t
        a, n = n, a
        if a % 4 == n % 4 == 3:
            t = -t
        a %= n
    if n == 1:
        return t
    else:
        return 0


''' 
    function to find d,
    a random quadratic non-residue modulo p
    with 2<=d<=p-1
'''


def random_quadratic_non_residue(p):
    while True:
        d = randint(2, p - 1)
        if jacobi_symbol(d, p) == -1:
            return d


'''
here, we compute the modular square root of a (mod p)
'''


def modular_square_root(a, p):
    a_mod_p = a % p
    if sqrt(a_mod_p) == floor(sqrt(a_mod_p)):
        return floor(sqrt(a_mod_p))
    else:
        # I. if p is equivalent to 1 modulo 8
        if (p - 1) % 8 == 0:
            # write p-1 as p-1=2^s*t, where t is odd
            s = 0
            while True:
                if ((p - 1) / (2 ** s)) % 2 == 0:
                    s += 1
                else:
                    break
            t = (p - 1) // (2 ** s)
            d = random_quadratic_non_residue(p)
            A = (a ** t) % p
            D = (d ** t) % p
            D_1 = modular_inverse(D, p)

            power = 1
            for k in range(0, (2 ** (s - 1)) + 1, 2):
                even_power = D_1 ** power
                if (modular_inverse(D ** even_power, p) - A) % p == 0:
                    return (a ** ((t + 1) / 2) * (D ** k)) % p
        # II. if p is equivalent to 3 modulo 4
        elif (p - 3) % 4 == 0:  # 3 mod 4
            return a ** ((p + 1) // 4)
        # III. if p is equivalent to 5 modulo 8
        elif (p - 5) % 8 == 0:
            if (a ** ((p - 1) / 4) - 1) % p == 0:
                return a ** ((p + 3) // 8) % p
            else:
                return (2 * a * (4 * a) ** ((p - 5) // 8)) % p


'''
 Extended Euclidean Algorithm
'''


def gcd_extended(a, b):
    u2 = 1
    u1 = 0
    v2 = 0
    v1 = 1
    d, u, v = 0, 0, 0
    while b > 0:
        q = a // b
        r = a - q * b
        u = u2 - q * u1
        v = v2 - q * v1
        a = b
        b = r
        u2 = u1
        u1 = u
        v2 = v1
        v1 = v
        d = a
        u = u2
        v = v2
    return d, u, v


'''
    modular inverse of a number a modulo m
'''


def modular_inverse(a, m):
    gcd, x, y = gcd_extended(a, m)
    return x % m


'''
    we generate a random prime number of 4 digits;
    to verify if it is prime, we use the Miller-Rabin test
'''


def random_prime():
    rnd = randint(1000, 9999)
    while True:
        if rnd % 2 == 1 and miller_rabin(rnd) and (rnd - 3) % 4 == 0:
            return rnd
        else:
            rnd = randint(1000, 9999)


'''
    here we obtain a map with the conrespondences between letters and numbers
'''


def alphabet():
    i = 0
    alpha = {'_': i}
    i += 1
    for letter in list(string.ascii_uppercase):
        alpha[letter] = i
        i += 1
    return alpha


'''
    here we obtain a map with the conrespondences between numbers and letters
'''


def reverse_alphabet():
    i = 0
    reverse_alpha = {i: '_'}
    i += 1
    for letter in list(string.ascii_uppercase):
        reverse_alpha[i] = letter
        i += 1
    return reverse_alpha


'''
    function to generate a valid key
    for the encryption system
'''


def key_generation(k, l):
    while True:
        p = random_prime()
        q = random_prime()
        while q == p:
            q = random_prime()
        public_key = p * q
        private_key = [p, q]
        if valid_key(public_key, k, l):
            return public_key, private_key


'''
    function to split a text into blocks of k letters
'''


def split_text_into_words(text, k):
    text_blocks = []
    while text:
        lng = len(text)
        if k <= lng:
            block = text[0:k]
            text = text[k:lng]
            text_blocks.append(block)
        else:
            while len(text) < k:
                text += '_'
    return text_blocks


'''
    function to get the corresponding text 
    from its numerical equivalent
'''


def number_to_word(encrypt, l, reverse_alpha):
    ciphertext = ""
    for power in range(l - 1, -1, -1):
        numerical_equiv = encrypt // (27 ** power)
        ciphertext += reverse_alpha[numerical_equiv]
        encrypt -= numerical_equiv * (27 ** power)
    return ciphertext


'''
    function to obtain the numerical equivalence 
    of a word (block of text)
'''


def word_to_number(block, alpha):
    m = 0
    for i in range(len(block)):
        m += alpha[block[i]] * 27 ** (len(block) - i - 1)
    return m


'''
    text validation 
    the text must contain only symbols from
    within the given alphabet
'''


def valid_text(text):
    alpha = alphabet()
    for i in range(0, len(text)):
        if text[i] not in alpha:
            raise TextValidationError()


'''
    function for key validation
'''


def valid_key(key, k, l):
    if isinstance(key, list):
        if not 27 ** k < key[0] * key[1] < 27 ** l:
            return False
    else:
        if not 27 ** k < key < 27 ** l:
            return False
    return True


'''
    encryption function
    f(m)=m^2 mod n
'''


def encryption_function(m, public_key):
    return (m ** 2) % public_key


def rabin_encryption(text, k, l, public_key):
    text = text.upper()
    text = text.replace(" ", "_")
    valid_text(text)
    ciphertext = ""
    alpha = alphabet()
    reverse_alpha = reverse_alphabet()

    # Split plaintext
    plaintext_words = split_text_into_words(text, k)

    # numerical equivalents
    for block in plaintext_words:
        m = word_to_number(block, alpha)
        binary = bin(m)
        binary += binary[len(binary) - redundancy_size:len(binary)]
        encrypt = encryption_function(int(binary, 2), public_key)
        ciphertext += number_to_word(encrypt, l, reverse_alpha)
    return ciphertext


def decryption_function(m, private_key, public_key, k, reverse_alpha):
    a1 = modular_square_root(m, private_key[0])
    a2 = modular_square_root(m, private_key[1])
    N1 = private_key[1]
    N2 = private_key[0]
    K1 = modular_inverse(N1, N2)
    K2 = modular_inverse(N2, N1)

    # list containing the four possible solutions
    x = [(a1 * N1 * K1 + a2 * N2 * K2) % public_key,
         (-a1 * N1 * K1 + a2 * N2 * K2) % public_key,
         (a1 * N1 * K1 - a2 * N2 * K2) % public_key,
         (-a1 * N1 * K1 - a2 * N2 * K2) % public_key]
    res = []
    text_result = ""

    accepted_solutions = real_solutions(x)
    for sol in accepted_solutions:
        sol = int(bin(sol)[:len(bin(sol)) - redundancy_size], 2)
        if sol < 27 ** k:
            dec = number_to_word(sol, k, reverse_alpha)
            res.append(dec)

    return res, text_result


def rabin_decryption(text, private_key, public_key, k, l):
    ambiguous = False
    decrypted_text = ""

    # text validation
    valid_text(text)

    alpha = alphabet()
    reverse_alpha = reverse_alphabet()

    # split ciphertext into blocks of l letters
    ciphertext_blocks = split_text_into_words(text, l)

    decryption_results = []
    for block in ciphertext_blocks:
        m = word_to_number(block, alpha)
        res, txt = decryption_function(m, private_key, public_key, k, reverse_alpha)
        decryption_results.append(res)
        if len(res) != 1:
            ambiguous = True
            decrypted_text = ""
    if not ambiguous:
        for block in decryption_results:
            decrypted_text += block[0]
        decrypted_text = decrypted_text.replace('_', ' ')

    return decryption_results, ciphertext_blocks, decrypted_text

'''
    function to determine the solutions that have the 
    corresponding redundancy
'''
def real_solutions(x):
    acc_sol = []
    for sol in x:
        binary_sol = bin(sol)
        length = len(binary_sol)
        if binary_sol[length - redundancy_size * 2:length - redundancy_size] \
                == binary_sol[length - redundancy_size:length]:
            if sol not in acc_sol:
                acc_sol.append(sol)
    return acc_sol
