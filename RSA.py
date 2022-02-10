import math
import random


class RSAHelper:
    """Helper class that used to perform a calulation in RSA approches."""

    def __init__(self, n=1000):
        self._limit = n
        self._primes = self._sieve_of_eratosthenes(self._limit)
        self.setup()

    @classmethod
    def _sieve_of_eratosthenes(cls, n):
        p = 2
        prime = [True for i in range(n + 1)]
        while p * p <= n:
            if prime[p] == True:
                for i in range(p ** 2, n + 1, p):
                    prime[i] = False
            p += 1
        primes = [num + 2 for num, is_prime in enumerate(prime[2:]) if is_prime]
        return primes

    def _get_prime_number(self, ignore=None):
        indx = random.randint(0, len(self._primes) - 1)
        number = self._primes[indx]
        return number if ignore != number else self._get_prime_number(ignore=ignore)

    def _mod_inverse(self, x, n):
        return pow(x, -1, n)  # Works only in Python3.8 and above

    def _co_prime(self, phi):
        for i in range(2, phi):
            gcd = math.gcd(i, phi)
            if gcd == 1:
                return i

    def setup(self):
        p = self._get_prime_number()
        q = self._get_prime_number(p)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = self._co_prime(phi)
        d = self._mod_inverse(e, phi)
        self.public_key = (n, e)
        self._private_key = (n, d)


class RSAClient:
    """A client which use RSA and send message each other."""

    def __init__(self, username, limit=50):
        self.username = username
        self._helper = RSAHelper(limit)
        self.messages = {}

    @property
    def public_key(self):
        return self._helper.public_key

    def _normalize_message(self, message):
        return [ord(c) for c in message]

    def _add_message(self, encrypted_message, username):
        self.messages[username] = encrypted_message

    @classmethod
    def decrypt_message(cls, d, n, encrypted_message):
        return (encrypted_message ** d) % n

    @classmethod
    def encrypte_message(cls, e, n, message):
        return (message ** e) % n

    def send_message(self, client, message):
        messages = self._normalize_message(message)
        n, e = client.public_key
        encrypted_message = []
        for msg in messages:
            encrypted_message.append(
                bin(self.encrypte_message(e, n, msg))[2:].zfill(12)
            )
        client._add_message(encrypted_message, self.username)
        self._add_message(encrypted_message, self.username)

    def read_message(self, username):
        n, d = self._helper._private_key
        encrypted_message = self.messages[username]
        decrypted_message = [
            self.decrypt_message(d, n, int(msg, 2)) for msg in encrypted_message
        ]
        return "".join([chr(i) for i in decrypted_message])


client_1 = RSAClient("abnos")
client_2 = RSAClient("usher")

message = """
1) **RSA** algorithm is asymmetric cryptography algorithm.
2) Asymmetric actually means that it works on two different keys i.e. Public Key and Private Key.
3) As the name describes that the Public Key is given to everyone and Private key is kept private.
"""

client_1.send_message(client_2, message)

print(
    "Message Recived By Client 2 (in binary)",
    "".join(client_2.messages["abnos"]),
    sep="\n",
)
print('\n\n\n')
print("Decrypted Message Client 2", client_2.read_message("abnos"), sep="\n")
print("Decrypted Message Client 1", client_1.read_message("abnos"), sep="\n")
