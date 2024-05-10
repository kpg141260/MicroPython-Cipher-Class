"""
Helper module for encryption in AES-ECB Maode
"""
import uos
from   ucryptolib import aes

MODE_ECB   = 1
BLOCK_SIZE = 16
KEY_LENGTH = 32

class _Subscriptable():
    def __getitem__(self, item):
        return None

_subscriptable = _Subscriptable()

plain_text  = _subscriptable
cipher_text = _subscriptable
key         = _subscriptable

class crypto:
    _key    = _subscriptable
    _cipher = object

    # Initialisation and some sanity checks
    def __init__ (self, key):
        if key is not None:
            # Check the key length and adjust as required
            # key is too short
            if len(key) < KEY_LENGTH:
                pad = 32 - len(key)
                self._key = key + ('_')*pad
            # key is too long
            elif len(key) > KEY_LENGTH:
                for i in range (KEY_LENGTH):
                    self._key[i] = key[i]
            # key is just right
            else:
                self._key = key
        else:
            raise ValueError ( 'crypto - Error: no encryption key provided!' )
    
    # encrypt plain text    
    def encrypt (self, plain_text) -> bytearray:
        # Create instance of aes cipher
        try:
            self._cipher = aes (self._key, MODE_ECB)
        except (Exception) as ex:
            raise RuntimeError (f'Error in crypto.encrypt(): {ex}')
        
        # Do padding if required
        pad = BLOCK_SIZE - len(plain_text) % BLOCK_SIZE
        plain_text = plain_text + " "*pad
        
        # encrypt the plain_text and return cipher
        return self._cipher.encrypt(plain_text)
        
        
    def decrypt (self, cipher_text) -> str:
        # Create instance of aes cipher
        try:
            self._cipher = aes (self._key, MODE_ECB)
        except (Exception) as ex:
            raise RuntimeError (f'Error in crypto.decrypt(): {ex}')
        
        decrypted = self._cipher.decrypt(cipher_text)
        return decrypted.decode('utf-8')
    
    # Make sure to call the destruct method when done.
    # It will overwrite the key in memory.
    def destruct (self):
        self._key = "" * 32
        self._key = None
        # Destroy the cipher object
        self._cipher = None

