# A D Library of encryption, decryption, encode, hash, and message digital signatures.

The same functional and fully compatible C++ project:
https://github.com/shove70/shove.c

### AES:

```
import crypto.aes;

string key = "12341234123412341234123412341234";
ubyte[] message = cast(ubyte[])"123412341234123412341234123412341";

ubyte[] buffer = AESUtils.encrypt!AES128(message, key);
buffer = AESUtils.decrypt!AES128(buffer, key);

assert(message == buffer);
```

### XTEA:

```
import crypto.tea.xtea;

int[4] key = [1, 2, 3, 4];
int rounds = 64;
ubyte[] message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

ubyte[] buffer = Xtea.encrypt(message, key, rounds);
buffer = Xtea.decrypt(buffer, key, rounds);

assert(message == buffer);
```

### RSA:

```
import crypto.rsa;

RSAKeyPair keyPair = RSA.generateKeyPair(1024);
writeln(keyPair.privateKey);
writeln(keyPair.publicKey);

string data = "Data that needs to be encrypted";

ubyte[] en = RSA.encrypt(keyPair.privateKey, cast(ubyte[])data);
ubyte[] de = RSA.decrypt(keyPair.publicKey, en);
writeln(cast(string)de);

assert(cast(string)de = data);
```

For more examples, see unittest, Thanks.
