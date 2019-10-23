[![Build Status](https://travis-ci.org/shove70/crypto.svg?branch=master)](https://travis-ci.org/shove70/crypto)
[![GitHub tag](https://img.shields.io/github/tag/shove70/crypto.svg?maxAge=86400)](https://github.com/shove70/crypto/releases)
[![Dub downloads](https://img.shields.io/dub/dt/crypto.svg)](http://code.dlang.org/packages/crypto)

# A D Library of encryption, decryption, encode, hash, and message digital signatures.

The same functional and fully compatible C++ project:
https://github.com/shove70/shove.c

### AES:

```d
import crypto.aes;
import crypto.padding;

string key = "12341234123412341234123412341234";
ubyte[] message = cast(ubyte[])"123412341234123412341234123412341";
ubyte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1, 2, 3, 4];

ubyte[] buffer = AESUtils.encrypt!AES128(message, key, iv, PaddingMode.PKCS5);
buffer = AESUtils.decrypt!AES128(buffer, key, iv, PaddingMode.PKCS5);

assert(message == buffer);
```

### Blake2b:

```d
import crypto.blake2.blake2b;
import crypto.hex;
import std.base64;
import std.digest.crc;

ubyte[] hash;
ubyte[] hashResult = hexBytes("28248967dc89fdbdaea74cb99ceec5cd4e06547f095b83d31e9a580bb739a539c077a295ef76b0ef5e8b83abe7a5f82d48639566bececfa6b80c9ec4a6a80889");
assert(blake2b!B512(hash, cast(ubyte[])"Blake2b") == 0);
assert(hash == hashResult);
assert(toHexString!(LetterCase.lower)(hash) == "28248967dc89fdbdaea74cb99ceec5cd4e06547f095b83d31e9a580bb739a539c077a295ef76b0ef5e8b83abe7a5f82d48639566bececfa6b80c9ec4a6a80889");
assert(Base64.encode(hash) == "KCSJZ9yJ/b2up0y5nO7FzU4GVH8JW4PTHppYC7c5pTnAd6KV73aw716Lg6vnpfgtSGOVZr7Oz6a4DJ7EpqgIiQ==");
```

### XTEA:

```d
import crypto.tea.xtea;
import crypto.padding;

int[4] key = [1, 2, 3, 4];
int rounds = 64;
ubyte[] message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

ubyte[] buffer = Xtea.encrypt(message, key, rounds, PaddingMode.PKCS5);
buffer = Xtea.decrypt(buffer, key, rounds, PaddingMode.PKCS5);

assert(message == buffer);
```

### RSA:

```d
import crypto.rsa;

RSAKeyPair keyPair = RSA.generateKeyPair(1024);
writeln(keyPair.privateKey);
writeln(keyPair.publicKey);

string data = "Data that needs to be encrypted";

ubyte[] en = RSA.encrypt(keyPair.privateKey, cast(ubyte[])data);
ubyte[] de = RSA.decrypt(keyPair.publicKey, en);
writeln(cast(string)de);

assert(cast(string)de == data);
```

### Thanks

* @n8sh
* @Boris-Barboris
* @DarkRiDDeR
* @Cédric Picard

### Other

For more examples, see unittest, Thanks.
