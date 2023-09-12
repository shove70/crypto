module crypto.rsa;

import std.bigint;
import std.bitmanip;
import std.datetime;
import std.base64;
import std.typecons;

import crypto.bigint;
import crypto.random;
public import crypto.padding;

struct RSAKeyPair
{
    string privateKey;
    string publicKey;
}

struct RSAKeyInfo
{
    @property BigInt modulus()
    {
        return _modulus;
    }

    @property ubyte[] modulus_bytes()
    {
        return _modulus_bytes;
    }

    @property BigInt exponent()
    {
        return _exponent;
    }

    @property ubyte[] exponent_bytes()
    {
        return _exponent_bytes;
    }

    this(BigInt modulus, ubyte[] modulus_bytes, BigInt exponent, ubyte[] exponent_bytes)
    {
        _modulus = modulus;
        _modulus_bytes = modulus_bytes;
        _exponent = exponent;
        _exponent_bytes = exponent_bytes;
    }

private:

    BigInt _modulus;
    ubyte[] _modulus_bytes;
    BigInt _exponent;
    ubyte[] _exponent_bytes;
}

class RSA
{
    static RSAKeyPair generateKeyPair(uint bitLength = 2048)
    {
        assert((bitLength >= 128) && (bitLength % 8 == 0),
            "Bitlength is required to be a multiple of 8 and not less than 128. It’s recommended that it be no less than 2048.");

        BigInt x, y;

        BigInt ex_gcd(BigInt a, BigInt b)
        {
            if (b == 0)
            {
                x = BigInt("1");
                y = BigInt("0");
                return a;
            }

            BigInt ans = ex_gcd(b, a % b);
            BigInt temp = x;
            x = y;
            y = temp - (a / b * y);

            return ans;
        }

        BigInt cal(BigInt a, BigInt k)
        {
            BigInt gcd = ex_gcd(a, k);

            if (gcd % 1 != 0)
            {
                return BigInt("-1");
            }

            x = x * (1 / gcd);

            if (k < 0)
            {
                k *= -1;
            }

            BigInt ans = x % k;

            if (ans < 0)
            {
                ans += k;
            }

            return ans;
        }

        size_t confidence;
        if (bitLength <= 128)       confidence = 50;
        else if (bitLength <= 256)  confidence = 27;
        else if (bitLength <= 512)  confidence = 15;
        else if (bitLength <= 768)  confidence = 8;
        else if (bitLength <= 1024) confidence = 4;
        else                        confidence = 2;

        BigInt p, q, n, t, e, d;

        do
        {
            p = BigIntHelper.randomGenerate(bitLength / 2, 1, 1);
        }
        while (!BigIntHelper.isProbablePrime(p, confidence));
        do
        {
            q = BigIntHelper.randomGenerate(bitLength / 2, 1, 1);
        }
        while (!BigIntHelper.isProbablePrime(q, confidence));

        n = p * q;
        t = (p - 1) * (q - 1);
        e = 65537;
        d = cal(e, t);

        return RSAKeyPair(encodeKey(n, d), encodeKey(n, e));
    }

    static string encodeKey(T : iPKCS = SimpleFormat)(BigInt modulus, BigInt exponent)
    {
        return T.encodeKey(modulus, exponent);
    }

    static RSAKeyInfo decodeKey(T : iPKCS = SimpleFormat)(string key)
    {
        return T.decodeKey(key).get;
    }

    static ubyte[] encrypt(T : iPKCS = SimpleFormat)(string key, ubyte[] data, bool mixinXteaMode = false)
    {
        return crypt!("encrypt", T)(key, data, mixinXteaMode);
    }

    static ubyte[] encrypt(RSAKeyInfo key, ubyte[] data, bool mixinXteaMode = false)
    {
        return crypt!"encrypt"(key, data, mixinXteaMode);
    }

    static ubyte[] decrypt(T : iPKCS = SimpleFormat)(string key, ubyte[] data, bool mixinXteaMode = false)
    {
        return crypt!("decrypt", T)(key, data, mixinXteaMode);
    }

    static ubyte[] decrypt(RSAKeyInfo key, ubyte[] data, bool mixinXteaMode = false)
    {
        return crypt!"decrypt"(key, data, mixinXteaMode);
    }

private:

    static ubyte[] crypt(string T1, T2 : iPKCS = SimpleFormat)(string key, ubyte[] data, bool mixinXteaMode)
    if (T1 == "encrypt" || T1 == "decrypt")
    {
        RSAKeyInfo ki = decodeKey!T2(key);
        return crypt!(T1)(ki, data, mixinXteaMode);
    }

    static ubyte[] crypt(string T)(RSAKeyInfo key, ubyte[] data, bool mixinXteaMode)
    if (T == "encrypt" || T == "decrypt")
    {
        if (mixinXteaMode)
        {
            return crypt_mixinXteaMode!T(key, data);
        }

        size_t keySize = key.modulus_bytes.length;

        BigInt getNextBlock(out size_t blockSize)
        {
            if (data.length == 0)
            {
                blockSize = 0;
                return BigInt("0");
            }

            static if (T == "decrypt")
            {
                ubyte[] block = data[0 .. ($ >= keySize) ? keySize : $];
                blockSize = block.length;
                return BigIntHelper.fromBytes(block);
            }
            else
            {
                // Prevent preamble 0, and make the encrypto results random
                ubyte preamble = rnd.next!ubyte(0x01, 0xFF);
                blockSize = (keySize <= data.length) ? keySize : data.length;

                while (true)
                {
                    ubyte[] block = [preamble] ~ data[0 .. blockSize];
                    BigInt t = BigIntHelper.fromBytes(block);
                    if (t >= key.modulus)
                    {
                        blockSize--;
                        assert(blockSize > 0, "Key bits is too small.");
                        continue;
                    }
                    return t;
                }
            }
        }

        ubyte[] ret;

        while (data.length > 0)
        {
            size_t blockSize;
            BigInt block = getNextBlock(blockSize);
            if (blockSize == 0)
            {
                break;
            }

            block = BigIntHelper.powmod(block, key.exponent, key.modulus);
            ubyte[] block_buf = BigIntHelper.toUBytes(block);
            static if (T == "encrypt")
            {
                for (size_t i; i < keySize - block_buf.length; i++)
                {
                    ret ~= cast(ubyte)0;
                }
            }
            else
            {
                block_buf = block_buf[1 .. $];
            }

            ret ~= block_buf;
            data = data[blockSize .. $];
        }

        return ret;
    }

    static ubyte[] crypt_mixinXteaMode(string T)(RSAKeyInfo key, ubyte[] data)
    if (T == "encrypt" || T == "decrypt")
    {
        import crypto.tea;

        int[4] xteaKey;
        int rounds = 64;
        size_t keySize = key.modulus_bytes.length;

        void generateXteaKey(in ubyte[] buf)
        {
            ubyte[] data = new ubyte[int.sizeof * 4];
            for (int i = 0; i < int.sizeof * 4; i++)
            {
                data[i] = buf[i % buf.length];
            }

            for (int i = 0; i < 4; i++)
            {
                xteaKey[i] = data.peek!int(i * int.sizeof);
            }
        }

        BigInt getNextBlock(out size_t blockSize)
        {
            if (data.length == 0)
            {
                blockSize = 0;
                return BigInt("0");
            }

            static if (T == "decrypt")
            {
                ubyte[] block = data[0 .. ($ >= keySize) ? keySize : $];
                blockSize = block.length;
                return BigIntHelper.fromBytes(block);
            }
            else
            {
                // Prevent preamble 0, and make the encrypto results random
                ubyte preamble = rnd.next!ubyte(0x01, 0xFF);
                blockSize = (keySize <= data.length) ? keySize : data.length;

                while (true)
                {
                    ubyte[] block = [preamble] ~ data[0 .. blockSize];
                    BigInt t = BigIntHelper.fromBytes(block);
                    if (t >= key.modulus)
                    {
                        blockSize--;
                        assert(blockSize > 0, "Key bits is too small.");
                        continue;
                    }

                    generateXteaKey(block);
                    return t;
                }
            }
        }

        ubyte[] ret;

        size_t blockSize;
        BigInt block = getNextBlock(blockSize);
        if (blockSize == 0)
        {
            return ret;
        }

        block = BigIntHelper.powmod(block, key.exponent, key.modulus);
        ubyte[] block_buf = BigIntHelper.toUBytes(block);
        static if (T == "encrypt")
        {
            for (size_t i; i < keySize - block_buf.length; i++)
            {
                ret ~= cast(ubyte)0;
            }
        }
        else
        {
            generateXteaKey(block_buf);
            block_buf = block_buf[1 .. $];
        }

        ret ~= block_buf;

        if (blockSize >= data.length)
        {
            return ret;
        }

        data = data[blockSize .. $];

        static if (T == "encrypt")
        {
            ret ~= Xtea.encrypt(data, xteaKey, rounds, PaddingMode.Customized);
        }
        else
        {
            ret ~= Xtea.decrypt(data, xteaKey, rounds, PaddingMode.Customized);
        }

        return ret;
    }
}

interface iPKCS
{
    static string encodeKey(BigInt modulus, BigInt exponent);
    static Nullable!RSAKeyInfo decodeKey(string key);
}

class SimpleFormat : iPKCS
{
    static string encodeKey(BigInt modulus, BigInt exponent)
    {
        ubyte[] m_bytes = BigIntHelper.toUBytes(modulus);
        ubyte[] e_bytes = BigIntHelper.toUBytes(exponent);

        ubyte[] buffer = new ubyte[4];

        buffer.write!int(cast(int) m_bytes.length, 0);
        buffer ~= m_bytes;
        buffer ~= e_bytes;

        return Base64.encode(buffer);
    }

    static Nullable!RSAKeyInfo decodeKey(string key)
    {
        ubyte[] buffer = Base64.decode(key);
        int m_len = buffer.peek!int(0);
        ubyte[] modulus_bytes = buffer[4 .. 4 + m_len];
        ubyte[] exponent_bytes = buffer[4 + m_len .. $];

        return Nullable!RSAKeyInfo(RSAKeyInfo(BigIntHelper.fromBytes(modulus_bytes),
                modulus_bytes, BigIntHelper.fromBytes(exponent_bytes), exponent_bytes));
    }
}

class PKCS1 : iPKCS
{
    static string encodeKey(BigInt modulus, BigInt exponent)
    {
        return string.init;
    }

    static Nullable!RSAKeyInfo decodeKey(string key)
    {
        return Nullable!RSAKeyInfo();
    }
}

class PKCS8 : iPKCS
{
    static string encodeKey(BigInt modulus, BigInt exponent)
    {
        return string.init;
    }

    static Nullable!RSAKeyInfo decodeKey(string key)
    {
        return Nullable!RSAKeyInfo();
    }
}

unittest
{
    import crypto.rsa;

    RSAKeyPair keyPair = RSA.generateKeyPair(1024);

    string data = `
And the workload proves (POW) reusable workload proof (RPOW) 2. hash function
The hash function (Hash Function), also known as a hash function, gives an input x, which calculates the corresponding output H (x). The main features of a hash function are:
The input x can be a string of any length
The output, that is, the length of H (x) is fixed

The procedure for calculating H (x) is efficient (for string X of length n), the time complexity of H (x) should be O (n)
For bitcoin, the hash function used by such cryptographic systems, it needs to have the following properties:
    `;

    ubyte[] sb = cast(ubyte[]) data;
    ubyte[] db = RSA.encrypt(keyPair.privateKey, sb);
    sb = RSA.decrypt(keyPair.publicKey, db);
    assert(cast(string) sb == data);
}

// for mixinXteaMode
unittest
{
    import crypto.rsa;

    RSAKeyInfo pri_key = RSA.decodeKey("AAAAgIcksjBHK7FYePatdsIWiHv7Z+HixIcD0dMyEtXLAGf9fDujn05Seyz1mTIE62UKMojVK+O4oxVT9Ljf8w5F81dTnanoKH0+I/lQN5CR95nRgUEwhZFSbmYM2YeACsfPyX1V5iP0KU8LN9D7/7q64lSZ6XbHGpa7DRv7yvDHaMyJBkGipi2FTk6EOxdIui+E3giDhKeU5ZM9sYNN7+vX9vh7Od+XTm7vGOO91dz4cNMKB9+mioJPunsKh0yG2hBO9Zg+IZNWir/jRfG/w38Av4pQOkRsz9U/ZsTA37XKqzglnwaKGPSw51RJuWuv9RXDRh12Po6oLnr5TkK0OBeJPgE=");
    RSAKeyInfo pub_key = RSA.decodeKey("AAAAgIcksjBHK7FYePatdsIWiHv7Z+HixIcD0dMyEtXLAGf9fDujn05Seyz1mTIE62UKMojVK+O4oxVT9Ljf8w5F81dTnanoKH0+I/lQN5CR95nRgUEwhZFSbmYM2YeACsfPyX1V5iP0KU8LN9D7/7q64lSZ6XbHGpa7DRv7yvDHaMyJAQAB");

    string data = `
And the workload proves (POW) reusable workload proof (RPOW) 2. hash function
The hash function (Hash Function), also known as a hash function, gives an input x, which calculates the corresponding output H (x). The main features of a hash function are:
The input x can be a string of any length
The output, that is, the length of H (x) is fixed

The procedure for calculating H (x) is efficient (for string X of length n), the time complexity of H (x) should be O (n)
For bitcoin, the hash function used by such cryptographic systems, it needs to have the following properties:
    `;

    ubyte[] sb = cast(ubyte[]) data;
    ubyte[] db = RSA.encrypt(pri_key, sb, true);
    sb = RSA.decrypt(pub_key, db, true);
    assert(cast(string) sb == data);
}
