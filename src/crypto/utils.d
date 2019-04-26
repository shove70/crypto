module crypto.utils;

import std.bigint;
import std.array;
import std.algorithm;
import std.traits : Unqual;
import std.conv;
import std.random;
import std.bitmanip;

struct BigIntHelper
{
    static ubyte[] bigIntToUByteArray(BigInt value)
    {
        Appender!(ubyte[]) app;

        while (value > 0)
        {
            app.put((value - ((value >> 8) << 8)).to!ubyte);
            value >>= 8;
        }

        reverse(app.data);

        return app.data;
    }

    static BigInt bigIntFromUByteArray(in ubyte[] buffer)
    {
        BigInt ret = BigInt("0");

        for (uint i; i < buffer.length; i++)
        {
            ret <<= 8;
            ret += buffer[i];
        }

        return ret;
    }

//    static BigInt powMod(BigInt base, BigInt modulus, BigInt exponent)
//    {
//        assert(base >= 1 && exponent >= 0 && modulus >= 1);
//
//        BigInt result = BigInt("1");
//
//        while (exponent > 0)
//        {
//            if (exponent & 1)
//            {
//                result = (result * base) % modulus;
//            }
//
//            base = ((base % modulus) * (base % modulus)) % modulus;
//            exponent >>= 1;
//        }
//
//        return result;
//    }

    static BigInt powMod(const BigInt base, const BigInt modulus, const BigInt exponent)
    {
        assert(base >= 1 && exponent >= 0 && modulus >= 1);

        if (exponent == 0)
        {
            return BigInt(1) % modulus;
        }

        if (exponent == 1)
        {
            return base % modulus;
        }

        BigInt temp = powMod(base, modulus, exponent / 2);

        return (exponent & 1) ? (temp * temp * base) % modulus : (temp * temp) % modulus;
    }
}

alias rnd = secureRnd;

///++ Fast but cryptographically insecure source of random numbers. +/
//struct InsecureRandomGenerator
//{
//    private static Mt19937 generator;
//
//    static this()
//    {
//        generator.seed(unpredictableSeed);
//    }
//
//    /++
//    Params:
//        min = min inclusive
//        max = max inclusive
//    Returns: `x` such that `min <= x <= max`
//    +/
//    T next(T = uint)(T min = T.min, T max = T.max) if (is(Unqual!T == uint) || is(Unqual!T == int) || is(Unqual!T == ubyte) || is(Unqual!T == byte))
//    {
//        return uniform!("[]", T, T, typeof(generator))(min, max, generator);
//    }
//}

version (CRuntime_Bionic) version = SecureARC4Random; // ChaCha20
version (OSX) version = SecureARC4Random; // AES
version (OpenBSD) version = SecureARC4Random; // ChaCha20
version (NetBSD) version = SecureARC4Random; // ChaCha20
//version (FreeBSD) version = SecureARC4Random; // ARC4 before FreeBSD 12; ChaCha20 in FreeBSD 12.

version (SecureARC4Random)
{
    private extern(C) uint arc4random() @nogc nothrow @safe;
    private extern(C) uint arc4random_uniform(uint upperBound) @nogc nothrow @safe;

    /++ Cryptographically secure source of random numbers. Not available on all platforms. +/
    struct ARC4RandomGenerator
    {
        /++
        Params:
            min = min inclusive
            max = max inclusive
        Returns: `x` such that `min <= x <= max`
        +/
        T next(T = uint)(T min = T.min, T max = T.max) if (is(Unqual!T == uint) || is(Unqual!T == int) || is(Unqual!T == ubyte) || is(Unqual!T == byte))
        {
            if (min == T.min && max == T.max)
                return cast(T) arc4random();
            else
                return cast(T) (min + arc4random_uniform(1U + max - min));
        }
    }
    /// ditto
    alias SecureRandomGenerator = ARC4RandomGenerator;
    __gshared SecureRandomGenerator secureRnd; // Can be global because it has no mutable state.
}
else version (Windows)
{
    /++ Cryptographically secure source of random numbers. Not available on all platforms. +/
    struct CryptGenRandomGenerator
    {
        import core.sys.windows.wincrypt;

        __gshared private HCRYPTPROV hProvider;

        private uint[32] buffer;
        private uint pos = buffer.length;

        static this()
        {
            if (!hProvider)
                if (!CryptAcquireContextW(&hProvider, null, null, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
                    if (!CryptAcquireContextA(&hProvider, null, null, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_SILENT))
                        throw new Error("CryptAcquireContext failed");
        }

        /++
        Params:
            min = min inclusive
            max = max inclusive
        Returns: `x` such that `min <= x <= max`
        +/
        T next(T = uint)(T min = T.min, T max = T.max) if (is(Unqual!T == uint) || is(Unqual!T == int) || is(Unqual!T == ubyte) || is(Unqual!T == byte))
        {
            return uniform!("[]", T, T)(min, max, this);
        }

        // Stuff to make this work with std.random:
        enum uint min = uint.min;
        enum uint max = uint.max;
        enum bool isUniformRandom = true;
        enum bool empty = false;

        uint front() @nogc nothrow @trusted
        {
            if (pos >= buffer.length)
            {
                while (!CryptGenRandom(hProvider, buffer.sizeof, cast(ubyte*) &buffer))
                {
                    // Repeat until successful.
                }
                pos = 0;
            }
            return buffer[pos];
        }

        void popFront() @nogc nothrow @safe
        {
            pos++;
        }
    }
    /// ditto
    alias SecureRandomGenerator = CryptGenRandomGenerator;
    static SecureRandomGenerator secureRnd; // Thread-local because it has a mutable buffer.
}
