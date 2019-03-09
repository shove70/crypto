module crypto.utils;

import std.bigint;
import std.array;
import std.algorithm;
import std.traits : Unqual;
import std.conv;
import std.random;

struct BigIntHelper
{
    static ubyte[] bigIntToUByteArray(BigInt v)
    {
        Appender!(ubyte[]) app;

        while (v > 0)
        {
            app.put((v - ((v >> 8) << 8)).to!ubyte);
            v >>= 8;
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

    static BigInt powMod(BigInt base, BigInt modulus, BigInt exponent)
    {
        assert(base >= 1 && exponent >= 0 && modulus >= 1);

        BigInt result = BigInt("1");
        BigInt temp = base % modulus;

        while (exponent >= 1)
        {
            if (exponent % 2 != 0)
            {
                result = (result * temp) % modulus;
            }

            temp = (temp * temp) % modulus;
            exponent /= 2;
        }

        return result;
    }

    /*
    /// recursion
    static BigInt powMod(BigInt base, BigInt modulus, BigInt exponent)
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
        if (exponent % 2 != 0)
        {
            BigInt temp = powMod(base, modulus, exponent / 2);
            return (temp * temp * base) % modulus;
        }
        else
        {
            BigInt temp = powMod(base, modulus, exponent / 2);
            return (temp * temp) % modulus;
        }
    }
    */
}

/++ Fast but cryptographically insecure source of random numbers. +/
struct InsecureRandomGenerator
{
    private static Mt19937 generator;

    static this()
    {
        generator.seed(unpredictableSeed);
    }

    T next(T = uint)(T min = T.min, T max = T.max) if (is(Unqual!T == uint) || is(Unqual!T == int) || is(Unqual!T == ubyte) || is(Unqual!T == byte))
    {
        return uniform!("[]", T, T, typeof(generator))(min, max, generator);
    }
}

private @nogc nothrow pure @system
{
    version (linux)
        extern(C) void explicit_bzero(void* ptr, size_t cnt);
    version (FreeBSD)
        extern(C) void explicit_bzero(void* ptr, size_t cnt);
    version (OpenBSD)
        extern(C) void explicit_bzero(void* ptr, size_t cnt);
    version (OSX)
        extern(C) int memset_s(void* ptr, size_t destsz, int c, size_t n);
}

/++
Sets the array to all zero. On Linux, FreeBSD, and OpenBSD, uses
`explicit_bzero` to prevent an optimizing compiler from deeming the
data write "unnecessary" and omitting it. On Mac OS X uses `memset_s`
for the same purpose. The typical use of this function is to erase
secret keys after they are no longer needed.

Limitations:
On operating systems other than mentioned above this function is the
same as `array[] = 0` and is not protected from being removed by the
compiler.
+/
void explicitZero(scope ubyte[] array) @nogc nothrow pure @trusted
{
    if (__ctfe)
    {
        array[] = 0;
        return;
    }
    version (linux)
        explicit_bzero(array.ptr, array.length);
    else version (FreeBSD)
        explicit_bzero(array.ptr, array.length);
    else version (OpenBSD)
        explicit_bzero(array.ptr, array.length);
    else version (OSX)
        memset_s(array.ptr, array.length, 0, array.length);
    else
        array[] = 0;
}
