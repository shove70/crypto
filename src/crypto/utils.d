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

        BigInt temp = powMod(base, modulus, exponent / 2);

        return (exponent & 1) ? (temp * temp * base) % modulus : (temp * temp) % modulus;
    }
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

__gshared SecureRandomGenerator rnd;

struct SecureRandomGenerator
{
    import mir.random.engine : genRandomNonBlocking;
    import mir.random : randIndex;

    T next(T = uint)(T min = T.min, T max = T.max) if (is(Unqual!T == uint) || is(Unqual!T == int) || is(Unqual!T == ubyte) || is(Unqual!T == byte))
    {
        static if (T.sizeof == ubyte.sizeof)  alias UnsignedT = ubyte;
        static if (T.sizeof == ushort.sizeof) alias UnsignedT = ushort;
        static if (T.sizeof == uint.sizeof)   alias UnsignedT = uint;

        if (min == T.min && max == T.max)
        {
            UnsignedT[1] buffer = void;
            fill(cast(ubyte[]) buffer[]);
            return cast(T) buffer[0];
        }
        else
        {
            static struct Generator
            {
                enum isRandomEngine = true; // for mir.random interface
                enum UnsignedT max = UnsignedT.max; // for mir.random interface
                SecureRandomGenerator* this_;
                UnsignedT opCall()
                {
                    UnsignedT[1] buffer = void;
                    this_.fill(cast(ubyte[]) buffer[]);
                    return buffer[0];
                }
            }
            Generator gen = { &this };
            return cast(T) (min + gen.randIndex!UnsignedT(cast(UnsignedT) (max - min + 1)));
        }
    }

    void fill(scope ubyte[] buffer) @safe
    {
        for (ubyte[] unwritten = buffer; unwritten.length != 0;)
        {
            const n = genRandomNonBlocking(unwritten);

            if (ptrdiff_t(0) <= cast(ptrdiff_t)n)
            {
                unwritten = unwritten[n .. $];
            }
            else
            {
                throw new Exception("Error trying to obtain system entropy to generate random number.");
            }
        }
    }
}

unittest
{
    SecureRandomGenerator gen;
    const x = gen.next(100, 101);
    assert(x >= 100 && x <= 101);
}

version (LDC)
{
    import ldc.intrinsics : llvm_memset;
}
else private @nogc nothrow pure @system
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
Sets the array to all zero. When compiling with LDC uses an intrinsic
function that prevents the compiler from deeming the data write
unnecessary and omitting it. When not compiling with LDC uses
`explicit_bzero` on Linux, FreeBSD, and OpenBSD and `memset_s` on Mac
OS X for the same purpose. The typical use of this function is to
to erase secret keys after they are no longer needed.

Limitations:
On operating systems other than mentioned above, when not compiling
with LDC this function is the same as `array[] = 0` and is not
protected from being removed by the compiler.
+/
void explicitZero(scope ubyte[] array) @nogc nothrow pure @trusted
{
    if (__ctfe)
    {
        array[] = 0;
        return;
    }
    version (LDC)
    {
        static if (is(typeof(llvm_memset(array.ptr, 0, array.length, true)))) // LLVM 7+
            llvm_memset(array.ptr, 0, array.length, true); // "true" prevents removal.
        else // Pre-LLVM 7
            llvm_memset(array.ptr, 0, array.length, ubyte.alignof, true);
    }
    else version (linux)
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
