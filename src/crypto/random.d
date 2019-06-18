module crypto.random;

import std.traits : isIntegral;
import std.random;

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
        T next(T = uint)(T min = T.min, T max = T.max) if (isIntegral!T)
        {
            if (min == T.min && max == T.max)
                return cast(T) arc4random();
            else
                return cast(T) (min + arc4random_uniform(1U + max - min));
        }
    }

    __gshared ARC4RandomGenerator rnd; // Can be global because it has no mutable state.
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
        T next(T = uint)(T min = T.min, T max = T.max) if (isIntegral!T)
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

    static CryptGenRandomGenerator rnd; // Thread-local because it has a mutable buffer.
}
else
{
    /++ Fast but cryptographically insecure source of random numbers. +/
    struct InsecureRandomGenerator
    {
        private static Mt19937 generator;

        static this()
        {
            generator.seed(unpredictableSeed);
        }

        /++
        Params:
            min = min inclusive
            max = max inclusive
        Returns: `x` such that `min <= x <= max`
        +/
        T next(T = uint)(T min = T.min, T max = T.max) if (isIntegral!T)
        {
            return uniform!("[]", T, T, typeof(generator))(min, max, generator);
        }
    }

    __gshared InsecureRandomGenerator rnd; // Can be global because it has no mutable state.
}
