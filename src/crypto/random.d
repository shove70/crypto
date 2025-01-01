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
        enum min = uint.min;
        enum max = uint.max;
        enum isUniformRandom = true;
        enum empty = false;

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
else version (Posix)
{
    version (linux)
    {
        // getentropy available on Linux 3.17 and later.
        // http://www.man7.org/linux/man-pages/man3/getentropy.3.html
        import core.sys.linux.dlfcn : dlsym, RTLD_DEFAULT;
        private enum maybeHasGetEntropy = true;
    }
    else version (FreeBSD)
    {
        // getentropy available on FreeBSD 12 and later.
        // https://www.freebsd.org/cgi/man.cgi?query=getentropy&sektion=3&manpath=FreeBSD+12.0-stable
        import core.sys.freebsd.dlfcn : dlsym, RTLD_DEFAULT;
        private enum maybeHasGetEntropy = true;
    }
    else version (Solaris)
    {
        // getentropy available on Solaris 11.3 and later.
        // https://docs.oracle.com/cd/E86824_01/html/E54765/getentropy-2.html#REFMAN2getentropy-2
        import core.sys.solaris.dlfcn : dlsym, RTLD_DEFAULT;
        private enum maybeHasGetEntropy = true;
    }
    else
    {
        private enum maybeHasGetEntropy = false;
    }

    /++ Cryptographically secure source of random numbers. Not available on all platforms. +/
    struct PosixRandomGenerator
    {
        private uint[32] buffer; // Fill using `getentropy` if possible. Otherwise fill using /dev/urandom.
        private uint pos = buffer.length;

        static if (maybeHasGetEntropy)
        {
            private alias GetEntropyFn = extern(C) int function(scope void*, size_t) @nogc nothrow @system;
            private __gshared GetEntropyFn getentropy; // If unavailable, null.
            shared static this()
            {
                getentropy = cast(GetEntropyFn) dlsym(RTLD_DEFAULT, "getentropy");
            }
            static assert(buffer.sizeof <= 256, "buffer must be no more than 256 bytes for use with getentropy");
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
        enum min = uint.min;
        enum max = uint.max;
        enum isUniformRandom = true;
        enum empty = false;

        uint front() @trusted
        {
            if (pos >= buffer.length)
            {
                static if (maybeHasGetEntropy)
                {
                    if (getentropy is null || 0 != getentropy(buffer.ptr, buffer.sizeof))
                        fillBufferFromDevUrandom();
                }
                else
                {
                    fillBufferFromDevUrandom();
                }
                pos = 0;
            }
            return buffer[pos];
        }

        void popFront() @nogc nothrow @safe
        {
            pos++;
        }

        private void fillBufferFromDevUrandom()
        {
            import core.stdc.errno : errno, EAGAIN, EINTR;//, EWOULDBLOCK;
            import core.sys.posix.fcntl : open, O_RDONLY;
            import core.sys.posix.unistd : close, read;

            static if (maybeHasGetEntropy)
                pragma(inline, false);

            // Open file descriptor.
            int fd;
            while (-1 == (fd = open("/dev/urandom", O_RDONLY)))
            {
                import std.exception : ErrnoException;
                if (errno != EAGAIN && errno != EINTR)
                    throw new ErrnoException("Error opening /dev/urandom");
            }
            scope(exit) close(fd);

            // Read from /dev/urandom.
            ubyte* ptr = cast(ubyte*) buffer.ptr;
            size_t remaining = buffer.sizeof;
            do {
                const nread = read(fd, ptr, remaining);
                if (nread >= 0)
                {
                    remaining -= nread;
                }
                else
                {
                    import std.exception : ErrnoException;
                    if (errno != EAGAIN && errno != EINTR/* && errno != EWOULDBLOCK*/)
                        throw new ErrnoException("Error reading from /dev/urandom");
                }
            } while (remaining > 0);
        }
    }

    static PosixRandomGenerator rnd; // Thread-local because it has a mutable buffer.
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
