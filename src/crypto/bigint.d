module crypto.bigint;

import std.bigint;
import std.algorithm.mutation : reverse;
import std.algorithm.searching : find;
import std.conv : to, text;
import std.exception : enforce;
import std.range : repeat, array;

import crypto.random;

struct BigIntHelper
{
    /// Random generate a BigInt by bitLength.
    static BigInt randomGenerate(uint bitLength, int highBit = -1, int lowBit = -1)
    {
        enforce((bitLength > 0) && (bitLength % 8 == 0));

        ubyte[] buffer = new ubyte[bitLength / 8];

        uint pos = 0;
        uint current = 0;
        foreach (ref a; buffer)
        {
            if (pos == 0)
            {
                current = rnd.next;
            }

            a = cast(ubyte)(current >> 8 * pos);
            pos = (pos + 1) % uint.sizeof;
        }

        if (highBit == 0)
        {
            buffer[0] &= (0xFF >> 1);
        }
        else if (highBit == 1)
        {
            buffer[0] |= (0x01 << 7);
        }

        if (lowBit == 0)
        {
            buffer[$ - 1] &= (0xFF << 1);
        }
        else if (lowBit == 1)
        {
            buffer[$ - 1] |= 0x01;
        }

        return BigIntHelper.fromBytes(buffer);
    }

    /// Random generate a BigInt between min and max.
    static BigInt randomGenerate(const BigInt min, const BigInt max)
    {
        enforce(max >= min, text("BigIntHelper.randomGenerate(): invalid bounding interval ", min, ", ", max));

        BigInt r = randomGenerate(cast(uint)((max.uintLength + 1) * uint.sizeof * 8));
        return r % (max - min + 1) + min;
    }

    ///
    static ubyte[] toUBytes(const BigInt value) pure nothrow
    {
        size_t len = value.uintLength();
        ubyte[] ubytes = new ubyte[len * uint.sizeof];

        for (size_t i = 0; i < len; i++)
        {
            uint digit = value.getDigit!uint(i);
            ubyte* p = cast(ubyte*)&digit;

            for (size_t j = 0; j < uint.sizeof; j++)
            {
                ubytes[(len - i - 1) * uint.sizeof + (uint.sizeof - j - 1)] = *(p + j);
            }
        }

        return ubytes.find!((a, b) => a != b)(0);
    }

    /++
        Because std.bigint's member `data` is a private property,
        and there is no API `setDigit` that opens the opposite of getDigit,
        it can only be shifted by digits one by one.
        !! Here is a performance bottleneck.
    +/
    static BigInt fromBytes(in ubyte[] buffer) pure nothrow
    {
        size_t supplement = (uint.sizeof - buffer.length % uint.sizeof) % uint.sizeof;
        ubyte[] bytes = (supplement > 0) ? (cast(ubyte)0).repeat(supplement).array ~ buffer : cast(ubyte[])buffer;
        BigInt data = 0;

        for (size_t i = 0; i < bytes.length / uint.sizeof; i++)
        {
            uint digit;
            ubyte* p = cast(ubyte*)&digit;

            for (size_t j = 0; j < uint.sizeof; j++)
            {
                *(p + j) = bytes[i * uint.sizeof + uint.sizeof - j - 1];
            }

            data <<= 32;
            data += digit;
        }

        return data;
    }

    static if (__VERSION__ >= 2087)
        alias powmod = std.bigint.powmod;
    else
    {
        ///
        static BigInt powmod(const BigInt base, const BigInt exponent, const BigInt modulus) pure nothrow
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

            BigInt temp = powmod(base, exponent / 2, modulus);

            return (exponent & 1) ? mul(mul(temp, temp), base) % modulus : mul(temp, temp) % modulus;
        }
    }

    ///
    static bool millerRabinPrimeTest(const BigInt n, const size_t confidence)
    {
        enforce(confidence > 0, "confidence must be a positive integer greater than 0.");

        if (n < 2)
        {
            return false;
        }
        if (n == 2)
        {
            return true;
        }

        BigInt[] bases;
        if (n < 1_373_653)
        {
            bases = [BigInt(2), BigInt(3)];
        }
        else if (n <= 9_080_191)
        {
            bases = [BigInt(31), BigInt(73)];
        }
        else if (n <= 4_759_123_141)
        {
            bases = [BigInt(2), BigInt(7), BigInt(61)];
        }
        else if (n <= 2_152_302_898_747)
        {
            bases = [BigInt(2), BigInt(3), BigInt(5), BigInt(7), BigInt(11)];
        }
        else if (n <= 341_550_071_728_320)
        {
            if (n == 46_856_248_255_981)
            {
                return false;
            }

            bases = [BigInt(2), BigInt(3), BigInt(5), BigInt(7), BigInt(11), BigInt(13), BigInt(17)];
        }
        else if (n < 10_000_000_000_000_000)
        {
            bases = [BigInt(2), BigInt(3), BigInt(7), BigInt(61), BigInt(24251)];
        }
        else
        {
            /**
            Although in theory base should be between 2 and n - 1, because confidence is optimized before call,
            the larger n is, the smaller confidence is, so the requirement for base can not be too small,
            so the minimum value does not use 2, but uses n / 2 instead.
            */
            bases = new BigInt[confidence];
            import std.algorithm.iteration : each;
            bases.each!((ref b) => (b = randomGenerate(n / 2, n - 1)));
            //bases.each!((ref b) => (b = randomGenerate(BigInt(2), n - 1)));
        }

        import std.algorithm.searching : all;
        return (bases.all!((base) => (powmod(base, n - 1, n) == 1)));
    }

    static uint[] partialPrimesTable = [
        65003, 65011, 65027, 65029, 65033, 65053, 65063, 65071, 65089, 65099,
        65101, 65111, 65119, 65123, 65129, 65141, 65147, 65167, 65171, 65173,
        65179, 65183, 65203, 65213, 65239, 65257, 65267, 65269, 65287, 65293,
        65309, 65323, 65327, 65353, 65357, 65371, 65381, 65393, 65407, 65413,
        65419, 65423, 65437, 65447, 65449, 65479, 65497, 65519, 65521, 65537 ];

private:

    /++
        Bug BigInt mul() of phobos will be fixed in version 2.087.0
        Details:
            https://github.com/dlang/phobos/pull/6972
    +/
    static if (__VERSION__ < 2087)
    {
        static BigInt mul(const BigInt a, const BigInt b) pure nothrow
        {
            uint[] au = toUintArray(a);
            uint[] bu = toUintArray(b);

            uint[] r = new uint[au.length + bu.length];

            for (size_t i = 0; i < bu.length; i++)
            {
                for (size_t j = 0; j < au.length; j++)
                {
                    ulong t = cast(ulong)bu[i] * au[j] + r[i + j];
                    r[i + j] = t & 0xFFFF_FFFF;
                    uint c = t >> 32;
                    size_t h = i + j + 1;

                    while (c != 0)
                    {
                        t = cast(ulong)c + r[h];
                        r[h] = t & 0xFFFF_FFFF;
                        c = t >> 32;
                        h++;
                    }
                }
            }

            return fromUintArray(r);
        }

        static uint[] toUintArray(const BigInt data) pure nothrow
        {
            size_t n = data.uintLength();
            uint[] arr = new uint[n];

            for (size_t i = 0; i < n; i++)
            {
                arr[i] = data.getDigit!uint(i);
            }

            return arr;
        }

        static BigInt fromUintArray(const uint[] arr) pure nothrow
        {
            size_t zeros = 0;
            foreach_reverse (d; arr)
            {
                if (d != 0)
                {
                    break;
                }

                zeros++;
            }

            BigInt data = 0;

            foreach_reverse (d; arr[0..$ - zeros])
            {
                data <<= 32;
                data += d;
            }

            return data;
        }
    }
}
