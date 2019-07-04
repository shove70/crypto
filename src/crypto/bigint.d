module crypto.bigint;

import std.bigint;
import std.array : Appender;
import std.algorithm.mutation : reverse;
import std.conv : to, text;
import std.exception : enforce;

import crypto.random;

struct BigIntHelper
{
    /**
    Random generate a BigInt by bitLength.
    */
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

        return BigIntHelper.bigIntFromUByteArray(buffer);
    }

    /**
    Random generate a BigInt between min and max.
    */
    static BigInt randomGenerate(const BigInt min, const BigInt max)
    {
        enforce(max >= min, text("BigIntHelper.randomGenerate(): invalid bounding interval ", min, ", ", max));

        BigInt r = randomGenerate(cast(uint)((max.uintLength + 1) * uint.sizeof * 8));
        return r % (max - min + 1) + min;
    }

    ///
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

    ///
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

    static if (__VERSION__ >= 2087)
        alias powmod = std.bigint.powmod;
    else
    {
        ///
        static BigInt powmod(const BigInt base, const BigInt exponent, const BigInt modulus)
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
            // Generate random numbers between 2 and n - 1.
            bases = new BigInt[confidence];
            import std.algorithm.iteration : each;
            bases.each!((ref b) => (b = randomGenerate(BigInt(2), n - 1)));
        }

        import std.algorithm.searching : all;
        return (bases.all!((base) => (powmod(base, n - 1, n) == 1)));
    }

private:

    /++
        Bug BigInt mul() of phobos will be fixed in version 2.087.0
        Details:
            https://github.com/dlang/phobos/pull/6972
    +/
    static BigInt mul(const BigInt a, const BigInt b)
    {
        uint[] au = bigIntToUintArr(a);
        uint[] bu = bigIntToUintArr(b);

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

        return uintArrToBigInt(r);
    }

    static uint[] bigIntToUintArr(const BigInt data)
    {
        size_t n = data.uintLength();
        uint[] arr = new uint[n];

        for (size_t i = 0; i < n; i++)
        {
            arr[i] = data.getDigit!uint(i);
        }

        return arr;
    }

    static BigInt uintArrToBigInt(const uint[] arr)
    {
        size_t zeros = 0;
        foreach_reverse(d; arr)
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
