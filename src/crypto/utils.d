module crypto.utils;

import std.bigint;
import std.array;
import std.algorithm;
import std.conv;

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

        static if (__VERSION__ >= 2087)
            return (exponent & 1) ? (temp * temp * base) % modulus : (temp * temp) % modulus;
        else
            return (exponent & 1) ? mul(mul(temp, temp), base) % modulus : mul(temp, temp) % modulus;
    }

private:

    /++
        Bug BigInt mul() of phobos will be fixed in version 2.086.1
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
