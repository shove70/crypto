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

        return (exponent & 1) ? (temp * temp * base) % modulus : (temp * temp) % modulus;
    }
}
