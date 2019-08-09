module crypto.base58;

import std.bigint;
import std.conv;

public class Base58
{
    public static char[] ALPHABET = cast(char[]) "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static int[] INDEXES = new int[128];

    static this()
    {
        for (int i = 0; i < INDEXES.length; i++)
        {
            INDEXES[i] = -1;
        }

        for (int i = 0; i < ALPHABET.length; i++)
        {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    /// Encodes the given bytes as a base58 string (no checksum is appended).
    public static string encode(in byte[] inp)
    {
        if (inp.length == 0)
        {
            return "";
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < inp.length && inp[zeros] == 0)
        {
            ++zeros;
        }
        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
        auto input = new byte[inp.length];
        input[0 .. inp.length] = inp[0 .. $]; // since we modify it in-place
        auto encoded = new char[input.length * 2]; // upper bound
        auto outputStart = encoded.length;

        for (int inputStart = zeros; inputStart < input.length;)
        {
            encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];

            if (input[inputStart] == 0)
            {
                ++inputStart; // optimization - skip leading zeros
            }
        }
        // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
        while (outputStart < encoded.length && encoded[outputStart] == ALPHABET[0])
        {
            ++outputStart;
        }

        while (--zeros >= 0)
        {
            encoded[--outputStart] = ALPHABET[0];
        }
        // Return encoded string (including encoded leading zeros).
        return encoded[outputStart .. encoded.length].to!string();
    }

    /// Decodes the given base58 string into the original data bytes.
    public static byte[] decode(in char[] input)
    {
        if (input.length == 0)
        {
            return new byte[0];
        }
        // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
        byte[] input58 = new byte[input.length];

        for (int i = 0; i < input.length; ++i)
        {
            char c = input[i];
            int digit = c < 128 ? INDEXES[c] : -1;

            if (digit < 0)
            {
                throw new Exception("Illegal character " ~ c ~ " at position " ~ to!string(i));
            }

            input58[i] = cast(byte) digit;
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0)
        {
            ++zeros;
        }
        // Convert base-58 digits to base-256 digits.
        byte[] decoded = new byte[input.length];
        int outputStart = cast(int) decoded.length;

        for (int inputStart = zeros; inputStart < input58.length;)
        {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256);

            if (input58[inputStart] == 0)
            {
                ++inputStart; // optimization - skip leading zeros
            }
        }
        // Ignore extra leading zeroes that were added during the calculation.
        while (outputStart < decoded.length && decoded[outputStart] == 0)
        {
            ++outputStart;
        }
        // Return decoded data (including original number of leading zeros).
        return decoded[outputStart - zeros .. decoded.length];
    }

    private static BigInt decodeToBigInteger(string input)
    {
        return BigInt(cast(string) decode(input));
    }

    /++
    Divides a number, represented as an array of bytes each containing a single digit
    in the specified base, by the given divisor. The given number is modified in-place
    to contain the quotient, and the return value is the remainder.
    +/
    private static byte divmod(byte[] number, int firstDigit, int base, int divisor)
    {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;

        for (int i = firstDigit; i < number.length; i++)
        {
            int digit = cast(int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = cast(byte)(temp / divisor);
            remainder = temp % divisor;
        }

        return cast(byte) remainder;
    }
}

unittest
{
    string data = "abcdef1234";
    string en = Base58.encode(cast(byte[]) data);
    byte[] de = Base58.decode(en);
    assert(data == cast(string) de);
}
