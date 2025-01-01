module crypto.padding;

import std.exception;
import std.algorithm;
import std.bitmanip;

import crypto.random;

enum PaddingMode
{
    NoPadding,       // None
    ANSIX923,        // 00 00 00 04 (Zero   + size)
    ISO10126,        // 0A EB 02 04 (Random + size)
    PKCS5,           // 04 04 04 04 (All size)
    PKCS7,           // 04 04 04 04 (All size)
    Zeros,           // 00 00 00 00 (All zero)
    Customized       // 00 00 00 00 + (00 00 00 04) (Zero + Original size)
}

private enum PaddingStuff
{
    None, Zero, Random, Size, OriginalSize
}

alias
PaddingNoPadding  = PaddingImpl!(PaddingStuff.None,   PaddingStuff.None),
PaddingANSIX923   = PaddingImpl!(PaddingStuff.Zero,   PaddingStuff.Size),
PaddingISO10126   = PaddingImpl!(PaddingStuff.Random, PaddingStuff.Size),
PaddingPKCS5      = PaddingImpl!(PaddingStuff.Size,   PaddingStuff.Size),
PaddingPKCS7      = PaddingImpl!(PaddingStuff.Size,   PaddingStuff.Size),
PaddingZeros      = PaddingImpl!(PaddingStuff.Zero,   PaddingStuff.Zero),
PaddingCustomized = PaddingImpl!(PaddingStuff.Zero,   PaddingStuff.OriginalSize);   // For downward compatibility.

class PaddingImpl(PaddingStuff fill, PaddingStuff suffix)
{
    static ubyte[] padding(in ubyte[] data, size_t blockSize)
    {
        enforce(blockSize > 0 && blockSize % 8 == 0, "Invalid block size, which must be a multiple of 8.");
        static assert(suffix != PaddingStuff.OriginalSize || fill == PaddingStuff.Zero,
            "PaddingCustomized require: Zero + OriginalSize.");

        static if (fill == PaddingStuff.None || suffix == PaddingStuff.None)
        {
            enforce(data.length > 0 && data.length % blockSize == 0, "Invalid data size, which must be a multiple of blockSize.");

            return cast(ubyte[])data;
        }
        else static if (suffix != PaddingStuff.OriginalSize)
        {
            size_t paddingSize = blockSize - data.length % blockSize;
            int index = cast(int)paddingSize - 1;

            ubyte[] buf = new ubyte[paddingSize];

            void fillA(PaddingStuff type)
            {
                switch (type)
                {
                    case PaddingStuff.Zero:
                        buf[index] = 0x00;
                        break;
                    case PaddingStuff.Random:
                        buf[index] = rnd.next!ubyte;
                        break;
                    case PaddingStuff.Size:
                        buf[index] = cast(ubyte)paddingSize;
                        break;
                    default:
                        assert(0);
                }
            }

            fillA(suffix);

            while (--index >= 0)
            {
                fillA(fill);
            }

            return data ~ buf;
        }
        else
        {
            ubyte[] buf;

            while ((data.length + buf.length + 4) % 8 != 0)
            {
                buf ~= 0x00;
            }

            ubyte[] len_buf = new ubyte[4];
            len_buf.write!int(cast(int)data.length, 0);

            return data ~ buf ~ len_buf;
        }
    }

    static ubyte[] unpadding(in ubyte[] data, size_t blockSize)
    {
        enforce(blockSize > 0 && blockSize % 8 == 0, "Invalid block size, which must be a multiple of 8.");
        enforce(data.length > 0 && data.length % blockSize == 0, "Invalid data size, which must be a multiple of blockSize.");
        static assert(suffix != PaddingStuff.OriginalSize || fill == PaddingStuff.Zero, "PaddingCustomized require: Zero + OriginalSize.");

        static if (fill == PaddingStuff.None || suffix == PaddingStuff.None)
        {
            return cast(ubyte[])data;
        }
        else static if (fill == PaddingStuff.Zero && suffix == PaddingStuff.Size)
        {
            size_t size = data[$ - 1];
            enforce(size <= blockSize, "Error Padding Mode.");
            enforce(data[data.length - size..$ - 1].all!((a) => a == 0), "Error Padding Mode.");

            return cast(ubyte[])data[0..data.length - size];
        }
        else static if (fill == PaddingStuff.Random && suffix == PaddingStuff.Size)
        {
            size_t size = data[$ - 1];
            enforce(size <= blockSize, "Error Padding Mode.");

            return cast(ubyte[])data[0..data.length - size];
        }
        else static if (fill == PaddingStuff.Size && suffix == PaddingStuff.Size)
        {
            size_t size = data[$ - 1];
            enforce(size <= blockSize, "Error Padding Mode.");
            enforce(data[data.length - size..$ - 1].all!((a) => a == size), "Error Padding Mode.");

            return cast(ubyte[])data[0..data.length - size];
        }
        else static if (fill == PaddingStuff.Zero && suffix == PaddingStuff.Zero)
        {
            enforce(data[$ - 1] == 0, "Error Padding Mode.");
            int index = cast(int)data.length - 1;

            while (index >= 0 && data[index] == 0)
            {
                index--;
            }

            return cast(ubyte[])data[0..index + 1];
        }
        else static if (fill == PaddingStuff.Zero && suffix == PaddingStuff.OriginalSize)
        {
            int orgi_len;
            orgi_len = data.peek!int(data.length - 4);

            enforce(orgi_len >= 0 && orgi_len <= data.length - 4, "Invalid parameter: data.");

            for (size_t i = orgi_len; i < data.length - 4; i++)
            {
                enforce(data[i] == 0, "Invalid parameter: data.");
            }

            return cast(ubyte[])data[0..orgi_len];
        }
        else
        {
            assert(0);
        }
    }
}

unittest
{
    ubyte[] data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    ubyte[] paddinged = PaddingPKCS5.padding(data, 8);
    ubyte[] unpaddinged = PaddingPKCS5.unpadding(paddinged, 8);
    assert(data == unpaddinged);
}

class Padding
{
    static ubyte[] padding(in ubyte[] data, size_t blockSize, PaddingMode paddingMode)
    {
        final switch (paddingMode)
        {
            case PaddingMode.NoPadding:
                return PaddingNoPadding.padding(data, blockSize);
            case PaddingMode.ANSIX923:
                return PaddingANSIX923.padding(data, blockSize);
            case PaddingMode.ISO10126:
                return PaddingISO10126.padding(data, blockSize);
            case PaddingMode.PKCS5:
                return PaddingPKCS5.padding(data, blockSize);
            case PaddingMode.PKCS7:
                return PaddingPKCS7.padding(data, blockSize);
            case PaddingMode.Zeros:
                return PaddingZeros.padding(data, blockSize);
            case PaddingMode.Customized:
                return PaddingCustomized.padding(data, blockSize);
        }
    }

    static ubyte[] unpadding(in ubyte[] data, size_t blockSize, PaddingMode paddingMode)
    {
        final switch (paddingMode)
        {
            case PaddingMode.NoPadding:
                return PaddingNoPadding.unpadding(data, blockSize);
            case PaddingMode.ANSIX923:
                return PaddingANSIX923.unpadding(data, blockSize);
            case PaddingMode.ISO10126:
                return PaddingISO10126.unpadding(data, blockSize);
            case PaddingMode.PKCS5:
                return PaddingPKCS5.unpadding(data, blockSize);
            case PaddingMode.PKCS7:
                return PaddingPKCS7.unpadding(data, blockSize);
            case PaddingMode.Zeros:
                return PaddingZeros.unpadding(data, blockSize);
            case PaddingMode.Customized:
                return PaddingCustomized.unpadding(data, blockSize);
        }
    }
}
