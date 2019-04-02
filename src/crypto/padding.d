module crypto.padding;

import std.exception;
import std.array;
import std.algorithm;

import crypto.utils;

enum PaddingMode
{
    NoPadding,       // None
    ANSIX923,        // 00 00 00 04 (Zeros  + size)
    ISO10126,        // 0A EB 02 04 (Random + size)
    PKCS5,           // 04 04 04 04 (All size)
    PKCS7,           // 04 04 04 04 (All size)
    Zeros            // 00 00 00 00 (All zero)
}

alias PaddingNoPadding = PaddingImpl!("None",   "None");
alias PaddingANSIX923  = PaddingImpl!("Zero",   "Size");
alias PaddingISO10126  = PaddingImpl!("Random", "Size");
alias PaddingPKCS5     = PaddingImpl!("Size",   "Size");
alias PaddingPKCS7     = PaddingImpl!("Size",   "Size");
alias PaddingZeros     = PaddingImpl!("Zero",   "Zero");

class PaddingImpl(string fill, string suffix)
{
    static ubyte[] padding(in ubyte[] data, size_t blockSize)
    {
        enforce(((blockSize > 0) && (blockSize % 8 == 0)), "Invalid block size, which must be a multiple of 8.");

        static if ((fill == "None") || (suffix == "None"))
        {
            enforce(((data.length > 0) && (data.length % blockSize == 0)), "Invalid data size, which must be a multiple of blockSize.");

            return cast(ubyte[])data;
        }
        else
        {
            size_t paddingSize = blockSize - data.length % blockSize;
            int index = cast(int)paddingSize - 1;

            ubyte[] buf = new ubyte[paddingSize];

            void fillA(string type)
            {
                switch (type)
                {
                    case "Zero":
                        buf[index] = 0x00;
                        break;
                    case "Random":
                        buf[index] = rnd.next!ubyte;
                        break;
                    case "Size":
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
    }

    static ubyte[] unpadding(in ubyte[] data, size_t blockSize)
    {
        enforce(((blockSize > 0) && (blockSize % 8 == 0)), "Invalid block size, which must be a multiple of 8.");
        enforce(((data.length > 0) && (data.length % blockSize == 0)), "Invalid data size, which must be a multiple of blockSize.");

        static if ((fill == "None") || (suffix == "None"))
        {
            return cast(ubyte[])data;
        }
        else static if ((fill == "Zero") && (suffix == "Size"))
        {
            size_t size = data[$ - 1];
            enforce(size <= blockSize, "Error Padding Mode.");
            enforce(data[data.length - size .. $ - 1].all!((a) => (a == 0)), "Error Padding Mode.");

            return cast(ubyte[])data[0..data.length - size];
        }
        else static if ((fill == "Random") && (suffix == "Size"))
        {
            size_t size = data[$ - 1];
            enforce(size <= blockSize, "Error Padding Mode.");

            return cast(ubyte[])data[0..data.length - size];
        }
        else static if ((fill == "Size") && (suffix == "Size"))
        {
            size_t size = data[$ - 1];
            enforce(size <= blockSize, "Error Padding Mode.");
            enforce(data[data.length - size .. $ - 1].all!((a) => (a == size)), "Error Padding Mode.");

            return cast(ubyte[])data[0..data.length - size];
        }
        else static if ((fill == "Zero") && (suffix == "Zero"))
        {
            enforce(data[$ - 1] == 0, "Error Padding Mode.");
            int index = cast(int)data.length - 1;

            while ((index >= 0) && (data[index] == 0))
            {
                index--;
            }

            return cast(ubyte[])data[0..index + 1];
        }
        else
        {
            assert(0);
        }
    }
}

unittest
{
    import std.stdio;
    ubyte[] data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    ubyte[] paddinged = PaddingPKCS5.padding(data, 8);
    writeln(paddinged);

    data = PaddingPKCS5.unpadding(paddinged, 8);
    writeln(data);
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
        }
    }
}
