module crypto.tea;

import std.bitmanip;
import std.exception;

public import crypto.padding;

package class TEA
{
    this(const int[4] key)
    {
        m_key    = key;
        m_rounds = 32;
    }

    ~this()
    {
        import crypto.utils : secureZeroMemory;
        secureZeroMemory(m_key);
    }

    /// Encrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    alias encrypt = crypt!(encryptBlock);
    /// Decrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    alias decrypt = crypt!(decryptBlock);

    private void crypt(alias T)(ubyte[] _ubytes, size_t _offset = 0, long _count = -1)
    {
        if (_count == -1)
        {
            _count = cast(long)(_ubytes.length - _offset);
        }

        enforce(_count % 8 == 0);

        for (size_t i = _offset; i < _offset + _count; i += 8)
        {
            T(_ubytes, i);
        }
    }

    /// Encrypt given block of 8 ubytes
    private void encryptBlock(ubyte[] _ubytes, size_t _offset)
    {
        auto v0 = _ubytes.peek!(int, Endian.littleEndian)(_offset);
        auto v1 = _ubytes.peek!(int, Endian.littleEndian)(_offset + 4);

        int sum;

        foreach (i; 0 .. m_rounds)
        {
            sum += DELTA;
            v0 += ((v1 << 4) + m_key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + m_key[1]);
            v1 += ((v0 << 4) + m_key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + m_key[3]);
        }

        _ubytes.write!(int, Endian.littleEndian)(v0, _offset);
        _ubytes.write!(int, Endian.littleEndian)(v1, _offset + 4);
    }

    /// Decrypt given block of 8 ubytes
    private void decryptBlock(ubyte[] _ubytes, size_t _offset)
    {
        auto v0 = _ubytes.peek!(int, Endian.littleEndian)(_offset);
        auto v1 = _ubytes.peek!(int, Endian.littleEndian)(_offset + 4);

        auto sum = cast(int)(cast(uint) DELTA * cast(uint) m_rounds);  //0xC6EF3720

        foreach (i; 0 .. m_rounds)
        {
            v1 -= ((v0 << 4) + m_key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + m_key[3]);
            v0 -= ((v1 << 4) + m_key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + m_key[1]);
            sum -= DELTA;
        }

        _ubytes.write!(int, Endian.littleEndian)(v0, _offset);
        _ubytes.write!(int, Endian.littleEndian)(v1, _offset + 4);
    }
    private:
    enum int DELTA = cast(int) 0x9E3779B9;
    int[4] m_key;
    int    m_rounds;
}

///
struct Tea
{
    static ubyte[] encrypt(const ubyte[] input, const int[4] key, PaddingMode paddingMode = PaddingMode.NoPadding)
    {
        ubyte[] data = Padding.padding(input, 8, paddingMode);

        TEA tea = new TEA(key);
        tea.encrypt(data);

        return data;
    }

    static ubyte[] decrypt(const ubyte[] input, const int[4] key, PaddingMode paddingMode = PaddingMode.NoPadding)
    {
        auto data = input.dup;
        TEA tea = new TEA(key);
        tea.decrypt(data);

        return Padding.unpadding(data, 8, paddingMode);
    }
}

unittest
{
    ubyte[] data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    int[4] key = [1, 2, 3, 4];

    ubyte[] buf = Tea.encrypt(data, key, PaddingMode.PKCS5);
    buf = Tea.decrypt(buf, key, PaddingMode.PKCS5);
    assert(data == buf);
}

private class XTEA
{
    private enum DELTA = cast(int) 0x9E3779B9;
    private int[4] m_key;
    private int m_rounds;

    public this(const int[4] key, int rounds)
    {
        m_key    = key.dup;
        m_rounds = rounds;
    }

    ~this()
    {
        import crypto.utils : secureZeroMemory;
        secureZeroMemory(m_key);
    }

    /// Encrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    alias encrypt = crypt!encryptBlock;
    /// Decrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    alias decrypt = crypt!decryptBlock;

    private void crypt(alias T)(ubyte[] _ubytes, size_t _offset = 0, long _count = -1)
    {
        if (_count == -1)
        {
            _count = cast(long)(_ubytes.length - _offset);
        }

        enforce(_count % 8 == 0);

        for (size_t i = _offset; i < _offset + _count; i += 8)
        {
            T(_ubytes, i);
        }
    }

    /// Encrypt given block of 8 ubytes
    private void encryptBlock(ubyte[] _ubytes, size_t _offset)
    {
        auto v0 = _ubytes.peek!(int, Endian.littleEndian)(_offset);
        auto v1 = _ubytes.peek!(int, Endian.littleEndian)(_offset + 4);

        int sum;

        foreach (i; 0 .. m_rounds)
        {
            v0 += ((v1 << 4 ^ v1 >>> 5) + v1) ^ (sum + m_key[sum & 3]);
            sum += DELTA;
            v1 += ((v0 << 4 ^ v0 >>> 5) + v0) ^ (sum + m_key[sum >>> 11 & 3]);
        }

        _ubytes.write!(int, Endian.littleEndian)(v0, _offset);
        _ubytes.write!(int, Endian.littleEndian)(v1, _offset + 4);
    }

    /// Decrypt given block of 8 ubytes
    private void decryptBlock(ubyte[] _ubytes, size_t _offset)
    {
        auto v0 = _ubytes.peek!(int, Endian.littleEndian)(_offset);
        auto v1 = _ubytes.peek!(int, Endian.littleEndian)(_offset + 4);

        auto sum = cast(int)(cast(uint) DELTA * cast(uint) m_rounds);

        foreach (i; 0 .. m_rounds)
        {
            v1 -= ((v0 << 4 ^ cast(int)(cast(uint) v0 >> 5)) + v0) ^ (sum + m_key[cast(int)(cast(uint) sum >> 11) & 3]);
            sum -= DELTA;
            v0 -= ((v1 << 4 ^ cast(int)(cast(uint) v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
        }

        _ubytes.write!(int, Endian.littleEndian)(v0, _offset);
        _ubytes.write!(int, Endian.littleEndian)(v1, _offset + 4);
    }
}

///
struct Xtea
{
    static ubyte[] encrypt(const ubyte[] input, const int[4] key, int rounds = 64, PaddingMode paddingMode = PaddingMode.NoPadding)
    {
        ubyte[] data = Padding.padding(input, 8, paddingMode);

        XTEA xtea = new XTEA(key, rounds);
        xtea.encrypt(data);

        return data;
    }

    static ubyte[] decrypt(const ubyte[] input, const int[4] key, int rounds = 64, PaddingMode paddingMode = PaddingMode.NoPadding)
    {
        auto data = input.dup;
        XTEA xtea = new XTEA(key, rounds);
        xtea.decrypt(data);

        return Padding.unpadding(data, 8, paddingMode);
    }
}

unittest
{
    ubyte[] data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    int[4] key = [1, 2, 3, 4];
    enum rounds = 64;

    ubyte[] buf = Xtea.encrypt(data, key, rounds, PaddingMode.PKCS5);
    buf = Xtea.decrypt(buf, key, rounds, PaddingMode.PKCS5);
    assert(data == buf);
}
