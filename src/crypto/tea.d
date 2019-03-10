module crypto.tea;

import std.bitmanip;
import std.exception;

package struct TEA
{
    private enum int DELTA = cast(int) 0x9E3779B9;
    private int[4] m_key;
    private int    m_rounds;

    public this(int[4] key)
    {
        m_key    = key;
        m_rounds = 32;
    }

    /// Encrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    public alias Crypt!(EncryptBlock) Encrypt;
    /// Decrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    public alias Crypt!(DecryptBlock) Decrypt;

    private const void Crypt(alias T)(ubyte[] _ubytes, size_t _offset = 0, long _count = -1)
    {
        if (_count == -1)
        {
            _count = cast(long)(_ubytes.length - _offset);
        }

        enforce(_count % 8 == 0);

        for (size_t i = _offset; i < (_offset + _count); i += 8)
        {
            T(_ubytes, i);
        }
    }

    /// Encrypt given block of 8 ubytes
    private const void EncryptBlock(ubyte[] _ubytes, size_t _offset)
    {
        auto v0 = _ubytes.peek!(int, Endian.littleEndian)(_offset);
        auto v1 = _ubytes.peek!(int, Endian.littleEndian)(_offset + 4);

        int sum = 0;

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
    private const void DecryptBlock(ubyte[] _ubytes, size_t _offset)
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
}

class Tea
{
	public static ubyte[] encrypt(in ubyte[] input, in char[] key)
	{
		ubyte[] buf = cast(ubyte[])key;
		int[4] bkey = [buf[0], buf[1], buf[2], buf[3]];

		return encrypt(input, bkey);
	}
	
    public static ubyte[] encrypt(in ubyte[] input, int[4] key)
    {
        ubyte[] data = input.dup;
        int orgi_len = cast(int)data.length;

		while ((data.length + 4) % 8 != 0)
        {
            data ~= 0;
        }

        ubyte[] len_buf = new ubyte[4];
        len_buf.write!int(orgi_len, 0);
        data ~= len_buf;

        TEA tea = TEA(key);
        tea.Encrypt(data);

        return data;
    }

	public static ubyte[] decrypt(in ubyte[] input, in char[] key)
	{
		ubyte[] buf = cast(ubyte[])key;
		int[4] bkey = [buf[0], buf[1], buf[2], buf[3]];

		return decrypt(input, bkey);
	}

    public static ubyte[] decrypt(in ubyte[] input, int[4] key)
    {
        auto data = input.dup;
        TEA tea = TEA(key);
        tea.Decrypt(data);

        int orgi_len;
        orgi_len = data.peek!int(data.length - 4);

        return data[0 .. orgi_len];
    }

    unittest
    {
        import std.stdio;
        import crypto.tea;

        ubyte[] data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        int[4] key = [1, 2, 3, 4];

        ubyte[] buf = Tea.encrypt(data, key);
        writeln(buf);
        buf = Tea.decrypt(buf, key);
        writeln(buf);
    }
}

package struct XTEA
{
    private enum int DELTA = cast(int) 0x9E3779B9;
    private int[4] m_key;
    private int m_rounds;

    public this(int[4] key, int rounds)
    {
        m_key    = key;
        m_rounds = rounds;
    }

    /// Encrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    public alias Crypt!(EncryptBlock) Encrypt;
    /// Decrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    public alias Crypt!(DecryptBlock) Decrypt;

    private const void Crypt(alias T)(ubyte[] _ubytes, size_t _offset = 0, long _count = -1)
    {
        if (_count == -1)
        {
            _count = cast(long)(_ubytes.length - _offset);
        }

        enforce(_count % 8 == 0);

        for (size_t i = _offset; i < (_offset + _count); i += 8)
        {
            T(_ubytes, i);
        }
    }

    /// Encrypt given block of 8 ubytes
    private const void EncryptBlock(ubyte[] _ubytes, size_t _offset)
    {
        auto v0 = _ubytes.peek!(int, Endian.littleEndian)(_offset);
        auto v1 = _ubytes.peek!(int, Endian.littleEndian)(_offset + 4);

        int sum = 0;

        foreach (i; 0 .. m_rounds)
        {
            v0 += ((v1 << 4 ^ cast(int)(cast(uint) v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
            sum += DELTA;
            v1 += ((v0 << 4 ^ cast(int)(cast(uint) v0 >> 5)) + v0) ^ (sum + m_key[cast(int)(cast(uint) sum >> 11) & 3]);
        }

        _ubytes.write!(int, Endian.littleEndian)(v0, _offset);
        _ubytes.write!(int, Endian.littleEndian)(v1, _offset + 4);
    }

    /// Decrypt given block of 8 ubytes
    private const void DecryptBlock(ubyte[] _ubytes, size_t _offset)
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

class Xtea
{
	public static ubyte[] encrypt(in ubyte[] input, in char[] key, int rounds = 64)
	{
		ubyte[] buf = cast(ubyte[])key;
		int[4] bkey = [buf[0], buf[1], buf[2], buf[3]];

		return encrypt(input, bkey, rounds);
	}
	
    public static ubyte[] encrypt(in ubyte[] input, int[4] key, int rounds = 64)
    {
        ubyte[] data = input.dup;
        int orgi_len = cast(int)data.length;

		while ((data.length + 4) % 8 != 0)
        {
            data ~= 0;
        }

        ubyte[] len_buf = new ubyte[4];
        len_buf.write!int(orgi_len, 0);
        data ~= len_buf;

        XTEA xtea = XTEA(key, rounds);
        xtea.Encrypt(data);

        return data;
    }

	public static ubyte[] decrypt(in ubyte[] input, in char[] key, int rounds = 64)
	{
		ubyte[] buf = cast(ubyte[])key;
		int[4] bkey = [buf[0], buf[1], buf[2], buf[3]];

		return decrypt(input, bkey, rounds);
	}

    public static ubyte[] decrypt(in ubyte[] input, int[4] key, int rounds = 64)
    {
        auto data = input.dup;
        XTEA xtea = XTEA(key, rounds);
        xtea.Decrypt(data);

        int orgi_len;
        orgi_len = data.peek!int(data.length - 4);

        return data[0 .. orgi_len];
    }

    unittest
    {
        import std.stdio;
        import crypto.tea;

        ubyte[] data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        int[4] key   = [1, 2, 3, 4];
        int rounds   = 64;

        ubyte[] buf = Xtea.encrypt(data, key, rounds);
        writeln(buf);
        buf = Xtea.decrypt(buf, key, rounds);
        writeln(buf);
    }
}
