module crypto.tea.xtea;

import std.bitmanip;
import std.exception;

package struct XTEA
{
    /// XTEA delta constant
    private enum int DELTA = cast(int) 0x9E3779B9;

    /// Key - 4 integer
    private int[4] m_key;

    /// Round to go - 64 are commonly used
    private int m_rounds;

    /// c'tor
    public this(int[4] _key, int _rounds)
    {
        m_key = _key;
        m_rounds = _rounds;
    }

    /// Encrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    public alias Crypt!(EncryptBlock) Encrypt;
    /// Decrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
    public alias Crypt!(DecryptBlock) Decrypt;

    ///
    private const void Crypt(alias T)(ubyte[] _ubytes, size_t _offset = 0, long _count = -1)
    {
        if (_count == -1)
            _count = cast(long)(_ubytes.length - _offset);

        enforce(_count % 8 == 0);

        for (size_t i = _offset; i < (_offset + _count); i += 8)
            T(_ubytes, i);
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
            v1 += ((v0 << 4 ^ cast(int)(cast(uint) v0 >> 5)) + v0) ^ (
                    sum + m_key[cast(int)(cast(uint) sum >> 11) & 3]);
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
            v1 -= ((v0 << 4 ^ cast(int)(cast(uint) v0 >> 5)) + v0) ^ (
                    sum + m_key[cast(int)(cast(uint) sum >> 11) & 3]);
            sum -= DELTA;
            v0 -= ((v1 << 4 ^ cast(int)(cast(uint) v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
        }

        _ubytes.write!(int, Endian.littleEndian)(v0, _offset);
        _ubytes.write!(int, Endian.littleEndian)(v1, _offset + 4);
    }
}

class Xtea
{
	public static ubyte[] encrypt(ubyte[] input, string key, int rounds = 64)
	{
		ubyte[] buf = cast(ubyte[])key;
		int[4] bkey = [buf[0], buf[1], buf[2], buf[3]];

		return encrypt(input, bkey, rounds);
	}
	
    public static ubyte[] encrypt(ubyte[] input, int[4] key, int rounds = 64)
    {
        ubyte[] data = input.dup;
        int orgi_len = cast(int)data.length;
		while ((data.length + 4) % 8 != 0)
            data ~= 0;
            
        ubyte[] len_buf = new ubyte[4];
        len_buf.write!int(orgi_len, 0);
        data ~= len_buf;

        XTEA xeta = XTEA(key, rounds);
        xeta.Encrypt(data);
        return data;
    }

	public static ubyte[] decrypt(ubyte[] input, string key, int rounds = 64)
	{
		ubyte[] buf = cast(ubyte[])key;
		int[4] bkey = [buf[0], buf[1], buf[2], buf[3]];

		return decrypt(input, bkey, rounds);
	}

    public static ubyte[] decrypt(ubyte[] input, int[4] key, int rounds = 64)
    {
        auto data = input.dup;
        XTEA xeta = XTEA(key, rounds);
        xeta.Decrypt(data);

        int orgi_len;
        orgi_len = data.peek!int(data.length - 4);
        return data[0 .. orgi_len];
    }

    unittest
    {
        import crypto.tea.xtea;

        ubyte[] data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        int[4] key = [1, 2, 3, 4];
        int rounds = 64;

        ubyte[] buf = Xtea.encrypt(data, key, rounds);
        writeln(buf);
        buf = Xtea.decrypt(buf, key, rounds);
        writeln(buf);
    }
}
