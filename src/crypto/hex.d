module crypto.hex;

import std.traits;

// from https://github.com/dlang/phobos/pull/3058/files

/**
Check the correctness of a string for `hexString`.
The result is true if and only if the input string is composed of whitespace
characters (\f\n\r\t\v lineSep paraSep nelSep) and
an even number of hexadecimal digits (regardless of the case).
*/
@safe pure @nogc
private bool isHexLiteral(String)(scope const String hexData)
{
    import std.ascii : isHexDigit;
    import std.uni : lineSep, paraSep, nelSep;
    size_t i;
    foreach (dchar c; hexData)
    {
        switch (c)
        {
            case ' ', '\t', '\v', '\f', '\r', '\n',
                lineSep, paraSep, nelSep:
            continue;

            default:
        }
        if (!c.isHexDigit)
            return false;
        ++i;
    }
    return !(i & 1);
}

///
@safe unittest
{
    // test all the hex digits
    static assert("0123456789abcdefABCDEF".isHexLiteral);
    // empty or white strings are not valid
    static assert("\r\n\t".isHexLiteral);
    // but are accepted if the count of hex digits is even
    static assert("A\r\n\tB".isHexLiteral);
}

@safe unittest
{
    import std.ascii;
    // empty/whites
    static assert("".isHexLiteral);
    static assert(" \r".isHexLiteral);
    static assert(whitespace.isHexLiteral);
    static assert(""w.isHexLiteral);
    static assert(" \r"w.isHexLiteral);
    static assert(""d.isHexLiteral);
    static assert(" \r"d.isHexLiteral);
    static assert("\u2028\u2029\u0085"d.isHexLiteral);
    // odd x strings
    static assert(!("5" ~ whitespace).isHexLiteral);
    static assert(!"123".isHexLiteral);
    static assert(!"1A3".isHexLiteral);
    static assert(!"1 23".isHexLiteral);
    static assert(!"\r\n\tC".isHexLiteral);
    static assert(!"123"w.isHexLiteral);
    static assert(!"1A3"w.isHexLiteral);
    static assert(!"1 23"w.isHexLiteral);
    static assert(!"\r\n\tC"w.isHexLiteral);
    static assert(!"123"d.isHexLiteral);
    static assert(!"1A3"d.isHexLiteral);
    static assert(!"1 23"d.isHexLiteral);
    static assert(!"\r\n\tC"d.isHexLiteral);
    // even x strings with invalid charset
    static assert(!"12gG".isHexLiteral);
    static assert(!"2A  3q".isHexLiteral);
    static assert(!"12gG"w.isHexLiteral);
    static assert(!"2A  3q"w.isHexLiteral);
    static assert(!"12gG"d.isHexLiteral);
    static assert(!"2A  3q"d.isHexLiteral);
    // valid x strings
    static assert("5A" ~ whitespace.isHexLiteral);
    static assert("5A 01A C FF de 1b".isHexLiteral);
    static assert("0123456789abcdefABCDEF".isHexLiteral);
    static assert(" 012 34 5 6789 abcd ef\rAB\nCDEF".isHexLiteral);
    static assert("5A 01A C FF de 1b"w.isHexLiteral);
    static assert("0123456789abcdefABCDEF"w.isHexLiteral);
    static assert(" 012 34 5 6789 abcd ef\rAB\nCDEF"w.isHexLiteral);
    static assert("5A 01A C FF de 1b"d.isHexLiteral);
    static assert("0123456789abcdefABCDEF"d.isHexLiteral);
    static assert(" 012 34 5 6789 abcd ef\rAB\nCDEF"d.isHexLiteral);
    // library version allows what's pointed by issue 10454
    static assert("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".isHexLiteral);
}

/**
The $(D hexBytes) function is similar to the $(D hexString) one except
that it returns the hexadecimal data as an array of integral.
Params:
hexData = the $(D string) to be converted.
T = the integer type of an array element. By default it is set to $(D ubyte)
but all the integer types, excepted $(D ulong) and $(D long), are accepted.
Returns:
an array of T.
 */
@property @trusted nothrow pure
auto hexBytes(string hexData, T = ubyte)()
if (hexData.isHexLiteral && isIntegral!T && (T.sizeof <= 4))
{
    static if (T.sizeof == 1)
        return cast(T[]) hexStrImpl!char(hexData);
    else static if (T.sizeof == 2)
        return cast(T[]) hexStrImpl!wchar(hexData);
    else
        return cast(T[]) hexStrImpl!dchar(hexData);
}

/// ditto
@property @trusted pure
auto hexBytes(T = ubyte)(string hexData)
if (isIntegral!T && T.sizeof <= 4)
{
    if (hexData.isHexLiteral)
    {
        static if (T.sizeof == 1)
            return cast(T[]) hexStrImpl!char(hexData);
        else static if (T.sizeof == 2)
            return cast(T[]) hexStrImpl!wchar(hexData);
        else
            return cast(T[]) hexStrImpl!dchar(hexData);
    }
    else assert(0, "Invalid input string format in " ~ __FUNCTION__);
}

///
unittest
{
    // conversion at compile time
    auto array1 = hexBytes!"304A314B";
    assert(array1 == [0x30, 0x4A, 0x31, 0x4B]);
    // conversion at run time
    auto arbitraryData = "30 4A 31 4B";
    auto array2 = hexBytes(arbitraryData);
    assert(array2 == [0x30, 0x4A, 0x31, 0x4B]);
}

/*
    takes a hexadecimal string literal and returns its representation.
    hexData is granted to be a valid string by the caller.
    C is granted to be a valid char type by the caller.
*/
@safe nothrow pure
private auto hexStrImpl(C)(string hexData)
{
    import std.ascii;
    C[] result;
    ubyte chr;
    size_t cnt;
    result.length = hexData.length / 2;
    foreach(c; hexData)
        if (c.isHexDigit)
        {
            if (! (cnt & 1))
            {
                chr = 0;
                if (c.isAlpha)
                    chr += (c.toLower - 'a' + 10) << 4;
                else
                    chr += (c - '0') << 4;
            }
            else
            {
                if (c.isAlpha)
                    chr += (c.toLower - 'a' + 10);
                else
                    chr += (c - '0');
                result[cnt / 2] = chr;
            }
            ++cnt;
        }
    result.length = cnt / 2;
    return result;
}

unittest
{
    // compile time
    assert(hexBytes!"49 4A 4B" == [0x49, 0x4A, 0x4B]);
    assert(hexBytes!"494A4B" == [0x49, 0x4A, 0x4B]);
    assert(hexBytes!("494A4B", uint) == [0x49u, 0x4Au, 0x4Bu]);
    assert(hexBytes!("FF FE FD", byte) == [-1, -2, -3]);
    assert(hexBytes!("FF FE FD", short) == [255, 254, 253]);
    // run-time
    assert(hexBytes("49 4A 4B") == [0x49, 0x4A, 0x4B]);
}