module crypto.blake2.impl;

import core.stdc.string: memcpy;
import std.bitmanip;

package:
pure nothrow @nogc:


ushort load16(const void *src)
{
    version (LittleEndian)
    {
        ushort w;
        memcpy(&w, src, w.sizeof);
        return w;
    }
    else // BigEndian
    {
        auto p = cast(const(ubyte)*)src;
        return cast(ushort)((uint(p[0]) <<  0) |
                           (uint(p[1]) <<  8)) ;
    }
}

uint load32(const void *src)
{
    version (LittleEndian)
    {
        uint w;
        memcpy(&w, src, w.sizeof);
        return w;
    }
    else
    {
        auto p = cast(const(ubyte)*)src;
        return
        (uint(p[0]) <<  0) |
        (uint(p[1]) <<  8) |
        (uint(p[2]) << 16) |
        (uint(p[3]) << 24) ;
    }
}

ulong load64(const void *src)
{
    version (LittleEndian)
    {
        ulong w;
        memcpy(&w, src, w.sizeof);
        return w;
    }
    else
    {
        auto p = cast(const(ubyte)*)src;
        return
            (ulong(p[0]) <<  0) |
            (ulong(p[1]) <<  8) |
            (ulong(p[2]) << 16) |
            (ulong(p[3]) << 24) |
            (ulong(p[4]) << 32) |
            (ulong(p[5]) << 40) |
            (ulong(p[6]) << 48) |
            (ulong(p[7]) << 56) ;
    }
}

ulong load48(const void *src)
{
    auto p = cast(const(ubyte)*)src;
    return
    (ulong(p[0]) <<  0) |
    (ulong(p[1]) <<  8) |
    (ulong(p[2]) << 16) |
    (ulong(p[3]) << 24) |
    (ulong(p[4]) << 32) |
    (ulong(p[5]) << 40) ;
}


void store16(void *dst, in ushort w)
{
    version (LittleEndian)
    {
        memcpy(dst, &w, w.sizeof);
    }
    else
    {
        auto p = cast(ubyte*)dst;
        *p++ = cast(ubyte) w;
        w >>= 8;
        *p++ = cast(ubyte) w;
    }
}

void store32(void *dst, uint w)
{
    version (LittleEndian)
    {
        memcpy(dst, &w, w.sizeof);
    }
    else
    {
        auto p = cast(ubyte*)dst;
        p[0] = cast(ubyte)(w >>  0);
        p[1] = cast(ubyte)(w >>  8);
        p[2] = cast(ubyte)(w >> 16);
        p[3] = cast(ubyte)(w >> 24);
    }
}

void store48(void *dst, ulong w)
{
    auto p = cast(ubyte*)dst;
    p[0] = cast(ubyte)(w >>  0);
    p[1] = cast(ubyte)(w >>  8);
    p[2] = cast(ubyte)(w >> 16);
    p[3] = cast(ubyte)(w >> 24);
    p[4] = cast(ubyte)(w >> 32);
    p[5] = cast(ubyte)(w >> 40);
}

void store64(void *dst, ulong w)
{
    version (LittleEndian)
    {
        memcpy(dst, &w, w.sizeof);
    }
    else
    {
        auto p = cast(ubyte*)dst;
        p[0] = cast(ubyte)(w >>  0);
        p[1] = cast(ubyte)(w >>  8);
        p[2] = cast(ubyte)(w >> 16);
        p[3] = cast(ubyte)(w >> 24);
        p[4] = cast(ubyte)(w >> 32);
        p[5] = cast(ubyte)(w >> 40);
        p[6] = cast(ubyte)(w >> 48);
        p[7] = cast(ubyte)(w >> 56);
    }
}

uint rotr32(uint w, uint c)
{
    return (w >> c) | (w << 32 - c);
}

ulong rotr64(ulong w, uint c)
{
    return (w >> c) | (w << 64 - c);
}