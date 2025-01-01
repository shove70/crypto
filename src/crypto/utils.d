module crypto.utils;

/*
The MIT License (MIT)

Copyright (c) 2019 DarkRiDDeR

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
* Fills a block of memory with zeros. It is designed to be a more secure version of ZeroMemory.
*
* !!! function secureZeroMemory processes data by byte.
*
* Use this function instead of ZeroMemory when you want to ensure that your data will be overwritten promptly,
* as some compilers can optimize a call to ZeroMemory by removing it entirely.
*/
void secureZeroMemory(void* p, size_t length) pure nothrow @nogc
{
    version (D_InlineAsm_X86_64)
    {
        asm pure nothrow @nogc
        {
            mov RBX, [p];
            mov RDX, p;
            mov RCX, length;
            iter:
            xor RBX, RBX;
            mov [RDX], BL;
            inc RDX;
            loop iter;
        }
    }
    else version (D_InlineAsm_X86)
    {
        asm pure nothrow @nogc
        {
            mov EBX, [p];
            mov EDX, p;
            mov ECX, length;
            iter:
            xor EBX, EBX;
            mov [EDX], BL;
            inc EDX;
            loop iter;
        }
    }
    else version (LDC)
    {
        import ldc.intrinsics : llvm_memset;
        llvm_memset(p, 0, length, true); // The "true" means volatile.
    }
    else
    {
        static if (__VERSION__ >= 2089)
            import core.volatile : volatileStore;
        else
            import core.bitop : volatileStore;
        static void zero(void* p, size_t remaining) @nogc nothrow
        {
            for (; remaining != 0 && (cast(size_t) p) % size_t.alignof != 0; ++p, --remaining)
                volatileStore(cast(ubyte*) p, ubyte(0));
            for (; remaining >= size_t.sizeof; p += size_t.sizeof, remaining -= size_t.sizeof)
                volatileStore(cast(size_t*) p, size_t(0));
            for (; remaining != 0; ++p, --remaining)
                volatileStore(cast(ubyte*) p, ubyte(0));
        }
        // Workaround because volatileStore is not annotated "pure".
        (cast(void function(void*, size_t) @nogc nothrow pure) &zero)(p, length);
    }
}

void secureZeroMemory(void[] ar) pure nothrow @nogc
{
    if (ar.length)
        secureZeroMemory(ar.ptr, ar.length);
}

unittest
{
    auto ar = new ubyte[255];
    auto ar2 = ar.dup;

    foreach (i, ref e; ar2)
        e = cast(ubyte)i;
    assert(ar != ar2);

    secureZeroMemory(ar2.ptr, ar2.length);
    assert(ar == ar2);


    uint[] i  = [0, 0, 0,  0, 0 ];
    uint[] i2 = [8, 5, 99, 5, 99];
    // !!! function secureZeroMemory processes data by byte. Therefore, it is wrong:
    secureZeroMemory(i2.ptr, i2.length);
    assert(i != i2);
    // Need to calculate the length:
    secureZeroMemory(i2.ptr, uint.sizeof * i2.length);
    assert(i == i2);

    // or use a cast to type void[]
    i2 = [8, 5, 99, 5, 99];
    secureZeroMemory(i2);
    assert(i == i2);
}

unittest
{
    // Verify that secureZeroMemory doesn't have a buffer overrun.
    ubyte[17] array;
    array[] = 1;
    ubyte[] slice = array[1..$-1];
    secureZeroMemory(slice);
    // Slice should be 0.
    foreach (b; slice)
        assert(b == 0);
    // Bytes outside slice should be 1.
    assert(array[0] == 1);
    assert(array[$-1] == 1);
}
