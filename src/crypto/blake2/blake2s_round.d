module crypto.blake2.blake2s_round;

import std.conv: to;
import inteli.emmintrin;


package:
pure nothrow @nogc:


alias LOADU = _mm_loadu_si128;
alias STOREU = _mm_storeu_si128;
alias TOF = _mm_castsi128_ps;
alias TOI = _mm_castps_si128;


__m128i _mm_roti_epi32( in __m128i r, in int c )
@safe
{
    return _mm_xor_si128(_mm_srli_epi32((r), -(c) ),_mm_slli_epi32((r), 32-(-(c)) ));
}

version(LDC)
{
    template tmplG1 (int buf)
    {
        const tmplG1 = `
            rows[0] = _mm_add_epi32( _mm_add_epi32( rows[0], bufs[` ~to!string(buf)~ `]), rows[1] );
            rows[3] = _mm_xor_si128( rows[3], rows[0] );
            rows[3] = _mm_roti_epi32(rows[3], -16);
            rows[2] = _mm_add_epi32( rows[2], rows[3] );
            rows[1] = _mm_xor_si128( rows[1], rows[2] );
            rows[1] = _mm_roti_epi32(rows[1], -12);
        `;
    }

    template tmplG2 (int buf)
    {
        const tmplG2 = `
            rows[0] = _mm_add_epi32( _mm_add_epi32( rows[0], bufs[` ~to!string(buf)~ `]), rows[1] );
            rows[3] = _mm_xor_si128( rows[3], rows[0] );
            rows[3] = _mm_roti_epi32(rows[3], -8);
            rows[2] = _mm_add_epi32( rows[2], rows[3] );
            rows[1] = _mm_xor_si128( rows[1], rows[2] );
            rows[1] = _mm_roti_epi32(rows[1], -7);
        `;
    }
}
else
{
    void fG1 (ref __m128i[4] rows, in __m128i buf)
    {
        rows[0] = _mm_add_epi32(_mm_add_epi32(rows[0], buf), rows[1] );
        rows[3] = _mm_xor_si128(rows[3], rows[0] );
        rows[3] = _mm_roti_epi32(rows[3], -16);
        rows[2] = _mm_add_epi32(rows[2], rows[3] );
        rows[1] = _mm_xor_si128(rows[1], rows[2] );
        rows[1] = _mm_roti_epi32(rows[1], -12);
    }

    void fG2 (ref __m128i[4] rows, in __m128i buf)
    {
        rows[0] = _mm_add_epi32(_mm_add_epi32(rows[0], buf), rows[1] );
        rows[3] = _mm_xor_si128(rows[3], rows[0] );
        rows[3] = _mm_roti_epi32(rows[3], -8 );
        rows[2] = _mm_add_epi32(rows[2], rows[3] );
        rows[1] = _mm_xor_si128(rows[1], rows[2] );
        rows[1] = _mm_roti_epi32(rows[1], -7 );
    }
}


immutable DIAGONALIZE = `
    rows[0] = _mm_shuffle_epi32!(_MM_SHUFFLE(2,1,0,3))( rows[0] );
    rows[3] = _mm_shuffle_epi32!(_MM_SHUFFLE(1,0,3,2))( rows[3] );
    rows[2] = _mm_shuffle_epi32!(_MM_SHUFFLE(0,3,2,1))( rows[2] );
`;

immutable UNDIAGONALIZE = `
    rows[0] = _mm_shuffle_epi32!(_MM_SHUFFLE(0,3,2,1))( rows[0] );
    rows[3] = _mm_shuffle_epi32!(_MM_SHUFFLE(1,0,3,2))( rows[3] );
    rows[2] = _mm_shuffle_epi32!(_MM_SHUFFLE(2,1,0,3))( rows[2] );
`;

immutable matrix = [
        [
            [6,  4,  2,  0 ],
            [7,  5,  3,  1 ],
            [12, 10, 8,  14],
            [13, 11, 9,  15]
        ],
        [
            [13, 9,  4,  14],
            [6,  15, 8,  10],
            [11, 0,  1,  5 ],
            [7,  2,  12, 3 ]
        ],
        [
            [15, 5,  12, 11],
            [13, 2,  0,  8 ],
            [7,  3,  10, 9 ],
            [1,  6,  14, 4 ]
        ],
        [
            [11, 13, 3,  7 ],
            [14, 12, 1,  9 ],
            [4,  5,  2,  15],
            [0,  10, 6,  8 ]
        ],
        [
            [10, 2,  5,  9 ],
            [15, 4,  7,  0 ],
            [6,  11, 14, 3 ],
            [8,  12, 1,  13]
        ],
        [
            [8,  0,  6,  2 ],
            [3,  11, 10, 12],
            [15, 7,  4,  1 ],
            [14, 5,  13, 9 ]
        ],
        [
            [4,  14, 1,  12],
            [10, 13, 15, 5 ],
            [9,  6,  0,  8 ],
            [2,  3,  7,  11]
        ],
        [
            [3,  12, 7,  13],
            [9,  1,  14, 11],
            [8,  15, 5,  2 ],
            [6,  4,  0,  10]
        ],
        [
            [0,  11, 14, 6 ],
            [8,  3,  9,  15],
            [1,  13, 12, 10],
            [4,  7,  2,  5 ]
        ],
        [
            [1,  7,  8,  10],
            [5,  6,  4,  2 ],
            [3,  9,  15, 13],
            [12, 14, 11, 0 ]
        ]
    ];


version(LDC)
{
    template tmplLoadMsg (int r, int c, int buf)
    {
        const cell = matrix[r][c];
        const tmplLoadMsg = "
            bufs["~to!string(buf)~"] = _mm_set_epi32(
                m["~to!string(cell[0])~"],
                m["~to!string(cell[1])~"],
                m["~to!string(cell[2])~"],
                m["~to!string(cell[3])~"]
            );
        ";
    }
    template tmplRound (int r)
    {
        const tmplRound =
        tmplLoadMsg!(r, 0, 0) ~
        tmplG1!0 ~
        tmplLoadMsg!(r, 1, 1) ~
        tmplG2!1 ~
        DIAGONALIZE ~
        tmplLoadMsg!(r, 2, 2) ~
        tmplG1!2 ~
        tmplLoadMsg!(r, 3, 3) ~
        tmplG2!3 ~
        UNDIAGONALIZE
        ;
    }

}
else
{
    void loadMsg (in const(uint)[16] m, in int r, in int c, out __m128i buf)
    {
        const cell = matrix[r][c];
        buf = _mm_set_epi32(m[cell[0]], m[cell[1]], m[cell[2]], m[cell[3]]);
    }

    void round (in const(uint)[16] m, in int r, ref __m128i[4] rows, ref __m128i[4] bufs)
    {
        loadMsg(m, r, 0, bufs[0]);
        fG1(rows, bufs[0]);
        loadMsg(m, r, 1, bufs[1]);
        fG2(rows, bufs[1]);
        mixin(DIAGONALIZE);
        loadMsg(m, r, 2, bufs[2]);
        fG1(rows, bufs[2]);
        loadMsg(m, r, 3, bufs[3]);
        fG2(rows, bufs[3]);
        mixin(UNDIAGONALIZE);
    }
}