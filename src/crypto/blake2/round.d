module crypto.blake2.round;

import inteli.emmintrin;


package:
pure nothrow @nogc:


alias LOADU = _mm_loadu_si128;
alias STOREU = _mm_storeu_si128;
alias TOF = _mm_castsi128_ps;
alias TOI = _mm_castps_si128;


__m128i _mm_roti_epi64( in __m128i r, in int c )
@safe
{
    return _mm_xor_si128(_mm_srli_epi64( (r), -(c) ),_mm_slli_epi64( (r), 64-(-(c)) ));
}

static const G1 = `
    row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
    row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);

    row4l = _mm_xor_si128(row4l, row1l);
    row4h = _mm_xor_si128(row4h, row1h);

    row4l = _mm_roti_epi64(row4l, -32);
    row4h = _mm_roti_epi64(row4h, -32);

    row3l = _mm_add_epi64(row3l, row4l);
    row3h = _mm_add_epi64(row3h, row4h);

    row2l = _mm_xor_si128(row2l, row3l);
    row2h = _mm_xor_si128(row2h, row3h);

    row2l = _mm_roti_epi64(row2l, -24);
    row2h = _mm_roti_epi64(row2h, -24);
`;

const G2 = `
    row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
    row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);

    row4l = _mm_xor_si128(row4l, row1l);
    row4h = _mm_xor_si128(row4h, row1h);

    row4l = _mm_roti_epi64(row4l, -16);
    row4h = _mm_roti_epi64(row4h, -16);

    row3l = _mm_add_epi64(row3l, row4l);
    row3h = _mm_add_epi64(row3h, row4h);

    row2l = _mm_xor_si128(row2l, row3l);
    row2h = _mm_xor_si128(row2h, row3h);

    row2l = _mm_roti_epi64(row2l, -63);
    row2h = _mm_roti_epi64(row2h, -63);
`;

const DIAGONALIZE = `
    t0 = row4l;
    t1 = row2l;
    row4l = row3l;
    row3l = row3h;
    row3h = row4l;
    row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));
    row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));
    row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h));
    row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1));
`;

const UNDIAGONALIZE = `
    t0 = row3l;
    row3l = row3h;
    row3h = t0;
    t0 = row2l;
    t1 = row4l;
    row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l));
    row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));
    row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h));
    row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1));
`;

template tmplLoadMsg (int i, int m)
{
    import std.conv: to;

    const matrix = [
        [
            [2,  0,  6,  4 ],
            [3,  1,  7,  5 ],
            [10, 8,  14, 12],
            [11, 9,  15, 13]
        ],
        [
            [4,  14, 13, 9 ],
            [8,  10, 6,  15],
            [0,  1,  5,  11],
            [2,  12, 3,  7 ]
        ],
        [
            [12, 11, 15, 5 ],
            [0,  8,  13, 2 ],
            [3,  10, 9,  7 ],
            [6,  14, 4,  1 ]
        ],
        [
            [3,  7,  11, 13],
            [1,  9,  14, 12],
            [5,  2,  15, 4 ],
            [10, 6,  8,  0 ]
        ],
        [
            [5,  9,  10, 2 ],
            [7,  0,  15, 4 ],
            [11, 14, 3,  6 ],
            [12, 1,  13, 8 ]
        ],
        [
            [6,  2,  8,  0 ],
            [10, 12, 3,  11],
            [7,  4,  1,  15],
            [5,  13, 9,  14]
        ],
        [
            [1,  12, 4,  14],
            [15, 5,  10, 13],
            [6,  0,  8,  9 ],
            [3,  7,  11, 2 ]
        ],
        [
            [7,  13, 3,  12],
            [14, 11, 9,  1 ],
            [15, 5,  2,  8 ],
            [4,  0,  10, 6 ]
        ],
        [
            [14, 6,  0,  11],
            [9,  15, 8,  3 ],
            [13, 12, 10, 1 ],
            [7,  2,  5,  4 ]
        ],
        [
            [8,  10, 1,  7 ],
            [4,  2,  5,  6 ],
            [9,  15, 13, 3 ],
            [14, 11, 0,  12]
        ],
        [
            [2,  0,  6,  4 ],
            [3,  1,  7,  5 ],
            [10, 8,  14, 12],
            [11, 9,  15, 13]
        ],
        [
            [4,  14, 13, 9 ],
            [8,  10, 6,  15],
            [0,  1,  5,  11],
            [2,  12, 3,  7 ]
        ]
    ];

    const im = matrix[i][m];
    const tmplLoadMsg = "
        b0 = _mm_set_epi64x(m"~to!string(im[0])~", m"~to!string(im[1])~");
        b1 = _mm_set_epi64x(m"~to!string(im[2])~", m"~to!string(im[3])~");
    ";
}

template tmplRound (int r)
{
    const tmplRound =
        tmplLoadMsg!(r, 0) ~
        G1 ~
        tmplLoadMsg!(r, 1) ~
        G2 ~
        DIAGONALIZE ~
        tmplLoadMsg!(r, 2) ~
        G1 ~
        tmplLoadMsg!(r, 3) ~
        G2 ~
        UNDIAGONALIZE
    ;
}