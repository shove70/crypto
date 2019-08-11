module crypto.blake2.blake2s_round;

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

template tmplG1 (string buf)
{
    const tmplG1 = `
        row1 = _mm_add_epi32( _mm_add_epi32( row1, ` ~buf~ `), row2 );
        row4 = _mm_xor_si128( row4, row1 );
        row4 = _mm_roti_epi32(row4, -16);
        row3 = _mm_add_epi32( row3, row4 );
        row2 = _mm_xor_si128( row2, row3 );
        row2 = _mm_roti_epi32(row2, -12);
    `;
}

template tmplG2 (string buf)
{
    const tmplG2 = `
        row1 = _mm_add_epi32( _mm_add_epi32( row1, ` ~buf~ `), row2 );
        row4 = _mm_xor_si128( row4, row1 );
        row4 = _mm_roti_epi32(row4, -8);
        row3 = _mm_add_epi32( row3, row4 );
        row2 = _mm_xor_si128( row2, row3 );
        row2 = _mm_roti_epi32(row2, -7);
    `;
}

const DIAGONALIZE = `
    row1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2,1,0,3))( row1 );
    row4 = _mm_shuffle_epi32!(_MM_SHUFFLE(1,0,3,2))( row4 );
    row3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0,3,2,1))( row3 );
`;

const UNDIAGONALIZE = `
    row1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0,3,2,1))( row1 );
    row4 = _mm_shuffle_epi32!(_MM_SHUFFLE(1,0,3,2))( row4 );
    row3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2,1,0,3))( row3 );
`;

template tmplLoadMsg (int i, int m, string buf)
{
    import std.conv: to;

    const matrix = [
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

    const im = matrix[i][m];
    const tmplLoadMsg = "
        "~buf~" = _mm_set_epi32(
            m"~to!string(im[0])~",
            m"~to!string(im[1])~",
            m"~to!string(im[2])~",
            m"~to!string(im[3])~"
        );
    ";
}

template tmplRound (int r)
{
    const tmplRound =
        tmplLoadMsg!(r, 0, "buf1") ~
        tmplG1!"buf1" ~
        tmplLoadMsg!(r, 1, "buf2") ~
        tmplG2!"buf2" ~
        DIAGONALIZE ~
        tmplLoadMsg!(r, 2, "buf3") ~
        tmplG1!"buf3" ~
        tmplLoadMsg!(r, 3, "buf4") ~
        tmplG2!"buf4" ~
        UNDIAGONALIZE
    ;
}