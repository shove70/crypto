module crypto.blake2.blake2b_round;

import inteli.emmintrin;


package:
pure nothrow @nogc:


alias LOADU = _mm_loadu_si128;
alias STOREU = _mm_storeu_si128;
alias TOF = _mm_castsi128_ps;
alias TOI = _mm_castps_si128;


struct Row {
    __m128i l, h;

    this (__m128i l, __m128i h)
    {
        this.l = l;
        this.h = h;
    }
}

__m128i _mm_roti_epi64(in __m128i r, int c)
@safe
{
    return _mm_xor_si128(_mm_srli_epi64((r), -(c)),_mm_slli_epi64((r), 64-(-(c))));
}

immutable G1 = `
    rows[0].l = _mm_add_epi64(_mm_add_epi64(rows[0].l, b[0]), rows[1].l);
    rows[0].h = _mm_add_epi64(_mm_add_epi64(rows[0].h, b[1]), rows[1].h);

    rows[3].l = _mm_xor_si128(rows[3].l, rows[0].l);
    rows[3].h = _mm_xor_si128(rows[3].h, rows[0].h);

    rows[3].l = _mm_roti_epi64(rows[3].l, -32);
    rows[3].h = _mm_roti_epi64(rows[3].h, -32);

    rows[2].l = _mm_add_epi64(rows[2].l, rows[3].l);
    rows[2].h = _mm_add_epi64(rows[2].h, rows[3].h);

    rows[1].l = _mm_xor_si128(rows[1].l, rows[2].l);
    rows[1].h = _mm_xor_si128(rows[1].h, rows[2].h);

    rows[1].l = _mm_roti_epi64(rows[1].l, -24);
    rows[1].h = _mm_roti_epi64(rows[1].h, -24);
`;

immutable G2 = `
    rows[0].l = _mm_add_epi64(_mm_add_epi64(rows[0].l, b[0]), rows[1].l);
    rows[0].h = _mm_add_epi64(_mm_add_epi64(rows[0].h, b[1]), rows[1].h);

    rows[3].l = _mm_xor_si128(rows[3].l, rows[0].l);
    rows[3].h = _mm_xor_si128(rows[3].h, rows[0].h);

    rows[3].l = _mm_roti_epi64(rows[3].l, -16);
    rows[3].h = _mm_roti_epi64(rows[3].h, -16);

    rows[2].l = _mm_add_epi64(rows[2].l, rows[3].l);
    rows[2].h = _mm_add_epi64(rows[2].h, rows[3].h);

    rows[1].l = _mm_xor_si128(rows[1].l, rows[2].l);
    rows[1].h = _mm_xor_si128(rows[1].h, rows[2].h);

    rows[1].l = _mm_roti_epi64(rows[1].l, -63);
    rows[1].h = _mm_roti_epi64(rows[1].h, -63);
`;

immutable DIAGONALIZE = `
    t[0] = rows[3].l;
    t[1] = rows[1].l;
    rows[3].l = rows[2].l;
    rows[2].l = rows[2].h;
    rows[2].h = rows[3].l;
    rows[3].l = _mm_unpackhi_epi64(rows[3].h, _mm_unpacklo_epi64(t[0], t[0]));
    rows[3].h = _mm_unpackhi_epi64(t[0], _mm_unpacklo_epi64(rows[3].h, rows[3].h));
    rows[1].l = _mm_unpackhi_epi64(rows[1].l, _mm_unpacklo_epi64(rows[1].h, rows[1].h));
    rows[1].h = _mm_unpackhi_epi64(rows[1].h, _mm_unpacklo_epi64(t[1], t[1]));
`;

immutable UNDIAGONALIZE = `
    t[0] = rows[2].l;
    rows[2].l = rows[2].h;
    rows[2].h = t[0];
    t[0] = rows[1].l;
    t[1] = rows[3].l;
    rows[1].l = _mm_unpackhi_epi64(rows[1].h, _mm_unpacklo_epi64(rows[1].l, rows[1].l));
    rows[1].h = _mm_unpackhi_epi64(t[0], _mm_unpacklo_epi64(rows[1].h, rows[1].h));
    rows[3].l = _mm_unpackhi_epi64(rows[3].l, _mm_unpacklo_epi64(rows[3].h, rows[3].h));
    rows[3].h = _mm_unpackhi_epi64(rows[3].h, _mm_unpacklo_epi64(t[1], t[1]));
`;

immutable matrix = [
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


version (LDC)
{
    template tmplLoadMsg (int r, int c)
    {
        import std.conv: to;

        const cell = matrix[r][c];
        const tmplLoadMsg = "
            b[0] = _mm_set_epi64x(m["~to!string(cell[0])~"], m["~to!string(cell[1])~"]);
            b[1] = _mm_set_epi64x(m["~to!string(cell[2])~"], m["~to!string(cell[3])~"]);
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
}
else
{
    void loadMsg(in const(ulong)[16] m, int r, int c, out __m128i b0, out __m128i b1)
    {
        const cell = matrix[r][c];
        b0 = _mm_set_epi64x(m[cell[0]], m[cell[1]]);
        b1 = _mm_set_epi64x(m[cell[2]], m[cell[3]]);
    }

    void round(in const(ulong)[16] m, int r, ref Row[4] rows, ref __m128i[2] b, ref __m128i[2] t)
    {
        loadMsg(m, r, 0, b[0], b[1]);
        mixin(G1);
        loadMsg(m, r, 1, b[0], b[1]);
        mixin(G2);
        mixin(DIAGONALIZE);
        loadMsg(m, r, 2, b[0], b[1]);
        mixin(G1);
        loadMsg(m, r, 3, b[0], b[1]);
        mixin(G2);
        mixin(UNDIAGONALIZE);
    }
}