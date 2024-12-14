rule RainbowIsKawaii {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "13/12/2024"

    strings : 
        $header = { 4D 5A }

        // H.a.c.k.2.0.1.7
        $a1 = { 48 00 61 00 63 00 6B 00 32 00 30 00 31 00 37 }

        // -t.r.y. .t.o. .c.l.o.s.e. .m.e
        $a2 = { 2D 74 00 72 00 79 00 20 00 74 00 6F 00 20 00 63 00 6C 00 6F 00 73 00 65 00 20 00 6D 00 65 }

        // #c.a.n.'.t. .c.l.o.s.e. .m.e.!.!."
        $a3 = { 23 63 00 61 00 6E 00 27 00 74 00 20 00 63 00 6C 00 6F 00 73 00 65 00 20 00 6D 00 65 00 21 00 21 00 22 }

        // a.t.t.a.c.k.s.t.a.r.t
        $a4 = { 61 00 74 00 74 00 61 00 63 00 6B 00 73 00 74 00 61 00 72 00 74 }

        // y.o.u. .a.r.e. .a.l.r.e.a.d.y. .s.t.u.p.i.d. .l.m.a.o
        $a5 = { 79 00 6F 00 75 00 20 00 61 00 72 00 65 00 20 00 61 00 6C 00 72 00 65 00 61 00 64 00 79 00 20 00 73 00 74 00 75 00 70 00 69 00 64 00 20 00 6C 00 6D 00 61 00 6F }

        // S.T.U.P.I.D.?...B.u.t.t.o.n.1...Y.e.s. .y.e.s.!
        $a6 = { 53 00 54 00 55 00 50 00 49 00 44 00 3F 00 00 0F 42 00 75 00 74 00 74 00 6F 00 6E 00 31 00 00 11 59 00 65 00 73 00 20 00 79 00 65 00 73 00 21 }

        // CookieClicker_Hack2017
        $a7 = { 43 6F 6F 6B 69 65 43 6C 69 63 6B 65 72 5F 48 61 63 6B 32 30 31 37 }

        // 5400c28e-d6b5-4411-92c6-650155382179
        $a8 = { 35 34 30 30 63 32 38 65 2D 64 36 62 35 2D 34 34 31 31 2D 39 32 63 36 2D 36 35 30 31 35 35 33 38 32 31 37 39 }

        // C:\Users\boris\documents\visual studio 2017\Projects\CookieClicker_Hack2017
        $a9 = { 43 3A 5C 55 73 65 72 73 5C 62 6F 72 69 73 5C 64 6F 63 75 6D 65 6E 74 73 5C 76 69 73 75 61 6C 20 73 74 75 64 69 6F 20 32 30 31 37 5C 50 72 6F 6A 65 63 74 73 5C 43 6F 6F 6B 69 65 43 6C 69 63 6B 65 72 5F 48 61 63 6B 32 30 31 37 }

        // CookieClicker_Hack2017\obj\Debug\CookieClicker_Hack2017.pdb
        $a10 = { 43 6F 6F 6B 69 65 43 6C 69 63 6B 65 72 5F 48 61 63 6B 32 30 31 37 5C 6F 62 6A 5C 44 65 62 75 67 5C 43 6F 6F 6B 69 65 43 6C 69 63 6B 65 72 5F 48 61 63 6B 32 30 31 37 2E 70 64 62 }

    condition : 
        ( $header at 0 ) 
        and 8 of ( $a* )
        and filesize < 1000KB
}