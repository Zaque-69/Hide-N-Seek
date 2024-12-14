rule TaskILL {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "14/12/2024"

    strings : 
        $header = { 4D 5A }

        // T.a.s.k.I.L.L...e.x.e
        $a1 = { 54 00 61 00 73 00 6B 00 49 00 4C 00 4C 00 2E 00 65 00 78 00 65 }

        // Y.o.u.'.r.e. .l.u.c.k.y. .t.h.i.s. .t.i.m.e
        $a2 = { 59 00 6F 00 75 00 27 00 72 00 65 00 20 00 6C 00 75 00 63 00 6B 00 79 00 20 00 74 00 68 00 69 00 73 00 20 00 74 00 69 00 6D 00 65 }

        // M.U.T.S.E
        $a3 = { 4D 03 55 03 54 03 53 03 45 }

        // t.a.s.k.m.g.r
        $a4 = { 74 00 61 00 73 00 6B 00 6D 00 67 00 72 }

    condition : 
        ( $header at 0 ) 
        and all of ( $a* )
        and filesize < 100KB
}