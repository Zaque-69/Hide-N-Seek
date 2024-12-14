rule Koteyka2 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "13/12/2024"

    strings : 
        $header = { 4D 5A 40 }
        
        // E.n.d.e.r.m.a.n.c.h
        $a1 = { 45 00 6E 00 64 00 65 00 72 00 6D 00 61 00 6E 00 63 00 68 }
        
        // K.o.t.e.y.k.a. .2
        $a2 = { 4B 00 6F 00 74 00 65 00 79 00 6B 00 61 00 20 00 32 }

        // L.e.g.a.l.C.o.p.y.r.i.g.h.t
        $a3 = { 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 }

        // Project1.exe.=�)
        $a4 = { 50 72 6F 6A 65 63 74 31 2E 65 78 65 00 3D B0 29 }

        // B.B.A.B.O.R.T
        $a5 = { 42 00 42 00 41 00 42 00 4F 00 52 00 54 }

        // B.B.C.A.N.C.E.L
        $a6 = { 42 00 42 00 43 00 41 00 4E 00 43 00 45 00 4C }

    condition : 
        ( $header at 0 ) 
        and 5 of ( $a* ) 
        and filesize < 8000KB
}