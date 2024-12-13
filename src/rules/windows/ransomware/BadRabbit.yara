rule BadRabbit {
    meta : 
       author = "Z4que - All rights reverved"
	  date = "9/11/2024"

    strings : 
        $header = { 4D 5A }

        // Fast decoding Code from Chris Anderson
        $a1 = { 46 61 73 74 20 64 65 63 6F 64 69 6E 67 20 43 6F 64 65 20 66 72 6F 6D 20 43 68 72 69 73 20 41 6E 64 65 72 73 6F 6E }

        // C.o.m.p.a.n.y.N.a.m.e....A.d.o.b.e
        $a2 = { 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 00 41 00 64 00 6F 00 62 00 65 }

        // F.i.l.e.D.e.s.c.r.i.p.t.i.o.n....A.d.o.b.e
        $a3 = { 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 41 00 64 00 6F 00 62 00 65 }
    
        // L.e.g.a.l.C.o.p.y.r.i.g.h.t
        $a4 = { 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 }

        // 1.9.9.6.-.2.0.0.7
        $a5 = { 31 00 39 00 39 00 36 00 2D 00 32 00 30 00 31 00 37 }

        // http://ocsp.thawte.com
        $a6 = { 68 74 74 70 3A 2F 2F 6F 63 73 70 2E 74 68 61 77 74 65 2E 63 6F 6D }

        // http://crl.thawte.com/ThawteTimestamping
        $a7 = { 68 74 74 70 3A 2F 2F 63 72 6C 2E 74 68 61 77 74 65 2E 63 6F 6D 2F 54 68 61 77 74 65 54 69 6D 65 73 74 61 6D 70 69 6E 67 }

    condition : 
        ( $header at 0 ) 
        and 7 of ( $a* ) 
}