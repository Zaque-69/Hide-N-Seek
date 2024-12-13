rule Hydra {
    meta : 
        author = "Z4que - All rights reverved"
		date = "23/02/2024"

    strings : 
        $header = { 4D 5A }

        // Hydra.exe
        $a1 = { 48 79 64 72 61 2e 65 78 65 }

        // Microsoft Corporation
        $a2 = { 4D 69 63 72 6F 73 6F 66 74 20 43 6F 72 70 6F 72 61 74 69 6F 6E }

        // 6b1cece4-3226-49ba-8875-6ed650818f5b
        $a3 = { 36 62 31 63 65 63 65 34 2D 33 32 32 36 2D 34 39 62 61 2D 38 38 37 35 2D 36 65 64 36 35 30 38 31 38 66 35 62 }

        // Hydra.MsgBoxForm
        $a4 = { 48 79 64 72 61 2E 4D 73 67 42 6F 78 46 6F 72 6D }

        // PublicKeyToken=b77a5c561934e089
        $a5 = { 50 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 }

        // PublicKeyToken=b03f5f7f11d50a3a
        $a6 = { 50 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 30 33 66 35 66 37 66 31 31 64 35 30 61 33 61 }

        // D:\Visual Studio Projects\Hydra\Hydra\obj\Release\Hydra.pdb
        $a7 = { 44 3A 5C 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 50 72 6F 6A 65 63 74 73 5C 48 79 64 72 61 5C 48 79 64 72 61 5C 6F 62 6A 5C 52 65 6C 65 61 73 65 5C 48 79 64 72 61 2E 70 64 62 }         
        
        // C.u.t. .o.f.f. .a. .h.e.a.d
        $a8 = { 43 00 75 00 74 00 20 00 6F 00 66 00 66 00 20 00 61 00 20 00 68 00 65 00 61 00 64 }

        // t.w.o. .m.o.r.e. .w.i.l.l. .t.a.k.e. .i.t.s. .p.l.a.c.e
        $a9 = { 74 00 77 00 6F 00 20 00 6D 00 6F 00 72 00 65 00 20 00 77 00 69 00 6C 00 6C 00 20 00 74 00 61 00 6B 00 65 00 20 00 69 00 74 00 73 00 20 00 70 00 6C 00 61 00 63 00 65 }

        //W.i.P.e.t
        $a10 = { 57 00 69 00 50 00 65 00 74 }
   
    condition : 
        ( $header at 0 ) 
        and 8 of ( $a* ) 
        and filesize < 1000KB

}