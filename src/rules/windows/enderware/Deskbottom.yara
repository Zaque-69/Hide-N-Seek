rule DesktopBoom { 
        meta : 
        author = "Z4que - All rights reverved"
		date = "13/12/2024"

    strings : 
        $header = { 4D 5A 50 }
        
        // C:\Windows\WinSxS\amd64_microsoft-windows-shell-wallpaper-theme2_31bf3856ad364e35_6.3.9600.16384_none_c7984c4f78e5126d\
        $a1 = { 43 3A 5C 57 69 6E 64 6F 77 73 5C 57 69 6E 53 78 53 5C 61 6D 64 36 34 5F 6D 69 63 72 6F 73 6F 66 74 2D 77
            69 6E 64 6F 77 73 2D 73 68 65 6C 6C 2D 77 61 6C 6C 70 61 70 65 72 2D 74 68 65 6D 65 32 5F 33 31 62 66 33 38
            35 36 61 64 33 36 34 65 33 35 5F 36 2E 33 2E 39 36 30 30 2E 31 36 33 38 34 5F 6E 6F 6E 65 5F 63 37 39 38 34
            63 34 66 37 38 65 35 31 32 36 64 5C }
        
        // Deskbottom
        $a2 = { 44 65 73 6B 62 6F 74 74 6F 6D }

        // MS Sans Serif
        $a3 = { 4D 53 20 53 61 6E 73 20 53 65 72 69 66 }

        // B.B.A.B.O.R.T
        $a4 = { 42 00 42 00 41 00 42 00 4F 00 52 00 54 }

        // B.B.C.A.N.C.E.L
        $a5 = { 42 00 42 00 43 00 41 00 4E 00 43 00 45 00 4C }

        // P.A.C.K.A.G.E.I.N.F.O
        $a6 = { 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F }

        // M.A.I.N.I.C.O.N
        $a7 = { 4D 00 41 00 49 00 4E 00 49 00 43 00 4F 00 4E }

        // C.a.p.t.i.o.n...I.n.a.c.t.i.v.e
        $a8 = { 43 00 61 00 70 00 74 00 69 00 6F 00 6E 00 15 00 49 00 6E 00 61 00 63 00 74 00 69 00 76 00 65 }

        // D.2a.r.k. .S.h.a.d.o.w...3.D
        $a9 = { 44 00 61 00 72 00 6B 00 20 00 53 00 68 00 61 00 64 00 6F 00 77 00 08 00 33 00 44 }

        // G.r.e.e.n...O.l.i.v.e
        $a10 = { 47 00 72 00 65 00 65 00 6E 00 05 00 4F 00 6C 00 69 00 76 00 65 }

        // img8.jpg
        $img8 = { 69 6D 67 38 2E 6A 70 67 }
            
        // img9.jpg
        $img9 = { 69 6D 67 39 2E 6A 70 67 }
        
        // img10.jpg
        $img10 = { 69 6D 67 31 30 2E 6A 70 67 }
        
        // img11.jpg
        $img11 = { 69 6D 67 31 31 2E 6A 70 67 }
        
        // img12.jpg
        $img12 = { 69 6D 67 31 32 2E 6A 70 67 }
        
        // img13.jpg
        $img13 = { 69 6D 67 31 33 2E 6A 70 67 }
    
    condition : 
        ( $header at 0 ) 
        and 8 of ( $a* ) 
        and any of ( $img* )
        and filesize < 5000KB
}