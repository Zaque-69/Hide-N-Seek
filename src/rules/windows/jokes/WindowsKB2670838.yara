rule WindowsKB2670838 {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "13/12/2024"

    strings : 
        $header = { 4D 5A }

        // Ducky
        $a1 = { 44 75 63 6B 79 }

        // http://ns.adobe.com/xap/1.0/.<?xpacket begin='﻿'
        $a2 = { 68 74 74 70 3A 2F 2F 6E 73 2E 61 64 6F 62 65 2E 63 6F 6D 2F 78 61 70 2F 31 2E 30 2F 00 3C 3F 78 70 61 63 6B 65 74 20 62 65 67 69 6E 3D 27 EF BB BF 27 }

        // id='W5M0MpCehiHzreSzNTczkc9d'
        $a3 = { 69 64 3D 27 57 35 4D 30 4D 70 43 65 68 69 48 7A 72 65 53 7A 4E 54 63 7A 6B 63 39 64 27 }

        // http://www.w3.org/1999/02/22-rdf-syntax-ns
        $a4 = { 68 74 74 70 3A 2F 2F 77 77 77 2E 77 33 2E 6F 72 67 2F 31 39 39 39 2F 30 32 2F 32 32 2D 72 64 66 2D 73 79 6E 74 61 78 2D 6E 73 }

        // uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b
        $a5 = { 75 75 69 64 3A 66 61 66 35 62 64 64 35 2D 62 61 33 64 2D 31 31 64 61 2D 61 64 33 31 2D 64 33 33 64 37 35 31 38 32 66 31 62 }

        // id='W5M0MpCehiHzreSzNTczkc9d'
        $a6 = { 69 64 3D 27 57 35 4D 30 4D 70 43 65 68 69 48 7A 72 65 53 7A 4E 54 63 7A 6B 63 39 64 27 }

        // uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b
        $a7 = { 75 75 69 64 3A 66 61 66 35 62 64 64 35 2D 62 61 33 64 2D 31 31 64 61 2D 61 64 33 31 2D 64 33 33 64 37 35 31 38 32 66 31 62 }

        // 5400c28e-d6b5-4411-92c6-650155382179
        $a8 = { 35 34 30 30 63 32 38 65 2D 64 36 62 35 2D 34 34 31 31 2D 39 32 63 36 2D 36 35 30 31 35 35 33 38 32 31 37 39 }

    condition : 
        ( $header at 0 ) 
        and 6 of ( $a* )
        and filesize < 8000KB
}