rule _2a5ef385cc4ec7b753f412e61533f2c62c3d12cfffc28b76ed7bc76a3b387e15 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "27/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // onion
        $b1 = { 6F 6E 69 6F 6E }

        // /etc/debug.txt
        $b2 = { 2F 65 74 63 2F 64 65 62 75 67 2E 74 78 74 }

        // System install....Fail!!!
        $b3 = { 53 79 73 74 65 6D 20 69 6E 73 74 61 6C 6C 2E 2E 2E 00 46 61 69 6C 21 21 21 }
   
        // http://p1.feefreepool.net/cgi-bin/prometei.cgi
        $b4 = { 68 74 74 70 3A 2F 2F 70 31 2E 66 65 65 66 72 65 65 70 6F 6F 6C 2E 6E 65 74 2F 63 67 69 2D 62 69 6E 2F 70 72 6F 6D 65 74 65 69 2E 63 67 69 }

        // http://dummy.zero/cgi-bin/prometei.cgi
        $b5 = { 68 74 74 70 3A 2F 2F 64 75 6D 6D 79 2E 7A 65 72 6F 2F 63 67 69 2D 62 69 6E 2F 70 72 6F 6D 65 74 65 69 2E 63 67 69 }

        // https://gb7ni5rgeexdcncj.onion/cgi-bin/prometei.cgi
        $b6 = { 68 74 74 70 73 3A 2F 2F 67 62 37 6E 69 35 72 67 65 65 78 64 63 6E 63 6A 2E 6F 6E 69 6F 6E 2F 63 67 69 2D 62 69 6E 2F 70 72 6F 6D 65 74 65 69 2E 63 67 69 }

        // http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cg
        $b7 = { 68 74 74 70 3A 2F 2F 6D 6B 68 6B 6A 78 67 63 68 74 66 67 75 37 75 68 6F 66 78 7A 67 6F 61 77 6E 74 66 7A 72 6B 64 63 63 79 6D 76 65 65 6B 74 71
            67 70 78 72 70 6A 62 37 32 6F 71 2E 62 33 32 2E 69 32 70 2F 63 67 69 2D 62 69 6E 2F 70 72 6F 6D 65 74 65 69 2E 63 67 }

        // "id":"RJ372033v7RyJCSG"
        $b8 = { 22 69 64 22 3A 22 52 4A 33 37 32 30 33 33 76 37 52 79 4A 43 53 47 22 }

    condition : 
        ( $header at 0 ) 
        and 6 of ( $b* )
        and filesize < 200KB
}