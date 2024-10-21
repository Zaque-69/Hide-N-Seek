rule _135f766d84d2c5db45dbb56348b1f75797455f33e7243f9b79ea3fc6d7efdf8b { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "20/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // 194.15.36.193:666
        $b1 = { 31 39 34 2E 31 35 2E 33 36 2E 31 39 33 3A 36 36 36 }

        // /proc/net/route
        $b2 = { 2F 70 72 6F 63 2F 6E 65 74 2F 72 6F 75 74 65 }

        // /usr/bin/python3.Python3
        $b3 = { 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E 33 00 50 79 74 68 6F 6E 33 }
   
        // /usr/lib/portage.Gentoo
        $b4 = { 2F 75 73 72 2F 6C 69 62 2F 70 6F 72 74 61 67 65 00 47 65 6E 74 6F 6F }

    condition : 
        ( $header at 0 ) 
        and 4 of ( $b* )
        and filesize < 1000KB
}