rule _060b01f15c7fab6c4f656aa1f120ebc1221a71bca3177f50083db0ed77596f0f{
    meta : 
        author = "Z4que - All rights reverved"
		date = "11/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // /usr/bin/python2.7
        $b1 = { 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E 32 2E 37 }

        // /usr/bin/netstat
        $b2 = { 2F 75 73 72 2F 62 69 6E 2F 6E 65 74 73 74 61 74 }

        // /proc/self/exe
        $b3 = { 2F 70 72 6F 63 2F 73 65 6C 66 2F 65 78 65 }
   
        //EAEC2CA4-AF8D-4F61-8115-9EC26F6BF4E1
        $uuid = { 45 41 45 43 32 43 41 34 2D 41 46 38 44 2D 34 46 36 31 2D 38 31 31 35 2D 39 45 43 32 36 46 36 42 46 34 45 31 }

    condition : 
        ( $header at 0 ) 
        and 2 of ( $b* )
        and $uuid 
        and filesize < 300KB
}