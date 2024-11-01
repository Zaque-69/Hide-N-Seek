rule _33b7c82fc836f11ec1bfbca088b3e5243ca6bf74c081f1f17319103f30de097b { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "1/11/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        $loader = { 2F 6C 69 62 36 34 2F 6C 64 2D 6C 69 6E 75 78 2D 78 38 36 2D 36 34 }

        // 192.168.3.100
        $b1 = { 31 39 32 2E 31 36 38 2E 33 2E 31 30 30 }

        // Invalid parameters!
        $b2 = { 49 6E 76 61 6C 69 64 20 70 61 72 61 6D 65 74 65 72 73 21 }
   
        // <ipadresi> <port> <0-999> <0-999> <time (optional)>
        $b3 = { 3C 69 70 61 64 72 65 73 69 3E 20 3C 70 6F 72 74 3E 20 3C 30 2D 39 39 39 3E 20 3C 30 2D 39 39 39 3E 20 3C 74 69 6D 65 20 28 6F 70 74 69 6F 6E 61 6C 29 3E }

        // Red Hat 4.8.5-36
        $b4 = { 52 65 64 20 48 61 74 20 34 2E 38 2E 35 2D 33 36 }

    condition : 
        ( $header at 0 ) 
        and $loader
        and 4 of ( $b* )
        and filesize < 100KB
}