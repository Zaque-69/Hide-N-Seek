rule _3668b167f5c9083a9738cfc4bd863a07379a5b02ee14f48a10fb1240f3e421a6 {
    meta : 
        author = "Z4que - All rights reverved"
		date = "1/11/2024"

    strings : 
        $header = { 7F 45 4C 46 }

        // http://192.168.232.128
        $b1 = { 68 74 74 70 3A 2F 2F 31 39 32 2E 31 36 38 2E 32 33 32 2E 31 32 38 }

        // I'm having a problem resolving my host, someone will have to SPOOFS me manually
        $b2 = { 49 27 6D 20 68 61 76 69 6E 67 20 61 20 70 72 6F 62 6C 65 6D 20 72 65 73 6F 6C 76 69 6E 67 20 6D 79 20 68 6F 73 74 2C 20 73 6F 6D 65 6F 6E 65 20 77 69 6C 6C 20 68 61 76 65 20 74 6F 20 53 50 4F 4F 46 53 20 6D 65 20 6D 61 6E 75 61 6C 6C 79 }
   
        // FuckVulcan
        $b3 = { 46 75 63 6B 56 75 6C 63 61 6E }

        // DDOS Attacks & Functions
        $b4 = { 44 44 4F 53 20 41 74 74 61 63 6B 73 20 26 20 46 75 6E 63 74 69 6F 6E 73 }

        // http://31.31.72.123
        $b5 = { 68 74 74 70 3A 2F 2F 33 31 2E 33 31 2E 37 32 2E 31 32 33 }

    condition : 
        ( $header at 0 ) 
        and 4 of ( $b* )
        and filesize < 300KB
}