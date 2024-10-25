rule _1d2800352e15175ae5fa916b48a96b26f0199d9f8a9036648b3e44aa60ed2897 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "25/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // 19.168.1.23
        $b1 = { 31 39 2E 31 36 38 2E 31 2E 32 33 }

        // https://github.com/robertdavidgraham/masscan
        $b2 = { 68 74 74 70 73 3A 2F 2F 67 69 74 68 75 62 2E 63 6F 6D 2F 72 6F 62 65 72 74 64 61 76 69 64 67 72 61 68 61 6D 2F 6D 61 73 73 63 61 6E }

        // FAIL: bad source IPv4 address
        $b3 = { 46 41 49 4C 3A 20 62 61 64 20 73 6F 75 72 63 65 20 49 50 76 34 20 61 64 64 72 65 73 73 }
   
        // FAIL: range must be even power of two
        $b4 = { 46 41 49 4C 3A 20 72 61 6E 67 65 20 6D 75 73 74 20 62 65 20 65 76 65 6E 20 70 6F 77 65 72 20 6F 66 20 74 77 6F }

        // PORT SPECIFICATION AND SCAN ORDER
        $b5 = { 50 4F 52 54 20 53 50 45 43 49 46 49 43 41 54 49 4F 4E 20 41 4E 44 20 53 43 41 4E 20 4F 52 44 45 52 }

        // http://nmap.org/svn/docs/nmap.xs
        $b6 = { 68 74 74 70 3A 2F 2F 6E 6D 61 70 2E 6F 72 67 2F 73 76 6E 2F 64 6F 63 73 2F 6E 6D 61 70 2E 78 73 }

        // An example is the following, which scans the 10.x.x.x network for web servers
        $b7 = { 41 6E 20 65 78 61 6D 70 6C 65 0A 69 73 20 74 68 65 20 66 6F 6C 6C 6F 77 69 6E 67 2C 20 77 68 69 63 68 20 73 63 61 6E 73 20 74 68 65
            20 31 30 2E 78 2E 78 2E 78 20 6E 65 74 77 6F 72 6B 20 66 6F 72 20 77 65 62 20 73 65 72 76 65 72 73 }

    condition : 
        ( $header at 0 ) 
        and 5 of ( $b* )
        and filesize < 3000KB
}