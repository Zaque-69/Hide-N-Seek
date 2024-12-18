rule _14b898ab0df7209eb266b92684f1d68b15121304c17903b6b20789bf2345a4a0 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "21/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // 537.36.8.8.8.8
        $b1 = { 35 33 37 2E 33 36 00 38 2E 38 2E 38 2E 38 }

        // Windows NT 10.0
        $b2 = { 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 }

        // runs you if you read this lol
        $b3 = { 72 75 6E 73 20 79 6F 75 20 69 66 20 79 6F 75 20 72 65 61 64 20 74 68 69 73 20 6C 6F 6C }
   
        // then you tcp dumped it because it hit you and you need to patch it lololololol
        $b4 = { 74 68 65 6E 20 79 6F 75 20 74 63 70 20 64 75 6D 70 65 64 20 69 74 20 62 65 63 61 75 73 65 20 69 74 20 68 69 74 20 79 6F 75 20 61 6E 64 20 79 6F 75 20 6E 65 65 64 20 74 6F 20 70 61 74 63 68 20 69 74 20 6C 6F 6C 6F 6C 6F 6C 6F 6C 6F 6C }

        // /usr/bin/python3
        $b5 = { 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E 33 }

        // /usr/bin/perl
        $b6 = { 2F 75 73 72 2F 62 69 6E 2F 70 65 72 6C }

        // Device Connected:
        $b7 = { 44 65 76 69 63 65 20 43 6F 6E 6E 65 63 74 65 64 3A }

        // Port: %s | Arch: %s
        $b8 = { 50 6F 72 74 3A 20 25 73 20 7C 20 41 72 63 68 3A 20 25 73 }

        // /etc/resolv.conf./etc/config/resolv.conf.nameserver.domain.search
        $b9 = { 2F 65 74 63 2F 72 65 73 6F 6C 76 2E 63 6F 6E 66 00 2F 65 74 63 2F 63 6F 6E 66 69 67 2F 72 65 73 6F 6C 76 2E 63 6F 6E 66 00 6E 61 6D 65 73 65 72 76 65 72 00 64 6F 6D 61 69 6E 00 73 65 61 72 63 68 }

    condition : 
        ( $header at 0 ) 
        and 7 of ( $b* )
        and filesize < 1000KB
}