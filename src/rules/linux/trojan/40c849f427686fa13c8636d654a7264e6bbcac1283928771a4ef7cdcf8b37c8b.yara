rule _40c849f427686fa13c8636d654a7264e6bbcac1283928771a4ef7cdcf8b37c8b {
    meta : 
        author = "Z4que - All rights reverved"
		date = "2/11/2024"

    strings : 
        $header = { 7F 45 4C 46 }

        // PROT_EXEC|PROT_WRITE
        $b1 = { 50 52 4F 54 5F 45 58 45 43 7C 50 52 4F 54 5F 57 52 49 54 45 }

        // UPX!
        $b2 = { 55 50 58 21 }
   
        // This file is packed with the UPX executable packer http://upx.sf.net
        $b3 = { 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 68 74 74 70 3A 2F 2F 75 70 78 2E 73 66 2E 6E 65 74 }

        // Copyright (C) 1996-2018 the UPX Team
        $b4 = { 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 39 36 2D 32 30 31 38 20 74 68 65 20 55 50 58 20 54 65 61 6D }

        // Ubuntu 8.4.0-1u
        $b5 = { 55 62 75 6E 74 75 20 38 2E 34 2E 30 2D 31 75 }

    condition : 
        ( $header at 0 ) 
        and 4 of ( $b* )
        and filesize < 200KB
}