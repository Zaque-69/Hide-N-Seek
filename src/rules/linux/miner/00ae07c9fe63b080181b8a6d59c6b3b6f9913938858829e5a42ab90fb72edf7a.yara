rule _00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a_Monero_Miner {
    meta : 
        author = "Z4que - All rights reverved"
		date = "11/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        $loader = { 2F 6C 69 62 36 34 2F 6C 64 2D 6C 69 6E 75 78 2D 78 38 36 2D 36 34 }   
        
        //monero.xmr.arqma.ravencoin.raven
        $b1 = { 6D 6F 6E 65 72 6F 00 78 6D 72 00 61 72 71 6D 61 00 72 61 76 65 6E 63 6F
            69 6E 00 72 61 76 65 6E }

        //OpenSSL 1.1.1i  8 Dec 2020
        $b2 = { 4F 70 65 6E 53 53 4C 20 31 2E 31 2E 31 69 20 20 38 20 44 65 63 20 32 30
            32 30 }
            
        //cryptonight
        $b3 = { 63 72 79 70 74 6F 6E 69 67 68 74 }
        $b4 = { 58 4D 52 49 47 }
   
    condition : 
        ( $header at 0 ) 
        and $loader 
        and 3 of ( $b* ) 
        and filesize < 8000KB
}