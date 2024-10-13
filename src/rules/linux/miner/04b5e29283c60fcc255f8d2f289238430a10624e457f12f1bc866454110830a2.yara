rule _04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2 {
    meta : 
        author = "Z4que - All rights reverved"
		date = "11/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        //cryptonight
        $b1 = { 63 72 79 70 74 6F 6E 69 67 68 74 }

        //cryptonight-monerov7
        $b2 = { 63 72 79 70 74 6F 6E 69 67 68 74 2D 6D 6F 6E 65 72 6F 76 37 } 

         //cryptonight-monerov8
        $b3 = { 63 72 79 70 74 6F 6E 69 67 68 74 2D 6D 6F 6E 65 72 6F 76 38 }
    
        //cryptonight_v7
        $b4 = { 63 72 79 70 74 6F 6E 69 67 68 74 5F 76 37 }

        //randomx
        $b5 = { 72 61 6E 64 6F 6D 78 }

        //RandomARQ
        $b6 = { 52 61 6E 64 6F 6D 41 52 51 }

        //failed to allocate RandomX datasets, switching to slow mode
        $b7 = { 66 61 69 6C 65 64 20 74 6F 20 61 6C 6C 6F 63 61 74 65 20 52 61 6E 64 6F
            6D 58 20 64 61 74 61 73 65 74 73 2C 20 73 77 69 74 63 68 69 6E 67 20 74 6F
            20 73 6C 6F 77 20 6D 6F 64 65 }

         //monero.xmr.arqma.ravencoin.raven
        $b8 = { 6D 6F 6E 65 72 6F 00 78 6D 72 00 61 72 71 6D 61 00 72 61 76 65 6E 63 6F
            69 6E 00 72 61 76 65 6E }

        //Unexpected end of regex when ascii character
        $b9 = { 55 6E 65 78 70 65 63 74 65 64 20 65 6E 64 20 6F 66 20 72 65 67 65 78 20
            77 68 65 6E 20 61 73 63 69 69 20 63 68 61 72 61 63 74 65 72 }

        //"url": "95.142.46.73:80"
        $b10 = { 22 75 72 6C 22 3A 20 22 39 35 2E 31 34 32 2E 34 36 2E 37 33 3A 38 30 22 } 

        //"url": "195.2.92.181:80"
        $b11 = { 22 75 72 6C 22 3A 20 22 31 39 35 2E 32 2E 39 32 2E 31 38 31 3A 38 30 22 }
    
    
    condition : 
        ( $header at 0 ) 
        and 8 of ( $b* ) 
        and filesize < 6000KB
}