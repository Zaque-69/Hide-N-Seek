rule _bb64b27bff106d30a7b74b3589cc081c345a2b485a831d7e8c8837af3f238e1e { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "18/12/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // All of your files are currently encrypted by CONTI strain.
        $b1 = { 41 6C 6C 20 6F 66 20 79 6F 75 72 20 66 69 6C 65 73 20 61 72 65 20 63 75 72 72 65 6E 74 6C 79 20 65 6E 63 72 79 70 74 65 64 20 62 79 20 43 4F 4E 54 49 20 73 74 72 61 69 6E 2E }

        // If you don't know who we are - just "Google it"
        $b2 = { 49 66 20 79 6F 75 20 64 6F 6E 27 74 20 6B 6E 6F 77 20 77 68 6F 20 77 65 20 61 72 65 20 2D 20 6A 75 73 74 20 22 47 6F 6F 67 6C 65 20 69 74 22 }
            
        // As you already know, all of your data has been encrypted by our software
        $b3 = { 41 73 20 79 6F 75 20 61 6C 72 65 61 64 79 20 6B 6E 6F 77 2C 20 61 6C 6C 20 6F 66 20 79 6F 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6E 20 65 6E 63 72 79 70 74 65 64 20 62 79 20 6F 75 72 20 73 6F 66 74 77 61 72 65 }
        
        // It cannot be recovered by any means without contacting our team directly
        $b4 = { 49 74 20 63 61 6E 6E 6F 74 20 62 65 20 72 65 63 6F 76 65 72 65 64 20 62 79 20 61 6E 79 20 6D 65 61 6E 73 20 77 69 74 68 6F 75 74 20 63 6F 6E 74 61 63 74 69 6E 67 20 6F 75 72 20 74 65 61 6D 20 64 69 72 65 63 74 6C 79 }

        // DONT'T TRY TO RECOVER your data by yourselves.
        $b5 = { 44 4F 4E 54 27 54 20 54 52 59 20 54 4F 20 52 45 43 4F 56 45 52 20 79 6F 75 72 20 64 61 74 61 20 62 79 20 79 6F 75 72 73 65 6C 76 65 73 }

        // DON'T TRY TO IGNORE us
        $b6 = { 44 4F 4E 27 54 20 54 52 59 20 54 4F 20 49 47 4E 4F 52 45 20 75 73 }
   
        // So it will be better for both sides if you contact us as soon as possible
        $b7 = { 53 6F 20 69 74 20 77 69 6C 6C 20 62 65 20 62 65 74 74 65 72 20 66 6F 72 20 62 6F 74 68 20 73 69 64 65 73 20 69 66 20 79 6F 75 20 63 6F 6E 74 61 63 74 20 75 73 20 61 73 20 73 6F 6F 6E 20 61 73 20 70 6F 73 73 69 62 6C 65 }

        // To prove that we REALLY CAN get your data back - we offer you to decrypt two random files completely free of charge
        $b8 = { 54 6F 20 70 72 6F 76 65 20 74 68 61 74 20 77 65 20 52 45 41 4C 4C 59 20 43 41 4E 20 67 65 74 20 79 6F 75 72 20 64 61 74 61 20 62 61 63 6B 20 2D 20 77 65 20 6F 66 66 65 72 20 79 6F 75 20 74 6F 20 64 65 63 72 79 70 74 20 74 77 6F 20 72 61 6E 64 6F 6D 20 66 69 6C 65 73 20 63 6F 6D 70 6C 65 74 65 6C 79 20 66 72 65 65 20 6F 66 20 63 68 61 72 67 65 }

        // You can contact our team directly for further instructions through our website
        $b9 = { 59 6F 75 20 63 61 6E 20 63 6F 6E 74 61 63 74 20 6F 75 72 20 74 65 61 6D 20 64 69 72 65 63 74 6C 79 20 66 6F 72 20 66 75 72 74 68 65 72 20 69 6E 73 74 72 75 63 74 69 6F 6E 73 20 74 68 72 6F 75 67 68 20 6F 75 72 20 77 65 62 73 69 74 65 }

        // MIICCgKCAgEAzE9EcNlVWVD90IXnZbm2xF5enn2UtGv9yFDoufSvFTAs2524xqqx
        $b10 = { 4D 49 49 43 43 67 4B 43 41 67 45 41 7A 45 39 45 63 4E 6C 56 57 56 44 39 30 49 58 6E 5A 62 6D 32 78 46 35 65 6E 6E 32 55 74 47 76 39 79 46 44 6F 75 66 53 76 46 54 41 73 32 35 32 34 78 71 71 78 }

        // When you use this parameter, the locker encrypts files at the specified path
        $b11 = { 57 68 65 6E 20 79 6F 75 20 75 73 65 20 74 68 69 73 20 70 61 72 61 6D 65 74 65 72 2C 20 74 68 65 20 6C 6F 63 6B 65 72 20 65 6E 63 72 79 70 74 73 20 66 69 6C 65 73 20 61 74 20 74 68 65 20 73 70 65 63 69 66 69 65 64 20 70 61 74 68 }

        // This parameter is mandatory
        $b12 = { 54 68 69 73 20 70 61 72 61 6D 65 74 65 72 20 69 73 20 6D 61 6E 64 61 74 6F 72 79 }

    condition : 
        ( $header at 0 ) 
        and 10 of ( $b* ) 
        and filesize < 100KB
}