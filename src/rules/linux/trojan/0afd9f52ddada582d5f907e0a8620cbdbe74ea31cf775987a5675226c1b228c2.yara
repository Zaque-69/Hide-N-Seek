rule _0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "14/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // Killed bot process
        $b1 = { 4B 69 6C 6C 65 64 20 62 6F 74 20 70 72 6F 63 65 73 73 }
        
        // http://fast.no/support/crawler.asp
        $b2 = { 68 74 74 70 3A 2F 2F 66 61 73 74 2E 6E 6F 2F 73 75 70 70 6F 72 74 2F 63 72 61 77 6C 65 72 2E 61 73 70 }
            
        // http://www.billybobbot.com/crawler/   
        $b3 = { 68 74 74 70 3A 2F 2F 77 77 77 2E 62 69 6C 6C 79 62 6F 62 62 6F 74 2E 63 6F 6D 2F 63 72 61 77 6C 65 72 2F }
    
        // Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS 
        $b4 = { 53 65 6C 66 20 52 65 70 20 46 75 63 6B 69 6E 67 20 4E 65 54 69 53 20 61 6E 64 20 54 68 69 73 69 74 79 20 30 6E 20 55 72 20 46 75 43 6B 49 6E 47 20 46 6F 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4C 33 33 54 20 48 61 78 45 72 53 }

        // dayzddos.co runs you if you read this lol
        $b5 = { 64 61 79 7A 64 64 6F 73 2E 63 6F 20 72 75 6E 73 20 79 6F 75 20 69 66 20 79 6F 75 20 72 65 61 64 20 74 68 69 73 20 6C 6F 6C }

        // then you tcp dumped it because it hit you and you need to patch it lololololol
        $b6 = { 74 68 65 6E 20 79 6F 75 20 74 63 70 20 64 75 6D 70 65 64 20 69 74 20 62 65 63 61 75 73 65 20 69 74 20 68 69 74 20 79 6F 75 20 61 6E 64 20 79 6F 75 20 6E 65 65 64 20 74 6F 20 70 61 74 63 68 20 69 74 20 6C 6F 6C 6F 6C 6F 6C 6F 6C 6F 6C  }

        // Host:239.255.255.250:1900
        $b7 = { 48 6F 73 74 3A 32 33 39 2E 32 35 35 2E 32 35 35 2E 32 35 30 3A 31 39 30 30 }

        // http://104.168.11.84
        $b8 = { 68 74 74 70 3A 2F 2F 31 30 34 2E 31 36 38 2E 31 31 2E 38 34 } 

    condition : 
        ( $header at 0 ) 
        and 6 of ( $b* ) 
        and filesize < 300KB
}