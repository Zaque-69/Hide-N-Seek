rule Memz {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "14/12/2024"

    strings : 
        $header = { 4D 5A }

        // Your computer has been trashed by the MEMZ trojan
        $a1 = { 59 6F 75 72 20 63 6F 6D 70 75 74 65 72 20 68 61 73 20 62 65 65 6E 20 74 72 61 73 68 65 64 20 62 79 20 74 68 65 20 4D 45 4D 5A 20 74 72 6F 6A 61 6E }

        // Now enjo_�.�Nyan Cat
        $a2 = { 4E 6F 77 20 65 6E 6A 6F 5F BC 06 8A 4E 79 61 6E 20 43 61 74 }

        // YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN
        $a3 = { 59 4F 55 52 20 43 4F 4D 50 55 54 45 52 20 48 41 53 20 42 45 45 4E 20 46 55 43 4B 45 44 20 42 59 20 54 48 45 20 4D 45 4D 5A 20 54 52 4F 4A 41 4E }

        // Your computer won't boot up again, so use it as long as you can! :D
        $a4 = { 59 6F 75 72 20 63 6F 6D 70 75 74 65 72 20 77 6F 6E 27 74 20 62 6F 6F 74 20 75 70 20 61 67 61 69 6E 2C 0D 0A 73 6F 20 75 73 65 20 69 74 20 61 73 20 6C 6F 6E 67 20 61 73 20 79 6F 75 20 63 61 6E 21 0D 0A 0D 0A 3A 44 }

        // http://google.co.ck/search?q=best+way+to+kill+yourself
        $a5 = { 68 74 74 70 3A 2F 2F 67 6F 6F 67 6C 65 2E 63 6F 2E 63 6B 2F 73 65 61 72 63 68 3F 71 3D 62 65 73 74 2B 77 61 79 2B 74 6F 2B 6B 69 6C 6C 2B 79 6F 75 72 73 65 6C 66 }

        // http://google.co.ck/search?q=how+2+remove+a+virus
        $a6 = { 68 74 74 70 3A 2F 2F 67 6F 6F 67 6C 65 2E 63 6F 2E 63 6B 2F 73 65 61 72 63 68 3F 71 3D 68 6F 77 2B 32 2B 72 65 6D 6F 76 65 2B 61 2B 76 69 72 75 73 }

        // YOU TRIED SO HARD AND GOT SO FAR, BUT IN THE END, YOUR PC WAS STILL FUCKED!
        $a7 = { 59 4F 55 20 54 52 49 45 44 20 53 4F 20 48 41 52 44 20 41 4E 44 20 47 4F 54 20 53 4F 20 46 41 52 2C 20 42 55 54 20 49 4E 20 54 48 45 20 45 4E 44 2C 20 59 4F 55 52 20 50 43 20 57 41 53 20 53 54 49 4C 4C 20 46 55 43 4B 45 44 21 }

        // GET BETTER HAX NEXT TIME xD
        $a8 = { 47 45 54 20 42 45 54 54 45 52 20 48 41 58 20 4E 45 58 54 20 54 49 4D 45 20 78 44 }

        // HA HA HA HA HA HA HA
        $a9 = { 48 41 20 48 41 20 48 41 20 48 41 20 48 41 20 48 41 20 48 41 }

        // #MakeMalwareGreatAgain
        $a10 = { 23 4D 61 6B 65 4D 61 6C 77 61 72 65 47 72 65 61 74 41 67 61 69 6E }

    condition : 
        ( $header at 0 ) 
        and 8 of ( $a* )
        and filesize < 100KB
}