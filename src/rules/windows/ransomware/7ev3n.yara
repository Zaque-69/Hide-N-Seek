rule s7ev3n {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "13/12/2024"

    strings : 
        $header = { 4D 5A }

            // COMSPEC.cmd.exe./c..m.s.c.o.r.e.e...d.l.l
        	$a1 = { 43 4F 4D 53 50 45 43 00 63 6D 64 2E 65 78 65 00 2F 63 00 00 6D 00 73 00 63 00 6F 00 72 00 65 00 65 00 2E 00 64 00 6C 00 6C }

            // com..exe..bat..cmd
        	$a2 = { 63 6F 6D 00 2E 65 78 65 00 2E 62 61 74 00 2E 63 6D 64 }

            // All your documents, photos, databases, office projects
        	$a3 = { 41 6C 6C 20 79 6F 75 72 20 64 6F 63 75 6D 65 6E 74 73 2C 20 70 68 6F 74 6F 73 2C 20 64 61 74 61 62 61 73 65 73 2C 20 6F 66 66 69 63 65 20 70 72 6F 6A 65 63 74 73 }
        
            // and other important files have been encrypted with strongest encryption algorithm and unique key
        	$a4 = { 61 6E 64 20 6F 74 68 65 72 20 69 6D 70 6F 72 74 61 6E 74 20 66 69 6C 65 73 20 68 61 76 65 20 62 65 65 6E 20 65 6E 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6F 6E 67 65 73 74 20 65 6E 63 72 79 70 74 69 6F 6E 20 61 6C 67 6F 72 69 74 68 6D 20 61 6E 64 20 75 6E 69 71 75 65 20 6B 65 79 }

            // original files have been overwritten
            $a5 = { 6F 72 69 67 69 6E 61 6C 20 66 69 6C 65 73 20 68 61 76 65 20 62 65 65 6E 20 6F 76 65 72 77 72 69 74 74 65 6E }

            // Transaction will take about 50 minutes to accept and confirm the payment
            $a6 = { 54 72 61 6E 73 61 63 74 69 6F 6E 20 77 69 6C 6C 20 74 61 6B 65 20 61 62 6F 75 74 20 35 30 20 6D 69 6E 75 74 65 73 20 74 6F 20 61 63 63 65 70 74 20 61 6E 64 20 63 6F 6E 66 69 72 6D 20 74 68 65 20 70 61 79 6D 65 6E 74 }

            // Usually decryption will take about 1-3 hours
            $a7 = { 55 73 75 61 6C 6C 79 20 64 65 63 72 79 70 74 69 6F 6E 20 77 69 6C 6C 20 74 61 6B 65 20 61 62 6F 75 74 20 31 2D 33 20 68 6F 75 72 73 }

            // Bitcoin is a digital currency that you can buy on 'ebay.com', 'localbitcoins.com', 'anxpro.com', 'ccedk.com'
            $a8 = { 42 69 74 63 6F 69 6E 20 69 73 20 61 20 64 69 67 69 74 61 6C 20 63 75 72 72 65 6E 63 79 20 74 68 61 74 20 79 6F 75 20 63 61 6E 20 62 75 79 20 6F 6E 20 27 65 62 61 79 2E 63 6F 6D 27 2C 20 27 6C 6F 63 61 6C 62 69 74 63 6F 69 6E 73 2E 63 6F 6D 27 2C 20 27 61 6E 78 70 72 6F 2E 63 6F 6D 27 2C 20 27 63 63 65 64 6B 2E 63 6F 6D 27 }

            // YOUR PERSONAL INFORMATION ARE ENCRYPTED by 7ev3n
            $a9 = { 59 4F 55 52 20 50 45 52 53 4F 4E 41 4C 20 49 4E 46 4F 52 4D 41 54 49 4F 4E 20 41 52 45 20 45 4E 43 52 59 50 54 45 44 20 62 79 20 37 65 76 33 6E }

            // \%username%.SystemDrive.\Users\.\AppData\Local\.system.exe..del.bat.@echo off
            $a10 = { 5C 25 75 73 65 72 6E 61 6D 65 25 00 53 79 73 74 65 6D 44 72 69 76 65 00 5C 55 73 65 72 73 5C 00 5C 41 70 70 44 61 74 61 5C 4C 6F 63 61 6C 5C 00 73 79 73 74 65 6D 2E 65 78 65 00 00 64 65 6C 2E 62 61 74 00 40 65 63 68 6F 20 6F 66 66 0A }

            // \Windows\System32\SCHTASKS.exe
            $a11 = { 5C 57 69 6E 64 6F 77 73 5C 53 79 73 74 65 6D 33 32 5C 53 43 48 54 41 53 4B 53 2E 65 78 65 }

    condition : 
        ( $header at 0 ) 
        and 9 of ( $a* ) 
        and filesize < 400KB
}