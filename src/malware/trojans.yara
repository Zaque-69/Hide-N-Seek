rule YouAreAnIdiot_positive {
    meta : 
        author = "Z4que - All rights reverved"
	  date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

        //YouAreAnIdiot.exe
        $c1 = { 59 6F 75 41 72 65 41 6E 49 64 69 6F 74 2E 65 78 65 } 

        //I think you are an idiot
        $c2 = { 49 00 20 00 74 00 68 00 69 00 6E 00 6B 00 20 00 79
                00 6F 00 75 00 20 00 61 00 72 00 65 00 20 00 61 00
                6E 00 20 00 69 00 64 00 69 00 6F 00 74 }

        //are you sure?
        $c3 = { 41 00 72 00 65 00 20 00 79 00 6F 00 75 00 20 00 73
                00 75 00 72 00 65 00 20 00 3F }
        
        //C:\Users\KenYue\documents\visual studio 2010\Projects\YouAreAnIdiot\YouAreAnIdiot\obj\x86\Debug\YouAreAnIdiot.pdb
        $c4 = { 43 3A 5C 55 73 65 72 73 5C 4B 65 6E 59 75 65 5C 64
                6F 63 75 6D 65 6E 74 73 5C 76 69 73 75 61 6C 20 73
                74 75 64 69 6F 20 32 30 31 30 5C 50 72 6F 6A 65 63
                74 73 5C 59 6F 75 41 72 65 41 6E 49 64 69 6F 74 5C
                59 6F 75 41 72 65 41 6E 49 64 69 6F 74 5C 6F 62 6A
                5C 78 38 36 5C 44 65 62 75 67 5C 59 6F 75 41 72 65
                41 6E 49 64 69 6F 74 2E 70 64 62 }

           condition : 
        ( $header at 0 ) and all of ( $c* )
}
rule MEMZ_positive {
    meta : 
        author = "Z4que - All rights reverved"
	   date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

        $c1 = "ur computer has been trashed by the MEMZ trojan" ascii wide
        $c2 = "YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN" ascii wide
        $c3 = "Your computer won't boot up again" ascii wide
        $c4 = "best+way+to+kill+yourself" ascii wide

    condition : 
        ( $header at 0 ) and all of ( $c* )
}
rule FreeYoutubeDownloader_positive {
    meta : 
        author = "Z4que - All rights reverved"
	   date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

        //Welcome to insteller Free Youtube Downloader. Copyright . 2015, Free Youtube Downloader
        $c1 = { 57 65 6C 63 6F 6D 65 20 74 6F 20 69 6E 73 74 61 6C
                6C 65 72 20 46 72 65 65 20 59 6F 75 74 75 62 65 20
                44 6F 77 6E 6C 6F 61 64 65 72 00 43 6F 70 79 72 69
                67 68 74 20 A9 20 32 30 31 35 2C 20 46 72 65 65 20
                59 6F 75 74 75 62 65 20 44 6F 77 6E 6C 6F 61 64 65
                72 00 }

        //At least 701.50 Kb of free disk space is requied
        $c2 = { 41 74 20 6C 65 61 73 74 20 37 30 31 2E 35 30 20 4B
                62 20 6F 66 20 66 72 65 65 20 64 69 73 6B 20 73 70
                61 63 65 20 69 73 20 72 65 71 75 69 72 65 64 }
        
        //Please wait while Free Youtube Downloader is being installed.
        $c3 = { 50 6C 65 61 73 65 20 77 61 69 74 20 77 68 69 6C 65
                20 46 72 65 65 20 59 6F 75 74 75 62 65 20 44 6F 77
                6E 6C 6F 61 64 65 72 20 69 73 20 62 65 69 6E 67 20
                69 6E 73 74 61 6C 6C 65 64 2E }

        //http://1.0.1.0
        $c4 = { 68 74 74 70 3A 2F 2F 00 31 00 30 00 31 00 30 }

        $c5 = "Uninstall.exe" ascii wide
        $c6 = "www.youtubedownloadernew.com" ascii wide


    condition : 
     
        ( $header at 0 ) and 4 of ( $c* ) 
}
rule HBMlocker_positive {
    meta : 
        author = "Z4que - All rights reverved"
	   date = "7/03/2024"

    strings : 
        $header = { 4D 5A }
  
        //HKEY_CUR.NTm..._USER\SOFTWA\MicZs\.{..t\Windows\CurIntVtsion -> change Win Registry
        $c1 = { 48 4B 45 59 5F 43 55 52 0F 4E 54 6D FB F2 FF 5F 55
                53 45 52 5C 53 4F 46 54 57 41 5C 4D 69 63 5A 73 5C
                7F 7B FB FF 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72
                49 6E 74 56 74 73 69 6F 6E }
        
        //I.N%userprofi.%\2503326..@.475
        $c2 = { 49 00 4E 25 75 73 65 72 70 72 6F 66 69 18 25 5C 32
                35 30 33 33 32 36 1E B0 40 F6 34 37 35 }
    condition : 
     
        ( $header at 0 ) and any of ( $c* ) 
}
