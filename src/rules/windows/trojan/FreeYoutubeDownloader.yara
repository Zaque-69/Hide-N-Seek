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