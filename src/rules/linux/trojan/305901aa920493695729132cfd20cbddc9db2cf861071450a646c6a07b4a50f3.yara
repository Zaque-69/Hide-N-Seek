rule _305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "29/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // Kaiten Ziggy StarTux
        $b1 = { 4B 61 69 74 65 6E 20 5A 69 67 67 79 20 53 74 61 72 54 75 78 }
        
        // Wierd, you shouldnt get this error and ITS NOT MY FAULT!
        $b2 = { 57 69 65 72 64 2C 20 79 6F 75 20 73 68 6F 75 6C 64 6E 74 20 67 65 74 20 74 68 69 73 20 65 72 72 6F 72 20 61 6E 64 20 49 54 53 20 4E 4F 54 20 4D 59 20 46 41 55 4C 54 21 }
            
        // In loving memory of David Bowie
        $b3 = { 49 6E 20 6C 6F 76 69 6E 67 20 6D 65 6D 6F 72 79 20 6F 66 20 44 61 76 69 64 20 42 6F 77 69 65 }
    
        // Downloads a file off the web and saves it onto the hd
        $b4 = { 44 6F 77 6E 6C 6F 61 64 73 20 61 20 66 69 6C 65 20 6F 66 66 20 74 68 65 20 77 65 62 20 61 6E 64 20 73 61 76 65 73 20 69 74 20 6F 6E 74 6F 20 74 68 65 20 68 64 }

        // image/gif
        $b5 = { 69 6D 61 67 65 2F 67 69 66 }

        // image/x-xbitmap
        $b6 = { 69 6D 61 67 65 2F 78 2D 78 62 69 74 6D 61 70 }

        // image/jpeg
        $b7 = { 69 6D 61 67 65 2F 6A 70 65 67 }

        // dss=/var/dbs/dropbear_dss_host_key
        $b8 = { 64 73 73 3D 2F 76 61 72 2F 64 62 73 2F 64 72 6F 70 62 65 61 72 5F 64 73 73 5F 68 6F 73 74 5F 6B 65 79 }

        // for i in dropbear dbclient dropbearkey dropbearconvert
        $b9 = { 66 6F 72 20 69 20 69 6E 20 64 72 6F 70 62 65 61 72 20 64 62 63 6C 69 65 6E 74 20 64 72 6F 70 62 65 61 72 6B 65 79 20 64 72 6F 70 62 65 61 72 63 6F 6E 76 65 72 74 }

        // killall -9
        $b10 = { 6B 69 6C 6C 61 6C 6C 20 2D 39 }

        // 352.376.433.422
        $b11 = { 33 35 32 00 33 37 36 00 34 33 33 00 34 32 32 }

        // I'm having a problem resolving my host, someone will have to SPOOFS me manually
        $b12 = { 49 27 6D 20 68 61 76 69 6E 67 20 61 20 70 72 6F 62 6C 65 6D 20 72 65 73 6F 6C 76 69 6E 67 20 6D 79 20 68 6F 73 74 2C 20 73 6F 6D 65 6F 6E 65 20 77 69 6C 6C 20 68 61 76 65 20 74 6F 20 53 50 4F 4F 46 53 20 6D 65 20 6D 61 6E 75 61 6C 6C 79 }

    condition : 
        ( $header at 0 ) 
        and 10 of ( $b* ) 
        and filesize < 1000KB
}