rule FreeYoutubeDownloader {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

        // \Microsoft\Internet Explorer\Quick Launch
        $a1 = { 5C 4D 69 63 72 6F 73 6F 66 74 5C 49 6E 74 65 72 6E 65 74 20 45 78 70 6C 6F 72 65 72 5C 51 75 69 63 6B 20 4C 61 75 6E 63 68 }

        // SMART INSTALL MAKER
        $a2 = { 53 4D 41 52 54 20 49 4E 53 54 41 4C 4C 20 4D 41 4B 45 52 }

        // sim.exe
        $a3 = { 73 69 6D 2E 65 78 65 }

        // Copyright 1995-2002 Jean-loup Gailly
        $a4 = { 43 6F 70 79 72 69 67 68 74 20 31 39 39 35 2D 32 30 30 32 20 4A 65 61 6E 2D 6C 6F 75 70 20 47 61 69 6C 6C 79 }

        // Y.o.u.t.u.b.e. .D.o.w.n.l.o.a.d.e.r
        $a5 = { 59 00 6F 00 75 00 74 00 75 00 62 00 65 00 20 00 44 00 6F 00 77 00 6E 00 6C 00 6F 00 61 00 64 00 65 00 72 }

        // F.i.l.e.D.e.s.c.r.i.p.t.i.o.n
        $a6 = { 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E }

        // Welcome to installer Free Youtube Downloader
        $a7 = { 57 65 6C 63 6F 6D 65 20 74 6F 20 69 6E 73 74 61 6C 6C 65 72 20 46 72 65 65 20 59 6F 75 74 75 62 65 20 44 6F 77 6E 6C 6F 61 64 65 72 }

        // At least 701.50 Kb of free disk space is required
        $a8 = { 41 74 20 6C 65 61 73 74 20 37 30 31 2E 35 30 20 4B 62 20 6F 66 20 66 72 65 65 20 64 69 73 6B 20 73 70 61 63 65 20 69 73 20 72 65 71 75 69 72 65 64 }

        // Click Install to continue with the installation
        $a9 = { 43 6C 69 63 6B 20 49 6E 73 74 61 6C 6C 20 74 6F 20 63 6F 6E 74 69 6E 75 65 20 77 69 74 68 20 74 68 65 20 69 6E 73 74 61 6C 6C 61 74 69 6F 6E }

        // or click Back if you want to review or change any settings
        $a10 = { 6F 72 20 63 6C 69 63 6B 20 42 61 63 6B 20 69 66 20 79 6F 75 20 77 61 6E 74 20 74 6F 20 72 65 76 69 65 77 20 6F 72 20 63 68 61 6E 67 65 20 61 6E 79 20 73 65 74 74 69 6E 67 73 }

        // Would you like to restart now?
        $a11 = { 57 6F 75 6C 64 20 79 6F 75 20 6C 69 6B 65 20 74 6F 20 72 65 73 74 61 72 74 20 6E 6F 77 3F }

    condition : 
        ( $header at 0 ) 
        and 9 of ( $a* ) 
        and filesize < 1MB
}