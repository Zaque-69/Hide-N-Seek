rule _0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "14/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        $loader = { 2F 6C 69 62 36 34 2F 6C 64 2D 6C 69 6E 75 78 2D 78 38 36 2D 36 34 }
        
        // /etc/passwd
        $b1 = { 2F 65 74 63 2F 70 61 73 73 77 64 }

        // File %s already exists! Please delete it and run again
        $b2 = { 46 69 6C 65 20 25 73 20 61 6C 72 65 61 64 79 20 65 78 69 73 74 73 21 20 50 6C 65 61 73 65 20 64 65 6C 65 74 65 20 69 74 20 61 6E 64 20 72 75 6E 20 61 67 61 69 6E }

        // Please enter the new password:
        $b3 = { 50 6C 65 61 73 65 20 65 6E 74 65 72 20 74 68 65 20 6E 65 77 20 70 61 73 73 77 6F 72 64 3A }

        // Check %s to see if the new user was created
        $b4 = { 43 68 65 63 6B 20 25 73 20 74 6F 20 73 65 65 20 69 66 20 74 68 65 20 6E 65 77 20 75 73 65 72 20 77 61 73 20 63 72 65 61 74 65 64 }

        // DON'T FORGET TO RESTORE
        $b5 = { 44 4F 4E 27 54 20 46 4F 52 47 45 54 20 54 4F 20 52 45 53 54 4F 52 45 }

        // Red Hat 4.8.5-39
        $b6 = { 52 65 64 20 48 61 74 20 34 2E 38 2E 35 2D 33 39 }

    condition : 
        ( $header at 0 ) 
        and $loader
        and 5 of ( $b* ) 
        and filesize < 2000KB
}