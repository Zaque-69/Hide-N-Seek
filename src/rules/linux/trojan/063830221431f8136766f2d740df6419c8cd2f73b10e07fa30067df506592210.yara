rule _063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210 {
    meta : 
        author = "Z4que - All rights reverved"
		date = "12/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        //5.253.84.120 -> UK
        $ip = { 35 2E 32 35 33 2E 38 34 2E 31 32 30 }
        //http://5.253.84.120/bins.sh
        $http = { 68 74 74 70 3A 2F 2F 35 2E 32 35 33 2E 38 34 2E 31 32 30 2F 62 69 6E 73 2E 73 68 }
   
        //telnet..root..admin
        $b1 = { 74 65 6C 6E 65 74 00 00 72 6F 6F 74 00 00 61 64 6D 69 6E }

        //toor..1234..4321..12345..54321
        $b2 = { 74 6F 6F 72 00 00 31 32 33 34 00 00 34 33 32 31 00 00 31 32 33 34 35 00 00 35 34 33 32 31 }

        //passwordBusyBox
        $b3 = { 70 61 73 73 77 6F 72 64 00 00 42 75 73 79 42 6F 78 }

        //PING.gethostbyname
        $b4 = { 50 49 4E 47 00 67 65 74 68 6F 73 74 62 79 6E 61 6D 65 }
    
        //Successfully Bruteforced IP:
        $b5 = { 53 75 63 63 65 73 73 66 75 6C 6C 79 20 42 72 75 74 65 66 6F 72 63 65 64 20 49 50 3A }
    
        //SCANNER ON | OFF.OFF.ON
        $b6 = { 53 43 41 4E 4E 45 52 20 4F 4E 20 7C 20 4F 46 46 00 4F 46 46 00 4F 4E }

        // /usr/bin/python.SERVER.ROUTER
        $b7 = { 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E 00 53 45 52 56 45 52 00 52 4F 55 54 45 52 }

        //rm -rf /tmp/* /var/* /var/run/* /var/tmp/*
        $rm1 = { 72 6D 20 2D 72 66 20 2F 74 6D 70 2F 2A 20 2F 76 61 72 2F 2A 20 2F 76 61 72 2F 72 75
            6E 2F 2A 20 2F 76 61 72 2F 74 6D 70 2F 2A }

        //rm -rf /var/log/wtmp.history -c;history -w
        $rm2 = { 72 6D 20 2D 72 66 20 2F 76 61 72 2F 6C 6F 67 2F 77 74 6D 70 00 68 69 73 74 6F 72 79
         20 2D 63 3B 68 69 73 74 6F 72 79 20 2D 77 }
    
        //rm -rf /tmp/*.history -c
        $rm3 = { 72 6D 20 2D 72 66 20 2F 74 6D 70 2F 2A 00 68 69 73 74 6F 72 79 20 2D 63 }
    
    condition : 
        ( $header at 0 ) 
        and 5 of ( $b* )
        and 2 of ( $rm* ) 
        and $ip
        and $http 
        and filesize < 2000KB
}