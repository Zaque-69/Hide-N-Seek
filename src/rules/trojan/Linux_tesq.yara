rule Linux_TSource_Engine_Query_trojan { 
    meta : 
		creation_date = "18/12/2024"
        fingerprint = "fbb6519406abce86330834b4068bfcc57ab24271ba3d1ccb71ff3357f207e407"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // /etc/config/resolv.conf
        $b1 = { 2F 65 74 63 2F 63 6F 6E 66 69 67 2F 72 65 73 6F 6C 76 2E 63 6F 6E 66 }

        // /etc/config/hosts
        $b2 = { 2F 65 74 63 2F 63 6F 6E 66 69 67 2F 68 6F 73 74 73 }

        // TSource Engine Query
        $b3 = { 54 53 6F 75 72 63 65 20 45 6E 67 69 6E 65 20 51 75 65 72 79 }

        // dedsecrunsyoulilassnigga
        $msg = { 64 65 64 73 65 63 72 75 6E 73 79 6F 75 6C 69 6C 61 73 73 6E 69 67 67 61 }

    condition : 
        ( $header at 0 ) 
        and all of ( $b* ) 
        and ( $msg or true )
        and filesize > 50KB
}