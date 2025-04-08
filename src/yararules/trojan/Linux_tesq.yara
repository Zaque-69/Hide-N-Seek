rule Linux_TSourceEngineQuery_trojan_e50764e4 { 
    meta : 
		creation_date = "18/12/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "CCE91619F32018FE8A3DD30EF66267D0C96505EFA800C5BF59F14F082A0DF770"
        os = "Linux"

    strings : 
        
        // /etc/config/resolv.conf
        $b1 = { 2F 65 74 63 2F 63 6F 6E 66 69 67 2F 72 65 73 6F 6C 76 2E 63 6F 6E 66 }

        // /etc/config/hosts
        $b2 = { 2F 65 74 63 2F 63 6F 6E 66 69 67 2F 68 6F 73 74 73 }

        // TSource Engine Query
        $b3 = { 54 53 6F 75 72 63 65 20 45 6E 67 69 6E 65 20 51 75 65 72 79 }

        // dedsecrunsyoulilassnigga
        $msg = { 64 65 64 73 65 63 72 75 6E 73 79 6F 75 6C 69 6C 61 73 73 6E 69 67 67 61 }

        // /x38/xFJ/x93/xID/x9A
        $string = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 }

    condition :
        filesize > 50KB 
        and all of ( $b* ) 
        and ( $string or false ) 
        and ( $msg or true )
}