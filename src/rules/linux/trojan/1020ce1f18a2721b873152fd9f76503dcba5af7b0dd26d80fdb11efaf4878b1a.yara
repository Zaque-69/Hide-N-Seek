rule _1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a {
    meta : 
        author = "Z4que - All rights reverved"
		date = "19/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // mettle..install.uninstall
        $b1 = { 6D 65 74 74 6C 65 00 00 69 6E 73 74 61 6C 6C 00 75 6E 69 6E 73 74 61 6C 6C }

        // invalid background setting
        $b2 = { 69 6E 76 61 6C 69 64 20 62 61 63 6B 67 72 6F 75 6E 64 20 73 65 74 74 69 6E 67 }

        // /mettle/mettle/src/main.c
        $b3 = { 2F 6D 65 74 74 6C 65 2F 6D 65 74 74 6C 65 2F 73 72 63 2F 6D 61 69 6E 2E 63 }

        // start as a background service
        $b4 = { 73 74 61 72 74 20 61 73 20 61 20 62 61 63 6B 67 72 6F 75 6E 64 20 73 65 72 76 69 63 65 }

        // /mettle/mettle/src/mettle.c
        $b5 = { 2F 6D 65 74 74 6C 65 2F 6D 65 74 74 6C 65 2F 73 72 63 2F 6D 65 74 74 6C 65 2E 63 }

        // Name:
        $b6 = { 4E 61 6D 65 3A }

        // Module:
        $b7 = { 4D 6F 64 75 6C 65 3A }

        // License:
        $b8 = { 4C 69 63 65 6E 73 65 3A }

        // /mettle/mettle/src/stdapi/net/resolve.c
        $b9 = { 2F 6D 65 74 74 6C 65 2F 6D 65 74 74 6C 65 2F 73 72 63 2F 73 74 64 61 70 69 2F 6E 65 74 2F 72 65 73 6F 6C 76 65 2E 63 }

        // /usr/local/bin
        $b10 = { 2F 75 73 72 2F 6C 6F 63 61 6C 2F 62 69 6E }

        // /usr/local/sbin
        $b11 = { 2F 75 73 72 2F 6C 6F 63 61 6C 2F 73 62 69 6E }

        // -p, --persist [none|install|uninstall] manage persistence
        $c1 = { 2D 70 2C 20 2D 2D 70 65 72 73 69 73 74 20 5B 6E 6F 6E 65 7C 69 6E 73 74 61 6C 6C 7C 75 6E 69 6E 73 74 61 6C 6C 5D 20 6D 61 6E 61 67 65 20 70 65 72 73 69 73 74 65 6E 63 65 }        
   
        // -m, --modules <path>   add modules from path
        $c2 = { 2D 6D 2C 20 2D 2D 6D 6F 64 75 6C 65 73 20 3C 70 61 74 68 3E 20 20 20 61 64 64 20 6D 6F 64 75 6C 65 73 20 66 72 6F 6D 20 70 61 74 68 }

        // -c, --console.hu:U:G:d:o:b:p:n:lcm
        $c3 = { 2D 63 2C 20 2D 2D 63 6F 6E 73 6F 6C 65 00 68 75 3A 55 3A 47 3A 64 3A 6F 3A 62 3A 70 3A 6E 3A 6C 63 6D }

        // -U, --uuid <uuid>
        $c4 = { 2D 55 2C 20 2D 2D 75 75 69 64 20 3C 75 75 69 64 3E }

    condition : 
        ( $header at 0 ) 
        and 9 of ( $b* ) 
        and 3 of ( $c* ) 
        and filesize < 2000KB
}