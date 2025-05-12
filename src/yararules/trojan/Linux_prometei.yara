rule Linux_prometei_abuse_ch {
    meta : 
		creation_date = "10/05/2025"
        update_date = "11/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "EB73A0E570F8DAC0CA978C9977D8B820D2D70DEFD1F1C517F6038B303E4C045D"
        sample = "https://bazaar.abuse.ch/user/1/"
        os = "Linux"

    strings : 

        // 9UPX!
        $upx = { 39 55 50 58 21 }
 
        // "config":1,"id":
        $b = { 22 63 6F 6E 66 69 67 22 3A 31 2C 22 69 64 22 3A }

        // http://p3.feefreepool.net
        $p1 = { 68 74 74 70 3A 2F 2F 70 33 2E 66 65 65 66 72 65 65 70 6F 6F 6C 2E 6E 65 74 }

        // prometei.cgi
        $p2 = { 70 72 6F 6D 65 74 65 69 2E 63 67 69 }

    condition : 
        ( filesize > 400KB and filesize < 500KB and $upx and $b )
        or ( filesize > 800KB and filesize < 1MB and $b and any of ( $p* ))
}