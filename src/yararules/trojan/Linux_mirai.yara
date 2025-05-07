rule Linux_mirai_trojan { 
    meta : 
		creation_date = "29/12/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "A401A34F44C62B7CBDD3940DB2F17D52FFDB68A9AE13A931B4DCA949DB854719"
        sample = ""
        os = "Linux"

    strings : 
        
        // b0tn3t
        $b1 = { 62 30 74 6E 33 74 }
      
        // KRACO}PV
        $b2 = { 4B 52 41 43 4F 7D 50 56 }

    condition : 
        all of them
}

rule Linux_mirai_trojan_pastebin { 
    meta : 
		creation_date = "29/12/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "26A1B4FB9A1845A6C1D827A23EEE955A4B4FF646361F222167A8E261052B8358"
        sample = ""
        os = "Linux"

    strings : 
        
        // Host: %s..Connection: close
        $b1 = { 48 6F 73 74 3A 20 25 73 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65 }

        // 706173746562696E2E636F6D
        $b2 = { 37 30 36 31 37 33 37 34 36 35 36 32 36 39 36 45 32 45 36 33 36 46 36 44 }
      
    condition : 
        all of them
}

rule Linux_mirai_trojan_9e35f0a9 { 
    meta : 
		creation_date = "02/02/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "682721804BF900FFCF85E47879C6CF6AD6683D037CEB34DC9141E73908BDE0D7"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/9e35f0a9eef0b597432cb8a7dfbd7ce16f657e7a74c26f7a91d81b998d00b24d"
        os = "Linux"

    strings : 
        
        // KILLBOT
        $b1 = { 4B 49 4C 4C 42 4F 54 }

        // TCP
        $b2 = { 54 43 50 }

    condition : 
        filesize > 20KB
        and all of them
}

rule Linux_mirai_trojan_0a4b4171 { 
    meta : 
		creation_date = "04/02/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "16D6D42F109A4DCA07D18506C91E0381CB70AF3C73C353351ED59868D122FB40"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/0a4b417193f63a3cce4550e363548384eb007f89e89eb831cf1b7f5ddf230a51"
        os = "Linux"

    strings : 
        
        // PROT_EXEC|PROT_WRITE failed
        $b1 = { 50 52 4F 54 5F 45 58 45 43 7C 50 52 4F 54 5F 57 52 49 54 45 20 66 61 69 6C 65 64 }

        // sequen9D
        $b2 = { 73 65 71 75 65 6E 39 44 }

    condition : 
        filesize > 50KB
        and all of them
}

rule Linux_mirai_trojan_cfe32f28 { 
    meta : 
		creation_date = "06/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "5B4BD851ABF049D1C5AA6278CE2F164F571ADAE716590A5BB6C2B40F6EF653F1"
        sample = "https://bazaar.abuse.ch/download/cfe32f284a48e53fbc44ce570f4d1846b704a095f8fb05abe1fae4cdbf3522ba/"
        os = "Linux"

    strings : 
        
        // C)QQWP
        $b1 = { 43 29 51 51 57 50 }

        // POST /cdn-cgi/
        $b2 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F }

        // suckmadick
        $c1 = { 73 75 63 6B 6D 61 64 69 63 6B }

        // considertooof
        $c2 = { 63 6F 6E 73 69 64 65 72 74 6F 6F 6F 66}

        // TaurusIsYoMomma
        $c3 = { 54 61 75 72 75 73 49 73 59 6F 4D 6F 6D 6D 61 }

        // OogaBooga
        $c4 = { 4F 6F 67 61 42 6F 6F 67 61 }

    condition : 
        filesize > 100KB
        and filesize < 200KB
        and all of ( $b* ) 
        and any of ( $c* )
}

rule Linux_mirai_trojan_90afe3be { 
    meta : 
		creation_date = "06/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "9FBD083ACEFC0F9CB7CDB1D80A8F018EC9B9378FF68C0A95AAB339C74DF1E05B"
        sample = "https://bazaar.abuse.ch/download/90afe3be00cc6cc67a460ff5e50a5dc86f796350df367cd6732c3c19448a6dd5/"
        os = "Linux"

    strings : 
        
        // M-SEARCH
        $b1 = { 4D 2D 53 45 41 52 43 48 }

        // 239.255.255.250
        $b2 = { 32 33 39 2E 32 35 35 2E 32 35 35 2E 32 35 30 }

        // D$@H
        $b3 = { 44 24 40 48 }

        // Amanda 2
        $b4 = { 41 6D 61 6E 64 61 20 32 }

    condition : 
        filesize < 100KB
        and all of them
}