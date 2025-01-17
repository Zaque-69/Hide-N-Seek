rule Linux_mirai_trojan { 
    meta : 
		creation_date = "29/12/2024"
        update_date = "09/01/2025"
        fingerprint = "8A5771A3FF2A167465DF75BCEB004E1742E69C7BD969A50BAE498F498C8AF8ED"
        github = "https://github.com/Zaque-69"
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
        update_date = "09/01/2025"
        fingerprint = "DCFB8DDC3690BC6FF63F47C9C97F34ABDE409E490A0E7496875CE897A5CA5594"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // Host: %s..Connection: close
        $b1 = { 48 6F 73 74 3A 20 25 73 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65 }

        // 706173746562696E2E636F6D
        $b2 = { 37 30 36 31 37 33 37 34 36 35 36 32 36 39 36 45 32 45 36 33 36 46 36 44 }
      
    condition : 
        all of them
}