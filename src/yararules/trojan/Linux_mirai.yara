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

rule Linux_mirai_trojan_9e35f0a9 { 
    meta : 
		creation_date = "02/02/2025"
        fingerprint = "FD67E5F06AF67D26C184AA0A5B773A6D674C5CD591B2E6A142BF39CE041282C2"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // KILLBOT
        $b1 = { 4B 49 4C 4C 42 4F 54 }

        // TCP
        $b2 = { 54 43 50 }

    condition : 
        all of them
}

rule Linux_mirai_trojan_0a4b4171 { 
    meta : 
		creation_date = "04/02/2025"
        fingerprint = ""
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // PROT_EXEC|PROT_WRITE failed
        $b1 = { 50 52 4F 54 5F 45 58 45 43 7C 50 52 4F 54 5F 57 52 49 54 45 20 66 61 69 6C 65 64 }

        // sequen9D
        $b2 = { 73 65 71 75 65 6E 39 44 }

    condition : 
        all of them
}