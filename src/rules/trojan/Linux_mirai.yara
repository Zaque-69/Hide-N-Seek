rule Linux_mirai_trojan { 
    meta : 
		creation_date = "29/12/2024"
        fingerprint = "af7780f352718919c4fb1811d61932e9c5b6fb19e31c40e31128ba5baefaf5b8"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
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
        fingerprint = "3a6513ad548606a70424c998e44ad3f37021f516489a350043d2435a44dfa220"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // Host: %s..Connection: close
        $b1 = { 48 6F 73 74 3A 20 25 73 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65 }

        // 706173746562696E2E636F6D
        $b2 = { 37 30 36 31 37 33 37 34 36 35 36 32 36 39 36 45 32 45 36 33 36 46 36 44 }
      
    condition : 
        all of them
}