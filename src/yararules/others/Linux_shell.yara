rule Linux_shell_69f4dcd1 {
    meta : 
		creation_date = "10/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = ""
        sample = "https://bazaar.abuse.ch/download/69f4dcd1de05fc553781e737e85bdae5f0e79e7f34ded1899d60630e54d43fe4/"
        os = "Linux"

    strings : 
        
        // wget http://aggressivepvp.cf/iwadyhsa
        $b1 = { 77 67 65 74 20 68 74 74 70 3A 2F 2F 61 67 67 72 65 73 73 69 76 65 70 76 70 2E 63 66 2F 69 77 61 64 79 68 73 61 }

        // daddyl33tpiss
        $b2 = { 64 61 64 64 79 6C 33 33 74 70 69 73 73 }

        // chmod 777
        $b3 = { 63 68 6D 6F 64 20 37 37 37 }

        // rm -rf daddyl33tpiss
        $b4 = { 72 6D 20 2D 72 66 20 64 61 64 64 79 6C 33 33 74 70 69 73 73 }

    condition : 
        filesize < 10KB
        and all of them
}

rule Linux_shell_e5d316eb {
    meta : 
		creation_date = "29/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "F0268C8F51F0E6995B15513F079A63DD8CF5398A39DBABE14CC43A5E30887B97"
        sample = "https://bazaar.abuse.ch/download/e5d316ebc47a527fd923fde8eeeca8cfb320232df361e7db5fa5984f69080030"
        os = "Linux"

    strings : 
        
        // cp /bin/busybox /tmp/
        $b1 = { 63 70 20 2F 62 69 6E 2F 62 75 73 79 62 6F 78 20 2F 74 6D 70 2F }

        // ulimit -n 1024
        $b2 = { 75 6C 69 6D 69 74 20 2D 6E 20 31 30 32 34 }

        // ftpget -v -u anonymous
        $b3 = { 66 74 70 67 65 74 20 2D 76 20 2D 75 20 61 6E 6F 6E 79 6D 6F 75 73 }

        // 193.228.91.123
        $b4 = { 31 39 33 2E 32 32 38 2E 39 31 2E 31 32 33 }

    condition : 
        filesize < 10KB
        and all of them
}

rule Linux_shell_e244ecda {
    meta : 
		creation_date = "10/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "B55CE630941C65BC61427C3D3A6AFE199A466162F7BB1C93653760C0BAE68D7A"
        sample = "https://bazaar.abuse.ch/download/e244ecda6b325a3c8b087ed731e93b42b295e6b7f91e7cec3649fb2d807263d3"
        os = "Linux"

    strings : 
        
        // wget http://81.17.16.122
        $b1 = { 77 67 65 74 20 68 74 74 70 3A 2F 2F 38 31 2E 31 37 2E 31 36 2E 31 32 32 }

        // curl -O http://81.17.16.122
        $b2 = { 63 75 72 6C 20 2D 4F 20 68 74 74 70 3A 2F 2F 38 31 2E 31 37 2E 31 36 2E 31 32 32 }

        // s84j93nd3ht03w33dt
        $b3 = { 73 38 34 6A 39 33 6E 64 33 68 74 30 33 77 33 33 64 74 }

    condition : 
        filesize < 10KB
        and all of them
}