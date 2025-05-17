rule Linux_no_escape_ransomware_16d9e969 { 
    meta : 
		creation_date = "17/04/2024"
        github = "https://github.com/Zaque-69"
        fingerprint = "1836D8B40E42758946381D300B2A9BA4EE61E5AB11633A8E0317F6CDE09A5E331"
        sample = "https://bazaar.abuse.ch/download/16d9e969457a76874e7452e687a7b6843c65ef75d1a4404d369074ad389f6c38"
        os = "Linux"

    strings : 
        
        // TARGET_PATH="/home"
        $b1 = { 54 41 52 47 45 54 5F 50 41 54 48 3D 22 2F 68 6F 6D 65 22 }

        // 164f8295_linux
        $b2 = { 31 36 34 66 38 32 39 35 5F 6C 69 6E 75 78 }

        // find / -name *.log -exec rm -rf {} \;
        $b3 = { 66 69 6E 64 20 2F 20 2D 6E 61 6D 65 20 2A 2E 6C 6F 67 20 2D 65 78 65 63 20 72 6D 20 2D 72 66 20 7B 7D 20 5C 3B }

        // $(find "$TARGET_PATH/$nfs_volume/" -type f);
        $b4 = { 24 28 66 69 6E 64 20 22 24 54 41 52 47 45 54 5F 50 41 54 48 2F 24 6E 66 73 5F 76 6F 6C 75 6D 65 2F 22 20 2D 74 79 70 65 20 66 29 3B }

        // /crypto/bio/bio_meth.c
        $c1 = { 2F 63 72 79 70 74 6F 2F 62 69 6F 2F 62 69 6F 5F 6D 65 74 68 2E 63 }

        // BIO_meth_new
        $c2 = { 42 49 4F 5F 6D 65 74 68 5F 6E 65 77 }

        // EVP_PKEY_CTX_get_group_name
        $c3 = { 45 56 50 5F 50 4B 45 59 5F 43 54 58 5F 67 65 74 5F 67 72 6F 75 70 5F 6E 61 6D 65 }

    condition : 
        ( filesize < 5KB
        and 2 of ($b*) )
        or ( filesize > 5MB
        and all of ( $c* ))
}