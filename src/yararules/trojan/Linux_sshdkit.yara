rule Linux_sshdkit_trojan {
    meta : 
		creation_date = "10/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "0AA65DBD61B27BCA2BAC68E7E710A500D922394215C4FD30EC76B0F31F9EA645"
        samples = "https://bazaar.abuse.ch/browse/tag/SSHdKit/"
        os = "Linux"

    strings : 

        // DQRTdeiqrt.sshd
        $b1 = { 44 51 52 54 64 65 69 71 72 74 00 73 73 68 64 }

        // Server listening on %s
        $b2 = { 53 65 72 76 65 72 20 6C 69 73 74 65 6E 69 6E 67 20 6F 6E 20 25 73 }

        // Don't panic.
        $b3 = { 44 6F 6E 27 74 20 70 61 6E 69 63 2E }

        // hostkeys-00@openssh.com
        $b4 = { 68 6F 73 74 6B 65 79 73 2D 30 30 40 6F 70 65 6E 73 73 68 2E 63 6F 6D }

        // after !!!
        $b5 = { 61 66 74 65 72 20 21 21 21 }

        // aes256-gcm@openssh.com
        $b6 = { 61 65 73 32 35 36 2D 67 63 6D 40 6F 70 65 6E 73 73 68 2E 63 6F 6D }

        // /mnt/mtd/Config/passwd
        $b7 = { 2F 6D 6E 74 2F 6D 74 64 2F 43 6F 6E 66 69 67 2F 70 61 73 73 77 64 }

        // >=RANDSALT_MAX_LEN, too long!
        $b8 = { 3E 3D 52 41 4E 44 53 41 4C 54 5F 4D 41 58 5F 4C 45 4E 2C 20 74 6F 6F 20 6C 6F 6E 67 21 }

        // hostkeyalgorithms
        $b9 = { 68 6F 73 74 6B 65 79 61 6C 67 6F 72 69 74 68 6D 73 }

        // curve over a
        $b10 = { 63 75 72 76 65 20 6F 76 65 72 20 61 }

    condition : 
        filesize < 1500KB
        and 8 of them
}