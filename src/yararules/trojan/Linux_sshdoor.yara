rule Linux_sshdoor_trojan_6de1e587 {
    meta : 
		creation_date = "18/01/2025"
        update_date = "28/01/2025"
        fingerprint = "6D89CE6B6C875F83E410B221C968589CA452C56B8877E75ED3DF0561EA4303AE"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // SSH_KEY_BITS_RESERVED
        $b1 = { 53 53 48 5F 4B 45 59 5F 42 49 54 53 5F 52 45 53 45 52 56 45 44 }

        // attack detected
        $b2 = { 61 74 74 61 63 6B 20 64 65 74 65 63 74 65 64 }

        // backdoor
        $b3 = { 62 61 63 6B 64 6F 6F 72 }

        // hmac-ripemd160@openssh.com
        $b4 = { 68 6D 61 63 2D 72 69 70 65 6D 64 31 36 30 40 6F 70 65 6E 73 73 68 2E 63 6F 6D }

    condition : 
        all of them
}