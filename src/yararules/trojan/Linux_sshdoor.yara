rule Linux_sshdoor__trojan_6de1e587 {
    meta : 
		creation_date = "18/01/2025"
        fingerprint = "63B2400EBE3B876A72B2F8C8E1D795A142F27D73B3C5F2A258A14CF93118CD18"
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