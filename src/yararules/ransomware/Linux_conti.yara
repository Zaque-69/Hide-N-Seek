rule Linux_conti_ransomware_8b57e96 {
	meta : 
		creation_date = "08/04/2024"
		github = "https://github.com/Zaque-69"
		fingerprint = "BE101D9C976451F74392D33DAD9C9FD09C7286198259E508399D0BEF9EE0BAD9"
		sample = "https://bazaar.abuse.ch/download/8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201/"
		os = "Linux"

	strings:
		
		// libcrypto
        $b1 = { 6C 69 62 63 72 79 70 74 6F }

        // encrypted by CONTI
        $b2 = { 65 6E 63 72 79 70 74 65 64 20 62 79 20 43 4F 4E 54 49 }

        // DON'T TRY TO RECOVER
        $b3 = { 44 4F 4E 27 54 20 54 52 59 20 54 4F 20 52 45 43 4F 56 45 52 }

        // https://torproject.org
        $b4 = { 68 74 74 70 73 3A 2F 2F 74 6F 72 70 72 6F 6A 65 63 74 2E 6F 72 67 }

	condition : 
		filesize > 20KB
        and filesize < 100KB
		and all of them
}
