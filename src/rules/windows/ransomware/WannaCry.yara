rule WannaCry {
	meta : 
		author = "Z4que - All rights reserved"
		date = "14/12/2024"

	strings:
		$header = { 4D 5A }

		// WANACRY!
		$a1 = { 57 41 4E 41 43 52 59 21 }

		// W.a.n.a.C.r.y.p.t.0.r...S.o.f.t.w.a.r.e
		$a2 = { 57 00 61 00 6E 00 61 00 43 00 72 00 79 00 70 00 74 00 30 00 72 00 00 00 53 00 6F 00 66 00 74 00 77 00 61 00 72 00 65 }

		// Microsoft Enhanced RSA and AES Cryptographic Provide
		$a3 = { 4D 69 63 72 6F 73 6F 66 74 20 45 6E 68 61 6E 63 65 64 20 52 53 41 20 61 6E 64 20 41 45 53 20 43 72 79 70 74 6F 67 72 61 70 68 69 63 20 50 72 6F 76 69 64 65 }

		// /grant Everyone:F /T /C /Q.attrib +h ..WNcry@2ol7
		$a4 = { 2F 67 72 61 6E 74 20 45 76 65 72 79 6F 6E 65 3A 46 20 2F 54 20 2F 43 20 2F 51 00 61 74 74 72 69 62 20 2B 68 20 2E 00 57 4E 63 72 79 40 32 6F 6C 37 }

		// msg/m_chinese (simplified).wnry
		$a5 = { 6D 73 67 2F 6D 5F 63 68 69 6E 65 73 65 20 28 73 69 6D 70 6C 69 66 69 65 64 29 2E 77 6E 72 79 }

		// msg/m_danish.wnry
		$a6 = { 6D 73 67 2F 6D 5F 64 61 6E 69 73 68 2E 77 6E 72 79 }

		// msg/m_romanian.wnry
		$a7 = { 6D 73 67 2F 6D 5F 72 6F 6D 61 6E 69 61 6E 2E 77 6E 72 79 }

	condition : 
		$header at 0 
		and 6 of ($a*)
		and filesize < 4MB
}