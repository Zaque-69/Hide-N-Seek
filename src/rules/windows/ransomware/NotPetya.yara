rule notpetya_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "28/01/2024"

	strings:
		$header = { 4D 5A }

		//"Send your Bitcoin Wallet and personal installation"
		$c1 = { 53 00 65 00 6E 00 64 00 20 00 79 00 6F 00 75 00 72 00 20
			00 42 00 69 00 74 00 63 00 6F 00 69 00 6E 00 20 00 77 00 61 00 6C
			00 6C 00 65 00 74 00 20 00 49 00 44 00 20 00 61 00 6E 00 64 00 20
			00 70 00 65 00 72 00 73 00 6F 00 6E 00 61 00 6C 00 20 00 69 00 6E
			00 73 00 74 00 61 00 6C 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 } 

		//*The wallet ID you need to send the BTC
		$c2 = { 31 00 4D 00 7A 00 37 00 31 00 35 00 33 00 48 00 4D 00 75 00
			78 00 58 00 54 00 75 00 52 00 32 00 52 00 31 00 74 00 37 00 38 00 
			6D 00 47 00 53 00 64 00 7A 00 61 00 41 00 74 00 4E 00 62 00 42 00 
			57 00 58 } 

		//"300 Worth of Bitcoin"
		$c3 = { 24 00 33 00 30 00 30 00 20 00 77 00 6F 00 72 00 74 00 68 00 20
			00 6F 00 66 00 20 00 42 00 69 00 74 00 63 00 6F 00 69 00 6E }

		//"encrypt"
		$c4 = { 65 00 6E 00 63 00 72 00 79 00 70 00 74 } 

		$c5 = "WARNING: DO NOT TURN OFF YOUR PC! IF YOU ABORT THIS PROCESS, YOU COULD DESTROY ALL OF YOUR DATA!" fullword ascii
		$c6 = "Ooops, your important files are encrypted" fullword ascii

	condition : 
		($header at 0) 
		and any of ($c*)
		and filesize < 500KB
}