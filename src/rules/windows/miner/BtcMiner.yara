rule BtcMiner_Virus_Positive{
	meta : 
		author = "Z4que - All rights reverved"
		date = "29/01/2024"

	strings:
		$header = { 4D 5A }

		$c1 = "NsCpuCNMiner32.exe" ascii wide
		$reg1 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$reg2 = "/c reg add" ascii wide

		//"C:/Documents and settings"
		$c2 = { 43 00 3A 00 5C 00 44 00 6F 00 63 00 75 00 6D 00
			65 00 6E 00 74 00 73 00 20 00 61 00 6E 00 64 00 20 00 53
			00 65 00 74 00 74 00 69 00 6E 00 67 00 73 00 5C }
			
		//"C:/Users"
		$c3 = { 43 00 3A 00 5C 00 55 00 73 00 65 00 72 00 73 00 5C }

	condition : 
		($header at 0) 
		and all of ($reg*) 
		and any of ($c*)
}
