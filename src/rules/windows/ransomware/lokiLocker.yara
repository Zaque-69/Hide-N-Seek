rule lokiLocker_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "27/01/2024"

	strings:
		$header = { 4D 5A }

        	//"your files have been encrypted"
		$c3 = { 59 00 6F 00 75 00 72 00 20 00 66 00 69 00 6C 00 65
		        00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65
		        00 6E 00 20 00 65 00 6E 00 63 00 72 00 79 00 70 00 74 00 65
		        00 64}
		
		//"Your compuer is locked. Please do not close this window"
		$c4 = { 59 00 6F 00 75 00 72 00 20 00 63 00 6F 00 6D 00 70
		        00 75 00 74 00 65 00 72 00 20 00 69 00 73 00 20 00 6C 00 6F
		        00 63 00 6B 00 65 00 64 00 2E 00 20 00 50 00 6C 00 65 00 61
		        00 73 00 65 00 20 00 64 00 6F 00 20 00 6E 00 6F 00 74 00 20
		        00 63 00 6C 00 6F 00 73 00 65 00 20 00 74 00 68 00 69 00 73
		        00 20 00 77 00 69 00 6E 00 64 00 6F 00 77 00 20 00 61 00 73
		        00 20 00 74 00 68 00 61 00 74 00 20 00 77 00 69 00 6C 00 6C
		        00 20 00 72 00 65 00 73 00 75 00 6C 00 74 00 20 00 69 00 6E
		        00 20 00 73 00 65 00 72 00 69 00 6F 00 75 00 73 00 20 00 63
		        00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 20 00 64 00 61
		        00 6D 00 61 00 67 00 65 }

        //"locked"
        $c5 = { 6C 00 6F 00 63 00 6B 00 65 00 64 }

        $c6 = "C:\\Users\\Tyler\\Desktop\\hidden-tear-master\\hidden-tear\\hidden-tear\\obj\\Debug\\VapeHacksLoader.pdb" ascii wide

	condition : 
		($header at 0) 
		and any of ($c*)
}