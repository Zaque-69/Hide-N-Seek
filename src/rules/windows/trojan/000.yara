rule _000exe { 
    meta : 
		author = "Z4que - All rights reserved"
		date = "14/12/2024"

	strings:
		$header = { 4D 5A }
		
		// PublicKeyToken=b77a5c561934e089
		$a1 = { 50 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 }

		// \rtf1\ansi\ansicpg1252\deff0\deflang1033
		$a2 = { 5C 72 74 66 31 5C 61 6E 73 69 5C 61 6E 73 69 63 70 67 31 32 35 32 5C 64 65 66 66 30 5C 64 65 66 6C 61 6E 67 31 30 33 33 }

		// YOU ARE THE NEXT
		$a3 = { 59 4F 55 20 41 52 45 20 54 48 45 20 4E 45 58 54 }

		// I CAN SEE YOU\par
		$a4 = { 49 20 43 41 4E 20 53 45 45 20 59 4F 55 5C 70 61 72 }

		// NOW ITS TOO LATE\par I GOT YOU
		$a5 = { 4E 4F 57 20 49 54 53 20 54 4F 4F 20 4C 41 54 45 5C 70 61 72 0D 0A 49 20 47 4F 54 20 59 4F 55 }

		// YOU HAVE BEEN WARNED
		$a6 = { 59 4F 55 20 48 41 56 45 20 42 45 45 4E 20 57 41 52 4E 45 44 }

		// DONT LOOK BEHIND YOU
		$a7 = { 44 4F 4E 54 20 4C 4F 4F 4B 20 42 45 48 49 4E 44 20 59 4F 55 }

        // Mainconcept MP4 Video Media Handler
        $a8 = { 4D 61 69 6E 63 6F 6E 63 65 70 74 20 4D 50 34 20 56 69 64 65 6F 20 4D 65 64 69 61 20 48 61 6E 64 6C 65 72 }

        // Single step trap
        $a9 = { 53 69 6E 67 6C 65 20 73 74 65 70 20 74 72 61 70 }

        // B.F.I.N.O.P.S.X.open.sysnative..bat..exe. .OK
        $a10 = { 42 00 46 00 49 00 4E 00 4F 00 50 00 53 00 58 00 6F 70 65 6E 00 73 79 73 6E 61 74 69 76 65 00 2E 62 61 74 00 2E 65 78 65 00 0D 0A 00 4F 4B }

        // C:\Users\FlyTech\Documents\Visual Studio 2015\Projects\Messager\Messager\obj\Debug\Messager.pdb
        $a11 = { 43 3A 5C 55 73 65 72 73 5C 46 6C 79 54 65 63 68 5C 44 6F 63 75 6D 65 6E 74 73 5C 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 32 30 31 35 5C 50 72 6F 6A 65 63 74 73 5C 4D 65 73 73 61 67 65 72 5C 4D 65 73 73 61 67 65 72 5C 6F 62 6A 5C 44 65 62 75 67 5C 4D 65 73 73 61 67 65 72 2E 70 64 62 }

	condition : 
		($header at 0 ) 
		and 9 of ($a*) 
		and filesize < 8MB
}