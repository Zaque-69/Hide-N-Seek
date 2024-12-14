rule ColorBug {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "14/12/2024"

    strings : 
        $header = { 4D 5A 50 }

        // SOFTWARE\Borland\Delphi\RTL.FPUMaskValue
        $a1 = { 53 4F 46 54 57 41 52 45 5C 42 6F 72 6C 61 6E 64 5C 44 65 6C 70 68 69 5C 52 54 4C 00 46 50 55 4D 61 73 6B 56 61 6C 75 65 } 

        // Portions Copyright (c) 1983,97 Borland
        $a2 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 37 20 42 6F 72 6C 61 6E 64 }

        // Software\Borland\Delphi\Locales
        $a3 = { 53 6F 66 74 77 61 72 65 5C 42 6F 72 6C 61 6E 64 5C 44 65 6C 70 68 69 5C 4C 6F 63 61 6C 65 73 }
        
        // Control Panel\Colors
        $a4 = { 43 6F 6E 74 72 6F 6C 20 50 61 6E 65 6C 5C 43 6F 6C 6F 72 73 }

    condition : 
        ( $header at 0 ) 
        and all of ( $a* )
}