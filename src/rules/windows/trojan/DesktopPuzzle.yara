rule DesktopPuzzle {
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
        
        // You can now continue whatever it was you were doing...
        $a4 = { 59 6F 75 20 63 61 6E 20 6E 6F 77 20 63 6F 6E 74 69 6E 75 65 20 77 68 61 74 65 76 65 72 20 69 74 20 77 61 73 20 79 6F 75 20 77 65 72 65 20 64 6F 69 6E 67 2E 2E 2E }

        // e-mail : andy_feys@hotmail.com
        $a5 = { 65 2D 6D 61 69 6C 20 3A 20 61 6E 64 79 5F 66 65 79 73 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D }

        // http://www.fortunecity.com/skyscraper/binary/44
        $a6 = { 68 74 74 70 3A 2F 2F 77 77 77 2E 66 6F 72 74 75 6E 65 63 69 74 79 2E 63 6F 6D 2F 73 6B 79 73 63 72 61 70 65 72 2F 62 69 6E 61 72 79 2F 34 34 }

        // Oops, looks like somebody doesn't like you very much !
        $a7 = { 4F 6F 70 73 2C 20 6C 6F 6F 6B 73 20 6C 69 6B 65 20 73 6F 6D 65 62 6F 64 79 20 64 6F 65 73 6E 27 74 20 6C 69 6B 65 20 79 6F 75 20 76 65 72 79 20 6D 75 63 68 20 21 }

        // You have to finish this sliding tile puzzle before you can continue whatever it is you're doing !
        $a8 = { 59 6F 75 20 68 61 76 65 20 74 6F 20 66 69 6E 69 73 68 20 74 68 69 73 20 73 6C 69 64 69 6E 67 20 74 69 6C 65 20 70 75 7A 7A 6C 65 20 62 65 66 6F 72 65 20 79 6F 75 20 63 61 6E 20 63 6F 6E 74 69 6E 75 65 20 77 68 61 74 65 76 65 72 20 69 74 20 69 73 20 79 6F 75 27 72 65 20 64 6F 69 6E 67 20 21 }

    condition : 
        ( $header at 0 ) 
        and 7 of ( $a* )
}