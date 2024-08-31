rule Hydra_positive {
    meta : 
        author = "Z4que - All rights reverved"
		date = "23/02/2024"

    strings : 
        $header = { 4D 5A }

        $c1 = "Hydra.exe" ascii wide
        $c2 = "D:/Visual Studio Projects/Hydra/Hydra/obj/Release/Hydra.pdb" ascii wide
        
        //Cut off a head, two more will take its place
        $b1 = { 43 00 75 00 74 00 20 00 6F 00 66 00 66 00 20 00 61 00 20 00
             68 00 65 00 61 00 64 00 2C 00 20 00 74 00 77 00 6F 00 20 00 6D
             00 6F 00 72 00 65 00 20 00 77 00 69 00 6C 00 6C 00 20 00 74 00
             61 00 6B 00 65 00 20 00 69 00 74 00 73 00 20 00 70 00 6C 00 61
             00 63 00 65 00
        }

        //WiPet -> the author of the virus
        $b2 = { 57 00 69 00 50 00 65 00 74 }
   
    condition : 
        ( $header at 0 ) and any of ( $c* ) and any of ( $b* )
}

rule RainbowIsKawaii_positive {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "23/02/2024"

    strings : 
        $header = { 4D 5A }

        $c1 = "C:/Users/boris/documents/visual studio 2017/Projects/CookieClicker_Hack2017/CookieClicker_Hack2017/obj/Debug/CookieClicker_Hack2017.pdb" ascii wide
        
        //"Label4 STUPID? Button1 Yes yes !"
        $c2 = { 4C 00 61 00 62 00 65 00 6C 00 34 00 00 0F 53 00 54 00 55 00
                50 00 49 00 44 00 3F 00 00 0F 42 00 75 00 74 00 74 00 6F 00
                6E 00 31 00 00 11 59 00 65 00 73 00 20 00 79 00 65 00 73 00
                21 }

        //"Button2 Heck no"
        $c3 = { 42 00 75 00 74 00 74 00 6F 00 6E 00 32 00 00 11 48 00 65 00
                63 00 6B 00 20 00 6E 00 6F }

    condition : 
        ( $header at 0 ) and any of ( $c* )
}

rule Fake_Windows_Update {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "02/06/2024" 
    strings : 
        $header = { 4D 5A }

        $c1 = "D:/Visual Studio Projects/WindowsUpdate/WindowsUpdate/obj/Release/Windows-KB2670838.msu.pdb" ascii wide
        
        //win 10 loads
        $c2 = { 77 00 69 00 6E 00 31 00 30 00 5F 00 6C 00 6F 00 61 00 64
                00 73 }
                
        $c3 = { 3C 68 74 74 70 3A 2F 2F 6E 73 2E 61 64 6F 62 65 2E 63 6F
                6D 2F 78 61 70 2F 31 2E 30 2F 00 3C 3F 78 70 61 63 6B 65 74 20
                62 65 67 69 6E 3D 27 EF BB BF 27 20 69 64 3D 27 57 35 4D 30 4D
                70 43 65 68 69 48 7A 72 65 53 7A 4E 54 63 7A 6B 63 39 64 27 3F
                3E 0D 0A 3C 78 3A 78 6D 70 6D 65 74 61 20 78 6D 6C 6E 73 3A 78
                3D 22 61 64 6F 62 65 3A 6E 73 3A 6D 65 74 61 2F 22 3E 3C 72 64
                66 3A 52 44 46 20 78 6D 6C 6E 73 3A 72 64 66 3D 22 68 74 74 70
                3A 2F 2F 77 77 77 2E 77 33 2E 6F 72 67 2F 31 39 39 39 2F 30 32
                2F 32 32 2D 72 64 66 2D 73 79 6E 74 61 78 2D 6E 73 23 22 3E 3C
                72 64 66 3A 44 65 73 63 72 69 70 74 69 6F 6E 20 72 64 66 3A 61
                62 6F 75 74 3D 22 75 75 69 64 3A 66 61 66 35 62 64 64 35 2D 62
                61 33 64 2D 31 31 64 61 2D 61 64 33 31 2D 64 33 33 64 37 35 31
                38 32 66 31 62 22 20 78 6D 6C 6E 73 3A 64 63 3D 22 68 74 74 70
                3A 2F 2F 70 75 72 6C 2E 6F 72 67 2F 64 63 2F 65 6C 65 6D 65 6E 
                74 73 2F 31 2E 31 2F 22 2F 3E 3C 72 64 66 3A 44 65 73 63 72 69 
                70 74 69 6F 6E 20 72 64 66 3A 61 62 6F 75 74 3D 22 75 75 69 64
                3A 66 61 66 35 62 64 64 35 2D 62 61 33 64 2D 31 31 64 61 2D 61 
                64 33 31 2D 64 33 33 64 37 35 31 38 32 66 31 62 22 20 78 6D 6C
                6E 73 3A 74 69 66 66 3D 22 68 74 74 70 3A 2F 2F 6E 73 2E 61 64
                6F 62 65 2E 63 6F 6D 2F 74 69 66 66 2F 31 2E 30 2F 22 2F 3E 3C
                2F 72 64 66 3A 52 44 46 3E 3C 2F 78 3A 78 6D 70 6D 65 74 61 3E }

    condition : 
        ( $header at 0 ) and any of ( $c* )
}