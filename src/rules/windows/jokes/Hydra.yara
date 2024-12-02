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
             00 63 00 65 00 }
        //WiPet -> the author of the virus
        $b2 = { 57 00 69 00 50 00 65 00 74 }
   
    condition : 
        ( $header at 0 ) 
        and any of ( $c* ) 
        and any of ( $b* )
}