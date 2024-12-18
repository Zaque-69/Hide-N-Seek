rule _f34b532117b3431387f11e3d92dc9ff417ec5dcee38a0175d39e323e5fdb1d2c { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "18/12/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // /mnt/hgfs/MyFc/MyFc/subhook/subhook_x86
        $b1 = { 2F 6D 6E 74 2F 68 67 66 73 2F 4D 79 46 63 2F 4D 79 46 63 2F 73 75 62 68 6F 6F 6B 2F 73 75 62 68 6F 6F 6B 5F 78 38 36 }

        // W7SLFSG4OPBJNAA8
        $b2 = { 57 37 53 4C 46 53 47 34 4F 50 42 4A 4E 41 41 38 }
            
        // GXCR7299I9MOWS97
        $b3 = { 47 58 43 52 37 32 39 39 49 39 4D 4F 57 53 39 37 }
        
        // (Ubuntu 11.3.0-1ubuntu1~22.04)
        $b4 = { 28 55 62 75 6E 74 75 20 31 31 2E 33 2E 30 2D 31 75 62 75 6E 74 75 31 7E 32 32 2E 30 34 29 }

    condition : 
        ( $header at 0 ) 
        and all of ( $b* ) 
        and filesize < 200KB
}