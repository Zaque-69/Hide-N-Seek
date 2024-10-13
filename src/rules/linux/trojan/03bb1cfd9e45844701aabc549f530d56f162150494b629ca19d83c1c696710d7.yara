rule _03bb1cfd9e45844701aabc549f530d56f162150494b629ca19d83c1c696710d7 {
    meta : 
        author = "Z4que - All rights reverved"
		date = "11/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        $loader = { 2F 6C 69 62 36 34 2F 6C 64 2D 6C 69 6E 75 78 2D 78 38 36
            2D 36 34 }   
        
        //email._encoded_words
        $e1 = { 65 6D 61 69 6C 2E 5F 65 6E 63 6F 64 65 64 5F 77 6F 72 64 73 }
        
        //email._header_value_parser
        $e2 = { 65 6D 61 69 6C 2E 5F 68 65 61 64 65 72 5F 76 61 6C 75 65 5F
            70 61 72 73 65 72 }
            
        //email._parseaddr
        $e3 = { 65 6D 61 69 6C 2E 5F 70 61 72 73 65 61 64 64 72 }
        
        //email._policybase
        $e4 = { 65 6D 61 69 6C 2E 5F 70 6F 6C 69 63 79 62 61 73 65 }
        
        //email.base64mime
        $e5 = { 65 6D 61 69 6C 2E 62 61 73 65 36 34 6D 69 6D 65 }
        
        //email.charset
        $e6 = { 65 6D 61 69 6C 2E 63 68 61 72 73 65 74 }
        
        //email.contentmanager
        $e7 = { 65 6D 61 69 6C 2E 63 6F 6E 74 65 6E 74 6D 61 6E 61 67 65 72 }
        
        //email.contentmanager
        $e8 = { 65 6D 61 69 6C 2E 67 65 6E 65 72 61 74 6F 72 }       
   
    condition : 
        ( $header at 0 ) 
        and $loader 
        and 6 of ( $e* ) 
        and filesize < 3000KB
}
