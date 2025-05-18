import 
    os

# Boolean to check the size of a file 
proc fileSize * (min_size : int, max_size : int, filename : string) : bool = 
    if os.getFileSize(filename) > min_size and os.getFileSize(filename) < max_size :
        return true
    false