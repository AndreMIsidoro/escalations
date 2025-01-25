# files

## Analise the file

### Use file command

    file <file_name>

### Use strings command

    strings <file_name>


### Use stat

    stat <file_name>

    If the modify date is different, this means the file was a static file on the webserver. If it is the same then it was a stream of bytes that were group as a file by the client

### Use exiftool

    exiftool <file_name>

    This gives a lot of information about the file, possibly including usernames