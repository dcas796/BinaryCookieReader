# BinaryCookieReader

Cloned originally from http://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py
Forked from https://github.com/as0ler/BinaryCookieReader/

## Modifications

- Added support for Python 3.12.3
- Added support for the SameSite Lax & SameSite Strict flags
- Added functionality to create a `cookies.txt` file in the `Netscape Cookies.txt File Format`

## Usage

`
python3 BinaryCookieReader.py [path] [output_path]
`

where `[path]` is the path to the `.binarycookies` file (generally, Safari's `Cookies.binarycookies` file is stored in `~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies`)
and `[output_path]` is the path pointing to the destination of the `cookies.txt` file (more information about the `Netscape Cookies.txt File Format` at `http://justsolve.archiveteam.org/wiki/Netscape_cookies.txt`).

## Cookies.binarycookies Format

Cookies.binarycookies file is composed of several pages and each page can have one or more cookies. The complete file format is explained below:

### File Format:
1. The file starts with a 4 byte magic string: cook. It is used to identify the file type.
2. Next four bytes is an integer specifying the number of pages in the file.
3. Following that, a 4 byte integer for each page, represents the page size.
4. Next to that, the file contains the actual page content. Each page is of length corresponding to the page size. Page format is explained below.
5. The file ends with an 8 byte value and it might be file checksum.`



### Page Format:
1. Every page starts with a 4 byte page header: 0x00000100.
2. Next four bytes is an integer specifying the number of cookies in the page.
3. Following that, a 4 byte integer for each cookie, represents the cookie offset. Offset specifies the start of the cookie in bytes from the start of the page.
4. Next to that, the page contains the actual cookie contents. Each cookie is of variable length. Cookie format is explained below.
5. Page ends with a 4 byte value and it is always 0x00000000.

### Cookie Format:
1. First 4 bytes in the cookie is the size of the cookie.
2. The next 4 bytes are unknown (may be related to cookies flags).
3. The next four bytes are the cookie flags. This is an integer value (1=Secure, 4=HttpOnly, 5= Secure+HttpOnly).
4. The next 4 bytes are unknown.
5. The next 4 bytes is an integer specifying the start of the url field in bytes from the start of the cookie record.
6. The next 4 bytes is an integer specifying the start of the name field in bytes from the start of the cookie record.
7. The next 4 bytes is an integer specifying the start of the path field in bytes from the start of the cookie record.
8. The next 4 bytes is an integer specifying the start of the value field in bytes from the start of the cookie record.
9. The next 8 bytes represents the end of the cookie and it is always 0x0000000000000000.
10. The next 8 bytes are the cookie expiration date. Date is in Mac epoch format (Mac absolute time). Mac epoch format starts from Jan 2001.
11. The next 8 bytes are the cookie creation date.
12. Next to that, the cookie contains the actual cookie domain, name, path & value. The order is not specific and they can appear in any order.
