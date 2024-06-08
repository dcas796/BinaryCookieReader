#*******************************************************************************#
# BinaryCookieReader: Written By Satishb3 (http://www.securitylearn.net).       #
#                     Edited by dcas796 (https://dcas796.github.io)             #
#                                                                               #
# For any bug fixes contact me: satishb3@securitylearn.net                      #
#                                                                               #
# Usage: python3 BinaryCookieReader.py [path] [output_path]                     #
#                                                                               #
# Safari browser and iOS applications store the persistent cookies in a binary  #
# file names Cookies.binarycookies.BinaryCookieReader is used to dump all the   #
# cookies from the binary Cookies.binarycookies file.                           #
#                                                                               #
#*******************************************************************************#

FLAGS_MASK_SECURE           = 0b00000001
FLAGS_MASK_HTTP_ONLY        = 0b00000100
FLAGS_MASK_SAMESITE         = 0b00001000
FLAGS_MASK_SAMESITE_STRICT  = 0b00010000

import sys
from struct import unpack
from io import BytesIO
from time import strftime, gmtime
from typing import Any

if len(sys.argv) != 3:
    print("Extract cookie data from Safari .binarycookies file format into a Netscape cookies.txt file format.")
    print("Usage: python3 BinaryCookieReader.py [path] [output_path]")
    print("Example: python3 BinaryCookieReader.py ~/cookies.binarycookies ~/cookies.txt")
    sys.exit(1)

FilePath = sys.argv[1]
output_file = sys.argv[2]

try:
    binary_file = open(FilePath, 'rb')
except IOError as e:
    print('File Not Found :' + FilePath)
    sys.exit(1)

file_header = binary_file.read(4)  # File Magic String:cook

try:
    output_file = open(output_file, "w+")
    output_file.write("# HTTP Cookie File\n")
except IOError as e:
    print(f"Cannot create file: {output_file}")
    sys.exit(1)

if file_header != b'cook':
    print(f"Not a .binarycookie file: {FilePath}")
    sys.exit(1)

# Number of pages in the binary file: 4 bytes
num_pages = unpack('>i', binary_file.read(4))[0]

page_sizes = []
for np in range(num_pages):
    # Each page size: 4 bytes*number of pages
    page_sizes.append(unpack('>i', binary_file.read(4))[0])

pages = []
for ps in page_sizes:
    # Grab individual pages and each page will contain >= one cookie
    pages.append(binary_file.read(ps))


print("#*************************************************************************#")
print("# BinaryCookieReader: developed by Satishb3: http://www.securitylearn.net #")
print("#*************************************************************************#")

for page in pages:
    # Converts the string to a file. So that we can use read/write operations easily.
    page = BytesIO(page)
    page.read(4)  # page header: 4 bytes: Always 00000100
    # Number of cookies in each page, first 4 bytes after the page header in every page.
    num_cookies = unpack('<i', page.read(4))[0]

    cookie_offsets = []
    for nc in range(num_cookies):
        # Every page contains >= one cookie. Fetch cookie starting point from page starting byte
        cookie_offsets.append(unpack('<i', page.read(4))[0])

    page.read(4)  # end of page header: Always 00000000

    cookie = ''
    for offset in cookie_offsets:
        page.seek(offset)  # Move the page pointer to the cookie starting point
        cookiesize = unpack('<i', page.read(4))[0]  # fetch cookie size
        cookie = BytesIO(page.read(cookiesize))  # read the complete cookie

        cookie.read(4)  # unknown

        # Cookie flags:  1=secure, 4=httponly, 5=secure+httponly
        flags = unpack('<i', cookie.read(4))[0]
        # print(hex(flags))
        cookie_flags: list[str] = []

        if flags & FLAGS_MASK_SECURE > 0:
            cookie_flags.append("secure")

        if flags & FLAGS_MASK_HTTP_ONLY > 0:
            cookie_flags.append("http_only")

        if flags & FLAGS_MASK_SAMESITE > 0:
            cookie_flags.append("samesite")

        if flags & FLAGS_MASK_SAMESITE_STRICT > 0:
            cookie_flags.append("samesite_strict")

        cookie.read(4)  # unknown

        # cookie domain offset from cookie starting point
        urloffset = unpack('<i', cookie.read(4))[0]

        # cookie name offset from cookie starting point
        nameoffset = unpack('<i', cookie.read(4))[0]

        # cookie path offset from cookie starting point
        pathoffset = unpack('<i', cookie.read(4))[0]

        # cookie value offset from cookie starting point
        valueoffset = unpack('<i', cookie.read(4))[0]

        endofcookie = cookie.read(8)  # end of cookie

        # Expiry date is in Mac epoch format: Starts from 1/Jan/2001
        expiry_date_epoch = unpack('<d', cookie.read(8))[0]+978307200

        # 978307200 is unix epoch of  1/Jan/2001 //[:-1] strips the last space
        expiry_date = strftime("%a, %d %b %Y ", gmtime(expiry_date_epoch))[:-1]

        # Cookies creation time
        create_date_epoch = unpack('<d', cookie.read(8))[0]+978307200
        create_date = strftime("%a, %d %b %Y ", gmtime(create_date_epoch))[:-1]
        # print create_date

        cookie.seek(urloffset-4)  # fetch domain value from url offset
        url = ''
        u = cookie.read(1)
        while unpack('<b', u)[0] != 0:
            url = url+u.decode("utf-8")
            u = cookie.read(1)

        cookie.seek(nameoffset-4)  # fetch cookie name from name offset
        name = ''
        n = cookie.read(1)
        while unpack('<b', n)[0] != 0:
            name = name+n.decode("utf-8")
            n = cookie.read(1)

        cookie.seek(pathoffset-4)  # fetch cookie path from path offset
        path = ''
        pa = cookie.read(1)
        while unpack('<b', pa)[0] != 0:
            path = path+pa.decode("utf-8")
            pa = cookie.read(1)

        cookie.seek(valueoffset-4)  # fetch cookie value from value offset
        value = ''
        va = cookie.read(1)
        while unpack('<b', va)[0] != 0:
            value = value+va.decode("utf-8")
            va = cookie.read(1)

        # print('Cookie : ' + name + '=' + value + '; domain='+url+'; path=' +
        #     path+'; ' + 'expires=' + expiry_date + '; ' + str(cookie_flags))

        include_subdomains = "TRUE" if cookie_flags.count("samesite") > 0 else "FALSE"
        is_secure = "TRUE" if cookie_flags.count("secure") > 0 else "FALSE"
        output_file.write(f"{url}\t{include_subdomains}\t{path}\t{is_secure}\t{int(expiry_date_epoch)}\t{name}\t{value}\n")

binary_file.close()
output_file.close()
