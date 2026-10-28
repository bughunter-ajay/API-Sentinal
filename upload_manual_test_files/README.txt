API Sentinel — File Upload manual test pack
Profile: generic
Files: 158

How to use:
1. Open MANIFEST.csv — column send_as = exact filename to use in multipart.
2. disk_file = the file on disk (safe name if send_as has ../ or %00).
3. Upload with Content-Type from content_type column.
4. For path-traversal / null-byte rows, rename or set filename= to send_as
   in Burp/Postman (disk name is only for storage).
