# WineMateInternalTool
For Tagtalk internal use only

[CAUTION] Tag Info cannot be changed once tag is written!

Usage:

1. Enter a valid wine ID (currently 1 ~ 4);
2. Click "Done";
3. Screen runtime log should show "Ready to write tags...";
4. Place cell phone close to an empty NFC tag to write and encrypt the tag;
5. Screen runtime log should indicate tag is written successfully and tagInfo is uploaded successfully. Error message will show up if writting or uploading fail;
6. Double check 'tag_info' table on AWS to make sure tagInfo is uploaded successfully to database; 
7. Click "Reset" to reset wine ID;
8. Click "Clear Log" to clear screen runtime log;
9. "Verify" function is to be added. 
