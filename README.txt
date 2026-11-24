FILES SUBMITTED:
- This one
- design.txt: describes program design, how the program works, and
  considerations made
- sender.py: sends packets to and receive ACKs from receiver.py
- receiver.py: sends ACKs to and receive data from sender.py
- read: sample text file (with more bytes than window size)
- jae-half-profile.jpg: a large binary file of Jae

COMMANDS:
newudpl -i localhost -o localhost -O 15
python3 receiver.py write 41191 localhost 31191
python3 sender.py jae-half-profile.jpg localhost 41191 5760 31191 1 2

REMARKS:
- The JPG of Jae is ~400K bytes.
- The window size of 5760 may be changed to any multiple of 576 to make our
  lives all easier.
- Values "-O 15" were chosen to make the screen dump
  occur within a reasonable window of time given the last two parameters of
  sender.py and the size of the image file. Other possible values include "-L 5 -O 10", etc.
- The last two parameters of sender.py are:
  * First: starting timeout value
  * Second: Factor to multiply timeout value by when timeout is reached
  The purpose of supplying these two parameters is to allow for testing of
  the programs within a reasonable window of time.
- In sum, the values for -L, -O, -B, starting timeout value, and
  multiplication factor can be adjusted as wished, provided one has enough
  time to wait.
- Currently, the RTT measure increases drastically after measuring RTT on
  packets after one full window. In particular, unreliability of packets in
  a window push up measured RTT. This is most significant in the case of
  lost packets, which won't be retransmitted unless timeout occurs.

FEATURES:
Beyond the requirements of the assignment:
 * Checks for integrity of ACKs.
 * Will be able to transmit any binary data.
 * Implements buffering at receiver.

BUGS:
- None to report as of writing.

NOTES FOR TESTING:
- These tests were ran on a 2019 edition of the Apple MacBook Pro. It would
  be best to rerun the commands above on an Apple computer from plus or
  minus a few years.
- NEWUDPL will require a Linux-based system.
