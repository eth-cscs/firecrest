Generate SSH CA keys:

ssh-keygen -t rsa -b 4096 -P "" -f ca-key -C "CA Authority-test"

Generate user ssh keys:

ssh-keygen -t rsa -b 2048 -P "" -f user-key


