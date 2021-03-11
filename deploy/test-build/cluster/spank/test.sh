#!/bin/bash

# TODO: this test fails if root is group owner of some other ownership variations, a more sophisticated check that looks at folder contents should be implemented

# with enabled $HOME the home directory is owned by the user
ENABLED_HOME=$(sshpass -p test11 ssh test1@127.0.0.1 -p 2223 srun stat -c %G /home/test1)
echo $ENABLED_HOME
if [[ $ENABLED_HOME = "test1" ]]
then
    echo PASS
else
    echo FAILED
fi

# with disabled $HOME, the home directory is now group owned by root 
DISABLED_HOME=$(sshpass -p test11 ssh test1@127.0.0.1 -p 2223 srun --nohome stat -c %G /home/test1)

if [[ $DISABLED_HOME = "root" ]]
then
    echo PASS
else
    echo FAILED
fi


