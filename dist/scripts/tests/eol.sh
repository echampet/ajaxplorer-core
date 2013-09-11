#!/bin/bash

echo -e "\e[1;34mChecking files eol (LF)\e[00m"
find . -type f -exec file "{}" ";" | grep CRLF
rc=$?
if [[ $rc == 0 ]]
then
    echo -e '\e[00;31mPlease check files eol\e[00m'
    exit 1
else
    echo -e "\e[1;32mFiles eol are OK\e[00m"
fi
