#!/bin/bash

for users in games gnats irc list news sync uucp; do
userdel -r "$users" 2> /dev/null
done