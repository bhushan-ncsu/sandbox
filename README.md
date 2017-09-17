# sandbox
This repository contains project of building a controlled environment (sandbox) using ptrace kernel API.
ptrace system call is used to observe and control the execution of child process by parent process.
Whenever a child process tries to make any system call the parent process can check the parameters like, the file being accessed, the mode in which the child process is trying to access the file etc. and by accessing these parameters the parent process can decide whether to let the child process to execute or not.

This is thus a controlled environment (sandbox) in which the parent process checks child process permissions in "config.txt" file and thus verifies and decides if the child process be allowed to execute the call.

The controlled environment can be used for testing of new softwares and check to see if it is maliciously trying to access any non-permitted files.
