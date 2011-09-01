#!/bin/bash

# ubuntu has an extremely not cool feature : you can't debug your own applications unless you change
# this /proc parameter...

echo 0 > /proc/sys/kernel/yama/ptrace_scope


