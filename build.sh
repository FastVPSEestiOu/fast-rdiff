#!/bin/bash

# yum install glibc-static openssl-static
g++ fastrdiff.cpp -lssl -ofastrdiff
