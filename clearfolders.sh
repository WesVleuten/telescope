#!/bin/bash

# Script that clears out any telescope outputs in the current direcoty
# Mainly for testing purposes

sudo find . -type d -name "telescope*" -exec rm -rf {} \; 2> /dev/null
