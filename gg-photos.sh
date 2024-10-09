#!/bin/bash

cd "$(dirname "$0")"

# Check if the folder argument is supplied
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <local_folder>"
    exit 1
fi

# Assign the first argument to the local_folder variable
local_folder="$1"

# Run the Python script with the local folder as an argument
python3 upload_photos.py "$local_folder"

