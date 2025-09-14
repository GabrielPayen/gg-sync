#!/bin/bash

cd "$(dirname "$0")"

# Check if the folder argument is supplied
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <local_folder> [--check]"
    exit 1
fi

# Assign the first argument to the local_folder variable
local_folder="$1"

# Shift to check for additional arguments like --check
shift

# Run the Python script with the local folder and any additional arguments (e.g., --check)
python3 upload_photos.py "$local_folder" "$@"
