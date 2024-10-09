# Script to batch upload photos from local storage to Google Photos

Google Photos web interface does not provide a way to recursively upload photos from a nested local folder.
Google client does not exist for Linux, and alternative only provide paid plans

## Usage

Get your Google secrets from Admin Console in `secrets.json`

```bash
chmod +x upload_photos.py
chmod +x gg-photos.sh
./gg-photo.sh <photos-folder>
```
## 1. Check for duplicate

## 2. Tweak Efix metadata if needed to assign creation date so that Gooogle Photos can sort by date

## 3. Upload and log error

## TODO

Add `requirements.txt`

Author : gabriel.payen.gp@gmail.com