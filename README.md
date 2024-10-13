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

## 1. Check for Google photos already upload from local folder

Assumes that their description is the local path source (see 3.)

## 2. Tweak Efix metadata if needed to assign creation date so that Gooogle Photos can sort by date

## 3. Upload and log error

Also assign the local path source as the description :
- Allows to quickly check if photo has already been uploaded
- Could be useful for disaster-recovery to rebuild local folder structure from Photos

## TODO

Add `requirements.txt`


Author : gabriel.payen.gp@gmail.com