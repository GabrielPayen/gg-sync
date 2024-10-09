import os
import pickle
import hashlib
import requests
import logging
import json
from datetime import datetime
from PIL import Image
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build, build_from_document
import sys
import os
import logging
import json
import requests
import piexif
from io import BytesIO
from mutagen.mp4 import MP4
# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
error_log_path = 'upload.errors.log'
# Create a logger for errors
error_logger = logging.getLogger('error_logger')
error_handler = logging.FileHandler(error_log_path)
error_handler.setLevel(logging.ERROR)
error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
error_handler.setFormatter(error_formatter)
error_logger.addHandler(error_handler)

if os.path.exists(error_log_path):
    os.remove(error_log_path)

# Scopes for Google Photos API
SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly', 'https://www.googleapis.com/auth/photoslibrary.appendonly']
discovery_url = "https://photoslibrary.googleapis.com/$discovery/rest?version=v1"

# Authenticate and create Google Photos API service
def authenticate_photos():
    logging.info("Authenticating to Google Photos API...")
    creds = None
    if os.path.exists('token_photos.pickle'):
        with open('token_photos.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('secrets.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token_photos.pickle', 'wb') as token:
            pickle.dump(creds, token)
    logging.info("Successfully authenticated.")
    return build_from_document(requests.get(discovery_url).json(), credentials=creds)

# Compute hash of the local file to ensure uniqueness (based on file content)
def compute_file_hash(file_path):
    logging.info(f"Computing hash for file: {file_path}")
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Get all existing media items from Google Photos
def get_existing_photos(service):
    logging.info("Fetching metadata info from Google Photos...this can take some time...")
    media_items = []
    next_page_token = ''
    filename_hash_map = {}
    
    while True:
        response = service.mediaItems().list(pageSize=100, pageToken=next_page_token).execute()
        media_items.extend(response.get('mediaItems', []))
        next_page_token = response.get('nextPageToken', '')
        if not next_page_token:
            break
    
    for item in media_items:
        # Store filename with its hash in a dictionary
        filename = item['filename']
        base_url = item['baseUrl'] + "=d"  # Get full-resolution photo for hash comparison
        filename_hash_map[filename] = base_url
        
    logging.info(f"Fetched {len(filename_hash_map)} existing media items.")
    return filename_hash_map

def modify_mp4_creation_date(file_path, creation_date):
    try:
        video = MP4(file_path)
        video["©day"] = creation_date  # Set the creation date
        video.save()  # Save changes
        logging.info(f"EXIF metadata updated with creation date: {creation_date} for {os.path.basename(file_path)}")
    except Exception as e:
        msg = f"Failed to update EXIF metadata for {os.path.basename(file_path)}: {e}"
        logging.error(msg)
        raise(Exception(msg))


def modifiy_image_creation_date(image_data, file_path, creation_date):
    try:
        bytes_io = BytesIO(image_data)
        img = Image.open(bytes_io)  # Load image from memory

        if "exif" in img.info:
            exif_dict = piexif.load(img.info["exif"])
        else:
            exif_dict = {"Exif": {}}
        
        # Check if 'DateTimeOriginal' exists in the EXIF data
        if piexif.ExifIFD.DateTimeOriginal in exif_dict["Exif"]:
            logging.info(f"EXIF DateTimeOriginal already exists = {exif_dict['Exif'][piexif.ExifIFD.DateTimeOriginal]} for {os.path.basename(file_path)}. No modification needed.")
            return bytes_io
        else:
            # Insert the 'DateTimeOriginal' into EXIF if it doesn't exist
            exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = creation_date
            exif_bytes = piexif.dump(exif_dict)

            # Save the modified image with updated EXIF to memory
            output = BytesIO()
            img.save(output, format=img.format, exif=exif_bytes)
            logging.info(f"EXIF metadata updated with creation date: {creation_date} for {os.path.basename(file_path)}")
            return output.getvalue()  # Return the modified image data
    except Exception as e:
        msg = f"Failed to update EXIF metadata for {file_path}: {e}"
        logging.error(msg)
        raise(Exception(msg))


def get_file_modified_date(file_path):
    timestamp = os.path.getmtime(file_path)
    return datetime.fromtimestamp(timestamp).strftime('%Y:%m:%d %H:%M:%S')


# Upload file to Google Photos
def upload_file(service, file_path):
    file_name = os.path.basename(file_path)
    logging.info(f"Uploading file: {file_path} ...")
    
    # Get the file's creation date
    creation_date = get_file_modified_date(file_path)
    
    # Open file once and read it into memory
    with open(file_path, 'rb') as file:
        file_data = file.read()  # Read file content into memory

        # Check if the file is an image and modify EXIF metadata if needed
        if file_name.lower().endswith(('.jpg', '.jpeg', '.png')):
            modified_image_data = modifiy_image_creation_date(file_data, file_path, creation_date)
            modified_file_data = modified_image_data
        elif file_name.lower().endswith('.mp4'):
            modify_mp4_creation_date(file_path, creation_date)  # Modify MP4 creation date
            modified_file_data = file_data  # Keep original data for videos
        else:
            msg = f"Unsupported file type: {file_name}"
            logging.error(msg)
            raise(Exception(msg))

        # Create the upload request
        url = 'https://photoslibrary.googleapis.com/v1/uploads'
        headers = {
            'Authorization': f'Bearer {service._http.credentials.token}',
            'Content-type': 'application/octet-stream',
            'X-Goog-Upload-File-Name': file_name,
            'X-Goog-Upload-Protocol': 'raw'
        }
        response = requests.post(url, headers=headers, data=modified_file_data)

    if response.status_code == 200:
        upload_token = response.content.decode('utf-8')
        
        # Create new media item
        new_media_item = {
            'newMediaItems': [
                {
                    'description': file_path,
                    'simpleMediaItem': {
                        'uploadToken': upload_token
                    }
                }
            ]
        }

        # Add the new media item to Google Photos
        upload_response = service.mediaItems().batchCreate(body=new_media_item).execute()
        logging.info(f"Successfully uploaded {file_name}.")
        return upload_response
    else:
        msg = f"Failed to upload {file_name} : {response.text}"
        logging.error(msg)
        raise(Exception(msg))


##FIXME : hash comparison is not working. Only check filename for now
# Compare local file with the photos in Google Photos based on filename and hash# Compare local file with the photos in Google Photos based on filename and hash
def raise_on_duplicate(filename_hash_map, local_file_path):
    local_file_name = os.path.basename(local_file_path)
    logging.info(f"Checking if photo exists for {local_file_path}...")

    if local_file_name in filename_hash_map:

    # Compute the hash for the local file
    #     local_file_hash = compute_file_hash(local_file_path)  # Calculate the hash for local file

    #     # If filename matches, check the hash to ensure it's the same file
    #     existing_photo_url = filename_hash_map[local_file_name]
    #     existing_photo = requests.get(existing_photo_url)

    #     if existing_photo.status_code == 200:
    #         existing_hash = hashlib.md5(existing_photo.content).hexdigest()
    #         if local_file_hash == existing_hash:  # Compare local hash with the existing hash
    #             logging.info(f"Photo already exists: {local_file_path}.")
    #             return True  # Photo already exists
    # else:
        raise(Exception(f"Found duplicate for: {local_file_name}"))
    logging.info(f"No duplicate found for {local_file_path}.")
    return False

##FIXME : do something for videos
# Upload all valid files (images/videos) from a folder to Google Photos
def upload_folder_to_google_photos(service, folder_path, photo_hashes):
    supported_formats = ['jpg', 'jpeg', 'png']
    
    logging.info(f"Uploading files from folder: {folder_path}...")
    print("\n")
    # Use os.walk to traverse directories recursively
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            if file_name.split('.')[-1].lower() in supported_formats:
                file_path = os.path.join(root, file_name)
                try :
                    if photo_hashes:
                        raise_on_duplicate(photo_hashes, file_path)
                    upload_file(service, file_path)
                except Exception as e:
                    msg = f"Failed to upload {file_name}. Error: {e}"
                    logging.error(msg)
                    error_logger.error(json.dumps({'file': file_name, 'reason': msg}))

                print("\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python upload_to_google_photos.py <local_folder>")
        sys.exit(1)

    local_folder = sys.argv[1]

    service = authenticate_photos()
    
    existing_photo_hashes = get_existing_photos(service)
    
    upload_folder_to_google_photos(service, local_folder, existing_photo_hashes)