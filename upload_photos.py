import os
from pathlib import Path
import pickle
import hashlib
import time
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
script_dir = os.path.dirname(os.path.abspath(__file__))
error_log_path = os.path.join(script_dir, 'upload.errors.log')
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
    logging.info("Fetching already uploaded files from local to Google Photos...this can take some time...")
    next_page_token = ''
    descriptions = []
    while True:
        response = service.mediaItems().list(pageSize=100, pageToken=next_page_token).execute()
        media_items = response.get('mediaItems', [])
        next_page_token = response.get('nextPageToken', '')
        for item in media_items:
            descriptions_batch = item.get('description', '')
            if descriptions_batch != '':
                descriptions.append(descriptions_batch)
        if not next_page_token:
            break
    
    descriptions = list(filter(lambda x: x != '', descriptions))
        
    logging.info(f"Fetched {len(descriptions)} existing media items uploaded from local (based on their description)")
    return descriptions

def modifiy_image_creation_date(image_data, date):
    try:
        bytes_io = BytesIO(image_data)
        img = Image.open(bytes_io)  # Load image from memory

        if "exif" in img.info:
            exif_dict = piexif.load(img.info["exif"])
        else:
            exif_dict = {"Exif": {}}
        
        # Check if 'DateTimeOriginal' exists in the EXIF data
        if piexif.ExifIFD.DateTimeOriginal in exif_dict["Exif"]: 
            logging.info(f"EXIF DateTimeOriginal already exists = {exif_dict['Exif'][piexif.ExifIFD.DateTimeOriginal]}. No modification needed.")
            return image_data
        else:
            # Insert the 'DateTimeOriginal' into EXIF if it doesn't exist
            exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = date
            exif_dict["Exif"][41729] = ''.encode('utf8') # somehow 41729 is buggy
            exif_bytes = piexif.dump(exif_dict)
    

            # Save the modified image with updated EXIF to memory
            output = BytesIO()
            img.save(output, format=img.format, exif=exif_bytes)
            logging.info(f"EXIF metadata updated with creation date: {date}")
            return output.getvalue()  # Return the modified image data
    except Exception as e:
        msg = f"Failed to update EXIF metadata: {e}"
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
            file_data = modifiy_image_creation_date(file_data, creation_date)
        elif file_name.lower().endswith('.mp4'):
            #FIXME find a way for mp4 file to fix date if not existing : ffmpeg ?
            file_data = file_data  # Keep original data for videos
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

        # Retry logic
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                logging.info(f"Attempt {attempt + 1} to upload {file_name}...")
                response = requests.pot(url, headers=headers, data=file_data)

                assert response.status_code == 200, f"Upload failed with status code: {response.status_code}"
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
                assert upload_response['newMediaItemResults'][0]['status']['message'] == 'Success', f"Failed to upload {file_name} : {upload_response['newMediaItemResults'][0]['status']['message']}"
                logging.info(f"Successfully uploaded {file_name}.")
                return  # Exit the function after a successful upload
            except Exception as e:
                msg = f"Failed to upload {file_name} : {e}"
                logging.error(msg)
                # Wait before retrying if not the last attempt
                if attempt < max_retries:
                    logging.info(f"Retrying in 60 seconds...") ### => beware api quota limit, should limit to 120 per min
                    time.sleep(60)  # Wait for 60 seconds before retrying
                else:
                    raise Exception(f"Upload failed after {max_retries + 1} attempts for {file_name}.")


##TODO : Only check filename for now assuming that already uploaded photos got uploaded with their source filepath as description
## Could be improved to be more generic, but 
def is_already_uploaded(existing_photos_desc, local_file_path):
    return local_file_path in existing_photos_desc

##FIXME : do something for videos
# Upload all valid files (images/videos) from a folder to Google Photos
def upload_folder_to_google_photos(service, folder_path, existing_photos_desc):
    supported_formats = ['jpg', 'jpeg', 'png']
    
    logging.info(f"Uploading files from folder: {folder_path}...")
    print("\n")
    # Use os.walk to traverse directories recursively
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            if file_name.split('.')[-1].lower() in supported_formats:
                file_path = os.path.join(root, file_name)
                try :
                    if is_already_uploaded(existing_photos_desc, file_path):
                        logging.warning(f"{file_path} already uploaded to Google Photos, skipping")
                    else :
                        print("\n")
                        upload_file(service, file_path)
                        print("\n")
                except Exception as e:
                    msg = f"Failed to upload {file_name}. Error: {e}"
                    logging.error(msg)
                    error_logger.error(json.dumps({'file': file_name, 'reason': msg}))

              

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Usage: python upload_to_google_photos.py <local_folder>")
        sys.exit(1)

    local_folder = os.path.expanduser(sys.argv[1])
    if not os.path.exists(local_folder):
        print(f"Error: Local folder '{local_folder}' does not exist") # white space issues when ran from cmd ?
        sys.exit(1)

    LOCAL_PATTERN = os.path.join(*Path(os.path.abspath(local_folder)).parts[:3])

    service = authenticate_photos()
    
    existing_photos_desc = get_existing_photos(service)
    # existing_photos_desc = []
    upload_folder_to_google_photos(service, local_folder, existing_photos_desc)