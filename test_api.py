import requests
import os

# Define URL
url = 'http://localhost:5000/api/match_photos'

# Path to a test image (User Selfie)
# valid image from Bhuman to test self-match
test_image_path = '/home/gaurav/pix_match/Bhuman/CR3_4582.JPG' 

if not os.path.exists(test_image_path):
    print(f"Test image not found at {test_image_path}")
    exit(1)

# Send POST request
files = {'photo': open(test_image_path, 'rb')}
try:
    print(f"Sending request to {url} with {test_image_path}...")
    response = requests.post(url, files=files)
    
    print(f"Status Code: {response.status_code}")
    print("Response JSON:", response.json())
    
    if response.status_code == 200:
        print("API Test Passed!")
    else:
        print("API Test Failed!")
except requests.exceptions.ConnectionError:
    print("Could not connect to the server. Is Flask running?")
except Exception as e:
    print(f"An error occurred: {e}")
