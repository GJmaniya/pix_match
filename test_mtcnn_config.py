import cv2
import os
from facenet_pytorch import MTCNN
import torch

# Test with different MTCNN settings
test_image = '/home/gaurav/pix_match/Bhuman/CR3_4582.JPG'

print(f"Testing various MTCNN configurations...")

device = 'cpu'

# Try more lenient settings
configs = [
    {"min_face_size": 40, "thresholds": [0.6, 0.7, 0.7], "name": "Lenient (min_face=40)"},
    {"min_face_size": 20, "thresholds": [0.5, 0.6, 0.6], "name": "Very Lenient (min_face=20)"},
    {"min_face_size": 90, "thresholds": [0.6, 0.7, 0.8], "name": "Original (min_face=90)"},
]

image = cv2.imread(test_image)
if image is None:
    print("Failed to load image")
    exit()

rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

for config in configs:
    print(f"\nTrying: {config['name']}")
    mtcnn = MTCNN(
        keep_all=True, 
        device=device, 
        min_face_size=config['min_face_size'], 
        thresholds=config['thresholds'],
        post_process=True
    )
    
    faces = mtcnn(rgb)
    
    if faces is None or len(faces) == 0:
        print(f"  ❌ No faces detected")
    else:
        print(f"  ✅ Detected {len(faces)} face(s)")
        print(f"  Face tensor shape: {faces.shape}")