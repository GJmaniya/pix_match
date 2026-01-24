import cv2
from matcher import FaceMatcher

# Test face detection directly
test_image = '/home/gaurav/pix_match/Bhuman/CR3_4582.JPG'

print(f"Testing face detection on: {test_image}")

# Initialize matcher
matcher = FaceMatcher(device_choice='cpu')

# Try to extract embeddings
embeddings, img = matcher.extract_embeddings(test_image)

if embeddings is None:
    print("❌ No embeddings extracted - face detection failed")
    print(f"Image object: {img is not None}")
    if img is not None:
        print(f"Image shape: {img.shape}")
else:
    print(f"✅ Embeddings extracted successfully!")
    print(f"Embeddings shape: {embeddings.shape}")
    print(f"Number of faces detected: {len(embeddings)}")
