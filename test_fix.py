import os
from matcher import FaceMatcher

TEST_IMAGE = "/home/gaurav/pix_match/gaurav/gaurav/d18d01a5-6def-443e-a099-895f57f51223.jpeg"
SEARCH_DIR = "/home/gaurav/pix_match/Bhuman"
OUTPUT_DIR = "/home/gaurav/pix_match/matchphotos_test"

matcher = FaceMatcher(device_choice='cpu')
result = matcher.find_matches(TEST_IMAGE, SEARCH_DIR, OUTPUT_DIR, tolerance=0.65)

print(f"\nResult: {result['status']}")
print(f"Matches found: {result['matches_found']}")
if result['matches_found'] > 0:
    print(f"Sample matches: {result['matched_files'][:10]}")
