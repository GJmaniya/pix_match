"""Quick check that the face models load with the installed library versions.

Run after changing dependencies:  python smoke_test_models.py
"""
import numpy as np
from PIL import Image

from matcher import FaceMatcher

matcher = FaceMatcher(device_choice='cpu')

# A blank image has no face: the pipeline must run end-to-end and report "no face".
blank = Image.fromarray(np.full((320, 320, 3), 200, dtype=np.uint8))
blank.save('/tmp/_smoke_blank.jpg')
embeddings, _ = matcher.extract_embeddings('/tmp/_smoke_blank.jpg')
assert embeddings is None, 'unexpected face found in a blank image'
# Face-index library used for matching
import faiss
index = faiss.IndexFlatL2(512)
vectors = np.random.rand(5, 512).astype('float32')
index.add(vectors)
distances, ids = index.search(vectors[:1], 1)
assert int(ids[0][0]) == 0 and float(distances[0][0]) < 1e-3

print('MODEL SMOKE TEST OK')
