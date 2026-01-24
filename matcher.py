import os
import logging
import time
import cv2
import torch
import numpy as np
import faiss
import shutil
from facenet_pytorch import MTCNN, InceptionResnetV1
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

class FaceMatcher:
    def __init__(self, device_choice='cpu'):
        self.device = 'cuda' if device_choice == 'gpu' and torch.cuda.is_available() else 'cpu'
        print(f"Using device: {self.device}")
        
        # Initialize MTCNN and InceptionResnetV1
        # Using more lenient parameters for better face detection
        self.mtcnn = MTCNN(keep_all=True, device=self.device, min_face_size=40, thresholds=[0.6, 0.7, 0.7], post_process=True)
        self.inception_model = InceptionResnetV1(pretrained='vggface2').eval().to(self.device)

    def preprocess_image(self, image, max_size=320):
        # Resize image to reduce computation while maintaining aspect ratio
        h, w = image.shape[:2]
        scale = max_size / max(h, w)
        if scale < 1:
            image = cv2.resize(image, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
        rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        return rgb, image

    def extract_embeddings(self, image_path):
        try:
            image = cv2.imread(image_path)
            if image is None: 
                return None, None
            rgb_image, original_image = self.preprocess_image(image)
            faces = self.mtcnn(rgb_image)
            if faces is None or len(faces) == 0: 
                return None, original_image

            # Batch process all faces in the image
            with torch.no_grad():
                embeddings = self.inception_model(faces.to(self.device))
                embeddings = torch.nn.functional.normalize(embeddings, p=2, dim=1)
            return embeddings.cpu().numpy(), original_image
        except Exception as e:
            logging.error(f"Error processing {image_path}: {e}")
            return None, None

    def extract_embedding_for_file(self, image_path):
        """Helper to extract embedding for a single file, used for parallel processing."""
        embeddings, _ = self.extract_embeddings(image_path)
        return image_path, embeddings

    def load_or_compute_directory_embeddings(self, search_dir, cache_path):
        """
        Loads embeddings from cache if available, otherwise computes and saves them.
        Returns a dictionary mapping filename -> embeddings (numpy array).
        """
        if os.path.exists(cache_path):
            logging.info(f"Loading embeddings from cache: {cache_path}")
            try:
                return torch.load(cache_path)
            except Exception as e:
                logging.error(f"Error loading cache: {e}. Recomputing...")
        
        logging.info(f"Computing embeddings for images in {search_dir}...")
        img_files = [
            os.path.join(search_dir, f) 
            for f in os.listdir(search_dir) 
            if f.lower().endswith(('.jpg', '.jpeg', '.png'))
        ]
        
        file_embeddings = {}
        
        # Parallel extraction
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = [executor.submit(self.extract_embedding_for_file, img_path) for img_path in img_files]
            
            for i, future in enumerate(as_completed(futures)):
                if i % 10 == 0:
                    logging.info(f"Processed {i}/{len(img_files)} images...")
                
                path, emb = future.result()
                if emb is not None:
                    file_embeddings[os.path.basename(path)] = emb
        
        # Save cache
        logging.info(f"Saving embeddings to cache: {cache_path}")
        torch.save(file_embeddings, cache_path)
        return file_embeddings

    def find_matches(self, user_photo_path, search_dir, output_dir, tolerance=0.5):
        """
        Main method to find matches using cached embeddings.
        """
        start_time = time.time()
        
        # 1. Get User Embedding
        logging.info(f"Processing reference photo: {user_photo_path}")
        user_embeddings, _ = self.extract_embeddings(user_photo_path)
        
        if user_embeddings is None:
            logging.error("Could not detect face in user photo.")
            return {"status": "error", "message": "No face detected in uploaded photo."}
            
        # 2. Load or Compute Search Embeddings
        cache_path = os.path.join(search_dir, "embeddings_cache.pt")
        search_embeddings_map = self.load_or_compute_directory_embeddings(search_dir, cache_path)
        
        if not search_embeddings_map:
             return {"status": "error", "message": "No faces found in search directory."}

        # 3. Create FAISS Index for User
        d = user_embeddings.shape[1]
        quantizer = faiss.IndexFlatL2(d)
        index = faiss.IndexIVFFlat(quantizer, d, 1, faiss.METRIC_L2)
        index.train(user_embeddings)
        index.add(user_embeddings)

        logging.info(f"Searching against {len(search_embeddings_map)} images...")
        
        match_count = 0
        matched_files = []
        os.makedirs(output_dir, exist_ok=True)
        
        # 4. Search
        # Compare user against all database images
        for filename, db_embeddings in search_embeddings_map.items():
            # db_embeddings might have multiple faces, check all of them
            if db_embeddings is None or len(db_embeddings) == 0:
                continue
                
            # Search for the closest match for each face in the DB image against the User Code
            # Note: We are doing inverse search here effectively.
            # We check if any face in the DB image is close to the User Face.
            dists, idxs = index.search(db_embeddings.astype(np.float32), 1)
            
            matched = False
            for dist in dists:
                if dist[0] < tolerance:
                    matched = True
                    break
            
            if matched:
                match_count += 1
                matched_files.append(filename)
                
                # COPYING SKIP: We now serve directly from source to save time!
                # file copying logic removed for performance
                pass

        total_time = time.time() - start_time
        logging.info(f"Completed. Found {match_count} matches in {total_time:.2f}s")
        
        return {
            "status": "success", 
            "matches_found": match_count, 
            "matched_files": matched_files,
            "time_taken": total_time,
            "output_directory": output_dir
        }
