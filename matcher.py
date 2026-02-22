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

    def preprocess_image(self, image, max_size=640):
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
        Loads embeddings from cache if available, updating it for new/deleted files.
        Returns a dictionary mapping filename -> embeddings (numpy array).
        """
        # Get all image files recursively
        current_files = set()
        for root, _, files in os.walk(search_dir):
            for file in files:
                if file.lower().endswith(('.jpg', '.jpeg', '.png')):
                    # Use relative path from search_dir
                    rel_dir = os.path.relpath(root, search_dir)
                    if rel_dir == '.':
                        rel_path = file
                    else:
                        rel_path = os.path.join(rel_dir, file)
                    current_files.add(rel_path)
        
        file_embeddings = {}
        cache_needs_update = False
        
        if os.path.exists(cache_path):
            logging.info(f"Loading embeddings from cache: {cache_path}")
            try:
                file_embeddings = torch.load(cache_path, weights_only=False)
            except Exception as e:
                logging.error(f"Error loading cache: {e}. Starting fresh...")
                file_embeddings = {}

        # Identify changes
        cached_files = set(file_embeddings.keys())
        new_files = current_files - cached_files
        deleted_files = cached_files - current_files
        
        # Remove deleted files from cache
        if deleted_files:
            logging.info(f"Removing {len(deleted_files)} deleted files from cache...")
            for f in deleted_files:
                del file_embeddings[f]
            cache_needs_update = True
            
        # Compute embeddings for new files
        if new_files:
            logging.info(f"Computing embeddings for {len(new_files)} new files...")
            new_file_paths = [os.path.join(search_dir, f) for f in new_files]
            
            # Parallel extraction for new files
            with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
                futures = [executor.submit(self.extract_embedding_for_file, img_path) for img_path in new_file_paths]
                
                for i, future in enumerate(as_completed(futures)):
                    if i % 10 == 0:
                        logging.info(f"Processed {i}/{len(new_files)} new images...")
                    
                    path, emb = future.result()
                    if emb is not None:
                        file_embeddings[os.path.basename(path)] = emb
            
            cache_needs_update = True
        
        # Save cache if updated
        if cache_needs_update:
            logging.info(f"Updating cache with {len(file_embeddings)} total entries: {cache_path}")
            torch.save(file_embeddings, cache_path)
            
        return file_embeddings

    def find_matches(self, user_photo_path, search_dir, output_dir, tolerance=0.50):
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
        # Using IndexFlatL2 to avoid clustering warnings
        d = user_embeddings.shape[1]
        index = faiss.IndexFlatL2(d)
        index.add(user_embeddings.astype(np.float32))

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
                
                # Copy matched file to output directory, preserving structure if needed
                # For simplicity, we'll flatten the structure in the output directory 
                # OR we can keep it. Let's keep it to avoid name collisions.
                src_path = os.path.join(search_dir, filename)
                dst_path = os.path.join(output_dir, filename)
                
                # Create parent directory if it doesn't exist
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                
                try:
                    shutil.copy2(src_path, dst_path)
                except Exception as e:
                    logging.error(f"Error copying {filename}: {e}")

        total_time = time.time() - start_time
        logging.info(f"Completed. Found {match_count} matches in {total_time:.2f}s")
        
        return {
            "status": "success", 
            "matches_found": match_count, 
            "matched_files": matched_files,
            "time_taken": total_time,
            "output_directory": output_dir
        }