import os
import logging
from facenet_pytorch import MTCNN, InceptionResnetV1
import torch
import cv2
import faiss
import numpy as np
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial

logging.basicConfig(level=logging.INFO, format='%(message)s')

image_folder = input("Enter the directory of images to process: ").strip()
known_faces_dir = input("Enter the directory for known faces: ").strip()
processed_images_dir = input("Enter the directory for storing recognized faces: ").strip()

os.makedirs(processed_images_dir, exist_ok=True)

device_choice = input("Do you want to use GPU or CPU? (Enter 'gpu' for GPU or 'cpu' for CPU): ").strip().lower()
while device_choice not in ['gpu', 'cpu']:
    device_choice = input("Invalid choice. Please enter 'gpu' or 'cpu': ").strip().lower()
device = 'cuda' if device_choice == 'gpu' and torch.cuda.is_available() else 'cpu'

# Optimized MTCNN with stricter thresholds and larger min_face_size
mtcnn = MTCNN(keep_all=True, device=device, min_face_size=60, thresholds=[0.6, 0.7, 0.8], post_process=True)
inception_model = InceptionResnetV1(pretrained='vggface2').eval().to(device)

def preprocess_image(image, max_size=640):
    # Resize image to reduce computation while maintaining aspect ratio
    h, w = image.shape[:2]
    scale = max_size / max(h, w)
    if scale < 1:
        image = cv2.resize(image, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    return rgb, image

def load_known_faces():
    all_embeddings = []
    all_names = []

    for person_name in os.listdir(known_faces_dir):
        person_folder = os.path.join(known_faces_dir, person_name)
        if not os.path.isdir(person_folder): continue

        embeddings = []
        for img_file in os.listdir(person_folder):
            img_path = os.path.join(person_folder, img_file)
            image = cv2.imread(img_path)
            if image is None: continue

            rgb_image, _ = preprocess_image(image)
            faces = mtcnn(rgb_image)
            if faces is None: continue

            # Batch process all faces in the image
            with torch.no_grad():
                embeddings_batch = inception_model(faces.to(device))
                embeddings_batch = torch.nn.functional.normalize(embeddings_batch, p=2, dim=1)
                embeddings.extend(embeddings_batch.cpu().numpy())

        if embeddings:
            mean_embedding = torch.tensor(embeddings).mean(dim=0, keepdim=True)
            mean_embedding = torch.nn.functional.normalize(mean_embedding, p=2, dim=1)
            all_embeddings.append(mean_embedding.numpy())
            all_names.append(person_name)

    if all_embeddings:
        embeddings_matrix = np.vstack(all_embeddings).astype(np.float32)
        d = embeddings_matrix.shape[1]
        nlist = min(100, len(all_names))  # Number of clusters for IVF index
        quantizer = faiss.IndexFlatL2(d)
        index = faiss.IndexIVFFlat(quantizer, d, nlist, faiss.METRIC_L2)
        if torch.cuda.is_available() and device == 'cuda':
            res = faiss.StandardGpuResources()
            index = faiss.index_cpu_to_gpu(res, 0, index)
        index.train(embeddings_matrix)
        index.add(embeddings_matrix)
        return index, all_names
    else:
        return None, []

def extract_embeddings(image_path):
    image = cv2.imread(image_path)
    if image is None: return None, None
    rgb_image, original_image = preprocess_image(image)
    faces = mtcnn(rgb_image)
    if faces is None or len(faces) == 0: return None, original_image

    # Batch process all faces in the image
    with torch.no_grad():
        embeddings = inception_model(faces.to(device))
        embeddings = torch.nn.functional.normalize(embeddings, p=2, dim=1)
    return embeddings.cpu().numpy(), original_image

def process_image(img_name, faiss_index, known_names, tolerance=0.3):
    img_path = os.path.join(image_folder, img_name)
    start = time.time()

    embeddings, image = extract_embeddings(img_path)
    if embeddings is None: 
        logging.info(f"No faces in {img_name}")
        return

    recognized_set = set()
    # Search for all embeddings in a single FAISS call
    dists, idxs = faiss_index.search(embeddings.astype(np.float32), 1)
    for dist, idx in zip(dists, idxs):
        if dist[0] < tolerance:
            person = known_names[idx[0]]
            recognized_set.add(person)
            person_dir = os.path.join(processed_images_dir, person)
            os.makedirs(person_dir, exist_ok=True)
            out_path = os.path.join(person_dir, f"processed_{img_name}")
            cv2.imwrite(out_path, image, [int(cv2.IMWRITE_JPEG_QUALITY), 90])

    logging.info(f"\033[1m{img_name}\033[0m ➤ {' • '.join(recognized_set) if recognized_set else 'No Match'}")
    logging.info(f"Processed in {time.time() - start:.2f} sec\n{'='*40}")

def main():
    if not os.path.exists(image_folder):
        print(f"Folder '{image_folder}' does not exist.")
        return

    logging.info("Loading known faces...")
    faiss_index, known_names = load_known_faces()
    if faiss_index is None:
        print("No known faces found.")
        return

    img_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    start_time = time.time()

    # Process images in parallel using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        executor.map(partial(process_image, faiss_index=faiss_index, known_names=known_names), img_files)

    total_time = time.time() - start_time
    logging.info(f"\n✅ All {len(img_files)} images processed in {total_time:.2f} seconds.")
    logging.info(f"🕒 Avg time/image: {total_time / len(img_files):.2f} seconds.")

if __name__ == "__main__":
    main()