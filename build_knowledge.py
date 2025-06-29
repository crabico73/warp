import os
import json
from pinecone import Pinecone, ServerlessSpec

# === Load config ===
with open('config.json', 'r') as f:
    config = json.load(f)
    api_key = config.get("pinecone_api_key")
    if not api_key:
        raise ValueError("Missing Pinecone API key in config.json")

# === Init Pinecone ===
pc = Pinecone(api_key=api_key)
index_name = "cosmocrack-knowledge"

# === Delete and recreate index ===
if index_name in pc.list_indexes().names():
    print(f"Deleting existing index '{index_name}'...")
    pc.delete_index(index_name)

print(f"Creating index '{index_name}'...")
pc.create_index(
    name=index_name,
    dimension=1536,
    metric='cosine',
    spec=ServerlessSpec(
        cloud='aws',
        region='us-east-1'
    )
)
print("Index created successfully.")

# === Connect to index ===
index = pc.Index(index_name)

# === Upload .txt files ===
knowledge_base_dir = "knowledge_base"
if not os.path.isdir(knowledge_base_dir):
    raise FileNotFoundError(f"No folder named '{knowledge_base_dir}' found!")

for filename in os.listdir(knowledge_base_dir):
    if filename.endswith(".txt"):
        path = os.path.join(knowledge_base_dir, filename)
        print(f"Processing {path}...")
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        vector = [0.1] * 1536  # Placeholder
        index.upsert(vectors=[{
            'id': filename,
            'values': vector,
            'metadata': {'text': content}
        }])
print("All files uploaded.")

