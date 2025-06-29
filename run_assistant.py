import pinecone as pc
import json

# Load the API key from your config file
with open('config.json', 'r') as f:
    config = json.load(f)
    api_key = config.get("pinecone_api_key")

from pinecone import Pinecone

# Initialize the client
pc = Pinecone(api_key=api_key)

# Create the assistant
assistant = pc.assistant.create_assistant(
    assistant_name="example-assistant",
    instructions="Answer in polite, short sentences. Use American English spelling and vocabulary.",
    timeout=30
)

print("Assistant created successfully!")
print(assistant)
