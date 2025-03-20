from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client["kisan_sathi"]  # Your MongoDB database name
