from django.contrib.auth import logout
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from .settings import users_collection  # Import MongoDB users collection
import bcrypt
from .settings import users_collection, crops_collection  # MongoDB collections
from pymongo import MongoClient
from django.conf import settings
import pymongo
from django.contrib.auth.decorators import login_required


# MongoDB connection
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "kisan_sathi"

client = MongoClient()
db = client["kisan_sathi"]

def home(request):
    return render(request, 'kisan_sathi/index.html')

def register(request):
    return render(request, 'kisan_sathi/register.html')

def login(request):
    return render(request, 'kisan_sathi/login.html')

def about(request):
    return render(request, 'kisan_sathi/about.html')

def contact(request):
    return render(request, 'kisan_sathi/contact.html')




@csrf_exempt  # Temporarily disable CSRF for simplicity
def register(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        user_type = request.POST.get("user_type")

        # Check if user already exists
        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            messages.error(request, "Email already registered.")
            return redirect("register")

        # Hash the password before storing
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Insert user into MongoDB
        user_data = {
            "name": name,
            "email": email,
            "password": hashed_password,  # Store hashed password
            "user_type": user_type
        }
        users_collection.insert_one(user_data)

        messages.success(request, "Registration successful. Please log in.")
        return redirect("login")

    return render(request, "kisan_sathi/register.html")





# Connect to MongoDB
client = pymongo.MongoClient(settings.MONGO_URI)
db = client["kisan_sathi"]  # Your database name
users_collection = db["users"]


@csrf_exempt  # Temporarily disable CSRF for simplicity
def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        # Fetch user from MongoDB
        user = users_collection.find_one({"email": email})

        if user:
            # Check if password matches
            if bcrypt.checkpw(password.encode("utf-8"), user["password"]):
                # Store user session
                request.session["user_email"] = user["email"]
                request.session["user_type"] = user["user_type"]

                messages.success(request, "Login successful!")
                return redirect("dashboard")  # Redirect to dashboard after login
            else:
                messages.error(request, "Invalid password. Please try again.")
        else:
            messages.error(request, "User not found. Please register first.")

    return render(request, "kisan_sathi/login.html")


def logout_view(request):
    logout(request)  # Clears session
    messages.success(request, "Logged out successfully!")
    return redirect("login")




# Create the Dashboard View

def dashboard(request):
    if "user_email" not in request.session:
        messages.error(request, "You must log in first.")
        return redirect("login")

    email = request.session["user_email"]
    user_type = request.session["user_type"]

    # Fetch user details from MongoDB
    user = users_collection.find_one({"email": email}, {"_id": 0})

    if user_type == "buyer":
        return render(request, "kisan_sathi/buyer_dashboard.html", {"user": user})

    elif user_type == "seller":
        # Fetch seller's listed crops
        seller_crops = crops_collection.find({"seller_email": email}, {"_id": 0})
        return render(request, "kisan_sathi/seller_dashboard.html", {"user": user, "crops": seller_crops})

    else:
        messages.error(request, "Invalid user type.")
        return redirect("login")
    


# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]
crop_collection = db["crops"]

def buyer_dashboard(request):
    search_query = request.GET.get("search", "").strip()
    category_filter = request.GET.get("category", "").strip()

    query = {}

    if search_query:
        query["crop_name"] = {"$regex": search_query, "$options": "i"}
    if category_filter:
        query["category"] = category_filter

    crops = list(crop_collection.find(query))

    # Convert MongoDB ObjectId to string
    for crop in crops:
        crop["_id"] = str(crop["_id"])
        crop["latitude"] = crop.get("latitude", None)
        crop["longitude"] = crop.get("longitude", None)
        # crop["contact_number"] = crop.get("contact_number") 

    return render(request, "buyer_dashboard.html", {"crops": crops})




from django.shortcuts import render, redirect
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]
crop_collection = db["crops"]

def seller_dashboard(request):
    if request.method == "POST":
        crop_name = request.POST.get("crop_name")
        category = request.POST.get("category")
        weight = float(request.POST.get("weight"))
        price = float(request.POST.get("price"))
        seller_name = request.POST.get("seller_name")
        seller_contact =request.POST.get("seller_contact")
        location = request.POST.get("location")

        crop_data = {
            "crop_name": crop_name,
            "category": category,
            "weight": weight,
            "price": price,
            "seller_name": seller_name,
            "seller_contact" : seller_contact,
            "location": location
        }

        crop_collection.insert_one(crop_data)
        return redirect("buyer_dashboard")

    return render(request, "seller_dashboard.html")


client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]
crop_collection = db["crops"]

def insert_crop(request):
    if request.method == "POST":
        crop_data = {
            "crop_name": request.POST["crop_name"],
            "category": request.POST["category"],
            "weight": float(request.POST["weight"]),
            "price": float(request.POST["price"]),
            "seller_name": request.POST["seller_name"],
            "location": request.POST["location"],
            "phone": request.POST["phone"],
            "email": request.POST.get("email", "")
        }
        crop_collection.insert_one(crop_data)
        return redirect("seller_dashboard")  # Redirect after successful insertion

    return render(request, "insert_crop.html")




def check_session(request):
    return HttpResponse(f"Session Data: {request.session.items()}")









