from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from pymongo import MongoClient
import hashlib
import uuid
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.sessions.backends.base import SessionBase
from kisan_sathi.settings import MONGO_DB

def home(request):
    return render(request, "accounts/home.html")


def register_view(request):
    return render(request, "accounts/register.html")


def login_view(request):
    return render(request, "accounts/login.html")


def about_view(request):
    return render(request, "accounts/about.html")

def contact_view(request):
    return render(request, "accounts/contact.html")


# Connect to MongoDB (Ensure your MongoDB server is running)
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]

def register_view(request):
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()
        confirm_password = request.POST.get("confirm_password", "").strip()
        role = request.POST.get("role", "").strip()

        # Check if passwords match
        if password != confirm_password:
            return render(request, "accounts/register.html", {"error": "Passwords do not match"})

        # Check if user already exists
        if db.users.find_one({"email": email}):
            return render(request, "accounts/register.html", {"error": "Email already exists"})

        # Hash password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Store user in MongoDB (Without email verification)
        user_data = {
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": role
        }
        db.users.insert_one(user_data)

        return redirect("login_view")  # Redirect to login page after successful registration

    return render(request, "accounts/register.html")




# Login view
# Connect to MongoDB (Ensure your MongoDB server is running)
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]

def login_view(request):
    if request.method == "POST":
        # Get the email and password from the POST request
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()

        # Debug: Print received email (avoid logging real passwords in production)
        print(f"Attempting login for email: {email}")

        # Hash the entered password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Look up the user in MongoDB
        user = db.users.find_one({"email": email, "password": hashed_password})

        # Debug: Print the user retrieved
        print("User found:" if user else "No user found with those credentials.")

        if user:
            # Set session variables
            request.session["user_id"] = str(user["_id"])
            request.session["email"] = user["email"]
            request.session["role"] = user.get("role", "")

            # Debug: Print session info
            print("Session set:", request.session.items())

            # Redirect based on user role
            if user.get("role") == "seller":
                print("Redirecting to seller_dashboard")
                return redirect("seller_dashboard")
            elif user.get("role") == "buyer":
                print("Redirecting to buyer_dashboard")
                return redirect("buyer_dashboard")
            else:
                print("User has an invalid role")
                return HttpResponse("Invalid user role.")

        # If user not found, return error message
        return render(request, "accounts/login.html", {"error": "Invalid email or password"})

    # For GET requests, simply render the login page
    return render(request, "accounts/login.html")




# Logout view
def logout_view(request):
    request.session.flush()
    return redirect("login_view")



def seller_dashboard(request):
    # Check session for proper role
    if request.session.get("role") != "seller":
        return redirect("login_view")
    return render(request, "accounts/seller_dashboard.html")

def buyer_dashboard(request):
    if request.session.get("role") != "buyer":
        return redirect("login_view")
    return render(request, "accounts/buyer_dashboard.html")




from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .tokens import account_activation_token  # We'll create this
import hashlib
from pymongo import MongoClient

# Connect to MongoDB (Make sure your MongoDB server is running)
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]

def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        role = request.POST.get("role")

        # Validate required fields
        if not username or not email or not password or not confirm_password or not role:
            return render(request, "accounts/register.html", {"error": "All fields are required"})

        # Check if passwords match
        if password != confirm_password:
            return render(request, "accounts/register.html", {"error": "Passwords do not match"})

        # Check if the email already exists in the database
        if db.users.find_one({"email": email}):
            return render(request, "accounts/register.html", {"error": "Email already exists"})

        # Hash password before storing
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Store user in MongoDB
        user_data = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "role": role
        }
        db.users.insert_one(user_data)

        # Redirect to login page after successful registration
        return redirect("login_view")  # Ensure "login_view" is correctly defined in urls.py

    return render(request, "accounts/register.html")


from django.shortcuts import render, redirect
from bson import ObjectId

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]

def seller_dashboard(request):
    if "user_id" not in request.session or request.session.get("role") != "seller":
        return redirect("login_view")  # Ensure the user is logged in

    seller_id = request.session["user_id"]

    # Fetch the seller's details (handling missing fields)
    seller = db.users.find_one({"_id": ObjectId(seller_id)}, {"username": 1})  # Only fetch the 'name' field
    seller_name = seller["username"] if seller and "username" in seller else "Seller"

    # Fetch crops and rename `_id` to `id`
    crops = list(db.crops.find({"seller_id": seller_id}))
    for crop in crops:
        crop["id"] = str(crop.pop("_id"))  # Convert ObjectId to string

    return render(request, "accounts/seller_dashboard.html", {"crops": crops, "seller_name": seller_name})


# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]

from bson import ObjectId

from bson import ObjectId

def add_crop(request):
    # Ensure the user is logged in as a seller
    if "user_id" not in request.session or request.session.get("role") != "seller":
        return redirect("login_view")

    if request.method == "POST":
        name = request.POST["name"]
        variety = request.POST["variety"]
        weight = request.POST["weight"]
        price = request.POST["price"]
        seller_id = request.session["user_id"]

        # Fetch seller details from the database
        seller = db.users.find_one({"_id": ObjectId(seller_id)}, {"contact_no": 1, "address": 1})

        # Get contact_no and address from request, allowing the seller to enter if not present
        contact_no = request.POST.get("contact_no") or (seller.get("contact_no") if seller else "")
        address = request.POST.get("address") or (seller.get("address") if seller else "")

        # If contact_no or address is newly provided, update the user's record in the database
        if not seller or not seller.get("contact_no") or not seller.get("address"):
            db.users.update_one(
                {"_id": ObjectId(seller_id)},
                {"$set": {"contact_no": contact_no, "address": address}}
            )

        # Insert the new crop into MongoDB
        db.crops.insert_one({
            "name": name,
            "variety": variety,
            "weight": weight,
            "price": price,
            "contact_no": contact_no,  # Store contact no from seller
            "address": address,        # Store address from seller
            "seller_id": seller_id,
        })

        return redirect("seller_dashboard")

    return render(request, "accounts/add_crop.html")


# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]

def edit_crop(request, crop_id):
    # Ensure the user is logged in as a seller
    if "user_id" not in request.session or request.session.get("role") != "seller":
        return redirect("login_view")

    # Fetch the crop details from MongoDB
    crop = db.crops.find_one({"_id": ObjectId(crop_id)})

    if not crop:
        return HttpResponse("Crop not found", status=404)

    if request.method == "POST":
        name = request.POST["name"]
        variety = request.POST["variety"]
        weight = request.POST["weight"]
        price = request.POST["price"]
        contact_no = request.POST["contact_no"]
        address = request.POST["address"]

        # Update crop details
        db.crops.update_one(
            {"_id": ObjectId(crop_id)},
            {"$set": {
                "name": name,
                "variety": variety,
                "weight": weight,
                "price": price,
                "contact_no": contact_no,
                "address": address,
            }},
        )

        return redirect("seller_dashboard")

    return render(request, "accounts/edit_crop.html", {"crop": crop})


def delete_crop(request, crop_id):
    if "user_id" not in request.session or request.session.get("role") != "seller":
        return redirect("login_view")

    db.crops.delete_one({"_id": ObjectId(crop_id)})

    return redirect("seller_dashboard")




# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["kisan_sathi"]
crop_collection = db["crops"] 


def buyer_dashboard(request):
    if "user_id" not in request.session or request.session.get("role") != "buyer":
        return redirect("login_view")  # Ensure the user is logged in
    
    #   # Refresh session data to avoid accidental logout
    # request.session.modified = True

    user_id = request.session["user_id"]
    
    # Fetch buyer's username
    user = db.users.find_one({"_id": ObjectId(user_id)}, {"username": 1})
    buyer_name = user["username"] if user else "Buyer"

    # Get filter parameters from request
    crop_name = request.GET.get("crop_name", "").strip()
    variety = request.GET.get("variety", "").strip()
    location = request.GET.get("location", "").strip()

    # Build filter query
    filter_query = {}
    if crop_name:
        filter_query["name"] = {"$regex": crop_name, "$options": "i"}  # Case-insensitive search
    if variety:
        filter_query["variety"] = {"$regex": variety, "$options": "i"}
    if location:
        filter_query["address"] = {"$regex": location, "$options": "i"}

    # Fetch filtered crops from MongoDB including seller_id
    crops = list(db.crops.find(
        filter_query, 
        {"name": 1, "variety": 1, "weight": 1, "price": 1, "contact_no": 1, "address": 1, "seller_id": 1}
    ))

    for crop in crops:
        crop["id"] = str(crop.pop("_id"))  # Convert ObjectId to string

        # Fetch seller details using seller_id
        if "seller_id" in crop:
            seller = db.users.find_one({"_id": ObjectId(crop["seller_id"])}, {"username": 1})
            crop["seller_name"] = seller["username"] if seller else "Unknown Seller"
        else:
            crop["seller_name"] = "Unknown Seller"

    # Fetch unique crop names, varieties, and locations for filter dropdowns
    crop_names = sorted(db.crops.distinct("name"))
    varieties = sorted(db.crops.distinct("variety"))
    locations = sorted(db.crops.distinct("address"))

    return render(request, "accounts/buyer_dashboard.html", {
        "buyer_name": buyer_name,   # Pass buyer's name to template
        "crops": crops,
        "crop_name": crop_name,
        "variety": variety,
        "location": location,
        "crop_names": crop_names,
        "varieties": varieties,
        "locations": locations,
    })





















