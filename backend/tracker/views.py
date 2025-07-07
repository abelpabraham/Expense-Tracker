from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import bcrypt
import jwt
from datetime import datetime, timezone
import datetime
from django.conf import settings
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["expense_tracker_db"]
users_collection = db["user"]

# JWT Secret Key
SECRET_KEY = "ASd9fj3Ksdjf93JskdfnNsl8fj39FskdJS9Fnskdfg=" #"some_really_random_and_secret_string" should put it somewhere else,like settings or .env file

@csrf_exempt
def register_user(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            username = data["username"]
            email = data["email"]
            password = data["password"]

            # Check if user already exists
            if users_collection.find_one({"email": email}):
                return JsonResponse({"error": "User already exists"}, status=400)

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Insert user into MongoDB
            users_collection.insert_one({
                "username": username,
                "email": email,
                "password": hashed_password.decode('utf-8'),
                "created_at": datetime.datetime.utcnow()
            })

            return JsonResponse({"message": "User registered successfully"}, status=201)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
        
@csrf_exempt
def login_user(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data["email"]
            password = data["password"]

            user = users_collection.find_one({"email": email})

            if not user or not bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
                return JsonResponse({"error": "Invalid credentials"}, status=400)

            # Generate JWT Token
            token = jwt.encode({
                "user_id": str(user["_id"]),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
            }, SECRET_KEY, algorithm="HS256")

            return JsonResponse({"token": token}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
        
from bson import ObjectId

transaction_collection = db["transaction"]

@csrf_exempt
def add_transaction(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            token = request.headers.get("Authorization")
            if not token:
                return JsonResponse({"error":"unauthorized"},status=401)
            
            decoded_token=jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id=decoded_token["user_id"]
            
            data["user_id"] = user_id
            data["created_at"] = datetime.datetime.utcnow()

            transaction_id = transaction_collection.insert_one(data).inserted_id
            return JsonResponse({"message":"Transaction addded","id":str(transaction_id)}, status=201)
        except Exception as e:
            return JsonResponse({"message":str(e)},status=500)
        
@csrf_exempt
def get_transactions(request):
    if request.method == "GET":
        try:
            token = request.headers.get("Authorization")

            if not token:
                return JsonResponse({"error": "Unauthorized"}, status=401)

            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token["user_id"]

            transactions = list(transaction_collection.find({"user_id": user_id}, {"_id": 1, "amount": 1, "category": 1, "type": 1, "date": 1}))
            for t in transactions:
                t["_id"] = str(t["_id"])

            return JsonResponse({"transactions": transactions}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
        
@csrf_exempt
def transaction_details(request,transaction_id):
    try:
        token=request.headers.get("Authorization")
        if not token:
            return JsonResponse({"error":"Unauthorised"},status=401)
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id=decoded_token["user_id"]
    except:
        return JsonResponse({"error":"Invalid or no token"},status=401)
    try:
        object_id = ObjectId(transaction_id)
    except:
        return JsonResponse({"error":"Invalid transaction ID"},status=400)
    if request.method=="PUT":
        data = json.loads(request.body)
        updated_data = {
            "type": data.get("type"),
            "amount": data.get("amount"),
            "category": data.get("category"),
            "date": data.get("date")
        }
        result = transaction_collection.update_one(
            {"_id": object_id,"user_id": user_id},
            {"$set": updated_data}
        )
        if result.modified_count == 1:
            return JsonResponse({"message": "Transaction updated successfully"})
        else:
            return JsonResponse({"error": "Transaction not found or not updated"}, status=404)
        
    elif request.method == 'DELETE':
        result = transaction_collection.delete_one(
            {"_id": object_id, "user_id": user_id}
        )
        if result.deleted_count == 1:
            return JsonResponse({"message": "Transaction deleted successfully"}, status=204)
        else:
            return JsonResponse({"error": "Transaction not found"}, status=404)

    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)