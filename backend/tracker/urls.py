from django.urls import path
from tracker.views import *

urlpatterns = [
    path("api/auth/register/", register_user, name="register"),
    path("api/auth/login/", login_user, name="login"),
    path("api/transactions/add/", add_transaction, name="add_transaction"),
    path("api/transactions/get/", get_transactions, name="get_transactions"),
    path("api/transactions/<transaction_id>/", transaction_details, name="transaction_details"),


    
]
