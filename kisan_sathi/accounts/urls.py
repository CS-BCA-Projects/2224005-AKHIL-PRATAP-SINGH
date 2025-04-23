from django.urls import path
from .views import home, register_view,login_view , logout_view , seller_dashboard  , buyer_dashboard ,add_crop ,edit_crop , delete_crop,about_view,contact_view



urlpatterns = [
    path("", home, name="home"),
    path("register/", register_view, name="register_view"),  # Add this
    path("login/", login_view, name="login_view"),  # Add this
    path("logout/", logout_view, name="logout_view"),
    path("seller_dashboard/", seller_dashboard, name="seller_dashboard"),
    path("buyer_dashboard/", buyer_dashboard, name="buyer_dashboard"),
    path("add_crop/", add_crop, name="add_crop"),
    path("edit_crop/<str:crop_id>/", edit_crop, name="edit_crop"),
    path("delete_crop/<str:crop_id>/", delete_crop, name="delete_crop"),
    path("about/", about_view, name="about_view"),
    path("contact/", contact_view, name="contact_view"),
    
    
    
    
]









