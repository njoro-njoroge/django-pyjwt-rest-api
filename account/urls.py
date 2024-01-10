from django.urls import path
from .views import RegisterView, LoginView, UserView,StoreNameView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('get_user/', UserView.as_view()),
    path('create_store/', StoreNameView.as_view()),
]
