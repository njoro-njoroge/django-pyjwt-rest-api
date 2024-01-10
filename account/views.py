from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import authentication_classes, permission_classes
from django.db import transaction

from .serializers import UserSerializer, StoreNameSerializer
from .models import User, Store
import jwt, datetime


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate token for the newly registered user
        utc_now = timezone.now()
        expiration_time = utc_now + timezone.timedelta(minutes=15)

        payload = {
            'id': user.id,
            'exp': expiration_time,
            'iat': utc_now
        }
        secret_key = 'secrets'  # Use the same secret key here
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        response_data = {
            'jwt': token,
            'user': serializer.data
        }

        # Include the token in the response headers or cookies
        response = Response(response_data)
        response.set_cookie(key='jwt', value=token, httponly=True)

        return response


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        store_name = request.data.get('store_name')

        user = User.objects.filter(email=email).first()

        if user is None or not user.check_password(password):
            raise AuthenticationFailed('Authentication failed')

        store = Store.objects.filter(store_name=store_name, user_id=user.id).first()

        if store is None:
            raise AuthenticationFailed('Authentication failed')

        # Generate token
        utc_now = timezone.now()
        expiration_time = utc_now + timezone.timedelta(minutes=15)

        payload = {
            'id': user.id,
            'exp': expiration_time,
            'iat': utc_now
        }
        secret_key = 'secrets'  # Use the same secret key here
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        response = Response({"jwt": token})
        response.set_cookie(key='jwt', value=token, httponly=True)

        return response


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed("Unauthenticated")

        try:

            payload = jwt.decode(token, 'secrets', algorithms=['HS256'])

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated")

        user = User.objects.filter(id=payload['id']).first()

        if not user:
            raise AuthenticationFailed("User not found")

        serializer = UserSerializer(user)
        return Response(serializer.data)


@authentication_classes([])
@permission_classes([])
class StoreNameView(APIView):

    @transaction.atomic
    def post(self, request):
        store_name = request.data.get('store_name')

        # Extract user information from the access token
        access_token = request.COOKIES.get('jwt')
        if not access_token:
            raise AuthenticationFailed('No token provided')

        try:
            decoded_token = jwt.decode(access_token, 'secrets', algorithms=['HS256'])
            user_id = decoded_token.get('id')
            user = User.objects.get(id=user_id)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')

        # Create a new Store object and associate it with the user
        store_name_obj = Store.objects.create(store_name=store_name, user=user)
        store_name_data = StoreNameSerializer(store_name_obj).data

        return Response({"store_name": store_name_data})