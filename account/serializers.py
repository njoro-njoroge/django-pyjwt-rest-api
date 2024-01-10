from rest_framework import serializers
from .models import User, Store


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'phone_number', 'email', 'location', 'password']
        # hide password from response
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = self.Meta.model(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user


class StoreNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Store
        fields = ['id', 'store_name', 'created_at', 'user']

    def create(self, validated_data):
        # When creating a new StoreName instance, associate it with the authenticated user
        user = self.context['request'].user
        return Store.objects.create(user=user, **validated_data)
