from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer
from .models import Product
from .serializers import ProductSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication


class UserSignupView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            serializer = UserSerializer(user)
            response_data = {
                'username': user.username,
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'country': user.country,
                'city': user.city,
                'postal_code': user.postal_code,
                'address': user.address,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)



class ProductAddView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        jwt_authentication =JWTAuthentication()
        user, token =jwt_authentication.authenticate(request)
        if user is None:
            return Response({'error':'Invalid access token'}, status = status.HTTP_401_UNAUTHORIZED)

        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductEditView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, pk):
        jwt_authentication = JWTAuthentication()
        user, token = jwt_authentication.authenticate(request)
        if user is None:
            return Response({'error': 'Invalid access token'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ProductSerializer(product, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, pk):
        jwt_authentication = JWTAuthentication()
        user, token = jwt_authentication.authenticate(request)
        if user is None:
            return Response({'error': 'Invalid access token'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

        product.delete()
        return Response({'message': 'Product deleted'},status=status.HTTP_204_NO_CONTENT)


