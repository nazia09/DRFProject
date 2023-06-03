from django.urls import path
from .views import UserSignupView, UserLoginView, ProductAddView, ProductEditView, ProductDeleteView


urlpatterns = [
    path('signup/', UserSignupView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('product/add/', ProductAddView.as_view(), name='product_add'),
    path('product/edit/<int:pk>/', ProductEditView.as_view(), name='product_edit'),
    path('product/delete/<int:pk>/', ProductDeleteView.as_view(), name='product_delete'),

]


