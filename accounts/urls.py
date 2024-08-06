from django.urls import path
from .views import RegisterAPIView, LoginAPIView, LogoutAPIView, ActivateAPIView, ForgotPasswordAPIView, ResetPasswordValidateAPIView, ResetPasswordAPIView, ChangePasswordAPIView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('activate/<uidb64>/<token>/', ActivateAPIView.as_view(), name='activate'),
    path('forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot_password'),
    path('reset-password-validate/<uidb64>/<token>/', ResetPasswordValidateAPIView.as_view(), name='reset_password_validate'),
    path('reset-password/', ResetPasswordAPIView.as_view(), name='reset_password'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change_password'),
]
