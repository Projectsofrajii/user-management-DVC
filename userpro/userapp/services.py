import datetime
import jwt
from django.conf import settings
from .models import RsmUserMaster
from django.core.mail import send_mail
import re

def user_email_selector(user_name:str):
    user = RsmUserMaster.objects.filter(user_name=user_name).first()
    return user

def create_token(user_name:str):
    payload = dict(
        user_name=user_name+"ReconnectEnergy",
        exp = datetime.datetime.utcnow()+datetime.timedelta(hours=24),
        iat=datetime.datetime.utcnow()
    )
    token = jwt.encode(payload,settings.SECRET_KEY,algorithm="HS256")
    return token

def send_forget_password(email,fptoken_cookie):
    subject = "Forget Password Token"
    message = f"Hello, your request for forgot password token is {fptoken_cookie} , generate new password using the token"
    #message = f"Hello, click on the link to reset your password http://13.235.72.170:8000/api/changepass/{token}"
    email_from = settings.EMAIL_HOST_USER
    recipient = [email]
    send_mail(subject,message,email_from,recipient)
    return True

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        # return redirect('home')
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')

def send_email(email,subject,message):
    try:
        email_from = settings.EMAIL_HOST
        send_mail(subject,message,email_from,[email])
    except Exception as e:
        print(e)