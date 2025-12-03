from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.utils.decorators import method_decorator
from .models import EventRegistration
from .serializers import EventRegistrationSerializer, PaymentVerificationSerializer


class RegistrationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for handling event registrations.
    """
    queryset = EventRegistration.objects.all()
    serializer_class = EventRegistrationSerializer

    def get_permissions(self):
        """
        Allow anyone to create registrations, but require authentication for list/retrieve.
        """
        if self.action == 'create':
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def create(self, request, *args, **kwargs):
        """
        Create a new registration.
        Accepts multipart/form-data.
        """
        import json
        import sys
        
        # Force immediate output
        sys.stdout.write("\n" + "="*60 + "\n")
        sys.stdout.write("[REGISTRATION] POST /api/registrations/ - Received data keys: " + str(list(request.data.keys())) + "\n")
        sys.stdout.flush()
        
        # Parse JSON strings for competitions and workshops when sent as FormData
        data = request.data.copy()
        
        # Handle competitions - FormData might send as string or list
        if 'competitions' in data:
            competitions_value = data['competitions']
            sys.stdout.write(f"[REGISTRATION] competitions type: {type(competitions_value)}, value: {competitions_value}\n")
            sys.stdout.flush()
            
            if isinstance(competitions_value, str):
                try:
                    data['competitions'] = json.loads(competitions_value)
                except (json.JSONDecodeError, TypeError):
                    data['competitions'] = []
            elif isinstance(competitions_value, list):
                data['competitions'] = competitions_value
            else:
                data['competitions'] = []
        else:
            data['competitions'] = []
        
        # Handle workshops
        if 'workshops' in data:
            workshops_value = data['workshops']
            sys.stdout.write(f"[REGISTRATION] workshops type: {type(workshops_value)}, value: {workshops_value}\n")
            sys.stdout.flush()
            
            if isinstance(workshops_value, str):
                try:
                    data['workshops'] = json.loads(workshops_value)
                except (json.JSONDecodeError, TypeError):
                    data['workshops'] = []
            elif isinstance(workshops_value, list):
                data['workshops'] = workshops_value
            else:
                data['workshops'] = []
        else:
            data['workshops'] = []
        
        sys.stdout.write(f"[REGISTRATION] Final competitions: {data.get('competitions')}, workshops: {data.get('workshops')}\n")
        sys.stdout.flush()
        
        serializer = self.get_serializer(data=data, context={'request': request})
        
        if not serializer.is_valid():
            sys.stdout.write(f"[REGISTRATION] VALIDATION ERRORS: {serializer.errors}\n")
            sys.stdout.flush()
            from rest_framework.exceptions import ValidationError
            raise ValidationError(serializer.errors)
        
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        sys.stdout.write(f"[REGISTRATION] SUCCESS - Registration created: ID {serializer.data.get('id')}\n")
        sys.stdout.write("="*60 + "\n")
        sys.stdout.flush()
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def list(self, request, *args, **kwargs):
        """
        List all registrations (admin only).
        Supports filtering by payment_verified status.
        """
        queryset = self.filter_queryset(self.get_queryset())
        
        # Filter by payment verification status if provided
        payment_verified = request.query_params.get('payment_verified', None)
        if payment_verified is not None:
            payment_verified = payment_verified.lower() == 'true'
            queryset = queryset.filter(payment_verified=payment_verified)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True, context={'request': request})
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a single registration (admin only).
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance, context={'request': request})
        return Response(serializer.data)

    @action(detail=True, methods=['patch'], permission_classes=[IsAuthenticated])
    def verify(self, request, pk=None):
        """
        Update payment verification status and notes (admin only).
        """
        registration = self.get_object()
        serializer = PaymentVerificationSerializer(registration, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Return full registration data
        full_serializer = EventRegistrationSerializer(registration, context={'request': request})
        return Response(full_serializer.data)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def admin_login(request):
    """
    Admin login endpoint.
    Supports both email and username for authentication.
    """
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response(
            {'error': 'Email and password are required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Try to find user by email first, then by username
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    username = None
    try:
        # First try to find user by email
        user_obj = User.objects.get(email=email)
        username = user_obj.username
    except User.DoesNotExist:
        # If not found by email, try username
        try:
            user_obj = User.objects.get(username=email)
            username = user_obj.username
        except User.DoesNotExist:
            username = email  # Fallback: try email as username
    
    # Authenticate with the username
    user = authenticate(request, username=username, password=password)
    
    if user is not None:
        if user.is_staff or user.is_superuser:
            login(request, user)
            # Explicitly save the session to ensure cookie is set
            request.session.save()
            
            # Create response
            response = Response({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username
                }
            })
            
            # Ensure session cookie is set with proper attributes
            # The session middleware should handle this, but we'll ensure it's set
            if request.session.session_key:
                response.set_cookie(
                    'sessionid',
                    request.session.session_key,
                    max_age=86400,  # 24 hours
                    httponly=True,
                    samesite='Lax',  # Use Lax for local development
                    secure=False  # False for HTTP localhost
                )
            
            return response
        else:
            return Response(
                {'error': 'User does not have admin privileges'},
                status=status.HTTP_403_FORBIDDEN
            )
    else:
        return Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_logout(request):
    """
    Admin logout endpoint.
    """
    logout(request)
    return Response({'success': True, 'message': 'Logout successful'})


@api_view(['GET'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def admin_check(request):
    """
    Check if admin is logged in.
    Returns authenticated status without requiring authentication.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # Debug logging
    logger.info(f"Admin check - User authenticated: {request.user.is_authenticated}")
    logger.info(f"Admin check - User: {request.user}")
    logger.info(f"Admin check - Session key: {request.session.session_key}")
    logger.info(f"Admin check - Cookies: {request.COOKIES}")
    
    if request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
        return Response({
            'authenticated': True,
            'user': {
                'id': request.user.id,
                'email': request.user.email,
                'username': request.user.username
            }
        })
    else:
        return Response({
            'authenticated': False
        })


@api_view(['GET'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def get_csrf_token(request):
    """
    Get CSRF token for the frontend.
    This endpoint ensures the CSRF cookie is set.
    """
    from django.middleware.csrf import get_token
    csrf_token = get_token(request)
    return Response({'csrfToken': csrf_token})


@api_view(['GET'])
@permission_classes([AllowAny])
def test_logging(request):
    """
    Test endpoint to verify logging is working.
    """
    import sys
    sys.stdout.write("\n" + "="*60 + "\n")
    sys.stdout.write("TEST LOGGING ENDPOINT CALLED\n")
    sys.stdout.write("="*60 + "\n")
    sys.stdout.flush()
    return Response({'message': 'Logging test successful - check server terminal'})
