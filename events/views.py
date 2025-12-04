from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.utils.decorators import method_decorator
from .models import EventRegistration
from .serializers import EventRegistrationSerializer, PaymentVerificationSerializer


# Custom SessionAuthentication that doesn't enforce CSRF
class NoCSRFSessionAuthentication(SessionAuthentication):
    """
    SessionAuthentication that doesn't enforce CSRF protection.
    Use this for endpoints that need to work without CSRF tokens.
    """
    def enforce_csrf(self, request):
        # Bypass CSRF check
        return


class RegistrationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for handling event registrations.
    """
    queryset = EventRegistration.objects.all()
    serializer_class = EventRegistrationSerializer
    authentication_classes = [NoCSRFSessionAuthentication, SessionAuthentication]

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
        
        # Log file upload information
        if 'payment_screenshot' in request.FILES:
            file = request.FILES['payment_screenshot']
            sys.stdout.write(f"[REGISTRATION] Payment screenshot received: {file.name}, size: {file.size}, type: {file.content_type}\n")
            sys.stdout.flush()
        if 'parent_signature' in request.FILES:
            file = request.FILES['parent_signature']
            sys.stdout.write(f"[REGISTRATION] Parent signature received: {file.name}, size: {file.size}, type: {file.content_type}\n")
            sys.stdout.flush()
        
        serializer = self.get_serializer(data=data, context={'request': request})
        
        if not serializer.is_valid():
            sys.stdout.write(f"[REGISTRATION] VALIDATION ERRORS: {serializer.errors}\n")
            sys.stdout.flush()
            from rest_framework.exceptions import ValidationError
            raise ValidationError(serializer.errors)
        
        try:
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            
            # Get the created instance to check file URLs
            instance = serializer.instance
            
            # Log the created registration with file URLs
            created_data = serializer.data
            sys.stdout.write(f"[REGISTRATION] SUCCESS - Registration created: ID {created_data.get('id')}\n")
            
            # Check actual file URLs from the instance
            if instance.payment_screenshot:
                actual_url = instance.payment_screenshot.url
                sys.stdout.write(f"[REGISTRATION] Payment screenshot - Instance URL: {actual_url}\n")
                sys.stdout.write(f"[REGISTRATION] Payment screenshot - Serialized URL: {created_data.get('payment_screenshot')}\n")
                sys.stdout.write(f"[REGISTRATION] Payment screenshot - File exists: {instance.payment_screenshot}\n")
            else:
                sys.stdout.write(f"[REGISTRATION] WARNING: Payment screenshot is None!\n")
            
            if instance.parent_signature:
                actual_url = instance.parent_signature.url
                sys.stdout.write(f"[REGISTRATION] Parent signature - Instance URL: {actual_url}\n")
                sys.stdout.write(f"[REGISTRATION] Parent signature - Serialized URL: {created_data.get('parent_signature')}\n")
            
            # Check Cloudinary configuration
            import os
            cloudinary_url = os.getenv('CLOUDINARY_URL')
            if cloudinary_url:
                sys.stdout.write(f"[REGISTRATION] Cloudinary URL is set: {cloudinary_url[:20]}...\n")
            else:
                sys.stdout.write(f"[REGISTRATION] WARNING: CLOUDINARY_URL not set! Files may not upload to Cloudinary.\n")
            
            sys.stdout.write("="*60 + "\n")
            sys.stdout.flush()
            return Response(created_data, status=status.HTTP_201_CREATED, headers=headers)
        except Exception as e:
            import traceback
            sys.stdout.write(f"[REGISTRATION] ERROR during create: {str(e)}\n")
            sys.stdout.write(f"[REGISTRATION] Traceback: {traceback.format_exc()}\n")
            sys.stdout.flush()
            raise

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
        try:
            import sys
            sys.stdout.write(f"\n[VERIFY] === Payment Verification Request ===\n")
            sys.stdout.write(f"[VERIFY] Registration ID: {pk}\n")
            sys.stdout.write(f"[VERIFY] User: {request.user} (Authenticated: {request.user.is_authenticated})\n")
            sys.stdout.write(f"[VERIFY] Request data: {request.data}\n")
            sys.stdout.flush()
            
            registration = self.get_object()
            sys.stdout.write(f"[VERIFY] Found registration: {registration.id} - {registration.student_name}\n")
            sys.stdout.write(f"[VERIFY] Current payment_verified status: {registration.payment_verified}\n")
            
            serializer = PaymentVerificationSerializer(registration, data=request.data, partial=True)
            if not serializer.is_valid():
                sys.stdout.write(f"[VERIFY] Validation errors: {serializer.errors}\n")
                sys.stdout.flush()
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            serializer.save()
            registration.refresh_from_db()
            sys.stdout.write(f"[VERIFY] Updated payment_verified status: {registration.payment_verified}\n")
            sys.stdout.write(f"[VERIFY] Notes: {registration.notes[:50] if registration.notes else 'None'}...\n")
            sys.stdout.write(f"[VERIFY] SUCCESS - Payment verification updated\n")
            sys.stdout.flush()
            
            # Return full registration data
            full_serializer = EventRegistrationSerializer(registration, context={'request': request})
            return Response(full_serializer.data)
        except Exception as e:
            import traceback
            sys.stdout.write(f"[VERIFY] ERROR: {str(e)}\n")
            sys.stdout.write(f"[VERIFY] Traceback: {traceback.format_exc()}\n")
            sys.stdout.flush()
            return Response(
                {'error': f'Failed to verify payment: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def admin_login(request):
    """
    Admin login endpoint.
    Supports both email and username for authentication.
    """
    import os
    import traceback
    
    try:
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
        
        user_obj = None
        username = None
        
        # First try to find user by email
        try:
            user_obj = User.objects.get(email=email)
            username = user_obj.username
        except User.DoesNotExist:
            # If not found by email, try username
            try:
                user_obj = User.objects.get(username=email)
                username = user_obj.username
            except User.DoesNotExist:
                # User doesn't exist - return invalid credentials
                return Response(
                    {'error': 'Invalid credentials'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        except User.MultipleObjectsReturned:
            # Multiple users with same email - get the first one
            user_obj = User.objects.filter(email=email).first()
            if user_obj:
                username = user_obj.username
            else:
                return Response(
                    {'error': 'Invalid credentials'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        
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
                    'redirect': '/dashboard',  # Frontend route to redirect to
                    'user': {
                        'id': user.id,
                        'email': user.email if user.email else '',
                        'username': user.username
                    }
                })
                
                # Get cookie settings from environment or settings
                is_secure = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
                samesite_value = 'None' if is_secure else 'Lax'
                
                # Ensure session cookie is set with proper attributes
                if request.session.session_key:
                    response.set_cookie(
                        'sessionid',
                        request.session.session_key,
                        max_age=86400,  # 24 hours
                        httponly=True,
                        samesite=samesite_value,
                        secure=is_secure
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
    except Exception as e:
        # Log the error for debugging
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Admin login error: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return a generic error message to avoid exposing internal details
        return Response(
            {'error': 'An error occurred during login. Please try again.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@authentication_classes([NoCSRFSessionAuthentication])  # Use custom auth that bypasses CSRF
@permission_classes([AllowAny])  # Allow any to avoid CSRF issues, but check auth manually
def admin_logout(request):
    """
    Admin logout endpoint.
    Uses custom authentication that bypasses CSRF protection.
    """
    # Check if user is authenticated
    if not request.user.is_authenticated:
        return Response(
            {'error': 'Not authenticated'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    logout(request)
    response = Response({'success': True, 'message': 'Logout successful'})
    
    # Clear the session cookie with proper settings
    import os
    is_secure = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
    samesite_value = 'None' if is_secure else 'Lax'
    
    response.delete_cookie(
        'sessionid',
        path='/',
        samesite=samesite_value,
        secure=is_secure
    )
    
    return response


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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def test_cloudinary(request):
    """
    Test endpoint to verify Cloudinary configuration.
    """
    import os
    import sys
    from django.core.files.storage import default_storage
    
    cloudinary_url = os.getenv('CLOUDINARY_URL', 'NOT SET')
    storage_class = default_storage.__class__.__name__
    storage_module = default_storage.__class__.__module__
    
    sys.stdout.write("\n" + "="*60 + "\n")
    sys.stdout.write("CLOUDINARY CONFIGURATION TEST\n")
    sys.stdout.write(f"CLOUDINARY_URL: {cloudinary_url[:30]}... (first 30 chars)\n")
    sys.stdout.write(f"Storage Class: {storage_class}\n")
    sys.stdout.write(f"Storage Module: {storage_module}\n")
    sys.stdout.write("="*60 + "\n")
    sys.stdout.flush()
    
    return Response({
        'cloudinary_configured': bool(cloudinary_url and cloudinary_url != 'NOT SET'),
        'storage_class': storage_class,
        'storage_module': storage_module,
        'cloudinary_url_set': cloudinary_url != 'NOT SET',
    })
