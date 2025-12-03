from django.db import models


class EventRegistration(models.Model):
    # Student Details
    student_name = models.CharField(max_length=255)
    student_class = models.CharField(max_length=100)
    school_name = models.CharField(max_length=255)
    student_contact = models.CharField(max_length=20)
    student_email = models.EmailField()

    # Sibling Details
    sibling1_name = models.CharField(max_length=255, blank=True)
    sibling1_school = models.CharField(max_length=255, blank=True)
    sibling1_class = models.CharField(max_length=100, blank=True)
    sibling2_name = models.CharField(max_length=255, blank=True)
    sibling2_school = models.CharField(max_length=255, blank=True)
    sibling2_class = models.CharField(max_length=100, blank=True)

    # Parent Details
    parent_name = models.CharField(max_length=255)
    parent_contact = models.CharField(max_length=20)
    parent_signature = models.ImageField(upload_to='signatures/', blank=True, null=True)

    # Competitions (Multiple Select - stored as JSON)
    competitions = models.JSONField(default=list, blank=True)

    # Workshops (Multiple Select - stored as JSON)
    workshops = models.JSONField(default=list, blank=True)

    # Payment Details
    payment_mode = models.CharField(max_length=100)
    transaction_id = models.CharField(max_length=255)
    payment_screenshot = models.ImageField(upload_to='payments/')

    # Payment Verification
    payment_verified = models.BooleanField(default=False)

    # Admin Notes
    notes = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Event Registration'
        verbose_name_plural = 'Event Registrations'

    def __str__(self):
        return f"{self.student_name} - {self.student_class} ({self.created_at.strftime('%Y-%m-%d')})"
