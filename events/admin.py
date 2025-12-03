from django.contrib import admin
from .models import EventRegistration


@admin.register(EventRegistration)
class EventRegistrationAdmin(admin.ModelAdmin):
    list_display = (
        'student_name',
        'student_class',
        'school_name',
        'parent_name',
        'payment_verified',
        'created_at',
    )
    list_filter = ('payment_verified', 'created_at', 'student_class')
    search_fields = ('student_name', 'student_email', 'parent_name', 'transaction_id')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Student Information', {
            'fields': ('student_name', 'student_class', 'school_name', 'student_contact', 'student_email')
        }),
        ('Sibling Information', {
            'fields': (
                'sibling1_name', 'sibling1_school', 'sibling1_class',
                'sibling2_name', 'sibling2_school', 'sibling2_class'
            ),
            'classes': ('collapse',)
        }),
        ('Parent Information', {
            'fields': ('parent_name', 'parent_contact', 'parent_signature')
        }),
        ('Event Details', {
            'fields': ('competitions', 'workshops')
        }),
        ('Payment Information', {
            'fields': ('payment_mode', 'transaction_id', 'payment_screenshot', 'payment_verified')
        }),
        ('Admin Notes', {
            'fields': ('notes',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
