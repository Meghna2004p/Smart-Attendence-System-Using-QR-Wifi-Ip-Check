from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import RegexValidator, MinValueValidator
from django.core.exceptions import ValidationError
import uuid
import secrets
from datetime import timedelta

class CampusSubnet(models.Model):
    """Model to store allowed campus WiFi subnets"""
    name = models.CharField(
        max_length=100,
        help_text="Descriptive name for this subnet (e.g., 'Main Campus WiFi')"
    )
    subnet = models.CharField(
        max_length=20, 
        unique=True,
        validators=[
            RegexValidator(
                regex=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$',
                message='Enter a valid subnet in CIDR notation (e.g., 192.168.1.0/24)'
            )
        ],
        help_text="Subnet in CIDR notation (e.g., '192.168.1.0/24')"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this subnet is currently allowed for attendance"
    )
    description = models.TextField(
        blank=True,
        help_text="Additional description or notes about this subnet"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def clean(self):
        """Validate subnet format"""
        import ipaddress
        try:
            ipaddress.ip_network(self.subnet, strict=False)
        except ipaddress.AddressValueError:
            raise ValidationError({'subnet': 'Invalid subnet format'})
    
    def __str__(self):
        return f"{self.name} ({self.subnet})"
    
    class Meta:
        verbose_name = "Campus Subnet"
        verbose_name_plural = "Campus Subnets"
        ordering = ['name']
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['subnet']),
        ]

class Course(models.Model):
    """Model for courses/subjects"""
    name = models.CharField(
        max_length=200,
        help_text="Full name of the course"
    )
    code = models.CharField(
        max_length=20, 
        unique=True,
        validators=[
            RegexValidator(
                regex=r'^[A-Z]{2,4}\d{3,4}[A-Z]?$',
                message='Course code should follow format: CS101, MATH2301, etc.'
            )
        ],
        help_text="Course code (e.g., CS101, MATH2301)"
    )
    teacher = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.PROTECT,  # Prevent deletion if there are courses
        limit_choices_to={'role': 'teacher'},
        related_name='taught_courses'
    )
    description = models.TextField(
        blank=True,
        help_text="Course description and objectives"
    )
    credits = models.PositiveSmallIntegerField(
        default=3,
        validators=[MinValueValidator(1)],
        help_text="Number of credit hours"
    )
    semester = models.CharField(
        max_length=20,
        blank=True,
        help_text="Semester/term when course is offered (e.g., Fall 2024)"
    )
    max_students = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum number of students allowed (leave empty for no limit)"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether the course is currently active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def clean(self):
        """Validate course data"""
        super().clean()
        # Note: Teacher validation is handled in the save() method
        # to avoid issues with Django admin form processing
    
    def save(self, *args, **kwargs):
        """Override save to validate teacher"""
        # Validate teacher if assigned
        if self.teacher_id:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                teacher = User.objects.get(pk=self.teacher_id)
                if not teacher.is_teacher():
                    raise ValidationError('Selected user must be a teacher.')
            except User.DoesNotExist:
                raise ValidationError('Selected teacher does not exist.')
        
        super().save(*args, **kwargs)
    
    def enrollment_count(self):
        """Get current enrollment count"""
        return self.enrollments.filter(status='enrolled').count()
    
    @property
    def is_full(self):
        """Check if course is at capacity"""
        if self.max_students:
            return self.enrollment_count() >= self.max_students
        return False
    
    def get_active_sessions(self):
        """Get currently active attendance sessions"""
        now = timezone.now()
        return self.attendance_sessions.filter(
            status='active',
            start_time__lte=now,
            end_time__gte=now
        )
    
    def __str__(self):
        return f"{self.code} - {self.name}"
    
    class Meta:
        ordering = ['code']
        indexes = [
            models.Index(fields=['teacher']),
            models.Index(fields=['is_active']),
            models.Index(fields=['code']),
        ]

class Enrollment(models.Model):
    """Model for student course enrollments"""
    STATUS_CHOICES = [
        ('enrolled', 'Enrolled'),
        ('dropped', 'Dropped'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'student'},
        related_name='enrollments'
    )
    course = models.ForeignKey(
        Course, 
        on_delete=models.CASCADE,
        related_name='enrollments'
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='enrolled',
        help_text="Current enrollment status"
    )
    grade = models.CharField(
        max_length=5,
        blank=True,
        help_text="Final grade (A, B, C, D, F, etc.)"
    )
    enrolled_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(
        blank=True,
        help_text="Additional notes about this enrollment"
    )
    
    def clean(self):
        """Validate enrollment data"""
        super().clean()
        if self.student and not self.student.is_student():
            raise ValidationError({'student': 'Selected user must be a student.'})
        
        # Check if course is full (only for new enrollments)
        if not self.pk and self.course and self.course.is_full:
            raise ValidationError({'course': 'This course is at maximum capacity.'})
    
    @property
    def attendance_percentage(self):
        """Calculate attendance percentage for this enrollment"""
        total_sessions = self.course.attendance_sessions.filter(
            status__in=['completed', 'expired']
        ).count()
        
        if total_sessions == 0:
            return 0
        
        attended_sessions = self.student.attendance_records.filter(
            session__course=self.course
        ).count()
        
        return round((attended_sessions / total_sessions) * 100, 2)
    
    def get_attendance_records(self):
        """Get all attendance records for this enrollment"""
        return self.student.attendance_records.filter(
            session__course=self.course
        ).order_by('-marked_at')
    
    class Meta:
        unique_together = ['student', 'course']
        verbose_name = "Course Enrollment"
        verbose_name_plural = "Course Enrollments"
        ordering = ['-enrolled_at']
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['course']),
            models.Index(fields=['status']),
            models.Index(fields=['enrolled_at']),
        ]
    
    def __str__(self):
        return f"{self.student.username} enrolled in {self.course.code} ({self.get_status_display()})"

class AttendanceSession(models.Model):
    """Model for attendance sessions created by teachers"""
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    ATTENDANCE_TYPE_CHOICES = [
        ('lecture', 'Lecture'),
        ('lab', 'Lab Session'),
        ('tutorial', 'Tutorial'),
        ('exam', 'Exam'),
        ('quiz', 'Quiz'),
        ('other', 'Other'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(
        Course, 
        on_delete=models.CASCADE,
        related_name='attendance_sessions'
    )
    teacher = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.PROTECT,
        limit_choices_to={'role': 'teacher'},
        related_name='created_sessions'
    )
    title = models.CharField(
        max_length=200,
        help_text="Session title (e.g., 'Week 5 Lecture', 'Midterm Exam')"
    )
    attendance_type = models.CharField(
        max_length=20,
        choices=ATTENDANCE_TYPE_CHOICES,
        default='lecture',
        help_text="Type of attendance session"
    )
    location = models.CharField(
        max_length=100, 
        blank=True,
        help_text="Physical location (room, building, etc.)"
    )
    start_time = models.DateTimeField(
        help_text="When the session starts"
    )
    end_time = models.DateTimeField(
        help_text="When the session ends"
    )
    status = models.CharField(
        max_length=10, 
        choices=STATUS_CHOICES, 
        default='scheduled'
    )
    qr_token = models.CharField(
        max_length=255, 
        unique=True,
        help_text="Unique token for QR code"
    )
    qr_expires_at = models.DateTimeField(
        help_text="When the QR code expires"
    )
    attendance_window_minutes = models.PositiveIntegerField(
        default=15,
        help_text="How many minutes before/after start time attendance is allowed"
    )
    require_location_verification = models.BooleanField(
        default=True,
        help_text="Whether to verify student location via IP subnet"
    )
    auto_close_after_end = models.BooleanField(
        default=True,
        help_text="Automatically close session after end time"
    )
    notes = models.TextField(
        blank=True,
        help_text="Additional notes or instructions for students"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def clean(self):
        """Validate session data"""
        super().clean()
        
        if self.start_time and self.end_time:
            if self.start_time >= self.end_time:
                raise ValidationError({
                    'end_time': 'End time must be after start time.'
                })
            
            # Session shouldn't be longer than 24 hours
            if (self.end_time - self.start_time) > timedelta(hours=24):
                raise ValidationError({
                    'end_time': 'Session cannot be longer than 24 hours.'
                })
        
        if self.teacher and not self.teacher.is_teacher():
            raise ValidationError({'teacher': 'Selected user must be a teacher.'})
        
        # Check if teacher is assigned to the course
        if self.course and self.teacher and self.course.teacher != self.teacher:
            raise ValidationError({
                'teacher': 'Teacher must be assigned to the selected course.'
            })
    
    def save(self, *args, **kwargs):
        """Override save to generate secure QR token and handle auto-activation"""
        if not self.qr_token:
            self.qr_token = self.generate_qr_token()
        
        if not self.qr_expires_at and self.start_time:
            # Use QR_CODE_EXPIRY_MINUTES from settings, or attendance_window_minutes as fallback
            from django.conf import settings
            expiry_minutes = getattr(settings, 'QR_CODE_EXPIRY_MINUTES', self.attendance_window_minutes)
            # QR code expires after the specified time from session start
            self.qr_expires_at = self.start_time + timedelta(minutes=expiry_minutes)
        
        # Auto-activate sessions that should be active
        now = timezone.now()
        if (self.status == 'scheduled' and 
            self.start_time and 
            self.start_time <= now and 
            self.end_time > now):
            self.status = 'active'
        
        super().save(*args, **kwargs)
    
    @staticmethod
    def generate_qr_token():
        """Generate a secure random token for QR code"""
        return secrets.token_urlsafe(32)
    
    def regenerate_qr_token(self):
        """Regenerate QR token (useful if compromised)"""
        self.qr_token = self.generate_qr_token()
        self.save(update_fields=['qr_token', 'updated_at'])
    
    def extend_qr_expiry(self, additional_minutes=None):
        """Extend QR code expiry time for ongoing sessions"""
        from django.conf import settings
        if additional_minutes is None:
            additional_minutes = getattr(settings, 'QR_CODE_EXPIRY_MINUTES', 30)
        
        # Extend from current time, not original expiry
        self.qr_expires_at = timezone.now() + timedelta(minutes=additional_minutes)
        self.save(update_fields=['qr_expires_at', 'updated_at'])
        return self.qr_expires_at
    
    def activate_session(self):
        """Manually activate a scheduled session"""
        if self.status == 'scheduled':
            self.status = 'active'
            # Also extend QR expiry to give more time
            from django.conf import settings
            expiry_minutes = getattr(settings, 'QR_CODE_EXPIRY_MINUTES', 30)
            self.qr_expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
            self.save(update_fields=['status', 'qr_expires_at', 'updated_at'])
            return True
        return False
    
    @classmethod
    def auto_manage_sessions(cls):
        """Auto-manage session states based on current time"""
        now = timezone.now()
        
        # Activate sessions that should be active
        scheduled_to_activate = cls.objects.filter(
            status='scheduled',
            start_time__lte=now,
            end_time__gt=now
        )
        
        activated_count = 0
        for session in scheduled_to_activate:
            session.status = 'active'
            session.save(update_fields=['status', 'updated_at'])
            activated_count += 1
        
        # Complete sessions that have ended
        active_to_complete = cls.objects.filter(
            status='active',
            end_time__lt=now,
            auto_close_after_end=True
        )
        
        completed_count = 0
        for session in active_to_complete:
            session.status = 'completed'
            session.save(update_fields=['status', 'updated_at'])
            completed_count += 1
        
        return {
            'activated': activated_count,
            'completed': completed_count
        }
    
    def is_active(self):
        """Check if the session is currently active"""
        now = timezone.now()
        return (
            self.status == 'active' and 
            self.start_time <= now <= self.end_time and
            now <= self.qr_expires_at
        )
    
    def can_mark_attendance(self, current_time=None):
        """Check if attendance can be marked at the given time"""
        if current_time is None:
            current_time = timezone.now()
        
        # Check if session is active
        if self.status != 'active':
            return False
        
        # Primary constraint: QR code must not be expired
        if current_time > self.qr_expires_at:
            return False
        
        # Secondary constraint: Must be within session time bounds
        # Allow attendance from 15 minutes before start until session ends
        window_start = self.start_time - timedelta(minutes=self.attendance_window_minutes)
        
        return window_start <= current_time <= self.end_time
    
    def get_attendance_count(self):
        """Get total number of students who marked attendance"""
        return self.attendance_records.count()
    
    def get_enrolled_students_count(self):
        """Get total number of students enrolled in the course"""
        return self.course.enrollments.filter(status='enrolled').count()
    
    def get_attendance_percentage(self):
        """Calculate attendance percentage for this session"""
        enrolled = self.get_enrolled_students_count()
        if enrolled == 0:
            return 0
        attended = self.get_attendance_count()
        return round((attended / enrolled) * 100, 2)
    
    def get_absent_students(self):
        """Get list of enrolled students who didn't attend"""
        attended_student_ids = self.attendance_records.values_list('student_id', flat=True)
        return self.course.enrollments.filter(
            status='enrolled'
        ).exclude(
            student_id__in=attended_student_ids
        ).select_related('student')
    
    class Meta:
        ordering = ['-start_time']
        verbose_name = "Attendance Session"
        verbose_name_plural = "Attendance Sessions"
        indexes = [
            models.Index(fields=['course']),
            models.Index(fields=['teacher']),
            models.Index(fields=['status']),
            models.Index(fields=['start_time']),
            models.Index(fields=['qr_token']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(end_time__gt=models.F('start_time')),
                name='end_time_after_start_time'
            ),
        ]
    
    def __str__(self):
        return f"{self.course.code} - {self.title} ({self.start_time.strftime('%Y-%m-%d %H:%M')})"

class AttendanceRecord(models.Model):
    """Model for individual attendance records"""
    STATUS_CHOICES = [
        ('present', 'Present'),
        ('late', 'Late'),
        ('excused', 'Excused'),
    ]
    
    session = models.ForeignKey(
        AttendanceSession, 
        on_delete=models.CASCADE,
        related_name='attendance_records'
    )
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'student'},
        related_name='attendance_records'
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='present',
        help_text="Attendance status"
    )
    marked_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When attendance was marked"
    )
    marked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='marked_attendance_records',
        null=True,
        blank=True,
        help_text="Who marked the attendance (for manual entries)"
    )
    ip_address = models.GenericIPAddressField(
        help_text="IP address when attendance was marked"
    )
    user_agent = models.TextField(
        blank=True,
        help_text="Browser/device information"
    )
    location_verified = models.BooleanField(
        default=False,
        help_text="Whether location was verified via IP subnet"
    )
    geo_location = models.CharField(
        max_length=100,
        blank=True,
        help_text="Geographic location if available"
    )
    notes = models.TextField(
        blank=True,
        help_text="Additional notes about this attendance record"
    )
    is_manual = models.BooleanField(
        default=False,
        help_text="Whether this was manually added by teacher/admin"
    )
    updated_at = models.DateTimeField(auto_now=True)
    
    def clean(self):
        """Validate attendance record"""
        super().clean()
        
        if self.student and not self.student.is_student():
            raise ValidationError({'student': 'Selected user must be a student.'})
        
        # Check if student is enrolled in the course
        if self.session and self.student:
            enrollment = self.session.course.enrollments.filter(
                student=self.student,
                status='enrolled'
            ).first()
            
            if not enrollment:
                raise ValidationError({
                    'student': 'Student must be enrolled in the course.'
                })
        
        # Auto-determine status based on timing if not manually set
        if not self.is_manual and self.session and self.marked_at:
            self.status = self.determine_attendance_status()
    
    def determine_attendance_status(self):
        """Automatically determine attendance status based on timing"""
        if not self.session or not self.marked_at:
            return 'present'
        
        # If marked before session start time - consider on time
        if self.marked_at <= self.session.start_time:
            return 'present'
        
        # If marked within attendance window but after start - consider late
        window_end = self.session.start_time + timedelta(
            minutes=self.session.attendance_window_minutes
        )
        
        if self.marked_at <= window_end:
            return 'late' if self.marked_at > self.session.start_time else 'present'
        
        # Beyond window - shouldn't happen if validation works, but default to late
        return 'late'
    
    @property
    def is_on_time(self):
        """Check if attendance was marked on time"""
        return self.status == 'present'
    
    @property
    def is_late(self):
        """Check if attendance was marked late"""
        return self.status == 'late'
    
    @property
    def minutes_after_start(self):
        """Calculate how many minutes after session start attendance was marked"""
        if not self.session or not self.marked_at:
            return 0
        
        delta = self.marked_at - self.session.start_time
        return max(0, int(delta.total_seconds() / 60))
    
    def get_verification_info(self):
        """Get verification information for this record"""
        return {
            'ip_address': self.ip_address,
            'location_verified': self.location_verified,
            'geo_location': self.geo_location,
            'user_agent': self.user_agent[:100] + '...' if len(self.user_agent) > 100 else self.user_agent,
            'is_manual': self.is_manual,
            'marked_by': self.marked_by.username if self.marked_by else 'System',
        }
    
    class Meta:
        unique_together = ['session', 'student']
        ordering = ['-marked_at']
        verbose_name = "Attendance Record"
        verbose_name_plural = "Attendance Records"
        indexes = [
            models.Index(fields=['session']),
            models.Index(fields=['student']),
            models.Index(fields=['status']),
            models.Index(fields=['marked_at']),
            models.Index(fields=['is_manual']),
        ]
    
    def __str__(self):
        status_display = self.get_status_display()
        return f"{self.student.username} - {self.session.course.code} ({status_display}) [{self.marked_at.strftime('%Y-%m-%d %H:%M')}]"
