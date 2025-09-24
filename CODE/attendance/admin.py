from django.contrib import admin
from .models import CampusSubnet, Course, Enrollment, AttendanceSession, AttendanceRecord

@admin.register(CampusSubnet)
class CampusSubnetAdmin(admin.ModelAdmin):
    list_display = ('name', 'subnet', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'subnet')

@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'teacher', 'is_active', 'created_at')
    list_filter = ('is_active', 'teacher', 'created_at')
    search_fields = ('code', 'name', 'teacher__username')
    raw_id_fields = ('teacher',)

@admin.register(Enrollment)
class EnrollmentAdmin(admin.ModelAdmin):
    list_display = ('student', 'course', 'enrolled_at')
    list_filter = ('course', 'enrolled_at')
    search_fields = ('student__username', 'course__code')
    raw_id_fields = ('student', 'course')

@admin.register(AttendanceSession)
class AttendanceSessionAdmin(admin.ModelAdmin):
    list_display = ('course', 'title', 'teacher', 'start_time', 'status', 'get_attendance_count')
    list_filter = ('status', 'course', 'start_time')
    search_fields = ('title', 'course__code', 'teacher__username')
    readonly_fields = ('id', 'qr_token', 'created_at')
    raw_id_fields = ('teacher',)
    
    def get_attendance_count(self, obj):
        return obj.get_attendance_count()
    get_attendance_count.short_description = 'Attendance Count'

@admin.register(AttendanceRecord)
class AttendanceRecordAdmin(admin.ModelAdmin):
    list_display = ('student', 'session', 'marked_at', 'ip_address', 'is_on_time')
    list_filter = ('marked_at', 'session__course')
    search_fields = ('student__username', 'session__title')
    readonly_fields = ('marked_at',)
    raw_id_fields = ('session', 'student')
