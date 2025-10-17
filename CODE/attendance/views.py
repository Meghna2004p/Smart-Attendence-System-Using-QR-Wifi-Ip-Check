from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.conf import settings
from datetime import timedelta
import json
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO

from .models import (
    AttendanceSession, AttendanceRecord, Course, 
    Enrollment, CampusSubnet
)
from .utils import (
    generate_qr_token, create_qr_code, validate_campus_subnet,
    get_client_ip, get_user_agent, is_token_valid, update_session_qr_token
)

@login_required
def dashboard(request):
    """Main dashboard - redirect based on user role"""
    if request.user.is_admin():
        return redirect('attendance:admin_dashboard')
    elif request.user.is_teacher():
        return redirect('attendance:teacher_dashboard')
    elif request.user.is_student():
        return redirect('attendance:student_dashboard')
    else:
        messages.error(request, 'Invalid user role.')
        return redirect('accounts:login')

# TEACHER VIEWS
@login_required
def teacher_dashboard(request):
    """Teacher dashboard showing courses and sessions"""
    if not request.user.is_teacher():
        messages.error(request, 'Access denied. Teachers only.')
        return redirect('attendance:dashboard')
    
    courses = Course.objects.filter(teacher=request.user, is_active=True)
    recent_sessions = AttendanceSession.objects.filter(
        teacher=request.user
    ).order_by('-start_time')[:10]
    
    context = {
        'courses': courses,
        'recent_sessions': recent_sessions,
    }
    return render(request, 'attendance/teacher_dashboard.html', context)

@login_required
def create_session(request):
    """Create new attendance session"""
    if not request.user.is_teacher():
        messages.error(request, 'Access denied. Teachers only.')
        return redirect('attendance:dashboard')
    
    courses = Course.objects.filter(teacher=request.user, is_active=True)
    
    if request.method == 'POST':
        course_id = request.POST.get('course')
        title = request.POST.get('title')
        location = request.POST.get('location', '')
        duration_minutes = int(request.POST.get('duration', 60))
        
        course = get_object_or_404(Course, id=course_id, teacher=request.user)
        
        # Create session
        start_time = timezone.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        qr_expires_at = start_time + timedelta(minutes=settings.QR_CODE_EXPIRY_MINUTES)
        
        session = AttendanceSession.objects.create(
            course=course,
            teacher=request.user,
            title=title,
            location=location,
            start_time=start_time,
            end_time=end_time,
            qr_token=generate_qr_token(None),  # Will be updated with actual session ID
            qr_expires_at=qr_expires_at
        )
        
        # Update with proper token using session ID
        update_session_qr_token(session)
        
        messages.success(request, f'Attendance session "{title}" created successfully!')
        return redirect('attendance:session_detail', session_id=session.id)
    
    context = {'courses': courses}
    return render(request, 'attendance/create_session.html', context)

@login_required
def session_detail(request, session_id):
    """Session detail view for teachers"""
    session = get_object_or_404(AttendanceSession, id=session_id)
    
    if not request.user.is_teacher() or session.teacher != request.user:
        messages.error(request, 'Access denied.')
        return redirect('attendance:dashboard')
    
    # Get attendance records
    attendance_records = AttendanceRecord.objects.filter(
        session=session
    ).select_related('student').order_by('-marked_at')
    
    # Generate QR code URL
    qr_url = request.build_absolute_uri(
        reverse('attendance:mark_attendance', kwargs={
            'session_id': session.id,
            'token': session.qr_token
        })
    )
    
    qr_image = create_qr_code(qr_url)
    
    context = {
        'session': session,
        'attendance_records': attendance_records,
        'qr_image': qr_image,
        'qr_url': qr_url,
    }
    return render(request, 'attendance/session_detail.html', context)

@login_required
def refresh_qr(request, session_id):
    """Refresh QR code token for a session"""
    session = get_object_or_404(AttendanceSession, id=session_id)
    
    if not request.user.is_teacher() or session.teacher != request.user:
        return JsonResponse({'error': 'Access denied'}, status=403)
    
    # Update token
    new_token = update_session_qr_token(session)
    
    # Generate new QR code
    qr_url = request.build_absolute_uri(
        reverse('attendance:mark_attendance', kwargs={
            'session_id': session.id,
            'token': new_token
        })
    )
    
    qr_image = create_qr_code(qr_url)
    
    return JsonResponse({
        'qr_image': qr_image,
        'qr_url': qr_url,
        'expires_at': session.qr_expires_at.isoformat()
    })

# STUDENT VIEWS
@login_required
def student_dashboard(request):
    """Student dashboard showing attendance history"""
    if not request.user.is_student():
        messages.error(request, 'Access denied. Students only.')
        return redirect('attendance:dashboard')
    
    # Get student enrollments and recent attendance
    enrollments = Enrollment.objects.filter(
        student=request.user
    ).select_related('course')
    
    recent_attendance = AttendanceRecord.objects.filter(
        student=request.user
    ).select_related('session__course').order_by('-marked_at')[:10]
    
    context = {
        'enrollments': enrollments,
        'recent_attendance': recent_attendance,
    }
    return render(request, 'attendance/student_dashboard.html', context)

@csrf_exempt
def mark_attendance(request, session_id, token):
    """Mark attendance for student with dual authentication"""
    try:
        # Get session
        session = get_object_or_404(AttendanceSession, id=session_id)
        
        # Validate token
        if not is_token_valid(token, session_id):
            if request.method == 'GET':
                context = {
                    'error': 'Invalid or expired QR code. Please ask your teacher for a new one.',
                    'session': session
                }
                return render(request, 'attendance/attendance_error.html', context)
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired QR code. Please ask your teacher for a new one.'
            }, status=400)
        
        # Check if user is authenticated
        if not request.user.is_authenticated:
            if request.method == 'GET':
                # Redirect to login with next parameter
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(request.get_full_path())
            return JsonResponse({
                'success': False,
                'error': 'Please log in to mark attendance.'
            }, status=401)
        
        if not request.user.is_student():
            error_msg = 'Only students can mark attendance.'
            if request.method == 'GET':
                context = {
                    'error': error_msg,
                    'session': session
                }
                return render(request, 'attendance/attendance_error.html', context)
            return JsonResponse({
                'success': False,
                'error': error_msg
            }, status=403)
        
        # Check if student is enrolled in the course
        if not Enrollment.objects.filter(student=request.user, course=session.course).exists():
            error_msg = 'You are not enrolled in this course.'
            if request.method == 'GET':
                context = {
                    'error': error_msg,
                    'session': session
                }
                return render(request, 'attendance/attendance_error.html', context)
            return JsonResponse({
                'success': False,
                'error': error_msg
            }, status=403)
        
        # Check if attendance already marked
        if AttendanceRecord.objects.filter(session=session, student=request.user).exists():
            success_msg = f'Attendance already marked for {session.course.name}.'
            if request.method == 'GET':
                context = {
                    'success': True,
                    'message': success_msg,
                    'session': session,
                    'student': request.user
                }
                return render(request, 'attendance/attendance_success.html', context)
            return JsonResponse({
                'success': False,
                'error': success_msg
            }, status=400)
        
        # For GET request, show confirmation page
        if request.method == 'GET':
            context = {
                'session': session,
                'student': request.user,
                'token': token
            }
            return render(request, 'attendance/mark_attendance.html', context)
        
        # For POST request, actually mark the attendance
        # Validate campus WiFi subnet
        client_ip = get_client_ip(request)
        if not validate_campus_subnet(client_ip):
            return JsonResponse({
                'success': False,
                'error': 'Attendance can only be marked from campus WiFi network.'
            }, status=403)
        
        # Mark attendance
        attendance_record = AttendanceRecord.objects.create(
            session=session,
            student=request.user,
            ip_address=client_ip,
            user_agent=get_user_agent(request)
        )
        
        success_msg = f'Attendance marked successfully for {session.course.name}!'
        
        # Return appropriate response based on request type
        if request.META.get('HTTP_ACCEPT', '').startswith('application/json'):
            return JsonResponse({
                'success': True,
                'message': success_msg,
                'course_name': session.course.name,
                'session_title': session.title,
                'marked_at': attendance_record.marked_at.isoformat()
            })
        else:
            # For regular form submission, show success page
            context = {
                'success': True,
                'message': success_msg,
                'session': session,
                'student': request.user,
                'attendance_record': attendance_record
            }
            return render(request, 'attendance/attendance_success.html', context)
        
    except Exception as e:
        error_msg = 'An error occurred while marking attendance. Please try again.'
        if request.method == 'GET':
            context = {
                'error': error_msg,
                'session': None
            }
            return render(request, 'attendance/attendance_error.html', context)
        return JsonResponse({
            'success': False,
            'error': error_msg
        }, status=500)

# ADMIN VIEWS
@login_required
def admin_dashboard(request):
    """Admin dashboard with system overview"""
    if not request.user.is_admin():
        messages.error(request, 'Access denied. Admins only.')
        return redirect('attendance:dashboard')
    
    # Get statistics
    total_courses = Course.objects.filter(is_active=True).count()
    total_students = request.user.__class__.objects.filter(role='student').count()
    total_teachers = request.user.__class__.objects.filter(role='teacher').count()
    
    # Get subnet statistics
    total_subnets = CampusSubnet.objects.count()
    active_subnets = CampusSubnet.objects.filter(is_active=True).count()
    inactive_subnets = total_subnets - active_subnets
    
    recent_sessions = AttendanceSession.objects.select_related(
        'course', 'teacher'
    ).order_by('-start_time')[:10]
    
    context = {
        'total_courses': total_courses,
        'total_students': total_students,
        'total_teachers': total_teachers,
        'total_subnets': total_subnets,
        'active_subnets': active_subnets,
        'inactive_subnets': inactive_subnets,
        'recent_sessions': recent_sessions,
    }
    return render(request, 'attendance/admin_dashboard.html', context)

# PDF EXPORT VIEWS
@login_required
def export_session_pdf(request, session_id):
    """Export attendance session as PDF"""
    session = get_object_or_404(AttendanceSession, id=session_id)
    
    # Check permissions
    if not (request.user.is_admin() or 
            (request.user.is_teacher() and session.teacher == request.user)):
        messages.error(request, 'Access denied.')
        return redirect('attendance:dashboard')
    
    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph(
        f"Attendance Report - {session.course.code}",
        styles['Title']
    )
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Session details
    details = [
        f"Course: {session.course.name} ({session.course.code})",
        f"Session: {session.title}",
        f"Teacher: {session.teacher.get_full_name() or session.teacher.username}",
        f"Date: {session.start_time.strftime('%Y-%m-%d')}",
        f"Time: {session.start_time.strftime('%H:%M')} - {session.end_time.strftime('%H:%M')}",
        f"Location: {session.location or 'Not specified'}",
    ]
    
    for detail in details:
        story.append(Paragraph(detail, styles['Normal']))
    
    story.append(Spacer(1, 12))
    
    # Attendance records
    attendance_records = AttendanceRecord.objects.filter(
        session=session
    ).select_related('student').order_by('student__username')
    
    if attendance_records:
        # Create table
        data = [['Student ID', 'Student Name', 'Marked At', 'Status']]
        
        for record in attendance_records:
            status = 'On Time' if record.is_on_time else 'Late'
            data.append([
                record.student.student_id or 'N/A',
                record.student.get_full_name() or record.student.username,
                record.marked_at.strftime('%Y-%m-%d %H:%M'),
                status
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        
        # Summary
        story.append(Spacer(1, 12))
        total_enrolled = session.get_enrolled_students_count()
        total_present = attendance_records.count()
        attendance_percentage = (total_present / total_enrolled * 100) if total_enrolled > 0 else 0
        
        summary_text = f"Summary: {total_present}/{total_enrolled} students present ({attendance_percentage:.1f}%)"
        story.append(Paragraph(summary_text, styles['Normal']))
    else:
        story.append(Paragraph("No attendance records found.", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    # Return response
    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    filename = f"attendance_{session.course.code}_{session.start_time.strftime('%Y%m%d_%H%M')}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response

@login_required
def live_attendance_updates(request, session_id):
    """Get live attendance updates for a session (AJAX endpoint)"""
    session = get_object_or_404(AttendanceSession, id=session_id)
    
    if not (request.user.is_teacher() and session.teacher == request.user):
        return JsonResponse({'error': 'Access denied'}, status=403)
    
    attendance_records = AttendanceRecord.objects.filter(
        session=session
    ).select_related('student').order_by('-marked_at')
    
    records_data = []
    for record in attendance_records:
        records_data.append({
            'student_name': record.student.get_full_name() or record.student.username,
            'student_id': record.student.student_id or 'N/A',
            'marked_at': record.marked_at.strftime('%H:%M:%S'),
            'is_on_time': record.is_on_time
        })
    
    return JsonResponse({
        'records': records_data,
        'total_count': len(records_data),
        'session_active': session.is_active()
    })
