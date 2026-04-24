"""
PDF Generation Service for Digital Passes
Handles creation of professional PDF passes for approved leave requests using HTML templates.
"""

import os
import logging
import base64
from datetime import datetime
from typing import Optional, Tuple
from io import BytesIO

try:
    import qrcode
    import qrcode.image.svg
    QR_CODE_AVAILABLE = True
except ImportError:
    QR_CODE_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("QR code library not available")

# Make WeasyPrint import optional and suppress warnings
WEASYPRINT_AVAILABLE = False
HTML = None
CSS = None
FontConfiguration = None

try:
    import warnings
    import sys
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore")
        # Suppress stderr output during import
        old_stderr = sys.stderr
        sys.stderr = open(os.devnull, 'w')
        try:
            from weasyprint import HTML, CSS
            from weasyprint.text.fonts import FontConfiguration
            WEASYPRINT_AVAILABLE = True
        finally:
            sys.stderr.close()
            sys.stderr = old_stderr
except Exception as e:
    # WeasyPrint or its dependencies not available (expected on serverless)
    pass

from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.urls import reverse
from ..models import DigitalPass, Student

logger = logging.getLogger(__name__)


class PDFGenerationService:
    """Service for generating professional PDF passes using HTML templates"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        if not WEASYPRINT_AVAILABLE:
            self.logger.warning("WeasyPrint not available. PDF generation will use fallback method.")
    
    def generate_pass_pdf(self, digital_pass: DigitalPass) -> Tuple[bool, Optional[str], Optional[bytes]]:
        """
        Generate PDF for a digital pass using HTML template
        """
        try:
            # Generate QR code data
            qr_code_data, qr_code_mime = self._generate_qr_code(digital_pass)
            student_photo_data, student_photo_mime = self._get_student_photo_base64(digital_pass.student)
            student_initials = self._get_student_initials(digital_pass.student.name)
 
            # Prepare context for template
            context = {
                'digital_pass': digital_pass,
                'student': digital_pass.student,
                'qr_code_data': qr_code_data,
                'qr_code_mime': qr_code_mime,
                'student_photo_data': student_photo_data,
                'student_photo_mime': student_photo_mime,
                'student_initials': student_initials,
                'warden_name': digital_pass.approved_by.name if digital_pass.approved_by else 'Warden',
                'hostel_name': getattr(settings, 'HOSTEL_NAME', 'Student Hostel'),
                'now': timezone.now(),
            }
 
            # Render HTML template
            try:
                html_content = render_to_string('passes/digital_pass_template.html', context)
            except Exception as e:
                self.logger.error(f"Error rendering template: {e}")
                return False, None, None
 
            # ── ATTEMPT 1: WeasyPrint ──────────────────────────────────────
            pdf_bytes = None
            if WEASYPRINT_AVAILABLE:
                try:
                    pdf_bytes = self._generate_pdf_with_weasyprint(html_content)
                    if pdf_bytes:
                        self.logger.info(f"PDF generated with WeasyPrint for pass {digital_pass.pass_number}")
                except Exception as e:
                    self.logger.error(f"WeasyPrint generation failed: {e}")
 
            # ── ATTEMPT 2: wkhtmltopdf fallback ───────────────────────────
            if not pdf_bytes:
                self.logger.warning(f"WeasyPrint failed for {digital_pass.pass_number}, trying wkhtmltopdf")
                try:
                    pdf_bytes = self._generate_pdf_with_wkhtmltopdf(html_content)
                    if pdf_bytes:
                        self.logger.info(f"PDF generated with wkhtmltopdf for pass {digital_pass.pass_number}")
                except Exception as e:
                    self.logger.error(f"wkhtmltopdf generation failed: {e}")
 
            # ── HARD FAIL — no silent HTML fallback ───────────────────────
            if not pdf_bytes:
                self.logger.error(f"All PDF methods failed for pass {digital_pass.pass_number}")
                return False, None, None
 
            # Save to file system
            try:
                file_path = self._save_pdf_to_file(digital_pass, pdf_bytes)
            except Exception as e:
                self.logger.error(f"Error saving PDF to file: {e}")
                return False, None, None
 
            # Update digital pass record
            try:
                digital_pass.pdf_generated = True
                digital_pass.pdf_path = file_path
                digital_pass.save()
            except Exception as e:
                self.logger.error(f"Error saving digital pass record: {e}")
                return True, file_path, pdf_bytes
 
            self.logger.info(f"PDF generated successfully for pass {digital_pass.pass_number}")
            return True, file_path, pdf_bytes
 
        except Exception as e:
            self.logger.error(f"Error generating PDF for pass {digital_pass.pass_number}: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False, None, None
        

    def _generate_qr_code(self, digital_pass: DigitalPass) -> Tuple[Optional[str], Optional[str]]:
        """Generate QR code for the digital pass"""
        if not QR_CODE_AVAILABLE:
            return None, None
        
        try:
            # QR payload includes fields required for instant guard-side verification.
            token = (digital_pass.verification_code or '').strip()

            # Human-readable payload so common QR scanner apps show details at a glance.
            qr_lines = [
                "Hostel Digital Leave Pass",
                f"Pass Number: {digital_pass.pass_number}",
                f"Student ID: {digital_pass.student.student_id}",
                f"Valid From: {digital_pass.from_date.isoformat()}",
                f"Valid To: {digital_pass.to_date.isoformat()}",
            ]
            if token:
                qr_lines.append(f"Verification Code: {token}")
            qr_data = "\n".join(qr_lines)
            
            # Create QR code with auto-adjustment
            qr = qrcode.QRCode(
                version=None,  # Auto-detect appropriate version
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=24,
                border=4,
            )
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            try:
                # Preferred path: PNG QR for wide compatibility.
                qr_img = qr.make_image(fill_color="black", back_color="white")
                buffer = BytesIO()
                qr_img.save(buffer, format='PNG')
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                buffer.close()
                return qr_code_base64, 'image/png'
            except Exception:
                # Fallback path when PIL backend is unavailable: generate SVG QR.
                qr_svg = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
                buffer = BytesIO()
                qr_svg.save(buffer)
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                buffer.close()
                return qr_code_base64, 'image/svg+xml'
            
        except Exception as e:
            self.logger.error(f"Error generating QR code: {e}")
            return None, None

    def _get_verify_pass_path(self) -> str:
        """Resolve verify-pass endpoint path with safe fallbacks."""
        try:
            return reverse('core:verify_digital_pass')
        except Exception:
            pass

        try:
            return reverse('verify_digital_pass')
        except Exception:
            # Final fallback keeps QR generation working even if URL names change.
            return '/api/verify-pass/'

    def _get_student_photo_base64(self, student: Student) -> Tuple[Optional[str], Optional[str]]:
        """Embed student profile photo as base64 so pass preview/PDF works everywhere."""
        try:
            if not student.profile_photo:
                return None, None

            with student.profile_photo.open('rb') as photo_file:
                encoded = base64.b64encode(photo_file.read()).decode()

            ext = os.path.splitext(student.profile_photo.name)[1].lower()
            mime_by_ext = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.webp': 'image/webp',
                '.gif': 'image/gif',
            }
            mime_type = mime_by_ext.get(ext, 'image/jpeg')
            return encoded, mime_type
        except Exception as e:
            self.logger.warning(f"Could not load profile photo for {student.student_id}: {e}")
            return None, None

    def _get_student_initials(self, student_name: str) -> str:
        """Compute initials for avatar fallback when no profile photo exists."""
        if not student_name:
            return 'ST'

        parts = [part for part in student_name.strip().split() if part]
        if not parts:
            return 'ST'

        initials = ''.join(part[0].upper() for part in parts[:2])
        return initials or 'ST'
    
    def _generate_pdf_with_weasyprint(self, html_content: str) -> Optional[bytes]:
        """Generate PDF using WeasyPrint - template already has styling"""
        try:
            from weasyprint import HTML
            from io import BytesIO
            
            pdf_buffer = BytesIO()
            
            # FIXED: added base_url + presentational_hints=True
            HTML(
                string=html_content,
                base_url=str(settings.BASE_DIR)      
            ).write_pdf(
                pdf_buffer,
                presentational_hints=True              # ← ADD: honours your @page { size: 960px 580px }
            )
            
            pdf_bytes = pdf_buffer.getvalue()
            pdf_buffer.close()
            
            if pdf_bytes and len(pdf_bytes) > 0:
                self.logger.info(f"PDF generated successfully ({len(pdf_bytes)} bytes)")
                return pdf_bytes
            else:
                self.logger.error("WeasyPrint produced empty PDF")
                return None
        except Exception as e:
            self.logger.error(f"Error generating PDF: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return None
    
    def _generate_pdf_with_reportlab(self, digital_pass: DigitalPass) -> Tuple[bool, Optional[str], Optional[bytes]]:
        """Fallback PDF generation using ReportLab (original method)"""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        try:
            # Create PDF in memory
            buffer = BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            # Setup styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=HexColor('#1f2937'),
                fontName='Helvetica-Bold'
            )
            
            # Build PDF content
            story = []
            
            # Header
            title = Paragraph("HOSTEL LEAVE PASS", title_style)
            story.append(title)
            story.append(Spacer(1, 20))
            
            # Pass info
            pass_info = f"<b>Pass Number:</b> {digital_pass.pass_number}"
            if digital_pass.verification_code:
                pass_info += f" | <b>Verification Code:</b> {digital_pass.verification_code}"
            
            story.append(Paragraph(pass_info, styles['Heading2']))
            story.append(Spacer(1, 20))
            
            # Student information
            student = digital_pass.student
            student_data = [
                ['Name:', student.name],
                ['Student ID:', student.student_id],
                ['Room:', f"{student.room_number}, Block {student.block}"],
                ['Leave From:', digital_pass.from_date.strftime('%d %B %Y')],
                ['Return On:', digital_pass.to_date.strftime('%d %B %Y')],
                ['Duration:', f"{digital_pass.total_days} day{'s' if digital_pass.total_days > 1 else ''}"],
                ['Reason:', digital_pass.reason],
                ['Status:', digital_pass.get_status_display()],
            ]
            
            table = Table(student_data, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            story.append(table)
            story.append(Spacer(1, 30))
            
            # Footer
            footer_text = f"""
            Generated on: {timezone.now().strftime('%d %B %Y at %I:%M %p')}<br/>
            This is a computer-generated document. No signature required.
            """
            story.append(Paragraph(footer_text, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            
            # Get PDF bytes
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            # Save to file system
            file_path = self._save_pdf_to_file(digital_pass, pdf_bytes)
            
            # Update digital pass record
            digital_pass.pdf_generated = True
            digital_pass.pdf_path = file_path
            digital_pass.save()
            
            return True, file_path, pdf_bytes
            
        except Exception as e:
            self.logger.error(f"Error generating PDF with ReportLab: {e}")
            return False, None, None
    
    def _save_pdf_to_file(self, digital_pass: DigitalPass, pdf_bytes: bytes) -> str:
        """Save PDF bytes to file system"""
        # Create passes directory if it doesn't exist
        passes_dir = os.path.join(settings.MEDIA_ROOT, 'passes')
        os.makedirs(passes_dir, exist_ok=True)
        
        # Detect if this is HTML or PDF based on content
        is_html = pdf_bytes.startswith(b'<!DOCTYPE html') or pdf_bytes.startswith(b'<html')
        
        # Generate filename with appropriate extension
        if is_html:
            filename = f"pass_{digital_pass.pass_number}_{digital_pass.student.student_id}.html"
        else:
            filename = f"pass_{digital_pass.pass_number}_{digital_pass.student.student_id}.pdf"
        
        file_path = os.path.join(passes_dir, filename)
        
        # Write to file
        with open(file_path, 'wb') as f:
            f.write(pdf_bytes)
        
        # Return relative path for database storage
        return os.path.join('passes', filename)
    
    def generate_pass_html(self, digital_pass: DigitalPass) -> str:
        """Generate HTML version of the pass for preview"""
        try:
            # Generate QR code data
            qr_code_data, qr_code_mime = self._generate_qr_code(digital_pass)
            student_photo_data, student_photo_mime = self._get_student_photo_base64(digital_pass.student)
            student_initials = self._get_student_initials(digital_pass.student.name)
            
            # Prepare context for template
            context = {
                'digital_pass': digital_pass,
                'student': digital_pass.student,
                'qr_code_data': qr_code_data,
                'qr_code_mime': qr_code_mime,
                'student_photo_data': student_photo_data,
                'student_photo_mime': student_photo_mime,
                'student_initials': student_initials,
                'warden_name': digital_pass.approved_by.name if digital_pass.approved_by else 'Warden',
                'hostel_name': getattr(settings, 'HOSTEL_NAME', 'Student Hostel'),
                'now': timezone.now(),
            }
            
            # Render HTML template
            html_content = render_to_string('passes/digital_pass_template.html', context)
            return html_content
            
        except Exception as e:
            self.logger.error(f"Error generating HTML for pass {digital_pass.pass_number}: {e}")
            return f"<html><body><h1>Error generating pass</h1><p>{str(e)}</p></body></html>"
    
    def get_pdf_file_path(self, digital_pass: DigitalPass) -> Optional[str]:
        """Get full file path for a digital pass PDF"""
        if not digital_pass.pdf_path:
            return None
        
        return os.path.join(settings.MEDIA_ROOT, digital_pass.pdf_path)
    
    def pdf_exists(self, digital_pass: DigitalPass) -> bool:
        """Check if PDF file exists on disk"""
        if not digital_pass.pdf_path:
            return False
        
        file_path = self.get_pdf_file_path(digital_pass)
        return file_path and os.path.exists(file_path)


# Global service instance
pdf_generation_service = PDFGenerationService()