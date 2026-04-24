"""
QR Image Generation Service
Handles creation and storage of QR code images for guest verification
"""

import os
import logging
from io import BytesIO
from pathlib import Path

try:
    import qrcode
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage

logger = logging.getLogger(__name__)


class QRImageService:
    """Service for generating and managing QR code images"""
    
    def __init__(self):
        self.qr_folder = 'qr_codes'
        self.media_root = settings.MEDIA_ROOT
        self.media_url = settings.MEDIA_URL
        
    def generate_qr_image(self, data, filename_prefix='qr_'):
        """
        Generate a QR code image and save it to media storage
        
        Args:
            data: String data to encode in QR code
            filename_prefix: Prefix for the generated file
            
        Returns:
            dict: {
                'success': bool,
                'file_path': str (relative path in media),
                'file_url': str (public URL for WhatsApp),
                'error': str (if failed)
            }
        """
        if not QR_AVAILABLE:
            logger.error("qrcode library not available")
            return {
                'success': False,
                'file_path': None,
                'file_url': None,
                'error': 'QR code generation library not available'
            }
        
        try:
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Save to BytesIO
            img_io = BytesIO()
            img.save(img_io, format='PNG')
            img_io.seek(0)
            
            # Generate filename
            import uuid
            unique_id = str(uuid.uuid4())[:8]
            filename = f"{filename_prefix}{unique_id}.png"
            file_path = f"{self.qr_folder}/{filename}"
            
            # Save to Django's storage system
            saved_path = default_storage.save(file_path, ContentFile(img_io.read()))
            
            # Generate public URL
            file_url = f"{settings.MEDIA_URL}{saved_path}"
            
            logger.info(f"QR image generated successfully: {saved_path}")
            
            return {
                'success': True,
                'file_path': saved_path,
                'file_url': file_url,
                'error': None
            }
            
        except Exception as e:
            logger.error(f"Failed to generate QR image: {str(e)}")
            return {
                'success': False,
                'file_path': None,
                'file_url': None,
                'error': str(e)
            }
    
    def delete_qr_image(self, file_path):
        """Delete a QR image file"""
        try:
            if default_storage.exists(file_path):
                default_storage.delete(file_path)
                logger.info(f"QR image deleted: {file_path}")
                return True
        except Exception as e:
            logger.warning(f"Failed to delete QR image {file_path}: {str(e)}")
        return False


# Singleton instance
qr_image_service = QRImageService()
