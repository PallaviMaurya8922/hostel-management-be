import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def _normalize_phone(phone: str | None) -> str:
    """Normalize phone number for WhatsApp API.

    Accepts common Indian formats:
    - 10-digit local number: 9876543210 -> 919876543210
    - 12-digit with country code: 919876543210 -> 919876543210
    - Optional '+' and separators are ignored
    """
    if not phone:
        return ""

    digits = "".join(ch for ch in str(phone).strip() if ch.isdigit())

    if len(digits) == 10:
        return f"91{digits}"

    if len(digits) == 12 and digits.startswith("91"):
        return digits

    # Fallback for non-standard formats; let API return validation errors if invalid.
    return digits


def send_leave_request(phone: str | None, leave_id: str, student_name: str) -> dict:
    """Send interactive WhatsApp message to parent for leave approval."""
    normalized_phone = _normalize_phone(phone)
    if not normalized_phone:
        logger.info("Skipping parent WhatsApp request for leave %s: no parent phone", leave_id)
        return {"skipped": True, "reason": "missing_phone"}

    access_token = getattr(settings, "ACCESS_TOKEN", "")
    phone_number_id = getattr(settings, "PHONE_NUMBER_ID", "")

    if not access_token or not phone_number_id:
        logger.warning("Skipping parent WhatsApp request for leave %s: WhatsApp settings not configured", leave_id)
        return {"skipped": True, "reason": "missing_settings"}

    url = f"https://graph.facebook.com/v19.0/{phone_number_id}/messages"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    data = {
        "messaging_product": "whatsapp",
        "to": normalized_phone,
        "type": "interactive",
        "interactive": {
            "type": "button",
            "body": {
                "text": f"Your child {student_name} has applied for leave.\n\nDo you approve this request?"
            },
            "action": {
                "buttons": [
                    {
                        "type": "reply",
                        "reply": {
                            "id": f"approve_leave_{leave_id}",
                            "title": "YES",
                        },
                    },
                    {
                        "type": "reply",
                        "reply": {
                            "id": f"reject_leave_{leave_id}",
                            "title": "NO",
                        },
                    },
                ]
            },
        },
    }

    response = requests.post(url, headers=headers, json=data, timeout=15)
    response.raise_for_status()
    result = response.json()
    logger.info("WhatsApp leave request sent for %s to %s", leave_id, normalized_phone)
    return result


def send_whatsapp_text(phone: str | None, text: str) -> dict:
    """Send plain text WhatsApp message."""
    normalized_phone = _normalize_phone(phone)
    if not normalized_phone:
        return {"skipped": True, "reason": "missing_phone"}

    access_token = getattr(settings, "ACCESS_TOKEN", "")
    phone_number_id = getattr(settings, "PHONE_NUMBER_ID", "")

    if not access_token or not phone_number_id:
        return {"skipped": True, "reason": "missing_settings"}

    url = f"https://graph.facebook.com/v19.0/{phone_number_id}/messages"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    data = {
        "messaging_product": "whatsapp",
        "to": normalized_phone,
        "type": "text",
        "text": {
            "body": text,
        },
    }

    response = requests.post(url, headers=headers, json=data, timeout=15)
    response.raise_for_status()
    return response.json()


def check_token_validity() -> dict:
    """Check if the WhatsApp token is valid by making a test API call."""
    access_token = getattr(settings, "ACCESS_TOKEN", "")
    phone_number_id = getattr(settings, "PHONE_NUMBER_ID", "")

    if not access_token or not phone_number_id:
        return {
            "valid": False,
            "reason": "missing_configuration",
            "message": "WhatsApp access token or phone number ID not configured"
        }

    url = f"https://graph.facebook.com/v19.0/{phone_number_id}"

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return {
                "valid": True,
                "message": "WhatsApp token is valid and active",
                "phone_number_id": phone_number_id,
                "details": response.json()
            }
        elif response.status_code == 401:
            error_data = response.json().get("error", {})
            return {
                "valid": False,
                "reason": "authentication_failed",
                "message": "WhatsApp token is invalid or expired",
                "error": error_data.get("message", "Unknown authentication error"),
                "error_code": error_data.get("code", None)
            }
        else:
            return {
                "valid": False,
                "reason": "api_error",
                "message": f"WhatsApp API returned status {response.status_code}",
                "status_code": response.status_code,
                "response": response.text[:200]
            }
    except requests.exceptions.Timeout:
        return {
            "valid": False,
            "reason": "timeout",
            "message": "WhatsApp API request timed out"
        }
    except requests.exceptions.RequestException as e:
        return {
            "valid": False,
            "reason": "request_error",
            "message": f"Failed to reach WhatsApp API: {str(e)}"
        }


def send_whatsapp_image(phone: str | None, image_url: str, caption: str = None) -> dict:
    """Send image message via WhatsApp.
    
    Args:
        phone: Recipient phone number
        image_url: Public URL of the image (must be accessible to WhatsApp)
        caption: Optional caption for the image
        
    Returns:
        dict: API response or error info
    """
    normalized_phone = _normalize_phone(phone)
    if not normalized_phone:
        return {"skipped": True, "reason": "missing_phone"}

    access_token = getattr(settings, "ACCESS_TOKEN", "")
    phone_number_id = getattr(settings, "PHONE_NUMBER_ID", "")

    if not access_token or not phone_number_id:
        return {"skipped": True, "reason": "missing_settings"}

    url = f"https://graph.facebook.com/v19.0/{phone_number_id}/messages"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    data = {
        "messaging_product": "whatsapp",
        "to": normalized_phone,
        "type": "image",
        "image": {
            "link": image_url,
        },
    }
    
    if caption:
        data["image"]["caption"] = caption

    try:
        response = requests.post(url, headers=headers, json=data, timeout=15)
        response.raise_for_status()
        result = response.json()
        logger.info(f"WhatsApp image sent to {normalized_phone}")
        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send WhatsApp image to {normalized_phone}: {str(e)}")
        return {
            "error": True,
            "message": f"Failed to send WhatsApp image: {str(e)}"
        }
