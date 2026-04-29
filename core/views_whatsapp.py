import json
import logging

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from core.models import AbsenceRecord
from core.services.whatsapp_service import send_whatsapp_text, check_token_validity

logger = logging.getLogger(__name__)


def whatsapp_verify(request):
    """Webhook verification endpoint for Meta WhatsApp Cloud API."""
    mode = request.GET.get("hub.mode")
    token = request.GET.get("hub.verify_token")
    challenge = request.GET.get("hub.challenge")

    if mode == "subscribe" and token == settings.VERIFY_TOKEN:
        return HttpResponse(challenge, status=200)

    return HttpResponse("Verification failed", status=403)


def _handle_whatsapp_statuses(value: dict) -> None:
    """Persist read time when Meta sends status=read for a tracked outbound message."""
    statuses = value.get("statuses")
    if not isinstance(statuses, list):
        return
    for st in statuses:
        if not isinstance(st, dict):
            continue
        if st.get("status") != "read":
            continue
        mid = st.get("id")
        if not mid:
            continue
        mid_str = str(mid)[:128]
        updated = AbsenceRecord.objects.filter(
            parent_whatsapp_message_id=mid_str,
            parent_whatsapp_read_at__isnull=True,
        ).update(parent_whatsapp_read_at=timezone.now())
        if updated:
            logger.info("WhatsApp read receipt stored for absence message_id=%s", mid_str)


@csrf_exempt
def whatsapp_webhook(request):
    """Unified webhook endpoint for Meta verification (GET) and callbacks (POST)."""
    if request.method == "GET":
        return whatsapp_verify(request)

    if request.method != "POST":
        return JsonResponse({"status": "method_not_allowed"}, status=405)

    try:
        data = json.loads(request.body or "{}")
        entry = data.get("entry")
        if not isinstance(entry, list) or not entry:
            return JsonResponse({"status": "ignored"})

        changes = entry[0].get("changes")
        if not isinstance(changes, list) or not changes:
            return JsonResponse({"status": "ignored"})

        value = changes[0].get("value") or {}
        if not isinstance(value, dict):
            return JsonResponse({"status": "ignored"})

        _handle_whatsapp_statuses(value)

        if "messages" not in value:
            return JsonResponse({"status": "ok"})

        msg = value["messages"][0]
        phone = msg.get("from")

        if msg.get("type") != "interactive":
            return JsonResponse({"status": "ignored"})

        button_id = msg["interactive"]["button_reply"]["id"]

        if button_id.startswith("approve_leave_"):
            leave_id = button_id.replace("approve_leave_", "", 1)
            updated = AbsenceRecord.objects.filter(
                absence_id=leave_id,
                parent_approval__isnull=True,
                status="pending",
            ).update(
                parent_approval=True,
                parent_response_at=timezone.now(),
            )
            if updated and phone:
                send_whatsapp_text(phone, "Thank you. You approved the leave request. The warden will review it now.")

        elif button_id.startswith("reject_leave_"):
            leave_id = button_id.replace("reject_leave_", "", 1)
            updated = AbsenceRecord.objects.filter(
                absence_id=leave_id,
                parent_approval__isnull=True,
                status="pending",
            ).update(
                parent_approval=False,
                parent_response_at=timezone.now(),
                status="rejected",
                approval_reason="Rejected by parent on WhatsApp",
            )
            if updated and phone:
                send_whatsapp_text(phone, "Thank you. You rejected the leave request. The request is now closed.")

        return JsonResponse({"status": "ok"})

    except Exception as exc:
        logger.error("WhatsApp webhook error: %s", exc)
        return JsonResponse({"status": "ok"})


def check_whatsapp_token(request):
    """Check if the WhatsApp token is valid."""
    if request.method != "GET":
        return JsonResponse({"error": "GET method required"}, status=405)

    result = check_token_validity()

    status_code = 200 if result.get("valid") else 400

    return JsonResponse(result, status=status_code)