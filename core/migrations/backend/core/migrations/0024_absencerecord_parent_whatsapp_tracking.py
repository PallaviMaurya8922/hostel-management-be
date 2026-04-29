from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0023_maintenance_request_attachment"),
    ]

    operations = [
        migrations.AddField(
            model_name="absencerecord",
            name="parent_whatsapp_sent_at",
            field=models.DateTimeField(
                blank=True,
                null=True,
                help_text="When the interactive parent approval WhatsApp was accepted by Meta (not skipped).",
            ),
        ),
        migrations.AddField(
            model_name="absencerecord",
            name="parent_whatsapp_message_id",
            field=models.CharField(
                max_length=128,
                blank=True,
                null=True,
                help_text="WhatsApp Cloud API message id for correlating delivery/read webhooks.",
            ),
        ),
        migrations.AddField(
            model_name="absencerecord",
            name="parent_whatsapp_read_at",
            field=models.DateTimeField(
                blank=True,
                null=True,
                help_text="When Meta reported the parent message as read (webhook status=read only).",
            ),
        ),
    ]