"""
Simple Daily Summary Generator for basic hostel reporting.
Generates simple daily summaries for wardens.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from django.utils import timezone
from django.db.models import Q, Count
from core.models import Student, Staff, GuestRequest, AbsenceRecord, MaintenanceRequest


@dataclass
class SimpleDailySummary:
    """Simple daily summary data structure"""
    date: datetime
    total_absent: int
    active_guests: int
    pending_maintenance: int
    urgent_items: List[str]
    generated_at: datetime


class SimpleDailySummaryGenerator:
    """Simple service for generating basic daily summaries"""
    
    def __init__(self):
        self.current_date = timezone.now().date()
    
    def generate_morning_summary(self, date: Optional[datetime] = None) -> SimpleDailySummary:
        """Generate simple morning summary."""
        if date:
            self.current_date = date.date()
        
        # Count active absences
        active_absences = AbsenceRecord.objects.filter(
            status='approved',
            start_date__lte=timezone.now(),
            end_date__gte=timezone.now()
        ).count()
        
        # Count active guests
        active_guests = GuestRequest.objects.filter(
            status='approved',
            start_date__lte=timezone.now(),
            end_date__gte=timezone.now()
        ).count()
        
        # Count pending maintenance
        pending_maintenance = MaintenanceRequest.objects.filter(
            status='pending'
        ).count()
        
        # Simple urgent items
        urgent_items = []
        emergency_maintenance = MaintenanceRequest.objects.filter(
            status='pending',
            priority='emergency'
        ).count()
        
        if emergency_maintenance > 0:
            urgent_items.append(f"{emergency_maintenance} emergency maintenance requests")
        
        return SimpleDailySummary(
            date=timezone.now(),
            total_absent=active_absences,
            active_guests=active_guests,
            pending_maintenance=pending_maintenance,
            urgent_items=urgent_items,
            generated_at=timezone.now()
        )
    
    def format_summary_for_display(self, summary: SimpleDailySummary) -> str:
        """Format summary for simple display."""
        formatted = f"""
Daily Hostel Summary - {summary.date.strftime('%Y-%m-%d')}

Students currently absent: {summary.total_absent}
Active guests: {summary.active_guests}
Pending maintenance requests: {summary.pending_maintenance}

Urgent items:
"""
        if summary.urgent_items:
            for item in summary.urgent_items:
                formatted += f"- {item}\n"
        else:
            formatted += "- None\n"
        
        return formatted


# Create simple instance
daily_summary_generator = SimpleDailySummaryGenerator()