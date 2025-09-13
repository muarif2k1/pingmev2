from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from chat.models import SupportTicket

class Command(BaseCommand):
    help = 'Clean up old resolved support tickets'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=365,
            help='Delete resolved tickets older than this many days',
        )

    def handle(self, *args, **options):
        days = options['days']
        cutoff_date = timezone.now() - timedelta(days=days)
        
        old_tickets = SupportTicket.objects.filter(
            status__in=['resolved', 'closed'],
            resolved_at__lt=cutoff_date
        )
        
        count = old_tickets.count()
        old_tickets.delete()
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully deleted {count} old support tickets'
            )
        )