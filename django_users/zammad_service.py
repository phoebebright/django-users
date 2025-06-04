from zammad_py import ZammadAPI
from django.conf import settings
from django.utils import timezone
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class ZammadService:
    def __init__(self):
        zammad_config = getattr(settings, 'ZAMMAD', {})

        self.zammad_url = zammad_config.get('url', '')
        self.zammad_host = zammad_config.get('host', '')
        self.api_token = zammad_config.get('http_token', '')

        if not self.zammad_url or not self.api_token:
            raise ValueError("ZAMMAD settings must include 'url' and 'http_token'")

        # Extract base URL for zammad_py (it expects the base URL, not the API endpoint)
        base_url = self.zammad_host or self.zammad_url.replace('/api/v1', '')

        self.client = ZammadAPI(
            url=base_url,
            http_token=self.api_token,
        )

    def create_or_get_user(self, django_user) -> Optional[Dict[str, Any]]:
        """Create or get user in Zammad"""
        try:
            # First, try to find existing user by email
            users = self.client.user.search(query=f'email:{django_user.email}')
            if users:
                return users[0]

            # If not found, create new user
            user_data = {
                'email': django_user.email,
                'firstname': django_user.first_name or 'Unknown',
                'lastname': django_user.last_name or 'User',
                'active': True,
                'note': f'Created from Django app for user ID: {django_user.id}',
            }

            # Add optional fields if they exist on your user model
            if hasattr(django_user, 'phone') and django_user.phone:
                user_data['phone'] = str(django_user.phone)

            if hasattr(django_user, 'organization') and django_user.organization:
                user_data['organization'] = str(django_user.organization)

            zammad_user = self.client.user.create(user_data)
            logger.info(f"Created Zammad user {zammad_user['id']} for Django user {django_user.id}")
            return zammad_user

        except Exception as e:
            logger.error(f"Error creating/getting Zammad user for {django_user.email}: {e}")
            return None

    def create_ticket(self, ticket_contact: 'ZammadTicketContact') -> bool:
        """Create ticket in Zammad and update the local object"""
        try:
            # Ensure user exists in Zammad
            zammad_user = self.create_or_get_user(ticket_contact.user)
            if not zammad_user:
                ticket_contact.sync_status = 'failed'
                ticket_contact.save()
                return False

            # Prepare ticket data
            ticket_data = {
                'title': ticket_contact.title,
                'group': ticket_contact.group_name,
                'customer_id': zammad_user['id'],
                'priority_id': int(ticket_contact.priority),
                'state': 'new',
                'article': {
                    'subject': ticket_contact.title,
                    'body': ticket_contact.notes or 'No additional details provided.',
                    'type': 'web',
                    'sender': 'Customer',
                    'internal': False,
                }
            }

            # Add custom attributes to ticket
            if ticket_contact.attributes:
                ticket_data.update(ticket_contact.attributes)

            # Add site information if provided
            if ticket_contact.site:
                ticket_data['note'] = f"Site: {ticket_contact.site}"

            # Create ticket in Zammad
            zammad_ticket = self.client.ticket.create(ticket_data)

            # Update local ticket with Zammad data
            ticket_contact.zammad_ticket_id = zammad_ticket['id']
            ticket_contact.zammad_ticket_number = zammad_ticket['number']
            ticket_contact.status = zammad_ticket.get('state', {}).get('name', 'new').lower()
            ticket_contact.zammad_created_at = self._parse_zammad_datetime(zammad_ticket.get('created_at'))
            ticket_contact.zammad_updated_at = self._parse_zammad_datetime(zammad_ticket.get('updated_at'))
            ticket_contact.last_synced = timezone.now()
            ticket_contact.sync_status = 'synced'

            # Store additional Zammad data in attributes
            if not ticket_contact.attributes:
                ticket_contact.attributes = {}
            ticket_contact.attributes.update({
                'zammad_state_id': zammad_ticket.get('state_id'),
                'zammad_group_id': zammad_ticket.get('group_id'),
                'zammad_owner_id': zammad_ticket.get('owner_id'),
            })

            ticket_contact.save()

            logger.info(f"Created Zammad ticket {zammad_ticket['id']} for contact {ticket_contact.id}")
            return True

        except Exception as e:
            logger.error(f"Error creating Zammad ticket for contact {ticket_contact.id}: {e}")
            ticket_contact.sync_status = 'failed'
            ticket_contact.save()
            return False

    def sync_ticket(self, ticket_contact: 'ZammadTicketContact') -> bool:
        """Sync ticket data from Zammad"""
        if not ticket_contact.zammad_ticket_id:
            return False

        try:
            zammad_ticket = self.client.ticket.find(ticket_contact.zammad_ticket_id)

            # Update local ticket with latest Zammad data
            ticket_contact.status = zammad_ticket.get('state', {}).get('name', 'unknown').lower()
            ticket_contact.zammad_updated_at = self._parse_zammad_datetime(zammad_ticket.get('updated_at'))
            ticket_contact.last_synced = timezone.now()
            ticket_contact.sync_status = 'synced'

            # Update attributes with fresh data
            if not ticket_contact.attributes:
                ticket_contact.attributes = {}
            ticket_contact.attributes.update({
                'zammad_state_id': zammad_ticket.get('state_id'),
                'zammad_priority_id': zammad_ticket.get('priority_id'),
                'zammad_owner_id': zammad_ticket.get('owner_id'),
                'last_sync': timezone.now().isoformat(),
            })

            ticket_contact.save()
            return True

        except Exception as e:
            logger.error(f"Error syncing ticket {ticket_contact.zammad_ticket_id}: {e}")
            return False

    def get_user_tickets(self, django_user) -> List[Dict[str, Any]]:
        """Get all tickets for a user from Zammad"""
        try:
            tickets = self.client.ticket.search(query=f'customer.email:{django_user.email}')
            return tickets or []
        except Exception as e:
            logger.error(f"Error fetching tickets for user {django_user.email}: {e}")
            return []

    def sync_user_tickets(self, django_user) -> List['ZammadTicketContact']:
        """Import tickets from Zammad for a user"""
        zammad_tickets = self.get_user_tickets(django_user)
        synced_contacts = []

        for ticket_data in zammad_tickets:
            ticket_id = ticket_data['id']

            # Check if we already have this ticket locally
            try:
                contact = ZammadTicketContact.objects.get(zammad_ticket_id=ticket_id)
                # Update existing
                contact.status = ticket_data.get('state', {}).get('name', 'unknown').lower()
                contact.zammad_updated_at = self._parse_zammad_datetime(ticket_data.get('updated_at'))
                contact.last_synced = timezone.now()
                contact.sync_status = 'synced'
                contact.save()

            except ZammadTicketContact.DoesNotExist:
                # Create new contact record
                contact = ZammadTicketContact.objects.create(
                    user=django_user,
                    method='zammad_ticket',
                    title=ticket_data.get('title', 'Imported Ticket'),
                    notes=f"Imported from Zammad ticket #{ticket_data.get('number', ticket_id)}",
                    zammad_ticket_id=ticket_id,
                    zammad_ticket_number=ticket_data.get('number'),
                    status=ticket_data.get('state', {}).get('name', 'unknown').lower(),
                    priority=str(ticket_data.get('priority_id', 2)),
                    zammad_created_at=self._parse_zammad_datetime(ticket_data.get('created_at')),
                    zammad_updated_at=self._parse_zammad_datetime(ticket_data.get('updated_at')),
                    last_synced=timezone.now(),
                    sync_status='synced',
                    attributes={
                        'imported_from_zammad': True,
                        'zammad_state_id': ticket_data.get('state_id'),
                        'zammad_group_id': ticket_data.get('group_id'),
                    }
                )

            synced_contacts.append(contact)

        return synced_contacts

    def _parse_zammad_datetime(self, dt_string: str) -> Optional[datetime]:
        """Parse Zammad datetime string to Django datetime"""
        if not dt_string:
            return None
        try:
            # Zammad typically returns ISO format
            if dt_string.endswith('Z'):
                dt_string = dt_string[:-1] + '+00:00'
            return datetime.fromisoformat(dt_string)
        except (ValueError, TypeError):
            return None
