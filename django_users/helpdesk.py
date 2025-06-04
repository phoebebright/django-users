import logging

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import CreateView, DetailView, ListView
from django.urls import reverse_lazy, reverse
from .models import ZammadTicketContact, EntryTicketLink
from .forms import SupportTicketForm
from .tools.permission_mixins import UserCanAdministerMixin
from .zammad_service import ZammadService

logger = logging.getLogger('django')

User = get_user_model()

class CreateTicketView(LoginRequiredMixin, CreateView):
    """View for users to create support tickets"""
    model = ZammadTicketContact
    form_class = SupportTicketForm
    template_name = 'support/create_ticket.html'

    def form_valid(self, form):
        # Set user and method before saving
        form.instance.user = self.request.user
        form.instance.method = 'zammad_ticket'

        # Save the ticket contact record
        self.object = form.save()

        # Try to create in Zammad
        try:
            zammad_service = ZammadService()
            success = zammad_service.create_ticket(self.object)

            if success:
                messages.success(
                    self.request,
                    f'Your support ticket #{self.object.zammad_ticket_number} has been created successfully.'
                )
            else:
                messages.warning(
                    self.request,
                    'Your ticket has been saved locally but could not be synchronized with our support system. '
                    'Our team will review it shortly.'
                )
        except Exception as e:
            logger.error(f"Error creating Zammad ticket: {e}")
            messages.warning(
                self.request,
                'Your ticket has been saved but there was an issue with our support system sync.'
            )

        return redirect(self.get_success_url())

    def get_success_url(self):
        return reverse('ticket_detail', kwargs={'pk': self.object.pk})


class TicketDetailView(LoginRequiredMixin, DetailView):
    """View ticket details"""
    model = ZammadTicketContact
    template_name = 'support/ticket_detail.html'
    context_object_name = 'ticket'

    def get_queryset(self):
        # Only allow users to view their own tickets
        return ZammadTicketContact.objects.filter(user=self.request.user)

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)

        # Try to sync latest data if ticket exists in Zammad
        if obj.zammad_ticket_id:
            try:
                zammad_service = ZammadService()
                zammad_service.sync_ticket(obj)
                obj.refresh_from_db()
            except Exception as e:
                logger.error(f"Error syncing ticket {obj.id}: {e}")

        return obj

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['zammad_url'] = self.object.get_zammad_url()
        return context


class MyTicketsView(LoginRequiredMixin, ListView):
    """List all tickets for the current user"""
    model = ZammadTicketContact
    template_name = 'support/my_tickets.html'
    context_object_name = 'tickets'
    paginate_by = 10

    def get_queryset(self):
        queryset = ZammadTicketContact.objects.filter(user=self.request.user)

        # Optional: Add filtering
        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset.order_by('-contact_date')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get available statuses for filter
        context['available_statuses'] = ZammadTicketContact.objects.filter(
            user=self.request.user
        ).values_list('status', flat=True).distinct()

        context['current_status'] = self.request.GET.get('status')
        return context



class AdminUserTicketsView(UserCanAdministerMixin, DetailView):
    """Admin view to see all tickets for a specific user"""
    model = User
    template_name = 'admin/user_tickets.html'
    context_object_name = 'user'
    pk_url_kwarg = 'user_id'

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()

        # Sync tickets from Zammad if requested
        if request.GET.get('sync') == '1':
            try:
                zammad_service = ZammadService()
                synced_tickets = zammad_service.sync_user_tickets(self.object)
                messages.success(request, f'Synced {len(synced_tickets)} tickets from Zammad')
            except Exception as e:
                messages.error(request, f'Error syncing tickets: {str(e)}')
                logger.error(f"Error syncing tickets for user {self.object.id}: {e}")

            # Redirect to remove the sync parameter from URL
            return redirect('admin_user_tickets', user_id=self.object.id)

        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get all tickets for this user
        context['tickets'] = ZammadTicketContact.objects.filter(
            user=self.object
        ).order_by('-contact_date')

        # Get linked entries for display
        context['entry_links'] = EntryTicketLink.objects.filter(
            ticket__user=self.object
        ).select_related('ticket', 'created_by')

        return context


class LinkTicketToEntryView(UserCanAdministerMixin, View):
    """Admin endpoint to link a ticket to an entry object"""

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        ticket_id = request.POST.get('ticket_id')
        entry_id = request.POST.get('entry_id')
        entry_type = request.POST.get('entry_type')
        notes = request.POST.get('notes', '')

        if not all([ticket_id, entry_id, entry_type]):
            return JsonResponse({'error': 'Missing required parameters'}, status=400)

        try:
            ticket = ZammadTicketContact.objects.get(id=ticket_id)

            link, created = EntryTicketLink.objects.get_or_create(
                ticket=ticket,
                entry_id=int(entry_id),
                entry_type=entry_type,
                defaults={
                    'created_by': request.user,
                    'notes': notes
                }
            )

            return JsonResponse({
                'success': True,
                'created': created,
                'link_id': link.id,
                'message': 'Link created successfully' if created else 'Link already exists'
            })

        except ZammadTicketContact.DoesNotExist:
            return JsonResponse({'error': 'Ticket not found'}, status=404)
        except ValueError:
            return JsonResponse({'error': 'Invalid entry_id'}, status=400)
        except Exception as e:
            logger.error(f"Error linking ticket {ticket_id} to entry {entry_type}:{entry_id}: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)


class AdminSyncTicketView(UserCanAdministerMixin, View):
    """Admin endpoint to manually sync a specific ticket"""

    def get(self, request, ticket_id, *args, **kwargs):
        ticket = get_object_or_404(ZammadTicketContact, id=ticket_id)

        try:
            zammad_service = ZammadService()
            success = zammad_service.sync_ticket(ticket)

            if success:
                messages.success(request, f'Ticket {ticket.zammad_ticket_number} synced successfully')
            else:
                messages.error(request, 'Failed to sync ticket')

        except Exception as e:
            messages.error(request, f'Error syncing ticket: {str(e)}')
            logger.error(f"Error syncing ticket {ticket_id}: {e}")

        return redirect('admin_user_tickets', user_id=ticket.user.id)


class AdminTicketListView(UserCanAdministerMixin, ListView):
    """Admin view to list all tickets with filtering options"""
    model = ZammadTicketContact
    template_name = 'admin/ticket_list.html'
    context_object_name = 'tickets'
    paginate_by = 20

    def get_queryset(self):
        queryset = ZammadTicketContact.objects.select_related('user').order_by('-contact_date')

        # Add filters
        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        priority_filter = self.request.GET.get('priority')
        if priority_filter:
            queryset = queryset.filter(priority=priority_filter)

        sync_status_filter = self.request.GET.get('sync_status')
        if sync_status_filter:
            queryset = queryset.filter(sync_status=sync_status_filter)

        # Search by user email or ticket title
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(user__email__icontains=search) |
                Q(title__icontains=search) |
                Q(zammad_ticket_number__icontains=search)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Add filter options to context
        context['available_statuses'] = ZammadTicketContact.STATUS_CHOICES
        context['available_priorities'] = ZammadTicketContact.PRIORITY_CHOICES
        context['sync_statuses'] = [
            ('pending', 'Pending'),
            ('synced', 'Synced'),
            ('failed', 'Failed'),
        ]

        # Current filter values
        context['current_filters'] = {
            'status': self.request.GET.get('status'),
            'priority': self.request.GET.get('priority'),
            'sync_status': self.request.GET.get('sync_status'),
            'search': self.request.GET.get('search'),
        }

        return context


class BulkSyncTicketsView(UserCanAdministerMixin, View):
    """Admin view to bulk sync tickets from Zammad"""

    def post(self, request, *args, **kwargs):
        try:
            zammad_service = ZammadService()

            # Get list of user IDs to sync (or all users if none specified)
            user_ids = request.POST.getlist('user_ids')
            if user_ids:
                users = User.objects.filter(id__in=user_ids)
            else:
                users = User.objects.filter(email__isnull=False).exclude(email='')

            total_synced = 0
            failed_users = []

            for user in users:
                try:
                    synced_tickets = zammad_service.sync_user_tickets(user)
                    total_synced += len(synced_tickets)
                except Exception as e:
                    logger.error(f"Failed to sync tickets for user {user.id}: {e}")
                    failed_users.append(user.email)

            success_msg = f'Successfully synced {total_synced} tickets for {users.count()} users'
            if failed_users:
                success_msg += f'. Failed for: {", ".join(failed_users[:5])}'
                if len(failed_users) > 5:
                    success_msg += f' and {len(failed_users) - 5} others'

            messages.success(request, success_msg)

        except Exception as e:
            logger.error(f"Error in bulk sync: {e}")
            messages.error(request, f'Bulk sync failed: {str(e)}')

        return redirect('admin_ticket_list')
