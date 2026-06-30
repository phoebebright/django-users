from django.http import HttpResponse
from zammad_py import ZammadAPI
from django.conf import settings

'''
settings example:
ZAMMED = {
    'url': 'https://skorie.zammad.com/api/v1',
    'host': 'https://skorie.zammad.com',
    'http_token': 'token',
}
'''
zammad = ZammadAPI(url=settings.ZAMMED['url'], http_token=settings.ZAMMED['http_token'])

def add_ticket(request, payload):
   ''' payload example:
   {
      'title': 'some new title',
      'state': 'new',
      'priority': '2 normal',
      'owner': '-',
      'customer': 'nicole.braun@zammad.org',
      'group': 'Users',
      'article': {
         'sender': 'Customer',
         'type': 'note',
         'subject': 'some subject',
         'content_type': 'text/plain',
         'body': "some body\nnext line",
      }
   '''
   new_ticket = zammad.ticket.create(payload)


   return HttpResponse(f"Ticket created with ID: {new_ticket['id']} and Title: {new_ticket['title']}")
