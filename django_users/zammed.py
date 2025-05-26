from zammad_py import ZammadAPI
from django.conf import settings

# Initialize the client with the URL, username, and password
# Note the Host URL should be in this format: 'https://zammad.example.org/api/v1/'
client = ZammadAPI(url=settings.ZAMMED['host'], username=settings.ZAMMED['username'], password=settings.ZAMMED['pw'])

# Example: Access all users
this_page = client.user.all()
for user in this_page:
    print(user)

# Example: Get information about the current user
print(client.user.me())

# Example: Create a ticket
params = {
   "title": "Help me!",
   "group": "2nd Level",
   "customer": "david@example.com",
   "article": {
      "subject": "My subject",
      "body": "I am a message!",
      "type": "note",
      "internal": false
   }
}
new_ticket = client.ticket.create(params=params)
