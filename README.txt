Do Next

FISH
- fix fields in users - remove subscribed, mobile, whatsapp
- fix fields in person - remove mobile and whatsapp

- form not fading on submit and takes a while so needs to
- user account page
    - change password
    - change timezone
    - manage comms channels

- migration
    - copy email in comms channel and set email as preferred - DONE, on user save, creates comms channel

- problem signup
    - create new channel
    - send verification code to new channel
    - admin can verify


Copied from Skorie3 28Feb24 - will require change in db to implement

TODO:
Initially point to table in web
Organisation needs to replace id PK with code
    - code added but foreign keys will need replacing


Migrating Users

rename model

ALTER TABLE web_person RENAME TO users_person;
ALTER TABLE web_role RENAME TO users_role;
ALTER TABLE web_personorganisation RENAME TO users_personorganisation;
ALTER TABLE web_usercontact RENAME TO users_usercontact;
ALTER TABLE web_organisation RENAME TO users_organisation;
ALTER TABLE web_customuser RENAME TO users_customuser;

Organisation replace id with code as pk is not straightforward because of foreign keys - just add code as additional field for now.

Manuallyt add users migration 1 and put timestamp before web migration 1
makemigrations and migrate

Rosette 1-3
Run rest of migrations

MyHorse -> MyPartner
MyRider -> MyCompetitor
