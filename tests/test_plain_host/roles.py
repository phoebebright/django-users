"""Generic roles only - a copy of BuiltAir's config/roles_and_disciplines.py
(27Sep26), the reference non-skorie host. No issuer, organiser, judge or
competitor roles."""
import logging
logger = logging.getLogger('django')

class Disciplines(object):

    DISCIPLINE_ANY = "*"
    DISCIPLINE_CHOICES = (
        (DISCIPLINE_ANY, "Any"),
    )
    DEFAULT_DISCIPLINE = DISCIPLINE_ANY
    DISCIPLINES_IN_USER = [k for k,v in DISCIPLINE_CHOICES]

    @property
    def default(self):
        return self.DISCIPLINE_ANY

    @classmethod
    def codes(cls):
        return [code for code,name in cls.DISCIPLINE_CHOICES]

class ModelRoles(object):
    ROLE_ADMINISTRATOR = "A"  # can administor skorie - God
    ROLE_MANAGER = "M"
    ROLE_RESEARCHER = "R"
    ROLE_DEFAULT = "D"
    ROLE_FACTORY = "F"
    ROLE_BOT = "B"
    ROLE_SYSTEM = "Y"

    ROLE_DESCRIPTIONS = {
        ROLE_ADMINISTRATOR: "Administer", # - will require manual addition of is_staff and superuser on model for some options",
        ROLE_DEFAULT: "User",
    }


    SYSTEM_ROLES = {
        ROLE_SYSTEM: "System",
        ROLE_BOT: "Bot",
    }

    # used in model
    ROLE_CHOICES  = [(key, value) for key,value in ROLE_DESCRIPTIONS.items()]

    @classmethod
    def is_valid_role(cls, role):

        # check role is valid
        if len(role) != 1:
            return False

        try:
            ok = cls.ROLES[role]
        except:
            return False

        return True

    @classmethod
    def validate_roles(cls, roles):
        '''return list of valid roles from list of unvalidated roles'''
        valid_roles = []
        for item in roles:
            if item > "" and not ModelRoles.is_valid_role(item):
                logger.warning(f"trying to add invalid role {item} to event team")
            else:
                valid_roles.append(item)

        return valid_roles
