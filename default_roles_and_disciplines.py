import logging
logger = logging.getLogger('django')

class Disciplines(object):

    DISCIPLINE_ANY = "*"

    DEFAULT_DISCIPLINE = DISCIPLINE_ANY


    DISCIPLINE_CHOICES = (
        (DISCIPLINE_ANY, "Any"),
    )

    DISCIPLINES_IN_USER = [k for k,v in DISCIPLINE_CHOICES]

    @property
    def default(self):
        return self.DISCIPLINE_DRESSAGE

    @classmethod
    def codes(cls):
        return [code for code,name in cls.DISCIPLINE_CHOICES]



class ModelRoles(object):
    ROLE_ADMINISTRATOR = "A"
    ROLE_USER = "U"
    ROLE_SYSTEM = "Y"


    ROLE_DESCRIPTIONS = {
        ROLE_ADMINISTRATOR: "Administer the Skorie system",
        ROLE_USER: "User",

    }

    ROLES = {
        ROLE_ADMINISTRATOR: "Administrator",
        ROLE_USER: "User",
    }

    SYSTEM_ROLES = {
        ROLE_SYSTEM: "System",

    }



    ROLE_CHOICES  = [(key, value) for key,value in ROLES.items()]


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
