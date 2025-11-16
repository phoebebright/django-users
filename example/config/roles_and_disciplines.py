import logging
logger = logging.getLogger('django')

class Disciplines(object):

    DISCIPLINE_ANY = "*"
    DISCIPLINE_DRESSAGE = "D"
    DISCIPLINE_WESTERN_DRESSAGE = "W"
    DISCIPLINE_WORKING_EQUITATION_DRESSAGE = "E"
    DISCIPLINE_SHOWJUMPING = "J"
    DISCIPLINE_CROSSCOUNTRY = "X"
    DISCIPLINE_DRIVING = "V"
    DISCIPLINE_SHOWING = "S"

    DEFAULT_DISCIPLINE = DISCIPLINE_DRESSAGE


    DISCIPLINE_CHOICES = (
        (DISCIPLINE_DRESSAGE, "Dressage"),
        (DISCIPLINE_WESTERN_DRESSAGE, "Western Dressage"),
        (DISCIPLINE_WORKING_EQUITATION_DRESSAGE, "Working Equitation Dressage"),
        (DISCIPLINE_SHOWJUMPING, "Show Jumping"),
        (DISCIPLINE_CROSSCOUNTRY, "Cross Country"),
        (DISCIPLINE_SHOWING, "Showing"),
        (DISCIPLINE_ANY, "Any"),
        # (DISCIPLINE_CROSSCOUNTRY, "Cross Country"),

    )

    DISCIPLINES_IN_USER = [k for k,v in DISCIPLINE_CHOICES]

    @property
    def default(self):
        return self.DISCIPLINE_DRESSAGE

    @classmethod
    def codes(cls):
        return [code for code,name in cls.DISCIPLINE_CHOICES]

    def fei_code(self):
        '''
        S Jumping
D Dressage
C Eventing
A Driving
E Endurance
R Reining
V Vaulting
PED Para-Equestrian Dressage
PEA Para-Equestrian Driving
        :return:
        '''
        return "D"

class ModelRoles(object):
    ROLE_ADMINISTRATOR = "A"  # can administor skorie - God
    ROLE_MANAGER = "M"   # can create new events

    ROLE_ISSUER = "I"  # can add testsheets
    ROLE_JUDGE = "J"
    ROLE_AUXJUDGE = "K" # auxiliarry judge - judge for just one event, eg. trainee judge or try judging competitor
    ROLE_ORGANISER = "O"  # can organise a specific event
    ROLE_RIDER = "R"
    ROLE_COMPETITOR = "R"
    ROLE_SCORER = "S"
    ROLE_SCORER_BASIC = "B"
    ROLE_STEWARD = "E"
    ROLE_SYSTEM = "Y"
    ROLE_WRITER = "W"
    ROLE_DEFAULT = "D"
    ROLE_DOGSBODY = "G"
    ROLE_LEADER = "L" # person leading clinic, eg. Instructor

    ROLE_DESCRIPTIONS = {
        ROLE_ADMINISTRATOR: "Administer the Skorie system", # - will require manual addition of is_staff and superuser on model for some options",
        ROLE_MANAGER: "Manage events - can create new events",
        ROLE_ISSUER: "Manage a list of testsheets on behalf of a test issuer",
        ROLE_JUDGE: "Can judge at event",
        ROLE_AUXJUDGE: "Can practise judge at event",
        ROLE_ORGANISER: "Can organise a specific event",
        ROLE_RIDER: "Can ride at an event",   # deprecated
        ROLE_COMPETITOR: "Can compete at an event",
        ROLE_SCORER: "Can manage scores at an event",
        ROLE_SCORER_BASIC : "Can score at an event",
        ROLE_STEWARD: "Can steward at an event",
        ROLE_SYSTEM: "Non-user role - used to tag data created by the system",
        ROLE_WRITER: "Can write for a judge at an event",
        ROLE_DEFAULT: "Default role for new user",
        ROLE_DOGSBODY: "Can have general support role at event",
        ROLE_LEADER: "Teacher, presenter, coach at clinic - main leadership role",

    }

    # the order of this list will be used when picking the current user mode (role) if they have more than one
    EVENT_ROLES = {

        ROLE_ORGANISER: "Organiser",  # can organise an event but can't create a new one
        ROLE_JUDGE: "Judge",
        ROLE_LEADER: "Leader",
        ROLE_AUXJUDGE: "Trainee Judge",
        ROLE_SCORER_BASIC: "Scorer",
        ROLE_SCORER: "Scorer Pro",
        ROLE_STEWARD: "Steward",
        ROLE_WRITER: "Writer",
        ROLE_DOGSBODY: "Dogsbody",
        ROLE_RIDER: "Rider",
    }

    VIRTUAL_EVENT_ROLES = {
        ROLE_ORGANISER: "Organiser",
        ROLE_JUDGE: "Judge",
        ROLE_AUXJUDGE: "Trainee Judge",
    }



    NON_EVENT_ROLES = {
        ROLE_ADMINISTRATOR: "Administrator",
        ROLE_MANAGER: "Event Manager",  # can create and event and gets Organiser role for event
        ROLE_ISSUER: "Issuer",
        ROLE_JUDGE: "Judge",
        ROLE_AUXJUDGE: "Trainee Judge",
        ROLE_RIDER: "Competitor",
        ROLE_DEFAULT: "Default",
    }

    SYSTEM_ROLES = {
        ROLE_SYSTEM: "System",

    }


    #ROLES = dict(EVENT_ROLES.items()  + NON_EVENT_ROLES.items())
    ROLES = EVENT_ROLES.copy()
    ROLES.update(NON_EVENT_ROLES)


    # when adding roles a primary role is requested, eg organiser or judge, so that correct lookups can be done
    # additional roles do not include primary roles with specific looksups
    PRIMARY_EVENT_ROLES = {
        ROLE_ORGANISER: "Organiser",
        ROLE_JUDGE: "Judge",
        ROLE_SCORER_BASIC: "Scorer",
        ROLE_SCORER: "Scorer Pro",

        ROLE_STEWARD: "Steward",
        ROLE_WRITER: "Writer",
        ROLE_DOGSBODY: "Dogsbody",
    }
    ADDITIONAL_EVENT_ROLES =  {
        ROLE_SCORER_BASIC: "Scorer",
        ROLE_SCORER: "Scorer Pro",
        ROLE_STEWARD: "Steward",
        ROLE_WRITER: "Writer",
        ROLE_DOGSBODY: "Dogsbody",
        ROLE_AUXJUDGE: "Trainee Judge",
    }

    EVENT_ROLES_LIST = [role for role, _ in EVENT_ROLES.items()]
    EVENT_ROLES_LIST_NO_JUDGES = [ROLE_ORGANISER,ROLE_SCORER,ROLE_SCORER_BASIC,ROLE_STEWARD,ROLE_WRITER,ROLE_DOGSBODY]

    #NameError: name 'EVENT_ROLES_LIST_NO_JUDGES' is not defined?????
    #EVENT_ROLES_NO_JUDGES_CHOICES = [(key, value) for key,value in PRIMARY_EVENT_ROLES.items() if key in EVENT_ROLES_LIST_NO_JUDGES]

    VIRTUAL_EVENT_PRIMARY_ROLES = {
        ROLE_ORGANISER: "Organiser",
        ROLE_JUDGE: "Judge",
    }
    VIRTUAL_EVENT_ADDITIONAL_ROLES = {
        ROLE_AUXJUDGE: "Trainee Judge",
    }


    ROLE_CHOICES  = [(key, value) for key,value in ROLES.items()]
    EVENT_ROLE_CHOICES = [(key, value) for key,value in EVENT_ROLES.items()]

    # roles that can be chosen
    PRIMARY_ROLES_CHOICES = [(key, value) for key,value in PRIMARY_EVENT_ROLES.items()]
    ADDITIONAL_ROLES_CHOICES = [(key, value) for key,value in ADDITIONAL_EVENT_ROLES.items()]

    VIRTUAL_PRIMARY_ROLES_CHOICES = [(key, value) for key,value in VIRTUAL_EVENT_PRIMARY_ROLES.items()]
    VIRTUAL_ADDITIONAL_ROLES_CHOICES = [(key, value) for key,value in VIRTUAL_EVENT_ADDITIONAL_ROLES.items()]


    NON_EVENT_CHOICES = [(key, value) for key,value in NON_EVENT_ROLES.items()]
    EVENT_CHOICES = EVENT_ROLE_CHOICES
    ORGANISER_ROLES = [ROLE_ORGANISER,ROLE_SCORER,ROLE_SCORER_BASIC,ROLE_STEWARD,ROLE_WRITER,ROLE_DOGSBODY]

    JUDGE_ROLES = [ROLE_JUDGE,ROLE_AUXJUDGE]
    JUDGE_ROLE_CHOICES = [(ROLE_JUDGE,EVENT_ROLES[ROLE_JUDGE]),(ROLE_AUXJUDGE, EVENT_ROLES[ROLE_AUXJUDGE])]



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
