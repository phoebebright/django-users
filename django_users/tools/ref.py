import re

import nanoid

from django.db import IntegrityError
from django.apps import apps
import re
import logging
logger = logging.getLogger('django')


class RefConverter:
    regex = ''

    def to_python(self, value):
        '''ensure first letter is capitalised'''
        return value.capitalize()

    def to_url(self, value):
        return value

    @classmethod
    def valid_ref(cls, value):
        '''check this values matches the spec for this reference'''
        return (re.match(cls.regex, value))


class GadgetRefConverter(RefConverter):
    regex = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

class PersonRefConverter(RefConverter):
    regex = '[Pp][a-z0-9]{5}'

class RoleRefConverter(RefConverter):
    regex = '[Rr][a-z0-9]{6}'

def get_new_ref(model):
    '''
    S+6 = Scoresheet
    T+3 = Testsheet
    H+5 = Horse
    R+6 = Role
    P+5 = Person
    J+5 = Judge  # deprecated
    V+4 = Event
    C+5 = Competition
    E+8 = Entry = E + Event + sequence - handled in model
    W+5 = Order

    Rosettes
    Z+6 = Rosette

    2 = 900
    3 = 27,000
    4 = 810,000
    5 = 24,300,000
    6 = 729,000,000
    '''

    if type(model) == type("string"):
        model = model.lower()
    else:
        # assume model instance passed
        model = model._meta.model_name.lower()

    if model == "person":
        first = "P"
        size = 5
    elif model == "role":
        first = "R"
        size = 6

    else:
        raise IntegrityError("Unrecognised model %s" % model)

    return "%s%s" % (first, nanoid.generate(alphabet="23456789abcdefghjkmnpqrstvwxyz", size=size))


def get_obj_from_ref(ref):

    ref = ref.strip()
    first = ref[0]


    if first == "P":
        model = "Person"
        size = 5
    elif first == "R":
        model = "Role"
        size = 6

    else:
        logger.warning(f"Unrecognised first char in {ref} in get_obj_from_ref")
        raise IntegrityError("Unrecognised first char %s" % first)

    if len(ref) != size+1:
        raise IntegrityError("Invalid size of ref for model %s" % model)

    Model = apps.get_model(app_label='web', model_name=model)
    obj = Model.objects.get(ref=ref)

    return obj
