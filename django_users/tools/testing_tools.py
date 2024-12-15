import arrow
from django.utils import timezone
from django.contrib.sessions.middleware import SessionMiddleware
from django.conf import settings
import os

def ok_(expr, msg=None):
    """Shorthand for assert. Saves 3 whole characters!
    """
    if not expr:
        raise AssertionError(msg)


def eq_(b, a, msg=None):
    """Shorthand for 'assert a == b, "%r != %r" % (a, b)
    NOTE THAT I HAVE PUT ACTUAL FIRST THEN EXPECT WHICH IS WRONG - SO THE PARAMETERS ARE REVERSED HERE
    """
    if not a == b:
        raise AssertionError(msg or "Expect %r != Actual %r" % (a, b))

def assertDatesMatch(dt1, dt2, msg=None, seconds=60):
    '''test that two date/times match within a specified number of seconds'''

    # must both be dates to succeed
    if not dt1 or not dt2:
        raise AssertionError(msg)



    tz = timezone.get_current_timezone()

    # using arrow forces them into tz aware datetimes
    dt1 = arrow.get(dt1, tz)
    dt2 = arrow.get(dt2, tz)

    # note: abs doesn't work if dt1 < dt2
    if dt1 > dt2:
        diff = (dt1 - dt2).seconds
    else:
        diff = (dt2 - dt1).seconds


    if not (diff < seconds):

        if not msg:
            msg = "Differences in datetimes %s and %s is %d seconds and only allowed %d" % (str(dt1), str(dt2), diff, seconds)

        raise AssertionError(msg)

def generate_file(name, content):
    # put in site_media directory

    fullpath = os.path.join(settings.MEDIA_ROOT,  name)

    try:
        f = open(fullpath, 'wb')
        f.write(content)

    finally:
        f.flush()
        f.close()

    return f

def remove_file(fullpathname):
    # remove from in site_media/temp directory


    try:
        os.remove(fullpathname)

    except:
        pass

def add_session_to_request(request):
    """Annotate a request object with a session"""
    middleware = SessionMiddleware()
    middleware.process_request(request)
    request.session.save()