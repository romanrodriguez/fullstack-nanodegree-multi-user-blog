import random
import hashlib
import hmac

from string import letters

# Hashstore
# For the sake of this exercise, the secret is included here.
# This is not secure. It should be accessed externally.
secret = 'nUfsTrjoVDdDd43pcIyfS%Y0,gK-1TWn0mXqect2Fi0pbcxd"U'


def make_salt(length=5):
    """ Generate a salt to pair with hash keys """
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """ Salt password if none exist, otherwise create hash """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def make_secure_val(val):
    """ Pairs the cookie with a secret string """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """ Makes sure the cookie is valid """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def valid_pw(name, password, h):
    """ Checks if password is valid """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
