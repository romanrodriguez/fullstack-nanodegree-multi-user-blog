import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# Template
# Sets home path to templates folder
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

# Points Jinja2 Env to templates directory with XML/HTML Escape
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    """ Gets templates and renders with props to environment """
    t = jinja_env.get_template(template)
    return t.render(params)


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


# Datastore
def users_key(group='default'):
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class User(db.Model):
    """ Creates entity to store user daya in GAE Datastore """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    """ Creates entity to store blog post data in GAE Datastore """
    author = db.StringProperty()
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    votes = db.IntegerProperty(default=0)
    upvotes = db.StringListProperty()
    downvotes = db.StringListProperty()


    def render(self):
        """ Renders blog post to environment """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    """ Creates entity to store comments in GAE Datastore """
    author = db.StringProperty()
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now=True)


# Base Blog Handler
class BlogHandler(webapp2.RequestHandler):
    """ Base Blog Handler for all classes """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ Passes template and its parameters to jinja environment """
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """ Calls render_str and renders jinja environment """
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """ Creates a cookie based on given name and value """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """ Returns value of cookie itself """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# Page Management
class MainPage(BlogHandler):
    def get(self):
        self.render('index.html')


class BlogFront(BlogHandler):
    """ Shows all posts sorted from latest modified first """
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


class Welcome(BlogHandler):
    def get(self):
        user = self.request.cookies.get('user')
        if user:
            username = check_secure_val(user)
            if username:
                self.render("welcome.html", username = username)
            else:
                self.redirect('/signup')
        else:
            self.redirect('/signup')


# Blog Management
class PostPage(BlogHandler):
    """ Sends user to the permalink page upon successful post submission """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            msg = "Something went wrong!"
            self.render("message.html", msg=msg)

        comments = db.GqlQuery("SELECT * FROM Comment "
                               + "WHERE post_id = :1 "
                               + "ORDER BY created DESC",
                               post_id)

        self.render("permalink.html", post=post, comments=comments)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        author = self.user.name
        comment = self.request.get('comment')

        if comment:
            c = Comment(author = author,
                        post_id = post_id,
                        comment = comment)
            c.put()
        self.redirect('/')


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        author = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(),
                     author=author,
                     subject=subject,
                     content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Fill in all the fields, please!"
            self.render(
                "newpost.html",
                author=author,
                subject=subject,
                content=content,
                error=error)


class EditPost(BlogHandler):
    """ Edit existing blog posts """
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user.name == post.author:
                self.render('editpost.html', p=post)
            else:
                msg = "You are not authorized to edit this post."
                self.render('message.html', msg=msg)

    def post(self):
        if not self.user:
            self.redirect("/login")
        else:
            post_id = self.request.get('id')
            new_content = self.request.get('editpost')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)

            if new_content:
                p.content = new_content
                p.put()
                self.redirect('/%s' % post_id)
            else:
                error = "Content cannot be empty."
                self.render("editpost.html", p=p, error=error)


class DeletePost(BlogHandler):
    """ Delete existing blog posts """
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent = blog_key())
            post = db.get(key)

            if self.user.name == post.author:
                db.delete(key)
                self.render("message.html", msg="Post deleted.")
            else:
                msg = "You are not authorized to delete this post."
                self.render('message.html', msg=msg)


class EditComment(BlogHandler):
    """ Edits a comment """
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            comment_id = self.request.get('id')
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if self.user.name == comment.author:
                self.render("editcomment.html", comment=comment)
            else:
                msg = "You are not authorized to edit this comment."
                self.render("message.html", msg=msg)

    def post(self):
        if not self.user:
            self.redirect("/login")
        else:
            comment_id = self.request.get('id')
            edit_comment = self.request.get('editcomment')
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if edit_comment:
                comment.comment = edit_comment
                comment.put()
                self.render("message.html", msg="Comment updated.")
            else:
                self.render("message.html", msg="Error updating the comment.")


class DeleteComment(BlogHandler):
    """ Deletes a comment """
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            comment_id = self.request.get('id')
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if self.user.name == comment.author:
                db.delete(key)
                self.render("message.html", msg="Comment deleted.")
            else:
                msg = "You are not authorized to delete this comment."
                self.render('message.html', msg=msg)

class Upvote(BlogHandler):
    """ Manages upvotes on a post """
    def get(self):
        if self.user:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent = blog_key())
            post = db.get(key)

            if post.author == self.user.name:
                self.render("message.html", msg = "This is your own post.")
            elif self.user.name in post.upvoters:
                post.votes -= 1
                post.upvoters.remove(self.user.name)
                post.put()
                self.render("message.html", msg = ":(")
            elif self.user.name in post.downvoters:
                post.votes += 2
                post.downvoters.remove(self.user.name)
                post.upvoters.append(self.user.name)
                post.put()
                self.render("message.html", msg = "Thanks!")
            else:
                post.votes += 1
                post.upvoters.append(self.user.name)
                post.put()
                self.render("message.html", msg = "Thanks!")
        else:
            self.redirect('/login')

class Downvote(BlogHandler):
    """ Manages downvotes on a post """
    def get(self):
        if self.user:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent = blog_key())
            post = db.get(key)

            if post.author == self.user.name:
                self.render("message.html", msg = "This is your own post.")
            elif self.user.name in post.downvoters:
                post.votes += 1
                post.downvoters.remove(self.user.name)
                post.put()
                self.render("message.html", msg = ":)")
            elif self.user.name in post.upvoters:
                post.votes -= 2
                post.upvoters.remove(self.user.name)
                post.downvoters.append(self.user.name)
                post.put()
                self.render("message.html", msg = ":(")
            else:
                post.votes -= 1
                post.downvoters.append(self.user.name)
                post.put()
                self.render("message.html", msg = ":(")
        else:
            self.redirect('/login')


# User Management
# REGEX Rules
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    """ Validates user information by Regex and then registers user to site """
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """ Makes sure the user doesn't already exist """
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/?', BlogFront),
    ('/welcome', Welcome),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/edit', EditPost),
    ('/blog/delete', DeletePost),
    ('/blog/editcomment', EditComment),
    ('/blog/deletecomment', DeleteComment),
    ('/blog/upvote', Upvote),
    ('/blog/downvote', Downvote),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
], debug=True)
