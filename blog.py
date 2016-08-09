from lib.base import *

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
                self.render("welcome.html", username=username)
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
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        author = self.user.name
        comment = self.request.get('comment')

        if comment:
            c = Comment(author=author,
                        post_id=post_id,
                        comment=comment)
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
            return self.redirect('/blog')

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
                self.redirect('/blog/%s' % post_id)
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
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
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
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if post.author == self.user.name:
                self.render("message.html", msg="This is your own post.")
            elif self.user.name in post.upvotes:
                post.votes -= 1
                post.upvotes.remove(self.user.name)
                post.put()
                self.render("message.html", msg=":(")
            elif self.user.name in post.downvotes:
                post.votes += 2
                post.downvotes.remove(self.user.name)
                post.upvotes.append(self.user.name)
                post.put()
                self.render("message.html", msg="Thanks!")
            else:
                post.votes += 1
                post.upvotes.append(self.user.name)
                post.put()
                self.render("message.html", msg="Thanks!")
        else:
            self.redirect('/login')


class Downvote(BlogHandler):
    """ Manages downvotes on a post """
    def get(self):
        if self.user:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if post.author == self.user.name:
                self.render("message.html", msg="This is your own post.")
            elif self.user.name in post.downvotes:
                post.votes += 1
                post.downvotes.remove(self.user.name)
                post.put()
                self.render("message.html", msg=":)")
            elif self.user.name in post.upvotes:
                post.votes -= 2
                post.upvotes.remove(self.user.name)
                post.downvotes.append(self.user.name)
                post.put()
                self.render("message.html", msg=":(")
            else:
                post.votes -= 1
                post.downvotes.append(self.user.name)
                post.put()
                self.render("message.html", msg=":(")
        else:
            self.redirect('/login')


# User Management
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
