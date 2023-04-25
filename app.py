import os

from flask import Flask, render_template, request, flash, redirect, session, g
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError


from forms import UserAddForm, LoginForm, MessageForm, ProfileEditForm, ChangePasswordForm
from models import db, connect_db, User, Message, Likes

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///warbler'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
toolbar = DebugToolbarExtension(app)

connect_db(app)



def check_auth(f):
    def wrapper(*args, **kwargs):
        if not g.user:
            flash("Access unauthorized.", "danger")
            return redirect("/")
        val = f(*args, **kwargs)
        return val
    wrapper.__name__ = f.__name__
    return wrapper
##############################################################################
# User signup/login/logout

@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """
    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect("/")

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""
    do_logout()
    flash(f" You're logged out. Goodbye!", "success")
    return redirect("/")


##############################################################################
# General user routes:

@app.route('/users')
@check_auth
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.route('/users/<int:user_id>')
@check_auth
def users_show(user_id):
    """Show user profile."""
    # if not g.user:
    #     flash("Access unauthorized.", "danger")
    #     return redirect("/")
        
    user = User.query.get_or_404(user_id)

    # snagging messages in order from the database;
    # user.messages won't be in order by default
    messages = (Message
                .query
                .filter(Message.user_id == user_id)
                .order_by(Message.timestamp.desc())
                .limit(100)
                .all())
    return render_template('users/show.html', user=user, messages=messages)


@app.route('/users/<int:user_id>/following')
@check_auth
def show_following(user_id):
    """Show list of people this user is following."""


    user = User.query.get_or_404(user_id)
    return render_template('users/following.html', user=user)


@app.route('/users/<int:user_id>/followers')
@check_auth
def users_followers(user_id):
    """Show list of followers of this user."""

    user = User.query.get_or_404(user_id)
    return render_template('users/followers.html', user=user)

@app.route('/users/<int:user_id>/likes')
@check_auth
def users_likes(user_id):
    """Show list of followers of this user."""

    user = User.query.get_or_404(user_id)
    return render_template('users/likes.html', user=user)


@app.route('/users/follow/<int:follow_id>', methods=['POST'])
@check_auth
def add_follow(follow_id):
    """Add a follow for the currently-logged-in user."""

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.append(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/stop-following/<int:follow_id>', methods=['POST'])
@check_auth
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user."""

    followed_user = User.query.get(follow_id)
    g.user.following.remove(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/profile', methods=["GET", "POST"])
@check_auth
def edit_profile():
    """Update profile for current user."""

    user = g.user
    form = ProfileEditForm(obj=user)

    if form.validate_on_submit():
        if User.authenticate(user.username, form.password.data):
            try:

                user.username = form.username.data
                user.email = form.email.data
                user.image_url = form.image_url.data
                user.header_image_url = form.header_image_url.data
                user.bio = form.bio.data
                user.location = form.location.data
                  
                db.session.commit()

            except IntegrityError:
                flash("Username already taken", 'danger')
                return render_template('users/edit.html', form=form)

            return redirect(f"/users/{g.user.id}")
        
        else:
            flash("Incorrect Password", 'danger')
            return render_template('users/edit.html', form=form)

    else:
        return render_template('users/edit.html', form=form)



@app.route('/users/profile/password', methods=["GET", "POST"])
@check_auth
def change_password():
    """Change password for current user."""

    user = g.user
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if (form.new_password.data != form.new_password_match.data):
            flash("Non Matching Password", 'danger')
            return render_template('users/edit_password.html', form=form)

        elif User.authenticate(user.username, form.password.data): 
            try:

                new_password = form.new_password.data
                
                user = User.edit_password(user.username, new_password)
                g.user.password = user.password

            except IntegrityError:
                flash("Username already taken", 'danger')
                return render_template('users/edit_password.html', form=form)

            return redirect(f"/users/{g.user.id}")
        
        else:
            flash("Incorrect Password", 'danger')
            return render_template('users/edit_password.html', form=form)

    else:
        return render_template('users/edit_password.html', form=form)




@app.route('/users/delete', methods=["POST"])
@check_auth
def delete_user():
    """Delete user."""

    do_logout()

    db.session.delete(g.user)
    db.session.commit()

    return redirect("/signup")


@app.route('/users/add_like/<int:message_id>', methods=["POST"])
@check_auth
def like_message(message_id):
    """Like a message."""

    likes = [like.id for like in g.user.likes]
    if message_id not in likes:
        like = Likes(user_id=g.user.id, message_id=message_id)

        db.session.add(like)

        db.session.commit()

    else:
        like = Likes.query.filter(Likes.user_id==g.user.id, Likes.message_id==message_id).first()
        
        db.session.delete(like)
        db.session.commit()
    

    return redirect("/")


##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
@check_auth
def messages_add():
    """Add a message:

    Show form if GET. If valid, update message and redirect to user page.
    """

    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        return redirect(f"/users/{g.user.id}")

    return render_template('messages/new.html', form=form)


@app.route('/messages/<int:message_id>', methods=["GET"])
@check_auth
def messages_show(message_id):
    """Show a message."""

    msg = Message.query.get(message_id)
    return render_template('messages/show.html', message=msg)


@app.route('/messages/<int:message_id>/delete', methods=["POST"])
def messages_destroy(message_id):
    """Delete a message."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    msg = Message.query.get(message_id)
    db.session.delete(msg)
    db.session.commit()

    return redirect(f"/users/{g.user.id}")


##############################################################################
# Homepage and error pages


@app.route('/')
def homepage():
    """Show homepage:

    - anon users: no messages
    - logged in: 100 most recent messages of followed_users
    """

    if g.user:
        messages = (Message
                    .query
                    .order_by(Message.timestamp.desc())
                    .limit(100)
                    .all())
        
        followings = [following.id for following in g.user.following]
        followings.append(g.user.id)
        likes = [like.id for like in g.user.likes]

        return render_template('home.html', messages=messages, followings=followings, likes=likes)

    else:
        return render_template('home-anon.html')


##############################################################################
# Turning off all caching in Flask
#   (useful for dev; in production, this kind of stuff is typically
#   handled elsewhere)
#
# https://stackoverflow.com/questions/34066804/disabling-caching-in-flask

@app.after_request
def add_header(req):
    """Add non-caching headers on every request."""

    req.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    req.headers["Pragma"] = "no-cache"
    req.headers["Expires"] = "0"
    req.headers['Cache-Control'] = 'public, max-age=0'
    return req

@app.errorhandler(404)
def page_not_found(e):
    #snip
    return render_template('404.html'), 404