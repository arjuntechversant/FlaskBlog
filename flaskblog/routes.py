from flask import Flask, render_template, url_for, flash, redirect,request, abort,session,jsonify


from flaskblog import app,db,bcrpyt
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, RequestResetForm, ResetPasswordForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user,login_required


from flaskblog.oauth import OAuthSignIn

# from flask import OAuth

# from flask_oauth.client import OAuth
from flask_oauthlib.client import OAuth

# from flask_oauth import OAuth

import urllib
import urllib3
from urllib.request import urlopen

from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail,  Message

app.config['GOOGLE_ID'] = "548687100135-hg2e5lnq79gb8k7ekffsb6galuu3tisn.apps.googleusercontent.com"
app.config['GOOGLE_SECRET'] = "-g02Fl4Es4Xp2OQ1pyPNYxXV"


app.config['OAUTH_CREDENTIALS'] = {

    'facebook': {
        'id': '1050441568455413',
        'secret': 'e8868bcf35763bb3713d087624222205'
    }
}

app.config['MAIL_SERVER']='smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mkanandin@gmail.com'
app.config['MAIL_PASSWORD'] = 'chottu@33'


REDIRECT_URI = '/oauth2callback'

# creating OAuth object
oauth = OAuth()

#creating mail object
mail = Mail(app)

google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),

    request_token_params={
        'scope': 'email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',

)

@app.route("/")
@app.route("/home")
def home():
    posts = Post.query.all()   # select query
    return render_template('home.html', posts=posts)   # render template with passing context i.e. posts

@app.route("/about")
def about():
    return render_template('about.html', title='About')    # render template


@app.route("/register", methods=['GET', 'POST'])
def register():
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
    form = RegistrationForm()                # creating object
    if form.validate_on_submit():
        hashed_password = bcrpyt.generate_password_hash(form.password.data).decode('utf-8')         # hashing password
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)    # creating object of User model
        db.session.add(user)                  # creating session
        db.session.commit()                   # saving session
        flash('Your account has been created! You are now able to log in', 'success')   # diplaying message (message , type)
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrpyt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)

            # next_page = request.args.get('next')
            # return redirect(next_page) if next_page else redirect(url_for('home'))

            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form )


@app.route("/logout")
def logout():

    # db.session.remove()
    # db.session.commit()

    session.pop('google_token', None)
    logout_user()

    return redirect(url_for('home'))


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        # if form.picture.data:
        #     picture_file = save_picture(form.picture.data)
        #     current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    # image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    # return render_template('account.html', title='Account',
    #                        image_file=image_file, form=form)

    return render_template('account.html', title='Account', form=form)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post',
                           form=form, legend='New Post')


@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)


@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Update Post',
                           form=form, legend='Update Post')


@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))


#         $$        $$  FORGOT PASSWORD   $$   $$


# send email route
@app.route("/user/<string:username>")
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='mkanandin@gmail.com',
                  recipients=[user.email])
    url_reset = url_for('reset_token', token=token, _external=True)
    msg.body = """
    To reset your password, visit the following link:"""+\
        "<a href="+url_reset+\
              """>Click Me</a>If you did not make this request then simply ignore 
              this email and no changes will be made."""

    mail.send(msg)


# request email for reseting password
@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


# reset password
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrpyt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


#   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$  SOCIAL LOGIN-FACEBOOK $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('login'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):

    if not current_user.is_anonymous:
        return redirect(url_for('login'))
    oauth = OAuthSignIn.get_provider(provider)
    social_id, username, email = oauth.callback()
    if social_id is None:
        flash('Authentication failed.')
        return redirect(url_for('login'))
    user = User.query.filter_by(social_id=social_id).first()
    if not user:
        user = User(social_id=social_id, username=username, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user, True)
    return redirect(url_for('login'))


#   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ SOCIAL LOGIN-GOOGLE $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

@app.route('/googleindex')
def googleindex():
    # import pdb;pdb.set_trace()
    if 'google_token' in session:
        me = google.get('userinfo')
        print ("not logged in",me.data['email'])
        return jsonify({"data": me.data})
    return redirect(url_for('googlelogin'))


@app.route('/googlelogin')
def googlelogin():
    return google.authorize(callback=url_for('authorized', _external=True))

# @app.route('/logout')
# def logout():
#     session.pop('google_token', None)
#     return redirect(url_for('login'))


@app.route('/login/authorized')
def authorized():
    # import pdb;pdb.set_trace()
    resp = google.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    me = google.get('userinfo')
    print("logged in", me.data)
    email=me.data['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user, True)
    return redirect(url_for('login'))
    # return jsonify({"data": me.data})


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')
