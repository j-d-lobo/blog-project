from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_ckeditor.utils import cleanify
# from flask_gravatar import Gravatar (DOES NOT WORK ANYMORE)
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from sqlalchemy.exc import IntegrityError
from typing import List
from functools import wraps
from hashlib import md5
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from dotenv import load_dotenv # Added for Day 71 
import gunicorn # Added for Day 71  
import psycopg2 # Added for Day 71  
import email_validator
import os # Added for Day 71

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''
load_dotenv("Day 69\.env")
SECRET_KEY = os.getenv("SECRET_KEY")
DB_URI = os.getenv("DB_URI")

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = (DB_URI,'sqlite:///blog_capstone.db')

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# https://docs.sqlalchemy.org/en/20/orm/basic_relationships.html
# https://docs.sqlalchemy.org/en/20/orm/basic_relationships.html#one-to-many
# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    author : Mapped["User"] = relationship(back_populates="posts") # author becomes a User object
    author_id: Mapped[int] = mapped_column(ForeignKey("blog_users.id"))
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments : Mapped[List["Comment"]] = relationship(back_populates="post")


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "blog_users"
    id: Mapped[int] = mapped_column(Integer, primary_key= True)
    email: Mapped[str] = mapped_column(String(100), unique= True)
    password: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(100))
    avatar: Mapped[str] = mapped_column(String(1000))
    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author") #User can have many posts (parent)
    comments: Mapped[List["Comment"]] = relationship(back_populates="author") #User can have many comments (parent)

# TODO: Create a Comments table with id and comment text
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key= True)
    author: Mapped["User"] = relationship(back_populates="comments")
    author_id: Mapped[int] = mapped_column(ForeignKey("blog_users.id"))
    text: Mapped[str] = mapped_column(Text, nullable= False)
    post: Mapped["BlogPost"] = relationship(back_populates="comments")
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(id):
    return db.session.get(User, id)

def hash_password(pw):
    hashed_password = generate_password_hash(pw, method="pbkdf2:sha256", salt_length= 8)
    return hashed_password

def admin_only(function):
    @wraps(function)
    def wrapping_function(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:
            abort(403)
    wrapping_function.__name__ = function.__name__  # Should replace the wrapper function name with the name of the actual function
    # Meant to prevent the AssertionError: https://stackoverflow.com/questions/17256602/assertionerror-view-function-mapping-is-overwriting-an-existing-endpoint-functi
    return wrapping_function

def gen_avatar(email):
    digest = md5(email.lower().encode('utf-8')).hexdigest()
    size = 128
    return f"https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}"

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods= ["GET", "POST"])
def register():
    Register = RegisterForm()
    if Register.validate_on_submit(): # If the Register button on the WTForm is pressed, do this
        NewUser = User(
            name = request.form.get("name"), # Grabs the data from the RegisterForm in the name field
            email = request.form.get("email"), # Grabs the data from the RegisterForm in the email field 
            password = hash_password(request.form.get("password")), 
            # Grabs the data from the RegisterForm in the password field, hashs and salts the password
            avatar = gen_avatar(request.form.get('email'))
        )
        try: 
            db.session.add(NewUser) # Trys to add it to the database, if the unique clause is violated proceeds to the except statement
            db.session.commit()
            return redirect(url_for('login')) # After the user is registered, 
        except IntegrityError: # Activates when the unique clause in the User database is violated, meaning the user already exists 
            flash("Email already in use, try logging in.")
            return redirect(url_for('login'))
    return render_template("register.html", form= Register, logged_in= current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods= ["GET", "POST"])
def login():
    Login = LoginForm()
    if Login.validate_on_submit():
        user_email = request.form.get("email")
        user_password = request.form.get("password") #Plaintext password
        with app.app_context():
            user_to_authenticate = db.session.query(User).where(User.email == user_email).first()
            try: 
                STATUS = check_password_hash(user_to_authenticate.password, user_password)
                if STATUS:
                    login_user(user_to_authenticate)
                    flash("Successfully logged in!")
                    return redirect(url_for('get_all_posts'))
                else:
                    flash("Invalid password! Please try again.")
                    return render_template("login.html", form= Login, logged_in= current_user.is_authenticated)
            except AttributeError:
                flash("User not found! Please check that you have the right login credentials.")
                return render_template("login.html", form= Login, logged_in= current_user.is_authenticated)
    return render_template("login.html", form= Login, logged_in= current_user.is_authenticated)


@app.route('/logout')
def logout():
    session.pop('_flashes', None)
    logout_user()
    return redirect(url_for('get_all_posts', logged_in= current_user.is_authenticated))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    try:
        if current_user.id == 1:
            admin_check = True
        else:
            admin_check = False
    except AttributeError: #AnonymousUserMixin object has no attribute 'id' 
    # Means the user hasn't logged in, therefore they are anonymous
        admin_check = False
    return render_template("index.html", all_posts=posts, logged_in= current_user.is_authenticated, is_admin= admin_check)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods= ["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    AddComment = CommentForm()
    if AddComment.validate_on_submit():
        if current_user.is_authenticated == True: # Means user is logged in
            NewComment = Comment(
                text = AddComment.comment.data,
                author = current_user,
                author_id = current_user.id,
                post_id = post_id,
                post = db.get_or_404(BlogPost, post_id)
            )
            db.session.add(NewComment)
            db.session.commit()
        else:
            flash("You need to be logged in to write a comment. If you don't have an account, consider registering.")
            return redirect(url_for("login"))
    return render_template("post.html", form=AddComment, post=requested_post, logged_in= current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post(user=current_user):
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in= current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id, user=current_user):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in= current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id, user=current_user):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False, port=5002)
