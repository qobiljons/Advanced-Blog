from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentFrom
import smtplib
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("secret_key")
ckeditor = CKEditor(app)
Bootstrap5(app)

my_gmail = os.environ.get("my_gmail")
my_yahoo = os.environ.get("my_yahoo")
password = os.environ.get("password")

GMAIL_SMTP = "smtp.gmail.com"

login_manager = LoginManager()
login_manager.init_app(app)


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        admin = db.get_or_404(User, 1)
        if admin == current_user:
            return func(*args, **kwargs)
        else:
            return abort(403)

    return wrapper


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES


# MORE CODE ABOVE

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)


# MORE CODE BELOW

with app.app_context():
    db.create_all()



@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)




# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=password)
            db.session.add(new_user)
            db.session.commit()
            flash("You have successfully registered")
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        except IntegrityError:
            flash(message="You have already registered with this email log in instead")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email.
@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        if user is not None:
            password = check_password_hash(user.password, password=form.password.data)
            if password:
                login_user(user)
                return redirect(url_for("get_all_posts", logged_in=True, is_admin=current_user.id == 1))
            else:
                flash(message="Wrong password try again!")
        else:
            flash(message="User is not available please register first!")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


@app.route('/')
def get_all_posts():
    admin = None
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    if current_user == db.get_or_404(User, 1) and current_user.is_authenticated:
        admin = True
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, is_admin=admin)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    admin = None
    form = CommentFrom()
    requested_post = db.get_or_404(BlogPost, post_id)
    if current_user == db.get_or_404(User, 1) and current_user.is_authenticated:
        admin = True
    if current_user.is_authenticated and form.validate_on_submit():
        comment = form.comment.data
        print(comment)
        new_comment = Comment(
            text=comment,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    else:
        redirect(url_for("login"))
    return render_template("post.html", post=requested_post, is_admin=admin, form=form, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can create a new post

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
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
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
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
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user,
                           logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    comments_to_delete = db.session.execute(db.select(Comment).where(post_id==post_id)).scalars()
    for comment in comments_to_delete:
        db.session.delete(comment)
    db.session.commit()
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():

    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact", methods=["POST", "GET"])
def contact():
    if request.method == "POST":
        username = request.form["name"]
        email = request.form["email"]
        phone_number = request.form["phone"]
        message = request.form["message"]
        with smtplib.SMTP(GMAIL_SMTP) as connection:
            connection.starttls()
            connection.login(my_gmail, password=password)
            connection.sendmail(from_addr=my_gmail, to_addrs=my_yahoo,
                                msg=f"Subject:{email}\n\nUsername: {username},\nPhone Number: {phone_number},\nmessage: {message} ")
        return "Success!"
    else:
        return render_template("contact.html")
if __name__ == "__main__":
    app.run(debug=False, port=5004)
