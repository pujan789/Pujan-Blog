from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from flask_wtf import FlaskForm
from werkzeug import security
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField
from wtforms.validators import DataRequired

from forms import CreatePostForm,RegisterForm,LoginUser,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar()

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



##CONFIGURE TABLES

class BlogPost(UserMixin,db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User",back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)



class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")

    # *******Add parent relationship*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")



class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")


db.create_all()

db.create_all()
db.session.commit()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    try:
        user_id = int(current_user.get_id())
    except:
        user_id = 2

    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated,user_id=user_id)


@app.route('/register',methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    print("didn")

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user == None:
            hash_and_salted_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=form.email.data,
                name=form.name.data,
                password=hash_and_salted_password,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            print("till_here")
            return redirect(url_for("get_all_posts"))
        else:
            error = "You've already signed up with that email, log in instead!"
            return redirect(url_for('login',problem=error))

    return render_template("register.html",form=form)


@app.route('/login',methods=['GET',"POST"])
def login():
    error = None
    try :
        error = request.args.get("problem")
        print(error)
    except:
        pass
    form = LoginUser()
    if form.validate_on_submit():

        user = User.query.filter_by(email=form.email.data).first()
        if user == None:
            error = "The email does not exist, please try again"
        elif security.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)

                return redirect(url_for("get_all_posts"))
            else:
                error = "Password incorrect, please try again"


    return render_template("login.html",form=form,error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET',"POST"])
def show_post(post_id):
    gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False,
                        use_ssl=False, base_url=None)

    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    all_comments = db.session.query(Comment).all()


    try:
        user_id = int(current_user.get_id())
    except:
        user_id = 2
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.body.data,
                author_id=int(current_user.get_id()),
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        else:
            return redirect(url_for("login",problem="You need to login or register to comment"))

    return render_template("post.html", post=requested_post,user_id=user_id,logged_in=current_user.is_authenticated,form=form,comments=all_comments,gravatar=gravatar
                           )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['GET', 'POST'])
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
    return render_template("make-post.html", form=form,logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>",methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
