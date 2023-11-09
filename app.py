from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'mykey123'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
     
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(40), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators = [InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "The user name already exists. Please choose a different username"
            )
class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators = [InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")


def get_current_time():
    # Get current Indian time
    india_timezone = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    current_time = datetime.datetime.now(india_timezone)
    formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    return formatted_time


@app.route('/')
def auth():
    return render_template('auth.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            login_user(user)
            return redirect(url_for('home')) 
    return render_template('login.html', form=form)

@app.route('/home', methods=["GET","POST"])
@login_required
def home():
    current_time = get_current_time()
    form = LoginForm()
    user = User.query.filter_by(username=form.username.data).first()
    return render_template('home.html', user_data=user, user_profile_picture='F:/Assingment_projects/FormulaQ/images/DSC_copy1.jpg', current_time=current_time)
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)