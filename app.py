
from flask import Flask, request, redirect, render_template, url_for,request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os


base_dir = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(base_dir, 'my_login.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = '05d950ab20057e94493f07b4'

"""
To get a 12-digit (any number of choice) secret key, run this in the terminal:
python
import secrets
secrets.token_hex(12)
exit()
Copy the token from the terminal and paste it as the secret key in app.config abo
"""

db = SQLAlchemy(app)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True, nullable=False)
    email = db.Column(db.String(200),  nullable=False, unique=True)
    Username = db.Column(db.String(200),  nullable=False, unique=True)
    password_hash = db.Column(db.Text,  nullable=False)

    def __repr__(self):
        return f'{self.Username}'



@app.route('/', methods=('GET', 'POST'))
def index():
    return render_template('index.html')



@app.route('/register/', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        userExist= User.query.filter_by(Username=username).first()
        if userExist:
            return redirect(url_for(register))

        emailExist= User.query.filter_by(email=email).first()
        if emailExist:
            return redirect(url_for(register))
        passwordharsh = generate_password_hash(password)
        new_user = User(Username=username, email=email, password_hash=passwordharsh ) 
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


@login_manager.user_loader
def user_loader(id):
    return  User.query.get_or_404(int(id))
    

@app.route('/login/', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        old_user = User.query.filter_by(Username=username).first()
        if old_user and check_password_hash(old_user.password_hash, password):
            login_user(old_user)
        else:
            flash("Incorrect username or password ")
            return redirect(url_for('login'))
        return redirect(url_for('profile', username=username))
        
    return render_template('login.html')

@app.route('/<username>', methods=('GET', 'POST'))
def profile(username):
    username = username
    return render_template('profile.html', username=username)

@app.route('/logout/', methods=('GET', 'POST'))
def logout():
    logout = logout_user()
    return redirect(url_for('index'))

@app.route('/protected/', methods=('GET', 'POST'))
@login_required
def protected():
    return render_template('protected.html')

if __name__ == '__main__':
    app.run(debug=True, port=8000)
