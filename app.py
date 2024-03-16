from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, EqualTo
from wtforms import StringField, PasswordField, SubmitField
from datetime import datetime

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)  

app.secret_key = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'
    

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Integer, default=2000)
    user = db.relationship('User', backref=db.backref('account', lazy=True))

    def __repr__(self):
        return f'<Account {self.id}>'
    
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime)
    account = db.relationship('Account', backref=db.backref('transaction', lazy=True))
    
class registration_form(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=20)])
    cpassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class login_form(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# index routes
@app.route('/')
def home():
    return render_template('index.html', title = 'Home')

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user = User.query.filter_by(id=current_user.id).first()
    accounts = Account.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', title='Dashboard', accounts=accounts, user=user)

# Money handling routes
@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    accounts = Account.query.filter_by(user_id=current_user.id).all() # Get all accounts for the current user
    if request.method == 'POST':
        amount = request.form['amount']
        selected_account = Account.query.filter_by(id=request.form['account']).first() # Get the selected account
        selected_account.balance += int(amount)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('operations.html', title='Deposit', text='Deposit money', btn_action='Deposit', accounts=accounts)

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    accounts = Account.query.filter_by(user_id=current_user.id).all() # Get all accounts for the current user
    if request.method == 'POST':
        amount = request.form['amount']
        selected_account = Account.query.filter_by(id=request.form['account']).first() # Get the selected account
        if int(amount) > selected_account.balance:
            flash('Insufficient funds')
            flash(f'Your balance is {selected_account.balance}')
            return redirect(url_for('withdraw'))
        selected_account.balance -= int(amount)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('operations.html', title='Withdraw', text='Withdraw money', btn_action='Withdraw', accounts=accounts)


# Auth system
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registration_form()
    if request.method =='POST':
        username = form.username.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        new_user_account = Account(user_id=new_user.id)
        db.session.add(new_user_account)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('auth.html', title = 'Register', text='Create an account', form=registration_form(), btn_action="Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = login_form()
    if request.method == 'POST':
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                user.login_attempts += 1
                db.session.commit()
                flash('Invalid password')
                if user.login_attempts > 3:
                    user.is_locked = True
                    db.session.commit()
                    flash('Your account is locked')
        else:
            flash('Invalid username')

    return render_template('auth.html', title='Login', text='Login to your account', form=registration_form(),btn_action="Login")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

