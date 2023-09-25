from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)  # create the application instance
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'  # secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # connect to the database
db = SQLAlchemy(app)  # create an instance of SQLAlchemy

login_manager = LoginManager()  # create a login manager
login_manager.init_app(app)  # bind the login manager to the application
login_manager.login_view = 'login'  # set the login view

class User(db.Model, UserMixin):  # create a user model
  id = db.Column(db.Integer, primary_key=True)  # set the primary key
  username = db.Column(db.String(150), unique=True, nullable=False)  # set the username
  password = db.Column(db.String(150), nullable=False)  # set the password
  notes = db.relationship('Note', backref='user', lazy=True)  # set the relationship

class Note(db.Model):  # create a note model
  id = db.Column(db.Integer, primary_key=True)  # set the primary key
  content = db.Column(db.Text, nullable=False)  # set the content
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # set the user id


@login_manager.user_loader  # load the user
def load_user(user_id):  
  return User.query.get(int(user_id))  # return the user


class LoginForm(FlaskForm):
  username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])  # set the username
  password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])  # set the password
  submit = SubmitField('Login')

class RegisterForm(FlaskForm):
  username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])  # set the username
  password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])  # set the password
  submit = SubmitField('Register')

class NoteForm(FlaskForm):  # create a note form
  content = TextAreaField('Content', validators=[InputRequired()])    # set the content
  submit = SubmitField('Submit')  # set the submit

@app.route('/login', methods=['GET', 'POST'])  # set the login route
def login():
  form = LoginForm()  # create the login form
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()  # get the user
    if user and check_password_hash(user.password, form.password.data):  # check the password
      login_user(user)  # login the user
      flash('Logged in successfully!', category='success')  # set the flash message
      return redirect(url_for('notes'))  # redirect to the home page
    flash('Invalid Credentials', category='danger')  # set the flash message
  return render_template('login.html', form=form)  # render the login page

@app.route('/register', methods=['GET', 'POST'])  # set the register route

def register():
  form = RegisterForm()  # create the register form
  if form.validate_on_submit():
    hashed_password = generate_password_hash(form.password.data, method='sha256')  # hash the password
    new_user = User(username=form.username.data, password=hashed_password)  # create the new user
    db.session.add(new_user)  # add the user to the database
    db.session.commit()  # commit the changes
    flash('Account created!', category='success')  # set the flash message
    return redirect(url_for('login'))  # redirect to the login page
  return render_template('register.html', form=form)  # render the register page


@app.route('/notes', methods=['GET', 'POST'])  # set the notes route
@login_required  # check if the user is logged in
def notes():
  form = NoteForm()  # create the note form
  if form.validate_on_submit():
    new_note = Note(content=form.content.data, user_id=current_user.id)  # create the new note
    db.session.add(new_note)  # add the note to the database
    db.session.commit()  # commit the changes
    flash('Note created!', category='success')  # set the flash message
  return render_template('notes.html', form=form)  # render the notes page


@app.route('/delete-note/<int:note_id>')  # set the delete note route
@login_required  # check if the user is logged in
def delete_note(note_id):
  note = Note.query.get(note_id)  # get the note
  if note:  # check if the note exists
    if note.user_id == current_user.id:  # check if the user is the owner of the note
      db.session.delete(note)  # delete the note
      db.session.commit()  # commit the changes
      flash('Note deleted!', category='success')  # set the flash message
  return redirect(url_for('notes'))  # redirect to the notes page

@app.route('/logout')  # set the logout route
@login_required  # check if the user is logged in
def logout():
  logout_user()  # logout the user
  return redirect(url_for('login'))  # redirect to the login page

if __name__ == '__main__':
  app.run(debug=True)