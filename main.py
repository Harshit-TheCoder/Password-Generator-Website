from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask,render_template,request, redirect, url_for, jsonify
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField
from wtforms.validators import DataRequired
import random
import smtplib
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from wtforms.widgets import SubmitInput
from flask_bcrypt import Bcrypt

capital_letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
small_letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
special_characters = ['!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']


app = Flask(__name__)
bootstrap = Bootstrap5(app)
app.config['SECRET_KEY'] = 'AlooPaloo'
bcrypt = Bcrypt(app)

class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///userinfo.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class UserInfo(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    username = StringField(label='Username', validators=[DataRequired()])
    password = StringField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label="Log In")

class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    username = StringField(label='Username', validators=[DataRequired()])
    password = StringField(label='Password', validators=[DataRequired()])
    confirm_password = StringField(label='Confirm Password', validators=[DataRequired()])
    submit = SubmitField(label="Register")

class GeneratePassword(FlaskForm):
    password_length = IntegerField(label='Password Length', validators=[DataRequired()])
    num_small_letters = IntegerField(label='Number of Small Letters')
    num_capital_letters = IntegerField(label='Number of Capital Letters')
    num_digits = IntegerField(label='Number of digits')
    num_special_characters = IntegerField(label='Number of Special Characters')
    generate = SubmitField(label="Generate Password")
    generated_password = StringField(label='Generated Password')
    email_password = StringField(label='Recieve unencrypted password through email', widget=SubmitInput())
    password = StringField(label = "Encrypted Password")
    encrypt = StringField(label = "Encrypt", widget=SubmitInput())
    encrypt_password = StringField(label='Recieve encrypted password through email', widget=SubmitInput())



   
  
with app.app_context():
    db.create_all()


current_user = {
    "email":"",
    "username":"",
    "password":"",
    "generated_password":"",
    "encrypted_password":"",
}

@app.route('/')
def home():
    return render_template('index.html', bootstrap=bootstrap)


@app.route('/send_unencrypted_mail', methods=['GET', 'POST'])
def send_unencrypted_mail():
    return redirect(url_for('sendinfo', email=current_user['email']))

@app.route('/send_encrypted_mail', methods=['GET', 'POST'])
def send_encrypted_mail():
    return redirect(url_for('sendinfo', email=current_user['email']))
 
# @app.route('/generate', methods=['GET', 'POST'])
# def generate():
#     password = ""
#     generate_password = GeneratePassword()
#     if generate_password.validate_on_submit():
#         for i in range(generate_password.num_small_letters.data):
#             password += random.choice(small_letters)
        
#         for i in range(generate_password.num_capital_letters.data):
#             password += random.choice(capital_letters)
        
#         for i in range(generate_password.num_digits.data):
#             password += random.choice(numbers)
        
#         for i in range(generate_password.num_special_characters.data):
#             password += random.choice(special_characters)

#         password_list = list(password)
#         random.shuffle(password_list)
#         new_password = ''.join(password_list)

#         generate_password.generated_password.data = new_password

#         # You might need to import current_user from wherever it's defined
#         # Assuming it's a Flask-Login User object
#         current_user['generated_password'] = new_password
#         print(current_user)
#         return jsonify({'data': new_password})

#     # In case form validation fails
#     return render_template('generate_password.html',form2=generate_password, bootstrap=bootstrap)

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    generate_password = GeneratePassword()

    if generate_password.validate_on_submit():
        # Generate the password
        generated_password = generate_random_password(generate_password)

        # Hash the generated password
        hashed_password = bcrypt.generate_password_hash(generated_password, rounds=10).decode('utf-8')

        # Update the current_user dictionary
        current_user['generated_password'] = generated_password
        current_user['encrypted_password'] = hashed_password

        # Returning JSON response instead of rendering template
        return jsonify({'data': generated_password})

    # In case form validation fails
    return render_template('generate_password.html', form2=generate_password, bootstrap=bootstrap)

# Helper function to generate random password
def generate_random_password(generate_password):
    password = ""
    for i in range(generate_password.num_small_letters.data):
        password += random.choice(small_letters)
    for i in range(generate_password.num_capital_letters.data):
        password += random.choice(capital_letters)
    for i in range(generate_password.num_digits.data):
        password += random.choice(numbers)
    for i in range(generate_password.num_special_characters.data):
        password += random.choice(special_characters)

    password_list = list(password)
    random.shuffle(password_list)
    return ''.join(password_list)

@app.route('/encrypt_password', methods=['POST'])
def encrypt_password():
    # Encrypt the generated password
    generated_password = current_user['generated_password']
    print(generated_password)
    hashed_password = bcrypt.generate_password_hash(generated_password, rounds=10).decode('utf-8')
    current_user['encrypted_password'] = hashed_password
    print(current_user)
    return jsonify({'data': hashed_password})

    
@app.route('/sendinfo/<email>', methods=['GET', 'POST'])
def sendinfo(email):
    print(email)
    my_email = "harshitharlalka11@gmail.com"
    password = "iutcfhwussnpucgg"
    
    with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        
        user = UserInfo.query.filter_by(email=email).first()
        if user:
            subject = "User Information"
            message = MIMEMultipart()
            message['From'] = my_email
            message['To'] = user.email
            message['Subject'] = subject
            
            body = f''' Hi {user.username}!! I am CodeCryptor.I have mailed your CodeCryptor Account Infomation,alongwith the generated password.
                Email: {user.email}
                Username: {user.username}
                Password: {user.password}
                Generated Password: {current_user['generated_password']}
                Encrypted Password: {current_user['encrypted_password']}
            Your Password has been encrypted using 10 salt rounds.
                Have a nice day buddy!! 
                '''
            message.attach(MIMEText(body, 'plain'))
            
            text = message.as_string()
            connection.sendmail(from_addr=my_email, to_addrs=user.email, msg=text)
            return "Email sent successfully"
        else:
            return "User not found"


@app.route('/login', methods=["GET", "POST"])
def login():
     login_form = LoginForm()
     generate_password = GeneratePassword()
     if login_form.validate_on_submit():
        entered_username = login_form.username.data
        entered_password = login_form.password.data
        user = UserInfo.query.filter_by(username=entered_username).first()
        print("Stored Password:",user.password)
        print("Entered Password:", entered_password)
        if user:
            stored_password = user.password
            if stored_password == entered_password:
                current_user["email"] = user.email
                current_user["username"] = user.username
                current_user["password"] = user.password
                return redirect(url_for('generate'))
            else:
                return "Invalid Password"
        else:
            return "Oops User not found please register"
     return render_template("login.html", form=login_form, bootstrap=bootstrap)

@app.route('/register', methods=["GET", "POST"])
def register():
     register_form = RegisterForm()
     current_user["email"] = register_form.email.data
     current_user["username"] = register_form.username.data
     current_user["password"] = register_form.password.data
     if register_form.validate_on_submit():
        with app.app_context():
            info = UserInfo(
                 email = register_form.email.data,
                 username=register_form.username.data,
                 password=register_form.password.data)
            db.session.add(info)
            db.session.commit()
        return render_template("index.html") 
     return render_template("register.html", form1=register_form, bootstrap=bootstrap)
   


if __name__=='__main__':
    app.run(debug=True)



    # @app.route('/generate', methods=['GET', 'POST'])
# def generate():
#     password=""
#     new_password=""
#     generate_password = GeneratePassword()
#     if generate_password.validate_on_submit():
#         for i in range(generate_password.num_small_letters.data):
#             password += random.choice(small_letters)
        
#         for i in range(generate_password.num_capital_letters.data):
#             password += random.choice(capital_letters)
        
#         for i in range(generate_password.num_digits.data):
#             password += random.choice(numbers)
        
#         for i in range(generate_password.num_special_characters.data):
#             password += random.choice(special_characters)

#         for i in range(len(password)):
#             new_password += random.choice(password)

#         generate_password.generated_password.data = new_password
#         current_user["generated_password"] = new_password
#         print(current_user)
#         if generate_password.email_password.data:
#             sendinfo(current_user['email'])
#         elif generate_password.encrypt.data:
#             hashed_password = bcrypt.generate_password_hash(new_password, rounds=10).decode('utf-8')
#             generate_password.password.data = hashed_password
#             current_user['encrypted_password'] = hashed_password  # Ensure hashed_password is defined before using it
#         elif generate_password.encrypt_password.data:
#             sendinfo(current_user['email'])
#         return render_template('generate_password.html', form2=generate_password, bootstrap=bootstrap)
       
#     return render_template('generate_password.html',form2=generate_password, bootstrap=bootstrap)