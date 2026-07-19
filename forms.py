from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp, ValidationError

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50),
        Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers and underscores')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Sign Up')

    def validate_password(self, field):
        password = field.data
        if not any(c.isupper() for c in password):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not any(c.islower() for c in password):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not any(c.isdigit() for c in password):
            raise ValidationError('Password must contain at least one digit.')
        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            raise ValidationError('Password must contain at least one special character.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50)
    ])
    password = PasswordField('Password', validators=[
        DataRequired()
    ])
    submit = SubmitField('Login')


class Verify2FAForm(FlaskForm):
    code = StringField('Verification Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Code must be exactly 6 digits'),
        Regexp('^[0-9]+$', message='Code must only contain numbers')
    ])
    submit = SubmitField('Verify')